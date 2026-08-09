//! Secret and scanner-evidence encryption at rest.
//!
//! Sensitive configuration values (OAuth2 client secrets, API keys) use the
//! legacy hostname-bound format described below. Scanner evidence instead uses
//! per-artifact data keys wrapped by a domain-separated, hostname-independent
//! KEK derived from the same owner-only `secret.key` material.
//!
//! This isn't HSM-level security, but it prevents casual reading of secrets
//! from the database file. The encryption key is derived from:
//! - A fixed application salt
//! - The hostname of the machine
//! - A 32-byte CSPRNG random component stored outside the database in a 0600
//!   file at `<data_dir>/secret.key`

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Read, Write};

const APP_SALT: &[u8] = b"AutomateSTIG-secret-encryption-v1";
const EVIDENCE_KEK_SALT: &[u8] = b"AutomateSTIG-evidence-kek-salt-v1";
const EVIDENCE_KEK_INFO: &[u8] = b"AutomateSTIG/scanner-evidence/key-encryption-key/v1";
const EVIDENCE_KEY_ID_DOMAIN: &[u8] = b"AutomateSTIG/scanner-evidence/key-id/v1";
const AES_GCM_NONCE_LEN: usize = 12;
const AES_GCM_TAG_LEN: usize = 16;
const EVIDENCE_DEK_LEN: usize = 32;

/// Algorithm identifier persisted alongside encrypted scanner evidence.
pub const EVIDENCE_ARTIFACT_ALGORITHM: &str = "AES-256-GCM+HKDF-SHA256-v1";

/// A scanner evidence artifact encrypted with a random per-artifact data key.
///
/// Both binary fields contain a 12-byte nonce followed by ciphertext and the
/// 16-byte AES-GCM authentication tag. `wrapped_dek` contains the encrypted
/// 32-byte data-encryption key. The caller-provided AAD is authenticated for
/// both layers but is not stored here.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedEvidenceArtifact {
    pub algorithm: String,
    pub key_id: String,
    pub ciphertext: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}

impl fmt::Debug for SealedEvidenceArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedEvidenceArtifact")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("wrapped_dek_len", &self.wrapped_dek.len())
            .finish()
    }
}

/// Encrypt exact scanner evidence bytes with a fresh 256-bit data key.
///
/// The data key is wrapped with an evidence-specific KEK derived from the
/// owner-only `secret.key` material using HKDF-SHA-256. Unlike the legacy
/// configuration-secret helper below, this derivation is not tied to the
/// machine hostname.
pub fn seal_evidence_artifact(
    plaintext: &[u8],
    aad: &[u8],
    key_material: &str,
) -> Result<SealedEvidenceArtifact, String> {
    let root_key = evidence_root_key(key_material)?;
    let key_id = evidence_key_id(root_key.as_ref());
    let rng = SystemRandom::new();

    let mut dek = SensitiveKey::random(&rng)?;
    let data_key = aead_key(dek.as_ref())?;
    let ciphertext = seal_binary_blob(&data_key, plaintext, aad, &rng)?;

    let kek = evidence_kek(root_key.as_ref())?;
    let wrapped_dek = seal_binary_blob(&kek, dek.as_ref(), aad, &rng)?;
    dek.clear();

    Ok(SealedEvidenceArtifact {
        algorithm: EVIDENCE_ARTIFACT_ALGORITHM.to_string(),
        key_id,
        ciphertext,
        wrapped_dek,
    })
}

/// Authenticate and decrypt a scanner evidence artifact.
///
/// Decryption fails closed for a different key, different AAD, modified
/// metadata, or tampering with either encrypted blob.
pub fn open_evidence_artifact(
    artifact: &SealedEvidenceArtifact,
    aad: &[u8],
    key_material: &str,
) -> Result<Vec<u8>, String> {
    if artifact.algorithm != EVIDENCE_ARTIFACT_ALGORITHM {
        return Err("Unsupported evidence encryption algorithm".to_string());
    }

    let root_key = evidence_root_key(key_material)?;
    if artifact.key_id != evidence_key_id(root_key.as_ref()) {
        return Err("Evidence encryption key does not match".to_string());
    }

    let kek = evidence_kek(root_key.as_ref())?;
    let mut dek = SensitiveBytes::new(open_binary_blob(&kek, &artifact.wrapped_dek, aad)?);
    if dek.as_ref().len() != EVIDENCE_DEK_LEN {
        return Err("Invalid wrapped evidence key".to_string());
    }

    let data_key = aead_key(dek.as_ref())?;
    let plaintext = open_binary_blob(&data_key, &artifact.ciphertext, aad)?;
    dek.clear();
    Ok(plaintext)
}

fn evidence_root_key(key_material: &str) -> Result<SensitiveKey, String> {
    let normalized = key_material.trim();
    if normalized.len() != EVIDENCE_DEK_LEN * 2
        || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Evidence encryption requires 32 bytes of hex key material".to_string());
    }

    let decoded = hex::decode(normalized)
        .map_err(|_| "Evidence encryption requires valid hex key material".to_string())?;
    let bytes: [u8; EVIDENCE_DEK_LEN] = decoded
        .try_into()
        .map_err(|_| "Evidence encryption requires 32 bytes of key material".to_string())?;
    Ok(SensitiveKey(bytes))
}

fn evidence_kek(root_key: &[u8]) -> Result<LessSafeKey, String> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, EVIDENCE_KEK_SALT);
    let pseudorandom_key = salt.extract(root_key);
    let info = [EVIDENCE_KEK_INFO];
    let output_key_material = pseudorandom_key
        .expand(&info, &AES_256_GCM)
        .map_err(|_| "Evidence key derivation failed".to_string())?;
    Ok(LessSafeKey::new(UnboundKey::from(output_key_material)))
}

fn evidence_key_id(root_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_KEY_ID_DOMAIN);
    hasher.update(root_key);
    hex::encode(&hasher.finalize())
}

fn aead_key(key_bytes: &[u8]) -> Result<LessSafeKey, String> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes)
        .map_err(|_| "Evidence encryption key creation failed".to_string())?;
    Ok(LessSafeKey::new(unbound_key))
}

fn seal_binary_blob(
    key: &LessSafeKey,
    plaintext: &[u8],
    aad: &[u8],
    rng: &dyn SecureRandom,
) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| "Random number generation failed".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = SensitiveBytes::new(plaintext.to_vec());
    key.seal_in_place_append_tag(nonce, Aad::from(aad), in_out.as_mut())
        .map_err(|_| "Evidence encryption failed".to_string())?;

    let mut blob = Vec::with_capacity(AES_GCM_NONCE_LEN + in_out.as_ref().len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(in_out.as_ref());
    Ok(blob)
}

fn open_binary_blob(key: &LessSafeKey, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN {
        return Err("Encrypted evidence blob is too short".to_string());
    }

    let (nonce_bytes, ciphertext) = blob.split_at(AES_GCM_NONCE_LEN);
    let nonce_bytes: [u8; AES_GCM_NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| "Invalid evidence nonce".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = SensitiveBytes::new(ciphertext.to_vec());
    let plaintext_len = key
        .open_in_place(nonce, Aad::from(aad), in_out.as_mut())
        .map_err(|_| "Evidence decryption failed: key, AAD, or data mismatch".to_string())?
        .len();
    in_out.truncate(plaintext_len);
    Ok(in_out.into_vec())
}

struct SensitiveKey([u8; EVIDENCE_DEK_LEN]);

impl SensitiveKey {
    fn random(rng: &dyn SecureRandom) -> Result<Self, String> {
        let mut bytes = [0u8; EVIDENCE_DEK_LEN];
        rng.fill(&mut bytes)
            .map_err(|_| "Random number generation failed".to_string())?;
        Ok(Self(bytes))
    }

    fn as_ref(&self) -> &[u8] {
        &self.0
    }

    fn clear(&mut self) {
        self.0.fill(0);
    }
}

impl Drop for SensitiveKey {
    fn drop(&mut self) {
        self.clear();
    }
}

struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_ref(&self) -> &[u8] {
        &self.0
    }

    fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    fn clear(&mut self) {
        self.0.fill(0);
    }

    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Load the shared random key material, creating it on first use.
pub fn load_or_create_key_material(data_dir: &std::path::Path) -> Result<String, String> {
    secure_private_directory(data_dir)?;
    let key_path = data_dir.join("secret.key");
    match std::fs::symlink_metadata(&key_path) {
        Ok(_) => return read_private_key_material(&key_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Failed to inspect {}: {error}", key_path.display())),
    }

    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes)
        .map_err(|_| "Random number generation failed".to_string())?;
    let key_material = hex::encode(&bytes);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match options.open(&key_path) {
        Ok(file) => file,
        // A concurrent process may have won creation. Validate and use its file.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return read_private_key_material(&key_path)
        }
        Err(error) => return Err(format!("Failed to create {}: {error}", key_path.display())),
    };
    file.write_all(key_material.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("Failed to write {}: {e}", key_path.display()))?;

    Ok(key_material)
}

/// Load existing key material without replacing a missing key. Decryption
/// paths use this fail-closed variant so loss of `secret.key` cannot silently
/// create a new key and obscure the recovery condition.
pub fn load_existing_key_material(data_dir: &std::path::Path) -> Result<String, String> {
    secure_private_directory(data_dir)?;
    let key_path = data_dir.join("secret.key");
    read_private_key_material(&key_path)
}

fn secure_private_directory(path: &std::path::Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "Secret directory must be a real directory, not a symlink: {}",
                    path.display()
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.uid() != unsafe { libc::geteuid() } {
                    return Err(format!(
                        "Secret directory is not owned by the current user: {}",
                        path.display()
                    ));
                }
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("Failed to protect {}: {error}", path.display()))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .map_err(|error| format!("Failed to create {}: {error}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("Failed to protect {}: {error}", path.display()))?;
            }
        }
        Err(error) => return Err(format!("Failed to inspect {}: {error}", path.display())),
    }
    Ok(())
}

fn read_private_key_material(path: &std::path::Path) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("Failed to inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "Secret key must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!(
                "Secret key must be owned by the current user with mode 0600: {}",
                path.display()
            ));
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let file = options
            .open(path)
            .map_err(|error| format!("Failed to open {}: {error}", path.display()))?;
        let mut key = String::new();
        file.take(129)
            .read_to_string(&mut key)
            .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
        validate_key_material(path, key)
    }
    #[cfg(not(unix))]
    {
        let mut key = String::new();
        std::fs::File::open(path)
            .and_then(|mut file| file.take(129).read_to_string(&mut key))
            .map_err(|error| format!("Failed to read {}: {error}", path.display()))?;
        validate_key_material(path, key)
    }
}

fn validate_key_material(path: &std::path::Path, key: String) -> Result<String, String> {
    let key = key.trim().to_string();
    if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "Secret key must contain exactly 32 hex-encoded bytes: {}",
            path.display()
        ));
    }
    Ok(key)
}

/// Encrypt a secret string for storage.
/// Returns a hex-encoded string of: nonce (12 bytes) + ciphertext + tag.
pub fn encrypt_secret(plaintext: &str, db_key_material: &str) -> Result<String, String> {
    let key_bytes = derive_key(db_key_material);

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|e| format!("Key creation failed: {}", e))?;
    let key = LessSafeKey::new(unbound_key);

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| "Random number generation failed".to_string())?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext+tag.
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&in_out);

    Ok(hex::encode(&result))
}

/// Decrypt a secret string from storage.
/// Input is the hex-encoded string from encrypt_secret.
pub fn decrypt_secret(hex_ciphertext: &str, db_key_material: &str) -> Result<String, String> {
    let data = hex::decode(hex_ciphertext).map_err(|e| format!("Invalid hex: {}", e))?;

    if data.len() < 12 + 16 {
        return Err("Ciphertext too short".to_string());
    }

    let key_bytes = derive_key(db_key_material);
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|e| format!("Key creation failed: {}", e))?;
    let key = LessSafeKey::new(unbound_key);

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::assume_unique_for_key(
        nonce_bytes
            .try_into()
            .map_err(|_| "Invalid nonce".to_string())?,
    );

    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "Decryption failed — key mismatch or tampered data".to_string())?;

    String::from_utf8(plaintext.to_vec())
        .map_err(|e| format!("Invalid UTF-8 in decrypted data: {}", e))
}

/// Derive a 256-bit key from the database key material and machine info.
fn derive_key(db_key_material: &str) -> [u8; 32] {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown-host".to_string());

    let mut hasher = Sha256::new();
    hasher.update(APP_SALT);
    hasher.update(hostname.as_bytes());
    hasher.update(db_key_material.as_bytes());

    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Simple hex encoding (no extra dependency needed).
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[allow(clippy::manual_is_multiple_of)]
    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 {
            return Err("Odd-length hex string".to_string());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| format!("Invalid hex at pos {}: {}", i, e))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_key(byte: u8) -> String {
        hex::encode(&[byte; EVIDENCE_DEK_LEN])
    }

    #[test]
    fn evidence_artifact_roundtrips_binary_bytes_and_has_storage_layout() {
        let plaintext = b"scanner evidence\0with\xffbinary bytes";
        let aad = b"run-id=run-123\nevidence-sha256=abc";
        let key_material = evidence_key(0x42);

        let artifact = seal_evidence_artifact(plaintext, aad, &key_material).unwrap();

        assert_eq!(artifact.algorithm, EVIDENCE_ARTIFACT_ALGORITHM);
        assert_eq!(artifact.key_id.len(), 64);
        assert!(artifact.key_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            artifact.ciphertext.len(),
            AES_GCM_NONCE_LEN + plaintext.len() + AES_GCM_TAG_LEN
        );
        assert_eq!(
            artifact.wrapped_dek.len(),
            AES_GCM_NONCE_LEN + EVIDENCE_DEK_LEN + AES_GCM_TAG_LEN
        );
        assert_eq!(
            open_evidence_artifact(&artifact, aad, &key_material).unwrap(),
            plaintext
        );
    }

    #[test]
    fn evidence_encryption_uses_a_fresh_dek_and_nonce_per_artifact() {
        let plaintext = b"same evidence";
        let aad = b"same authenticated metadata";
        let key_material = evidence_key(0x24);

        let first = seal_evidence_artifact(plaintext, aad, &key_material).unwrap();
        let second = seal_evidence_artifact(plaintext, aad, &key_material).unwrap();

        assert_eq!(first.key_id, second.key_id);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_ne!(first.wrapped_dek, second.wrapped_dek);

        let root_key = evidence_root_key(&key_material).unwrap();
        let kek = evidence_kek(root_key.as_ref()).unwrap();
        let mut first_dek = open_binary_blob(&kek, &first.wrapped_dek, aad).unwrap();
        let mut second_dek = open_binary_blob(&kek, &second.wrapped_dek, aad).unwrap();
        assert_ne!(first_dek, second_dek);
        first_dek.fill(0);
        second_dek.fill(0);
    }

    #[test]
    fn evidence_key_id_is_stable_for_normalized_key_material() {
        let key_material = evidence_key(0xab);
        let normalized_variant = format!("  {}\n", key_material.to_uppercase());

        let first = seal_evidence_artifact(b"one", b"aad-one", &key_material).unwrap();
        let second = seal_evidence_artifact(b"two", b"aad-two", &normalized_variant).unwrap();

        assert_eq!(first.key_id, second.key_id);
    }

    #[test]
    fn evidence_decryption_rejects_wrong_aad_and_wrong_key() {
        let key_material = evidence_key(0x11);
        let artifact = seal_evidence_artifact(b"evidence", b"correct aad", &key_material).unwrap();

        assert!(open_evidence_artifact(&artifact, b"wrong aad", &key_material).is_err());
        assert!(open_evidence_artifact(&artifact, b"correct aad", &evidence_key(0x12)).is_err());
    }

    #[test]
    fn evidence_decryption_rejects_tampered_ciphertext_and_wrapped_key() {
        let key_material = evidence_key(0x51);
        let aad = b"authenticated metadata";
        let artifact = seal_evidence_artifact(b"evidence", aad, &key_material).unwrap();

        let mut tampered_nonce = artifact.clone();
        tampered_nonce.ciphertext[0] ^= 1;
        assert!(open_evidence_artifact(&tampered_nonce, aad, &key_material).is_err());

        let mut tampered_ciphertext = artifact.clone();
        let last = tampered_ciphertext.ciphertext.len() - 1;
        tampered_ciphertext.ciphertext[last] ^= 1;
        assert!(open_evidence_artifact(&tampered_ciphertext, aad, &key_material).is_err());

        let mut tampered_wrap_nonce = artifact.clone();
        tampered_wrap_nonce.wrapped_dek[0] ^= 1;
        assert!(open_evidence_artifact(&tampered_wrap_nonce, aad, &key_material).is_err());

        let mut tampered_wrapped_key = artifact;
        let last = tampered_wrapped_key.wrapped_dek.len() - 1;
        tampered_wrapped_key.wrapped_dek[last] ^= 1;
        assert!(open_evidence_artifact(&tampered_wrapped_key, aad, &key_material).is_err());
    }

    #[test]
    fn evidence_decryption_rejects_tampered_metadata_and_short_blobs() {
        let key_material = evidence_key(0x61);
        let aad = b"authenticated metadata";
        let artifact = seal_evidence_artifact(b"evidence", aad, &key_material).unwrap();

        let mut wrong_algorithm = artifact.clone();
        wrong_algorithm.algorithm = "AES-256-GCM-unknown".to_string();
        assert!(open_evidence_artifact(&wrong_algorithm, aad, &key_material).is_err());

        let mut wrong_key_id = artifact.clone();
        wrong_key_id.key_id.push('0');
        assert!(open_evidence_artifact(&wrong_key_id, aad, &key_material).is_err());

        let mut short_ciphertext = artifact.clone();
        short_ciphertext
            .ciphertext
            .truncate(AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN - 1);
        assert!(open_evidence_artifact(&short_ciphertext, aad, &key_material).is_err());

        let mut short_wrapped_key = artifact;
        short_wrapped_key
            .wrapped_dek
            .truncate(AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN - 1);
        assert!(open_evidence_artifact(&short_wrapped_key, aad, &key_material).is_err());
    }

    #[test]
    fn evidence_artifact_debug_redacts_encrypted_bytes() {
        let plaintext = b"plaintext-debug-sentinel";
        let artifact =
            seal_evidence_artifact(plaintext, b"debug aad", &evidence_key(0x71)).unwrap();
        let ciphertext_hex = hex::encode(&artifact.ciphertext);
        let wrapped_dek_hex = hex::encode(&artifact.wrapped_dek);

        let debug = format!("{artifact:?}");

        assert!(!debug.contains(std::str::from_utf8(plaintext).unwrap()));
        assert!(!debug.contains(&ciphertext_hex));
        assert!(!debug.contains(&wrapped_dek_hex));
        assert!(debug.contains("ciphertext_len"));
        assert!(debug.contains("wrapped_dek_len"));
    }

    #[test]
    fn evidence_encryption_rejects_non_secret_key_material() {
        assert!(seal_evidence_artifact(b"evidence", b"aad", "short key").is_err());
        assert!(seal_evidence_artifact(b"evidence", b"aad", &"z".repeat(64)).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = "my-super-secret-oauth-client-secret-123";
        let key_material = "some-random-db-stored-salt";

        let encrypted = encrypt_secret(secret, key_material).unwrap();
        assert_ne!(encrypted, secret); // Must be different from plaintext.
        assert!(encrypted.len() > secret.len()); // Includes nonce + tag.

        let decrypted = decrypt_secret(&encrypted, key_material).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_wrong_key_fails() {
        let secret = "test-secret";
        let encrypted = encrypt_secret(secret, "correct-key").unwrap();

        let result = decrypt_secret(&encrypted, "wrong-key");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let secret = "test-secret";
        let mut encrypted = encrypt_secret(secret, "key").unwrap();

        // Tamper with the ciphertext.
        let last = encrypted.len() - 1;
        let mut chars: Vec<char> = encrypted.chars().collect();
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        encrypted = chars.into_iter().collect();

        let result = decrypt_secret(&encrypted, "key");
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"hello world";
        let encoded = hex::encode(data);
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_load_or_create_key_material() {
        let temp_dir = tempfile::tempdir().unwrap();

        let first = load_or_create_key_material(temp_dir.path()).unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|character| character.is_ascii_hexdigit()));

        let key_path = temp_dir.path().join("secret.key");
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), first);

        let second = load_or_create_key_material(temp_dir.path()).unwrap();
        assert_eq!(second, first);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn loading_for_decryption_never_creates_a_replacement_key() {
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("secret.key");

        assert!(load_existing_key_material(temp_dir.path()).is_err());
        assert!(!key_path.exists());

        let created = load_or_create_key_material(temp_dir.path()).unwrap();
        assert_eq!(
            load_existing_key_material(temp_dir.path()).unwrap(),
            created
        );
    }

    #[cfg(unix)]
    #[test]
    fn secret_key_rejects_symlinks_and_permissive_existing_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp_dir = tempfile::tempdir().unwrap();
        let target = temp_dir.path().join("target");
        std::fs::write(&target, "0".repeat(64)).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, temp_dir.path().join("secret.key")).unwrap();
        assert!(load_or_create_key_material(temp_dir.path())
            .unwrap_err()
            .contains("non-symlink"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "0".repeat(64));

        std::fs::remove_file(temp_dir.path().join("secret.key")).unwrap();
        std::fs::write(temp_dir.path().join("secret.key"), "0".repeat(64)).unwrap();
        std::fs::set_permissions(
            temp_dir.path().join("secret.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(load_or_create_key_material(temp_dir.path())
            .unwrap_err()
            .contains("mode 0600"));
    }
}
