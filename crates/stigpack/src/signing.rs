//! Ed25519 signing and verification for .stigpack files.
//!
//! Signs the manifest.json content with an Ed25519 private key.
//! Verification uses the corresponding public key.
//!
//! Key management uses raw 32-byte private seeds and public keys. Users add
//! approved `.pub` files to the configured trust directory.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;

use crate::{StigpackError, StigpackResult};

/// Generate a new Ed25519 keypair for signing stigpacks.
/// Returns (private_key_bytes, public_key_bytes).
pub fn generate_keypair() -> StigpackResult<([u8; 32], [u8; 32])> {
    let signing_key = random_signing_key()?;
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key.to_bytes(), verifying_key.to_bytes()))
}

/// Load an existing external signing key and its adjacent public trust anchor.
///
/// This function never creates or writes key material. Production pack
/// builders use it so signing-key generation remains an explicit offline key
/// ceremony rather than a side effect of running AutomateSTIG.
pub fn load_signing_key_pair(
    private_path: &Path,
    public_path: &Path,
) -> StigpackResult<([u8; 32], [u8; 32])> {
    if private_path == public_path {
        return Err(StigpackError::SignatureError(
            "signing private and public key paths must be different".to_string(),
        ));
    }
    if !path_exists_without_following(private_path)? {
        return Err(StigpackError::SignatureError(format!(
            "signing private key does not exist; generate it in an offline key ceremony: {}",
            private_path.display()
        )));
    }
    if !path_exists_without_following(public_path)? {
        return Err(StigpackError::SignatureError(format!(
            "signing public trust anchor does not exist: {}",
            public_path.display()
        )));
    }
    let private_key = read_fixed_key(private_path, true)?;
    let public_key = read_fixed_key(public_path, false)?;
    let derived = SigningKey::from_bytes(&private_key)
        .verifying_key()
        .to_bytes();
    if derived != public_key {
        return Err(StigpackError::SignatureError(format!(
            "signing private key does not match its public trust anchor: {}",
            public_path.display()
        )));
    }
    Ok((private_key, public_key))
}

/// Explicitly create a new external signing key pair.
///
/// Both paths must be absent. This is intended for an operator-invoked offline
/// key ceremony, never as an implicit pack-build or GUI side effect.
pub fn create_signing_key_pair(
    private_path: &Path,
    public_path: &Path,
) -> StigpackResult<([u8; 32], [u8; 32])> {
    if private_path == public_path {
        return Err(StigpackError::SignatureError(
            "signing private and public key paths must be different".to_string(),
        ));
    }
    if path_exists_without_following(private_path)? || path_exists_without_following(public_path)? {
        return Err(StigpackError::SignatureError(format!(
            "refusing to replace existing signing key material: {} or {}",
            private_path.display(),
            public_path.display()
        )));
    }
    secure_parent(private_path)?;
    secure_parent(public_path)?;
    let (private_key, public_key) = generate_keypair()?;
    write_private_key(private_path, &private_key)?;
    if let Err(error) = write_public_key(public_path, &public_key) {
        let _ = std::fs::remove_file(private_path);
        return Err(error.into());
    }
    Ok((private_key, public_key))
}

/// Stable human-verifiable identifier for an Ed25519 public key.
pub fn public_key_fingerprint(public_key: &[u8; 32]) -> String {
    format!("SHA256:{:x}", Sha256::digest(public_key))
}

fn path_exists_without_following(path: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn secure_parent(path: &Path) -> StigpackResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StigpackError::SignatureError(format!(
            "key parent must be a real directory: {}",
            parent.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(StigpackError::SignatureError(format!(
                "key directory must be owned by the current user and not group/world writable: {}",
                parent.display()
            )));
        }
    }
    #[cfg(windows)]
    automatestig_core::path_safety::validate_sensitive_directory(parent, "key directory")
        .map_err(|error| StigpackError::SignatureError(error.to_string()))?;
    Ok(())
}

fn read_fixed_key(path: &Path, private: bool) -> StigpackResult<[u8; 32]> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StigpackError::SignatureError(format!(
            "key must be a regular non-symlink file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let allowed_owner =
            metadata.uid() == unsafe { libc::geteuid() } || (!private && metadata.uid() == 0);
        let forbidden_mode = if private { 0o077 } else { 0o022 };
        if !allowed_owner || metadata.permissions().mode() & forbidden_mode != 0 {
            return Err(StigpackError::SignatureError(format!(
                "{} key has unsafe ownership or permissions: {}",
                if private { "private" } else { "public" },
                path.display()
            )));
        }
    }

    let policy = if private {
        automatestig_core::path_safety::SensitiveFilePolicy::Private
    } else {
        #[cfg(windows)]
        {
            automatestig_core::path_safety::SensitiveFilePolicy::IntegrityProtected
        }
        #[cfg(not(windows))]
        {
            // Unix intentionally permits root-owned public trust anchors; the
            // metadata checks above retain that policy.
            automatestig_core::path_safety::SensitiveFilePolicy::UntrustedInput
        }
    };
    let file = automatestig_core::path_safety::open_sensitive_file(
        path,
        if private {
            "private signing key"
        } else {
            "public trust anchor"
        },
        policy,
    )
    .map_err(|error| StigpackError::SignatureError(error.to_string()))?;
    let mut bytes = Vec::with_capacity(33);
    file.take(33).read_to_end(&mut bytes)?;
    if bytes.len() != 32 {
        return Err(StigpackError::SignatureError(format!(
            "signing key must contain exactly 32 bytes: {}",
            path.display()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn write_private_key(path: &Path, bytes: &[u8; 32]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    automatestig_core::path_safety::configure_no_follow(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    automatestig_core::path_safety::validate_open_sensitive_file(
        &file,
        path,
        "private signing key",
        automatestig_core::path_safety::SensitiveFilePolicy::Private,
    )
    .map_err(std::io::Error::other)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn write_public_key(path: &Path, bytes: &[u8; 32]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    automatestig_core::path_safety::configure_no_follow(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    automatestig_core::path_safety::validate_open_sensitive_file(
        &file,
        path,
        "public trust anchor",
        automatestig_core::path_safety::SensitiveFilePolicy::IntegrityProtected,
    )
    .map_err(std::io::Error::other)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Sign manifest content with an Ed25519 private key.
pub fn sign_manifest(
    manifest_json: &[u8],
    private_key_bytes: &[u8; 32],
) -> StigpackResult<Vec<u8>> {
    let signing_key = SigningKey::from_bytes(private_key_bytes);

    // Sign the SHA-256 hash of the manifest (deterministic).
    let mut hasher = Sha256::new();
    hasher.update(manifest_json);
    let hash = hasher.finalize();

    let signature = signing_key.sign(&hash);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a signature against manifest content and a public key.
pub fn verify_signature(
    manifest_json: &[u8],
    signature_bytes: &[u8],
    public_key_bytes: &[u8; 32],
) -> StigpackResult<bool> {
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| StigpackError::SignatureError(format!("Invalid public key: {}", e)))?;

    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| StigpackError::SignatureError(format!("Invalid signature: {}", e)))?;

    // Verify against SHA-256 hash of manifest.
    let mut hasher = Sha256::new();
    hasher.update(manifest_json);
    let hash = hasher.finalize();

    match verifying_key.verify(&hash, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// A set of trusted public keys for signature verification.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    /// Trusted public keys (32-byte Ed25519 public keys).
    keys: Vec<TrustedKey>,
}

/// A trusted public key with metadata.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// Key identifier / label.
    pub label: String,
    /// The 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted key.
    pub fn add_key(&mut self, label: &str, public_key: [u8; 32]) {
        self.keys.push(TrustedKey {
            label: label.to_string(),
            public_key,
        });
    }

    /// Load trusted keys from a directory (one .pub file per key).
    pub fn load_from_directory(&mut self, dir: &std::path::Path) -> std::io::Result<usize> {
        let metadata = match std::fs::symlink_metadata(dir) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("trust store must be a real directory: {}", dir.display()),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let owner_ok = metadata.uid() == unsafe { libc::geteuid() } || metadata.uid() == 0;
            if !owner_ok || metadata.permissions().mode() & 0o022 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "trust store must be owned by the current user or root and not group/world writable: {}",
                        dir.display()
                    ),
                ));
            }
        }
        #[cfg(windows)]
        let _directory_custody =
            automatestig_core::path_safety::validate_sensitive_directory(dir, "trust store")
                .map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
                })?;

        let mut count = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pub") {
                let key = read_fixed_key(&path, false).map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                })?;
                let label = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                self.add_key(&label, key);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Verify a signature against all trusted keys. Returns the label of
    /// the matching key if verification succeeds.
    pub fn verify_against_trusted(
        &self,
        manifest_json: &[u8],
        signature_bytes: &[u8],
    ) -> StigpackResult<Option<String>> {
        Ok(self
            .verify_against_trusted_identity(manifest_json, signature_bytes)?
            .map(|(label, _)| label))
    }

    /// Verify and return both the local label and cryptographic key fingerprint.
    pub fn verify_against_trusted_identity(
        &self,
        manifest_json: &[u8],
        signature_bytes: &[u8],
    ) -> StigpackResult<Option<(String, String)>> {
        Ok(self
            .verify_against_trusted_key(manifest_json, signature_bytes)?
            .map(|key| (key.label.clone(), public_key_fingerprint(&key.public_key))))
    }

    pub(crate) fn verify_against_trusted_key(
        &self,
        manifest_json: &[u8],
        signature_bytes: &[u8],
    ) -> StigpackResult<Option<&TrustedKey>> {
        for key in &self.keys {
            match verify_signature(manifest_json, signature_bytes, &key.public_key) {
                Ok(true) => return Ok(Some(key)),
                Ok(false) | Err(_) => continue,
            }
        }
        Ok(None)
    }

    /// Public key material used by runtime executable-content verification.
    pub fn public_keys(&self) -> Vec<[u8; 32]> {
        self.keys.iter().map(|key| key.public_key).collect()
    }

    /// Number of trusted keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the trust store is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Generate a random signing key using OS randomness.
fn random_signing_key() -> StigpackResult<SigningKey> {
    let mut seed = [0u8; 32];
    // Use ring's SystemRandom for secure key generation.
    let rng = ring::rand::SystemRandom::new();
    ring::rand::SecureRandom::fill(&rng, &mut seed)
        .map_err(|_| StigpackError::SignatureError("OS random generator failed".to_string()))?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (private_key, public_key) = generate_keypair().unwrap();
        let manifest = b"{ \"pack_id\": \"test\", \"version\": \"1.0\" }";

        let signature = sign_manifest(manifest, &private_key).unwrap();
        assert_eq!(signature.len(), 64); // Ed25519 signatures are 64 bytes.

        let valid = verify_signature(manifest, &signature, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_invalid_signature() {
        let (private_key, public_key) = generate_keypair().unwrap();
        let manifest = b"{ \"pack_id\": \"test\" }";

        let signature = sign_manifest(manifest, &private_key).unwrap();

        // Tamper with the manifest.
        let tampered = b"{ \"pack_id\": \"evil\" }";
        let valid = verify_signature(tampered, &signature, &public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_wrong_key() {
        let (private_key, _) = generate_keypair().unwrap();
        let (_, other_public) = generate_keypair().unwrap();
        let manifest = b"test data";

        let signature = sign_manifest(manifest, &private_key).unwrap();
        let valid = verify_signature(manifest, &signature, &other_public).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_trust_store() {
        let (private_key, public_key) = generate_keypair().unwrap();
        let manifest = b"test manifest";
        let signature = sign_manifest(manifest, &private_key).unwrap();

        let mut store = TrustStore::new();
        store.add_key("official", public_key);

        let result = store.verify_against_trusted(manifest, &signature).unwrap();
        assert_eq!(result, Some("official".to_string()));
    }

    #[test]
    fn test_trust_store_no_match() {
        let (private_key, _) = generate_keypair().unwrap();
        let (_, other_public) = generate_keypair().unwrap();
        let manifest = b"test";
        let signature = sign_manifest(manifest, &private_key).unwrap();

        let mut store = TrustStore::new();
        store.add_key("other", other_public);

        let result = store.verify_against_trusted(manifest, &signature).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn explicit_creation_refuses_overwrite_and_pair_is_reusable() {
        let dir = tempfile::TempDir::new().unwrap();
        let private = dir.path().join("signing/content.key");
        let public = dir.path().join("trusted/content.pub");
        let first = create_signing_key_pair(&private, &public).unwrap();
        assert!(create_signing_key_pair(&private, &public).is_err());
        let second = load_signing_key_pair(&private, &public).unwrap();
        assert_eq!(first, second);
        assert_eq!(std::fs::read(public).unwrap().len(), 32);
    }

    #[test]
    fn load_signing_key_pair_never_creates_missing_keys() {
        let dir = tempfile::TempDir::new().unwrap();
        let private = dir.path().join("offline/content.key");
        let public = dir.path().join("offline/content.pub");
        assert!(load_signing_key_pair(&private, &public).is_err());
        assert!(!private.exists());
        assert!(!public.exists());

        secure_parent(&private).unwrap();
        let (private_bytes, public_bytes) = generate_keypair().unwrap();
        write_private_key(&private, &private_bytes).unwrap();
        write_public_key(&public, &public_bytes).unwrap();
        assert_eq!(
            load_signing_key_pair(&private, &public).unwrap(),
            (private_bytes, public_bytes)
        );
    }

    #[test]
    fn loading_refuses_missing_or_mismatched_key_pair() {
        let dir = tempfile::TempDir::new().unwrap();
        let private = dir.path().join("signing/content.key");
        let public = dir.path().join("trusted/content.pub");
        create_signing_key_pair(&private, &public).unwrap();

        std::fs::remove_file(&private).unwrap();
        let error = load_signing_key_pair(&private, &public).unwrap_err();
        assert!(error.to_string().contains("does not exist"));

        let (replacement, _) = generate_keypair().unwrap();
        std::fs::create_dir_all(private.parent().unwrap()).unwrap();
        write_private_key(&private, &replacement).unwrap();
        let error = load_signing_key_pair(&private, &public).unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_private_and_trust_keys() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().unwrap();
        let target = dir.path().join("target.key");
        std::fs::write(&target, [7u8; 32]).unwrap();
        let private = dir.path().join("content.key");
        let public = dir.path().join("content.pub");
        symlink(&target, &private).unwrap();
        std::fs::write(&public, [8u8; 32]).unwrap();
        assert!(load_signing_key_pair(&private, &public)
            .unwrap_err()
            .to_string()
            .contains("non-symlink"));

        let trust = dir.path().join("trust");
        std::fs::create_dir(&trust).unwrap();
        symlink(&target, trust.join("evil.pub")).unwrap();
        assert!(TrustStore::new().load_from_directory(&trust).is_err());
    }
}
