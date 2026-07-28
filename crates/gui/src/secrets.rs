//! Secret encryption at rest.
//!
//! Encrypts sensitive configuration values (OAuth2 client secrets, API keys)
//! before storing them in the SQLite database. Uses AES-256-GCM with a key
//! derived from machine-specific data.
//!
//! This isn't HSM-level security, but it prevents casual reading of secrets
//! from the database file. The encryption key is derived from:
//! - A fixed application salt
//! - The hostname of the machine
//! - A 32-byte CSPRNG random component stored outside the database in a 0600
//!   file at `<data_dir>/secret.key`

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const APP_SALT: &[u8] = b"AutomateSTIG-secret-encryption-v1";

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
