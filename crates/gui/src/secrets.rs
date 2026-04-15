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
//! - A random component stored in the database itself

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

const APP_SALT: &[u8] = b"AutomateSTIG-secret-encryption-v1";

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
    let data = hex::decode(hex_ciphertext)
        .map_err(|e| format!("Invalid hex: {}", e))?;

    if data.len() < 12 + 16 {
        return Err("Ciphertext too short".to_string());
    }

    let key_bytes = derive_key(db_key_material);
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|e| format!("Key creation failed: {}", e))?;
    let key = LessSafeKey::new(unbound_key);

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::assume_unique_for_key(
        nonce_bytes.try_into().map_err(|_| "Invalid nonce".to_string())?,
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

    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if !hex.len().is_multiple_of(&2) {
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
}
