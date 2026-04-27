//! Ed25519 signing and verification for .stigpack files.
//!
//! Signs the manifest.json content with an Ed25519 private key.
//! Verification uses the corresponding public key.
//!
//! Key management:
//! - Keys are generated as PEM files
//! - The public key is embedded in the application (for official packs)
//! - Users can add trusted public keys for third-party packs

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{StigpackError, StigpackResult};

/// Generate a new Ed25519 keypair for signing stigpacks.
/// Returns (private_key_bytes, public_key_bytes).
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let signing_key = random_signing_key();
    let verifying_key = signing_key.verifying_key();
    (signing_key.to_bytes(), verifying_key.to_bytes())
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
        if !dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pub") {
                if let Ok(bytes) = std::fs::read(&path) {
                    if bytes.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes);
                        let label = path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();
                        self.add_key(&label, key);
                        count += 1;
                    }
                }
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
        for key in &self.keys {
            match verify_signature(manifest_json, signature_bytes, &key.public_key) {
                Ok(true) => return Ok(Some(key.label.clone())),
                _ => continue,
            }
        }
        Ok(None)
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
fn random_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    // Use ring's SystemRandom for secure key generation.
    let rng = ring::rand::SystemRandom::new();
    ring::rand::SecureRandom::fill(&rng, &mut seed).expect("OS RNG failed");
    SigningKey::from_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (private_key, public_key) = generate_keypair();
        let manifest = b"{ \"pack_id\": \"test\", \"version\": \"1.0\" }";

        let signature = sign_manifest(manifest, &private_key).unwrap();
        assert_eq!(signature.len(), 64); // Ed25519 signatures are 64 bytes.

        let valid = verify_signature(manifest, &signature, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_invalid_signature() {
        let (private_key, public_key) = generate_keypair();
        let manifest = b"{ \"pack_id\": \"test\" }";

        let signature = sign_manifest(manifest, &private_key).unwrap();

        // Tamper with the manifest.
        let tampered = b"{ \"pack_id\": \"evil\" }";
        let valid = verify_signature(tampered, &signature, &public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_wrong_key() {
        let (private_key, _) = generate_keypair();
        let (_, other_public) = generate_keypair();
        let manifest = b"test data";

        let signature = sign_manifest(manifest, &private_key).unwrap();
        let valid = verify_signature(manifest, &signature, &other_public).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_trust_store() {
        let (private_key, public_key) = generate_keypair();
        let manifest = b"test manifest";
        let signature = sign_manifest(manifest, &private_key).unwrap();

        let mut store = TrustStore::new();
        store.add_key("official", public_key);

        let result = store.verify_against_trusted(manifest, &signature).unwrap();
        assert_eq!(result, Some("official".to_string()));
    }

    #[test]
    fn test_trust_store_no_match() {
        let (private_key, _) = generate_keypair();
        let (_, other_public) = generate_keypair();
        let manifest = b"test";
        let signature = sign_manifest(manifest, &private_key).unwrap();

        let mut store = TrustStore::new();
        store.add_key("other", other_public);

        let result = store.verify_against_trusted(manifest, &signature).unwrap();
        assert_eq!(result, None);
    }
}
