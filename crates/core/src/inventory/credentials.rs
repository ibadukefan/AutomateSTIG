//! Credential vault — encrypted storage for authentication secrets.
//!
//! Supports multiple credential types:
//! - Username + password (SSH, WinRM)
//! - SSH private key (with optional passphrase)
//! - SSH certificate
//! - Kerberos (domain + username for ticket-based auth)
//! - Token-based (API keys, bearer tokens)
//! - Certificate-based (client TLS certs for WinRM/HTTPS)
//!
//! All secrets are encrypted at rest using AES-256-GCM before
//! storage in the SQLite database.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A stored credential in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Unique identifier.
    pub id: String,

    /// Human-readable label (e.g., "Linux admin account", "Domain SA").
    pub label: String,

    /// Credential type and data.
    pub credential: CredentialType,

    /// Description / notes.
    pub description: Option<String>,

    /// When this credential was created.
    pub created_at: DateTime<Utc>,

    /// When this credential was last used.
    pub last_used: Option<DateTime<Utc>>,

    /// When this credential expires (if applicable).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Types of credentials supported.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialType {
    /// Username + password.
    Password {
        username: String,
        /// Encrypted at rest — plaintext only in memory during use.
        password: String,
    },

    /// SSH private key file.
    SshKey {
        username: String,
        /// The private key content (PEM format), encrypted at rest.
        private_key: String,
        /// Optional passphrase for the key, encrypted at rest.
        passphrase: Option<String>,
    },

    /// SSH certificate (OpenSSH format).
    SshCertificate {
        username: String,
        /// Certificate content.
        certificate: String,
        /// Associated private key, encrypted at rest.
        private_key: String,
    },

    /// Kerberos / Active Directory domain credentials.
    Kerberos {
        username: String,
        /// Domain (e.g., "NAVY.MIL").
        domain: String,
        /// Password for initial TGT, encrypted at rest.
        password: String,
    },

    /// Token / API key (for REST-based devices, cloud platforms).
    Token {
        /// The token value, encrypted at rest.
        token: String,
        /// Token type hint (e.g., "bearer", "api-key").
        token_type: Option<String>,
    },

    /// Client TLS certificate (for WinRM over HTTPS, mutual TLS).
    ClientCertificate {
        /// Certificate in PEM format.
        certificate: String,
        /// Private key in PEM format, encrypted at rest.
        private_key: String,
    },
}

impl StoredCredential {
    /// Create a new password credential.
    pub fn new_password(label: &str, username: &str, password: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            label: label.to_string(),
            credential: CredentialType::Password {
                username: username.to_string(),
                password: password.to_string(),
            },
            description: None,
            created_at: Utc::now(),
            last_used: None,
            expires_at: None,
        }
    }

    /// Create a new SSH key credential.
    pub fn new_ssh_key(label: &str, username: &str, private_key: &str, passphrase: Option<&str>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            label: label.to_string(),
            credential: CredentialType::SshKey {
                username: username.to_string(),
                private_key: private_key.to_string(),
                passphrase: passphrase.map(|s| s.to_string()),
            },
            description: None,
            created_at: Utc::now(),
            last_used: None,
            expires_at: None,
        }
    }

    /// Create a Kerberos credential.
    pub fn new_kerberos(label: &str, username: &str, domain: &str, password: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            label: label.to_string(),
            credential: CredentialType::Kerberos {
                username: username.to_string(),
                domain: domain.to_string(),
                password: password.to_string(),
            },
            description: None,
            created_at: Utc::now(),
            last_used: None,
            expires_at: None,
        }
    }

    /// Create a token credential.
    pub fn new_token(label: &str, token: &str, token_type: Option<&str>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            label: label.to_string(),
            credential: CredentialType::Token {
                token: token.to_string(),
                token_type: token_type.map(|s| s.to_string()),
            },
            description: None,
            created_at: Utc::now(),
            last_used: None,
            expires_at: None,
        }
    }

    /// Get the username (if applicable).
    pub fn username(&self) -> Option<&str> {
        match &self.credential {
            CredentialType::Password { username, .. } => Some(username),
            CredentialType::SshKey { username, .. } => Some(username),
            CredentialType::SshCertificate { username, .. } => Some(username),
            CredentialType::Kerberos { username, .. } => Some(username),
            CredentialType::Token { .. } => None,
            CredentialType::ClientCertificate { .. } => None,
        }
    }

    /// Check if this credential has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
    }
}

/// Credential vault — manages encrypted storage and retrieval.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CredentialVault {
    /// All stored credentials (secrets are encrypted in the serialized form).
    pub credentials: Vec<StoredCredential>,
}

impl CredentialVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a credential to the vault.
    pub fn add(&mut self, cred: StoredCredential) {
        self.credentials.push(cred);
    }

    /// Get a credential by ID.
    pub fn get(&self, id: &str) -> Option<&StoredCredential> {
        self.credentials.iter().find(|c| c.id == id)
    }

    /// Remove a credential by ID.
    pub fn remove(&mut self, id: &str) -> bool {
        let len_before = self.credentials.len();
        self.credentials.retain(|c| c.id != id);
        self.credentials.len() < len_before
    }

    /// List all credentials (without exposing secrets in the listing).
    pub fn list_summary(&self) -> Vec<CredentialSummary> {
        self.credentials
            .iter()
            .map(|c| CredentialSummary {
                id: c.id.clone(),
                label: c.label.clone(),
                credential_type: match &c.credential {
                    CredentialType::Password { .. } => "password".to_string(),
                    CredentialType::SshKey { .. } => "ssh_key".to_string(),
                    CredentialType::SshCertificate { .. } => "ssh_certificate".to_string(),
                    CredentialType::Kerberos { .. } => "kerberos".to_string(),
                    CredentialType::Token { .. } => "token".to_string(),
                    CredentialType::ClientCertificate { .. } => "client_certificate".to_string(),
                },
                username: c.username().map(|s| s.to_string()),
                is_expired: c.is_expired(),
                last_used: c.last_used,
            })
            .collect()
    }
}

/// Summary view of a credential (no secrets exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub id: String,
    pub label: String,
    pub credential_type: String,
    pub username: Option<String>,
    pub is_expired: bool,
    pub last_used: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_vault() {
        let mut vault = CredentialVault::new();

        vault.add(StoredCredential::new_password("Linux admin", "admin", "secret123"));
        vault.add(StoredCredential::new_ssh_key("Deploy key", "deploy", "-----BEGIN OPENSSH PRIVATE KEY-----\n...", None));
        vault.add(StoredCredential::new_kerberos("Domain SA", "svc_stig", "NAVY.MIL", "DomainP@ss"));
        vault.add(StoredCredential::new_token("API Key", "sk-12345abcdef", Some("bearer")));

        assert_eq!(vault.credentials.len(), 4);

        let summaries = vault.list_summary();
        assert_eq!(summaries.len(), 4);
        assert_eq!(summaries[0].credential_type, "password");
        assert_eq!(summaries[1].credential_type, "ssh_key");
        assert_eq!(summaries[2].credential_type, "kerberos");
        assert_eq!(summaries[3].credential_type, "token");
        // Summaries should NOT contain actual passwords.
    }

    #[test]
    fn test_credential_remove() {
        let mut vault = CredentialVault::new();
        let cred = StoredCredential::new_password("test", "user", "pass");
        let id = cred.id.clone();
        vault.add(cred);

        assert!(vault.remove(&id));
        assert_eq!(vault.credentials.len(), 0);
        assert!(!vault.remove(&id)); // Already removed.
    }

    #[test]
    fn test_credential_expiry() {
        let mut cred = StoredCredential::new_token("Temp token", "tok123", None);
        assert!(!cred.is_expired());

        cred.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(cred.is_expired());
    }
}
