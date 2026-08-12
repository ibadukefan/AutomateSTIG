//! Persisted STIG Manager connection settings shared by the GUI and the
//! canonical scanner-delivery client.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Persisted GUI connection settings.
///
/// This DTO intentionally retains the established on-disk JSON field names so
/// existing encrypted GUI configuration remains readable. It contains no HTTP
/// behavior; live requests are made only through the canonical
/// [`super::StigManagerClient`], which always verifies TLS certificates.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StigManagerConfig {
    /// STIG Manager API base URL, normally ending in `/api`.
    pub api_url: String,
    /// Tested browser GUI base URL on the same HTTPS origin as `api_url`.
    ///
    /// STIG Manager 1.6.13+1 does not expose safe asset/review deep-link
    /// routes; callers may open only this unparameterized base URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gui_url: Option<String>,
    /// OAuth/OIDC client-credentials token endpoint.
    pub token_url: String,
    /// OAuth client identifier.
    pub client_id: String,
    /// OAuth client secret, encrypted by the GUI before persistence.
    pub client_secret: String,
    /// Previously selected collection retained only as a UI convenience.
    #[serde(default)]
    pub default_collection_id: Option<String>,
    /// Compatibility field from the established persisted schema.
    ///
    /// Production scanner connections require this to remain `true`; neither
    /// this DTO nor the canonical client implements an invalid-certificate
    /// bypass.
    #[serde(default = "tls_verification_enabled")]
    pub verify_tls: bool,
}

impl Default for StigManagerConfig {
    fn default() -> Self {
        Self {
            api_url: String::new(),
            gui_url: None,
            token_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            default_collection_id: None,
            verify_tls: true,
        }
    }
}

impl fmt::Debug for StigManagerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StigManagerConfig")
            .field("api_url", &self.api_url)
            .field("gui_url", &self.gui_url)
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("default_collection_id", &self.default_collection_id)
            .field("verify_tls", &self.verify_tls)
            .finish()
    }
}

impl StigManagerConfig {
    /// Whether all credentials needed for a connection are present.
    pub fn is_configured(&self) -> bool {
        !self.api_url.trim().is_empty()
            && !self.token_url.trim().is_empty()
            && !self.client_id.trim().is_empty()
            && !self.client_secret.trim().is_empty()
    }

    /// Validate a possibly-empty persisted endpoint pair.
    ///
    /// Both endpoints may be blank while STIG Manager is unconfigured, but a
    /// partial pair is rejected. Any configured connection must retain TLS
    /// certificate verification.
    pub fn validate_urls(&self) -> Result<(), String> {
        if self.api_url.trim().is_empty() && self.token_url.trim().is_empty() {
            return Ok(());
        }
        self.validate_endpoints()
    }

    /// Validate the complete endpoint pair required by a live client.
    pub fn validate_endpoints(&self) -> Result<(), String> {
        if self.api_url.trim().is_empty() || self.token_url.trim().is_empty() {
            return Err(
                "STIG Manager api_url and token_url must both be set for a connection".to_string(),
            );
        }
        if !self.verify_tls {
            return Err(
                "STIG Manager connections require TLS certificate verification".to_string(),
            );
        }
        super::client::validate_endpoint_url("STIG Manager API", &self.api_url)
            .map_err(|error| error.to_string())?;
        super::client::validate_endpoint_url("OAuth token", &self.token_url)
            .map_err(|error| error.to_string())?;
        if let Some(gui_url) = self.gui_url.as_deref() {
            let gui = super::client::validate_endpoint_url("STIG Manager GUI", gui_url)
                .map_err(|error| error.to_string())?;
            let api = reqwest::Url::parse(&self.api_url)
                .map_err(|error| format!("invalid STIG Manager API URL: {error}"))?;
            if gui.scheme() != api.scheme()
                || gui.host_str() != api.host_str()
                || gui.port_or_known_default() != api.port_or_known_default()
            {
                return Err(
                    "STIG Manager GUI URL must use the same HTTPS origin as api_url".to_string(),
                );
            }
            if gui.path().is_empty() || !gui.path().ends_with('/') {
                return Err(
                    "STIG Manager GUI URL must be an unparameterized base URL ending in /"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

const fn tls_verification_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> StigManagerConfig {
        StigManagerConfig {
            api_url: "https://stigman.example.mil/api".to_string(),
            gui_url: Some("https://stigman.example.mil/".to_string()),
            token_url: "https://identity.example.mil/oauth/token".to_string(),
            client_id: "automatestig".to_string(),
            client_secret: "decrypted-only-in-memory".to_string(),
            default_collection_id: Some("7".to_string()),
            verify_tls: true,
        }
    }

    #[test]
    fn established_persisted_json_schema_round_trips_without_drift() {
        let raw = r#"{"api_url":"https://stigman.example.mil/api","token_url":"https://identity.example.mil/oauth/token","client_id":"automatestig","client_secret":"enc:ciphertext","default_collection_id":"7","verify_tls":true}"#;
        let config: StigManagerConfig = serde_json::from_str(raw).unwrap();
        let serialized = serde_json::to_value(&config).unwrap();

        assert_eq!(
            serialized,
            serde_json::json!({
                "api_url": "https://stigman.example.mil/api",
                "token_url": "https://identity.example.mil/oauth/token",
                "client_id": "automatestig",
                "client_secret": "enc:ciphertext",
                "default_collection_id": "7",
                "verify_tls": true,
            })
        );
    }

    #[test]
    fn missing_legacy_tls_field_defaults_to_verification_enabled() {
        let config: StigManagerConfig = serde_json::from_str(
            r#"{"api_url":"","token_url":"","client_id":"","client_secret":"","default_collection_id":null}"#,
        )
        .unwrap();

        assert!(config.verify_tls);
    }

    #[test]
    fn configured_endpoints_are_https_and_tls_verification_is_mandatory() {
        let mut config = configured();
        assert!(config.is_configured());
        assert!(config.validate_urls().is_ok());

        config.verify_tls = false;
        assert!(config
            .validate_endpoints()
            .unwrap_err()
            .contains("TLS certificate verification"));

        config.verify_tls = true;
        for unsafe_url in [
            "http://stigman.example.mil/api",
            "https://user:secret@stigman.example.mil/api",
            "https://stigman.example.mil/api?redirect=elsewhere",
            "https://localhost/api",
        ] {
            config.api_url = unsafe_url.to_string();
            assert!(
                config.validate_endpoints().is_err(),
                "accepted {unsafe_url}"
            );
        }
    }

    #[test]
    fn debug_output_never_exposes_the_client_secret() {
        let rendered = format!("{:?}", configured());
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("decrypted-only-in-memory"));
    }
}
