//! STIG-Manager API client.
//!
//! Connects to a running STIG-Manager instance via its REST API.
//! Supports OAuth2 authentication (via Keycloak) using Client Credentials flow.
//!
//! Key operations:
//! - List collections, assets, STIGs
//! - Push evaluation results (reviews) with Result Engine metadata
//! - Create assets and assign STIGs
//! - Pull existing reviews for comparison/merge

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// STIG-Manager connection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StigManagerConfig {
    /// STIG-Manager base URL (e.g., "https://stigman.example.mil/api").
    pub api_url: String,

    /// Keycloak/OIDC token endpoint for OAuth2.
    pub token_url: String,

    /// OAuth2 Client ID.
    pub client_id: String,

    /// OAuth2 Client Secret.
    pub client_secret: String,

    /// Collection ID to push to (if set as default).
    pub default_collection_id: Option<String>,

    /// Whether to verify TLS certificates (disable for self-signed).
    pub verify_tls: bool,
}

impl Default for StigManagerConfig {
    fn default() -> Self {
        Self {
            api_url: String::new(),
            token_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            default_collection_id: None,
            verify_tls: true,
        }
    }
}

impl StigManagerConfig {
    pub fn is_configured(&self) -> bool {
        !self.api_url.is_empty()
            && !self.token_url.is_empty()
            && !self.client_id.is_empty()
            && !self.client_secret.is_empty()
    }
}

/// OAuth2 token with expiry tracking.
struct TokenCache {
    access_token: String,
    expires_at: Instant,
}

/// STIG-Manager API client.
pub struct StigManagerClient {
    config: StigManagerConfig,
    http: reqwest::Client,
    token: tokio::sync::Mutex<Option<TokenCache>>,
}

// --- API response types ---

#[derive(Debug, Serialize, Deserialize)]
pub struct SmCollection {
    #[serde(rename = "collectionId")]
    pub collection_id: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub assets: usize,
    #[serde(default)]
    pub stigs: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmAsset {
    #[serde(rename = "assetId")]
    pub asset_id: String,
    pub name: String,
    pub fqdn: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "collectionId")]
    pub collection_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmStig {
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    pub title: Option<String>,
    #[serde(rename = "lastRevisionStr")]
    pub last_revision_str: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmReview {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub result: String,
    pub detail: String,
    pub comment: String,
    #[serde(rename = "autoResult")]
    pub auto_result: bool,
    pub status: String,
    #[serde(rename = "resultEngine", skip_serializing_if = "Option::is_none")]
    pub result_engine: Option<SmResultEngine>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmResultEngine {
    #[serde(rename = "type")]
    pub engine_type: String,
    pub product: String,
    pub version: String,
    #[serde(rename = "checkContent", skip_serializing_if = "Option::is_none")]
    pub check_content: Option<SmCheckContent>,
    pub time: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmCheckContent {
    pub location: Option<String>,
    pub component: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmReviewPost {
    pub source: SmReviewSource,
    pub assets: Vec<SmAssetReviews>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmReviewSource {
    pub benchmark: String,
    pub results: Vec<SmReview>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmAssetReviews {
    #[serde(rename = "assetId")]
    pub asset_id: String,
    pub reviews: Vec<SmReview>,
}

/// Result of a push operation.
#[derive(Debug, Serialize, Deserialize)]
pub struct PushResult {
    pub inserted: usize,
    pub updated: usize,
    pub unchanged: usize,
}

// --- Token response ---

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
    #[allow(dead_code)]
    token_type: Option<String>,
}

impl StigManagerClient {
    /// Create a new client with the given configuration.
    pub fn new(config: StigManagerConfig) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(!config.verify_tls)
            .user_agent(format!("AutomateSTIG/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("HTTP client error: {}", e))?;

        Ok(Self {
            config,
            http,
            token: tokio::sync::Mutex::new(None),
        })
    }

    /// Authenticate via OAuth2 Client Credentials flow.
    async fn authenticate(&self) -> Result<(), String> {
        // Check if existing token is still valid.
        {
            let guard = self.token.lock().await;
            if let Some(ref cache) = *guard {
                if Instant::now() < cache.expires_at {
                    return Ok(());
                }
            }
        }

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let resp = self
            .http
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Token request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Authentication failed ({}): {}", status, body));
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| format!("Token parse error: {}", e))?;

        let expires_in = token_resp.expires_in.unwrap_or(300);
        // Refresh 30 seconds before actual expiry.
        let expires_at = Instant::now() + Duration::from_secs(expires_in.saturating_sub(30));

        let mut guard = self.token.lock().await;
        *guard = Some(TokenCache {
            access_token: token_resp.access_token,
            expires_at,
        });

        Ok(())
    }

    /// Get the current access token, authenticating if needed.
    async fn get_token(&self) -> Result<String, String> {
        self.authenticate().await?;
        let guard = self.token.lock().await;
        Ok(guard
            .as_ref()
            .map(|t| t.access_token.clone())
            .unwrap_or_default())
    }

    /// Test the connection — authenticate and fetch user info.
    pub async fn test_connection(&self) -> Result<String, String> {
        self.authenticate().await?;
        let token = self.get_token().await?;

        let resp = self
            .http
            .get(format!("{}/user", self.config.api_url))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("Connection test failed: {}", e))?;

        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            let username = body["username"].as_str().unwrap_or("unknown");
            Ok(format!("Connected as: {}", username))
        } else {
            Err(format!("API returned {}", resp.status()))
        }
    }

    /// List all collections the user has access to.
    pub async fn list_collections(&self) -> Result<Vec<SmCollection>, String> {
        let token = self.get_token().await?;

        let resp = self
            .http
            .get(format!("{}/collections", self.config.api_url))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        resp.json().await.map_err(|e| format!("Parse error: {}", e))
    }

    /// List assets in a collection.
    pub async fn list_assets(&self, collection_id: &str) -> Result<Vec<SmAsset>, String> {
        let token = self.get_token().await?;

        let resp = self
            .http
            .get(format!(
                "{}/collections/{}/assets",
                self.config.api_url, collection_id
            ))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        resp.json().await.map_err(|e| format!("Parse error: {}", e))
    }

    /// List STIGs assigned to an asset.
    pub async fn list_asset_stigs(
        &self,
        collection_id: &str,
        asset_id: &str,
    ) -> Result<Vec<SmStig>, String> {
        let token = self.get_token().await?;

        let resp = self
            .http
            .get(format!(
                "{}/collections/{}/assets/{}/stigs",
                self.config.api_url, collection_id, asset_id
            ))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        resp.json().await.map_err(|e| format!("Parse error: {}", e))
    }

    /// Create an asset in a collection.
    pub async fn create_asset(
        &self,
        collection_id: &str,
        name: &str,
        fqdn: Option<&str>,
        ip: Option<&str>,
    ) -> Result<SmAsset, String> {
        let token = self.get_token().await?;

        let body = serde_json::json!({
            "name": name,
            "collectionId": collection_id,
            "fqdn": fqdn,
            "ip": ip,
        });

        let resp = self
            .http
            .post(format!(
                "{}/collections/{}/assets",
                self.config.api_url, collection_id
            ))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Create asset failed ({}): {}", status, body));
        }

        resp.json().await.map_err(|e| format!("Parse error: {}", e))
    }

    /// Push reviews (evaluation results) for an asset+STIG in a collection.
    pub async fn push_reviews(
        &self,
        collection_id: &str,
        asset_id: &str,
        benchmark_id: &str,
        reviews: Vec<SmReview>,
    ) -> Result<PushResult, String> {
        let token = self.get_token().await?;

        let body = serde_json::json!({
            "reviews": reviews,
        });

        let resp = self
            .http
            .put(format!(
                "{}/collections/{}/assets/{}/stigs/{}/reviews",
                self.config.api_url, collection_id, asset_id, benchmark_id
            ))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Push reviews failed ({}): {}", status, body));
        }

        // STIG-Manager returns stats on success.
        resp.json().await.map_err(|e| format!("Parse error: {}", e))
    }

    /// Convert an AutomateSTIG checklist to STIG-Manager reviews.
    pub fn checklist_to_reviews(
        checklist: &automatestig_core::models::checklist::Checklist,
    ) -> Vec<SmReview> {
        checklist
            .findings
            .iter()
            .map(|f| {
                let is_automated = matches!(
                    f.source,
                    automatestig_core::models::finding::FindingSource::Automated
                        | automatestig_core::models::finding::FindingSource::SccScan
                        | automatestig_core::models::finding::FindingSource::AcasScan
                        | automatestig_core::models::finding::FindingSource::OpenScap
                        | automatestig_core::models::finding::FindingSource::CustomCheck
                );

                SmReview {
                    rule_id: f.rule_id.clone(),
                    result: f.status.as_stig_manager_str().to_string(),
                    detail: f.finding_details.clone(),
                    comment: f.comments.clone(),
                    auto_result: is_automated,
                    status: "saved".to_string(),
                    result_engine: if is_automated {
                        Some(SmResultEngine {
                            engine_type: "script".to_string(),
                            product: "AutomateSTIG".to_string(),
                            version: env!("CARGO_PKG_VERSION").to_string(),
                            check_content: None,
                            time: Some(f.evaluated_at.to_rfc3339()),
                        })
                    } else {
                        None
                    },
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_is_configured() {
        let empty = StigManagerConfig::default();
        assert!(!empty.is_configured());

        let configured = StigManagerConfig {
            api_url: "https://stigman.example.mil/api".to_string(),
            token_url: "https://keycloak.example.mil/realms/stigman/protocol/openid-connect/token"
                .to_string(),
            client_id: "automatestig".to_string(),
            client_secret: "secret123".to_string(),
            default_collection_id: None,
            verify_tls: true,
        };
        assert!(configured.is_configured());
    }

    #[test]
    fn test_checklist_to_reviews() {
        use automatestig_core::models::asset::Asset;
        use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
        use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};
        use automatestig_core::models::stig::Severity;

        let stig_info = ChecklistStigInfo {
            stig_id: "Test_STIG".to_string(),
            title: "Test".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            uuid: None,
            description: None,
            filename: None,
        };

        let mut cl = Checklist::new(Asset::new("server01"), stig_info);
        let mut f = Finding::new_not_reviewed("V-1", "SV-1r1_rule", "V-1", "Test", Severity::High);
        f.status = FindingStatus::Open;
        f.source = FindingSource::SccScan;
        f.finding_details = "Not configured".to_string();
        cl.findings.push(f);

        let mut f2 =
            Finding::new_not_reviewed("V-2", "SV-2r1_rule", "V-2", "Test2", Severity::Medium);
        f2.status = FindingStatus::NotAFinding;
        f2.source = FindingSource::Manual;
        cl.findings.push(f2);

        let reviews = StigManagerClient::checklist_to_reviews(&cl);
        assert_eq!(reviews.len(), 2);

        assert_eq!(reviews[0].rule_id, "SV-1r1_rule");
        assert_eq!(reviews[0].result, "fail");
        assert!(reviews[0].auto_result);
        assert!(reviews[0].result_engine.is_some());

        assert_eq!(reviews[1].rule_id, "SV-2r1_rule");
        assert_eq!(reviews[1].result, "pass");
        assert!(!reviews[1].auto_result);
        assert!(reviews[1].result_engine.is_none());
    }
}
