//! STIG-Manager API client.
//!
//! Connects to a running STIG-Manager instance via its REST API.
//! Supports OAuth2 authentication (via Keycloak) using Client Credentials flow.
//!
//! Key operations:
//! - List collections, assets, STIGs
//! - Push evaluation results (reviews) with Result Engine metadata
//! - Sparse scanner-result delivery to existing assigned assets

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const MAX_STIGMAN_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const STIGMAN_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

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
    #[serde(default)]
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

    /// Validate a possibly-empty persisted configuration.
    ///
    /// Both endpoints may be blank while STIG Manager is unconfigured, but a
    /// partial endpoint pair is never accepted.
    pub fn validate_urls(&self) -> Result<(), String> {
        if self.api_url.trim().is_empty() && self.token_url.trim().is_empty() {
            return Ok(());
        }
        if self.api_url.trim().is_empty() || self.token_url.trim().is_empty() {
            return Err(
                "STIG Manager api_url and token_url must both be set or both be blank".to_string(),
            );
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
        validate_stigman_url("STIG Manager API", &self.api_url)?;
        validate_stigman_url("OAuth token", &self.token_url)?;
        Ok(())
    }
}

/// Whether an environment variable is enabled with a truthy value.
fn env_flag(name: &str) -> bool {
    crate::outbound::env_flag(name)
}

fn stigman_allowlist_entries() -> Vec<String> {
    crate::outbound::allowlist_entries("AUTOMATESTIG_STIGMAN_TARGET_ALLOWLIST")
}

fn allowlist_matches_stigman_destination(host: &str, ip: Option<IpAddr>) -> bool {
    let entries = stigman_allowlist_entries();
    !entries.is_empty() && crate::outbound::host_or_ip_matches_allowlist(host, ip, &entries)
}

/// Validate an outbound STIG Manager/OIDC URL before secrets are sent to it.
///
/// Production defaults are intentionally conservative: HTTPS only, no embedded
/// credentials, and no localhost/private/link-local literal destinations unless
/// AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS is explicitly set for an isolated lab.
pub(crate) fn validate_stigman_url(label: &str, raw: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(raw).map_err(|e| format!("Invalid {label}: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("{label} must use https://"));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(format!(
            "{label} must not include embedded credentials or a fragment"
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("{label} must include a host"))?;
    let host_for_ip = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if crate::outbound::hostname_is_local_or_metadata(host_for_ip) {
        return Err(format!("{label} host is not allowed: {host_for_ip}"));
    }
    if let Ok(ip) = host_for_ip.parse::<std::net::IpAddr>() {
        if crate::outbound::is_invalid_ip(ip) {
            return Err(format!(
                "{label} uses an invalid, reserved, multicast, or documentation literal address"
            ));
        }
        if crate::outbound::is_private_or_local_ip(ip)
            && !allowlist_matches_stigman_destination(host_for_ip, Some(ip))
            && !env_flag("AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS")
        {
            return Err(format!(
                "{label} resolves to a private/local literal address; set AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS=1 only in an isolated lab"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedStigmanEndpoint {
    host: String,
    addresses: Vec<SocketAddr>,
}

async fn resolve_stigman_endpoint(
    label: &str,
    raw: &str,
) -> Result<ResolvedStigmanEndpoint, String> {
    let allowlist = stigman_allowlist_entries();
    let allow_private = env_flag("AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_DESTINATIONS")
        || env_flag("AUTOMATESTIG_ALLOW_PRIVATE_STIGMAN_URLS");
    resolve_stigman_endpoint_with(
        label,
        raw,
        &allowlist,
        allow_private,
        |host, port| async move {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|addresses| addresses.collect())
        },
    )
    .await
}

async fn resolve_stigman_endpoint_with<F, Fut>(
    label: &str,
    raw: &str,
    allowlist: &[String],
    allow_private: bool,
    resolver: F,
) -> Result<ResolvedStigmanEndpoint, String>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    validate_stigman_url(label, raw)?;
    let url = reqwest::Url::parse(raw).map_err(|e| format!("Invalid {label}: {e}"))?;
    let raw_host = url
        .host_str()
        .ok_or_else(|| format!("{label} must include a host"))?;
    let host = raw_host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(raw_host)
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let lookup = tokio::time::timeout(STIGMAN_CONNECT_TIMEOUT, resolver(host.clone(), port))
        .await
        .map_err(|_| {
            format!(
                "{label} host {host} resolution timed out after {} seconds",
                STIGMAN_CONNECT_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| format!("Failed to resolve {label} host {host}: {error}"))?;
    authorize_stigman_addresses_with_policy(label, &host, port, lookup, allowlist, allow_private)
}

fn authorize_stigman_addresses_with_policy(
    label: &str,
    host: &str,
    port: u16,
    addresses: Vec<SocketAddr>,
    allowlist: &[String],
    allow_private: bool,
) -> Result<ResolvedStigmanEndpoint, String> {
    let mut unique = Vec::with_capacity(addresses.len());
    for address in addresses {
        if address.port() != port {
            return Err(format!(
                "{label} resolver returned unexpected port {} for {host}:{port}",
                address.port()
            ));
        }
        if !unique.contains(&address) {
            unique.push(address);
        }
    }
    if unique.is_empty() {
        return Err(format!("{label} host {host} resolved to no addresses"));
    }
    let ips = unique.iter().map(SocketAddr::ip).collect::<Vec<_>>();
    crate::outbound::validate_resolved_ips_with_policy(
        label,
        host,
        &ips,
        allowlist,
        allow_private,
    )?;
    Ok(ResolvedStigmanEndpoint {
        host: host.to_string(),
        addresses: unique,
    })
}

/// OAuth2 token with expiry tracking.
struct TokenCache {
    access_token: String,
    expires_at: Instant,
}

/// STIG-Manager API client.
pub struct StigManagerClient {
    config: StigManagerConfig,
    api_http: reqwest::Client,
    token_http: reqwest::Client,
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
    #[serde(default)]
    pub collection: Option<SmAssetCollection>,
    #[serde(default)]
    pub stigs: Vec<SmStig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SmAssetCollection {
    #[serde(rename = "collectionId")]
    pub collection_id: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmStig {
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(rename = "revisionStr", alias = "lastRevisionStr", default)]
    pub revision_str: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmResultEngine {
    #[serde(rename = "type")]
    pub engine_type: String,
    pub product: String,
    pub version: String,
    pub time: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SmExistingReview {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub result: String,
    #[serde(rename = "autoResult", default)]
    pub auto_result: bool,
    pub status: SmReviewStatus,
    #[serde(rename = "resultEngine", default)]
    pub result_engine: Option<SmResultEngine>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum SmReviewStatus {
    Label(String),
    Object { label: String },
}

impl SmReviewStatus {
    fn label(&self) -> &str {
        match self {
            Self::Label(label) | Self::Object { label } => label,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SmReviewConflict {
    pub rule_id: String,
    pub reason: String,
    pub existing_result: String,
    pub existing_status: String,
    pub existing_engine: Option<String>,
}

// --- Token response ---

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

async fn parse_response<T: DeserializeOwned>(
    mut response: reqwest::Response,
    operation: &str,
) -> Result<T, String> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_STIGMAN_RESPONSE_BYTES as u64)
    {
        return Err(format!(
            "{operation} response exceeds the {MAX_STIGMAN_RESPONSE_BYTES}-byte limit"
        ));
    }
    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(MAX_STIGMAN_RESPONSE_BYTES);
    let mut body = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("Failed to read {operation} response: {error}"))?
    {
        if chunk.len() > MAX_STIGMAN_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(format!(
                "{operation} response exceeds the {MAX_STIGMAN_RESPONSE_BYTES}-byte limit"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let detail: String = String::from_utf8_lossy(&body).chars().take(2_000).collect();
        return Err(format!("{operation} failed ({status}): {detail}"));
    }
    serde_json::from_slice(&body)
        .map_err(|error| format!("Failed to parse {operation} response: {error}"))
}

fn build_stigman_http_client(
    endpoint: &ResolvedStigmanEndpoint,
    accept_invalid_certs: bool,
) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(STIGMAN_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // A process-level proxy would bypass the pinned socket destination.
        .no_proxy()
        .danger_accept_invalid_certs(accept_invalid_certs)
        .user_agent(format!("AutomateSTIG/{}", env!("CARGO_PKG_VERSION")))
        .resolve_to_addrs(&endpoint.host, &endpoint.addresses)
        .build()
        .map_err(|error| format!("HTTP client error: {error}"))
}

impl StigManagerClient {
    /// Resolve and authorize both configured endpoints once, then create
    /// clients whose DNS maps are pinned to those numeric addresses.
    pub async fn new(config: StigManagerConfig) -> Result<Self, String> {
        config.validate_endpoints()?;
        let allow_invalid_certs = env_flag("AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS");
        let accept_invalid_certs = !config.verify_tls && allow_invalid_certs;
        if accept_invalid_certs {
            tracing::warn!(
                "STIG-Manager TLS certificate verification disabled via AUTOMATESTIG_ALLOW_INVALID_STIGMAN_CERTS"
            );
        }

        let api_endpoint = resolve_stigman_endpoint("STIG Manager API", &config.api_url).await?;
        let token_endpoint = resolve_stigman_endpoint("OAuth token", &config.token_url).await?;
        let api_http = build_stigman_http_client(&api_endpoint, accept_invalid_certs)?;
        let token_http = build_stigman_http_client(&token_endpoint, accept_invalid_certs)?;

        Ok(Self {
            config,
            api_http,
            token_http,
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
            .token_http
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Token request failed: {}", e))?;

        let token_resp: TokenResponse = parse_response(resp, "Authentication").await?;

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
        guard
            .as_ref()
            .map(|t| t.access_token.clone())
            .ok_or_else(|| "Authentication succeeded without caching an access token".to_string())
    }

    /// Test the connection — authenticate and fetch user info.
    pub async fn test_connection(&self) -> Result<String, String> {
        self.authenticate().await?;
        let token = self.get_token().await?;

        let resp = self
            .api_http
            .get(format!("{}/user", self.config.api_url))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("Connection test failed: {}", e))?;

        let body: serde_json::Value = parse_response(resp, "Connection test").await?;
        let username = body["username"].as_str().unwrap_or("unknown");
        Ok(format!("Connected as: {}", username))
    }

    /// List all collections the user has access to.
    pub async fn list_collections(&self) -> Result<Vec<SmCollection>, String> {
        let token = self.get_token().await?;

        let resp = self
            .api_http
            .get(format!("{}/collections", self.config.api_url))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        parse_response(resp, "List collections").await
    }

    /// List assets in a collection.
    pub async fn list_assets(&self, collection_id: &str) -> Result<Vec<SmAsset>, String> {
        let token = self.get_token().await?;

        let mut url = reqwest::Url::parse(&format!("{}/assets", self.config.api_url))
            .map_err(|error| format!("Invalid STIG Manager assets URL: {error}"))?;
        url.query_pairs_mut()
            .append_pair("collectionId", collection_id)
            .append_pair("projection", "stigs");

        let resp = self
            .api_http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        parse_response(resp, "List assets").await
    }

    /// List STIGs assigned to an asset.
    pub async fn list_asset_stigs(
        &self,
        collection_id: &str,
        asset_id: &str,
    ) -> Result<Vec<SmStig>, String> {
        let token = self.get_token().await?;

        let asset_id = parse_numeric_identifier("asset ID", asset_id)?;
        let mut url = reqwest::Url::parse(&format!("{}/assets/{asset_id}", self.config.api_url))
            .map_err(|error| format!("Invalid STIG Manager asset URL: {error}"))?;
        url.query_pairs_mut().append_pair("projection", "stigs");

        let resp = self
            .api_http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let asset: SmAsset = parse_response(resp, "Get asset assignments").await?;
        let actual_collection = asset
            .collection
            .as_ref()
            .map(|collection| collection.collection_id.as_str())
            .or(asset.collection_id.as_deref());
        if actual_collection != Some(collection_id) {
            return Err(format!(
                "STIG Manager asset {asset_id} does not belong to collection {collection_id}"
            ));
        }
        Ok(asset.stigs)
    }

    /// Return current reviews so delivery can refuse to overwrite human work.
    pub async fn list_asset_reviews(
        &self,
        collection_id: &str,
        asset_id: &str,
    ) -> Result<Vec<SmExistingReview>, String> {
        let token = self.get_token().await?;
        let collection_id = parse_numeric_identifier("collection ID", collection_id)?;
        let asset_id = parse_numeric_identifier("asset ID", asset_id)?;
        let mut url = reqwest::Url::parse(&format!(
            "{}/collections/{collection_id}/reviews",
            self.config.api_url
        ))
        .map_err(|error| format!("Invalid STIG Manager reviews URL: {error}"))?;
        url.query_pairs_mut()
            .append_pair("assetId", asset_id)
            .append_pair("rules", "mapped");

        let resp = self
            .api_http
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|error| format!("Request failed: {error}"))?;

        parse_response(resp, "List asset reviews").await
    }

    /// Push reviews (evaluation results) for an asset+STIG in a collection.
    pub async fn push_reviews(
        &self,
        collection_id: &str,
        asset_id: &str,
        reviews: Vec<SmReview>,
    ) -> Result<serde_json::Value, String> {
        let token = self.get_token().await?;
        let collection_id = parse_numeric_identifier("collection ID", collection_id)?;
        let asset_id = parse_numeric_identifier("asset ID", asset_id)?;

        let resp = self
            .api_http
            .post(format!(
                "{}/collections/{}/reviews/{}",
                self.config.api_url, collection_id, asset_id
            ))
            .bearer_auth(&token)
            .json(&reviews)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        // STIG-Manager returns stats on success.
        parse_response(resp, "Push reviews").await
    }

    /// Convert only evidence-owned machine determinations to STIG Manager
    /// reviews. Manual, imported, answer-file, collection-error, and untouched
    /// Not Reviewed rows belong to STIG Manager and are intentionally omitted.
    pub fn checklist_to_reviews(
        checklist: &automatestig_core::models::checklist::Checklist,
    ) -> Vec<SmReview> {
        use automatestig_core::models::finding::{FindingSource, FindingStatus};

        checklist
            .findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.source,
                    FindingSource::Automated | FindingSource::Evidence
                ) && finding.status != FindingStatus::NotReviewed
            })
            .map(|f| {
                let is_automated = f.source == FindingSource::Automated;

                SmReview {
                    rule_id: f.rule_id.clone(),
                    result: f.status.as_stig_manager_str().to_string(),
                    detail: f.finding_details.clone(),
                    comment: f.comments.clone(),
                    auto_result: is_automated,
                    status: "saved".to_string(),
                    // Supplied evidence is conservatively not marked as an
                    // autoResult, but the deterministic evaluator still owns
                    // the result and identifies itself for safe future retries.
                    result_engine: Some(SmResultEngine {
                        engine_type: "script".to_string(),
                        product: "AutomateSTIG".to_string(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        time: Some(f.evaluated_at.to_rfc3339()),
                    }),
                }
            })
            .collect()
    }
}

fn parse_numeric_identifier<'a>(label: &str, value: &'a str) -> Result<&'a str, String> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("STIG Manager {label} must be a numeric identifier"));
    }
    Ok(value)
}

/// Identify remote reviews that cannot be safely replaced by this scanner.
/// Only a saved review whose result engine is AutomateSTIG is scanner-owned.
pub fn scanner_review_conflicts(
    proposed: &[SmReview],
    existing: &[SmExistingReview],
) -> Vec<SmReviewConflict> {
    let existing_by_rule: HashMap<&str, &SmExistingReview> = existing
        .iter()
        .map(|review| (review.rule_id.as_str(), review))
        .collect();

    proposed
        .iter()
        .filter_map(|review| {
            let existing = existing_by_rule.get(review.rule_id.as_str())?;
            let status = existing.status.label();
            let engine = existing
                .result_engine
                .as_ref()
                .map(|engine| engine.product.clone());
            let owned = status == "saved"
                && engine
                    .as_deref()
                    .is_some_and(|product| product.eq_ignore_ascii_case("AutomateSTIG"));
            if owned {
                return None;
            }

            Some(SmReviewConflict {
                rule_id: review.rule_id.clone(),
                reason: if status != "saved" {
                    format!("remote review is {status}, not saved")
                } else {
                    "remote review is not owned by AutomateSTIG".to_string()
                },
                existing_result: existing.result.clone(),
                existing_status: status.to_string(),
                existing_engine: engine,
            })
        })
        .collect()
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
        assert!(configured.validate_urls().is_ok());
        assert!(configured.validate_endpoints().is_ok());
        assert!(empty.validate_urls().is_ok());
        assert!(empty.validate_endpoints().is_err());
    }

    #[test]
    fn endpoints_require_https_and_reject_userinfo_or_fragments() {
        for invalid in [
            "http://stigman.example.mil/api",
            "http://127.0.0.1:54000/api",
            "https://user:secret@stigman.example.mil/api",
            "https://stigman.example.mil/api#fragment",
            "file:///tmp/token",
        ] {
            assert!(validate_stigman_url("test", invalid).is_err());
        }
        assert!(validate_stigman_url("test", "https://stigman.example.mil/api").is_ok());
    }

    #[tokio::test]
    async fn chunked_response_is_stopped_at_the_running_size_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
                )
                .await
                .unwrap();
            let chunk = vec![b'x'; 1024 * 1024];
            for _ in 0..=MAX_STIGMAN_RESPONSE_BYTES / chunk.len() {
                if stream
                    .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
                    .await
                    .is_err()
                {
                    return;
                }
                if stream.write_all(&chunk).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
        });

        let response = reqwest::Client::new()
            .get(format!("http://{address}/oversized"))
            .send()
            .await
            .unwrap();
        let error = parse_response::<serde_json::Value>(response, "Chunked test")
            .await
            .unwrap_err();
        assert!(error.contains("exceeds"), "unexpected error: {error}");
        server.await.unwrap();
    }

    #[test]
    fn validate_stigman_urls_reject_unsafe_destinations() {
        for raw in [
            "http://stigman.example.mil/api",
            "https://user:pass@stigman.example.mil/api",
            "https://localhost/api",
            "https://127.0.0.1/api",
            "https://10.0.0.5/api",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/api",
            "https://0.0.0.0/api",
            "https://192.0.2.1/api",
            "https://224.0.0.1/api",
            "https://[::]/api",
            "https://[2001:db8::1]/api",
            "https://[ff02::1]/api",
            "not-a-url",
        ] {
            assert!(
                validate_stigman_url("api_url", raw).is_err(),
                "{raw} should be rejected"
            );
        }
    }

    #[test]
    fn validate_stigman_allows_private_literal_when_exact_allowlisted() {
        assert!(crate::outbound::host_or_ip_matches_allowlist(
            "10.10.1.5",
            Some("10.10.1.5".parse().unwrap()),
            &["10.10.1.5".to_string()]
        ));
    }

    #[test]
    fn validate_stigman_urls_accept_public_https_hosts() {
        validate_stigman_url("api_url", "https://stigman.example.mil/api").unwrap();
        validate_stigman_url(
            "token_url",
            "https://keycloak.example.mil/realms/stigman/protocol/openid-connect/token",
        )
        .unwrap();
    }

    #[test]
    fn authorized_endpoint_pins_addresses_under_the_original_hostname() {
        let addresses = vec![
            "8.8.8.8:443".parse().unwrap(),
            "8.8.4.4:443".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        ];
        let endpoint = authorize_stigman_addresses_with_policy(
            "api_url",
            "stigman.example.mil",
            443,
            addresses,
            &["stigman.example.mil".to_string()],
            false,
        )
        .unwrap();
        assert_eq!(endpoint.host, "stigman.example.mil");
        assert_eq!(
            endpoint.addresses,
            vec![
                "8.8.8.8:443".parse().unwrap(),
                "8.8.4.4:443".parse().unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn endpoint_resolution_runs_once_and_retains_url_host_for_tls() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let endpoint = resolve_stigman_endpoint_with(
            "token_url",
            "https://keycloak.example.mil:8443/oauth/token",
            &["keycloak.example.mil".to_string()],
            false,
            move |host, port| async move {
                assert_eq!(host, "keycloak.example.mil");
                assert_eq!(port, 8443);
                resolver_calls.fetch_add(1, Ordering::SeqCst);
                Ok(vec!["8.8.8.8:8443".parse().unwrap()])
            },
        )
        .await
        .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(endpoint.host, "keycloak.example.mil");
        assert_eq!(endpoint.addresses, vec!["8.8.8.8:8443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn pinned_client_preserves_host_header_and_does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let size = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/must-not-follow\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            String::from_utf8_lossy(&request[..size]).into_owned()
        });

        let endpoint = ResolvedStigmanEndpoint {
            host: "pinned.example.test".to_string(),
            addresses: vec![address],
        };
        let client = build_stigman_http_client(&endpoint, false).unwrap();
        let response = client
            .get(format!(
                "http://pinned.example.test:{}/start",
                address.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);

        let request = server.await.unwrap().to_ascii_lowercase();
        assert!(
            request.contains(&format!(
                "\r\nhost: pinned.example.test:{}\r\n",
                address.port()
            )),
            "unexpected request: {request}"
        );
    }

    #[test]
    fn authorized_endpoint_rejects_unlisted_public_and_private_rebinding() {
        let unlisted = authorize_stigman_addresses_with_policy(
            "api_url",
            "unlisted.example.mil",
            443,
            vec!["8.8.8.8:443".parse().unwrap()],
            &["stigman.example.mil".to_string()],
            false,
        )
        .unwrap_err();
        assert!(unlisted.contains("unlisted"));

        let private_rebind = authorize_stigman_addresses_with_policy(
            "api_url",
            "stigman.example.mil",
            443,
            vec!["10.10.1.5:443".parse().unwrap()],
            &["stigman.example.mil".to_string()],
            false,
        )
        .unwrap_err();
        assert!(private_rebind.contains("private/local/link-local"));

        authorize_stigman_addresses_with_policy(
            "api_url",
            "stigman.example.mil",
            443,
            vec!["10.10.1.5:443".parse().unwrap()],
            &[
                "stigman.example.mil".to_string(),
                "10.10.0.0/16".to_string(),
            ],
            false,
        )
        .unwrap();
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
        f.source = FindingSource::Automated;
        f.finding_details = "Not configured".to_string();
        cl.findings.push(f);

        let mut f2 =
            Finding::new_not_reviewed("V-2", "SV-2r1_rule", "V-2", "Test2", Severity::Medium);
        f2.status = FindingStatus::NotAFinding;
        f2.source = FindingSource::Manual;
        cl.findings.push(f2);

        let reviews = StigManagerClient::checklist_to_reviews(&cl);
        assert_eq!(reviews.len(), 1);

        assert_eq!(reviews[0].rule_id, "SV-1r1_rule");
        assert_eq!(reviews[0].result, "fail");
        assert!(reviews[0].auto_result);
        assert!(reviews[0].result_engine.is_some());
    }

    #[test]
    fn supplied_evidence_is_delivered_as_scanner_owned_but_not_auto_result() {
        use automatestig_core::models::asset::Asset;
        use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
        use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};
        use automatestig_core::models::stig::Severity;

        let mut checklist = Checklist::new(
            Asset::new("router01"),
            ChecklistStigInfo {
                stig_id: "Cisco_STIG".to_string(),
                title: "Cisco".to_string(),
                version: "1".to_string(),
                release: "1".to_string(),
                release_date: None,
                uuid: None,
                description: None,
                filename: None,
            },
        );
        let mut finding =
            Finding::new_not_reviewed("V-1", "SV-1_rule", "V-1", "Evidence rule", Severity::Medium);
        finding.source = FindingSource::Evidence;
        finding.status = FindingStatus::Open;
        checklist.findings.push(finding);

        let reviews = StigManagerClient::checklist_to_reviews(&checklist);
        assert_eq!(reviews.len(), 1);
        assert!(!reviews[0].auto_result);
        assert_eq!(
            reviews[0].result_engine.as_ref().unwrap().product,
            "AutomateSTIG"
        );
    }

    #[test]
    fn conflict_detection_protects_human_and_submitted_reviews() {
        let proposed = vec![SmReview {
            rule_id: "SV-1_rule".to_string(),
            result: "fail".to_string(),
            detail: "evidence".to_string(),
            comment: String::new(),
            auto_result: true,
            status: "saved".to_string(),
            result_engine: Some(SmResultEngine {
                engine_type: "script".to_string(),
                product: "AutomateSTIG".to_string(),
                version: "0.3.0".to_string(),
                time: None,
            }),
        }];

        let human = vec![SmExistingReview {
            rule_id: "SV-1_rule".to_string(),
            result: "pass".to_string(),
            auto_result: false,
            status: SmReviewStatus::Object {
                label: "saved".to_string(),
            },
            result_engine: None,
        }];
        assert_eq!(scanner_review_conflicts(&proposed, &human).len(), 1);

        let submitted_ours = vec![SmExistingReview {
            rule_id: "SV-1_rule".to_string(),
            result: "fail".to_string(),
            auto_result: true,
            status: SmReviewStatus::Object {
                label: "submitted".to_string(),
            },
            result_engine: proposed[0].result_engine.clone(),
        }];
        assert_eq!(
            scanner_review_conflicts(&proposed, &submitted_ours).len(),
            1
        );

        let saved_ours = vec![SmExistingReview {
            rule_id: "SV-1_rule".to_string(),
            result: "pass".to_string(),
            auto_result: true,
            status: SmReviewStatus::Label("saved".to_string()),
            result_engine: proposed[0].result_engine.clone(),
        }];
        assert!(scanner_review_conflicts(&proposed, &saved_ours).is_empty());
    }

    #[test]
    fn stig_manager_ids_are_numeric_before_becoming_path_segments() {
        assert_eq!(parse_numeric_identifier("asset ID", " 42 ").unwrap(), "42");
        assert!(parse_numeric_identifier("asset ID", "../42").is_err());
        assert!(parse_numeric_identifier("asset ID", "asset-42").is_err());
    }
}
