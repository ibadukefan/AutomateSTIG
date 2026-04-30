//! AutomateSTIG Desktop GUI.
//!
//! Launches a local web server and opens the browser to the UI.
//! All communication is localhost-only — no external network calls.

mod api;
pub mod disa;
pub mod secrets;
pub mod ssh;
mod state;
pub mod stigman;
pub mod winrm;

use std::net::SocketAddr;

use automatestig_core::checks::CheckPlatform;
use automatestig_core::inventory::assets::{ManagedAsset, ScanProtocol};
use automatestig_core::models::asset::Asset;
use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};
use automatestig_core::models::stig::Severity;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use chrono::Utc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::EnvFilter;

use state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Initialize application state.
    let state = AppState::init().expect("Failed to initialize application state");

    // Clone for background checker before moving into router.
    let bg_state = state.clone();

    // Bind address: PORT may set the port for hosted platforms, but it does not
    // enable demo mode. Network exposure and demo behavior must be explicit.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    let bind_host = std::env::var("AUTOMATESTIG_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let bind_ip: std::net::IpAddr = bind_host
        .parse()
        .expect("AUTOMATESTIG_BIND must be an IP address such as 127.0.0.1 or 0.0.0.0");
    let demo_mode = std::env::var("AUTOMATESTIG_DEMO")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    seed_demo_data(&state, demo_mode);

    let addr = SocketAddr::from((bind_ip, port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");
    let local_addr = listener.local_addr().expect("Failed to get local address");
    let url = format!("http://{}", local_addr);

    // Generate auth token. Server/non-loopback mode requires an explicit token;
    // desktop localhost and explicit demo mode get a random per-session token.
    let is_loopback = bind_ip.is_loopback();
    let auth_token = resolve_auth_token(
        std::env::var("AUTOMATESTIG_AUTH_TOKEN").ok(),
        is_loopback,
        demo_mode,
    )
    .expect("Invalid AutomateSTIG auth configuration");
    let auth_token_for_middleware = auth_token.clone();

    // Build the router with security layers:
    // 1. CORS restricted to same origin
    // 2. Request body limit (100 MB)
    // 3. Auth token verification on /api routes
    let app = Router::new()
        .nest("/api", api::routes())
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let token = auth_token_for_middleware.clone();
            async move {
                // Allow unauthenticated health checks for hosted/demo deployments.
                if req.uri().path() == "/api/status" {
                    return Ok::<Response, std::convert::Infallible>(next.run(req).await);
                }

                // Only check auth on /api routes, not frontend static files.
                if req.uri().path().starts_with("/api") {
                    // Check header first, then query param (for download links).
                    let header_token = req
                        .headers()
                        .get("X-Auth-Token")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let query_token = req
                        .uri()
                        .query()
                        .and_then(|q| q.split('&').find_map(|p| p.strip_prefix("token=")))
                        .unwrap_or("")
                        .to_string();

                    if header_token != token && query_token != token {
                        return Ok(axum::response::IntoResponse::into_response((
                            axum::http::StatusCode::UNAUTHORIZED,
                            "Invalid or missing auth token",
                        )));
                    }
                }
                Ok::<Response, std::convert::Infallible>(next.run(req).await)
            }
        }))
        .fallback({
            let token = if is_loopback || demo_mode {
                Some(auth_token.clone())
            } else {
                None
            };
            move |uri: axum::http::Uri| {
                let t = token.clone();
                async move { serve_frontend_with_token(uri, t.as_deref()) }
            }
        })
        .layer(RequestBodyLimitLayer::new(100 * 1024 * 1024)) // 100 MB
        .layer({
            let mut cors = CorsLayer::new()
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any);
            if is_loopback {
                cors = cors.allow_origin(AllowOrigin::exact(
                    url.parse().expect("Failed to parse origin"),
                ));
            }
            cors
        })
        .with_state(state);
    eprintln!();
    eprintln!("  AutomateSTIG v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  GUI running at: {}", url);
    if demo_mode {
        eprintln!("  Demo data: enabled via AUTOMATESTIG_DEMO");
    }
    eprintln!("  Press Ctrl+C to stop.");
    eprintln!();

    // Start background STIG update checker (every 24 hours) only if
    // the user has opted in via agent config. Air-gapped by default.
    tokio::spawn(async move {
        // Check if background updates are enabled in config.
        let enabled = bg_state
            .db()
            .get_config("auto_update_enabled")
            .ok()
            .flatten()
            .map(|v| v == "true")
            .unwrap_or(false);

        if enabled {
            tracing::info!("Background STIG update checker enabled");
            disa::start_background_checker(bg_state, 24).await;
        } else {
            tracing::info!(
                "Background update checker disabled (air-gapped mode). Enable in Settings."
            );
        }
    });

    // Open browser (skip in demo/hosted mode).
    if !demo_mode && is_loopback {
        if let Err(e) = open::that(&url) {
            eprintln!("  Could not open browser: {}", e);
            eprintln!("  Open {} manually.", url);
        }
    }

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("  Server error: {}", e);
        std::process::exit(1);
    }
}

fn seed_demo_data(state: &AppState, demo_mode: bool) {
    if !demo_mode {
        return;
    }

    let db = state.db();

    if db.get_config("demo_seeded").ok().flatten().as_deref() == Some("true") {
        return;
    }

    let mut assets = vec![
        ManagedAsset::new(
            "WEB-APP-01",
            "10.10.20.15",
            CheckPlatform::Windows,
            ScanProtocol::Winrm,
        ),
        ManagedAsset::new(
            "DB-CORE-01",
            "10.10.30.22",
            CheckPlatform::Linux,
            ScanProtocol::Ssh,
        ),
        ManagedAsset::new(
            "EDGE-GW-01",
            "10.10.1.1",
            CheckPlatform::CiscoIos,
            ScanProtocol::Ssh,
        ),
    ];

    assets[0].id = "demo-asset-web-01".to_string();
    assets[0].assigned_stigs = vec![
        "Windows_Server_2022_STIG".to_string(),
        "IIS_10.0_STIG".to_string(),
    ];
    assets[0].tags = vec![
        "production".to_string(),
        "web".to_string(),
        "windows".to_string(),
    ];
    assets[0].os_info = Some("Windows Server 2022 Datacenter".to_string());
    assets[0].notes = Some("Demo IIS web application server".to_string());
    assets[0].last_compliance_pct = Some(91.2);
    assets[0].last_evaluated = Some(Utc::now());

    assets[1].id = "demo-asset-db-01".to_string();
    assets[1].assigned_stigs = vec!["RHEL_9_STIG".to_string(), "PostgreSQL_14_STIG".to_string()];
    assets[1].tags = vec![
        "production".to_string(),
        "database".to_string(),
        "linux".to_string(),
    ];
    assets[1].os_info = Some("Red Hat Enterprise Linux 9".to_string());
    assets[1].notes = Some("Demo PostgreSQL database host".to_string());
    assets[1].last_compliance_pct = Some(87.4);
    assets[1].last_evaluated = Some(Utc::now());

    assets[2].id = "demo-asset-net-01".to_string();
    assets[2].assigned_stigs = vec!["Cisco_IOS_STIG".to_string()];
    assets[2].tags = vec![
        "network".to_string(),
        "edge".to_string(),
        "production".to_string(),
    ];
    assets[2].os_info = Some("Cisco IOS XE 17.x".to_string());
    assets[2].notes = Some("Demo branch edge gateway".to_string());
    assets[2].last_compliance_pct = Some(94.8);
    assets[2].last_evaluated = Some(Utc::now());

    if let Ok(json) = serde_json::to_string(&assets) {
        let _ = db.set_config("asset_inventory", &json);
    }

    let checklists = vec![
        sample_checklist(
            "WEB-APP-01",
            "Windows_Server_2022_STIG",
            "Microsoft Windows Server 2022 STIG",
            "1",
            "4",
            vec![
                (
                    "V-254239",
                    "SV-254239r958388_rule",
                    "TLS 1.2 must be enabled",
                    Severity::High,
                    FindingStatus::Open,
                ),
                (
                    "V-254281",
                    "SV-254281r958514_rule",
                    "Audit logon events must be configured",
                    Severity::Medium,
                    FindingStatus::Open,
                ),
                (
                    "V-254300",
                    "SV-254300r958570_rule",
                    "SMB signing must be required",
                    Severity::Medium,
                    FindingStatus::NotAFinding,
                ),
                (
                    "V-254333",
                    "SV-254333r958669_rule",
                    "PowerShell transcription must be enabled",
                    Severity::Low,
                    FindingStatus::NotApplicable,
                ),
            ],
        ),
        sample_checklist(
            "WEB-APP-01",
            "IIS_10.0_STIG",
            "Microsoft IIS 10.0 STIG",
            "2",
            "1",
            vec![
                (
                    "V-218796",
                    "SV-218796r603267_rule",
                    "Directory browsing must be disabled",
                    Severity::Medium,
                    FindingStatus::Open,
                ),
                (
                    "V-218801",
                    "SV-218801r603282_rule",
                    "Sample content must be removed",
                    Severity::Medium,
                    FindingStatus::NotAFinding,
                ),
                (
                    "V-218804",
                    "SV-218804r603291_rule",
                    "Request filtering must be configured",
                    Severity::Low,
                    FindingStatus::NotAFinding,
                ),
            ],
        ),
        sample_checklist(
            "DB-CORE-01",
            "RHEL_9_STIG",
            "Red Hat Enterprise Linux 9 STIG",
            "1",
            "2",
            vec![
                (
                    "V-258095",
                    "SV-258095r986512_rule",
                    "FIPS mode must be enabled",
                    Severity::High,
                    FindingStatus::Open,
                ),
                (
                    "V-258101",
                    "SV-258101r986530_rule",
                    "Auditd must be configured",
                    Severity::Medium,
                    FindingStatus::NotAFinding,
                ),
                (
                    "V-258144",
                    "SV-258144r986679_rule",
                    "USB storage must be disabled when not required",
                    Severity::Low,
                    FindingStatus::NotReviewed,
                ),
            ],
        ),
        sample_checklist(
            "DB-CORE-01",
            "PostgreSQL_14_STIG",
            "PostgreSQL 14 STIG",
            "1",
            "1",
            vec![
                (
                    "V-260001",
                    "SV-260001r990001_rule",
                    "Logging collector must be enabled",
                    Severity::Medium,
                    FindingStatus::Open,
                ),
                (
                    "V-260014",
                    "SV-260014r990044_rule",
                    "SSL must be enforced",
                    Severity::High,
                    FindingStatus::NotAFinding,
                ),
                (
                    "V-260028",
                    "SV-260028r990088_rule",
                    "Untrusted extensions must be removed",
                    Severity::Low,
                    FindingStatus::NotApplicable,
                ),
            ],
        ),
        sample_checklist(
            "EDGE-GW-01",
            "Cisco_IOS_STIG",
            "Cisco IOS STIG",
            "3",
            "5",
            vec![
                (
                    "V-220501",
                    "SV-220501r604001_rule",
                    "Unused services must be disabled",
                    Severity::Medium,
                    FindingStatus::NotAFinding,
                ),
                (
                    "V-220544",
                    "SV-220544r604118_rule",
                    "AAA must be configured",
                    Severity::High,
                    FindingStatus::Open,
                ),
                (
                    "V-220590",
                    "SV-220590r604240_rule",
                    "SNMP community strings must be secured",
                    Severity::Medium,
                    FindingStatus::NotAFinding,
                ),
            ],
        ),
    ];

    for checklist in &checklists {
        let _ = db.save_checklist(checklist);
        let _ = db.log_evaluation(checklist, "demo-seed", Some(&checklist.asset.hostname));
    }

    let _ = db.set_config("demo_seeded", "true");
}

fn sample_checklist(
    hostname: &str,
    stig_id: &str,
    title: &str,
    version: &str,
    release: &str,
    findings_spec: Vec<(&str, &str, &str, Severity, FindingStatus)>,
) -> Checklist {
    let mut asset = Asset::new(hostname);
    asset.os = Some(hostname.to_string());

    let mut checklist = Checklist::new(
        asset,
        ChecklistStigInfo {
            stig_id: stig_id.to_string(),
            title: title.to_string(),
            version: version.to_string(),
            release: release.to_string(),
            release_date: Some("2026-04-15".to_string()),
            uuid: None,
            description: Some(format!("Demo seeded checklist for {}", hostname)),
            filename: None,
        },
    );

    checklist.findings = findings_spec
        .into_iter()
        .enumerate()
        .map(|(idx, (vuln, rule, title, severity, status))| {
            let mut f = Finding::new_not_reviewed(vuln, rule, vuln, title, severity);
            f.status = status;
            f.source = FindingSource::Manual;
            f.finding_details = match status {
                FindingStatus::Open => {
                    format!("Demo finding evidence for {} on {}", vuln, hostname)
                }
                FindingStatus::NotAFinding => {
                    format!("Validated compliant for {} on {}", vuln, hostname)
                }
                FindingStatus::NotApplicable => {
                    format!("Marked not applicable for {} in demo scenario", vuln)
                }
                FindingStatus::NotReviewed => format!("Pending analyst review for {}", vuln),
            };
            f.comments = format!("Demo seeded item {} for presentation purposes", idx + 1);
            f.evaluated_at = Utc::now();
            f.evaluated_by = "AutomateSTIG demo seed".to_string();
            f
        })
        .collect();
    checklist.touch();
    checklist
}

fn generate_session_token() -> Result<String, String> {
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut bytes)
        .map_err(|_| "Failed to generate random token".to_string())?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

fn resolve_auth_token(
    explicit_token: Option<String>,
    is_loopback: bool,
    demo_mode: bool,
) -> Result<String, String> {
    if let Some(token) = explicit_token {
        if token.len() < 16 && !is_loopback {
            return Err(
                "AUTOMATESTIG_AUTH_TOKEN must be at least 16 characters for non-localhost binds"
                    .to_string(),
            );
        }
        return Ok(token);
    }

    if is_loopback || demo_mode {
        return generate_session_token();
    }

    Err("AUTOMATESTIG_AUTH_TOKEN is required when binding outside localhost".to_string())
}

/// Serve embedded frontend files.
/// For index.html, injects the session auth token so the JS can authenticate API calls.
fn serve_frontend_with_token(
    uri: axum::http::Uri,
    token: Option<&str>,
) -> axum::response::Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    let inject_token = |body: &[u8], token: Option<&str>| -> Vec<u8> {
        let Some(token) = token else {
            return body.to_vec();
        };
        let script = format!("<script>window.__AUTH_TOKEN__='{}';</script>", token);
        let html = String::from_utf8_lossy(body);
        html.replace("</head>", &format!("{}</head>", script))
            .into_bytes()
    };

    match FrontendAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            let raw = content.data.into_owned();
            let body = if path == "index.html" {
                inject_token(&raw, token)
            } else {
                raw
            };
            ([(axum::http::header::CONTENT_TYPE, mime)], body).into_response()
        }
        None => match FrontendAssets::get("index.html") {
            Some(content) => {
                let body = inject_token(&content.data, token);
                (
                    [(axum::http::header::CONTENT_TYPE, "text/html".to_string())],
                    body,
                )
                    .into_response()
            }
            None => (axum::http::StatusCode::NOT_FOUND, "Frontend not found").into_response(),
        },
    }
}

use axum::response::IntoResponse;

#[derive(rust_embed::Embed)]
#[folder = "frontend/"]
struct FrontendAssets;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_loopback_demo_without_explicit_token_gets_random_session_token() {
        let token = resolve_auth_token(None, false, true).expect("demo hosted mode should start");

        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn non_loopback_server_without_token_is_rejected() {
        let error = resolve_auth_token(None, false, false).expect_err("server mode needs a token");

        assert_eq!(
            error,
            "AUTOMATESTIG_AUTH_TOKEN is required when binding outside localhost"
        );
    }

    #[test]
    fn non_loopback_short_explicit_token_is_rejected() {
        let error = resolve_auth_token(Some("short".to_string()), false, true)
            .expect_err("short hosted tokens are unsafe");

        assert_eq!(
            error,
            "AUTOMATESTIG_AUTH_TOKEN must be at least 16 characters for non-localhost binds"
        );
    }
}
