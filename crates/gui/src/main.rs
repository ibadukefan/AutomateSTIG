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
use std::time::Duration;

use automatestig_core::inventory::scheduler::ScheduleFrequency;
use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use chrono::{DateTime, Utc};
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

    // Clone for background tasks before moving into router.
    let update_bg_state = state.clone();
    let scheduler_bg_state = state.clone();
    let agent_bg_state = state.clone();

    // Bind address: PORT may set the port for hosted platforms.
    // Network exposure must be explicit via AUTOMATESTIG_BIND.
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    let bind_host = std::env::var("AUTOMATESTIG_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let bind_ip: std::net::IpAddr = bind_host
        .parse()
        .expect("AUTOMATESTIG_BIND must be an IP address such as 127.0.0.1 or 0.0.0.0");

    let addr = SocketAddr::from((bind_ip, port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");
    let local_addr = listener.local_addr().expect("Failed to get local address");
    let url = format!("http://{}", local_addr);

    // Generate auth token. Server/non-loopback mode requires an explicit token;
    // desktop localhost gets a random per-session token.
    let is_loopback = bind_ip.is_loopback();
    let auth_token = resolve_auth_token(std::env::var("AUTOMATESTIG_AUTH_TOKEN").ok(), is_loopback)
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
                // Allow unauthenticated health checks.
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

                    if !ct_token_eq(&header_token, &token) && !ct_token_eq(&query_token, &token) {
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
            let token = if is_loopback {
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
        .layer(axum::extract::DefaultBodyLimit::max(100 * 1024 * 1024))
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
    eprintln!("  Press Ctrl+C to stop.");
    eprintln!();

    // Start background STIG update checker (every 24 hours) only if
    // the user has opted in via agent config. Air-gapped by default.
    tokio::spawn(async move {
        // Check if background updates are enabled in config.
        let enabled = update_bg_state
            .db()
            .get_config("auto_update_enabled")
            .ok()
            .flatten()
            .map(|v| v == "true")
            .unwrap_or(false);

        if enabled {
            tracing::info!("Background STIG update checker enabled");
            disa::start_background_checker(update_bg_state, 24).await;
        } else {
            tracing::info!(
                "Background update checker disabled (air-gapped mode). Enable in Settings."
            );
        }
    });

    // Start the evaluation scheduler dispatcher.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;

            let due_schedules = {
                let db = scheduler_bg_state.db();
                let mut config = api::load_schedules(&db);
                let scheduler_enabled = config.schedules.iter().any(|schedule| schedule.enabled);
                let mut changed = false;

                if config.enabled != scheduler_enabled {
                    config.enabled = scheduler_enabled;
                    changed = true;
                }

                if !config.enabled {
                    if changed {
                        api::save_schedules(&db, &config);
                    }
                    Vec::new()
                } else {
                    let now = Utc::now();

                    for schedule in &mut config.schedules {
                        if schedule.enabled
                            && schedule.next_run.is_none()
                            && !matches!(schedule.frequency, ScheduleFrequency::Once)
                        {
                            schedule.next_run = Some(schedule.calculate_next_run(now));
                            changed = true;
                        }
                    }

                    if changed {
                        api::save_schedules(&db, &config);
                    }

                    config
                        .schedules
                        .iter()
                        .filter(|schedule| api::schedule_is_due(schedule, now))
                        .cloned()
                        .collect()
                }
            };

            for schedule in due_schedules {
                tracing::info!(
                    schedule_id = %schedule.id,
                    schedule_name = %schedule.name,
                    "Running scheduled evaluation"
                );

                let state = scheduler_bg_state.clone();
                let schedule_id = schedule.id.clone();
                let schedule_name = schedule.name.clone();

                match tokio::spawn(async move { api::execute_schedule(&state, &schedule).await })
                    .await
                {
                    Ok(status) => {
                        let db = scheduler_bg_state.db();
                        let mut config = api::load_schedules(&db);
                        if let Some(stored) =
                            config.schedules.iter_mut().find(|s| s.id == schedule_id)
                        {
                            stored.mark_executed(status);
                            api::refresh_scheduler_enabled(&mut config);
                            api::save_schedules(&db, &config);
                        } else {
                            tracing::warn!(
                                schedule_id = %schedule_id,
                                "Scheduled evaluation completed but schedule no longer exists"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            schedule_id = %schedule_id,
                            schedule_name = %schedule_name,
                            "Scheduled evaluation task failed: {}",
                            e
                        );
                    }
                }
            }
        }
    });

    // Start the agent-mode continuous compliance dispatcher.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        let mut last_cycle: Option<DateTime<Utc>> = None;

        loop {
            interval.tick().await;

            let config = {
                let db = agent_bg_state.db();
                api::load_agent_config(&db)
            };

            if !config.enabled {
                continue;
            }

            let now = Utc::now();
            let scan_interval =
                chrono::Duration::minutes(config.scan_interval_minutes.max(1) as i64);
            let is_due = last_cycle
                .map(|last_run| now >= last_run + scan_interval)
                .unwrap_or(true);

            if !is_due {
                continue;
            }

            last_cycle = Some(now);
            tracing::info!("Running agent cycle");

            let state = agent_bg_state.clone();
            match tokio::spawn(async move { api::run_agent_cycle(&state).await }).await {
                Ok(scanned) => {
                    tracing::info!(targets_scanned = scanned, "Agent cycle completed");
                }
                Err(e) => {
                    tracing::error!("Agent cycle task failed: {}", e);
                }
            }
        }
    });

    // Open browser for local desktop mode.
    if is_loopback {
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

fn generate_session_token() -> Result<String, String> {
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut bytes)
        .map_err(|_| "Failed to generate random token".to_string())?;
    Ok(bytes.iter().map(|b| format!("{:02x}", b)).collect())
}

#[allow(deprecated)]
fn ct_token_eq(candidate: &str, expected: &str) -> bool {
    candidate.len() == expected.len()
        && ring::constant_time::verify_slices_are_equal(candidate.as_bytes(), expected.as_bytes())
            .is_ok()
}

fn resolve_auth_token(explicit_token: Option<String>, is_loopback: bool) -> Result<String, String> {
    if let Some(token) = explicit_token {
        if token.len() < 16 && !is_loopback {
            return Err(
                "AUTOMATESTIG_AUTH_TOKEN must be at least 16 characters for non-localhost binds"
                    .to_string(),
            );
        }
        return Ok(token);
    }

    if is_loopback {
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
    fn non_loopback_server_without_token_is_rejected() {
        let error = resolve_auth_token(None, false).expect_err("server mode needs a token");

        assert_eq!(
            error,
            "AUTOMATESTIG_AUTH_TOKEN is required when binding outside localhost"
        );
    }

    #[test]
    fn non_loopback_short_explicit_token_is_rejected() {
        let error = resolve_auth_token(Some("short".to_string()), false)
            .expect_err("short server tokens are unsafe");

        assert_eq!(
            error,
            "AUTOMATESTIG_AUTH_TOKEN must be at least 16 characters for non-localhost binds"
        );
    }

    #[test]
    fn test_ct_token_eq() {
        assert!(ct_token_eq("abcdef", "abcdef"));
        assert!(!ct_token_eq("abcdeg", "abcdef"));
        assert!(!ct_token_eq("abc", "abcdef"));
        assert!(!ct_token_eq("", "abcdef"));
    }
}
