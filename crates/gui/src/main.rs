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

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::EnvFilter;

use state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Initialize application state.
    let state = AppState::init().expect("Failed to initialize application state");

    // Clone for background checker before moving into router.
    let bg_state = state.clone();

    // Bind to a random available port on localhost.
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");
    let local_addr = listener.local_addr().expect("Failed to get local address");
    let url = format!("http://{}", local_addr);

    // Generate a cryptographically random auth token for this session.
    let auth_token: String = {
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut bytes)
            .expect("Failed to generate random token");
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    };
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
                        .and_then(|q| {
                            q.split('&')
                                .find_map(|p| p.strip_prefix("token="))
                        })
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
            let token = auth_token.clone();
            move |uri: axum::http::Uri| {
                let t = token.clone();
                async move { serve_frontend_with_token(uri, &t) }
            }
        })
        .layer(RequestBodyLimitLayer::new(100 * 1024 * 1024)) // 100 MB
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(
                    url.parse().expect("Failed to parse origin"),
                ))
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
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
            tracing::info!("Background update checker disabled (air-gapped mode). Enable in Settings.");
        }
    });

    // Open browser.
    if let Err(e) = open::that(&url) {
        eprintln!("  Could not open browser: {}", e);
        eprintln!("  Open {} manually.", url);
    }

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("  Server error: {}", e);
        std::process::exit(1);
    }
}

/// Serve embedded frontend files.
/// For index.html, injects the session auth token so the JS can authenticate API calls.
fn serve_frontend_with_token(uri: axum::http::Uri, token: &str) -> axum::response::Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    let inject_token = |body: &[u8], token: &str| -> Vec<u8> {
        let script = format!("<script>window.__AUTH_TOKEN__='{}';</script>", token);
        let html = String::from_utf8_lossy(body);
        html.replace("</head>", &format!("{}</head>", script)).into_bytes()
    };

    match FrontendAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            let raw = content.data.into_owned();
            let body = if path == "index.html" { inject_token(&raw, token) } else { raw };
            ([(axum::http::header::CONTENT_TYPE, mime)], body).into_response()
        }
        None => {
            match FrontendAssets::get("index.html") {
                Some(content) => {
                    let body = inject_token(&content.data, token);
                    ([(axum::http::header::CONTENT_TYPE, "text/html".to_string())], body).into_response()
                }
                None => (axum::http::StatusCode::NOT_FOUND, "Frontend not found").into_response(),
            }
        }
    }
}

use axum::response::IntoResponse;

#[derive(rust_embed::Embed)]
#[folder = "frontend/"]
struct FrontendAssets;
