//! AutomateSTIG Desktop GUI.
//!
//! Launches a local web server and opens the browser to the UI.
//! All communication is localhost-only — no external network calls.

mod api;
pub mod disa;
mod state;
pub mod stigman;

use std::net::SocketAddr;

use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
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

    // Build the router with CORS restricted to our exact origin.
    let app = Router::new()
        .nest("/api", api::routes())
        .fallback(serve_frontend)
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

    axum::serve(listener, app).await.unwrap();
}

/// Serve embedded frontend files.
async fn serve_frontend(
    uri: axum::http::Uri,
) -> impl axum::response::IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    serve_embedded_file(path)
}

fn serve_embedded_file(path: &str) -> axum::response::Response {
    match FrontendAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            let body: Vec<u8> = content.data.into_owned();
            (
                [(axum::http::header::CONTENT_TYPE, mime)],
                body,
            )
                .into_response()
        }
        None => {
            // Fallback to index.html for SPA routing.
            match FrontendAssets::get("index.html") {
                Some(content) => {
                    let body: Vec<u8> = content.data.into_owned();
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/html".to_string())],
                        body,
                    )
                        .into_response()
                }
                None => (
                    axum::http::StatusCode::NOT_FOUND,
                    "Frontend not found",
                )
                    .into_response(),
            }
        }
    }
}

use axum::response::IntoResponse;

#[derive(rust_embed::Embed)]
#[folder = "frontend/"]
struct FrontendAssets;
