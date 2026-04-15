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

    // Generate a random auth token for this session.
    // API requests must include this token to prevent other local processes
    // or cross-origin requests from accessing the API.
    let auth_token: String = {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let s = RandomState::new();
        let mut h = s.build_hasher();
        h.write_usize(std::process::id() as usize);
        h.write_u128(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos());
        format!("{:016x}{:016x}", h.finish(), RandomState::new().build_hasher().finish())
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
                    let provided = req
                        .headers()
                        .get("X-Auth-Token")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if provided != token {
                        return Ok(axum::response::IntoResponse::into_response((
                            axum::http::StatusCode::UNAUTHORIZED,
                            "Invalid or missing auth token",
                        )));
                    }
                }
                Ok::<Response, std::convert::Infallible>(next.run(req).await)
            }
        }))
        .fallback(serve_frontend)
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
    // Store auth token in state for injection into frontend.
    {
        let db = bg_state.db();
        let _ = db.set_config("_session_auth_token", &auth_token);
    }

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
/// For index.html, injects the session auth token so the JS can authenticate API calls.
async fn serve_frontend(
    uri: axum::http::Uri,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::response::Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match FrontendAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            let mut body: Vec<u8> = content.data.into_owned();

            // Inject auth token into index.html.
            if path == "index.html" {
                let token = state
                    .db()
                    .get_config("_session_auth_token")
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let script = format!(
                    "<script>window.__AUTH_TOKEN__='{}';</script>",
                    token
                );
                let html = String::from_utf8_lossy(&body);
                let injected = html.replace("</head>", &format!("{}</head>", script));
                body = injected.into_bytes();
            }

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
                    let mut body: Vec<u8> = content.data.into_owned();
                    let token = state
                        .db()
                        .get_config("_session_auth_token")
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let script = format!(
                        "<script>window.__AUTH_TOKEN__='{}';</script>",
                        token
                    );
                    let html = String::from_utf8_lossy(&body);
                    let injected = html.replace("</head>", &format!("{}</head>", script));
                    body = injected.into_bytes();

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
