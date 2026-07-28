//! AutomateSTIG Desktop GUI.
//!
//! Launches a local web server and opens the browser to the UI.
//! All communication is localhost-only — no external network calls.

mod api;
pub mod disa;
mod outbound;
pub mod secrets;
pub mod ssh;
mod state;
pub mod stigman;

use std::net::{IpAddr, SocketAddr};

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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Initialize application state.
    let state = AppState::init().expect("Failed to initialize application state");

    // Clone for background tasks before moving into router.
    let update_bg_state = state.clone();

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
    let listener_port = local_addr.port();

    // Build the router with security layers:
    // 1. CORS restricted to same origin
    // 2. Hard transport ceiling (individual upload routes enforce lower exact caps)
    // 3. Auth token verification on /api routes
    let app = Router::new()
        .nest("/api", api::routes())
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let token = auth_token_for_middleware.clone();
            async move {
                // A loopback listener is still reachable by a browser through DNS
                // rebinding. Only serve requests whose authority names loopback on
                // the actual listener port, so an attacker-controlled Host cannot
                // receive the token-bearing frontend or call the API same-origin.
                if is_loopback
                    && !is_allowed_loopback_host(
                        req.headers().get(axum::http::header::HOST),
                        listener_port,
                    )
                {
                    return Ok::<Response, std::convert::Infallible>(
                        axum::response::IntoResponse::into_response((
                            axum::http::StatusCode::MISDIRECTED_REQUEST,
                            "Invalid Host header",
                        )),
                    );
                }

                // Allow unauthenticated health checks.
                if req.uri().path() == "/api/status" {
                    return Ok::<Response, std::convert::Infallible>(next.run(req).await);
                }

                // Only check auth on /api routes, not frontend static files.
                if req.uri().path().starts_with("/api") {
                    // The auth token is accepted only through the request header.
                    let header_token = req
                        .headers()
                        .get("X-Auth-Token")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();

                    if !ct_token_eq(&header_token, &token) {
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
        .layer(RequestBodyLimitLayer::new(258 * 1024 * 1024))
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
    // the user has opted in. Air-gapped by default.
    tokio::spawn(async move {
        // Check if background updates are enabled in config.
        let enabled = match update_bg_state.db().get_config("auto_update_enabled") {
            Ok(value) => value.map(|value| value == "true").unwrap_or(false),
            Err(error) => {
                tracing::error!("Failed to read background-update setting: {error}");
                false
            }
        };

        if enabled {
            tracing::info!("Background STIG update checker enabled");
            disa::start_background_checker(update_bg_state, 24).await;
        } else {
            tracing::info!(
                "Background update checker disabled (air-gapped mode). Enable in Settings."
            );
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
        if token.len() < 16 {
            return Err("AUTOMATESTIG_AUTH_TOKEN must be at least 16 characters".to_string());
        }
        return Ok(token);
    }

    if is_loopback {
        return generate_session_token();
    }

    Err("AUTOMATESTIG_AUTH_TOKEN is required when binding outside localhost".to_string())
}

fn is_allowed_loopback_host(
    host_header: Option<&axum::http::HeaderValue>,
    listener_port: u16,
) -> bool {
    let Some(raw) = host_header.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Ok(authority) = raw.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    if authority.port_u16() != Some(listener_port) {
        return false;
    }

    let host = authority.host().trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Serve embedded frontend files.
/// For index.html, injects the session auth token so the JS can authenticate API calls.
fn serve_frontend_with_token(
    uri: axum::http::Uri,
    token: Option<&str>,
) -> axum::response::Response {
    // Unknown API paths must stay API 404s. Serving the single-page frontend
    // here can make a removed mutation endpoint appear to succeed with HTTP
    // 200 and HTML, which is unsafe for scripts and misleading for operators.
    if uri.path() == "/api" || uri.path().starts_with("/api/") {
        return (axum::http::StatusCode::NOT_FOUND, "API endpoint not found").into_response();
    }

    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    let inject_token = |body: &[u8], token: Option<&str>| -> Vec<u8> {
        let Some(token) = token else {
            return body.to_vec();
        };
        // JSON string encoding plus HTML-significant escaping safely embeds an
        // arbitrary configured token without permitting a `</script>` break-out.
        let encoded = serde_json::to_string(token)
            .expect("string serialization cannot fail")
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026");
        let script = format!("<script>window.__AUTH_TOKEN__={encoded};</script>");
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
    fn unknown_api_paths_are_not_rewritten_to_the_frontend() {
        let response = serve_frontend_with_token(
            "/api/library/removed-mutation".parse().unwrap(),
            Some("test-token-0123456789"),
        );

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }

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
            "AUTOMATESTIG_AUTH_TOKEN must be at least 16 characters"
        );
    }

    #[test]
    fn loopback_empty_or_short_explicit_token_is_rejected() {
        for token in ["", "short"] {
            let error = resolve_auth_token(Some(token.to_string()), true)
                .expect_err("an explicit weak token must never disable authentication");
            assert_eq!(
                error,
                "AUTOMATESTIG_AUTH_TOKEN must be at least 16 characters"
            );
        }
    }

    #[test]
    fn loopback_host_guard_rejects_dns_rebinding_and_wrong_ports() {
        use axum::http::HeaderValue;

        for allowed in ["127.0.0.1:4567", "localhost:4567", "[::1]:4567"] {
            assert!(is_allowed_loopback_host(
                Some(&HeaderValue::from_str(allowed).unwrap()),
                4567
            ));
        }
        for rejected in [
            "attacker.example:4567",
            "127.0.0.1:9999",
            "127.0.0.1",
            "192.0.2.1:4567",
        ] {
            assert!(!is_allowed_loopback_host(
                Some(&HeaderValue::from_str(rejected).unwrap()),
                4567
            ));
        }
        assert!(!is_allowed_loopback_host(None, 4567));
    }

    #[tokio::test]
    async fn frontend_token_is_javascript_escaped() {
        let response = serve_frontend_with_token(
            "/".parse().unwrap(),
            Some("0123456789abc'</script><script>alert(1)</script>"),
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("</script><script>alert(1)"));
        assert!(html.contains("\\u003c/script\\u003e"));
    }

    #[test]
    fn test_ct_token_eq() {
        assert!(ct_token_eq("abcdef", "abcdef"));
        assert!(!ct_token_eq("abcdeg", "abcdef"));
        assert!(!ct_token_eq("abc", "abcdef"));
        assert!(!ct_token_eq("", "abcdef"));
    }
}
