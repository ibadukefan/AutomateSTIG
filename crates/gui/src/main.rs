//! AutomateSTIG Desktop GUI.
//!
//! Launches a web server and, in the default loopback desktop mode, opens the
//! browser to the UI. Network exposure requires an explicit bind and token.

mod api;
mod scanner_api;
pub mod secrets;
mod state;

// Preserve the scanner API's established internal DTO path while keeping all
// STIG Manager network behavior in the canonical integrations client.
mod stigman {
    pub(crate) use automatestig_integrations::stig_manager::StigManagerConfig;
}

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

use state::AppState;

#[tokio::main]
async fn main() {
    // Initialize application state.
    let state = AppState::init().expect("Failed to initialize application state");
    let _log_guard = init_logging(&state).expect("Failed to initialize secure application logs");
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        data_dir = %state.inner.data_dir.display(),
        "AutomateSTIG GUI starting"
    );
    scanner_api::start_evidence_retention_sweeper(state.clone());

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
    let failed_auth_limiter = FailedAuthLimiter::default();
    let listener_port = local_addr.port();

    // Build the router with security layers:
    // 1. CORS restricted to same origin
    // 2. Hard transport ceiling (individual upload routes enforce lower exact caps)
    // 3. Auth token verification on /api routes
    let app = Router::new()
        .nest("/api", api::routes())
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let token = auth_token_for_middleware.clone();
            let limiter = failed_auth_limiter.clone();
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
                    let peer_ip = req
                        .extensions()
                        .get::<ConnectInfo<SocketAddr>>()
                        .map(|ConnectInfo(address)| address.ip());
                    if let Some(retry_after) = peer_ip.and_then(|ip| limiter.retry_after(ip)) {
                        let mut response = axum::response::IntoResponse::into_response((
                            axum::http::StatusCode::TOO_MANY_REQUESTS,
                            "Too many failed authentication attempts",
                        ));
                        if let Ok(value) = axum::http::HeaderValue::from_str(
                            &retry_after.as_secs().max(1).to_string(),
                        ) {
                            response
                                .headers_mut()
                                .insert(axum::http::header::RETRY_AFTER, value);
                        }
                        tracing::warn!(?peer_ip, "API authentication temporarily rate limited");
                        return Ok(response);
                    }
                    // The auth token is accepted only through the request header.
                    let header_token = req
                        .headers()
                        .get("X-Auth-Token")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    if !ct_token_eq(header_token, &token) {
                        if let Some(ip) = peer_ip {
                            limiter.record_failure(ip);
                        }
                        tracing::warn!(?peer_ip, "API authentication failed");
                        return Ok(axum::response::IntoResponse::into_response((
                            axum::http::StatusCode::UNAUTHORIZED,
                            "Invalid or missing auth token",
                        )));
                    }
                    if let Some(ip) = peer_ip {
                        limiter.record_success(ip);
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
        .layer(middleware::from_fn(security_response_headers))
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

    // Open browser for local desktop mode.
    if is_loopback {
        if let Err(e) = open::that(&url) {
            eprintln!("  Could not open browser: {}", e);
            eprintln!("  Open {} manually.", url);
        }
    }

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        eprintln!("  Server error: {}", e);
        std::process::exit(1);
    }
}

/// Apply browser containment to every response and prevent authenticated API
/// data from being cached by browsers or shared reverse proxies. The API uses
/// a custom authentication header, so `Vary` must name it explicitly.
async fn security_response_headers(req: Request, next: Next) -> Response {
    let is_api = req.uri().path() == "/api" || req.uri().path().starts_with("/api/");
    let response = next.run(req).await;
    harden_response(response, is_api)
}

fn harden_response(mut response: Response, is_api: bool) -> Response {
    use axum::http::header::{
        CACHE_CONTROL, CONTENT_SECURITY_POLICY, PRAGMA, REFERRER_POLICY, VARY,
        X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
    };
    use axum::http::{HeaderName, HeaderValue};

    let headers = response.headers_mut();
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; worker-src 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
        ),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );

    if is_api {
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store, max-age=0"),
        );
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        headers.append(VARY, HeaderValue::from_static("X-Auth-Token"));
    }
    response
}

fn init_logging(state: &AppState) -> Result<tracing_appender::non_blocking::WorkerGuard, String> {
    let log_dir = state.inner.data_dir.join("logs");
    state::secure_private_directory(&log_dir)
        .map_err(|error| format!("Failed to secure {}: {error}", log_dir.display()))?;
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("automatestig-gui.jsonl")
        .max_log_files(14)
        .build(&log_dir)
        .map_err(|error| format!("Failed to open persistent log: {error}"))?;
    let (file_writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(false)
        .buffered_lines_limit(8_192)
        .finish(appender);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let console = tracing_subscriber::fmt::layer().with_target(false);
    let structured_file = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(file_writer);
    tracing_subscriber::registry()
        .with(filter)
        .with(console)
        .with(structured_file)
        .try_init()
        .map_err(|error| format!("Failed to install logging subscriber: {error}"))?;
    Ok(guard)
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
        if !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(
                "AUTOMATESTIG_AUTH_TOKEN must contain only visible ASCII characters without whitespace"
                    .to_string(),
            );
        }
        let minimum = if is_loopback { 16 } else { 32 };
        if token.len() < minimum {
            return Err(format!(
                "AUTOMATESTIG_AUTH_TOKEN must be at least {minimum} characters{}",
                if is_loopback {
                    ""
                } else {
                    " for a non-loopback bind"
                }
            ));
        }
        return Ok(token);
    }

    if is_loopback {
        return generate_session_token();
    }

    Err("AUTOMATESTIG_AUTH_TOKEN is required when binding outside localhost".to_string())
}

const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const AUTH_BLOCK_DURATION: Duration = Duration::from_secs(5 * 60);
const AUTH_FAILURE_LIMIT: u32 = 10;
const MAX_AUTH_TRACKED_PEERS: usize = 4096;

#[derive(Clone, Default)]
struct FailedAuthLimiter {
    peers: Arc<Mutex<HashMap<IpAddr, FailedAuthState>>>,
}

#[derive(Clone, Copy)]
struct FailedAuthState {
    window_started: Instant,
    failures: u32,
    blocked_until: Option<Instant>,
}

impl FailedAuthLimiter {
    fn retry_after(&self, peer: IpAddr) -> Option<Duration> {
        self.retry_after_at(peer, Instant::now())
    }

    fn retry_after_at(&self, peer: IpAddr, now: Instant) -> Option<Duration> {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = peers.get(&peer).copied()?;
        if let Some(blocked_until) = state.blocked_until {
            if blocked_until > now {
                return Some(blocked_until.duration_since(now));
            }
            peers.remove(&peer);
        } else if now.duration_since(state.window_started) >= AUTH_FAILURE_WINDOW {
            peers.remove(&peer);
        }
        None
    }

    fn record_failure(&self, peer: IpAddr) {
        self.record_failure_at(peer, Instant::now());
    }

    fn record_failure_at(&self, peer: IpAddr, now: Instant) {
        let mut peers = self
            .peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        peers.retain(|_, state| {
            state.blocked_until.is_some_and(|until| until > now)
                || now.duration_since(state.window_started) < AUTH_FAILURE_WINDOW
        });
        if peers.len() >= MAX_AUTH_TRACKED_PEERS && !peers.contains_key(&peer) {
            // The map is bounded under address-spray attacks. Refuse to evict a
            // currently blocked peer merely to remember a new one.
            return;
        }
        let state = peers.entry(peer).or_insert(FailedAuthState {
            window_started: now,
            failures: 0,
            blocked_until: None,
        });
        if now.duration_since(state.window_started) >= AUTH_FAILURE_WINDOW {
            state.window_started = now;
            state.failures = 0;
            state.blocked_until = None;
        }
        state.failures = state.failures.saturating_add(1);
        if state.failures >= AUTH_FAILURE_LIMIT {
            state.blocked_until = Some(now + AUTH_BLOCK_DURATION);
        }
    }

    fn record_success(&self, peer: IpAddr) {
        self.peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&peer);
    }
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
        // Keep the secret out of executable script so a strict self-only CSP
        // can protect the page. Attribute escaping prevents tag or attribute
        // injection for every visible-ASCII token accepted at startup.
        let encoded = token
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;");
        let metadata = format!(r#"<meta name="automatestig-auth-token" content="{encoded}">"#);
        let html = String::from_utf8_lossy(body);
        html.replace("</head>", &format!("{metadata}</head>"))
            .into_bytes()
    };

    let protect_token_bearing_html = |response: &mut axum::response::Response,
                                      contains_token: bool| {
        if !contains_token {
            return;
        }
        response.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response.headers_mut().insert(
            axum::http::header::PRAGMA,
            axum::http::HeaderValue::from_static("no-cache"),
        );
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
            let mut response = ([(axum::http::header::CONTENT_TYPE, mime)], body).into_response();
            protect_token_bearing_html(&mut response, path == "index.html");
            response
        }
        None => match FrontendAssets::get("index.html") {
            Some(content) => {
                let body = inject_token(&content.data, token);
                let mut response = (
                    [(axum::http::header::CONTENT_TYPE, "text/html".to_string())],
                    body,
                )
                    .into_response();
                protect_token_bearing_html(&mut response, true);
                response
            }
            None => (axum::http::StatusCode::NOT_FOUND, "Frontend not found").into_response(),
        },
    }
}

use axum::response::IntoResponse;

#[derive(rust_embed::Embed)]
#[folder = "frontend/scanner/"]
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
            "AUTOMATESTIG_AUTH_TOKEN must be at least 32 characters for a non-loopback bind"
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
    fn explicit_tokens_with_whitespace_controls_or_non_ascii_are_rejected() {
        for token in [
            "0123456789abcdef ",
            "0123456789abcdef\n",
            "0123456789abcde\t",
            "0123456789abcdeé",
        ] {
            let error = resolve_auth_token(Some(token.to_string()), false)
                .expect_err("browser-incompatible tokens must be rejected at startup");
            assert_eq!(
                error,
                "AUTOMATESTIG_AUTH_TOKEN must contain only visible ASCII characters without whitespace"
            );
        }
    }

    #[test]
    fn explicit_visible_ascii_token_is_accepted() {
        let token = "A-strong_non-loopback_token!2026-08";
        assert_eq!(
            resolve_auth_token(Some(token.to_string()), false).unwrap(),
            token
        );
    }

    #[test]
    fn failed_authentication_is_bounded_and_recovers() {
        let limiter = FailedAuthLimiter::default();
        let peer = "192.0.2.44".parse().unwrap();
        let started = Instant::now();

        for offset in 0..AUTH_FAILURE_LIMIT - 1 {
            limiter.record_failure_at(peer, started + Duration::from_millis(offset.into()));
            assert!(limiter
                .retry_after_at(peer, started + Duration::from_secs(1))
                .is_none());
        }
        limiter.record_failure_at(peer, started + Duration::from_secs(2));
        assert!(limiter
            .retry_after_at(peer, started + Duration::from_secs(3))
            .is_some());
        assert!(limiter
            .retry_after_at(peer, started + AUTH_BLOCK_DURATION + Duration::from_secs(3))
            .is_none());
    }

    #[test]
    fn successful_authentication_clears_failure_history() {
        let limiter = FailedAuthLimiter::default();
        let peer = "192.0.2.45".parse().unwrap();
        let started = Instant::now();
        for _ in 0..AUTH_FAILURE_LIMIT {
            limiter.record_failure_at(peer, started);
        }
        assert!(limiter.retry_after_at(peer, started).is_some());
        limiter.record_success(peer);
        assert!(limiter.retry_after_at(peer, started).is_none());
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
    async fn frontend_token_is_attribute_escaped_and_not_executable() {
        let response = serve_frontend_with_token(
            "/".parse().unwrap(),
            Some("0123456789abc'\"><script>alert(1)</script>"),
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("><script>alert(1)</script>"));
        assert!(!html.contains("window.__AUTH_TOKEN__"));
        assert!(html.contains("name=\"automatestig-auth-token\""));
        assert!(html.contains("&#39;&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[tokio::test]
    async fn root_serves_the_scanner_first_shell() {
        let response =
            serve_frontend_with_token("/".parse().unwrap(), Some("test-token-0123456789"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains("AutomateSTIG Scanner"));
        assert!(html.contains(">Deliveries<"));
        assert!(html.contains(">Scanner Content<"));
        assert!(!html.contains(">Assets<"));
        assert!(!html.contains(">Findings<"));
    }

    #[test]
    fn token_bearing_frontend_html_is_not_cacheable() {
        for path in ["/", "/client-side-route"] {
            let response =
                serve_frontend_with_token(path.parse().unwrap(), Some("test-token-0123456789"));

            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("no-store")
            );
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::PRAGMA)
                    .and_then(|value| value.to_str().ok()),
                Some("no-cache")
            );
        }
    }

    #[test]
    fn browser_and_api_security_headers_are_closed_by_default() {
        let browser = harden_response(axum::response::IntoResponse::into_response("ok"), false);
        assert_eq!(
            browser
                .headers()
                .get(axum::http::header::X_CONTENT_TYPE_OPTIONS)
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            browser
                .headers()
                .get(axum::http::header::X_FRAME_OPTIONS)
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
        let csp = browser
            .headers()
            .get(axum::http::header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));

        let api = harden_response(axum::response::IntoResponse::into_response("ok"), true);
        assert_eq!(
            api.headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store, max-age=0")
        );
        assert!(api
            .headers()
            .get_all(axum::http::header::VARY)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| value == "X-Auth-Token"));
    }

    #[test]
    fn test_ct_token_eq() {
        assert!(ct_token_eq("abcdef", "abcdef"));
        assert!(!ct_token_eq("abcdeg", "abcdef"));
        assert!(!ct_token_eq("abc", "abcdef"));
        assert!(!ct_token_eq("", "abcdef"));
    }
}
