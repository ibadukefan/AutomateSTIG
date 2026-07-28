//! DISA STIG content fetcher.
//!
//! Fetches STIG content directly from https://public.cyber.mil/stigs/downloads/
//! Parses the downloads page to discover available STIGs, downloads the ZIPs,
//! extracts XCCDF benchmarks, and imports them into the local library.
//!
//! This module is only active when the app is in "Connected" mode.
//! In air-gapped mode, all network calls are disabled.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use automatestig_core::library::{BenchmarkImport, GeneratedCheckPackIntent};
use automatestig_parsers::disa::{self, ParsedBenchmark};

use crate::state::AppState;

/// Base URL for DISA STIG downloads.
const DISA_DOWNLOADS_URL: &str = "https://public.cyber.mil/stigs/downloads/";
const MAX_DOWNLOADS_PAGE_BYTES: u64 = 4 * 1024 * 1024;
const ALLOWED_DISA_HOSTS: &[&str] = &["public.cyber.mil", "dl.dod.cyber.mil", "cyber.mil"];

#[derive(Debug)]
pub enum FetchError {
    InvalidRequest(String),
    Remote(String),
    RemoteContent(String),
    Library(String),
    Worker(String),
}

impl FetchError {
    pub fn is_invalid_request(&self) -> bool {
        matches!(self, Self::InvalidRequest(_))
    }

    pub fn is_library_error(&self) -> bool {
        matches!(self, Self::Library(_) | Self::Worker(_))
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message)
            | Self::Remote(message)
            | Self::RemoteContent(message)
            | Self::Library(message)
            | Self::Worker(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for FetchError {}

/// A discovered STIG available for download from DISA.
#[derive(Debug, Clone, Serialize)]
pub struct DisaStigEntry {
    /// Display title.
    pub title: String,
    /// Direct download URL for the ZIP.
    pub download_url: String,
    /// File size (if available).
    pub size: Option<String>,
    /// Last updated date (if available).
    pub updated: Option<String>,
}

/// Result of a content fetch operation.
#[derive(Debug, Clone, Serialize)]
pub struct FetchResult {
    /// Number of new benchmarks imported.
    pub new_benchmarks: usize,
    /// Number of updated benchmarks.
    pub updated_benchmarks: usize,
    /// Number of benchmarks already up to date.
    pub already_current: usize,
    /// Details of each operation.
    pub details: Vec<String>,
    /// Any errors encountered.
    pub errors: Vec<String>,
}

/// Fetch the list of available STIGs from DISA's public download page.
pub async fn list_available_stigs() -> Result<Vec<DisaStigEntry>, String> {
    let client = disa_http_client(Duration::from_secs(30))
        .map_err(|error| format!("Failed to create HTTP client: {error}"))?;

    // Fetch the DISA downloads page.
    let response = client
        .get(DISA_DOWNLOADS_URL)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch DISA page: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "DISA downloads page returned status {}",
            response.status()
        ));
    }
    validate_parsed_disa_url(response.url(), false)
        .map_err(|error| format!("Unsafe DISA response URL: {error}"))?;
    let bytes = read_response_limited(response, MAX_DOWNLOADS_PAGE_BYTES)
        .await
        .map_err(|error| error.to_string())?;
    let html = std::str::from_utf8(&bytes)
        .map_err(|error| format!("DISA downloads page is not UTF-8: {error}"))?;

    parse_disa_downloads_page(html)
}

/// Parse the DISA downloads HTML page to extract STIG download links.
fn parse_disa_downloads_page(html: &str) -> Result<Vec<DisaStigEntry>, String> {
    let mut entries = Vec::new();
    let mut cursor = html;

    while let Some(anchor_start) = cursor.find("<a") {
        cursor = &cursor[anchor_start + 2..];
        let Some(tag_end) = cursor.find('>') else {
            break;
        };
        let tag = &cursor[..tag_end];
        let remainder = &cursor[tag_end + 1..];
        let Some(close_anchor) = remainder.find("</a>") else {
            cursor = remainder;
            continue;
        };
        let label_html = &remainder[..close_anchor];
        cursor = &remainder[close_anchor + 4..];

        let Some(href) = extract_href(tag) else {
            continue;
        };
        let href_lower = href.to_lowercase();
        if !(href_lower.contains("stig") || href_lower.contains("benchmark"))
            || !href_lower.ends_with(".zip")
        {
            continue;
        }

        let title = strip_html(label_html).trim().to_string();
        let title = if title.is_empty() {
            href.rsplit('/')
                .next()
                .unwrap_or("Unknown STIG")
                .to_string()
        } else {
            title
        };

        entries.push(DisaStigEntry {
            title,
            download_url: if href.starts_with("http") {
                href
            } else {
                format!("https://public.cyber.mil{}", href)
            },
            size: None,
            updated: None,
        });
    }

    // Deduplicate by URL.
    entries.sort_by(|a, b| a.download_url.cmp(&b.download_url));
    entries.dedup_by(|a, b| a.download_url == b.download_url);

    Ok(entries)
}

fn extract_href(anchor_tag: &str) -> Option<String> {
    let href_pos = anchor_tag.to_lowercase().find("href")?;
    let after_href = &anchor_tag[href_pos + 4..];
    let equals_pos = after_href.find('=')?;
    let value = after_href[equals_pos + 1..].trim_start();
    let quote = value.chars().next()?;
    if quote == '"' || quote == '\'' {
        let rest = &value[quote.len_utf8()..];
        let end = rest.find(quote)?;
        Some(rest[..end].to_string())
    } else {
        let end = value
            .find(|c: char| c.is_whitespace())
            .unwrap_or(value.len());
        Some(value[..end].trim_end_matches('/').to_string())
    }
}

fn strip_html(input: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

/// Validate a URL is on the DISA allowlist. Prevents SSRF attacks.
fn validate_disa_url(url: &str, require_zip: bool) -> Result<reqwest::Url, FetchError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|error| FetchError::InvalidRequest(format!("Invalid DISA URL: {error}")))?;
    validate_parsed_disa_url(&parsed, require_zip).map_err(FetchError::InvalidRequest)?;
    Ok(parsed)
}

fn validate_parsed_disa_url(url: &reqwest::Url, require_zip: bool) -> Result<(), String> {
    if url.scheme() != "https" {
        return Err("DISA URLs must use HTTPS".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("DISA URLs may not contain credentials".to_owned());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "DISA URL is missing a hostname".to_owned())?;
    if !ALLOWED_DISA_HOSTS.contains(&host) {
        return Err(format!("hostname {host:?} is not on the DISA allowlist"));
    }
    if let Some(port) = url.port() {
        if port != 443 {
            return Err("DISA URLs may use only the default HTTPS port".to_owned());
        }
    }
    if url.fragment().is_some() {
        return Err("DISA URLs may not contain fragments".to_owned());
    }
    if require_zip && !url.path().to_ascii_lowercase().ends_with(".zip") {
        return Err("DISA content URL path must end in .zip".to_owned());
    }
    Ok(())
}

fn disa_http_client(timeout: Duration) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("AutomateSTIG/0.2")
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.error(std::io::Error::other("too many DISA redirects"));
            }
            if let Err(error) = validate_parsed_disa_url(attempt.url(), false) {
                return attempt.error(std::io::Error::other(error));
            }
            attempt.follow()
        }))
        .build()
}

async fn read_response_limited(
    mut response: reqwest::Response,
    limit: u64,
) -> Result<Vec<u8>, FetchError> {
    if let Some(length) = response.content_length() {
        if length > limit {
            return Err(FetchError::Remote(format!(
                "Remote content length {length} exceeds the {limit}-byte limit"
            )));
        }
    }
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(limit)
            .try_into()
            .unwrap_or(0),
    );
    let mut received = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| FetchError::Remote(format!("Failed to read download: {error}")))?
    {
        received = received.checked_add(chunk.len() as u64).ok_or_else(|| {
            FetchError::Remote("Remote content size arithmetic overflowed".to_owned())
        })?;
        if received > limit {
            return Err(FetchError::Remote(format!(
                "Remote content exceeds the {limit}-byte limit"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Download a STIG ZIP from DISA and import it into the library.
pub async fn download_and_import(url: &str, state: &AppState) -> Result<FetchResult, FetchError> {
    let url = validate_disa_url(url, true)?;
    let client = disa_http_client(Duration::from_secs(120))
        .map_err(|error| FetchError::Remote(format!("HTTP client error: {error}")))?;

    // Download the ZIP.
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|error| FetchError::Remote(format!("Download failed: {error}")))?;

    if !response.status().is_success() {
        return Err(FetchError::Remote(format!(
            "Download failed with status: {}",
            response.status()
        )));
    }
    validate_parsed_disa_url(response.url(), true)
        .map_err(|error| FetchError::Remote(format!("Unsafe final download URL: {error}")))?;

    let bytes = read_response_limited(response, disa::MAX_DISA_ARCHIVE_BYTES).await?;

    let parsed = disa::parse_disa_zip_bytes(&bytes)
        .map_err(|error| FetchError::RemoteContent(format!("DISA archive rejected: {error}")))?;
    let permit = state
        .inner
        .content_import_lock
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| FetchError::Worker("Content import coordinator is unavailable".to_owned()))?;
    let task_state = state.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        import_parsed(parsed, &task_state)
    })
    .await
    .map_err(|error| FetchError::Worker(format!("Content import worker failed: {error}")))?
}

/// Download all available STIGs from DISA (or a filtered set).
pub async fn fetch_all_content(state: &AppState) -> Result<FetchResult, String> {
    let available = list_available_stigs().await?;

    let mut combined = FetchResult {
        new_benchmarks: 0,
        updated_benchmarks: 0,
        already_current: 0,
        details: Vec::new(),
        errors: Vec::new(),
    };

    if available.is_empty() {
        combined
            .details
            .push("No STIG downloads found on DISA site".to_string());
        return Ok(combined);
    }

    combined
        .details
        .push(format!("Found {} STIG packages on DISA", available.len()));

    for entry in &available {
        match download_and_import(&entry.download_url, state).await {
            Ok(result) => {
                combined.new_benchmarks += result.new_benchmarks;
                combined.updated_benchmarks += result.updated_benchmarks;
                combined.already_current += result.already_current;
                combined.details.extend(result.details);
            }
            Err(e) => {
                combined.errors.push(format!("{}: {}", entry.title, e));
            }
        }
    }

    Ok(combined)
}

fn import_parsed(
    parsed: Vec<ParsedBenchmark>,
    state: &AppState,
) -> Result<FetchResult, FetchError> {
    let mut library = state
        .library()
        .map_err(|error| FetchError::Library(format!("Library error: {error}")))?;
    let imports: Vec<_> = parsed
        .iter()
        // Connected DISA fetch installs reference benchmarks only. Executable
        // checks must arrive through the reviewed embedded/signed-pack path.
        .map(|item| BenchmarkImport::new(&item.benchmark, GeneratedCheckPackIntent::Remove))
        .collect();
    let outcome = library
        .import_benchmarks(&imports)
        .map_err(|error| FetchError::Library(format!("Library import failed: {error}")))?;
    let added: std::collections::HashSet<_> = outcome.added_ids.iter().collect();
    let details = parsed
        .iter()
        .map(|item| {
            let action = if added.contains(&item.benchmark.id) {
                "New"
            } else {
                "Updated"
            };
            format!(
                "{action}: {} {} ({} rules, reference content only; source {})",
                item.benchmark.id,
                item.benchmark.version_string(),
                item.benchmark.rules.len(),
                item.source_name
            )
        })
        .collect();

    Ok(FetchResult {
        new_benchmarks: outcome.added_count(),
        updated_benchmarks: outcome.updated_count(),
        already_current: 0,
        details,
        errors: Vec::new(),
    })
}

/// Background update checker.
/// Runs periodically to check for new STIG content from DISA.
pub async fn start_background_checker(state: AppState, interval_hours: u64) {
    let interval = Duration::from_secs(interval_hours * 3600);

    loop {
        tokio::time::sleep(interval).await;

        tracing::info!("Background STIG update check starting...");

        match check_for_updates(&state).await {
            Ok(result) => {
                if result.new_benchmarks > 0 || result.updated_benchmarks > 0 {
                    tracing::info!(
                        "STIG update check complete: {} new, {} updated",
                        result.new_benchmarks,
                        result.updated_benchmarks
                    );
                } else {
                    tracing::info!("STIG update check: all content is current");
                }
            }
            Err(e) => {
                tracing::warn!("STIG update check failed: {}", e);
            }
        }
    }
}

/// Check for updates without downloading everything — just see what's available.
pub async fn check_for_updates(state: &AppState) -> Result<UpdateCheckResult, String> {
    let available = list_available_stigs().await?;
    let library = state
        .library()
        .map_err(|e| format!("Library error: {}", e))?;

    let installed: Vec<String> = library
        .list_benchmarks()
        .iter()
        .map(|b| b.id.clone())
        .collect();

    Ok(UpdateCheckResult {
        available_count: available.len(),
        installed_count: installed.len(),
        new_benchmarks: 0, // Would need to compare versions
        updated_benchmarks: 0,
        available_stigs: available,
    })
}

/// Result of an update check.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheckResult {
    pub available_count: usize,
    pub installed_count: usize,
    pub new_benchmarks: usize,
    pub updated_benchmarks: usize,
    pub available_stigs: Vec<DisaStigEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn raw_http_response(response: &'static [u8]) -> reqwest::Response {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(response).await.unwrap();
        });
        reqwest::Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap()
    }

    #[test]
    fn parses_disa_download_links_without_html_parser_dependency() {
        let html = r#"
            <html><body>
              <a href="/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_STIG.zip">
                <span>Windows Server 2022 STIG</span>
              </a>
              <a class='download' href='https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_STIG.zip'>RHEL 8 STIG</a>
              <a href="/not-a-stig.txt">Ignore me</a>
              <a href="/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_STIG.zip">Duplicate</a>
            </body></html>
        "#;

        let entries = parse_disa_downloads_page(html).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].title, "RHEL 8 STIG");
        assert_eq!(
            entries[0].download_url,
            "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_STIG.zip"
        );
        assert_eq!(entries[1].title, "Windows Server 2022 STIG");
        assert_eq!(
            entries[1].download_url,
            "https://public.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_STIG.zip"
        );
    }

    #[test]
    fn parses_empty_anchor_title_from_filename() {
        let html = r#"<a href=/wp-content/uploads/stigs/zip/U_Benchmark.zip></a>"#;

        let entries = parse_disa_downloads_page(html).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "U_Benchmark.zip");
    }

    #[test]
    fn disa_url_allowlist_uses_parsed_exact_hosts() {
        assert!(validate_disa_url("https://public.cyber.mil/wp-content/U_STIG.zip", true).is_ok());
        assert!(validate_disa_url(
            "https://dl.dod.cyber.mil:443/content/U_STIG.ZIP?download=1",
            true
        )
        .is_ok());

        for unsafe_url in [
            "http://public.cyber.mil/content/U_STIG.zip",
            "https://public.cyber.mil.evil.example/U_STIG.zip",
            "https://public.cyber.mil@evil.example/U_STIG.zip",
            "https://public.cyber.mil:444/U_STIG.zip",
            "https://public.cyber.mil/content/not-a-pack.xml",
            "https://public.cyber.mil/content/U_STIG.zip#fragment",
        ] {
            assert!(
                validate_disa_url(unsafe_url, true).is_err(),
                "unexpectedly accepted {unsafe_url}"
            );
        }
    }

    #[tokio::test]
    async fn streamed_body_limit_does_not_require_content_length() {
        let response = raw_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n",
        )
        .await;
        let error = read_response_limited(response, 6).await.unwrap_err();
        assert!(matches!(error, FetchError::Remote(_)));
    }

    #[tokio::test]
    async fn content_length_is_only_an_early_rejection() {
        let response = raw_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n",
        )
        .await;
        let error = read_response_limited(response, 6).await.unwrap_err();
        assert!(matches!(error, FetchError::Remote(_)));
    }
}
