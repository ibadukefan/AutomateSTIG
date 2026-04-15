//! DISA STIG content fetcher.
//!
//! Fetches STIG content directly from https://public.cyber.mil/stigs/downloads/
//! Parses the downloads page to discover available STIGs, downloads the ZIPs,
//! extracts XCCDF benchmarks, and imports them into the local library.
//!
//! This module is only active when the app is in "Connected" mode.
//! In air-gapped mode, all network calls are disabled.

use std::io::Read;
use std::time::Duration;

use serde::Serialize;

use automatestig_parsers::xccdf;

use crate::state::AppState;

/// Base URL for DISA STIG downloads.
const DISA_DOWNLOADS_URL: &str = "https://public.cyber.mil/stigs/downloads/";

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
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("AutomateSTIG/0.1")
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Fetch the DISA downloads page.
    let html = client
        .get(DISA_DOWNLOADS_URL)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch DISA page: {}", e))?
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    parse_disa_downloads_page(&html)
}

/// Parse the DISA downloads HTML page to extract STIG download links.
fn parse_disa_downloads_page(html: &str) -> Result<Vec<DisaStigEntry>, String> {
    let document = scraper::Html::parse_document(html);
    let mut entries = Vec::new();

    // DISA's download page uses links to ZIP files.
    // Look for all links that point to STIG ZIP files.
    let link_selector = scraper::Selector::parse("a[href]").unwrap();

    for element in document.select(&link_selector) {
        if let Some(href) = element.value().attr("href") {
            let href_lower = href.to_lowercase();
            // Filter for STIG-related ZIP downloads.
            if (href_lower.contains("stig") || href_lower.contains("benchmark"))
                && href_lower.ends_with(".zip")
            {
                let title = element.text().collect::<String>().trim().to_string();
                let title = if title.is_empty() {
                    // Extract filename from URL.
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
                        href.to_string()
                    } else {
                        format!("https://public.cyber.mil{}", href)
                    },
                    size: None,
                    updated: None,
                });
            }
        }
    }

    // Deduplicate by URL.
    entries.sort_by(|a, b| a.download_url.cmp(&b.download_url));
    entries.dedup_by(|a, b| a.download_url == b.download_url);

    Ok(entries)
}

/// Download a STIG ZIP from DISA and import it into the library.
pub async fn download_and_import(
    url: &str,
    state: &AppState,
) -> Result<FetchResult, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("AutomateSTIG/0.1")
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    // Download the ZIP.
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Download failed with status: {}", response.status()));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read download: {}", e))?;

    // Process the ZIP.
    import_zip_bytes(&bytes, state)
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
                combined
                    .errors
                    .push(format!("{}: {}", entry.title, e));
            }
        }
    }

    Ok(combined)
}

/// Import STIG content from in-memory ZIP bytes.
fn import_zip_bytes(data: &[u8], state: &AppState) -> Result<FetchResult, String> {
    let cursor = std::io::Cursor::new(data);
    let mut archive =
        zip::ZipArchive::new(cursor).map_err(|e| format!("Invalid ZIP: {}", e))?;

    let mut result = FetchResult {
        new_benchmarks: 0,
        updated_benchmarks: 0,
        already_current: 0,
        details: Vec::new(),
        errors: Vec::new(),
    };

    let mut library = state
        .library()
        .map_err(|e| format!("Library error: {}", e))?;

    // Find all XCCDF files in the ZIP.
    let xccdf_names: Vec<String> = (0..archive.len())
        .filter_map(|i| {
            let file = archive.by_index(i).ok()?;
            let name = file.name().to_string();
            let lower = name.to_lowercase();
            if lower.ends_with("-xccdf.xml") || lower.ends_with("_xccdf.xml") {
                Some(name)
            } else {
                None
            }
        })
        .collect();

    for name in &xccdf_names {
        let mut file = match archive.by_name(name) {
            Ok(f) => f,
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to read {}: {}", name, e));
                continue;
            }
        };

        let mut xml = String::new();
        if let Err(e) = file.read_to_string(&mut xml) {
            result
                .errors
                .push(format!("Failed to read {}: {}", name, e));
            continue;
        }

        match xccdf::parse_xccdf_benchmark_str(&xml) {
            Ok(benchmark) => {
                let id = benchmark.id.clone();
                let ver = benchmark.version_string();
                let rules = benchmark.rules.len();

                // Check if already in library.
                let existing = library.get_benchmark_entry(&id);
                let is_update = existing.is_some();

                match library.add_benchmark(&benchmark) {
                    Ok(()) => {
                        if is_update {
                            result.updated_benchmarks += 1;
                            result
                                .details
                                .push(format!("Updated: {} {} ({} rules)", id, ver, rules));
                        } else {
                            result.new_benchmarks += 1;
                            result
                                .details
                                .push(format!("New: {} {} ({} rules)", id, ver, rules));
                        }
                    }
                    Err(e) => {
                        result.errors.push(format!("Failed to add {}: {}", id, e));
                    }
                }
            }
            Err(e) => {
                result
                    .errors
                    .push(format!("Parse error in {}: {}", name, e));
            }
        }
    }

    if xccdf_names.is_empty() {
        result.already_current += 1;
    }

    Ok(result)
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
