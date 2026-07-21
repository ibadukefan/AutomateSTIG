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

use reqwest::Url;
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

/// Exact hostnames allowed for DISA content downloads.
const ALLOWED_DISA_HOSTS: &[&str] = &["public.cyber.mil", "dl.dod.cyber.mil", "cyber.mil"];

/// Maximum compressed upload/download size accepted for DISA XCCDF ZIPs.
pub(crate) const MAX_XCCDF_ZIP_BYTES: usize = 100 * 1024 * 1024;
/// Maximum ZIP members inspected for DISA XCCDF import.
pub(crate) const MAX_XCCDF_ZIP_ENTRIES: usize = 512;
/// Maximum total declared uncompressed bytes across ZIP members.
pub(crate) const MAX_XCCDF_ZIP_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum uncompressed bytes read from any single XCCDF XML member.
pub(crate) const MAX_XCCDF_XML_BYTES: u64 = 50 * 1024 * 1024;

/// Validate a URL is on the DISA allowlist. Prevents SSRF attacks.
fn validate_disa_url(url: &str) -> Result<Url, String> {
    let parsed = Url::parse(url).map_err(|e| format!("Invalid DISA URL: {e}"))?;
    if parsed.scheme() != "https" {
        return Err("DISA URL must use https://".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("DISA URL must not include embedded credentials".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "DISA URL must include a host".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if !ALLOWED_DISA_HOSTS.iter().any(|allowed| *allowed == host) {
        return Err(format!(
            "URL not on allowlist. Only DISA hosts ({}) are permitted. Got: {}",
            ALLOWED_DISA_HOSTS.join(", "),
            url.chars().take(100).collect::<String>()
        ));
    }
    Ok(parsed)
}

fn append_download_chunk(buf: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<(), String> {
    let next_len = buf
        .len()
        .checked_add(chunk.len())
        .ok_or_else(|| "Downloaded ZIP size overflow".to_string())?;
    if next_len > limit {
        return Err(format!(
            "Downloaded ZIP is too large: {} > {} bytes",
            next_len, limit
        ));
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

async fn read_response_capped(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("Failed to read download: {}", e))?
    {
        append_download_chunk(&mut bytes, &chunk, limit)?;
    }
    Ok(bytes)
}

/// Validate a DISA/XCCDF ZIP before parsing XML from it.
pub(crate) fn validate_xccdf_zip_limits<R: std::io::Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Result<(), String> {
    validate_xccdf_zip_limits_with_caps(
        archive,
        MAX_XCCDF_ZIP_ENTRIES,
        MAX_XCCDF_ZIP_UNCOMPRESSED_BYTES,
        MAX_XCCDF_XML_BYTES,
    )
}

fn validate_xccdf_zip_limits_with_caps<R: std::io::Read + std::io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    max_entries: usize,
    max_uncompressed_bytes: u64,
    max_xccdf_xml_bytes: u64,
) -> Result<(), String> {
    if archive.len() > max_entries {
        return Err(format!(
            "ZIP has too many entries: {} > {}",
            archive.len(),
            max_entries
        ));
    }

    let mut total_uncompressed = 0u64;
    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .map_err(|e| format!("Failed to inspect ZIP entry {}: {}", i, e))?;
        let name = file.name().to_string();
        if name.contains('\\') || name.contains('\0') || file.enclosed_name().is_none() {
            return Err(format!("ZIP entry has unsafe path: {}", name));
        }
        total_uncompressed = total_uncompressed
            .checked_add(file.size())
            .ok_or_else(|| "ZIP declared size overflow".to_string())?;
        if total_uncompressed > max_uncompressed_bytes {
            return Err(format!(
                "ZIP expands beyond limit: {} > {} bytes",
                total_uncompressed, max_uncompressed_bytes
            ));
        }
        let lower = name.to_lowercase();
        if (lower.ends_with("-xccdf.xml") || lower.ends_with("_xccdf.xml"))
            && file.size() > max_xccdf_xml_bytes
        {
            return Err(format!(
                "XCCDF XML member is too large: {} has {} bytes, limit {}",
                name,
                file.size(),
                max_xccdf_xml_bytes
            ));
        }
    }

    Ok(())
}

/// Download a STIG ZIP from DISA and import it into the library.
pub async fn download_and_import(url: &str, state: &AppState) -> Result<FetchResult, String> {
    let parsed_url = validate_disa_url(url)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if validate_disa_url(attempt.url().as_str()).is_ok() {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .user_agent("AutomateSTIG/0.1")
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    // Download the ZIP.
    let response = client
        .get(parsed_url)
        .send()
        .await
        .map_err(|e| format!("Download failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Download failed with status: {}",
            response.status()
        ));
    }

    let bytes = read_response_capped(response, MAX_XCCDF_ZIP_BYTES).await?;

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
                combined.errors.push(format!("{}: {}", entry.title, e));
            }
        }
    }

    Ok(combined)
}

/// Import STIG content from in-memory ZIP bytes.
fn import_zip_bytes(data: &[u8], state: &AppState) -> Result<FetchResult, String> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| format!("Invalid ZIP: {}", e))?;
    validate_xccdf_zip_limits(&mut archive)?;

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
                        // Auto-generate check pack from check-content.
                        let conv = automatestig_core::converter::convert_benchmark(&benchmark);
                        if conv.automated > 0 {
                            let packs_dir = library.root().join("auto_check_packs");
                            let _ = std::fs::create_dir_all(&packs_dir);
                            if let Ok(json) =
                                automatestig_core::converter::check_pack_to_json(&conv.check_pack)
                            {
                                if let Ok(dest) = automatestig_core::path_safety::safe_join_under(
                                    &packs_dir,
                                    &format!("{}.json", id),
                                ) {
                                    let _ = std::fs::write(dest, &json);
                                }
                            }
                        }

                        if is_update {
                            result.updated_benchmarks += 1;
                            result.details.push(format!(
                                "Updated: {} {} ({} rules, {} auto-checks)",
                                id, ver, rules, conv.automated
                            ));
                        } else {
                            result.new_benchmarks += 1;
                            result.details.push(format!(
                                "New: {} {} ({} rules, {} auto-checks)",
                                id, ver, rules, conv.automated
                            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn zip_with_files(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            for (name, content) in files {
                writer.start_file(*name, options).unwrap();
                std::io::Write::write_all(&mut writer, content).unwrap();
            }
            writer.finish().unwrap();
        }
        bytes.into_inner()
    }

    #[test]
    fn validates_xccdf_zip_limits_reject_path_traversal() {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            writer.start_file("../evil-xccdf.xml", options).unwrap();
            std::io::Write::write_all(&mut writer, b"<Benchmark/>").unwrap();
            writer.finish().unwrap();
        }

        let cursor = std::io::Cursor::new(bytes.into_inner());
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        assert!(validate_xccdf_zip_limits(&mut archive).is_err());
    }

    #[test]
    fn validates_xccdf_zip_limits_accept_safe_xccdf_member() {
        let mut bytes = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut bytes);
            let options = zip::write::SimpleFileOptions::default();
            writer.start_file("safe/sample-xccdf.xml", options).unwrap();
            std::io::Write::write_all(&mut writer, b"<Benchmark/>").unwrap();
            writer.finish().unwrap();
        }

        let cursor = std::io::Cursor::new(bytes.into_inner());
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        validate_xccdf_zip_limits(&mut archive).unwrap();
    }

    #[test]
    fn rejects_non_disa_urls_and_embedded_credentials() {
        for url in [
            "http://public.cyber.mil/stigs/downloads/file.zip",
            "https://user:pass@public.cyber.mil/stigs/downloads/file.zip",
            "https://public.cyber.mil.evil.example/file.zip",
            "https://127.0.0.1/file.zip",
        ] {
            assert!(validate_disa_url(url).is_err(), "{url} should be rejected");
        }
        validate_disa_url("https://public.cyber.mil/stigs/downloads/file.zip").unwrap();
        validate_disa_url("https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/file.zip")
            .unwrap();
    }

    #[test]
    fn capped_download_accumulator_rejects_over_limit_before_buffering_more() {
        let mut buf = Vec::new();
        append_download_chunk(&mut buf, b"12345", 8).unwrap();
        assert!(append_download_chunk(&mut buf, b"6789", 8).is_err());
        assert_eq!(buf, b"12345");
    }

    #[test]
    fn validates_xccdf_zip_limits_reject_too_many_entries() {
        let zip = zip_with_files(&[("one.txt", b"1"), ("two.txt", b"2")]);
        let cursor = std::io::Cursor::new(zip);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        assert!(validate_xccdf_zip_limits_with_caps(&mut archive, 1, 100, 100).is_err());
    }

    #[test]
    fn validates_xccdf_zip_limits_reject_total_uncompressed_over_cap() {
        let zip = zip_with_files(&[("one.txt", b"12345"), ("two.txt", b"67890")]);
        let cursor = std::io::Cursor::new(zip);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        assert!(validate_xccdf_zip_limits_with_caps(&mut archive, 10, 9, 100).is_err());
    }

    #[test]
    fn validates_xccdf_zip_limits_reject_oversized_xccdf_member() {
        let zip = zip_with_files(&[("sample-xccdf.xml", b"0123456789")]);
        let cursor = std::io::Cursor::new(zip);
        let mut archive = zip::ZipArchive::new(cursor).unwrap();
        assert!(validate_xccdf_zip_limits_with_caps(&mut archive, 10, 100, 5).is_err());
    }

    #[test]
    fn validates_xccdf_zip_limits_reject_windows_absolute_and_null_paths() {
        for name in [
            "C:\\temp\\evil-xccdf.xml",
            "/tmp/evil-xccdf.xml",
            "evil\0-xccdf.xml",
        ] {
            let zip = zip_with_files(&[(name, b"<Benchmark/>")]);
            let cursor = std::io::Cursor::new(zip);
            let mut archive = zip::ZipArchive::new(cursor).unwrap();
            assert!(
                validate_xccdf_zip_limits(&mut archive).is_err(),
                "{name} should be rejected"
            );
        }
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
}
