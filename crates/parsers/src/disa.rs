//! Bounded, fail-closed DISA XCCDF ingestion.
//!
//! Every ZIP consumer uses this module so local CLI imports, GUI uploads, and
//! connected downloads enforce the same archive and decompression limits.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use automatestig_archive_safety::{ArchiveError, ArchivePolicy, SafeZipArchive};
use automatestig_core::models::stig::StigBenchmark;
use thiserror::Error;

use crate::xccdf;

pub const MAX_DISA_ARCHIVE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_DISA_ARCHIVE_ENTRIES: usize = 256;
pub const MAX_XCCDF_MEMBER_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_SELECTED_XCCDF_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_DECLARED_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_COMPRESSION_RATIO: u64 = 100;
pub const COMPRESSION_RATIO_GRACE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ParsedBenchmark {
    pub source_name: String,
    pub benchmark: StigBenchmark,
}

#[derive(Debug, Error)]
pub enum DisaImportError {
    #[error(transparent)]
    Archive(#[from] ArchiveError),

    #[error("XCCDF member {name} is not valid UTF-8")]
    InvalidUtf8 { name: String },

    #[error("invalid XCCDF benchmark in {name}: {reason}")]
    InvalidXccdf { name: String, reason: String },

    #[error("archive contains no XCCDF benchmark members")]
    NoXccdf,

    #[error("benchmark ID {id:?} occurs in both {first:?} and {second:?}")]
    DuplicateBenchmarkId {
        id: String,
        first: String,
        second: String,
    },

    #[error("XCCDF input exceeds the {limit}-byte limit")]
    XmlSizeExceeded { limit: u64 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl DisaImportError {
    pub fn is_resource_limit(&self) -> bool {
        matches!(self, Self::XmlSizeExceeded { .. })
            || matches!(self, Self::Archive(error) if error.is_resource_limit())
    }
}

pub fn disa_archive_policy() -> ArchivePolicy {
    let mut policy = ArchivePolicy::strict(
        MAX_DISA_ARCHIVE_BYTES,
        MAX_DISA_ARCHIVE_ENTRIES,
        MAX_DECLARED_ARCHIVE_BYTES,
        MAX_SELECTED_XCCDF_BYTES,
    );
    policy.max_declared_total_bytes = MAX_DECLARED_ARCHIVE_BYTES;
    policy.max_actual_member_bytes = MAX_XCCDF_MEMBER_BYTES;
    policy.max_actual_total_bytes = MAX_SELECTED_XCCDF_BYTES;
    policy.max_compression_ratio = Some(MAX_COMPRESSION_RATIO);
    policy.compression_ratio_grace_bytes = COMPRESSION_RATIO_GRACE_BYTES;
    policy
}

pub fn is_xccdf_benchmark(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("-xccdf.xml") || lower.ends_with("_xccdf.xml")
}

pub fn parse_disa_zip_path(path: &Path) -> Result<Vec<ParsedBenchmark>, DisaImportError> {
    let archive = SafeZipArchive::open_path(path, disa_archive_policy())?;
    parse_archive(archive)
}

pub fn parse_disa_zip_bytes(data: &[u8]) -> Result<Vec<ParsedBenchmark>, DisaImportError> {
    let archive = SafeZipArchive::from_bytes(data, disa_archive_policy())?;
    parse_archive(archive)
}

pub fn parse_xccdf_path(path: &Path) -> Result<ParsedBenchmark, DisaImportError> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_XCCDF_MEMBER_BYTES {
        return Err(DisaImportError::XmlSizeExceeded {
            limit: MAX_XCCDF_MEMBER_BYTES,
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_XCCDF_MEMBER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_XCCDF_MEMBER_BYTES {
        return Err(DisaImportError::XmlSizeExceeded {
            limit: MAX_XCCDF_MEMBER_BYTES,
        });
    }
    let source_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("upload.xml");
    parse_xccdf_bytes(source_name, &bytes)
}

fn parse_archive<R: std::io::Read + std::io::Seek>(
    mut archive: SafeZipArchive<R>,
) -> Result<Vec<ParsedBenchmark>, DisaImportError> {
    let candidates: Vec<_> = archive
        .entries()
        .iter()
        .filter(|entry| !entry.is_directory && is_xccdf_benchmark(&entry.name))
        .map(|entry| (entry.index, entry.name.clone()))
        .collect();
    if candidates.is_empty() {
        return Err(DisaImportError::NoXccdf);
    }

    let mut budget = archive.new_read_budget();
    let mut parsed = Vec::with_capacity(candidates.len());
    for (index, name) in candidates {
        let bytes = archive.read_index_with_limit(index, MAX_XCCDF_MEMBER_BYTES, &mut budget)?;
        parsed.push(parse_xccdf_bytes(&name, &bytes)?);
    }
    validate_unique_ids(&parsed)?;
    Ok(parsed)
}

pub fn parse_xccdf_bytes(
    source_name: &str,
    bytes: &[u8],
) -> Result<ParsedBenchmark, DisaImportError> {
    if bytes.len() as u64 > MAX_XCCDF_MEMBER_BYTES {
        return Err(DisaImportError::XmlSizeExceeded {
            limit: MAX_XCCDF_MEMBER_BYTES,
        });
    }
    let xml = std::str::from_utf8(bytes).map_err(|_| DisaImportError::InvalidUtf8 {
        name: source_name.to_owned(),
    })?;
    let benchmark =
        xccdf::parse_xccdf_benchmark_str(xml).map_err(|error| DisaImportError::InvalidXccdf {
            name: source_name.to_owned(),
            reason: error.to_string(),
        })?;

    // The low-level XCCDF reader remains intentionally permissive for legacy
    // conversion callers. Content import has a stricter boundary: a real
    // Benchmark root, a stable ID, and at least one rule are required.
    if benchmark.xccdf_id.is_none() || benchmark.id.trim().is_empty() {
        return Err(DisaImportError::InvalidXccdf {
            name: source_name.to_owned(),
            reason: "missing XCCDF Benchmark root or id".to_owned(),
        });
    }
    if benchmark.rules.is_empty() {
        return Err(DisaImportError::InvalidXccdf {
            name: source_name.to_owned(),
            reason: "benchmark contains no rules".to_owned(),
        });
    }

    Ok(ParsedBenchmark {
        source_name: source_name.to_owned(),
        benchmark,
    })
}

fn validate_unique_ids(parsed: &[ParsedBenchmark]) -> Result<(), DisaImportError> {
    let mut seen: HashMap<String, String> = HashMap::new();
    for item in parsed {
        if let Some(first) = seen.get(&item.benchmark.id) {
            return Err(DisaImportError::DuplicateBenchmarkId {
                id: item.benchmark.id.clone(),
                first: first.clone(),
                second: item.source_name.clone(),
            });
        }
        seen.insert(item.benchmark.id.clone(), item.source_name.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::write::SimpleFileOptions;

    use super::*;

    fn xml(id: &str) -> Vec<u8> {
        format!(
            r#"<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="{id}"><title>Test</title><version>1</version><Group id="V-1"><title>Group</title><Rule id="SV-1" severity="medium"><version>R-1</version><title>Rule</title></Rule></Group></Benchmark>"#
        )
        .into_bytes()
    }

    fn zip(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut output);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in files {
                writer.start_file(*name, options).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap();
        }
        output.into_inner()
    }

    #[test]
    fn parses_every_candidate_by_preflighted_index() {
        let bytes = zip(&[
            ("one-xccdf.xml", xml("one")),
            ("notes.txt", b"ignored".to_vec()),
            ("nested/two_XCCDF.XML", xml("two")),
        ]);
        let parsed = parse_disa_zip_bytes(&bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].benchmark.id, "one");
        assert_eq!(parsed[1].benchmark.id, "two");
    }

    #[test]
    fn rejects_no_xccdf_and_invalid_utf8() {
        let no_xccdf = zip(&[("readme.txt", b"hello".to_vec())]);
        assert!(matches!(
            parse_disa_zip_bytes(&no_xccdf),
            Err(DisaImportError::NoXccdf)
        ));

        let invalid = zip(&[("bad-xccdf.xml", vec![0xff, 0xfe])]);
        assert!(matches!(
            parse_disa_zip_bytes(&invalid),
            Err(DisaImportError::InvalidUtf8 { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_benchmark_ids_atomically() {
        let bytes = zip(&[
            ("one-xccdf.xml", xml("same")),
            ("two-xccdf.xml", xml("same")),
        ]);
        assert!(matches!(
            parse_disa_zip_bytes(&bytes),
            Err(DisaImportError::DuplicateBenchmarkId { .. })
        ));
    }

    #[test]
    fn rejects_declared_or_actual_xccdf_bombs() {
        let oversized = vec![b'A'; MAX_XCCDF_MEMBER_BYTES as usize + 1];
        let bytes = zip(&[("bomb-xccdf.xml", oversized)]);
        let error = parse_disa_zip_bytes(&bytes).unwrap_err();
        assert!(error.is_resource_limit(), "unexpected error: {error:?}");
    }

    #[test]
    fn xml_requires_a_real_nonempty_benchmark() {
        assert!(matches!(
            parse_xccdf_bytes("not-xccdf.xml", b"<root />"),
            Err(DisaImportError::InvalidXccdf { .. })
        ));
    }
}
