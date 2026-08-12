//! Fail-closed ZIP archive inspection and bounded decompression.
//!
//! ZIP central-directory metadata is untrusted. [`SafeZipArchive`] therefore
//! performs a cheap metadata preflight and also limits the bytes emitted by the
//! decompressor. Callers address entries by the preflighted index so duplicate
//! names cannot change which member is read.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Component, Path};

use thiserror::Error;
use zip::{CompressionMethod, ZipArchive};

/// Limits and format restrictions applied to an archive.
#[derive(Clone, Debug)]
pub struct ArchivePolicy {
    /// Maximum size of the archive before decompression.
    pub max_compressed_bytes: u64,
    /// Maximum number of central-directory entries, including directories.
    pub max_entries: usize,
    /// Maximum declared uncompressed size of one member.
    pub max_declared_member_bytes: u64,
    /// Maximum sum of all declared uncompressed member sizes.
    pub max_declared_total_bytes: u64,
    /// Maximum number of bytes actually emitted for one member.
    pub max_actual_member_bytes: u64,
    /// Maximum number of bytes actually emitted across selected members.
    pub max_actual_total_bytes: u64,
    /// Maximum raw UTF-8 member-name length.
    pub max_name_bytes: usize,
    /// Maximum number of path components in a member name.
    pub max_path_components: usize,
    /// Compression methods accepted by this consumer.
    pub allowed_compression: Vec<CompressionMethod>,
    /// Optional declared compression-ratio screen. This is defense in depth;
    /// actual decompressed-byte limits remain authoritative.
    pub max_compression_ratio: Option<u64>,
    /// Do not apply ratio screening below this declared member size.
    pub compression_ratio_grace_bytes: u64,
    /// Whether explicit directory entries are allowed.
    pub allow_directories: bool,
}

impl ArchivePolicy {
    /// A strict policy with caller-provided resource bounds.
    pub fn strict(
        max_compressed_bytes: u64,
        max_entries: usize,
        max_member_bytes: u64,
        max_total_bytes: u64,
    ) -> Self {
        Self {
            max_compressed_bytes,
            max_entries,
            max_declared_member_bytes: max_member_bytes,
            max_declared_total_bytes: max_total_bytes,
            max_actual_member_bytes: max_member_bytes,
            max_actual_total_bytes: max_total_bytes,
            max_name_bytes: 1_024,
            max_path_components: 16,
            allowed_compression: vec![CompressionMethod::Stored, CompressionMethod::Deflated],
            max_compression_ratio: None,
            compression_ratio_grace_bytes: 0,
            allow_directories: true,
        }
    }
}

/// A central-directory entry that passed preflight validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveEntry {
    pub index: usize,
    pub name: String,
    pub declared_size: u64,
    pub compressed_size: u64,
    pub is_directory: bool,
    pub compression: CompressionMethod,
}

/// Tracks the actual decompressed-byte budget for one archive operation.
#[derive(Clone, Debug)]
pub struct ReadBudget {
    limit: u64,
    consumed: u64,
}

impl ReadBudget {
    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.consumed)
    }
}

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("archive is {actual} bytes, exceeding compressed-size limit of {limit} bytes")]
    CompressedSizeExceeded { actual: u64, limit: u64 },

    #[error("archive contains {actual} entries, exceeding limit of {limit}")]
    EntryCountExceeded { actual: usize, limit: usize },

    #[error("archive member {index} has a non-UTF-8 name")]
    NonUtf8Name { index: usize },

    #[error("unsafe archive member path {name:?}: {reason}")]
    UnsafePath { name: String, reason: &'static str },

    #[error("duplicate archive member name: {name}")]
    DuplicateName { name: String },

    #[error(
        "central directory declares {declared} entries but exposes only {unique} unique names"
    )]
    CentralDirectoryNameCollision { declared: u64, unique: usize },

    #[error(
        "archive member names collide after case/path normalization: {first:?} and {second:?}"
    )]
    NormalizedNameCollision { first: String, second: String },

    #[error("encrypted archive member is not allowed: {name}")]
    EncryptedMember { name: String },

    #[error("symbolic-link archive member is not allowed: {name}")]
    SymlinkMember { name: String },

    #[error("special-file archive member is not allowed: {name}")]
    SpecialFileMember { name: String },

    #[error("directory archive member is not allowed: {name}")]
    DirectoryMember { name: String },

    #[error("unsupported compression method {method} for archive member {name}")]
    UnsupportedCompression { name: String, method: String },

    #[error("declared compression ratio for archive member {name} ({uncompressed}:{compressed}) exceeds {max_ratio}:1")]
    CompressionRatioExceeded {
        name: String,
        uncompressed: u64,
        compressed: u64,
        max_ratio: u64,
    },

    #[error("declared size of archive member {name} is {actual} bytes, exceeding limit of {limit} bytes")]
    DeclaredMemberSizeExceeded {
        name: String,
        actual: u64,
        limit: u64,
    },

    #[error("declared archive size exceeds aggregate limit of {limit} bytes")]
    DeclaredTotalSizeExceeded { limit: u64 },

    #[error("archive size arithmetic overflowed")]
    SizeOverflow,

    #[error("archive members overlap: {first:?} and {second:?}")]
    OverlappingMembers { first: String, second: String },

    #[error("missing archive member: {0}")]
    MissingMember(String),

    #[error("cannot read directory archive member: {0}")]
    CannotReadDirectory(String),

    #[error("actual decompressed size of archive member {name} exceeds limit of {limit} bytes")]
    ActualMemberSizeExceeded { name: String, limit: u64 },

    #[error("actual decompressed archive data exceeds aggregate limit of {limit} bytes while reading {name}")]
    ActualTotalSizeExceeded { name: String, limit: u64 },

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ArchiveError {
    /// Whether this error should normally map to a resource-limit response
    /// (for example HTTP 413) rather than a generic malformed-archive error.
    pub fn is_resource_limit(&self) -> bool {
        matches!(
            self,
            Self::CompressedSizeExceeded { .. }
                | Self::EntryCountExceeded { .. }
                | Self::CompressionRatioExceeded { .. }
                | Self::DeclaredMemberSizeExceeded { .. }
                | Self::DeclaredTotalSizeExceeded { .. }
                | Self::ActualMemberSizeExceeded { .. }
                | Self::ActualTotalSizeExceeded { .. }
        )
    }
}

/// A ZIP archive whose metadata was preflighted against an [`ArchivePolicy`].
pub struct SafeZipArchive<R: Read + Seek> {
    archive: ZipArchive<R>,
    policy: ArchivePolicy,
    entries: Vec<ArchiveEntry>,
    name_to_index: HashMap<String, usize>,
}

impl SafeZipArchive<File> {
    /// Open an archive from disk after enforcing the compressed-size limit.
    pub fn open_path(path: &Path, policy: ArchivePolicy) -> Result<Self, ArchiveError> {
        let file = File::open(path)?;
        let compressed_len = file.metadata()?.len();
        Self::from_reader(file, compressed_len, policy)
    }
}

impl<'a> SafeZipArchive<Cursor<&'a [u8]>> {
    /// Inspect archive bytes without filesystem or network side effects.
    ///
    /// This entry point is suitable for fuzz targets: constructing the safe
    /// archive performs the complete metadata preflight, after which a target
    /// can read selected indices with a bounded [`ReadBudget`].
    pub fn from_bytes(bytes: &'a [u8], policy: ArchivePolicy) -> Result<Self, ArchiveError> {
        Self::from_reader(Cursor::new(bytes), bytes.len() as u64, policy)
    }
}

impl<R: Read + Seek> SafeZipArchive<R> {
    /// Open an archive from a reader whose exact compressed length is known.
    ///
    /// Streamed callers must count ingress bytes before invoking this method;
    /// `compressed_len` is part of the security boundary and may not be derived
    /// solely from an untrusted HTTP `Content-Length` header.
    pub fn from_reader(
        mut reader: R,
        compressed_len: u64,
        policy: ArchivePolicy,
    ) -> Result<Self, ArchiveError> {
        if compressed_len > policy.max_compressed_bytes {
            return Err(ArchiveError::CompressedSizeExceeded {
                actual: compressed_len,
                limit: policy.max_compressed_bytes,
            });
        }

        // zip 2.x stores entries in a name-keyed map and therefore collapses
        // exact duplicate names. Preserve the central-directory count before
        // construction so those ambiguous archives cannot evade duplicate and
        // entry-count policy checks.
        let declared_entry_count = central_directory_entry_count(&mut reader, compressed_len)?;
        if let Some(declared) = declared_entry_count {
            if declared > policy.max_entries as u64 {
                return Err(ArchiveError::EntryCountExceeded {
                    actual: usize::try_from(declared).unwrap_or(usize::MAX),
                    limit: policy.max_entries,
                });
            }
        }

        let mut archive = ZipArchive::new(reader)?;
        if let Some(declared) = declared_entry_count {
            if declared != archive.len() as u64 {
                return Err(ArchiveError::CentralDirectoryNameCollision {
                    declared,
                    unique: archive.len(),
                });
            }
        }
        if archive.len() > policy.max_entries {
            return Err(ArchiveError::EntryCountExceeded {
                actual: archive.len(),
                limit: policy.max_entries,
            });
        }

        let mut entries = Vec::with_capacity(archive.len());
        let mut name_to_index = HashMap::with_capacity(archive.len());
        let mut normalized_names: HashMap<String, String> = HashMap::new();
        let mut exact_names = HashSet::with_capacity(archive.len());
        let mut declared_total = 0u64;
        let mut regions = Vec::with_capacity(archive.len());

        for index in 0..archive.len() {
            // Raw access exposes metadata (including encrypted flags) without
            // starting a decompressor or requiring a password.
            let file = archive.by_index_raw(index)?;
            let name = std::str::from_utf8(file.name_raw())
                .map_err(|_| ArchiveError::NonUtf8Name { index })?
                .to_owned();
            let (canonical_name, normalized_name) = validate_path(&name, &policy)?;

            if !exact_names.insert(canonical_name.clone()) {
                return Err(ArchiveError::DuplicateName {
                    name: canonical_name,
                });
            }
            if let Some(first) = normalized_names.insert(normalized_name, canonical_name.clone()) {
                return Err(ArchiveError::NormalizedNameCollision {
                    first,
                    second: canonical_name,
                });
            }
            if file.encrypted() {
                return Err(ArchiveError::EncryptedMember {
                    name: canonical_name,
                });
            }
            if file.is_symlink() {
                return Err(ArchiveError::SymlinkMember {
                    name: canonical_name,
                });
            }

            let is_directory = file.is_dir();
            if is_directory && !policy.allow_directories {
                return Err(ArchiveError::DirectoryMember {
                    name: canonical_name,
                });
            }
            if let Some(mode) = file.unix_mode() {
                let file_type = mode & 0o170000;
                let regular = file_type == 0 || file_type == 0o100000;
                let directory = file_type == 0o040000 && is_directory;
                if !regular && !directory {
                    return Err(ArchiveError::SpecialFileMember {
                        name: canonical_name,
                    });
                }
            }

            let compression = file.compression();
            if !policy.allowed_compression.contains(&compression) {
                return Err(ArchiveError::UnsupportedCompression {
                    name: canonical_name,
                    method: compression.to_string(),
                });
            }

            let declared_size = file.size();
            if declared_size > policy.max_declared_member_bytes {
                return Err(ArchiveError::DeclaredMemberSizeExceeded {
                    name: canonical_name,
                    actual: declared_size,
                    limit: policy.max_declared_member_bytes,
                });
            }
            declared_total = declared_total
                .checked_add(declared_size)
                .ok_or(ArchiveError::SizeOverflow)?;
            if declared_total > policy.max_declared_total_bytes {
                return Err(ArchiveError::DeclaredTotalSizeExceeded {
                    limit: policy.max_declared_total_bytes,
                });
            }
            if declared_size > policy.compression_ratio_grace_bytes {
                if let Some(max_ratio) = policy.max_compression_ratio {
                    let compressed_size = file.compressed_size();
                    let allowed_uncompressed = compressed_size
                        .checked_mul(max_ratio)
                        .ok_or(ArchiveError::SizeOverflow)?;
                    if declared_size > allowed_uncompressed {
                        return Err(ArchiveError::CompressionRatioExceeded {
                            name: canonical_name,
                            uncompressed: declared_size,
                            compressed: compressed_size,
                            max_ratio,
                        });
                    }
                }
            }

            let region_start = file.header_start();
            let region_end = file
                .data_start()
                .checked_add(file.compressed_size())
                .ok_or(ArchiveError::SizeOverflow)?;
            if region_end < region_start {
                return Err(ArchiveError::SizeOverflow);
            }
            regions.push((region_start, region_end, canonical_name.clone()));

            name_to_index.insert(canonical_name.clone(), index);
            entries.push(ArchiveEntry {
                index,
                name: canonical_name,
                declared_size,
                compressed_size: file.compressed_size(),
                is_directory,
                compression,
            });
        }

        regions.sort_by_key(|region| region.0);
        for adjacent in regions.windows(2) {
            let (left_start, left_end, left_name) = &adjacent[0];
            let (right_start, _, right_name) = &adjacent[1];
            if left_start < left_end && right_start < left_end {
                return Err(ArchiveError::OverlappingMembers {
                    first: left_name.clone(),
                    second: right_name.clone(),
                });
            }
        }

        Ok(Self {
            archive,
            policy,
            entries,
            name_to_index,
        })
    }

    pub fn entries(&self) -> &[ArchiveEntry] {
        &self.entries
    }

    pub fn entry(&self, name: &str) -> Option<&ArchiveEntry> {
        self.name_to_index
            .get(name)
            .and_then(|index| self.entries.get(*index))
    }

    pub fn new_read_budget(&self) -> ReadBudget {
        ReadBudget {
            limit: self.policy.max_actual_total_bytes,
            consumed: 0,
        }
    }

    pub fn read_named(
        &mut self,
        name: &str,
        budget: &mut ReadBudget,
    ) -> Result<Vec<u8>, ArchiveError> {
        self.read_named_with_limit(name, self.policy.max_actual_member_bytes, budget)
    }

    /// Read a member with both the policy's per-member limit and a narrower
    /// caller limit. The decompressor is probed to `effective_limit + 1`, so
    /// over-limit data is rejected rather than silently truncated.
    pub fn read_named_with_limit(
        &mut self,
        name: &str,
        caller_limit: u64,
        budget: &mut ReadBudget,
    ) -> Result<Vec<u8>, ArchiveError> {
        let index = *self
            .name_to_index
            .get(name)
            .ok_or_else(|| ArchiveError::MissingMember(name.to_owned()))?;
        self.read_index_with_limit(index, caller_limit, budget)
    }

    pub fn read_index_with_limit(
        &mut self,
        index: usize,
        caller_limit: u64,
        budget: &mut ReadBudget,
    ) -> Result<Vec<u8>, ArchiveError> {
        let entry = self
            .entries
            .get(index)
            .cloned()
            .ok_or_else(|| ArchiveError::MissingMember(format!("entry index {index}")))?;
        if entry.is_directory {
            return Err(ArchiveError::CannotReadDirectory(entry.name));
        }

        let member_limit = self.policy.max_actual_member_bytes.min(caller_limit);
        if entry.declared_size > member_limit {
            return Err(ArchiveError::DeclaredMemberSizeExceeded {
                name: entry.name,
                actual: entry.declared_size,
                limit: member_limit,
            });
        }
        // Never trust a budget created for another, more permissive archive.
        // The archive's own aggregate policy remains the upper bound.
        let aggregate_limit = budget.limit.min(self.policy.max_actual_total_bytes);
        let remaining = aggregate_limit.saturating_sub(budget.consumed);
        let effective_limit = member_limit.min(remaining);
        let probe_limit = effective_limit
            .checked_add(1)
            .ok_or(ArchiveError::SizeOverflow)?;

        let mut file = self.archive.by_index(index)?;
        let mut data = Vec::new();
        file.by_ref().take(probe_limit).read_to_end(&mut data)?;
        if data.len() as u64 > effective_limit {
            if remaining <= member_limit {
                return Err(ArchiveError::ActualTotalSizeExceeded {
                    name: entry.name,
                    limit: aggregate_limit,
                });
            }
            return Err(ArchiveError::ActualMemberSizeExceeded {
                name: entry.name,
                limit: member_limit,
            });
        }

        budget.consumed = budget
            .consumed
            .checked_add(data.len() as u64)
            .ok_or(ArchiveError::SizeOverflow)?;
        Ok(data)
    }
}

fn validate_path(name: &str, policy: &ArchivePolicy) -> Result<(String, String), ArchiveError> {
    if name.is_empty() {
        return Err(ArchiveError::UnsafePath {
            name: name.to_owned(),
            reason: "empty name",
        });
    }
    if name.len() > policy.max_name_bytes {
        return Err(ArchiveError::UnsafePath {
            name: name.to_owned(),
            reason: "name is too long",
        });
    }
    if name.contains('\0') || name.contains('\\') {
        return Err(ArchiveError::UnsafePath {
            name: name.to_owned(),
            reason: "NUL and backslash are not allowed",
        });
    }

    let is_directory = name.ends_with('/');
    let without_trailing_slash = name.strip_suffix('/').unwrap_or(name);
    if without_trailing_slash.is_empty() || Path::new(name).is_absolute() {
        return Err(ArchiveError::UnsafePath {
            name: name.to_owned(),
            reason: "absolute or empty path",
        });
    }

    let mut parts = Vec::new();
    for component in Path::new(without_trailing_slash).components() {
        match component {
            Component::Normal(part) if !part.is_empty() => {
                parts.push(part.to_string_lossy().into_owned())
            }
            _ => {
                return Err(ArchiveError::UnsafePath {
                    name: name.to_owned(),
                    reason: "non-normal path component",
                })
            }
        }
    }
    if parts.is_empty() || parts.len() > policy.max_path_components {
        return Err(ArchiveError::UnsafePath {
            name: name.to_owned(),
            reason: "invalid path depth",
        });
    }

    let mut canonical = parts.join("/");
    if is_directory {
        canonical.push('/');
    }
    if canonical != name {
        return Err(ArchiveError::UnsafePath {
            name: name.to_owned(),
            reason: "path is not in canonical form",
        });
    }

    // Directory/file aliases and common case-insensitive filesystem aliases
    // share the same normalized key.
    let normalized = parts.join("/").to_lowercase();
    Ok((canonical, normalized))
}

fn central_directory_entry_count<R: Read + Seek>(
    reader: &mut R,
    compressed_len: u64,
) -> Result<Option<u64>, ArchiveError> {
    // EOCD is at least 22 bytes and its comment is at most u16::MAX bytes.
    const MAX_EOCD_SEARCH: u64 = 22 + u16::MAX as u64;
    if compressed_len < 22 {
        return Ok(None);
    }
    let tail_len = compressed_len.min(MAX_EOCD_SEARCH);
    reader.seek(SeekFrom::Start(compressed_len - tail_len))?;
    let mut tail = vec![0u8; tail_len as usize];
    reader.read_exact(&mut tail)?;

    let Some(relative_eocd) = (0..=tail.len() - 22).rev().find(|offset| {
        tail[*offset..].starts_with(b"PK\x05\x06")
            && *offset + 22 + u16::from_le_bytes([tail[*offset + 20], tail[*offset + 21]]) as usize
                == tail.len()
    }) else {
        return Ok(None);
    };
    let eocd_offset = compressed_len - tail_len + relative_eocd as u64;
    let count = u16::from_le_bytes([tail[relative_eocd + 10], tail[relative_eocd + 11]]);
    if count != u16::MAX {
        return Ok(Some(count as u64));
    }

    // ZIP64 locator immediately precedes the traditional EOCD.
    if eocd_offset < 20 {
        return Ok(None);
    }
    reader.seek(SeekFrom::Start(eocd_offset - 20))?;
    let mut locator = [0u8; 20];
    reader.read_exact(&mut locator)?;
    if !locator.starts_with(b"PK\x06\x07") {
        return Ok(None);
    }
    let zip64_eocd_offset = u64::from_le_bytes(locator[8..16].try_into().unwrap());
    reader.seek(SeekFrom::Start(zip64_eocd_offset))?;
    let mut zip64_eocd = [0u8; 56];
    reader.read_exact(&mut zip64_eocd)?;
    if !zip64_eocd.starts_with(b"PK\x06\x06") {
        return Ok(None);
    }
    Ok(Some(u64::from_le_bytes(
        zip64_eocd[32..40].try_into().unwrap(),
    )))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        {
            let mut writer = ZipWriter::new(&mut output);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            for (name, bytes) in files {
                writer.start_file(*name, options).unwrap();
                writer.write_all(bytes).unwrap();
            }
            writer.finish().unwrap();
        }
        output.into_inner()
    }

    fn policy(member: u64, total: u64) -> ArchivePolicy {
        ArchivePolicy::strict(1024 * 1024, 16, member, total)
    }

    #[test]
    fn actual_member_limit_uses_n_plus_one_probe() {
        let mut bytes = make_zip(&[("large.xml", &vec![b'A'; 1_025])]);
        let central = bytes
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .unwrap();
        bytes[central + 24..central + 28].copy_from_slice(&1_024u32.to_le_bytes());
        let configured = policy(1_024, 8_192);
        let mut archive = SafeZipArchive::from_bytes(&bytes, configured).unwrap();
        let mut budget = archive.new_read_budget();
        let error = archive.read_named("large.xml", &mut budget).unwrap_err();
        assert!(
            matches!(error, ArchiveError::ActualMemberSizeExceeded { .. }),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn forged_small_declared_size_cannot_bypass_runtime_limit() {
        let mut bytes = make_zip(&[("bomb.xml", &vec![b'A'; 32 * 1024])]);
        let central = bytes
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .unwrap();
        // Central-directory uncompressed size is attacker-controlled. Forge it
        // to one byte while leaving the real deflate stream intact.
        bytes[central + 24..central + 28].copy_from_slice(&1u32.to_le_bytes());

        let mut archive = SafeZipArchive::from_reader(
            Cursor::new(&bytes),
            bytes.len() as u64,
            policy(1_024, 8_192),
        )
        .unwrap();
        assert_eq!(archive.entry("bomb.xml").unwrap().declared_size, 1);
        let mut budget = archive.new_read_budget();
        let error = archive.read_named("bomb.xml", &mut budget).unwrap_err();
        assert!(matches!(
            error,
            ArchiveError::ActualMemberSizeExceeded { .. }
        ));
    }

    #[test]
    fn actual_aggregate_limit_is_enforced() {
        let bytes = make_zip(&[("one", &vec![b'1'; 700]), ("two", &vec![b'2'; 700])]);
        let mut configured = policy(1_024, 1_024);
        // Lie-friendly metadata preflight remains generous while the actual
        // aggregate output budget is intentionally narrow for this test.
        configured.max_declared_total_bytes = 4_096;
        let mut archive =
            SafeZipArchive::from_reader(Cursor::new(&bytes), bytes.len() as u64, configured)
                .unwrap();
        let mut budget = archive.new_read_budget();
        archive.read_named("one", &mut budget).unwrap();
        let error = archive.read_named("two", &mut budget).unwrap_err();
        assert!(matches!(
            error,
            ArchiveError::ActualTotalSizeExceeded { .. }
        ));
    }

    #[test]
    fn duplicate_and_case_colliding_names_are_rejected() {
        let mut duplicate = make_zip(&[("same", b"one"), ("diff", b"two")]);
        for offset in 0..duplicate.len().saturating_sub(4) {
            if &duplicate[offset..offset + 4] == b"diff" {
                duplicate[offset..offset + 4].copy_from_slice(b"same");
            }
        }
        let duplicate_error = SafeZipArchive::from_reader(
            Cursor::new(&duplicate),
            duplicate.len() as u64,
            policy(1_024, 4_096),
        )
        .err()
        .unwrap();
        assert!(
            matches!(
                duplicate_error,
                ArchiveError::DuplicateName { .. }
                    | ArchiveError::CentralDirectoryNameCollision { .. }
            ),
            "unexpected error: {duplicate_error:?}"
        );

        let collision = make_zip(&[("A/File.xml", b"one"), ("a/file.xml", b"two")]);
        assert!(matches!(
            SafeZipArchive::from_reader(
                Cursor::new(&collision),
                collision.len() as u64,
                policy(1_024, 4_096)
            ),
            Err(ArchiveError::NormalizedNameCollision { .. })
        ));
    }

    #[test]
    fn compressed_entry_and_path_limits_fail_preflight() {
        let bytes = make_zip(&[("safe/file", b"content")]);
        let error = SafeZipArchive::from_reader(
            Cursor::new(&bytes),
            bytes.len() as u64,
            ArchivePolicy::strict(1, 16, 1_024, 4_096),
        )
        .err()
        .unwrap();
        assert!(matches!(error, ArchiveError::CompressedSizeExceeded { .. }));

        let unsafe_zip = make_zip(&[("../escape", b"content")]);
        let error = SafeZipArchive::from_reader(
            Cursor::new(&unsafe_zip),
            unsafe_zip.len() as u64,
            policy(1_024, 4_096),
        )
        .err()
        .unwrap();
        assert!(matches!(error, ArchiveError::UnsafePath { .. }));
    }

    #[test]
    fn malformed_prefixes_and_single_bit_mutations_never_panic() {
        let bytes = make_zip(&[("content/benchmark.xml", b"<Benchmark/>")]);
        for end in 0..=bytes.len() {
            let _ = SafeZipArchive::from_bytes(&bytes[..end], policy(1_024, 4_096));
        }
        for index in 0..bytes.len() {
            for bit in 0..8 {
                let mut mutated = bytes.clone();
                mutated[index] ^= 1 << bit;
                let _ = SafeZipArchive::from_bytes(&mutated, policy(1_024, 4_096));
            }
        }
    }

    #[test]
    fn optional_ratio_screen_has_a_grace_threshold() {
        let bytes = make_zip(&[("repetitive.xml", &vec![b'A'; 4_096])]);
        let mut configured = policy(8_192, 8_192);
        configured.max_compression_ratio = Some(2);
        configured.compression_ratio_grace_bytes = 1_024;
        let error = SafeZipArchive::from_bytes(&bytes, configured)
            .err()
            .unwrap();
        assert!(error.is_resource_limit());
        assert!(matches!(
            error,
            ArchiveError::CompressionRatioExceeded { .. }
        ));

        let small = make_zip(&[("small.xml", &[b'A'; 128])]);
        let mut with_grace = policy(8_192, 8_192);
        with_grace.max_compression_ratio = Some(2);
        with_grace.compression_ratio_grace_bytes = 1_024;
        SafeZipArchive::from_bytes(&small, with_grace).unwrap();
    }
}
