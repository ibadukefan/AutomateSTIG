#![no_main]

use automatestig_archive_safety::{ArchivePolicy, SafeZipArchive};
use libfuzzer_sys::fuzz_target;

const MAX_COMPRESSED_BYTES: u64 = 2_048;
const MAX_ENTRIES: usize = 6;
const MAX_DECLARED_MEMBER_BYTES: u64 = 256;
const MAX_DECLARED_TOTAL_BYTES: u64 = 512;
const MAX_ACTUAL_MEMBER_BYTES: u64 = 128;
const MAX_ACTUAL_TOTAL_BYTES: u64 = 256;
const CALLER_READ_LIMIT: u64 = 96;

fuzz_target!(|input: &[u8]| {
    // Text-encoded seeds let the repository keep deterministic ZIP corpus
    // members without depending on binary-patch support. Arbitrary libFuzzer
    // input still reaches SafeZipArchive unchanged.
    let decoded = decode_hex_seed(input);
    let archive_bytes = decoded.as_deref().unwrap_or(input);

    let mut policy = ArchivePolicy::strict(
        MAX_COMPRESSED_BYTES,
        MAX_ENTRIES,
        MAX_DECLARED_MEMBER_BYTES,
        MAX_DECLARED_TOTAL_BYTES,
    );
    policy.max_actual_member_bytes = MAX_ACTUAL_MEMBER_BYTES;
    policy.max_actual_total_bytes = MAX_ACTUAL_TOTAL_BYTES;
    policy.max_name_bytes = 64;
    policy.max_path_components = 4;
    policy.max_compression_ratio = Some(32);
    policy.compression_ratio_grace_bytes = 8;

    let Ok(mut archive) = SafeZipArchive::from_bytes(archive_bytes, policy) else {
        return;
    };

    assert!(archive.entries().len() <= MAX_ENTRIES);
    let entries = archive.entries().to_vec();
    let mut budget = archive.new_read_budget();

    for entry in entries {
        let consumed_before = budget.consumed();
        let result = archive.read_index_with_limit(entry.index, CALLER_READ_LIMIT, &mut budget);
        if let Ok(bytes) = result {
            assert!(!entry.is_directory);
            assert!(bytes.len() as u64 <= CALLER_READ_LIMIT);
            assert_eq!(budget.consumed(), consumed_before + bytes.len() as u64);
        }
        assert!(budget.consumed() <= MAX_ACTUAL_TOTAL_BYTES);
    }

    // Invalid indices must remain an ordinary error path, even after reads have
    // consumed part or all of the aggregate budget.
    let _ = archive.read_index_with_limit(usize::MAX, 1, &mut budget);
    assert!(budget.consumed() <= MAX_ACTUAL_TOTAL_BYTES);
});

fn decode_hex_seed(input: &[u8]) -> Option<Vec<u8>> {
    let encoded = input.strip_prefix(b"hex:")?;
    // Text corpus files conventionally end in a newline.
    let encoded = encoded.strip_suffix(b"\n").unwrap_or(encoded);
    let encoded = encoded.strip_suffix(b"\r").unwrap_or(encoded);
    if encoded.len() % 2 != 0 || encoded.len() / 2 > MAX_COMPRESSED_BYTES as usize {
        return None;
    }

    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
