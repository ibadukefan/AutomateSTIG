use std::io;
use std::path::Path;

pub(crate) const PARSE_FILE_SIZE_LIMIT_BYTES: u64 = 128 * 1024 * 1024;

pub(crate) fn read_to_string_capped(path: &Path, max_bytes: u64) -> io::Result<String> {
    if std::fs::metadata(path)?.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds 128 MB parse limit",
        ));
    }
    std::fs::read_to_string(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_read_to_string_capped_rejects_oversize() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"longer than eight bytes").unwrap();

        assert!(read_to_string_capped(file.path(), 8).is_err());
        assert_eq!(
            read_to_string_capped(file.path(), 128).unwrap(),
            "longer than eight bytes"
        );
    }
}
