pub mod build_pack;
pub mod convert;
pub mod coverage;
pub mod disa_import;
pub mod evaluate;
pub mod export;
pub mod gen_answer;
pub mod import;
pub mod library;
pub mod status;
pub mod summary;
pub mod verify;

use std::path::PathBuf;

/// Get the default AutomateSTIG data directory.
pub fn default_data_dir() -> PathBuf {
    dirs_or_default().join(".automatestig")
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Get library path from CLI args or default.
pub fn library_path(cli: &crate::Cli) -> PathBuf {
    cli.library
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_data_dir().join("library"))
}

/// Get database path from CLI args or default.
pub fn db_path(cli: &crate::Cli) -> PathBuf {
    cli.db
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_data_dir().join("data.db"))
}
