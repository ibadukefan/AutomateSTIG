use anyhow::Result;
use automatestig_core::library::StigLibrary;
use automatestig_storage::Database;

use super::{db_path, library_path};

pub fn run(cli: &crate::Cli) -> Result<()> {
    println!("AutomateSTIG v{}", env!("CARGO_PKG_VERSION"));
    println!("  100% deterministic | Air-gapped first | Open source (MIT)");
    println!();

    // Library status.
    let lib_path = library_path(cli);
    match StigLibrary::open(&lib_path) {
        Ok(library) => {
            let benchmarks = library.list_benchmarks();
            println!("STIG Library: {} ({} benchmarks)", lib_path.display(), benchmarks.len());
            for b in &benchmarks {
                println!("  - {} {} ({} rules)", b.id, b.version, b.rule_count);
            }
        }
        Err(_) => {
            println!(
                "STIG Library: Not initialized (run 'automatestig library init')"
            );
        }
    }

    println!();

    // Database status.
    let db = db_path(cli);
    match Database::open(&db) {
        Ok(database) => {
            let checklists = database.list_checklists().unwrap_or_default();
            println!("Database: {} ({} checklists)", db.display(), checklists.len());
        }
        Err(_) => {
            println!("Database: Not yet created");
        }
    }

    println!();
    println!("Data directory: {}", super::default_data_dir().display());

    Ok(())
}
