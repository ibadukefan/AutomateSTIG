use anyhow::Result;
use automatestig_core::library::StigLibrary;
use automatestig_storage::Database;
use console::style;

use super::{db_path, library_path};
use crate::ui;

pub fn run(cli: &crate::Cli) -> Result<()> {
    ui::print_banner();

    // Library status.
    let lib_path = library_path(cli);
    ui::section("STIG Library");
    match StigLibrary::open(&lib_path) {
        Ok(library) => {
            let benchmarks = library.list_benchmarks();
            ui::detail("Location", &lib_path.display().to_string());
            ui::detail("Benchmarks", &benchmarks.len().to_string());
            if !benchmarks.is_empty() {
                eprintln!();
                for b in &benchmarks {
                    eprintln!(
                        "    {} {} {} {}",
                        style("•").dim(),
                        style(&b.id).cyan(),
                        style(&b.version).dim(),
                        style(format!("({} rules)", b.rule_count)).dim(),
                    );
                }
            }
        }
        Err(_) => {
            ui::warn("Not initialized — run 'automatestig library init'");
        }
    }

    eprintln!();

    // Database status.
    ui::section("Database");
    let db = db_path(cli);
    match Database::open(&db) {
        Ok(database) => {
            let checklists = database.list_checklists().unwrap_or_default();
            ui::detail("Location", &db.display().to_string());
            ui::detail("Checklists", &checklists.len().to_string());
        }
        Err(_) => {
            ui::detail("Status", "Not yet created");
        }
    }

    eprintln!();
    ui::section("Configuration");
    ui::detail(
        "Data directory",
        &super::default_data_dir().display().to_string(),
    );
    ui::detail("Mode", "Air-gapped (offline only)");
    ui::detail("Determinism", "100% — zero AI/ML");
    eprintln!();

    Ok(())
}
