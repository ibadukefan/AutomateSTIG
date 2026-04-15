use anyhow::{Context, Result};
use automatestig_core::library::StigLibrary;

use super::library_path;

pub fn list(cli: &crate::Cli) -> Result<()> {
    let lib_path = library_path(cli);
    let library = StigLibrary::open(&lib_path)
        .context("Failed to open STIG library. Run 'automatestig library init' first.")?;

    let benchmarks = library.list_benchmarks();

    if benchmarks.is_empty() {
        println!("STIG Library is empty. Import a .stigpack to add benchmarks.");
        println!("  Usage: automatestig import --pack <FILE.stigpack>");
        return Ok(());
    }

    println!("Available STIG Benchmarks ({}):\n", benchmarks.len());
    println!(
        "  {:<40} {:<10} {:<15} {:>6}",
        "ID", "Version", "Platform", "Rules"
    );
    println!("  {}", "-".repeat(75));

    for b in &benchmarks {
        println!(
            "  {:<40} {:<10} {:<15} {:>6}",
            b.id, b.version, b.platform_family, b.rule_count
        );
    }

    Ok(())
}

pub fn show(id: &str, cli: &crate::Cli) -> Result<()> {
    let lib_path = library_path(cli);
    let library = StigLibrary::open(&lib_path)?;

    let benchmark = library.load_benchmark(id)?;

    println!("Benchmark: {}", benchmark.title);
    println!("  ID: {}", benchmark.id);
    println!("  Version: {}", benchmark.version_string());
    println!("  Platform: {} ({})", benchmark.platform.name, benchmark.platform.family);
    println!("  Rules: {}", benchmark.rules.len());

    let cat_i = benchmark.rules_by_severity(automatestig_core::models::stig::Severity::High);
    let cat_ii = benchmark.rules_by_severity(automatestig_core::models::stig::Severity::Medium);
    let cat_iii = benchmark.rules_by_severity(automatestig_core::models::stig::Severity::Low);

    println!("    CAT I (High):   {}", cat_i.len());
    println!("    CAT II (Medium): {}", cat_ii.len());
    println!("    CAT III (Low):  {}", cat_iii.len());

    if let Some(ref desc) = benchmark.description.chars().take(200).collect::<String>().into() {
        if !benchmark.description.is_empty() {
            println!("\n  Description: {}...", desc);
        }
    }

    Ok(())
}

pub fn init(cli: &crate::Cli) -> Result<()> {
    let lib_path = library_path(cli);

    if lib_path.join("index.json").exists() {
        println!("STIG Library already exists at: {}", lib_path.display());
        return Ok(());
    }

    StigLibrary::init(&lib_path)?;
    println!("STIG Library initialized at: {}", lib_path.display());
    println!("  Import .stigpack files to add benchmarks:");
    println!("  automatestig import --pack <FILE.stigpack>");

    Ok(())
}
