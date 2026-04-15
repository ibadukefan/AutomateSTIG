use anyhow::{Context, Result};
use console::style;
use automatestig_core::library::StigLibrary;
use automatestig_core::models::stig::Severity;

use super::library_path;
use crate::ui;

pub fn list(cli: &crate::Cli) -> Result<()> {
    let lib_path = library_path(cli);
    let library = StigLibrary::open(&lib_path)
        .context("Failed to open STIG library. Run 'automatestig library init' first.")?;

    let benchmarks = library.list_benchmarks();

    ui::print_banner();

    if benchmarks.is_empty() {
        ui::section("STIG Library (empty)");
        eprintln!();
        ui::warn("No benchmarks installed. Import a .stigpack to add benchmarks:");
        eprintln!("    automatestig import --pack <FILE.stigpack>");
        eprintln!();
        return Ok(());
    }

    ui::section(&format!("STIG Library ({} benchmarks)", benchmarks.len()));
    eprintln!();

    eprintln!(
        "  {:<40} {:<10} {:<15} {:>6}",
        style("ID").bold().underlined(),
        style("Version").bold().underlined(),
        style("Platform").bold().underlined(),
        style("Rules").bold().underlined(),
    );

    for b in &benchmarks {
        eprintln!(
            "  {:<40} {:<10} {:<15} {:>6}",
            style(&b.id).cyan(),
            style(&b.version).dim(),
            &b.platform_family,
            b.rule_count,
        );
    }

    eprintln!();

    Ok(())
}

pub fn show(id: &str, cli: &crate::Cli) -> Result<()> {
    let lib_path = library_path(cli);
    let library = StigLibrary::open(&lib_path)?;

    let benchmark = library.load_benchmark(id)?;

    ui::print_banner();
    ui::section(&benchmark.title);
    ui::detail("ID", &benchmark.id);
    ui::detail("Version", &benchmark.version_string());
    ui::detail("Platform", &format!("{} ({})", benchmark.platform.name, benchmark.platform.family));
    ui::detail("Total rules", &benchmark.rules.len().to_string());

    let cat_i = benchmark.rules_by_severity(Severity::High);
    let cat_ii = benchmark.rules_by_severity(Severity::Medium);
    let cat_iii = benchmark.rules_by_severity(Severity::Low);

    eprintln!();
    eprintln!(
        "    {} CAT I (High)    {}",
        style("■").red(),
        style(cat_i.len()).bold(),
    );
    eprintln!(
        "    {} CAT II (Medium) {}",
        style("■").yellow(),
        style(cat_ii.len()).bold(),
    );
    eprintln!(
        "    {} CAT III (Low)   {}",
        style("■").dim(),
        style(cat_iii.len()).bold(),
    );

    if !benchmark.description.is_empty() {
        let desc: String = benchmark.description.chars().take(200).collect();
        eprintln!();
        ui::detail("Description", &desc);
    }

    eprintln!();

    Ok(())
}

pub fn init(cli: &crate::Cli) -> Result<()> {
    let lib_path = library_path(cli);

    ui::print_banner();

    if lib_path.join("index.json").exists() {
        ui::success(&format!("STIG Library already exists at: {}", lib_path.display()));
        eprintln!();
        return Ok(());
    }

    StigLibrary::init(&lib_path)?;
    ui::success(&format!("STIG Library initialized at: {}", lib_path.display()));
    eprintln!();
    ui::detail("Next step", "Import a .stigpack to add benchmarks:");
    eprintln!("    automatestig import --pack <FILE.stigpack>");
    eprintln!();

    Ok(())
}
