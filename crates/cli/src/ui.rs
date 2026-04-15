//! Premium CLI output styling.
//!
//! Provides consistent, clean, styled terminal output across all commands.

use console::{style, Style, Term};

/// Application banner shown on startup.
pub fn print_banner() {
    let term = Term::stderr();
    let width = term.size().1 as usize;
    let width = width.min(80);

    eprintln!();
    eprintln!(
        "  {} {}",
        style("AutomateSTIG").bold().cyan(),
        style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim(),
    );
    eprintln!(
        "  {}",
        style("STIG Evaluation & Compliance Automation").dim(),
    );
    eprintln!("  {}", style("─".repeat(width.saturating_sub(4))).dim());
    eprintln!();
}

/// Print a section header.
pub fn section(title: &str) {
    eprintln!("  {} {}", style("▸").cyan().bold(), style(title).bold());
}

/// Print an info line.
pub fn info(label: &str, value: &str) {
    eprintln!(
        "    {:<20} {}",
        style(label).dim(),
        value,
    );
}

/// Print a success message.
pub fn success(msg: &str) {
    eprintln!("  {} {}", style("✓").green().bold(), msg);
}

/// Print a warning message.
pub fn warn(msg: &str) {
    eprintln!("  {} {}", style("⚠").yellow().bold(), msg);
}

/// Print an error message.
pub fn error(msg: &str) {
    eprintln!("  {} {}", style("✗").red().bold(), msg);
}

/// Print a key-value detail line.
pub fn detail(key: &str, value: &str) {
    eprintln!("    {} {}", style(format!("{}:", key)).dim(), value);
}

/// Print a finding summary table.
#[allow(clippy::too_many_arguments)]
pub fn print_summary_table(
    total: usize,
    open: usize,
    naf: usize,
    na: usize,
    nr: usize,
    cat_i: usize,
    cat_ii: usize,
    cat_iii: usize,
    compliance_pct: f64,
) {
    let open_style = if open > 0 {
        Style::new().red().bold()
    } else {
        Style::new().green().bold()
    };

    let cat_i_style = if cat_i > 0 {
        Style::new().red().bold()
    } else {
        Style::new().dim()
    };

    let compliance_style = if compliance_pct >= 95.0 {
        Style::new().green().bold()
    } else if compliance_pct >= 80.0 {
        Style::new().yellow().bold()
    } else {
        Style::new().red().bold()
    };

    eprintln!();
    eprintln!("  {}", style("┌──────────────────────────────────────────────────┐").dim());
    eprintln!(
        "  {}  Total Rules:        {:<6}                      {}",
        style("│").dim(),
        style(total).bold(),
        style("│").dim(),
    );
    eprintln!(
        "  {}  Open:               {:<6} {} {} {}   {}",
        style("│").dim(),
        open_style.apply_to(open),
        cat_i_style.apply_to(format!("I:{}", cat_i)),
        if cat_ii > 0 {
            style(format!("II:{}", cat_ii)).yellow().to_string()
        } else {
            style(format!("II:{}", cat_ii)).dim().to_string()
        },
        if cat_iii > 0 {
            style(format!("III:{}", cat_iii)).yellow().to_string()
        } else {
            style(format!("III:{}", cat_iii)).dim().to_string()
        },
        style("│").dim(),
    );
    eprintln!(
        "  {}  Not a Finding:      {:<6}                      {}",
        style("│").dim(),
        style(naf).green(),
        style("│").dim(),
    );
    eprintln!(
        "  {}  Not Applicable:     {:<6}                      {}",
        style("│").dim(),
        style(na).dim(),
        style("│").dim(),
    );
    eprintln!(
        "  {}  Not Reviewed:       {:<6}                      {}",
        style("│").dim(),
        if nr > 0 {
            style(nr).yellow().to_string()
        } else {
            style(nr).dim().to_string()
        },
        style("│").dim(),
    );
    eprintln!("  {}", style("│──────────────────────────────────────────────────│").dim());
    eprintln!(
        "  {}  Compliance:         {:<6}                      {}",
        style("│").dim(),
        compliance_style.apply_to(format!("{:.1}%", compliance_pct)),
        style("│").dim(),
    );
    eprintln!("  {}", style("└──────────────────────────────────────────────────┘").dim());
    eprintln!();
}

/// Print a findings table header.
pub fn print_findings_header() {
    eprintln!(
        "  {:<12} {:<8} {:<17} {}",
        style("Vuln ID").bold().underlined(),
        style("Sev").bold().underlined(),
        style("Status").bold().underlined(),
        style("Title").bold().underlined(),
    );
}

/// Print a single finding row.
pub fn print_finding_row(vuln_id: &str, severity: &str, status: &str, title: &str) {
    let sev_styled = match severity {
        "CAT I" => style(format!("{:<8}", severity)).red().bold().to_string(),
        "CAT II" => style(format!("{:<8}", severity)).yellow().to_string(),
        "CAT III" => style(format!("{:<8}", severity)).dim().to_string(),
        _ => format!("{:<8}", severity),
    };

    let status_styled = match status {
        "Open" => style(format!("{:<17}", status)).red().bold().to_string(),
        "Not a Finding" | "NotAFinding" => style(format!("{:<17}", "Not a Finding")).green().to_string(),
        "Not Applicable" | "Not_Applicable" => style(format!("{:<17}", "Not Applicable")).dim().to_string(),
        _ => style(format!("{:<17}", status)).yellow().to_string(),
    };

    let title_truncated: String = title.chars().take(44).collect();

    eprintln!(
        "  {:<12} {} {} {}",
        style(vuln_id).cyan(),
        sev_styled,
        status_styled,
        title_truncated,
    );
}

/// Print a file output notice.
pub fn output_file(label: &str, path: &str, format: &str) {
    eprintln!(
        "  {} {} {} {}",
        style("→").cyan().bold(),
        label,
        style(path).underlined(),
        style(format!("({})", format)).dim(),
    );
}

/// Print a horizontal rule.
pub fn hr() {
    let term = Term::stderr();
    let width = (term.size().1 as usize).min(80);
    eprintln!("  {}", style("─".repeat(width.saturating_sub(4))).dim());
}
