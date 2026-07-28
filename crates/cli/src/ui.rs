//! Premium CLI output styling.
//!
//! Provides consistent, clean, styled terminal output across all commands.

use console::{style, Style, Term};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScoreTone {
    Green,
    Yellow,
    Red,
}

fn assessed_pass_tone(assessed_pass_pct: f64, benchmark_coverage_pct: f64) -> ScoreTone {
    if assessed_pass_pct < 80.0 {
        ScoreTone::Red
    } else if benchmark_coverage_pct < 100.0 {
        ScoreTone::Yellow
    } else if assessed_pass_pct >= 95.0 {
        ScoreTone::Green
    } else {
        ScoreTone::Yellow
    }
}

/// Application banner shown on startup.
pub fn print_banner() {
    let term = Term::stdout();
    let width = term.size().1 as usize;
    let width = width.min(80);

    println!();
    println!(
        "  {} {}",
        style("AutomateSTIG").bold().cyan(),
        style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim(),
    );
    println!(
        "  {}",
        style("STIG Evaluation & Compliance Automation").dim(),
    );
    println!("  {}", style("─".repeat(width.saturating_sub(4))).dim());
    println!();
}

/// Print a section header.
pub fn section(title: &str) {
    println!("  {} {}", style("▸").cyan().bold(), style(title).bold());
}

/// Print an info line.
pub fn info(label: &str, value: &str) {
    println!("    {:<20} {}", style(label).dim(), value,);
}

/// Print a success message.
pub fn success(msg: &str) {
    println!("  {} {}", style("✓").green().bold(), msg);
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
    println!("    {} {}", style(format!("{}:", key)).dim(), value);
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
    assessed_pass_pct: f64,
    benchmark_coverage_pct: f64,
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

    let assessed_pass_style = match assessed_pass_tone(assessed_pass_pct, benchmark_coverage_pct) {
        ScoreTone::Green => Style::new().green().bold(),
        ScoreTone::Yellow => Style::new().yellow().bold(),
        ScoreTone::Red => Style::new().red().bold(),
    };
    let coverage_style = if benchmark_coverage_pct >= 100.0 {
        Style::new().green().bold()
    } else {
        Style::new().yellow().bold()
    };
    let assessed = total.saturating_sub(nr);

    println!();
    println!(
        "  {}",
        style("┌──────────────────────────────────────────────────┐").dim()
    );
    println!(
        "  {}  Total Rules:        {:<6}                      {}",
        style("│").dim(),
        style(total).bold(),
        style("│").dim(),
    );
    println!(
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
    println!(
        "  {}  Not a Finding:      {:<6}                      {}",
        style("│").dim(),
        style(naf).green(),
        style("│").dim(),
    );
    println!(
        "  {}  Not Applicable:     {:<6}                      {}",
        style("│").dim(),
        style(na).dim(),
        style("│").dim(),
    );
    println!(
        "  {}  Not Reviewed:       {:<6}                      {}",
        style("│").dim(),
        if nr > 0 {
            style(nr).yellow().to_string()
        } else {
            style(nr).dim().to_string()
        },
        style("│").dim(),
    );
    println!(
        "  {}",
        style("│──────────────────────────────────────────────────│").dim()
    );
    println!(
        "  {}  Assessed controls:  {:<12}                {}",
        style("│").dim(),
        format!("{assessed}/{total}"),
        style("│").dim(),
    );
    println!(
        "  {}  Assessed pass rate: {:<6}                      {}",
        style("│").dim(),
        assessed_pass_style.apply_to(format!("{:.1}%", assessed_pass_pct)),
        style("│").dim(),
    );
    println!(
        "  {}  Benchmark coverage: {:<6}                      {}",
        style("│").dim(),
        coverage_style.apply_to(format!("{:.1}%", benchmark_coverage_pct)),
        style("│").dim(),
    );
    println!(
        "  {}",
        style("└──────────────────────────────────────────────────┘").dim()
    );
    println!();
}

/// Print a findings table header.
pub fn print_findings_header() {
    println!(
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
        "Not a Finding" | "NotAFinding" => style(format!("{:<17}", "Not a Finding"))
            .green()
            .to_string(),
        "Not Applicable" | "Not_Applicable" => {
            style(format!("{:<17}", "Not Applicable")).dim().to_string()
        }
        _ => style(format!("{:<17}", status)).yellow().to_string(),
    };

    let title_truncated: String = title.chars().take(44).collect();

    println!(
        "  {:<12} {} {} {}",
        style(vuln_id).cyan(),
        sev_styled,
        status_styled,
        title_truncated,
    );
}

/// Print a file output notice.
pub fn output_file(label: &str, path: &str, format: &str) {
    println!(
        "  {} {} {} {}",
        style("→").cyan().bold(),
        label,
        style(path).underlined(),
        style(format!("({})", format)).dim(),
    );
}

/// Print a horizontal rule.
pub fn hr() {
    let term = Term::stdout();
    let width = (term.size().1 as usize).min(80);
    println!("  {}", style("─".repeat(width.saturating_sub(4))).dim());
}

#[cfg(test)]
mod tests {
    use super::{assessed_pass_tone, ScoreTone};

    #[test]
    fn unresolved_controls_prevent_a_green_pass_grade() {
        assert_eq!(
            assessed_pass_tone(100.0, 3.0 / 203.0 * 100.0),
            ScoreTone::Yellow
        );
        assert_eq!(assessed_pass_tone(100.0, 99.9), ScoreTone::Yellow);
        assert_eq!(assessed_pass_tone(100.0, 100.0), ScoreTone::Green);
        assert_eq!(assessed_pass_tone(50.0, 10.0), ScoreTone::Red);
    }
}
