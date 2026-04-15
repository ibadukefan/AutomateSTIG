//! HTML compliance report generation.
//!
//! Generates clean, professional compliance reports from checklists.

use std::path::Path;

use anyhow::{Context, Result};
use automatestig_core::models::checklist::Checklist;
use automatestig_core::models::finding::FindingStatus;
use automatestig_core::models::stig::Severity;
use automatestig_parsers::{ckl, cklb};

use crate::ui;

pub fn run(inputs: &[String], output: &str, title: Option<&str>) -> Result<()> {
    ui::print_banner();
    ui::section("Generate Compliance Report");

    let mut checklists = Vec::new();
    for input in inputs {
        let path = Path::new(input);
        if !path.exists() {
            anyhow::bail!("File not found: {}", input);
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let cl = match ext {
            "ckl" => ckl::parse_ckl_file(path).context(format!("Failed to parse: {}", input))?,
            "cklb" => cklb::parse_cklb_file(path).context(format!("Failed to parse: {}", input))?,
            "json" => {
                let content = std::fs::read_to_string(path)?;
                serde_json::from_str(&content)?
            }
            _ => anyhow::bail!("Unsupported: .{}", ext),
        };

        ui::detail("Input", input);
        checklists.push(cl);
    }

    let report_title = title.unwrap_or("STIG Compliance Report");
    let html = generate_html_report(&checklists, report_title);
    std::fs::write(output, &html)?;

    eprintln!();
    ui::success(&format!(
        "Report generated — {} checklist(s), {} total findings",
        checklists.len(),
        checklists.iter().map(|c| c.findings.len()).sum::<usize>(),
    ));
    ui::output_file("Output", output, "HTML");
    eprintln!();

    Ok(())
}

fn generate_html_report(checklists: &[Checklist], title: &str) -> String {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");

    // Aggregate stats.
    let total_findings: usize = checklists.iter().map(|c| c.findings.len()).sum();
    let total_open: usize = checklists
        .iter()
        .flat_map(|c| c.findings.iter())
        .filter(|f| f.status == FindingStatus::Open)
        .count();
    let total_naf: usize = checklists
        .iter()
        .flat_map(|c| c.findings.iter())
        .filter(|f| f.status == FindingStatus::NotAFinding)
        .count();
    let total_na: usize = checklists
        .iter()
        .flat_map(|c| c.findings.iter())
        .filter(|f| f.status == FindingStatus::NotApplicable)
        .count();
    let total_nr: usize = checklists
        .iter()
        .flat_map(|c| c.findings.iter())
        .filter(|f| f.status == FindingStatus::NotReviewed)
        .count();

    let evaluated = total_findings - total_nr;
    let compliance_pct = if evaluated > 0 {
        ((total_naf + total_na) as f64 / evaluated as f64) * 100.0
    } else {
        0.0
    };

    let mut checklist_sections = String::new();
    for cl in checklists {
        let summary = cl.summary();
        let open_findings: Vec<_> = cl
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Open)
            .collect();

        let mut open_rows = String::new();
        for f in &open_findings {
            let sev = f.severity_override.unwrap_or(f.severity);
            let sev_class = match sev {
                Severity::High => "sev-high",
                Severity::Medium => "sev-med",
                Severity::Low => "sev-low",
            };
            let details_escaped = html_escape(&f.finding_details);
            open_rows.push_str(&format!(
                r#"<tr><td class="{sev_class}">{sev}</td><td>{vuln}</td><td>{title}</td><td class="details">{details}</td></tr>"#,
                sev_class = sev_class,
                sev = sev.as_cat_str(),
                vuln = f.vuln_id,
                title = html_escape(&f.rule_title),
                details = if details_escaped.is_empty() { "&mdash;" } else { &details_escaped },
            ));
        }

        let cl_compliance = summary.compliance_pct();
        let compliance_class = if cl_compliance >= 95.0 {
            "good"
        } else if cl_compliance >= 80.0 {
            "warn"
        } else {
            "bad"
        };

        checklist_sections.push_str(&format!(
            r#"
    <div class="checklist">
      <h2>{stig_title}</h2>
      <div class="meta">
        <span>Asset: <strong>{hostname}</strong></span>
        <span>STIG: {stig_id} V{version}R{release}</span>
      </div>
      <div class="stats">
        <div class="stat"><div class="stat-value">{total}</div><div class="stat-label">Total</div></div>
        <div class="stat bad"><div class="stat-value">{open}</div><div class="stat-label">Open</div></div>
        <div class="stat good"><div class="stat-value">{naf}</div><div class="stat-label">Not a Finding</div></div>
        <div class="stat"><div class="stat-value">{na}</div><div class="stat-label">N/A</div></div>
        <div class="stat"><div class="stat-value">{nr}</div><div class="stat-label">Not Reviewed</div></div>
        <div class="stat {compliance_class}"><div class="stat-value">{compliance:.1}%</div><div class="stat-label">Compliance</div></div>
      </div>
      {open_table}
    </div>"#,
            stig_title = html_escape(&cl.stig_info.title),
            hostname = html_escape(&cl.asset.hostname),
            stig_id = &cl.stig_info.stig_id,
            version = &cl.stig_info.version,
            release = &cl.stig_info.release,
            total = summary.total,
            open = summary.open,
            naf = summary.not_a_finding,
            na = summary.not_applicable,
            nr = summary.not_reviewed,
            compliance_class = compliance_class,
            compliance = cl_compliance,
            open_table = if open_findings.is_empty() {
                r#"<p class="all-clear">No open findings.</p>"#.to_string()
            } else {
                format!(
                    r#"<h3>Open Findings ({count})</h3>
      <table class="findings">
        <thead><tr><th>Sev</th><th>Vuln ID</th><th>Title</th><th>Details</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>"#,
                    count = open_findings.len(),
                    rows = open_rows,
                )
            },
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  :root {{ --bg: #0d1117; --surface: #161b22; --card: #1c2128; --border: #30363d;
           --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff; --green: #3fb950;
           --red: #f85149; --yellow: #d29922; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          background: var(--bg); color: var(--text); line-height: 1.6; padding: 40px 20px; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  header {{ text-align: center; margin-bottom: 48px; }}
  header h1 {{ font-size: 2rem; margin-bottom: 4px; }}
  header .subtitle {{ color: var(--muted); }}
  .summary-bar {{ display: flex; gap: 16px; justify-content: center; flex-wrap: wrap; margin: 24px 0; }}
  .summary-bar .pill {{ background: var(--surface); border: 1px solid var(--border);
                        border-radius: 20px; padding: 8px 20px; font-size: 0.9rem; }}
  .summary-bar .pill strong {{ color: var(--accent); }}
  .summary-bar .pill.compliance {{ font-weight: 700; }}
  .summary-bar .pill.compliance.good {{ border-color: var(--green); color: var(--green); }}
  .summary-bar .pill.compliance.warn {{ border-color: var(--yellow); color: var(--yellow); }}
  .summary-bar .pill.compliance.bad {{ border-color: var(--red); color: var(--red); }}
  .checklist {{ background: var(--surface); border: 1px solid var(--border);
                border-radius: 12px; padding: 28px; margin-bottom: 24px; }}
  .checklist h2 {{ font-size: 1.25rem; margin-bottom: 8px; }}
  .meta {{ color: var(--muted); font-size: 0.9rem; display: flex; gap: 24px; margin-bottom: 20px; }}
  .stats {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
           padding: 12px 20px; text-align: center; min-width: 100px; }}
  .stat-value {{ font-size: 1.5rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }}
  .stat.good .stat-value {{ color: var(--green); }}
  .stat.bad .stat-value {{ color: var(--red); }}
  .stat.warn .stat-value {{ color: var(--yellow); }}
  h3 {{ font-size: 1rem; margin-bottom: 12px; color: var(--muted); }}
  .findings {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  .findings th {{ text-align: left; padding: 8px 12px; border-bottom: 2px solid var(--border);
                  color: var(--muted); font-size: 0.75rem; text-transform: uppercase; }}
  .findings td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  .findings tr:hover {{ background: var(--card); }}
  .sev-high {{ color: var(--red); font-weight: 700; }}
  .sev-med {{ color: var(--yellow); }}
  .sev-low {{ color: var(--muted); }}
  .details {{ max-width: 400px; font-size: 0.8rem; color: var(--muted); word-break: break-word; }}
  .all-clear {{ color: var(--green); font-weight: 600; padding: 12px 0; }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 48px;
            padding-top: 24px; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>{title}</h1>
    <p class="subtitle">Generated by AutomateSTIG v{version} &mdash; {date}</p>
  </header>
  <div class="summary-bar">
    <div class="pill"><strong>{total_findings}</strong> Total Findings</div>
    <div class="pill"><strong style="color: var(--red)">{total_open}</strong> Open</div>
    <div class="pill"><strong style="color: var(--green)">{total_naf}</strong> Not a Finding</div>
    <div class="pill"><strong>{total_na}</strong> N/A</div>
    <div class="pill compliance {compliance_class}"><strong>{compliance:.1}%</strong> Compliance</div>
  </div>
  {sections}
  <footer>
    AutomateSTIG &mdash; 100% Deterministic STIG Compliance Automation<br>
    This report is unclassified. All results are reproducible and auditable.
  </footer>
</div>
</body>
</html>"#,
        title = html_escape(title),
        version = env!("CARGO_PKG_VERSION"),
        date = now,
        total_findings = total_findings,
        total_open = total_open,
        total_naf = total_naf,
        total_na = total_na,
        compliance_class = if compliance_pct >= 95.0 { "good" } else if compliance_pct >= 80.0 { "warn" } else { "bad" },
        compliance = compliance_pct,
        sections = checklist_sections,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
    use automatestig_core::models::finding::Finding;

    #[test]
    fn test_generate_html_report() {
        let stig_info = ChecklistStigInfo {
            stig_id: "Test_STIG".to_string(),
            title: "Test STIG".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            uuid: None,
            description: None,
            filename: None,
        };

        let mut cl = Checklist::new(Asset::new("server01"), stig_info);
        let mut f = Finding::new_not_reviewed("V-1", "SV-1", "V-1", "Test Rule", Severity::High);
        f.status = FindingStatus::Open;
        f.finding_details = "Not configured".to_string();
        cl.findings.push(f);

        let mut f2 = Finding::new_not_reviewed("V-2", "SV-2", "V-2", "Test Rule 2", Severity::Medium);
        f2.status = FindingStatus::NotAFinding;
        cl.findings.push(f2);

        let html = generate_html_report(&[cl], "Test Report");
        assert!(html.contains("Test Report"));
        assert!(html.contains("server01"));
        assert!(html.contains("V-1"));
        assert!(html.contains("CAT I"));
        assert!(html.contains("AutomateSTIG"));
    }
}
