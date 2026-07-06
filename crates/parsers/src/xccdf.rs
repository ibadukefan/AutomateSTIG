//! XCCDF (Extensible Configuration Checklist Description Format) parser.
//!
//! Parses XCCDF benchmark files and XCCDF result files from SCC/OpenSCAP.
//! Used to import STIG benchmarks and map scan results to findings.

use std::path::Path;

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use automatestig_core::models::scan::{ScanResult, ScanResultSet, ScanSource, ScannerType};
use automatestig_core::models::stig::*;

use crate::error::{ParseError, ParseResult};
use crate::util::{read_to_string_capped, PARSE_FILE_SIZE_LIMIT_BYTES};

/// Parse an XCCDF benchmark file into a StigBenchmark.
pub fn parse_xccdf_benchmark(path: &Path) -> ParseResult<StigBenchmark> {
    let content = read_to_string_capped(path, PARSE_FILE_SIZE_LIMIT_BYTES)?;
    parse_xccdf_benchmark_str(&content)
}

/// Parse XCCDF benchmark XML content.
pub fn parse_xccdf_benchmark_str(xml: &str) -> ParseResult<StigBenchmark> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut benchmark = StigBenchmark {
        id: String::new(),
        title: String::new(),
        description: String::new(),
        version: String::new(),
        release: String::new(),
        release_date: None,
        xccdf_id: None,
        platform: Platform::default(),
        rules: Vec::new(),
    };

    let mut buf = Vec::new();
    let mut current_tag = String::new();
    let mut in_benchmark = false;
    let mut in_group = false;
    let mut in_rule = false;
    let mut in_ident = false;
    let mut in_reference = false;

    // Current rule being parsed.
    let mut current_rule = new_empty_rule();
    let mut current_group_id = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                current_tag = local_name.clone();

                match local_name.as_str() {
                    "Benchmark" => {
                        in_benchmark = true;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"id" {
                                benchmark.id = String::from_utf8_lossy(&attr.value).to_string();
                                benchmark.xccdf_id = Some(benchmark.id.clone());
                            }
                        }
                    }
                    "Group" => {
                        in_group = true;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"id" {
                                current_group_id = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "Rule" => {
                        in_rule = true;
                        current_rule = new_empty_rule();
                        current_rule.group_id = current_group_id.clone();

                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"id" => {
                                    current_rule.rule_id =
                                        String::from_utf8_lossy(&attr.value).to_string();
                                }
                                b"severity" => {
                                    let sev_str = String::from_utf8_lossy(&attr.value).to_string();
                                    if let Some(sev) = Severity::from_cat_str(&sev_str) {
                                        current_rule.severity = sev;
                                        current_rule.weight = sev.default_weight();
                                    }
                                }
                                b"weight" => {
                                    if let Ok(w) =
                                        String::from_utf8_lossy(&attr.value).parse::<f64>()
                                    {
                                        current_rule.weight = w;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    "ident" => {
                        in_ident = true;
                    }
                    "reference" => in_reference = true,
                    "platform" if in_benchmark && !in_group => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"idref" {
                                let cpe = String::from_utf8_lossy(&attr.value).to_string();
                                benchmark.platform.cpe.push(cpe);
                            }
                        }
                    }
                    _ => {}
                }
            }

            Ok(Event::End(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();

                match local_name.as_str() {
                    "Benchmark" => in_benchmark = false,
                    "Group" => {
                        in_group = false;
                        current_group_id.clear();
                    }
                    "Rule" => {
                        in_rule = false;
                        // Derive vuln_id from group_id (standard DISA convention).
                        if current_rule.vuln_id.is_empty() {
                            current_rule.vuln_id = current_rule.group_id.clone();
                        }
                        benchmark.rules.push(current_rule.clone());
                        current_rule = new_empty_rule();
                    }
                    "ident" => in_ident = false,
                    "reference" => in_reference = false,
                    _ => {}
                }
                current_tag.clear();
            }

            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();

                if in_reference {
                    // Dublin Core fields (dc:title/dc:publisher/...) live inside <reference>;
                    // skip them so dc:title does not overwrite the rule's real <title>.
                } else if in_rule {
                    match current_tag.as_str() {
                        "title" => current_rule.title = text,
                        "description" | "discussion" => {
                            if current_rule.discussion.is_empty() {
                                current_rule.discussion = text;
                            }
                        }
                        "fixtext" | "fix" => current_rule.fix_text = text,
                        "check-content" => current_rule.check_content = text,
                        "version" => {
                            // Rule version — extract vuln_id.
                            current_rule.vuln_id = text;
                        }
                        _ => {
                            if in_ident && text.starts_with("CCI-") {
                                current_rule.cci_refs.push(text);
                            }
                        }
                    }
                } else if in_benchmark && !in_group {
                    match current_tag.as_str() {
                        "title" => benchmark.title = text,
                        "description" => benchmark.description = text,
                        "version" => benchmark.version = text,
                        "release-info" | "plain-text" if text.contains("Release:") => {
                            if let Some(r) = text.split("Release:").nth(1) {
                                benchmark.release =
                                    r.split_whitespace().next().unwrap_or("0").to_string();
                            }
                        }
                        _ => {}
                    }
                }
            }

            Ok(Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();

                if local_name == "platform" && in_benchmark && !in_group {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"idref" {
                            let cpe = String::from_utf8_lossy(&attr.value).to_string();
                            benchmark.platform.cpe.push(cpe);
                        }
                    }
                }
            }

            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ParseError::XmlError(format!(
                    "XCCDF parse error at position {}: {}",
                    reader.buffer_position(),
                    e
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    // Derive platform name from CPE if available.
    if !benchmark.platform.cpe.is_empty() {
        benchmark.platform.name = benchmark.platform.cpe[0].clone();
    }

    // Derive benchmark ID from title if not set.
    if benchmark.id.is_empty() && !benchmark.title.is_empty() {
        benchmark.id = benchmark
            .title
            .replace(' ', "_")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_')
            .collect();
    }

    Ok(benchmark)
}

/// Parse XCCDF result file (from SCC or OpenSCAP) into scan results.
pub fn parse_xccdf_results(path: &Path) -> ParseResult<ScanResultSet> {
    let content = read_to_string_capped(path, PARSE_FILE_SIZE_LIMIT_BYTES)?;
    parse_xccdf_results_str(&content)
}

/// Parse XCCDF result XML content.
pub fn parse_xccdf_results_str(xml: &str) -> ParseResult<ScanResultSet> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut results = Vec::new();
    let mut source = ScanSource {
        scanner: ScannerType::Scc,
        scanner_version: None,
        scan_date: None,
        source_file: None,
        target: None,
        profile: None,
    };

    let mut buf = Vec::new();
    let mut current_tag = String::new();
    let mut in_rule_result = false;
    let mut in_test_result = false;
    let mut current_rule_ref = String::new();
    let mut current_result = String::new();
    let mut current_evidence = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                current_tag = local_name.clone();

                match local_name.as_str() {
                    "TestResult" => {
                        in_test_result = true;
                        // Extract test metadata.
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"test-system" => {
                                    let sys = String::from_utf8_lossy(&attr.value).to_string();
                                    if sys.contains("openscap") {
                                        source.scanner = ScannerType::OpenScap;
                                    }
                                }
                                b"id" => {
                                    source.scanner_version =
                                        Some(String::from_utf8_lossy(&attr.value).to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                    "rule-result" => {
                        in_rule_result = true;
                        current_result.clear();
                        current_evidence.clear();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"idref" {
                                current_rule_ref = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "check-content-ref" if in_rule_result => {
                        capture_check_content_ref(e, &mut current_evidence);
                    }
                    _ => {}
                }
            }

            Ok(Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if local_name == "check-content-ref" && in_rule_result {
                    capture_check_content_ref(e, &mut current_evidence);
                }
            }

            Ok(Event::End(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();

                match local_name.as_str() {
                    "TestResult" => in_test_result = false,
                    "rule-result" => {
                        in_rule_result = false;
                        let passed = match current_result.as_str() {
                            "pass" | "fixed" => Some(true),
                            "fail" => Some(false),
                            "notapplicable" => None, // Will need special handling
                            _ => None,
                        };

                        results.push(ScanResult {
                            rule_ref: current_rule_ref.clone(),
                            passed,
                            raw_result: current_result.clone(),
                            evidence: (!current_evidence.is_empty())
                                .then(|| current_evidence.join("\n")),
                            benchmark_ref: None,
                        });
                    }
                    _ => {}
                }
                current_tag.clear();
            }

            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();

                if in_rule_result && current_tag == "result" {
                    current_result = text;
                } else if in_rule_result
                    && matches!(
                        current_tag.as_str(),
                        "message" | "instance" | "check-content"
                    )
                {
                    let text = text.trim();
                    if !text.is_empty() {
                        current_evidence.push(format!("{}: {}", current_tag, text));
                    }
                } else if in_test_result && current_tag == "target" {
                    source.target = Some(text);
                } else if in_test_result && current_tag == "profile" {
                    source.profile = Some(text);
                }
            }

            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(ParseError::XmlError(format!(
                    "XCCDF result parse error: {}",
                    e
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(ScanResultSet { source, results })
}

fn capture_check_content_ref(
    event: &quick_xml::events::BytesStart<'_>,
    evidence: &mut Vec<String>,
) {
    let mut attrs = Vec::new();
    for attr in event.attributes().flatten() {
        if matches!(attr.key.as_ref(), b"href" | b"name") {
            attrs.push(format!(
                "{}={}",
                String::from_utf8_lossy(attr.key.as_ref()),
                String::from_utf8_lossy(&attr.value)
            ));
        }
    }
    if !attrs.is_empty() {
        evidence.push(format!("check-content-ref: {}", attrs.join(" ")));
    }
}

fn new_empty_rule() -> StigRule {
    StigRule {
        vuln_id: String::new(),
        rule_id: String::new(),
        group_id: String::new(),
        title: String::new(),
        discussion: String::new(),
        severity: Severity::Medium,
        check_content: String::new(),
        fix_text: String::new(),
        cci_refs: Vec::new(),
        legacy_ids: Vec::new(),
        stig_ref: None,
        weight: 8.0,
        automatable: CheckAutomation::Manual,
        automated_check: None,
        remediation_ids: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_xccdf_benchmark() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="Windows_Server_2022_STIG">
  <title>Microsoft Windows Server 2022 Security Technical Implementation Guide</title>
  <description>This STIG provides security guidance for Windows Server 2022.</description>
  <version>001</version>
  <plain-text id="release-info">Release: 4 Benchmark Date: 24 Jul 2024</plain-text>
  <platform idref="cpe:/o:microsoft:windows_server_2022:-" />
  <Group id="V-254239">
    <title>SRG-OS-000033-GPOS-00014</title>
    <Rule id="SV-254239r958388_rule" severity="high" weight="10.0">
      <version>V-254239</version>
      <title>Windows Server 2022 must use TLS 1.2</title>
      <description>TLS 1.2 is required for secure communications.</description>
      <fixtext>Enable TLS 1.2 in the registry.</fixtext>
      <check>
        <check-content>Verify TLS 1.2 is enabled.</check-content>
      </check>
      <ident system="http://iase.disa.mil/cci">CCI-000068</ident>
    </Rule>
  </Group>
  <Group id="V-254240">
    <title>SRG-OS-000069-GPOS-00037</title>
    <Rule id="SV-254240r958392_rule" severity="medium" weight="8.0">
      <version>V-254240</version>
      <title>Windows Server 2022 password complexity</title>
      <description>Password complexity must be enabled.</description>
      <fixtext>Enable password complexity in Group Policy.</fixtext>
      <check>
        <check-content>Verify password complexity is enabled.</check-content>
      </check>
      <ident system="http://iase.disa.mil/cci">CCI-000192</ident>
    </Rule>
  </Group>
</Benchmark>"#
    }

    fn sample_xccdf_results() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <TestResult id="scap_result_1" test-system="cpe:/a:disa:scc:5.7">
    <target>webserver01</target>
    <rule-result idref="SV-254239r958388_rule">
      <result>fail</result>
      <message severity="info">SCC evaluated registry key HKLM\Software\Example and found it missing.</message>
      <instance>HKLM\Software\Example</instance>
      <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
        <check-content-ref href="scc-results.xml" name="oval:example:def:1" />
      </check>
    </rule-result>
    <rule-result idref="SV-254240r958392_rule">
      <result>pass</result>
      <message>Policy value matched the expected setting.</message>
    </rule-result>
  </TestResult>
</Benchmark>"#
    }

    #[test]
    fn test_parse_xccdf_benchmark() {
        let benchmark = parse_xccdf_benchmark_str(sample_xccdf_benchmark()).unwrap();

        assert_eq!(benchmark.id, "Windows_Server_2022_STIG");
        assert_eq!(benchmark.version, "001");
        assert_eq!(benchmark.release, "4");
        assert_eq!(benchmark.rules.len(), 2);

        let rule1 = &benchmark.rules[0];
        assert_eq!(rule1.vuln_id, "V-254239");
        assert_eq!(rule1.severity, Severity::High);
        assert!(rule1.cci_refs.contains(&"CCI-000068".to_string()));

        let rule2 = &benchmark.rules[1];
        assert_eq!(rule2.vuln_id, "V-254240");
        assert_eq!(rule2.severity, Severity::Medium);
    }

    #[test]
    fn test_rule_title_not_clobbered_by_reference() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" xmlns:dc="http://purl.org/dc/elements/1.1/" id="Example_STIG">
  <title>Example Benchmark</title>
  <reference>
    <dc:title>DPMS Target Benchmark</dc:title>
    <dc:publisher>DISA</dc:publisher>
  </reference>
  <Group id="V-000001">
    <Rule id="SV-000001r1_rule" severity="medium">
      <version>V-000001</version>
      <title>Real rule title</title>
      <reference>
        <dc:title>DPMS Target Something</dc:title>
        <dc:publisher>DISA</dc:publisher>
      </reference>
    </Rule>
  </Group>
</Benchmark>"#;

        let benchmark = parse_xccdf_benchmark_str(xml).unwrap();

        assert_eq!(benchmark.title, "Example Benchmark");
        assert_eq!(benchmark.rules.len(), 1);
        assert_eq!(benchmark.rules[0].title, "Real rule title");
    }

    #[test]
    fn test_parse_xccdf_results() {
        let results = parse_xccdf_results_str(sample_xccdf_results()).unwrap();

        assert_eq!(results.source.target.as_deref(), Some("webserver01"));
        assert_eq!(results.results.len(), 2);

        assert_eq!(results.results[0].rule_ref, "SV-254239r958388_rule");
        assert_eq!(results.results[0].passed, Some(false));
        let evidence = results.results[0].evidence.as_deref().unwrap_or_default();
        assert!(evidence.contains("SCC evaluated registry key"));
        assert!(evidence.contains("instance: HKLM\\Software\\Example"));
        assert!(
            evidence.contains("check-content-ref: href=scc-results.xml name=oval:example:def:1")
        );

        assert_eq!(results.results[1].rule_ref, "SV-254240r958392_rule");
        assert_eq!(results.results[1].passed, Some(true));
        assert_eq!(
            results.results[1].evidence.as_deref(),
            Some("message: Policy value matched the expected setting.")
        );
    }
}
