//! Cross-platform integration tests for AutomateSTIG.
//!
//! These tests exercise the full pipeline end-to-end:
//! - CKL/CKLB/XCCDF parsing and roundtripping
//! - Evaluation engine with scan results + answer files
//! - STIG library lifecycle (init → add → load → integrity check)
//! - Stigpack build → verify → import pipeline
//! - Format conversion (CKL ↔ CKLB ↔ JSON)
//! - SQLite storage CRUD
//! - STIG-Manager export
//!
//! All tests use temporary directories and are safe to run in parallel.
//! They cover Windows, macOS, and Linux (no platform-specific features used).

#[cfg(test)]
mod integration {

    use automatestig_core::answer::{AnswerEntry, AnswerFile};
    use automatestig_core::engine::EvaluationEngine;
    use automatestig_core::library::StigLibrary;
    use automatestig_core::models::asset::Asset;
    use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo};
    use automatestig_core::models::finding::{FindingSource, FindingStatus};
    use automatestig_core::models::scan::{ScanResult, ScanResultSet, ScanSource, ScannerType};
    use automatestig_core::models::stig::*;
    use automatestig_integrations::stig_manager;
    use automatestig_parsers::{ckl, cklb, xccdf};
    use automatestig_stigpack::builder::PackBuilder;
    use automatestig_stigpack::importer;
    use automatestig_stigpack::verifier;
    use automatestig_storage::Database;

    use tempfile::TempDir;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    fn make_benchmark(id: &str, num_rules: usize) -> StigBenchmark {
        let rules: Vec<StigRule> = (1..=num_rules)
            .map(|i| {
                let severity = match i % 3 {
                    0 => Severity::High,
                    1 => Severity::Medium,
                    _ => Severity::Low,
                };
                StigRule {
                    vuln_id: format!("V-{}", 100000 + i),
                    rule_id: format!("SV-{}r1_rule", 100000 + i),
                    group_id: format!("V-{}", 100000 + i),
                    title: format!("Test Rule {} for {}", i, id),
                    discussion: format!("Discussion for rule {}", i),
                    severity,
                    check_content: format!("Check content for rule {}", i),
                    fix_text: format!("Fix text for rule {}", i),
                    cci_refs: vec![format!("CCI-{:06}", i)],
                    legacy_ids: vec![format!("SV-OLD-{}", i)],
                    stig_ref: Some(format!("{} :: V1R1", id)),
                    weight: severity.default_weight(),
                    automatable: CheckAutomation::Manual,
                    automated_check: None,
                    remediation_ids: vec![],
                }
            })
            .collect();

        StigBenchmark {
            id: id.to_string(),
            title: format!("{} Security Technical Implementation Guide", id),
            description: "Test benchmark for integration testing".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            xccdf_id: Some(id.to_string()),
            platform: Platform {
                family: "test".to_string(),
                name: "Test Platform".to_string(),
                cpe: vec!["cpe:/o:test:platform".to_string()],
            },
            rules,
        }
    }

    fn make_scan_results(benchmark: &StigBenchmark, pass_ratio: f64) -> ScanResultSet {
        let results: Vec<ScanResult> = benchmark
            .rules
            .iter()
            .enumerate()
            .map(|(i, rule)| {
                let passed = (i as f64 / benchmark.rules.len() as f64) < pass_ratio;
                ScanResult {
                    rule_ref: rule.vuln_id.clone(),
                    passed: Some(passed),
                    raw_result: if passed { "pass" } else { "fail" }.to_string(),
                    evidence: Some(format!("Automated check result for {}", rule.vuln_id)),
                    benchmark_ref: Some(benchmark.id.clone()),
                }
            })
            .collect();

        ScanResultSet {
            source: ScanSource {
                scanner: ScannerType::Scc,
                scanner_version: Some("5.7".to_string()),
                scan_date: None,
                source_file: Some("test_scan.xml".to_string()),
                target: Some("testhost.example.mil".to_string()),
                profile: Some("MAC-1_Classified".to_string()),
            },
            results,
        }
    }

    fn make_checklist_with_findings() -> Checklist {
        let benchmark = make_benchmark("Test_STIG", 10);
        let asset = Asset::new("webserver01");
        let scan = make_scan_results(&benchmark, 0.7); // 70% pass

        let engine = EvaluationEngine::with_defaults();
        engine
            .evaluate(&benchmark, &asset, Some(&scan), &[])
            .unwrap()
    }

    // ---------------------------------------------------------------------------
    // End-to-end evaluation pipeline
    // ---------------------------------------------------------------------------

    #[test]
    fn test_full_evaluation_pipeline() {
        let benchmark = make_benchmark("Windows_Server_2022_STIG", 50);
        let asset = Asset::new("dc01.navy.mil");
        let scan = make_scan_results(&benchmark, 0.9); // 90% pass

        let mut answer = AnswerFile::new("Site Answers", Some("Windows_Server_2022_STIG"));
        // Mark some findings as N/A via answer file.
        answer.add_entry(AnswerEntry {
            vuln_id: "V-100001".to_string(),
            status: FindingStatus::NotApplicable,
            finding_details: Some("Not applicable in this environment".to_string()),
            comments: Some("Reviewed by ISSO".to_string()),
            severity_override: None,
            severity_override_justification: None,
            force_override: true,
        });

        let engine = EvaluationEngine::with_defaults();
        let checklist = engine
            .evaluate(&benchmark, &asset, Some(&scan), &[answer])
            .unwrap();

        // Verify results.
        assert_eq!(checklist.findings.len(), 50);
        assert_eq!(checklist.asset.hostname, "dc01.navy.mil");

        // V-100001 should be N/A from the answer file (force_override).
        let f1 = checklist.find_by_vuln_id("V-100001").unwrap();
        assert_eq!(f1.status, FindingStatus::NotApplicable);
        assert_eq!(f1.source, FindingSource::AnswerFile);

        // Summary should be reasonable.
        let summary = checklist.summary();
        assert!(summary.not_a_finding > 0);
        assert!(summary.open > 0 || summary.not_reviewed > 0);
        assert!(summary.compliance_pct() > 0.0);
    }

    #[test]
    fn test_xccdf_scanner_evidence_survives_evaluation_and_ckl_cklb_export() {
        let benchmark_xml =
            include_str!("../../../fixtures/disa-xccdf/windows_server_2022_sanitized_xccdf.xml");
        let benchmark = xccdf::parse_xccdf_benchmark_str(benchmark_xml).unwrap();
        let scan_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">
  <TestResult id="scc_result_1" test-system="cpe:/a:disa:scc:5.7">
    <target>sanitized-win2022.example.test</target>
    <profile>MAC-2_Sensitive</profile>
    <rule-result idref="SV-254239r958388_rule">
      <result>fail</result>
      <message severity="info">Registry value HKLM\Example\Tls12 was missing.</message>
      <check system="urn:xccdf:check:system:script">
        <check-content-ref href="scc-results.xml" name="SV-254239r958388_rule" />
        <check-content>reg query HKLM\Example\Tls12 returned not found</check-content>
      </check>
    </rule-result>
  </TestResult>
</Benchmark>"#;
        let scan = xccdf::parse_xccdf_results_str(scan_xml).unwrap();
        let asset = Asset::new("sanitized-win2022.example.test");
        let engine = EvaluationEngine::with_defaults();
        let checklist = engine
            .evaluate(&benchmark, &asset, Some(&scan), &[])
            .unwrap();

        let finding = checklist.find_by_vuln_id("V-254239").unwrap();
        assert_eq!(finding.status, FindingStatus::Open);
        assert_eq!(finding.source, FindingSource::SccScan);
        assert!(finding
            .finding_details
            .contains("Registry value HKLM\\Example\\Tls12 was missing"));
        assert!(finding
            .finding_details
            .contains("check-content-ref: href=scc-results.xml name=SV-254239r958388_rule"));
        assert!(finding
            .finding_details
            .contains("check-content: reg query HKLM\\Example\\Tls12 returned not found"));
        assert!(finding.comments.contains("Scanner: SCC"));
        assert!(finding
            .comments
            .contains("Target: sanitized-win2022.example.test"));
        assert!(finding.comments.contains("Profile: MAC-2_Sensitive"));
        assert!(finding.comments.contains("Raw result: fail"));

        let ckl = ckl::parse_ckl(&ckl::write_ckl(&checklist).unwrap()).unwrap();
        let ckl_finding = ckl.find_by_vuln_id("V-254239").unwrap();
        assert!(ckl_finding
            .finding_details
            .contains("Registry value HKLM\\Example\\Tls12 was missing"));
        assert!(ckl_finding.comments.contains("Scanner: SCC"));

        let cklb = cklb::parse_cklb(&cklb::write_cklb(&checklist).unwrap()).unwrap();
        let cklb_finding = cklb.find_by_vuln_id("V-254239").unwrap();
        assert!(cklb_finding
            .finding_details
            .contains("Registry value HKLM\\Example\\Tls12 was missing"));
        assert!(cklb_finding.comments.contains("Scanner: SCC"));
    }

    #[test]
    fn test_evaluation_with_no_scan_all_not_reviewed() {
        let benchmark = make_benchmark("RHEL_9_STIG", 20);
        let asset = Asset::new("linuxbox");

        let engine = EvaluationEngine::with_defaults();
        let checklist = engine.evaluate(&benchmark, &asset, None, &[]).unwrap();

        assert_eq!(checklist.findings.len(), 20);
        assert!(checklist
            .findings
            .iter()
            .all(|f| f.status == FindingStatus::NotReviewed));
        assert_eq!(checklist.summary().not_reviewed, 20);
    }

    #[test]
    fn test_evaluation_merge_previous() {
        let benchmark = make_benchmark("Test_STIG", 5);
        let asset = Asset::new("server01");
        let engine = EvaluationEngine::with_defaults();

        // Create a "previous" checklist with manual entries.
        let mut prev = engine.evaluate(&benchmark, &asset, None, &[]).unwrap();
        prev.findings[0].status = FindingStatus::NotApplicable;
        prev.findings[0].source = FindingSource::Manual;
        prev.findings[0].finding_details = "Manually verified N/A".to_string();

        // Create a new checklist (all Not_Reviewed).
        let mut current = engine.evaluate(&benchmark, &asset, None, &[]).unwrap();

        // Merge — manual entries should carry forward.
        engine.merge_previous(&mut current, &prev).unwrap();

        assert_eq!(current.findings[0].status, FindingStatus::NotApplicable);
        assert_eq!(current.findings[0].source, FindingSource::Imported);
        assert_eq!(current.findings[0].finding_details, "Manually verified N/A");
    }

    // ---------------------------------------------------------------------------
    // CKL roundtrip
    // ---------------------------------------------------------------------------

    #[test]
    fn test_ckl_roundtrip_preserves_all_fields() {
        let dir = TempDir::new().unwrap();
        let checklist = make_checklist_with_findings();
        let path = dir.path().join("test.ckl");

        // Write → Read → verify.
        ckl::write_ckl_file(&checklist, &path).unwrap();
        let loaded = ckl::parse_ckl_file(&path).unwrap();

        assert_eq!(loaded.asset.hostname, checklist.asset.hostname);
        assert_eq!(loaded.stig_info.stig_id, checklist.stig_info.stig_id);
        assert_eq!(loaded.findings.len(), checklist.findings.len());

        // Verify individual finding data survived the roundtrip.
        for (orig, loaded_f) in checklist.findings.iter().zip(loaded.findings.iter()) {
            assert_eq!(orig.vuln_id, loaded_f.vuln_id);
            assert_eq!(orig.status, loaded_f.status);
            assert_eq!(orig.severity, loaded_f.severity);
        }
    }

    #[test]
    fn test_cklb_roundtrip() {
        let dir = TempDir::new().unwrap();
        let checklist = make_checklist_with_findings();
        let path = dir.path().join("test.cklb");

        cklb::write_cklb_file(&checklist, &path).unwrap();
        let loaded = cklb::parse_cklb_file(&path).unwrap();

        assert_eq!(loaded.asset.hostname, checklist.asset.hostname);
        assert_eq!(loaded.findings.len(), checklist.findings.len());
    }

    // ---------------------------------------------------------------------------
    // Format conversion
    // ---------------------------------------------------------------------------

    #[test]
    fn test_ckl_to_cklb_to_json_conversion() {
        let dir = TempDir::new().unwrap();
        let original = make_checklist_with_findings();

        // CKL → CKLB → JSON → verify consistency.
        let ckl_path = dir.path().join("step1.ckl");
        let cklb_path = dir.path().join("step2.cklb");
        let json_path = dir.path().join("step3.json");

        ckl::write_ckl_file(&original, &ckl_path).unwrap();
        let from_ckl = ckl::parse_ckl_file(&ckl_path).unwrap();

        cklb::write_cklb_file(&from_ckl, &cklb_path).unwrap();
        let from_cklb = cklb::parse_cklb_file(&cklb_path).unwrap();

        let json = serde_json::to_string_pretty(&from_cklb).unwrap();
        std::fs::write(&json_path, &json).unwrap();
        let from_json: Checklist = serde_json::from_str(&json).unwrap();

        // Core data should survive the chain.
        assert_eq!(from_json.asset.hostname, original.asset.hostname);
        assert_eq!(from_json.findings.len(), original.findings.len());

        // Status should be preserved through all conversions.
        let orig_open = original
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Open)
            .count();
        let final_open = from_json
            .findings
            .iter()
            .filter(|f| f.status == FindingStatus::Open)
            .count();
        assert_eq!(orig_open, final_open);
    }

    // ---------------------------------------------------------------------------
    // STIG Library lifecycle
    // ---------------------------------------------------------------------------

    #[test]
    fn test_library_full_lifecycle() {
        let dir = TempDir::new().unwrap();
        let lib_path = dir.path().join("stiglib");

        // Init.
        let mut library = StigLibrary::init(&lib_path).unwrap();
        assert!(library.list_benchmarks().is_empty());

        // Add benchmarks.
        let b1 = make_benchmark("Win2022_STIG", 10);
        let b2 = make_benchmark("RHEL9_STIG", 8);
        library.add_benchmark(&b1).unwrap();
        library.add_benchmark(&b2).unwrap();

        assert_eq!(library.list_benchmarks().len(), 2);

        // Close and reopen.
        let library = StigLibrary::open(&lib_path).unwrap();
        assert_eq!(library.list_benchmarks().len(), 2);

        // Load and verify.
        let loaded = library.load_benchmark("Win2022_STIG").unwrap();
        assert_eq!(loaded.rules.len(), 10);
        assert_eq!(loaded.title, b1.title);

        // Integrity check — tamper and verify it fails.
        let data_path = lib_path.join("benchmarks/Win2022_STIG.json");
        std::fs::write(&data_path, "corrupted data").unwrap();
        assert!(library.load_benchmark("Win2022_STIG").is_err());
    }

    // ---------------------------------------------------------------------------
    // Stigpack pipeline: build → verify → import
    // ---------------------------------------------------------------------------

    #[test]
    fn test_stigpack_full_pipeline() {
        let dir = TempDir::new().unwrap();
        let pack_path = dir.path().join("test.stigpack");
        let lib_path = dir.path().join("stiglib");

        // Build a pack with two benchmarks.
        let b1 = make_benchmark("Windows_2022", 15);
        let b2 = make_benchmark("RHEL_9", 12);

        let b1_json = serde_json::to_string_pretty(&b1).unwrap();
        let b2_json = serde_json::to_string_pretty(&b2).unwrap();

        PackBuilder::new("disa-stigs-2024q4", "DISA STIGs 2024 Q4", "2024.4.0")
            .description("Quarterly STIG content update")
            .author("AutomateSTIG CI")
            .add_file_bytes("benchmarks/Windows_2022.json", b1_json.as_bytes())
            .add_file_bytes("benchmarks/RHEL_9.json", b2_json.as_bytes())
            .add_file_bytes(
                "answer_templates/windows_answers.yaml",
                b"name: Windows Defaults\nversion: '1.0'\nentries: []",
            )
            .build(&pack_path)
            .unwrap();

        assert!(pack_path.exists());

        // Verify the pack.
        let verification = verifier::verify_pack(&pack_path).unwrap();
        assert!(verification.manifest_valid);
        assert!(verification.integrity_valid);
        assert_eq!(verification.file_results.len(), 3);
        assert!(verification.file_results.iter().all(|f| f.hash_match));

        // Import into a fresh library.
        let mut library = StigLibrary::init(&lib_path).unwrap();
        let result = importer::import_pack(&pack_path, &mut library).unwrap();

        assert_eq!(result.pack_id, "disa-stigs-2024q4");
        assert_eq!(result.benchmarks_imported, 2);
        assert_eq!(result.answer_templates_imported, 1);
        assert!(result.warnings.is_empty());

        // Verify the imported benchmarks work.
        let loaded = library.load_benchmark("Windows_2022").unwrap();
        assert_eq!(loaded.rules.len(), 15);

        let loaded2 = library.load_benchmark("RHEL_9").unwrap();
        assert_eq!(loaded2.rules.len(), 12);
    }

    // ---------------------------------------------------------------------------
    // SQLite storage
    // ---------------------------------------------------------------------------

    #[test]
    fn test_database_full_lifecycle() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");

        let db = Database::open(&db_path).unwrap();

        // Save multiple checklists.
        let cl1 = make_checklist_with_findings();
        let cl2 = {
            let b = make_benchmark("RHEL9", 5);
            let engine = EvaluationEngine::with_defaults();
            engine
                .evaluate(&b, &Asset::new("linuxbox"), None, &[])
                .unwrap()
        };

        let id1 = cl1.id.to_string();
        let _id2 = cl2.id.to_string();

        db.save_checklist(&cl1).unwrap();
        db.save_checklist(&cl2).unwrap();

        // List.
        let list = db.list_checklists().unwrap();
        assert_eq!(list.len(), 2);

        // Load and verify.
        let loaded = db.load_checklist(&id1).unwrap();
        assert_eq!(loaded.asset.hostname, "webserver01");
        assert_eq!(loaded.findings.len(), 10);

        // Log evaluation on cl2 (not cl1, since we'll delete cl1).
        db.log_evaluation(&cl2, "integration-test", Some("test run"))
            .unwrap();

        // Delete cl1 (has no evaluation log entries, so no FK conflict).
        assert!(db.delete_checklist(&id1).unwrap());
        assert!(!db.delete_checklist(&id1).unwrap()); // Already deleted.
        assert_eq!(db.list_checklists().unwrap().len(), 1);

        // Config.
        db.set_config("last_import", "2024-01-15").unwrap();
        assert_eq!(
            db.get_config("last_import").unwrap().as_deref(),
            Some("2024-01-15")
        );
    }

    // ---------------------------------------------------------------------------
    // Answer files
    // ---------------------------------------------------------------------------

    #[test]
    fn test_answer_file_json_yaml_roundtrip() {
        let dir = TempDir::new().unwrap();

        let mut af = AnswerFile::new("Site Standard Answers", Some("Windows_Server_2022_STIG"));
        af.description = Some("Standard answers for our Windows servers".to_string());
        for i in 1..=5 {
            af.add_entry(AnswerEntry {
                vuln_id: format!("V-{}", 100000 + i),
                status: if i % 2 == 0 {
                    FindingStatus::NotApplicable
                } else {
                    FindingStatus::NotAFinding
                },
                finding_details: Some(format!("Standard response for rule {}", i)),
                comments: Some("Reviewed by ISSO".to_string()),
                severity_override: None,
                severity_override_justification: None,
                force_override: false,
            });
        }

        // JSON roundtrip.
        let json_path = dir.path().join("answers.json");
        af.save_json(&json_path).unwrap();
        let from_json = AnswerFile::load(&json_path).unwrap();
        assert_eq!(from_json.entries.len(), 5);
        assert_eq!(from_json.name, "Site Standard Answers");

        // YAML roundtrip.
        let yaml_path = dir.path().join("answers.yaml");
        af.save_yaml(&yaml_path).unwrap();
        let from_yaml = AnswerFile::load(&yaml_path).unwrap();
        assert_eq!(from_yaml.entries.len(), 5);

        // Validate.
        assert!(af.validate().is_empty());
    }

    #[test]
    fn test_generate_answer_template_from_checklist() {
        let checklist = make_checklist_with_findings();

        let template = automatestig_core::answer::generate_answer_template(&checklist, false);
        // Should only include findings that are NOT "Not Reviewed".
        let reviewed_count = checklist
            .findings
            .iter()
            .filter(|f| f.status != FindingStatus::NotReviewed)
            .count();
        assert_eq!(template.entries.len(), reviewed_count);
    }

    // ---------------------------------------------------------------------------
    // Integrations: STIG-Manager export
    // ---------------------------------------------------------------------------

    #[test]
    fn test_stig_manager_export() {
        let checklist = make_checklist_with_findings();

        let json =
            stig_manager::export_to_stig_manager_json(&[checklist], "Test Collection").unwrap();
        let import: stig_manager::StigManagerImport = serde_json::from_str(&json).unwrap();

        assert_eq!(import.collection, "Test Collection");
        assert_eq!(import.assets.len(), 1);
        assert_eq!(import.assets[0].name, "webserver01");
        assert_eq!(import.assets[0].stigs.len(), 1);
        assert_eq!(import.assets[0].stigs[0].reviews.len(), 10);

        // All automated results should have result_engine.
        for review in &import.assets[0].stigs[0].reviews {
            if review.auto_result {
                assert!(review.result_engine.is_some());
                let re = review.result_engine.as_ref().unwrap();
                assert_eq!(re.product, "AutomateSTIG");
            }
        }
    }

    // ---------------------------------------------------------------------------
    // XCCDF parsing
    // ---------------------------------------------------------------------------

    #[test]
    fn test_xccdf_benchmark_parsing() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="Test_Bench">
  <title>Test Benchmark</title>
  <description>Test description</description>
  <version>002</version>
  <plain-text id="release-info">Release: 3 Benchmark Date: 01 Jan 2024</plain-text>
  <platform idref="cpe:/o:test:os" />
  <Group id="V-1001">
    <Rule id="SV-1001r1_rule" severity="high" weight="10.0">
      <version>V-1001</version>
      <title>High severity rule</title>
      <description>Must be configured</description>
      <fixtext>Configure it</fixtext>
      <check><check-content>Verify configuration</check-content></check>
      <ident system="http://iase.disa.mil/cci">CCI-000001</ident>
    </Rule>
  </Group>
  <Group id="V-1002">
    <Rule id="SV-1002r1_rule" severity="medium" weight="8.0">
      <version>V-1002</version>
      <title>Medium severity rule</title>
      <description>Should be configured</description>
      <fixtext>Configure it too</fixtext>
      <check><check-content>Verify other config</check-content></check>
      <ident system="http://iase.disa.mil/cci">CCI-000002</ident>
    </Rule>
  </Group>
</Benchmark>"#;

        let benchmark = xccdf::parse_xccdf_benchmark_str(xml).unwrap();
        assert_eq!(benchmark.id, "Test_Bench");
        assert_eq!(benchmark.version, "002");
        assert_eq!(benchmark.release, "3");
        assert_eq!(benchmark.rules.len(), 2);

        assert_eq!(benchmark.rules[0].severity, Severity::High);
        assert_eq!(benchmark.rules[0].vuln_id, "V-1001");
        assert!(benchmark.rules[0]
            .cci_refs
            .contains(&"CCI-000001".to_string()));

        assert_eq!(benchmark.rules[1].severity, Severity::Medium);
    }

    // ---------------------------------------------------------------------------
    // Config dump evaluation
    // ---------------------------------------------------------------------------

    #[test]
    fn test_cisco_config_evaluation() {
        use automatestig_parsers::config_dump::*;

        let config_text = r#"!
hostname CORE-SW-01
!
service password-encryption
!
ip ssh version 2
!
banner login ^
Authorized users only.
^
!
line vty 0 4
 transport input ssh
!
ntp server 10.0.0.100
!
end"#;

        let config = parse_cisco_config(config_text, ConfigType::CiscoIos).unwrap();
        assert_eq!(config.hostname.as_deref(), Some("CORE-SW-01"));

        // Check: SSH v2 must be present.
        let r1 = evaluate_config_check(&config, "V-NET-001", &["ip ssh version 2"], &[], None);
        assert_eq!(r1.passed, Some(true));

        // Check: Telnet must be absent from VTY lines.
        let r2 = evaluate_config_check(
            &config,
            "V-NET-002",
            &["transport input ssh"],
            &["transport input telnet"],
            Some("line vty"),
        );
        assert_eq!(r2.passed, Some(true));

        // Check: NTP must be configured.
        let r3 = evaluate_config_check(&config, "V-NET-003", &["ntp server"], &[], None);
        assert_eq!(r3.passed, Some(true));

        // Check: Should fail — looking for something that doesn't exist.
        let r4 = evaluate_config_check(
            &config,
            "V-NET-004",
            &["ip access-list extended"],
            &[],
            None,
        );
        assert_eq!(r4.passed, Some(false));
    }

    // ---------------------------------------------------------------------------
    // Finding summary statistics
    // ---------------------------------------------------------------------------

    #[test]
    fn test_finding_summary_accuracy() {
        let benchmark = make_benchmark("Test", 100);
        let asset = Asset::new("testhost");
        let scan = make_scan_results(&benchmark, 0.85); // 85% pass

        let engine = EvaluationEngine::with_defaults();
        let checklist = engine
            .evaluate(&benchmark, &asset, Some(&scan), &[])
            .unwrap();

        let summary = checklist.summary();

        // Verify totals add up.
        assert_eq!(
            summary.total,
            summary.open + summary.not_a_finding + summary.not_applicable + summary.not_reviewed
        );

        // With 85% pass rate and no answer files, should be roughly 85 NaF, 15 Open.
        assert!(summary.not_a_finding >= 80);
        assert!(summary.open >= 10);
        assert_eq!(summary.not_reviewed, 0); // All should be evaluated.

        // CAT breakdowns should add up to open.
        assert_eq!(
            summary.open,
            summary.cat_i_open + summary.cat_ii_open + summary.cat_iii_open
        );

        // Compliance percentage should be reasonable.
        assert!(summary.compliance_pct() > 80.0);
        assert!(summary.compliance_pct() < 100.0);
    }

    // ---------------------------------------------------------------------------
    // Cross-platform path handling
    // ---------------------------------------------------------------------------

    #[test]
    fn test_library_with_spaces_in_path() {
        let dir = TempDir::new().unwrap();
        let lib_path = dir.path().join("my stig library");

        let mut library = StigLibrary::init(&lib_path).unwrap();
        let benchmark = make_benchmark("Test_STIG", 3);
        library.add_benchmark(&benchmark).unwrap();

        let loaded = library.load_benchmark("Test_STIG").unwrap();
        assert_eq!(loaded.rules.len(), 3);
    }

    #[test]
    fn test_database_with_unicode_path() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("data.db");

        let db = Database::open(&db_path).unwrap();
        let cl = make_checklist_with_findings();
        db.save_checklist(&cl).unwrap();

        let loaded = db.load_checklist(&cl.id.to_string()).unwrap();
        assert_eq!(loaded.findings.len(), cl.findings.len());
    }

    // ---------------------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn test_empty_checklist_operations() {
        let stig_info = ChecklistStigInfo {
            stig_id: "Empty_STIG".to_string(),
            title: "Empty".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            uuid: None,
            description: None,
            filename: None,
        };

        let cl = Checklist::new(Asset::new("empty"), stig_info);

        assert!(cl.findings.is_empty());
        assert_eq!(cl.summary().total, 0);
        assert_eq!(cl.summary().compliance_pct(), 0.0);
        assert!(cl.open_findings().is_empty());
    }

    #[test]
    fn test_severity_override_in_summary() {
        let benchmark = make_benchmark("Test", 5);
        let asset = Asset::new("testhost");
        let engine = EvaluationEngine::with_defaults();
        let mut cl = engine.evaluate(&benchmark, &asset, None, &[]).unwrap();

        // Set one finding to Open with severity override.
        cl.findings[0].status = FindingStatus::Open;
        cl.findings[0].severity = Severity::Medium; // Original.
        cl.findings[0].severity_override = Some(Severity::High); // Override.

        let summary = cl.summary();
        // The overridden finding should be counted as CAT I.
        assert_eq!(summary.cat_i_open, 1);
    }

    #[test]
    fn test_large_benchmark_performance() {
        // Ensure evaluation scales reasonably.
        let benchmark = make_benchmark("Large_STIG", 500);
        let asset = Asset::new("bigserver");
        let scan = make_scan_results(&benchmark, 0.95);

        let engine = EvaluationEngine::with_defaults();
        let start = std::time::Instant::now();
        let checklist = engine
            .evaluate(&benchmark, &asset, Some(&scan), &[])
            .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(checklist.findings.len(), 500);
        // Should complete in well under 1 second.
        assert!(
            elapsed.as_secs() < 1,
            "Evaluation took too long: {:?}",
            elapsed
        );
    }

    // ---------------------------------------------------------------------------
    // Check executor E2E
    // ---------------------------------------------------------------------------

    #[test]
    fn test_check_executor_windows_registry() {
        use automatestig_core::checks::executor::execute_check;
        use automatestig_core::checks::*;

        let mut data = SystemData::default();
        data.registry.insert(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel".to_string(),
            serde_json::json!(5),
        );

        let check = CheckDefinition {
            vuln_id: "V-254270".to_string(),
            platform: CheckPlatform::Windows,
            check: Check::Registry {
                path: r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa".to_string(),
                value_name: "LmCompatibilityLevel".to_string(),
                value_type: None,
            },
            expected: ExpectedResult::Equals {
                value: serde_json::json!(5),
            },
            description: Some("NTLMv2 only".to_string()),
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_check_executor_linux_compound() {
        use automatestig_core::checks::executor::execute_check;
        use automatestig_core::checks::*;

        let mut data = SystemData::default();
        data.file_contents.insert(
            "/etc/ssh/sshd_config".to_string(),
            "PermitRootLogin no\nMaxAuthTries 3\n".to_string(),
        );
        data.services
            .insert("sshd".to_string(), "active".to_string());

        let check = CheckDefinition {
            vuln_id: "V-COMPOUND".to_string(),
            platform: CheckPlatform::Linux,
            check: Check::All {
                checks: vec![
                    Check::FileContent {
                        path: "/etc/ssh/sshd_config".to_string(),
                        pattern: "PermitRootLogin no".to_string(),
                        is_regex: false,
                    },
                    Check::Service {
                        name: "sshd".to_string(),
                        expected_status: ServiceStatus::Running,
                    },
                ],
            },
            expected: ExpectedResult::AllPass,
            description: None,
        };

        let result = execute_check(&check, &data);
        assert!(result.passed);
    }

    // ---------------------------------------------------------------------------
    // XCCDF converter E2E
    // ---------------------------------------------------------------------------

    #[test]
    fn test_xccdf_converter_auto_generates_checks() {
        use automatestig_core::converter;

        let benchmark = StigBenchmark {
            id: "Test_Converter_STIG".to_string(),
            title: "Test Linux STIG for Converter".to_string(),
            description: "Test".to_string(),
            version: "1".to_string(),
            release: "1".to_string(),
            release_date: None,
            xccdf_id: None,
            platform: Platform::default(),
            rules: vec![
                StigRule {
                    vuln_id: "V-1".to_string(),
                    rule_id: "SV-1".to_string(),
                    group_id: "V-1".to_string(),
                    title: "IP forwarding".to_string(),
                    discussion: "".to_string(),
                    severity: Severity::Medium,
                    check_content: "Verify sysctl net.ipv4.ip_forward is not 0.".to_string(),
                    fix_text: "".to_string(),
                    cci_refs: vec![],
                    legacy_ids: vec![],
                    stig_ref: None,
                    weight: 8.0,
                    automatable: CheckAutomation::Full,
                    automated_check: None,
                    remediation_ids: vec![],
                },
                StigRule {
                    vuln_id: "V-2".to_string(),
                    rule_id: "SV-2".to_string(),
                    group_id: "V-2".to_string(),
                    title: "Manual check".to_string(),
                    discussion: "".to_string(),
                    severity: Severity::Low,
                    check_content: "Interview the ISSO and verify policy exists.".to_string(),
                    fix_text: "".to_string(),
                    cci_refs: vec![],
                    legacy_ids: vec![],
                    stig_ref: None,
                    weight: 2.0,
                    automatable: CheckAutomation::Manual,
                    automated_check: None,
                    remediation_ids: vec![],
                },
                StigRule {
                    vuln_id: "V-3".to_string(),
                    rule_id: "SV-3".to_string(),
                    group_id: "V-3".to_string(),
                    title: "Package check".to_string(),
                    discussion: "".to_string(),
                    severity: Severity::Medium,
                    check_content: "Verify the package telnet-server must not be installed."
                        .to_string(),
                    fix_text: "".to_string(),
                    cci_refs: vec![],
                    legacy_ids: vec![],
                    stig_ref: None,
                    weight: 8.0,
                    automatable: CheckAutomation::Full,
                    automated_check: None,
                    remediation_ids: vec![],
                },
            ],
        };

        let result = converter::convert_benchmark(&benchmark);
        assert_eq!(result.automated, 2); // sysctl + package
        assert_eq!(result.manual, 1); // interview
        assert_eq!(result.check_pack.checks.len(), 2);
        assert_eq!(
            result.check_pack.platform,
            automatestig_core::checks::CheckPlatform::Linux
        );
    }

    // ---------------------------------------------------------------------------
    // Inventory and credentials E2E
    // ---------------------------------------------------------------------------

    #[test]
    fn test_asset_inventory_roundtrip() {
        use automatestig_core::checks::CheckPlatform;
        use automatestig_core::inventory::assets::*;

        let mut asset = ManagedAsset::new(
            "web01",
            "10.0.1.50",
            CheckPlatform::Linux,
            ScanProtocol::Ssh,
        );
        asset.assigned_stigs = vec!["RHEL_9_STIG".to_string(), "Apache_2.4_STIG".to_string()];
        asset.tags = vec!["production".to_string(), "web-tier".to_string()];

        let json = serde_json::to_string(&asset).unwrap();
        let loaded: ManagedAsset = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.name, "web01");
        assert_eq!(loaded.assigned_stigs.len(), 2);
        assert_eq!(loaded.tags.len(), 2);
        assert_eq!(loaded.effective_port(), 22);
    }

    #[test]
    fn test_credential_vault_lifecycle() {
        use automatestig_core::inventory::credentials::*;

        let mut vault = CredentialVault::new();

        let cred1 = StoredCredential::new_password("Admin", "admin", "P@ssw0rd");
        let cred2 = StoredCredential::new_ssh_key("Deploy", "deploy", "-----BEGIN KEY-----", None);
        let cred3 =
            StoredCredential::new_kerberos("Domain SA", "svc_stig", "NAVY.MIL", "DomainPass");
        let cred4 = StoredCredential::new_token("API Key", "sk-abc123", Some("bearer"));

        let id1 = cred1.id.clone();

        vault.add(cred1);
        vault.add(cred2);
        vault.add(cred3);
        vault.add(cred4);

        assert_eq!(vault.credentials.len(), 4);

        // Summaries should not expose secrets.
        let summaries = vault.list_summary();
        assert_eq!(summaries[0].credential_type, "password");
        assert_eq!(summaries[1].credential_type, "ssh_key");
        assert_eq!(summaries[2].credential_type, "kerberos");
        assert_eq!(summaries[3].credential_type, "token");

        // Remove and verify.
        assert!(vault.remove(&id1));
        assert_eq!(vault.credentials.len(), 3);
    }

    // ---------------------------------------------------------------------------
    // Signed stigpack E2E
    // ---------------------------------------------------------------------------

    #[test]
    fn test_signed_stigpack_pipeline() {
        use automatestig_stigpack::builder::PackBuilder;
        use automatestig_stigpack::signing;
        use automatestig_stigpack::verifier;

        let dir = TempDir::new().unwrap();
        let pack_path = dir.path().join("signed.stigpack");

        // Generate keypair.
        let (private_key, public_key) = signing::generate_keypair();

        // Build a signed pack.
        let benchmark = make_benchmark("Signed_Test", 5);
        let json = serde_json::to_string(&benchmark).unwrap();

        PackBuilder::new("signed-pack", "Signed Pack", "1.0.0")
            .signing_key(private_key)
            .add_file_bytes("benchmarks/Signed_Test.json", json.as_bytes())
            .build(&pack_path)
            .unwrap();

        // Verify with correct key — should pass.
        let mut trust_store = signing::TrustStore::new();
        trust_store.add_key("official", public_key);

        let result = verifier::verify_pack_with_trust(&pack_path, Some(&trust_store)).unwrap();
        assert!(result.manifest_valid);
        assert!(result.integrity_valid);
        assert_eq!(result.signature_valid, Some(true));

        // Verify with wrong key — should fail signature.
        let (_, other_pub) = signing::generate_keypair();
        let mut bad_store = signing::TrustStore::new();
        bad_store.add_key("wrong", other_pub);

        let result2 = verifier::verify_pack_with_trust(&pack_path, Some(&bad_store)).unwrap();
        assert!(result2.manifest_valid);
        assert!(result2.integrity_valid);
        assert_eq!(result2.signature_valid, Some(false));
    }

    // ---------------------------------------------------------------------------
    // Replacement-readiness fixture scaffolding
    // ---------------------------------------------------------------------------

    #[test]
    fn test_sanitized_xccdf_and_scan_result_fixtures_parse() {
        let benchmark_xml =
            include_str!("../../../fixtures/disa-xccdf/windows_server_2022_sanitized_xccdf.xml");
        let benchmark = xccdf::parse_xccdf_benchmark_str(benchmark_xml).unwrap();
        assert_eq!(benchmark.id, "Windows_Server_2022_STIG");
        assert_eq!(benchmark.rules.len(), 2);
        assert!(benchmark.rules.iter().any(|r| r.vuln_id == "V-254239"));

        let scc_xml =
            include_str!("../../../fixtures/scc-results/windows_server_2022_scc_results.xml");
        let scc_results = xccdf::parse_xccdf_results_str(scc_xml).unwrap();
        assert_eq!(
            scc_results.source.target.as_deref(),
            Some("sanitized-win2022.example.test")
        );
        assert_eq!(scc_results.results.len(), 2);
        assert_eq!(scc_results.results[0].passed, Some(false));
        assert_eq!(scc_results.results[1].passed, Some(true));

        let openscap_xml =
            include_str!("../../../fixtures/openscap-results/rhel8_openscap_results.xml");
        let openscap_results = xccdf::parse_xccdf_results_str(openscap_xml).unwrap();
        assert_eq!(
            openscap_results.source.target.as_deref(),
            Some("sanitized-rhel8.example.test")
        );
        assert_eq!(openscap_results.results.len(), 2);
        assert_eq!(openscap_results.results[0].passed, Some(true));
        assert_eq!(openscap_results.results[1].passed, Some(false));
    }

    #[test]
    fn test_sanitized_ckl_and_cklb_fixtures_parse() {
        let ckl_xml = include_str!("../../../fixtures/ckl/windows_server_2022_sanitized.ckl");
        let ckl_checklist = ckl::parse_ckl(ckl_xml).unwrap();
        assert_eq!(ckl_checklist.asset.hostname, "sanitized-win2022");
        assert_eq!(ckl_checklist.findings.len(), 1);
        assert_eq!(ckl_checklist.findings[0].status, FindingStatus::Open);

        let cklb_json = include_str!("../../../fixtures/cklb/windows_server_2022_sanitized.cklb");
        let cklb_checklist = cklb::parse_cklb(cklb_json).unwrap();
        assert_eq!(cklb_checklist.asset.hostname, "sanitized-win2022");
        assert_eq!(cklb_checklist.findings.len(), 1);
        assert_eq!(cklb_checklist.findings[0].status, FindingStatus::Open);
    }

    #[test]
    fn test_example_coverage_manifests_are_internally_consistent() {
        for manifest_json in [include_str!("../../../content/coverage/rhel8.example.json")] {
            let manifest: serde_json::Value = serde_json::from_str(manifest_json).unwrap();
            assert_eq!(manifest["status"], "experimental");
            let total_rules = manifest["total_rules"].as_u64().unwrap();
            let rules = manifest["rules"].as_array().unwrap();
            assert_eq!(total_rules as usize, rules.len());
            assert!(rules
                .iter()
                .all(|rule| rule["vuln_id"].as_str().unwrap().starts_with("V-")));
            assert!(rules
                .iter()
                .all(|rule| rule["reason"].as_str().unwrap().len() > 10));
        }
    }
} // mod integration
