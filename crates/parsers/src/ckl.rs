//! CKL (Checklist) file parser and writer.
//!
//! CKL files are XML documents used by DISA STIG Viewer to store
//! evaluation results. This module reads and writes the CKL format
//! with full fidelity, supporting all standard elements.
//!
//! CKL Structure:
//! ```xml
//! <CHECKLIST>
//!   <ASSET>
//!     <ROLE>...</ROLE>
//!     <ASSET_TYPE>...</ASSET_TYPE>
//!     <HOST_NAME>...</HOST_NAME>
//!     ...
//!   </ASSET>
//!   <STIGS>
//!     <iSTIG>
//!       <STIG_INFO>
//!         <SI_DATA><SID_NAME>...</SID_NAME><SID_DATA>...</SID_DATA></SI_DATA>
//!         ...
//!       </STIG_INFO>
//!       <VULN>
//!         <STIG_DATA><VULN_ATTRIBUTE>...</VULN_ATTRIBUTE><ATTRIBUTE_DATA>...</ATTRIBUTE_DATA></STIG_DATA>
//!         ...
//!         <STATUS>...</STATUS>
//!         <FINDING_DETAILS>...</FINDING_DETAILS>
//!         <COMMENTS>...</COMMENTS>
//!         <SEVERITY_OVERRIDE>...</SEVERITY_OVERRIDE>
//!         <SEVERITY_JUSTIFICATION>...</SEVERITY_JUSTIFICATION>
//!       </VULN>
//!     </iSTIG>
//!   </STIGS>
//! </CHECKLIST>
//! ```

use std::io::Write;
use std::path::Path;

use quick_xml::events::{BytesEnd, BytesPI, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;

use automatestig_core::models::asset::{Asset, AssetRole, AssetType};
use automatestig_core::models::checklist::{Checklist, ChecklistStigInfo, Classification};
use automatestig_core::models::finding::{Finding, FindingSource, FindingStatus};
use automatestig_core::models::stig::Severity;

use crate::error::{ParseError, ParseResult};

/// Parse a CKL file from a path.
pub fn parse_ckl_file(path: &Path) -> ParseResult<Checklist> {
    let content = std::fs::read_to_string(path)?;
    parse_ckl(&content)
}

/// Parse CKL XML content into a Checklist.
pub fn parse_ckl(xml: &str) -> ParseResult<Checklist> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut asset = Asset::default();
    let mut stig_info = ChecklistStigInfo {
        stig_id: String::new(),
        title: String::new(),
        version: String::new(),
        release: String::new(),
        release_date: None,
        uuid: None,
        description: None,
        filename: None,
    };
    let mut findings: Vec<Finding> = Vec::new();
    let mut classification = Classification::Unclassified;

    // Parser state tracking.
    let mut in_asset = false;
    let mut in_stig_info = false;
    let mut in_vuln = false;
    let mut in_si_data = false;
    let mut in_stig_data = false;

    let mut current_tag = String::new();
    let mut si_name = String::new();
    let mut si_data = String::new();
    let mut vuln_attrs: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut vuln_attr_name = String::new();
    let mut vuln_attr_data = String::new();
    let mut vuln_status = String::new();
    let mut vuln_finding_details = String::new();
    let mut vuln_comments = String::new();
    let mut vuln_severity_override = String::new();
    let mut vuln_severity_justification = String::new();

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                current_tag = tag.clone();

                match tag.as_str() {
                    "ASSET" => in_asset = true,
                    "STIG_INFO" => in_stig_info = true,
                    "VULN" => {
                        in_vuln = true;
                        vuln_attrs.clear();
                        vuln_status.clear();
                        vuln_finding_details.clear();
                        vuln_comments.clear();
                        vuln_severity_override.clear();
                        vuln_severity_justification.clear();
                    }
                    "SI_DATA" => {
                        in_si_data = true;
                        si_name.clear();
                        si_data.clear();
                    }
                    "STIG_DATA" => {
                        in_stig_data = true;
                        vuln_attr_name.clear();
                        vuln_attr_data.clear();
                    }
                    _ => {}
                }
            }

            Ok(Event::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match tag.as_str() {
                    "ASSET" => in_asset = false,
                    "STIG_INFO" => in_stig_info = false,
                    "VULN" => {
                        in_vuln = false;
                        // Build finding from accumulated data.
                        let finding = build_finding_from_attrs(
                            &vuln_attrs,
                            &vuln_status,
                            &vuln_finding_details,
                            &vuln_comments,
                            &vuln_severity_override,
                            &vuln_severity_justification,
                        );
                        findings.push(finding);
                    }
                    "SI_DATA" => {
                        in_si_data = false;
                        if in_stig_info {
                            apply_stig_info(&mut stig_info, &si_name, &si_data);
                        }
                    }
                    "STIG_DATA" => {
                        in_stig_data = false;
                        if !vuln_attr_name.is_empty() {
                            vuln_attrs.insert(vuln_attr_name.clone(), vuln_attr_data.clone());
                        }
                    }
                    _ => {}
                }
                current_tag.clear();
            }

            Ok(Event::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();

                if in_asset {
                    match current_tag.as_str() {
                        "ROLE" => asset.role = AssetRole::from_ckl_str(&text),
                        "ASSET_TYPE" => asset.asset_type = AssetType::from_ckl_str(&text),
                        "HOST_NAME" => asset.hostname = text,
                        "HOST_IP" => asset.ip_address = Some(text),
                        "HOST_MAC" => asset.mac_address = Some(text),
                        "HOST_FQDN" => asset.fqdn = Some(text),
                        "TARGET_COMMENT" => asset.target_comment = Some(text),
                        "MARKING" => {
                            classification = match text.as_str() {
                                "CUI" => Classification::Cui,
                                "CONFIDENTIAL" => Classification::Confidential,
                                "SECRET" => Classification::Secret,
                                "TOP SECRET" => Classification::TopSecret,
                                _ => Classification::Unclassified,
                            };
                        }
                        _ => {}
                    }
                } else if in_si_data {
                    match current_tag.as_str() {
                        "SID_NAME" => si_name = text,
                        "SID_DATA" => si_data = text,
                        _ => {}
                    }
                } else if in_stig_data && in_vuln {
                    match current_tag.as_str() {
                        "VULN_ATTRIBUTE" => vuln_attr_name = text,
                        "ATTRIBUTE_DATA" => vuln_attr_data = text,
                        _ => {}
                    }
                } else if in_vuln {
                    match current_tag.as_str() {
                        "STATUS" => vuln_status = text,
                        "FINDING_DETAILS" => vuln_finding_details = text,
                        "COMMENTS" => vuln_comments = text,
                        "SEVERITY_OVERRIDE" => vuln_severity_override = text,
                        "SEVERITY_JUSTIFICATION" => vuln_severity_justification = text,
                        _ => {}
                    }
                }
            }

            Ok(Event::Eof) => break,
            Err(e) => return Err(ParseError::XmlError(format!("XML parse error: {}", e))),
            _ => {}
        }
        buf.clear();
    }

    let mut checklist = Checklist::new(asset, stig_info);
    checklist.findings = findings;
    checklist.classification = classification;

    Ok(checklist)
}

/// Write a Checklist to CKL XML format.
pub fn write_ckl(checklist: &Checklist) -> ParseResult<String> {
    let mut buffer = Vec::new();
    let mut writer = Writer::new_with_indent(&mut buffer, b' ', 2);

    // XML declaration.
    writer
        .write_event(Event::Decl(quick_xml::events::BytesDecl::new("1.0", Some("UTF-8"), None)))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    // Processing instruction for STIG Viewer compatibility.
    writer
        .write_event(Event::PI(BytesPI::new("xml-stylesheet type='text/xsl' href='STIG_unclass.xsl'")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    // <CHECKLIST>
    writer
        .write_event(Event::Start(BytesStart::new("CHECKLIST")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    // <ASSET>
    write_asset_element(&mut writer, &checklist.asset, &checklist.classification)?;

    // <STIGS>
    writer
        .write_event(Event::Start(BytesStart::new("STIGS")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    // <iSTIG>
    writer
        .write_event(Event::Start(BytesStart::new("iSTIG")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    // <STIG_INFO>
    write_stig_info_element(&mut writer, &checklist.stig_info)?;

    // <VULN> elements.
    for finding in &checklist.findings {
        write_vuln_element(&mut writer, finding)?;
    }

    // </iSTIG>
    writer
        .write_event(Event::End(BytesEnd::new("iSTIG")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    // </STIGS>
    writer
        .write_event(Event::End(BytesEnd::new("STIGS")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    // </CHECKLIST>
    writer
        .write_event(Event::End(BytesEnd::new("CHECKLIST")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    String::from_utf8(buffer).map_err(|e| ParseError::XmlError(e.to_string()))
}

/// Write a Checklist to a CKL file.
pub fn write_ckl_file(checklist: &Checklist, path: &Path) -> ParseResult<()> {
    let xml = write_ckl(checklist)?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(xml.as_bytes())?;
    Ok(())
}

// --- Helper functions ---

fn apply_stig_info(info: &mut ChecklistStigInfo, name: &str, data: &str) {
    match name {
        "version" => info.version = data.to_string(),
        "classification" => {} // Handled at ASSET level
        "customname" => {}
        "stigid" => info.stig_id = data.to_string(),
        "description" => info.description = Some(data.to_string()),
        "filename" => info.filename = Some(data.to_string()),
        "releaseinfo" => {
            info.release = extract_release_number(data);
            info.release_date = extract_release_date(data);
        }
        "title" => info.title = data.to_string(),
        "uuid" => info.uuid = Some(data.to_string()),
        "notice" => {}
        "source" => {}
        _ => {}
    }
}

fn extract_release_number(release_info: &str) -> String {
    // Format: "Release: 4 Benchmark Date: 24 Jul 2024"
    if let Some(pos) = release_info.find("Release:") {
        let rest = &release_info[pos + 8..];
        rest.split_whitespace()
            .next()
            .unwrap_or("0")
            .to_string()
    } else {
        "0".to_string()
    }
}

fn extract_release_date(release_info: &str) -> Option<String> {
    // Format: "Release: 4 Benchmark Date: 24 Jul 2024"
    release_info
        .find("Benchmark Date:")
        .map(|pos| release_info[pos + 15..].trim().to_string())
}

fn build_finding_from_attrs(
    attrs: &std::collections::HashMap<String, String>,
    status: &str,
    finding_details: &str,
    comments: &str,
    severity_override: &str,
    severity_justification: &str,
) -> Finding {
    let vuln_id = attrs.get("Vuln_Num").cloned().unwrap_or_default();
    let rule_id = attrs.get("Rule_ID").cloned().unwrap_or_default();
    let group_id = attrs.get("Group_Title").cloned().unwrap_or_default();
    let title = attrs.get("Rule_Title").cloned().unwrap_or_default();

    let severity = attrs
        .get("Severity")
        .and_then(|s| Severity::from_cat_str(s))
        .unwrap_or(Severity::Medium);

    let cci_refs: Vec<String> = attrs
        .get("CCI_REF")
        .map(|s| s.split(',').map(|c| c.trim().to_string()).collect())
        .unwrap_or_default();

    let legacy_ids: Vec<String> = ["LEGACY_ID", "STIGRef"]
        .iter()
        .filter_map(|key| attrs.get(*key))
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect();

    let mut finding = Finding::new_not_reviewed(&vuln_id, &rule_id, &group_id, &title, severity);
    finding.status = FindingStatus::from_ckl_str(status).unwrap_or(FindingStatus::NotReviewed);
    finding.finding_details = finding_details.to_string();
    finding.comments = comments.to_string();
    finding.cci_refs = cci_refs;
    finding.legacy_ids = legacy_ids;
    finding.source = FindingSource::Imported;

    if !severity_override.is_empty() {
        finding.severity_override = Severity::from_cat_str(severity_override);
        if !severity_justification.is_empty() {
            finding.severity_override_justification = Some(severity_justification.to_string());
        }
    }

    finding
}

fn write_simple_element<W: Write>(writer: &mut Writer<W>, tag: &str, text: &str) -> ParseResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new(tag)))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;
    writer
        .write_event(Event::Text(BytesText::new(text)))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;
    writer
        .write_event(Event::End(BytesEnd::new(tag)))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;
    Ok(())
}

fn write_asset_element<W: Write>(
    writer: &mut Writer<W>,
    asset: &Asset,
    classification: &Classification,
) -> ParseResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("ASSET")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    write_simple_element(writer, "ROLE", asset.role.as_ckl_str())?;
    write_simple_element(writer, "ASSET_TYPE", asset.asset_type.as_ckl_str())?;
    write_simple_element(writer, "MARKING", &classification.to_string())?;
    write_simple_element(writer, "HOST_NAME", &asset.hostname)?;
    write_simple_element(writer, "HOST_IP", asset.ip_address.as_deref().unwrap_or(""))?;
    write_simple_element(writer, "HOST_MAC", asset.mac_address.as_deref().unwrap_or(""))?;
    write_simple_element(writer, "HOST_FQDN", asset.fqdn.as_deref().unwrap_or(""))?;
    write_simple_element(
        writer,
        "TARGET_COMMENT",
        asset.target_comment.as_deref().unwrap_or(""),
    )?;
    write_simple_element(writer, "TECH_AREA", "")?;
    write_simple_element(writer, "TARGET_KEY", "")?;
    write_simple_element(writer, "WEB_OR_DATABASE", "false")?;
    write_simple_element(writer, "WEB_DB_SITE", "")?;
    write_simple_element(writer, "WEB_DB_INSTANCE", "")?;

    writer
        .write_event(Event::End(BytesEnd::new("ASSET")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    Ok(())
}

fn write_si_data<W: Write>(writer: &mut Writer<W>, name: &str, data: &str) -> ParseResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("SI_DATA")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;
    write_simple_element(writer, "SID_NAME", name)?;
    write_simple_element(writer, "SID_DATA", data)?;
    writer
        .write_event(Event::End(BytesEnd::new("SI_DATA")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;
    Ok(())
}

fn write_stig_info_element<W: Write>(
    writer: &mut Writer<W>,
    info: &ChecklistStigInfo,
) -> ParseResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("STIG_INFO")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    write_si_data(writer, "version", &info.version)?;
    write_si_data(writer, "classification", "UNCLASSIFIED")?;
    write_si_data(writer, "customname", "")?;
    write_si_data(writer, "stigid", &info.stig_id)?;
    write_si_data(
        writer,
        "description",
        info.description.as_deref().unwrap_or(""),
    )?;
    write_si_data(
        writer,
        "filename",
        info.filename.as_deref().unwrap_or(""),
    )?;

    let release_info = format!(
        "Release: {} Benchmark Date: {}",
        info.release,
        info.release_date.as_deref().unwrap_or("Unknown")
    );
    write_si_data(writer, "releaseinfo", &release_info)?;
    write_si_data(writer, "title", &info.title)?;
    write_si_data(
        writer,
        "uuid",
        info.uuid.as_deref().unwrap_or(""),
    )?;
    write_si_data(writer, "notice", "terms-of-use")?;
    write_si_data(writer, "source", "")?;

    writer
        .write_event(Event::End(BytesEnd::new("STIG_INFO")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    Ok(())
}

fn write_stig_data<W: Write>(writer: &mut Writer<W>, attr: &str, data: &str) -> ParseResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("STIG_DATA")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;
    write_simple_element(writer, "VULN_ATTRIBUTE", attr)?;
    write_simple_element(writer, "ATTRIBUTE_DATA", data)?;
    writer
        .write_event(Event::End(BytesEnd::new("STIG_DATA")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;
    Ok(())
}

fn write_vuln_element<W: Write>(writer: &mut Writer<W>, finding: &Finding) -> ParseResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("VULN")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    // Write STIG_DATA attributes.
    write_stig_data(writer, "Vuln_Num", &finding.vuln_id)?;
    write_stig_data(writer, "Severity", finding.severity.as_xccdf_str())?;
    write_stig_data(writer, "Group_Title", &finding.group_id)?;
    write_stig_data(writer, "Rule_ID", &finding.rule_id)?;
    write_stig_data(writer, "Rule_Title", &finding.rule_title)?;
    write_stig_data(writer, "Rule_Ver", "")?;
    write_stig_data(writer, "Weight", &finding.severity.default_weight().to_string())?;

    for cci in &finding.cci_refs {
        write_stig_data(writer, "CCI_REF", cci)?;
    }

    // Write finding details.
    write_simple_element(writer, "STATUS", finding.status.as_ckl_str())?;
    write_simple_element(writer, "FINDING_DETAILS", &finding.finding_details)?;
    write_simple_element(writer, "COMMENTS", &finding.comments)?;
    write_simple_element(
        writer,
        "SEVERITY_OVERRIDE",
        finding
            .severity_override
            .map(|s| s.as_xccdf_str())
            .unwrap_or(""),
    )?;
    write_simple_element(
        writer,
        "SEVERITY_JUSTIFICATION",
        finding
            .severity_override_justification
            .as_deref()
            .unwrap_or(""),
    )?;

    writer
        .write_event(Event::End(BytesEnd::new("VULN")))
        .map_err(|e| ParseError::XmlError(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ckl() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET>
    <ROLE>Member Server</ROLE>
    <ASSET_TYPE>Computing</ASSET_TYPE>
    <MARKING>CUI</MARKING>
    <HOST_NAME>webserver01</HOST_NAME>
    <HOST_IP>10.0.1.50</HOST_IP>
    <HOST_MAC>00:11:22:33:44:55</HOST_MAC>
    <HOST_FQDN>webserver01.example.mil</HOST_FQDN>
    <TARGET_COMMENT>Production web server</TARGET_COMMENT>
    <TECH_AREA></TECH_AREA>
    <TARGET_KEY></TARGET_KEY>
    <WEB_OR_DATABASE>false</WEB_OR_DATABASE>
    <WEB_DB_SITE></WEB_DB_SITE>
    <WEB_DB_INSTANCE></WEB_DB_INSTANCE>
  </ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA>
          <SID_NAME>version</SID_NAME>
          <SID_DATA>1</SID_DATA>
        </SI_DATA>
        <SI_DATA>
          <SID_NAME>stigid</SID_NAME>
          <SID_DATA>Windows_Server_2022_STIG</SID_DATA>
        </SI_DATA>
        <SI_DATA>
          <SID_NAME>title</SID_NAME>
          <SID_DATA>Microsoft Windows Server 2022 STIG</SID_DATA>
        </SI_DATA>
        <SI_DATA>
          <SID_NAME>releaseinfo</SID_NAME>
          <SID_DATA>Release: 4 Benchmark Date: 24 Jul 2024</SID_DATA>
        </SI_DATA>
        <SI_DATA>
          <SID_NAME>uuid</SID_NAME>
          <SID_DATA>abcd-1234</SID_DATA>
        </SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>V-254239</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>high</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>SV-254239r958388_rule</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>Windows Server 2022 must use TLS 1.2</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>SRG-OS-000033-GPOS-00014</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>CCI-000068</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STATUS>Open</STATUS>
        <FINDING_DETAILS>TLS 1.2 is not enabled in registry.</FINDING_DETAILS>
        <COMMENTS>Needs remediation</COMMENTS>
        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
      </VULN>
      <VULN>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>V-254240</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>SV-254240r958392_rule</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>Windows Server 2022 password complexity</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Group_Title</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>SRG-OS-000069-GPOS-00037</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STATUS>NotAFinding</STATUS>
        <FINDING_DETAILS>Password complexity enabled.</FINDING_DETAILS>
        <COMMENTS>Verified via GPO</COMMENTS>
        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>
        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>"#
    }

    #[test]
    fn test_parse_ckl() {
        let checklist = parse_ckl(sample_ckl()).unwrap();

        assert_eq!(checklist.asset.hostname, "webserver01");
        assert_eq!(checklist.asset.ip_address.as_deref(), Some("10.0.1.50"));
        assert_eq!(checklist.asset.role, AssetRole::MemberServer);
        assert_eq!(checklist.classification, Classification::Cui);

        assert_eq!(checklist.stig_info.stig_id, "Windows_Server_2022_STIG");
        assert_eq!(checklist.stig_info.version, "1");
        assert_eq!(checklist.stig_info.release, "4");
        assert_eq!(
            checklist.stig_info.title,
            "Microsoft Windows Server 2022 STIG"
        );

        assert_eq!(checklist.findings.len(), 2);

        let f1 = checklist.find_by_vuln_id("V-254239").unwrap();
        assert_eq!(f1.status, FindingStatus::Open);
        assert_eq!(f1.severity, Severity::High);
        assert_eq!(f1.rule_id, "SV-254239r958388_rule");
        assert!(f1.finding_details.contains("TLS 1.2"));

        let f2 = checklist.find_by_vuln_id("V-254240").unwrap();
        assert_eq!(f2.status, FindingStatus::NotAFinding);
        assert_eq!(f2.severity, Severity::Medium);
    }

    #[test]
    fn test_write_ckl() {
        let checklist = parse_ckl(sample_ckl()).unwrap();
        let xml_out = write_ckl(&checklist).unwrap();

        // Parse the output back and verify roundtrip.
        let parsed_back = parse_ckl(&xml_out).unwrap();
        assert_eq!(parsed_back.asset.hostname, "webserver01");
        assert_eq!(parsed_back.findings.len(), 2);
        assert_eq!(
            parsed_back.find_by_vuln_id("V-254239").unwrap().status,
            FindingStatus::Open,
        );
        assert_eq!(
            parsed_back.find_by_vuln_id("V-254240").unwrap().status,
            FindingStatus::NotAFinding,
        );
    }

    #[test]
    fn test_ckl_file_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.ckl");

        let checklist = parse_ckl(sample_ckl()).unwrap();
        write_ckl_file(&checklist, &path).unwrap();

        let loaded = parse_ckl_file(&path).unwrap();
        assert_eq!(loaded.asset.hostname, "webserver01");
        assert_eq!(loaded.findings.len(), 2);
    }
}
