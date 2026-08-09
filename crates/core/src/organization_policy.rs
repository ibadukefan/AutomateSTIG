//! Signed, asset-bound organization parameters for checks whose thresholds are
//! intentionally left to local policy by DISA.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use regex::Regex;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

const SCHEMA: &str = "automatestig-organization-policy/v1";
const IOS_XE_STIG: &str = "Cisco_IOS-XE_Router_NDM_STIG";
const IOS_XE_RELEASE: &str = "V3R7";
const MAX_POLICY_BYTES: usize = 64 * 1024;

/// JSON value decoder that rejects duplicate member names at every depth.
///
/// `serde_json` otherwise keeps the final duplicate, while a policy author or
/// another verifier could interpret the first. Signed security parameters must
/// have exactly one representation.
struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UniqueValueVisitor;

        impl<'de> Visitor<'de> for UniqueValueVisitor {
            type Value = UniqueJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object member names")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(UniqueJsonValue)
                    .ok_or_else(|| de::Error::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::String(value.to_string())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueJsonValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                UniqueJsonValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueJsonValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some(key) = object.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom(format!(
                            "duplicate JSON member name: {key}"
                        )));
                    }
                    values.insert(key, object.next_value::<UniqueJsonValue>()?.0);
                }
                Ok(UniqueJsonValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationPolicyDocument {
    pub schema: String,
    pub policy_id: String,
    pub policy_version: String,
    pub stig_id: String,
    pub stig_release: String,
    pub asset_hostname: String,
    pub effective_from: String,
    pub expires_at: String,
    pub rules: CiscoIosNdmRules,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiscoIosNdmRules {
    #[serde(rename = "V-215807")]
    pub concurrent_management_sessions: ConcurrentManagementSessions,
    #[serde(rename = "V-215838")]
    pub authoritative_ntp_sources: AuthoritativeNtpSources,
    #[serde(rename = "V-215836")]
    pub logging_buffer_capacity: LoggingBufferCapacity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcurrentManagementSessions {
    pub max_concurrent_management_sessions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingBufferCapacity {
    pub minimum_logging_buffer_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeNtpSources {
    pub approved_authoritative_ntp_sources: Vec<String>,
}

/// A policy whose exact bytes passed this module's Ed25519 trust check.
/// This type is deliberately excluded from `SystemData` serde so an evidence
/// transcript cannot self-assert trusted policy state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOrganizationPolicy {
    document: OrganizationPolicyDocument,
    sha256: String,
    signer_fingerprint: String,
}

impl VerifiedOrganizationPolicy {
    /// Verify the exact policy bytes against the supplied trusted Ed25519 keys,
    /// then parse and bind the policy to the evaluation context.
    ///
    /// Organization-policy signatures use the same hash-then-Ed25519 format as
    /// signed STIG content: Ed25519 signs the SHA-256 digest of `raw`.
    pub fn verify_and_parse(
        raw: &[u8],
        signature: &[u8],
        trusted_public_keys: &[[u8; 32]],
        expected_stig_id: &str,
        expected_stig_release: &str,
        expected_hostname: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, String> {
        validate_policy_size(raw)?;
        if signature.len() != 64 {
            return Err("organization policy signature must contain exactly 64 bytes".to_string());
        }
        let signature = Signature::from_slice(signature)
            .map_err(|error| format!("organization policy signature is invalid: {error}"))?;
        let digest = Sha256::digest(raw);
        let signer_public_key = trusted_public_keys
            .iter()
            .find(|public_key| {
                VerifyingKey::from_bytes(public_key)
                    .and_then(|key| key.verify(&digest, &signature))
                    .is_ok()
            })
            .ok_or_else(|| "organization-policy signature is not trusted".to_string())?;
        let document = parse_and_validate(
            raw,
            expected_stig_id,
            expected_stig_release,
            expected_hostname,
            now,
        )?;
        Ok(Self {
            document,
            sha256: format!("{digest:x}"),
            signer_fingerprint: format!("SHA256:{:x}", Sha256::digest(signer_public_key)),
        })
    }

    pub fn document(&self) -> &OrganizationPolicyDocument {
        &self.document
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn signer_fingerprint(&self) -> &str {
        &self.signer_fingerprint
    }
}

impl OrganizationPolicyDocument {
    /// Validate an unsigned policy before an offline signing ceremony.
    ///
    /// This deliberately returns no `VerifiedOrganizationPolicy`; only
    /// `VerifiedOrganizationPolicy::verify_and_parse` can construct that type.
    pub fn validate_for_signing(raw: &[u8], now: DateTime<Utc>) -> Result<(), String> {
        let document = parse_policy_document(raw)?;
        document.validate(IOS_XE_STIG, IOS_XE_RELEASE, &document.asset_hostname, now)
    }

    fn validate(
        &self,
        expected_stig_id: &str,
        expected_stig_release: &str,
        expected_hostname: &str,
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        let identifier = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
            .expect("static policy identifier regex");
        if self.schema != SCHEMA {
            return Err(format!("organization policy schema must be {SCHEMA}"));
        }
        if !identifier.is_match(&self.policy_id) || !identifier.is_match(&self.policy_version) {
            return Err("organization policy id or version is invalid".to_string());
        }
        if expected_stig_id != IOS_XE_STIG
            || expected_stig_release != IOS_XE_RELEASE
            || self.stig_id != expected_stig_id
            || self.stig_release != expected_stig_release
        {
            return Err(
                "organization policy STIG identity does not match the evaluation".to_string(),
            );
        }
        let hostname = self.asset_hostname.trim();
        if hostname.is_empty()
            || hostname.len() > 255
            || !hostname.eq_ignore_ascii_case(expected_hostname.trim())
        {
            return Err(
                "organization policy hostname does not match the configuration".to_string(),
            );
        }
        let effective = DateTime::parse_from_rfc3339(&self.effective_from)
            .map_err(|_| "organization policy effective_from must be RFC 3339".to_string())?
            .with_timezone(&Utc);
        let expires = DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|_| "organization policy expires_at must be RFC 3339".to_string())?
            .with_timezone(&Utc);
        if effective > now || expires <= now || expires <= effective {
            return Err("organization policy is not currently effective".to_string());
        }
        let sessions = self
            .rules
            .concurrent_management_sessions
            .max_concurrent_management_sessions;
        if !(1..=65_535).contains(&sessions) {
            return Err(
                "V-215807 max_concurrent_management_sessions must be 1..=65535".to_string(),
            );
        }
        let buffer = self
            .rules
            .logging_buffer_capacity
            .minimum_logging_buffer_bytes;
        if !(4_096..=2_147_483_647).contains(&buffer) {
            return Err(
                "V-215836 minimum_logging_buffer_bytes must be 4096..=2147483647".to_string(),
            );
        }
        let ntp_sources = &self
            .rules
            .authoritative_ntp_sources
            .approved_authoritative_ntp_sources;
        if !(2..=64).contains(&ntp_sources.len()) {
            return Err(
                "V-215838 approved_authoritative_ntp_sources must contain 2..=64 entries"
                    .to_string(),
            );
        }
        let endpoint =
            Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$").expect("static NTP endpoint regex");
        let mut normalized = std::collections::HashSet::new();
        if ntp_sources.iter().any(|source| {
            !endpoint.is_match(source) || !normalized.insert(source.to_ascii_lowercase())
        }) {
            return Err(
                "V-215838 approved_authoritative_ntp_sources entries must be unique valid host/IP tokens"
                    .to_string(),
            );
        }
        Ok(())
    }
}

fn validate_policy_size(raw: &[u8]) -> Result<(), String> {
    if raw.is_empty() || raw.len() > MAX_POLICY_BYTES {
        return Err(format!(
            "organization policy must be 1..={MAX_POLICY_BYTES} bytes"
        ));
    }
    Ok(())
}

fn parse_policy_document(raw: &[u8]) -> Result<OrganizationPolicyDocument, String> {
    validate_policy_size(raw)?;
    let unique: UniqueJsonValue = serde_json::from_slice(raw)
        .map_err(|error| format!("organization policy is invalid JSON: {error}"))?;
    serde_json::from_value(unique.0)
        .map_err(|error| format!("organization policy is invalid JSON: {error}"))
}

fn parse_and_validate(
    raw: &[u8],
    expected_stig_id: &str,
    expected_stig_release: &str,
    expected_hostname: &str,
    now: DateTime<Utc>,
) -> Result<OrganizationPolicyDocument, String> {
    let document = parse_policy_document(raw)?;
    document.validate(
        expected_stig_id,
        expected_stig_release,
        expected_hostname,
        now,
    )?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::{Signer, SigningKey};

    fn document() -> OrganizationPolicyDocument {
        OrganizationPolicyDocument {
            schema: SCHEMA.to_string(),
            policy_id: "example-iosxe-ndm".to_string(),
            policy_version: "1".to_string(),
            stig_id: IOS_XE_STIG.to_string(),
            stig_release: IOS_XE_RELEASE.to_string(),
            asset_hostname: "router-01".to_string(),
            effective_from: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            rules: CiscoIosNdmRules {
                concurrent_management_sessions: ConcurrentManagementSessions {
                    max_concurrent_management_sessions: 2,
                },
                logging_buffer_capacity: LoggingBufferCapacity {
                    minimum_logging_buffer_bytes: 4_096_000,
                },
                authoritative_ntp_sources: AuthoritativeNtpSources {
                    approved_authoritative_ntp_sources: vec![
                        "192.0.2.10".to_string(),
                        "192.0.2.11".to_string(),
                    ],
                },
            },
        }
    }

    fn sign_policy(raw: &[u8], seed: u8) -> ([u8; 32], Vec<u8>) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let signature = signing_key.sign(&Sha256::digest(raw));
        (
            signing_key.verifying_key().to_bytes(),
            signature.to_bytes().to_vec(),
        )
    }

    #[test]
    fn exact_policy_is_asset_release_time_and_signer_bound() {
        let raw = serde_json::to_vec(&document()).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap();
        let (public_key, signature) = sign_policy(&raw, 7);
        let verified = VerifiedOrganizationPolicy::verify_and_parse(
            &raw,
            &signature,
            &[public_key],
            IOS_XE_STIG,
            IOS_XE_RELEASE,
            "ROUTER-01",
            now,
        )
        .unwrap();
        assert_eq!(
            verified
                .document()
                .rules
                .concurrent_management_sessions
                .max_concurrent_management_sessions,
            2
        );
        assert_eq!(
            verified.signer_fingerprint(),
            format!("SHA256:{:x}", Sha256::digest(public_key))
        );
        for (hostname, expires, buffer) in [
            ("other-router", "2027-01-01T00:00:00Z", 4_096_000),
            ("router-01", "2026-01-01T00:00:01Z", 4_096_000),
            ("router-01", "2027-01-01T00:00:00Z", 1),
        ] {
            let mut invalid = document();
            invalid.asset_hostname = hostname.to_string();
            invalid.expires_at = expires.to_string();
            invalid
                .rules
                .logging_buffer_capacity
                .minimum_logging_buffer_bytes = buffer;
            let raw = serde_json::to_vec(&invalid).unwrap();
            let (public_key, signature) = sign_policy(&raw, 7);
            assert!(VerifiedOrganizationPolicy::verify_and_parse(
                &raw,
                &signature,
                &[public_key],
                IOS_XE_STIG,
                IOS_XE_RELEASE,
                "router-01",
                now,
            )
            .is_err());
        }
    }

    #[test]
    fn duplicate_policy_members_are_rejected_at_every_depth() {
        let now = Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap();
        for raw in [
            br#"{"schema":"automatestig-organization-policy/v1","schema":"automatestig-organization-policy/v1"}"#.as_slice(),
            br#"{"schema":"automatestig-organization-policy/v1","policy_id":"p","policy_version":"1","stig_id":"Cisco_IOS-XE_Router_NDM_STIG","stig_release":"V3R7","asset_hostname":"router-01","effective_from":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","rules":{"V-215807":{"max_concurrent_management_sessions":2,"max_concurrent_management_sessions":3},"V-215836":{"minimum_logging_buffer_bytes":4096000}}}"#.as_slice(),
        ] {
            let (public_key, signature) = sign_policy(raw, 7);
            let error = VerifiedOrganizationPolicy::verify_and_parse(
                raw,
                &signature,
                &[public_key],
                IOS_XE_STIG,
                IOS_XE_RELEASE,
                "router-01",
                now,
            )
            .unwrap_err();
            assert!(error.contains("duplicate JSON member name"), "{error}");
        }
    }

    #[test]
    fn verified_policy_cannot_be_constructed_without_a_matching_signature() {
        let raw = serde_json::to_vec(&document()).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap();
        let (public_key, signature) = sign_policy(&raw, 7);
        let (wrong_public_key, _) = sign_policy(&raw, 8);

        for (candidate_raw, candidate_signature, trusted_keys) in [
            (raw.as_slice(), signature.as_slice(), [].as_slice()),
            (
                raw.as_slice(),
                signature.as_slice(),
                std::slice::from_ref(&wrong_public_key),
            ),
            (
                raw.as_slice(),
                [0_u8; 64].as_slice(),
                std::slice::from_ref(&public_key),
            ),
        ] {
            assert!(VerifiedOrganizationPolicy::verify_and_parse(
                candidate_raw,
                candidate_signature,
                trusted_keys,
                IOS_XE_STIG,
                IOS_XE_RELEASE,
                "router-01",
                now,
            )
            .is_err());
        }

        let mut altered = raw;
        altered.push(b' ');
        assert!(VerifiedOrganizationPolicy::verify_and_parse(
            &altered,
            &signature,
            &[public_key],
            IOS_XE_STIG,
            IOS_XE_RELEASE,
            "router-01",
            now,
        )
        .is_err());
    }

    #[test]
    fn signing_validation_never_constructs_verified_policy() {
        let raw = serde_json::to_vec(&document()).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap();
        OrganizationPolicyDocument::validate_for_signing(&raw, now).unwrap();
    }

    #[test]
    fn authoritative_ntp_source_policy_is_bounded_unique_and_token_safe() {
        let now = Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap();
        for sources in [
            vec!["192.0.2.10".to_string()],
            vec!["NTP.EXAMPLE.MIL".to_string(), "ntp.example.mil".to_string()],
            vec!["192.0.2.10".to_string(), "bad source".to_string()],
        ] {
            let mut invalid = document();
            invalid
                .rules
                .authoritative_ntp_sources
                .approved_authoritative_ntp_sources = sources;
            let raw = serde_json::to_vec(&invalid).unwrap();
            let (public_key, signature) = sign_policy(&raw, 7);
            assert!(VerifiedOrganizationPolicy::verify_and_parse(
                &raw,
                &signature,
                &[public_key],
                IOS_XE_STIG,
                IOS_XE_RELEASE,
                "router-01",
                now,
            )
            .is_err());
        }
    }
}
