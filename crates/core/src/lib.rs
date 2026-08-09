//! AutomateSTIG Core - Data models, rule evaluation, and STIG library management.
//!
//! This crate provides the foundational types and logic for the AutomateSTIG platform:
//! - STIG data models (benchmarks, rules, checks, findings)
//! - Checklist (CKL/CKLB) data structures
//! - Rule evaluation engine (fully deterministic)
//! - Curated checks for NetApp ONTAP, FreeBSD/GPOS, and Cisco IOS-XE Router NDM
//! - Plan-bound SSH evidence collection for ONTAP and FreeBSD
//! - Answer file system
//! - STIG library management
//! - Curated and signed reviewed check-pack loading

pub mod answer;
pub mod check_packs;
pub mod checks;
pub mod coverage;
pub mod engine;
pub mod error;
pub mod inventory;
pub mod library;
pub mod library_content;
pub mod library_transaction;
pub mod models;
pub mod network_policy;
pub mod organization_policy;
pub mod path_safety;
pub mod remote;
pub mod scanner_benchmarks;
pub mod scanner_profiles;
pub mod target_adapters;
pub mod xccdf_results;

pub use error::{Error, Result};
