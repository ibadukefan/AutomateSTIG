//! AutomateSTIG Core - Data models, rule evaluation, and STIG library management.
//!
//! This crate provides the foundational types and logic for the AutomateSTIG platform:
//! - STIG data models (benchmarks, rules, checks, findings)
//! - Checklist (CKL/CKLB) data structures
//! - Rule evaluation engine (fully deterministic)
//! - Answer file system
//! - STIG library management

pub mod models;
pub mod engine;
pub mod answer;
pub mod error;
pub mod library;

pub use error::{Error, Result};
