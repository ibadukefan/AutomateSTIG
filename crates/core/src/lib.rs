//! AutomateSTIG Core - Data models, rule evaluation, and STIG library management.
//!
//! This crate provides the foundational types and logic for the AutomateSTIG platform:
//! - STIG data models (benchmarks, rules, checks, findings)
//! - Checklist (CKL/CKLB) data structures
//! - Rule evaluation engine (fully deterministic)
//! - Automated check system (Windows, Linux, network)
//! - Remote data collection framework
//! - Answer file system
//! - STIG library management
//! - Agent mode with drift detection
//! - Plugin system for extensibility

pub mod agent;
pub mod answer;
pub mod checks;
pub mod converter;
pub mod coverage;
pub mod engine;
pub mod error;
pub mod inventory;
pub mod library;
pub mod models;
pub mod path_safety;
pub mod plugins;
pub mod remote;

pub use error::{Error, Result};
