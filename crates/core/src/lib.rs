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

pub mod models;
pub mod engine;
pub mod answer;
pub mod error;
pub mod library;
pub mod checks;
pub mod remote;
pub mod agent;
pub mod plugins;
pub mod converter;

pub use error::{Error, Result};
