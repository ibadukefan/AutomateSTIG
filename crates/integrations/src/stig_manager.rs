//! Versioned STIG Manager scanner integration.
//!
//! This module intentionally exposes only the read-side discovery contract,
//! sparse scanner-review mapping, selected-run handoff support, and exact
//! remote no-op verification used by the scanner workflow. Asset management,
//! assignment management, portfolio export, and general assessment import are
//! owned by STIG Manager and are not part of AutomateSTIG's product surface.

mod client;
mod config;

pub use client::*;
pub use config::StigManagerConfig;
