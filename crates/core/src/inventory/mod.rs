//! Asset inventory and credential management.
//!
//! Persistent store of managed assets with:
//! - Encrypted credential vault (SSH keys, passwords, tokens, certificates)
//! - STIG assignments per asset
//! - Evaluation schedules
//! - Tags and groups for organization

pub mod assets;
pub mod credentials;
pub mod scheduler;
