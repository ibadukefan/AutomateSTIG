//! Parsers for STIG-related file formats.
//!
//! Supports reading and writing:
//! - CKL (DISA STIG Viewer checklist format)
//! - CKLB (STIG Viewer 3.x JSON-based checklist)
//! - XCCDF (SCAP benchmark/results XML)
//! - Device configuration dumps

pub mod ckl;
pub mod cklb;
pub mod disa;
pub mod error;
pub mod evidence;
mod util;
pub mod xccdf;

pub use error::{ParseError, ParseResult};
