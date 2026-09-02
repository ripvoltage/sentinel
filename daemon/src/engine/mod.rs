//! Detection engine for the ransomware daemon.
//!
//! Submodules:
//! - [`entropy`]: Shannon entropy calculations and threshold checks.
//! - [`heuristics`]: Behavioral evaluation of process I/O rates, suspicious extensions, and deletions.
//! - [`canaries`]: Canary (honeypot) sentinel file deployment and detection.

pub mod canaries;
pub mod entropy;
pub mod heuristics;
