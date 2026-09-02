//! Structured forensic logging subsystem for security auditing.
//!
//! Captures detailed forensic threat telemetry to `/var/log/ransomware-detector/alerts.log`
//! in JSON format with daily rotation, alongside structured console logging.

use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use chrono::{Local, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Structured forensic event representing a detected ransomware incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    /// Local timestamp in ISO 8601 format.
    pub timestamp: String,
    /// UTC timestamp in ISO 8601 format.
    pub timestamp_utc: String,
    /// Process ID of the malicious actor.
    pub pid: u32,
    /// Real User ID associated with the offending process.
    pub uid: u32,
    /// Real Group ID associated with the offending process.
    pub gid: u32,
    /// Executable path on disk.
    pub exe_path: String,
    /// Full command-line invocation.
    pub cmdline: String,
    /// Calculated Shannon entropy (0.0 to 8.0).
    pub entropy: f64,
    /// Heuristic or eBPF rule that triggered the detection.
    pub rule_triggered: String,
    /// List of file paths modified, encrypted, or renamed by the process.
    pub affected_files: Vec<String>,
    /// Defense mitigation action executed (e.g., "SIGSTOP + SIGKILL").
    pub action_taken: String,
}

impl ThreatEvent {
    /// Constructs a new [`ThreatEvent`] with current local and UTC timestamps.
    pub fn new(
        pid: u32,
        uid: u32,
        gid: u32,
        exe_path: impl Into<String>,
        cmdline: impl Into<String>,
        entropy: f64,
        rule_triggered: impl Into<String>,
        affected_files: Vec<String>,
        action_taken: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Local::now().to_rfc3339(),
            timestamp_utc: Utc::now().to_rfc3339(),
            pid,
            uid,
            gid,
            exe_path: exe_path.into(),
            cmdline: cmdline.into(),
            entropy,
            rule_triggered: rule_triggered.into(),
            affected_files,
            action_taken: action_taken.into(),
        }
    }
}

/// Initializes the global tracing subscriber with dual layers:
/// 1. A JSON-formatted daily rolling file logger writing to `/var/log/ransomware-detector/alerts.log`
/// 2. A human-readable diagnostic logger writing to `stderr`.
///
/// Returns the [`WorkerGuard`] which must be retained in memory for the lifetime
/// of the daemon to ensure asynchronous log flushes are not dropped on shutdown.
pub fn init_logging() -> Result<WorkerGuard> {
    let primary_log_dir = Path::new("/var/log/ransomware-detector");

    // Attempt to ensure the primary log directory exists, with fallback to ./logs
    // for non-root test environments.
    let log_dir: PathBuf = if fs::create_dir_all(primary_log_dir).is_ok() {
        primary_log_dir.to_path_buf()
    } else {
        let fallback = PathBuf::from("./logs");
        fs::create_dir_all(&fallback).with_context(|| {
            format!(
                "Failed to create primary log dir {:?} and fallback log dir {:?}",
                primary_log_dir, fallback
            )
        })?;
        fallback
    };

    let file_appender = RollingFileAppender::new(Rotation::DAILY, &log_dir, "alerts.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Layer 1: JSON formatted audit log
    let file_layer = fmt::layer()
        .json()
        .with_target(true)
        .with_thread_ids(true)
        .with_writer(non_blocking);

    // Layer 2: Human-readable stderr log
    let stderr_layer = fmt::layer()
        .with_target(true)
        .with_writer(std::io::stderr);

    // Filter configuration, defaulting to info
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(stderr_layer)
        .try_init()
        .map_err(|err| anyhow::anyhow!("Failed to initialize tracing subscriber: {}", err))?;

    debug!("Initialized structured logging into {:?}", log_dir);
    Ok(guard)
}

/// Logs a structured threat event to the audit pipeline.
///
/// Serializes the event to JSON and emits a `tracing::error!` event targeting
/// `"ransomware_alert"` with structured fields for high-priority SIEM integration.
pub fn log_threat_event(event: &ThreatEvent) {
    let json_message = serde_json::to_string(event)
        .unwrap_or_else(|e| format!(r#"{{"serialization_error": "{}"}}"#, e));

    error!(
        target: "ransomware_alert",
        pid = event.pid,
        uid = event.uid,
        gid = event.gid,
        exe = %event.exe_path,
        cmdline = %event.cmdline,
        entropy = event.entropy,
        rule = %event.rule_triggered,
        action = %event.action_taken,
        affected_files = ?event.affected_files,
        "{}",
        json_message
    );
}

/// Emits a debug-level log for granular I/O monitoring and tracing.
///
/// Filtered dynamically via `RUST_LOG` environment variable (e.g. `RUST_LOG=debug`).
pub fn log_io_event_debug(pid: u32, path: &str, event_type: &str, entropy: f64) {
    debug!(
        target: "ransomware_io_debug",
        pid = pid,
        path = %path,
        event_type = %event_type,
        entropy = entropy,
        "I/O event monitored: pid={} path='{}' type='{}' entropy={:.2}",
        pid,
        path,
        event_type,
        entropy
    );
}
