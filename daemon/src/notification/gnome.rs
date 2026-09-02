//! GNOME desktop notification integration.
//!
//! Emits critical visual alerts to active GNOME user sessions directly from
//! the root daemon by discovering user D-Bus session sockets under `/run/user/<UID>/bus`
//! and dispatching notifications with critical urgency.

use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use notify_rust::{Notification, Urgency};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

/// Structured information describing an identified ransomware threat event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    /// PID of the offending process.
    pub pid: u32,
    /// Absolute filesystem path of the offending binary.
    pub exe_path: String,
    /// Calculated Shannon entropy value of written data (0.0 to 8.0).
    pub entropy: f64,
    /// List of file paths modified, renamed, or encrypted by the process.
    pub affected_files: Vec<String>,
    /// Security action performed by the defense subsystem (e.g. "SIGSTOP + SIGKILL").
    pub action_taken: String,
    /// Status message from CoW snapshot restoration, if available.
    pub cow_status: Option<String>,
}

/// Discovers active GNOME desktop sessions and broadcasts a critical desktop
/// alert to all logged-in interactive users.
///
/// If no active sessions can be found or if dispatch fails across all sessions,
/// it falls back to [`send_fallback_notification`].
pub async fn send_critical_alert(threat: &ThreatInfo) -> Result<()> {
    let sessions = discover_user_sessions();
    let summary = "🚨 Amenaza de Ransomware Detectada";
    let body = format_notification_body(threat);

    if sessions.is_empty() {
        warn!("No active user sessions discovered in /run/user/; falling back to direct notification");
        return send_fallback_notification(threat);
    }

    let mut delivered_count = 0;

    for (uid, bus_path) in &sessions {
        match send_notification_to_session(*uid, bus_path, summary, &body).await {
            Ok(_) => {
                info!(
                    "Dispatched critical threat alert to UID {} via session bus {:?}",
                    uid, bus_path
                );
                delivered_count += 1;
            }
            Err(err) => {
                warn!(
                    "Failed to dispatch alert to UID {} on bus {:?}: {:#}",
                    uid, bus_path, err
                );
            }
        }
    }

    if delivered_count == 0 {
        warn!("Failed to deliver notification to any user session; attempting fallback");
        send_fallback_notification(threat)?;
    }

    Ok(())
}

/// Dispatches a notification using `notify_rust::Notification` with critical urgency.
///
/// This serves as a synchronous fallback when direct session spawning is unavailable.
pub fn send_fallback_notification(threat: &ThreatInfo) -> Result<()> {
    let summary = "🚨 Amenaza de Ransomware Detectada";
    let body = format_notification_body(threat);

    Notification::new()
        .appname("ransomware-detector")
        .summary(summary)
        .body(&body)
        .icon("dialog-warning")
        .urgency(Urgency::Critical)
        .show()
        .context("Failed to show fallback desktop notification")?;

    info!("Fallback notification successfully emitted via notify-rust");
    Ok(())
}

/// Scans `/run/user/` for active user session D-Bus sockets belonging to interactive
/// users (UID >= 1000).
///
/// Returns a vector of `(uid, bus_path)` tuples.
fn discover_user_sessions() -> Vec<(u32, PathBuf)> {
    let run_user = Path::new("/run/user");
    let mut sessions = Vec::new();

    let entries = match std::fs::read_dir(run_user) {
        Ok(entries) => entries,
        Err(err) => {
            warn!("Could not read directory /run/user: {:#}", err);
            return sessions;
        }
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if let Ok(uid) = name_str.parse::<u32>() {
            // Interactive users on standard Linux systems have UID >= 1000
            if uid >= 1000 {
                let bus_path = entry.path().join("bus");
                if bus_path.exists() {
                    sessions.push((uid, bus_path));
                }
            }
        }
    }

    sessions
}

/// Sends a desktop notification to a specific user session by executing `notify-send`
/// configured with that user's session bus address and environment.
///
/// # Pure Rust (zbus) Alternative:
/// ```rust,no_run
/// // For environments where spawning `notify-send` is undesirable, zbus can be used:
/// async fn send_via_zbus(bus_path: &std::path::Path, summary: &str, body: &str) -> anyhow::Result<()> {
///     let address: zbus::Address = format!("unix:path={}", bus_path.display()).try_into()?;
///     let connection = zbus::ConnectionBuilder::address(address)?.build().await?;
///     let mut hints = std::collections::HashMap::new();
///     hints.insert("urgency", zbus::zvariant::Value::U8(2)); // Urgency::Critical = 2
///     connection.call_method(
///         Some("org.freedesktop.Notifications"),
///         "/org/freedesktop/Notifications",
///         Some("org.freedesktop.Notifications"),
///         "Notify",
///         &("ransomware-detector", 0u32, "dialog-warning", summary, body, &[] as &[&str], hints, 0i32),
///     ).await?;
///     Ok(())
/// }
/// ```
async fn send_notification_to_session(
    uid: u32,
    bus_path: &Path,
    summary: &str,
    body: &str,
) -> Result<()> {
    let bus_addr = format!("unix:path={}", bus_path.display());
    let runtime_dir = format!("/run/user/{}", uid);

    use std::os::unix::process::CommandExt;

    let output = Command::new("notify-send")
        .uid(uid) // Drop from root to the actual user so DBus authenticates us
        .env("DBUS_SESSION_BUS_ADDRESS", &bus_addr)
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env("DISPLAY", ":0") // Usually required by notify-send under X11/XWayland
        .arg("--urgency=critical")
        .arg("--icon=dialog-warning")
        .arg("--app-name=sentinel")
        .arg(summary)
        .arg(body)
        .output()
        .await
        .with_context(|| format!("Failed to spawn notify-send for UID {}", uid))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "notify-send failed with exit code {:?}: {}",
            output.status.code(),
            stderr.trim()
        );
    }

    Ok(())
}

/// Helper to render structured threat information into a clean, human-readable
/// notification body.
fn format_notification_body(threat: &ThreatInfo) -> String {
    let files_summary = if threat.affected_files.is_empty() {
        "Ninguno detectado".to_string()
    } else {
        let displayed_files: Vec<&str> = threat
            .affected_files
            .iter()
            .take(5)
            .map(|s| s.as_str())
            .collect();
        let mut list = displayed_files.join("\n• ");
        list = format!("• {}", list);
        if threat.affected_files.len() > 5 {
            let remaining = threat.affected_files.len() - 5;
            list.push_str(&format!("\n... y {} archivo(s) más", remaining));
        }
        list
    };

    format!(
        "<b>Ejecutable:</b> {}\n\
         <b>PID:</b> {}\n\
         <b>Entropía de Shannon:</b> {:.2}\n\
         <b>Acción ejecutada:</b> {}\n\
         <b>Restauración CoW:</b> {}\n\
         <b>Archivos afectados:</b>\n{}",
        threat.exe_path,
        threat.pid,
        threat.entropy,
        threat.action_taken,
        threat.cow_status.as_deref().unwrap_or("N/A"),
        files_summary
    )
}
