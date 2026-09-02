//! Copy-on-Write (CoW) snapshot remediation subsystem.
//!
//! Provides automated preventive snapshots and instantaneous rollback capabilities
//! on modern Linux filesystems supporting subvolume snapshots (Btrfs and OpenZFS).

use std::path::Path;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{error, info, warn};

/// Supported Copy-on-Write filesystems for snapshot-based remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CowFilesystem {
    /// B-tree File System (Btrfs)
    Btrfs,
    /// Zettabyte File System (OpenZFS)
    Zfs,
    /// Standard or legacy filesystem without native CoW subvolume snapshots (e.g. ext4, XFS)
    Unsupported,
}

/// Determines the filesystem type hosting the given path by inspecting `stat -f`
/// and `/proc/mounts`.
pub fn detect_filesystem(path: &str) -> Result<CowFilesystem> {
    // Primary detection: stat -f --format=%T
    if let Ok(output) = std::process::Command::new("stat")
        .args(["-f", "--format=%T", path])
        .output()
    {
        if output.status.success() {
            let fstype = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
            if fstype.contains("btrfs") {
                return Ok(CowFilesystem::Btrfs);
            } else if fstype.contains("zfs") {
                return Ok(CowFilesystem::Zfs);
            }
        }
    }

    // Fallback detection: parse /proc/mounts to find closest mountpoint prefix
    if let Ok(mounts_content) = std::fs::read_to_string("/proc/mounts") {
        let target_path = std::fs::canonicalize(path).unwrap_or_else(|_| std::path::PathBuf::from(path));
        let target_str = target_path.to_string_lossy();
        let mut best_match: Option<(usize, CowFilesystem)> = None;

        for line in mounts_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let mount_point = parts[1];
                let fstype = parts[2].to_lowercase();

                if target_str.starts_with(mount_point) {
                    let match_len = mount_point.len();
                    let fs = match fstype.as_str() {
                        "btrfs" => CowFilesystem::Btrfs,
                        "zfs" => CowFilesystem::Zfs,
                        _ => CowFilesystem::Unsupported,
                    };

                    if let Some((best_len, _)) = best_match {
                        if match_len > best_len {
                            best_match = Some((match_len, fs));
                        }
                    } else {
                        best_match = Some((match_len, fs));
                    }
                }
            }
        }

        if let Some((_, fs)) = best_match {
            return Ok(fs);
        }
    }

    Ok(CowFilesystem::Unsupported)
}

/// Creates a preventive, read-only CoW snapshot of the specified path.
///
/// Returns the unique snapshot identifier path or URI.
pub async fn create_preventive_snapshot(path: &str) -> Result<String> {
    let fs = detect_filesystem(path)?;
    let timestamp = Utc::now().to_rfc3339();

    match fs {
        CowFilesystem::Btrfs => {
            let snapshots_dir = Path::new(path).join(".snapshots");
            if !snapshots_dir.exists() {
                tokio::fs::create_dir_all(&snapshots_dir)
                    .await
                    .with_context(|| format!("Failed to create snapshot directory {:?}", snapshots_dir))?;
            }

            let snapshot_name = format!("ransomware-guard-{}", timestamp);
            let snapshot_path = snapshots_dir.join(&snapshot_name);
            let snapshot_path_str = snapshot_path.to_string_lossy().into_owned();

            info!(
                "Creating read-only Btrfs snapshot of '{}' at '{}'",
                path, snapshot_path_str
            );

            let output = Command::new("btrfs")
                .args(["subvolume", "snapshot", "-r", path, &snapshot_path_str])
                .output()
                .await
                .with_context(|| {
                    format!(
                        "Failed to execute 'btrfs subvolume snapshot -r {} {}'",
                        path, snapshot_path_str
                    )
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("Btrfs snapshot creation failed: {}", stderr.trim());
                anyhow::bail!("Btrfs snapshot failed: {}", stderr.trim());
            }

            info!("Btrfs snapshot successfully created: {}", snapshot_path_str);
            Ok(snapshot_path_str)
        }
        CowFilesystem::Zfs => {
            let snapshot_id = format!("{}@ransomware-guard-{}", path, timestamp);
            info!("Creating ZFS snapshot '{}'", snapshot_id);

            let output = Command::new("zfs")
                .args(["snapshot", &snapshot_id])
                .output()
                .await
                .with_context(|| format!("Failed to execute 'zfs snapshot {}'", snapshot_id))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("ZFS snapshot creation failed: {}", stderr.trim());
                anyhow::bail!("ZFS snapshot failed: {}", stderr.trim());
            }

            info!("ZFS snapshot successfully created: {}", snapshot_id);
            Ok(snapshot_id)
        }
        CowFilesystem::Unsupported => {
            warn!("Path '{}' does not reside on a CoW filesystem (Btrfs/ZFS)", path);
            anyhow::bail!("Unsupported filesystem for CoW snapshots at path '{}'", path)
        }
    }
}

/// Restores files or rolls back the filesystem to the given snapshot state.
///
/// Returns a descriptive status message upon successful completion.
pub async fn restore_snapshot(snapshot_id: &str, filesystem: &CowFilesystem) -> Result<String> {
    match filesystem {
        CowFilesystem::Btrfs => {
            info!("Restoring Btrfs snapshot from '{}'", snapshot_id);
            let restored_target = format!("{}-restored", snapshot_id);

            let output = Command::new("btrfs")
                .args(["subvolume", "snapshot", snapshot_id, &restored_target])
                .output()
                .await
                .with_context(|| {
                    format!(
                        "Failed to execute 'btrfs subvolume snapshot {} {}'",
                        snapshot_id, restored_target
                    )
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("Btrfs snapshot restoration failed: {}", stderr.trim());
                anyhow::bail!("Btrfs snapshot restoration failed: {}", stderr.trim());
            }

            let status = format!(
                "Btrfs snapshot '{}' restored successfully to '{}'",
                snapshot_id, restored_target
            );
            info!("{}", status);
            Ok(status)
        }
        CowFilesystem::Zfs => {
            info!("Rolling back ZFS snapshot '{}'", snapshot_id);

            let output = Command::new("zfs")
                .args(["rollback", "-r", snapshot_id])
                .output()
                .await
                .with_context(|| format!("Failed to execute 'zfs rollback -r {}'", snapshot_id))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                error!("ZFS rollback failed: {}", stderr.trim());
                anyhow::bail!("ZFS rollback failed: {}", stderr.trim());
            }

            let status = format!("ZFS snapshot '{}' rolled back successfully", snapshot_id);
            info!("{}", status);
            Ok(status)
        }
        CowFilesystem::Unsupported => {
            anyhow::bail!("Cannot restore snapshot: unsupported filesystem")
        }
    }
}

/// Lists available preventive snapshots for the given target path.
pub async fn list_snapshots(path: &str) -> Result<Vec<String>> {
    let fs = detect_filesystem(path)?;
    let mut snapshots = Vec::new();

    match fs {
        CowFilesystem::Btrfs => {
            let snapshots_dir = Path::new(path).join(".snapshots");
            if snapshots_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&snapshots_dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if name.starts_with("ransomware-guard-") {
                            snapshots.push(entry.path().to_string_lossy().into_owned());
                        }
                    }
                }
            }

            if let Ok(output) = Command::new("btrfs")
                .args(["subvolume", "list", "-o", path])
                .output()
                .await
            {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if line.contains("ransomware-guard-") {
                            if let Some(pos) = line.find("path ") {
                                let subvol_rel = line[pos + 5..].trim();
                                let full_path = format!("{}/{}", path, subvol_rel);
                                if !snapshots.contains(&full_path) {
                                    snapshots.push(full_path);
                                }
                            }
                        }
                    }
                }
            }
        }
        CowFilesystem::Zfs => {
            let output = Command::new("zfs")
                .args(["list", "-t", "snapshot", "-o", "name", "-H"])
                .output()
                .await
                .with_context(|| "Failed to execute 'zfs list -t snapshot'")?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.contains("ransomware-guard-") && (path.is_empty() || trimmed.starts_with(path)) {
                        snapshots.push(trimmed.to_string());
                    }
                }
            }
        }
        CowFilesystem::Unsupported => {}
    }

    snapshots.sort();
    Ok(snapshots)
}
