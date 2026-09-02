//! Canary (honeypot) sentinel file management.
//!
//! Deploys realistic decoy files into designated user directories. Any write, rename,
//! or deletion event on these sentinel paths serves as an immediate high-fidelity indicator
//! of ransomware activity.

use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Directory name used for placing honeypot canary files.
pub const CANARY_DIR_NAME: &str = ".canary_sentinel";

/// Representative decoy file names deployed inside canary directories.
const CANARY_FILES: [&str; 6] = [
    "important_document.docx",
    "financial_report.xlsx",
    "family_photos.zip",
    "passwords.txt",
    "bitcoin_wallet.dat",
    "tax_return_2024.pdf",
];

/// Returns realistic synthetic content for a given canary file name.
fn get_canary_content(filename: &str) -> &'static [u8] {
    match filename {
        "important_document.docx" => {
            b"[SENTINEL_CANARY_DOCX_HEADER]\r\n\
              CONFIDENTIAL CORPORATE STRATEGY & MERGER TARGETS 2024-2026\r\n\
              DO NOT DISTRIBUTE - INTERNAL ONLY\r\n\
              Section 1: Executive Summary\r\n\
              Section 2: Valuation Models and Acquisition Roadmaps\r\n"
        }
        "financial_report.xlsx" => {
            b"[SENTINEL_CANARY_XLSX_HEADER]\r\n\
              Q1-Q4 Audited Balance Sheets, Revenue Forecasting, EBITDA Projections\r\n\
              Account ID: 884-29104-92A\r\n\
              Net Income: $14,892,000\r\n"
        }
        "family_photos.zip" => {
            b"PK\x03\x04\x14\x00\x00\x00\x08\x00\
              SENTINEL_CANARY_ARCHIVE_VACATION_PHOTOS_SUMMER_2023_FAMILY_MEMORIES\
              \x00\x00\x00\x00\x00\x00"
        }
        "passwords.txt" => {
            b"# Sentinel Canary Vault - Personal & Infrastructure Credentials\r\n\
              aws_access_key_id=AKIAIOSFODNN7EXAMPLE\r\n\
              aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n\
              root_database_master_pass=S3cur3_C4n4ry_T0k3n_V4ult_99!\r\n"
        }
        "bitcoin_wallet.dat" => {
            b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\
              SENTINEL_BITCOIN_CORE_WALLET_DESCRIPTOR_CANARY_v0.21.0\
              \x00\x00\x00\x00\x00\x00"
        }
        "tax_return_2024.pdf" => {
            b"%PDF-1.4\n\
              1 0 obj\n\
              << /Title (Federal Form 1040 - U.S. Individual Income Tax Return 2024) /Author (Sentinel Canary) >>\n\
              endobj\n\
              trailer\n\
              << /Root 1 0 R >>\n\
              %%EOF\n"
        }
        _ => b"[SENTINEL_CANARY_GENERIC_DECOY_FILE]\n",
    }
}

/// Deploys honeypot canary files into `~/.canary_sentinel/` directories across `/home/*` user homes.
///
/// If running as root, also deploys to `/root/.canary_sentinel/`.
///
/// # Returns
/// A vector containing paths to all successfully created canary decoy files.
pub fn deploy_canaries() -> anyhow::Result<Vec<PathBuf>> {
    let mut deployed = Vec::new();
    let mut target_dirs = Vec::new();

    // Enumerate user homes under /home/*
    if let Ok(entries) = fs::read_dir("/home") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !name.starts_with('.') {
                        target_dirs.push(path.join(CANARY_DIR_NAME));
                    }
                }
            }
        }
    }

    // Include /root if it exists
    let root_home = PathBuf::from("/root");
    if root_home.is_dir() {
        target_dirs.push(root_home.join(CANARY_DIR_NAME));
    }

    for canary_dir in target_dirs {
        match fs::create_dir_all(&canary_dir) {
            Ok(_) => {
                info!("Canary directory initialized at: {}", canary_dir.display());

                // Match ownership to the home directory (e.g. niko:niko) so that user-level
                // ransomware has permission to modify them and trigger the trap.
                let mut target_uid = 0;
                let mut target_gid = 0;
                if let Some(parent) = canary_dir.parent() {
                    if let Ok(meta) = fs::metadata(parent) {
                        use std::os::unix::fs::MetadataExt;
                        target_uid = meta.uid();
                        target_gid = meta.gid();
                    }
                }

                use std::os::unix::ffi::OsStrExt;
                let c_dir = std::ffi::CString::new(canary_dir.as_os_str().as_bytes()).unwrap();
                unsafe { libc::chown(c_dir.as_ptr(), target_uid, target_gid) };

                for file_name in CANARY_FILES {
                    let file_path = canary_dir.join(file_name);
                    let content = get_canary_content(file_name);
                    match fs::write(&file_path, content) {
                        Ok(_) => {
                            let c_file = std::ffi::CString::new(file_path.as_os_str().as_bytes()).unwrap();
                            unsafe { libc::chown(c_file.as_ptr(), target_uid, target_gid) };
                            deployed.push(file_path);
                        }
                        Err(e) => {
                            warn!("Failed to write canary file '{}': {}", file_path.display(), e);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Failed to create canary directory '{}': {}", canary_dir.display(), e);
            }
        }
    }

    info!("Deployed {} canary files across system honeypots", deployed.len());
    Ok(deployed)
}

/// Checks whether a given file path resides within a canary sentinel directory.
///
/// # Arguments
/// * `path` - Target file path to inspect.
///
/// # Returns
/// `true` if `path` contains [`CANARY_DIR_NAME`].
#[inline]
pub fn is_canary_path(path: &str) -> bool {
    path.contains(CANARY_DIR_NAME)
}

/// Returns a list of all currently existing deployed canary directories.
#[allow(dead_code)]
pub fn get_canary_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(entries) = fs::read_dir("/home") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !name.starts_with('.') {
                        let canary_dir = path.join(CANARY_DIR_NAME);
                        if canary_dir.is_dir() {
                            dirs.push(canary_dir);
                        }
                    }
                }
            }
        }
    }

    let root_canary = PathBuf::from("/root").join(CANARY_DIR_NAME);
    if root_canary.is_dir() {
        dirs.push(root_canary);
    }

    dirs
}

/// Helper function to deploy canaries into a custom base directory (useful for testing and sandboxes).
#[allow(dead_code)]
pub fn deploy_canaries_to_base<P: AsRef<Path>>(base_path: P) -> anyhow::Result<Vec<PathBuf>> {
    let canary_dir = base_path.as_ref().join(CANARY_DIR_NAME);
    fs::create_dir_all(&canary_dir)?;

    let mut deployed = Vec::new();
    for file_name in CANARY_FILES {
        let file_path = canary_dir.join(file_name);
        let content = get_canary_content(file_name);
        fs::write(&file_path, content)?;
        deployed.push(file_path);
    }

    Ok(deployed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_is_canary_path() {
        assert!(is_canary_path("/home/alice/.canary_sentinel/passwords.txt"));
        assert!(is_canary_path("/root/.canary_sentinel/important_document.docx"));
        assert!(is_canary_path(".canary_sentinel/file"));

        assert!(!is_canary_path("/home/alice/Documents/passwords.txt"));
        assert!(!is_canary_path("/home/alice/.config/app.conf"));
        assert!(!is_canary_path("/tmp/canary_sentinel/not_hidden"));
    }

    #[test]
    fn test_canary_files_list_count() {
        assert_eq!(CANARY_FILES.len(), 6);
        for file in CANARY_FILES {
            let content = get_canary_content(file);
            assert!(!content.is_empty(), "Canary content for {} must not be empty", file);
        }
    }

    #[test]
    fn test_deploy_canaries_to_custom_dir() {
        let temp_dir = std::env::temp_dir().join(format!("canary_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);

        let deployed = deploy_canaries_to_base(&temp_dir).expect("Deploy to custom dir must succeed");
        assert_eq!(deployed.len(), 6);

        for path in &deployed {
            assert!(path.is_file(), "File {} should exist", path.display());
            assert!(is_canary_path(&path.to_string_lossy()));
            let metadata = fs::metadata(path).unwrap();
            assert!(metadata.len() > 0);
        }

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
