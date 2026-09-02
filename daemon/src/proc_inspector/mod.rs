//! Process tree inspector for false-positive filtering.
//!
//! Inspects `/proc` metadata to identify benign tools (backup programs, compilers,
//! archiving utilities) and interactive shell sessions launched from terminal emulators.

use std::fs;
use std::path::Path;
use anyhow::{Context, Result};
use tracing::debug;

/// Process metadata extracted from `/proc/[pid]/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Real User ID.
    pub uid: u32,
    /// Real Group ID.
    pub gid: u32,
    /// Resolved executable path from `/proc/[pid]/exe`.
    pub exe: String,
    /// Command line arguments parsed from `/proc/[pid]/cmdline`.
    pub cmdline: Vec<String>,
    /// Command name from `/proc/[pid]/stat` or `task_struct::comm`.
    pub comm: String,
    /// Parent process ID (PPID).
    pub parent_pid: u32,
}

/// Whitelist of known benign binaries frequently exhibiting high-entropy writes or mass file access.
const TRUSTED_BINARIES: &[&str] = &[
    "tar",
    "gzip",
    "gunzip",
    "bzip2",
    "xz",
    "zstd",
    "lz4",
    "pigz",
    "gpg",
    "gpg2",
    "gpg-agent",
    "openssl",
    "age",
    "rsync",
    "cp",
    "mv",
    "dd",
    "ssh",
    "scp",
    "sftp",
    "rclone",
    "borg",
    "restic",
    "duplicity",
    "snap",
    "flatpak",
    "apt",
    "apt-get",
    "dpkg",
    "dnf",
    "yum",
    "pacman",
    "makepkg",
    "cargo",
    "rustc",
    "gcc",
    "g++",
    "clang",
    "make",
    "cmake",
    "ninja",
    "npm",
    "node",
    "python3",
    "pip",
    "java",
    "javac",
    "docker",
    "podman",
    "systemd-journald",
    "journalctl",
    "logrotate",
];

/// Known interactive user shells.
const SHELL_BINARIES: &[&str] = &["bash", "zsh", "fish", "dash", "sh"];

/// Known terminal emulators and multiplexers.
const TERMINAL_BINARIES: &[&str] = &[
    "gnome-terminal",
    "gnome-terminal-server",
    "konsole",
    "alacritty",
    "kitty",
    "tilix",
    "tmux",
    "screen",
];

/// Reads the text content of `/proc/[pid]/{name}`.
fn read_proc_file(pid: u32, name: &str) -> Result<String> {
    let path = format!("/proc/{}/{}", pid, name);
    fs::read_to_string(&path).with_context(|| format!("Failed to read proc file: {}", path))
}

/// Parses the `/proc/[pid]/stat` file into `(comm, parent_pid)`.
fn parse_proc_stat(stat_str: &str) -> Result<(String, u32)> {
    let open_paren = stat_str
        .find('(')
        .context("Missing '(' opening delimiter in /proc/[pid]/stat")?;
    let close_paren = stat_str
        .rfind(')')
        .context("Missing ')' closing delimiter in /proc/[pid]/stat")?;

    if close_paren <= open_paren {
        anyhow::bail!("Malformed comm in /proc/[pid]/stat");
    }

    let comm = stat_str[open_paren + 1..close_paren].to_string();
    let remainder = stat_str[close_paren + 1..].trim();

    // Fields after ')' are: state (field 3), ppid (field 4), pgrp, session, ...
    let mut tokens = remainder.split_whitespace();
    let _state = tokens
        .next()
        .context("Missing process state field in stat")?;
    let ppid_str = tokens
        .next()
        .context("Missing ppid field in stat")?;
    let parent_pid: u32 = ppid_str
        .parse()
        .with_context(|| format!("Invalid ppid value '{}'", ppid_str))?;

    Ok((comm, parent_pid))
}

/// Parses real UID and GID from `/proc/[pid]/status`.
fn parse_proc_status_ids(status_str: &str) -> (u32, u32) {
    let mut uid = 0;
    let mut gid = 0;

    for line in status_str.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(first) = rest.split_whitespace().next() {
                uid = first.parse().unwrap_or(0);
            }
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            if let Some(first) = rest.split_whitespace().next() {
                gid = first.parse().unwrap_or(0);
            }
        }
    }

    (uid, gid)
}

/// Reads and parses `/proc/[pid]/cmdline` into argument strings.
fn read_proc_cmdline(pid: u32) -> Vec<String> {
    let path = format!("/proc/{}/cmdline", pid);
    match fs::read(&path) {
        Ok(bytes) => bytes
            .split(|&b| b == 0)
            .filter(|slice| !slice.is_empty())
            .map(|slice| String::from_utf8_lossy(slice).to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolves the symlink `/proc/[pid]/exe` to find the binary path.
fn read_proc_exe(pid: u32, fallback_comm: &str) -> String {
    let path = format!("/proc/{}/exe", pid);
    match fs::read_link(&path) {
        Ok(dest) => dest.to_string_lossy().to_string(),
        Err(_) => fallback_comm.to_string(),
    }
}

/// Inspects a process by reading `/proc/[pid]/` metadata and constructs a [`ProcessInfo`].
///
/// # Arguments
/// * `pid` - Target process ID.
///
/// # Errors
/// Returns an error if `/proc/[pid]/stat` cannot be read or parsed.
pub fn inspect(pid: u32) -> Result<ProcessInfo> {
    let stat_content = read_proc_file(pid, "stat")?;
    let (comm, parent_pid) = parse_proc_stat(&stat_content)?;

    let status_content = read_proc_file(pid, "status").unwrap_or_default();
    let (uid, gid) = parse_proc_status_ids(&status_content);

    let cmdline = read_proc_cmdline(pid);
    let exe = read_proc_exe(pid, &comm);

    debug!(
        "Inspected PID {}: comm='{}', exe='{}', parent_pid={}, uid={}, gid={}",
        pid, comm, exe, parent_pid, uid, gid
    );

    Ok(ProcessInfo {
        pid,
        uid,
        gid,
        exe,
        cmdline,
        comm,
        parent_pid,
    })
}

/// Helper to get the filename / basename of a path or command string.
fn get_basename(path_or_name: &str) -> &str {
    Path::new(path_or_name)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(path_or_name)
}

/// Checks whether a process should be trusted to prevent false positives.
///
/// A process is considered trusted if:
/// 1. Its binary basename matches a whitelisted utility (archivers, compilers, package managers, etc.)
/// 2. An ancestor process in its process tree (up to 5 levels) is a shell (`bash`, `zsh`, etc.)
///    spawned inside an interactive terminal emulator (`gnome-terminal`, `tmux`, etc.).
pub fn is_trusted_process(info: &ProcessInfo) -> bool {
    let exe_base = get_basename(&info.exe);
    let comm_base = get_basename(&info.comm);

    // 1. Direct binary whitelist check
    if TRUSTED_BINARIES.contains(&exe_base) || TRUSTED_BINARIES.contains(&comm_base) {
        debug!(
            "Process PID {} ('{}') matched trusted binary whitelist",
            info.pid, info.comm
        );
        return true;
    }

    // 2. Parent chain check (walk up up to 5 levels)
    let mut current_pid = info.parent_pid;
    let mut shell_found = false;

    for level in 0..5 {
        if current_pid <= 1 {
            break;
        }

        match inspect(current_pid) {
            Ok(parent_info) => {
                let parent_comm = get_basename(&parent_info.comm);
                let parent_exe = get_basename(&parent_info.exe);

                let is_shell = SHELL_BINARIES.contains(&parent_comm)
                    || SHELL_BINARIES.contains(&parent_exe);
                let is_terminal = TERMINAL_BINARIES.contains(&parent_comm)
                    || TERMINAL_BINARIES.contains(&parent_exe);

                if is_shell {
                    shell_found = true;
                }

                if shell_found && is_terminal {
                    debug!(
                        "Process PID {} verified as interactive: ancestor PID {} is terminal '{}' hosting shell (level {})",
                        info.pid, parent_info.pid, parent_comm, level + 1
                    );
                    return true;
                }

                current_pid = parent_info.parent_pid;
            }
            Err(_) => break,
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_stat_standard() {
        let stat = "1234 (test_app) S 5678 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 1000 10000 100";
        let (comm, ppid) = parse_proc_stat(stat).expect("Parsing standard stat must succeed");
        assert_eq!(comm, "test_app");
        assert_eq!(ppid, 5678);
    }

    #[test]
    fn test_parse_proc_stat_with_spaces_and_parens() {
        let stat = "4321 (app (worker) thread) R 9876 4321 4321 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0";
        let (comm, ppid) = parse_proc_stat(stat).expect("Parsing stat with internal parens must succeed");
        assert_eq!(comm, "app (worker) thread");
        assert_eq!(ppid, 9876);
    }

    #[test]
    fn test_parse_proc_status_ids() {
        let status = "Name:\transomware-daemon\n\
                      State:\tS (sleeping)\n\
                      Uid:\t1000\t1000\t1000\t1000\n\
                      Gid:\t1001\t1001\t1001\t1001\n\
                      FDSize:\t64\n";
        let (uid, gid) = parse_proc_status_ids(status);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1001);
    }

    #[test]
    fn test_is_trusted_binary_whitelist() {
        let trusted_proc = ProcessInfo {
            pid: 100,
            uid: 1000,
            gid: 1000,
            exe: "/usr/bin/rsync".to_string(),
            cmdline: vec!["rsync".to_string(), "-av".to_string()],
            comm: "rsync".to_string(),
            parent_pid: 1,
        };
        assert!(is_trusted_process(&trusted_proc));

        let compiler_proc = ProcessInfo {
            pid: 101,
            uid: 1000,
            gid: 1000,
            exe: "/home/user/.cargo/bin/rustc".to_string(),
            cmdline: vec!["rustc".to_string(), "main.rs".to_string()],
            comm: "rustc".to_string(),
            parent_pid: 1,
        };
        assert!(is_trusted_process(&compiler_proc));

        let untrusted_proc = ProcessInfo {
            pid: 666,
            uid: 1000,
            gid: 1000,
            exe: "/tmp/malicious_payload".to_string(),
            cmdline: vec!["/tmp/malicious_payload".to_string()],
            comm: "malicious_paylo".to_string(),
            parent_pid: 1,
        };
        assert!(!is_trusted_process(&untrusted_proc));
    }
}
