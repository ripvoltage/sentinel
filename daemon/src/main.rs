//! # Ransomware Detector Daemon
//!
//! Real-time behavioral ransomware detection engine for GNU/Linux.
//!
//! This is the main userspace daemon that:
//! 1. Loads and attaches eBPF probes (kprobes, tracepoints, LSM hooks)
//! 2. Consumes I/O events from a BPF ring buffer
//! 3. Calculates Shannon entropy and evaluates behavioral heuristics
//! 4. Inspects `/proc` to filter false positives
//! 5. Neutralizes confirmed threats (SIGSTOP + SIGKILL)
//! 6. Initiates COW snapshot remediation (Btrfs / ZFS)
//! 7. Emits structured forensic logs and GNOME desktop alerts
//!
//! Must run as **root** (CAP_BPF + CAP_SYS_ADMIN).

mod cow_remediation;
mod defense;
mod engine;
mod logger;
mod notification;
mod proc_inspector;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::programs::{KProbe, Lsm, TracePoint};
use aya::{Ebpf, EbpfLoader, Btf};
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use ebpf_common::{EventType, IoEvent};

use crate::engine::canaries;
use crate::engine::entropy;
use crate::engine::heuristics::{HeuristicVerdict, HeuristicsEngine};
use crate::logger::audit::{self, ThreatEvent};
use crate::notification::gnome::ThreatInfo;

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

/// Path to the compiled eBPF object file.
const EBPF_OBJ_PATH: &str = "/usr/lib/sentinel/sentinel-ebpf.o";

/// Heuristic engine stale-entry cleanup interval.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum age of stale heuristic tracking entries.
const STALE_ENTRY_MAX_AGE: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    // ── 1. Initialize structured logging ──────────────────────────────
    let _log_guard = audit::init_logging()
        .context("Failed to initialize forensic logging subsystem")?;

    info!("═══════════════════════════════════════════════════════════════");
    info!("  Sentinel Daemon v{}", env!("CARGO_PKG_VERSION"));
    info!("  PID: {} | EUID: {}", std::process::id(), unsafe { libc::geteuid() });
    info!("═══════════════════════════════════════════════════════════════");

    // ── 2. Verify root privileges ─────────────────────────────────────
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!(
            "This daemon requires root privileges (CAP_BPF + CAP_SYS_ADMIN). \
             Run with sudo or as root."
        );
    }

    // ── 3. Deploy canary sentinel files ───────────────────────────────
    match canaries::deploy_canaries() {
        Ok(paths) => info!("Canary honeypot files deployed: {} files", paths.len()),
        Err(e) => warn!("Canary deployment partially failed: {:#}", e),
    }

    // ── 4. Load eBPF programs ─────────────────────────────────────────
    let mut bpf = load_ebpf_programs()
        .context("Failed to load and attach eBPF programs")?;

    // Register daemon PID in the eBPF DAEMON_PID map for LSM self-protection
    register_daemon_pid(&mut bpf)?;

    info!("eBPF probes loaded and attached successfully");

    // ── 5. Create preventive COW snapshot ─────────────────────────────
    tokio::spawn(async {
        for mount in ["/home", "/"] {
            match cow_remediation::create_preventive_snapshot(mount).await {
                Ok(snap) => info!("Preventive COW snapshot created: {}", snap),
                Err(e) => debug!("COW snapshot skipped for {}: {:#}", mount, e),
            }
        }
    });

    // ── 6. Start main event loop ──────────────────────────────────────
    let ring_buf = RingBuf::try_from(bpf.take_map("EVENTS").context("Missing EVENTS map")?)?;
    let heuristics = Arc::new(Mutex::new(HeuristicsEngine::new()));

    // Spawn periodic cleanup task for the heuristics engine
    let heuristics_cleanup = Arc::clone(&heuristics);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            heuristics_cleanup.lock().await.cleanup_stale(STALE_ENTRY_MAX_AGE);
        }
    });

    info!("Entering main event loop — monitoring filesystem I/O...");
    run_event_loop(ring_buf, heuristics).await
}

// ---------------------------------------------------------------------------
// eBPF loading and attachment
// ---------------------------------------------------------------------------

/// Loads the eBPF object, attaches kprobes, tracepoints, and LSM hooks.
fn load_ebpf_programs() -> Result<Ebpf> {
    let ebpf_path = PathBuf::from(EBPF_OBJ_PATH);

    // Allow fallback to a local path for development
    let obj_path = if ebpf_path.exists() {
        ebpf_path
    } else {
        let local_path = PathBuf::from("target/bpfel-unknown-none/release/ebpf-programs");
        if local_path.exists() {
            warn!("Using development eBPF object at {:?}", local_path);
            local_path
        } else {
            anyhow::bail!(
                "eBPF object not found at {:?} or {:?}. \
                 Build with: cargo +nightly build -Z build-std=core \
                 --target bpfel-unknown-none -p ebpf-programs",
                ebpf_path,
                local_path
            );
        }
    };

    let btf = Btf::from_sys_fs().context("Failed to load kernel BTF (CONFIG_DEBUG_INFO_BTF=y required)")?;
    let mut bpf = EbpfLoader::new()
        .btf(Some(&btf))
        .load_file(&obj_path)
        .with_context(|| format!("Failed to load eBPF object from {:?}", obj_path))?;

    // ── Attach kprobe: vfs_write ──────────────────────────────────────
    let vfs_write: &mut KProbe = bpf
        .program_mut("vfs_write")
        .context("Missing vfs_write program")?
        .try_into()?;
    vfs_write.load()?;
    vfs_write.attach("vfs_write", 0)?;
    info!("Attached kprobe: vfs_write");

    // ── Attach tracepoint: sys_enter_rename ───────────────────────────
    let tp_rename: &mut TracePoint = bpf
        .program_mut("sys_enter_rename")
        .context("Missing sys_enter_rename program")?
        .try_into()?;
    tp_rename.load()?;
    tp_rename.attach("syscalls", "sys_enter_renameat2")?;
    info!("Attached tracepoint: syscalls/sys_enter_renameat2");

    // ── Attach tracepoint: sys_enter_unlinkat ─────────────────────────
    let tp_unlink: &mut TracePoint = bpf
        .program_mut("sys_enter_unlinkat")
        .context("Missing sys_enter_unlinkat program")?
        .try_into()?;
    tp_unlink.load()?;
    tp_unlink.attach("syscalls", "sys_enter_unlinkat")?;
    info!("Attached tracepoint: syscalls/sys_enter_unlinkat");

    // ── Attach LSM: task_kill (self-protection) ───────────────────────
    if let Some(lsm_prog) = bpf.program_mut("task_kill").map(|p| TryInto::<&mut Lsm>::try_into(p)) {
        match lsm_prog {
            Ok(lsm) => {
                if lsm.load("task_kill", &btf).is_ok() {
                    if lsm.attach().is_ok() {
                        info!("Attached BPF-LSM: task_kill (daemon self-protection enabled)");
                    }
                }
            }
            Err(e) => warn!("BPF-LSM task_kill not available: {:#} (self-protection disabled)", e),
        }
    }

    // ── Attach LSM: bprm_check_security (destructive command blocking) ──
    if let Some(lsm_prog) = bpf.program_mut("bprm_check").map(|p| TryInto::<&mut Lsm>::try_into(p)) {
        match lsm_prog {
            Ok(lsm) => {
                if lsm.load("bprm_check_security", &btf).is_ok() {
                    if lsm.attach().is_ok() {
                        info!("Attached BPF-LSM: bprm_check_security (destructive command blocking enabled)");
                    }
                }
            }
            Err(e) => debug!("BPF-LSM bprm_check not available: {:#}", e),
        }
    }

    Ok(bpf)
}

/// Registers the daemon's PID in the eBPF DAEMON_PID array map for LSM
/// self-protection. The eBPF LSM hook reads this to block SIGKILL/SIGTERM.
fn register_daemon_pid(bpf: &mut Ebpf) -> Result<()> {
    use aya::maps::Array;

    let daemon_pid = defense::get_daemon_pid();

    if let Some(map) = bpf.take_map("DAEMON_PID") {
        let mut array: Array<_, u32> = Array::try_from(map)?;
        array.set(0, daemon_pid, 0)?;
        info!("Registered daemon PID {} in eBPF DAEMON_PID map", daemon_pid);
    } else {
        warn!("DAEMON_PID map not found — LSM self-protection may not function");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main event processing loop
// ---------------------------------------------------------------------------

/// Continuously polls the eBPF ring buffer and processes I/O events through
/// the detection pipeline. Uses `AsyncFd` for event-driven wakeups instead
/// of busy-polling.
async fn run_event_loop(
    ring_buf: RingBuf<aya::maps::MapData>,
    heuristics: Arc<Mutex<HeuristicsEngine>>,
) -> Result<()> {
    // Wrap ring buffer in AsyncFd for epoll-based readiness notification
    let mut async_rb = AsyncFd::new(ring_buf)
        .context("Failed to create AsyncFd for ring buffer")?;

    // Track affected files per PID for aggregated alerting
    let mut affected_files: std::collections::HashMap<u32, Vec<String>> =
        std::collections::HashMap::new();

    loop {
        // Wait for the ring buffer fd to become readable (data available)
        let mut guard = async_rb.readable_mut().await
            .context("AsyncFd readable failed")?;

        let rb = guard.get_inner_mut();
        let mut events_processed = 0u32;

        while let Some(item) = rb.next() {
            let data: &[u8] = item.as_ref();

            // Validate event size
            if data.len() < std::mem::size_of::<IoEvent>() {
                warn!(
                    "Undersized ring buffer event: {} bytes (expected {})",
                    data.len(),
                    std::mem::size_of::<IoEvent>()
                );
                continue;
            }

            // SAFETY: IoEvent is #[repr(C)] with fixed layout and only primitive
            // types. The eBPF ring buffer guarantees aligned, complete entries.
            let event: &IoEvent = unsafe { &*(data.as_ptr() as *const IoEvent) };

            if let Err(e) = process_event(event, &heuristics, &mut affected_files).await {
                error!("Error processing I/O event for PID {}: {:#}", event.pid, e);
            }

            events_processed += 1;
        }

        if events_processed > 0 {
            debug!("Processed {} ring buffer events in this cycle", events_processed);
        }

        // Clear readiness so we wait again for the next epoll notification
        guard.clear_ready();
    }
}

// ---------------------------------------------------------------------------
// Event processing pipeline
// ---------------------------------------------------------------------------

/// Processes a single I/O event through the full detection pipeline:
///
/// 1. Calculate Shannon entropy from the kernel-side byte histogram
/// 2. Check canary file modification (immediate high-confidence signal)
/// 3. Evaluate behavioral heuristics (frequency, entropy, extension changes)
/// 4. Inspect `/proc` for false-positive filtering
/// 5. On confirmed threat: neutralize → log → notify → remediate
async fn process_event(
    event: &IoEvent,
    heuristics: &Arc<Mutex<HeuristicsEngine>>,
    affected_files: &mut std::collections::HashMap<u32, Vec<String>>,
) -> Result<()> {
    let path = String::from_utf8_lossy(event.path_bytes()).to_string();
    let new_path = String::from_utf8_lossy(event.new_path_bytes()).to_string();
    let comm = String::from_utf8_lossy(event.comm_bytes()).to_string();

    // ── 1. Entropy calculation ────────────────────────────────────────
    let ent = if event.event_type == EventType::VfsWrite && event.data_len > 0 {
        entropy::calculate_entropy_from_histogram(
            &event.byte_counts,
            event.data_len as usize,
        )
    } else {
        0.0
    };

    // Debug-level I/O telemetry
    let event_type_str = match event.event_type {
        EventType::VfsWrite => "VfsWrite",
        EventType::Rename => "Rename",
        EventType::Unlink => "Unlink",
    };
    audit::log_io_event_debug(event.pid, &path, event_type_str, ent);

    // ── 2. Canary check (highest confidence) ──────────────────────────
    let canary_triggered = canaries::is_canary_path(&path);
    if canary_triggered {
        warn!(
            "🚨 CANARY FILE ACCESSED by PID {} ({}): {}",
            event.pid, comm, path
        );
    }

    // ── 3. Heuristic evaluation ───────────────────────────────────────
    let verdict = {
        let new_path_opt = if event.event_type == EventType::Rename {
            Some(new_path.as_str())
        } else {
            None
        };

        heuristics.lock().await.evaluate(
            event.pid,
            &path,
            new_path_opt,
            event.event_type,
            ent,
        )
    };

    // Track affected files
    let files = affected_files.entry(event.pid).or_default();
    if !path.is_empty() {
        files.push(path.clone());
        // Keep bounded
        if files.len() > 100 {
            files.drain(..50);
        }
    }

    // ── 4. Determine if threat is confirmed ───────────────────────────
    let is_threat = match &verdict {
        HeuristicVerdict::Suspicious { score, .. } => {
            // High score or canary = confirmed threat
            *score >= 40 || canary_triggered
        }
        HeuristicVerdict::Benign => canary_triggered,
    };

    if !is_threat {
        return Ok(());
    }

    // ── 5. Anti-false-positive: /proc inspection ──────────────────────
    match proc_inspector::inspect(event.pid) {
        Ok(proc_info) => {
            if proc_inspector::is_trusted_process(&proc_info) {
                info!(
                    "False positive suppressed: PID {} ({}) is a trusted process",
                    event.pid, proc_info.exe
                );
                return Ok(());
            }
        }
        Err(e) => {
            // Process may have already exited — proceed with threat response
            debug!("Could not inspect PID {}: {:#}", event.pid, e);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // ⚠️ CONFIRMED THREAT — execute response sequence
    // ═══════════════════════════════════════════════════════════════════

    let reasons = match &verdict {
        HeuristicVerdict::Suspicious { reasons, .. } => reasons.clone(),
        HeuristicVerdict::Benign => vec!["Canary file modification".to_string()],
    };

    let rule_triggered = if canary_triggered {
        format!(
            "Canary File Modified | {}",
            reasons.join(" | ")
        )
    } else {
        reasons.join(" | ")
    };

    error!(
        "🚨 RANSOMWARE THREAT CONFIRMED: PID {} ({}) — {}",
        event.pid, comm, rule_triggered
    );

    // ── 6a. Neutralize the malicious process ──────────────────────────
    let action_taken = match defense::neutralize_threat(event.pid) {
        Ok(()) => {
            info!("Threat PID {} neutralized (SIGSTOP + SIGKILL)", event.pid);
            "Process neutralized: SIGSTOP + SIGKILL".to_string()
        }
        Err(e) => {
            error!("Failed to neutralize PID {}: {:#}", event.pid, e);
            format!("Neutralization failed: {}", e)
        }
    };

    // ── 6b. Attempt COW snapshot restoration ──────────────────────────
    let cow_status = attempt_cow_restoration(&path).await;

    // ── 6c. Gather process forensic metadata ──────────────────────────
    let (exe_path, cmdline_str, uid, gid) = match proc_inspector::inspect(event.pid) {
        Ok(info) => (
            info.exe.clone(),
            info.cmdline.join(" "),
            info.uid,
            info.gid,
        ),
        Err(_) => (
            comm.clone(),
            comm.clone(),
            event.uid,
            event.gid,
        ),
    };

    let pid_files = affected_files.remove(&event.pid).unwrap_or_default();

    // ── 6d. Emit forensic audit log ───────────────────────────────────
    let threat_event = ThreatEvent::new(
        event.pid,
        uid,
        gid,
        &exe_path,
        &cmdline_str,
        ent,
        &rule_triggered,
        pid_files.clone(),
        &action_taken,
    );
    audit::log_threat_event(&threat_event);

    // ── 6e. Send GNOME desktop notification ───────────────────────────
    let threat_info = ThreatInfo {
        pid: event.pid,
        exe_path,
        entropy: ent,
        affected_files: pid_files,
        action_taken,
        cow_status: Some(cow_status),
    };

    // Spawn notification delivery so it doesn't block the event loop
    tokio::spawn(async move {
        if let Err(e) = notification::gnome::send_critical_alert(&threat_info).await {
            error!("Failed to send GNOME notification: {:#}", e);
            // Try fallback
            if let Err(e2) = notification::gnome::send_fallback_notification(&threat_info) {
                error!("Fallback notification also failed: {:#}", e2);
            }
        }
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// COW remediation helper
// ---------------------------------------------------------------------------

/// Attempts to restore the most recent COW snapshot for the filesystem
/// containing the affected path.
async fn attempt_cow_restoration(affected_path: &str) -> String {
    // Determine the mount point / subvolume for the affected file
    let mount_point = std::path::Path::new(affected_path)
        .ancestors()
        .find(|p| p == &std::path::Path::new("/home") || p == &std::path::Path::new("/"))
        .unwrap_or(std::path::Path::new("/"))
        .to_string_lossy()
        .to_string();

    let fs_type = match cow_remediation::detect_filesystem(&mount_point) {
        Ok(fs) => fs,
        Err(e) => {
            warn!("Could not detect filesystem for COW restoration: {:#}", e);
            return format!("Filesystem detection failed: {}", e);
        }
    };

    if fs_type == cow_remediation::CowFilesystem::Unsupported {
        return "COW restoration unavailable: filesystem is not Btrfs or ZFS".to_string();
    }

    // Find the most recent snapshot
    match cow_remediation::list_snapshots(&mount_point).await {
        Ok(snapshots) if !snapshots.is_empty() => {
            let latest = snapshots.last().unwrap();
            match cow_remediation::restore_snapshot(latest, &fs_type).await {
                Ok(status) => {
                    info!("COW restoration successful: {}", status);
                    status
                }
                Err(e) => {
                    error!("COW restoration failed: {:#}", e);
                    format!("Restoration failed: {}", e)
                }
            }
        }
        Ok(_) => "No snapshots available for restoration".to_string(),
        Err(e) => {
            error!("Failed to list snapshots: {:#}", e);
            format!("Snapshot listing failed: {}", e)
        }
    }
}
