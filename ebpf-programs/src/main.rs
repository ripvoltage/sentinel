//! # ebpf-programs
//!
//! eBPF kernel probes, tracepoints, and LSM hooks for behavioral ransomware detection.
//!
//! ## Build Instructions
//!
//! This crate targets the `bpfel-unknown-none` target and requires nightly Rust with `bpf-linker`:
//! ```text
//! cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release -p ebpf-programs
//! ```
//!
//! ## Architecture
//!
//! - **Maps**:
//!   - `EVENTS`: Ring buffer (`BPF_MAP_TYPE_RINGBUF`) delivering [`ebpf_common::IoEvent`] records to userspace.
//!   - `TRUSTED_PIDS`: Hash map (`BPF_MAP_TYPE_HASH`) containing whitelisted PIDs to skip in kernel probes.
//!   - `DAEMON_PID`: Array map (`BPF_MAP_TYPE_ARRAY`) storing the ransomware daemon PID for LSM tamper-protection.
//!
//! - **Probes**:
//!   - `vfs_write` (kprobe): Intercepts writes, calculates byte histogram and entropy features.
//!   - `sys_enter_rename` (tracepoint): Intercepts file renames / extension alterations.
//!   - `sys_enter_unlinkat` (tracepoint): Intercepts mass file deletions.
//!   - `task_kill` (LSM hook): Protects the detector daemon from `SIGKILL` / `SIGTERM`.
//!   - `bprm_check_security` (LSM hook): Blocks destructive system utility executions (e.g., wipefs, dd).

#![no_std]
#![no_main]

mod lsm_shield;
mod vfs_tracker;

use aya_ebpf::{
    macros::{kprobe, lsm, map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext, TracePointContext},
};
use ebpf_common::IoEvent;

// ---------------------------------------------------------------------------
// BPF Maps
// ---------------------------------------------------------------------------

/// Ring buffer map for streaming [`ebpf_common::IoEvent`] entries to the userspace daemon.
/// 512 KiB ring buffer size (must be a power of 2 and multiple of page size).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// Hash map storing whitelisted/trusted PIDs (PID -> flags/status).
/// Writes from these PIDs are bypassed immediately in kernel space to reduce overhead.
#[map]
static TRUSTED_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// Single-element array storing the userspace detector daemon PID (index 0).
/// Used by LSM hooks to prevent tampering or unauthorized termination of the daemon.
#[map]
static DAEMON_PID: Array<u32> = Array::with_max_entries(1, 0);

/// Per-CPU scratch space for building [`IoEvent`] without exceeding the 512-byte
/// BPF stack limit. Each CPU gets its own copy (no locking needed).
#[map]
static SCRATCH_EVENT: PerCpuArray<IoEvent> = PerCpuArray::with_max_entries(1, 0);

// ---------------------------------------------------------------------------
// eBPF Probes & Hook Entry Points
// ---------------------------------------------------------------------------

/// Kprobe on kernel function `vfs_write`.
///
/// Intercepts write operations on regular files, samples the write buffer,
/// computes byte histograms, and pushes [`ebpf_common::IoEvent`] to the `EVENTS` ring buffer.
#[kprobe]
pub fn vfs_write(ctx: ProbeContext) -> u32 {
    unsafe {
        match vfs_tracker::handle_vfs_write(&ctx, &EVENTS, &TRUSTED_PIDS, &SCRATCH_EVENT) {
            Ok(_) => 0,
            Err(ret) => ret as u32,
        }
    }
}

/// Tracepoint for `syscalls/sys_enter_rename` (and `sys_enter_renameat2`).
#[tracepoint]
pub fn sys_enter_rename(ctx: TracePointContext) -> u32 {
    unsafe {
        match vfs_tracker::handle_rename(&ctx, &EVENTS, &SCRATCH_EVENT) {
            Ok(_) => 0,
            Err(ret) => ret as u32,
        }
    }
}

/// Tracepoint for `syscalls/sys_enter_unlinkat`.
#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    unsafe {
        match vfs_tracker::handle_unlink(&ctx, &EVENTS, &SCRATCH_EVENT) {
            Ok(_) => 0,
            Err(ret) => ret as u32,
        }
    }
}

/// LSM hook on `task_kill`.
///
/// Prevents untrusted processes from sending `SIGKILL` (9) or `SIGTERM` (15) to
/// the detector daemon (`DAEMON_PID`).
#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    // STUB: requires bpf-linker + nightly
    unsafe { lsm_shield::handle_task_kill(&ctx, &DAEMON_PID) }
}

/// LSM hook on `bprm_check_security`.
///
/// Inspects binaries before execution (`execve`) and blocks destructive commands
/// (such as `wipefs`, `fdisk`, `lvremove`, `mkfs`, `dd`) used by ransomware
/// for system sabotaging.
#[lsm(hook = "bprm_check_security")]
pub fn bprm_check(ctx: LsmContext) -> i32 {
    // STUB: requires bpf-linker + nightly
    unsafe { lsm_shield::handle_bprm_check(&ctx) }
}

// ---------------------------------------------------------------------------
// Panic Handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
