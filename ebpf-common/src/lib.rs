//! # ebpf-common
//!
//! Shared `no_std` types with stable C ABI (`#[repr(C)]`) used for communication
//! between eBPF kernel probes and the userspace daemon via BPF Ring Buffer.
//!
//! This crate compiles for both `bpfel-unknown-none` (eBPF) and the host target.

#![no_std]

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum file path length captured in events.
pub const MAX_PATH_LEN: usize = 256;

/// Maximum process command name length (`/proc/[pid]/comm`).
pub const MAX_COMM_LEN: usize = 16;

/// Block size for entropy analysis. 512 bytes is highly accurate for Shannon entropy 
/// and avoids eBPF verifier loop unrolling explosion (max 4 outer loop iterations).
pub const BLOCK_SIZE: usize = 512;

/// Shannon entropy threshold (fixed-point × 100) for kernel-side pre-filtering.
/// Equivalent to 7.92 in floating point.
pub const ENTROPY_THRESHOLD_FIXED: u32 = 792;

/// First N bytes of the write buffer captured verbatim for magic-number / header
/// inspection in userspace. Kept small to minimise ring-buffer pressure.
pub const MAGIC_SAMPLE_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Event type discriminant
// ---------------------------------------------------------------------------

/// Discriminant for the kind of I/O operation captured by a kernel probe.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// `vfs_write` — first 4 KiB block written to a regular file.
    VfsWrite = 0,
    /// `sys_enter_rename` / `sys_enter_renameat2`.
    Rename = 1,
    /// `sys_enter_unlinkat` — file deletion.
    Unlink = 2,
}

// ---------------------------------------------------------------------------
// Primary ring-buffer event
// ---------------------------------------------------------------------------

/// I/O event transmitted from kernel eBPF probes to the userspace daemon via
/// `BPF_MAP_TYPE_RINGBUF`.
///
/// **Layout**: `#[repr(C)]` guarantees a deterministic, architecture-independent
/// memory layout so that the same struct definition can be used on both sides
/// of the eBPF ↔ userspace boundary without serialisation overhead.
///
/// **Size budget** (approximate):
/// ```text
///   4 + 4 + 4 + 4          =   16   (pid, uid, gid, event_type)
///   8                       =    8   (timestamp_ns)
///   16                      =   16   (comm)
///   256 + 256               =  512   (path, new_path)
///   64                      =   64   (magic_sample)
///   4 + 4                   =    8   (data_len, _pad)
///   256 × 4                 = 1024   (byte_counts)
///                             ─────
///                             1648 bytes per event
/// ```
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoEvent {
    // ── Process identity ──────────────────────────────────────────────
    /// PID of the process that performed the I/O.
    pub pid: u32,
    /// Real UID.
    pub uid: u32,
    /// Real GID.
    pub gid: u32,

    // ── Event metadata ────────────────────────────────────────────────
    /// Type of file-system operation.
    pub event_type: EventType,
    /// Kernel monotonic timestamp (`bpf_ktime_get_ns()`).
    pub timestamp_ns: u64,

    // ── Process name ──────────────────────────────────────────────────
    /// `comm` field from `task_struct`, null-padded.
    pub comm: [u8; MAX_COMM_LEN],

    // ── File paths ────────────────────────────────────────────────────
    /// Absolute path of the affected file, null-padded.
    pub path: [u8; MAX_PATH_LEN],
    /// For `Rename` events: destination path, null-padded. Zeroed otherwise.
    pub new_path: [u8; MAX_PATH_LEN],

    // ── Data sample ───────────────────────────────────────────────────
    /// First [`MAGIC_SAMPLE_LEN`] bytes of the write buffer.
    /// Used for file-type / magic-number detection in userspace.
    pub magic_sample: [u8; MAGIC_SAMPLE_LEN],

    /// Actual number of bytes in the captured write (may be < [`BLOCK_SIZE`]).
    pub data_len: u32,

    /// Padding for alignment.
    pub _pad: u32,

    // ── Byte-frequency histogram ──────────────────────────────────────
    /// Histogram of byte values in the first [`BLOCK_SIZE`] bytes of the write
    /// buffer. Computed inside the eBPF probe so that userspace can derive
    /// Shannon entropy without receiving the raw 4 KiB block (zero-copy).
    pub byte_counts: [u32; 256],
}

// Safety: IoEvent is composed entirely of primitive Copy types with a fixed
// repr(C) layout. Send + Sync are required for sharing via the ring-buffer
// consumer in an async (tokio) context.
#[cfg(feature = "user")]
unsafe impl Send for IoEvent {}
#[cfg(feature = "user")]
unsafe impl Sync for IoEvent {}

// ---------------------------------------------------------------------------
// Helper methods
// ---------------------------------------------------------------------------

impl IoEvent {
    /// Return the process command name as a byte slice, trimmed at the first
    /// NUL terminator.
    #[inline]
    pub fn comm_bytes(&self) -> &[u8] {
        let len = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_COMM_LEN);
        &self.comm[..len]
    }

    /// Return the affected file path as a byte slice, trimmed at the first NUL.
    #[inline]
    pub fn path_bytes(&self) -> &[u8] {
        let len = self
            .path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_PATH_LEN);
        &self.path[..len]
    }

    /// Return the rename-destination path as a byte slice, trimmed at the first
    /// NUL. Empty slice when the event is not a `Rename`.
    #[inline]
    pub fn new_path_bytes(&self) -> &[u8] {
        let len = self
            .new_path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_PATH_LEN);
        &self.new_path[..len]
    }
}
