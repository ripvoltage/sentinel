//! # vfs_tracker
//!
//! Kernel probe and tracepoint handlers for monitoring file system I/O activity.
//! Uses per-CPU array map for IoEvent scratch space (512-byte BPF stack limit).
//! Avoids `memset` intrinsic by using bounded loops and MaybeUninit.

use core::mem::MaybeUninit;

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_buf, bpf_probe_read_user_str_bytes,
    },
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, TracePointContext},
};

// Raw BPF helper to avoid memset from aya_ebpf's bpf_get_current_comm wrapper
#[inline(always)]
unsafe fn get_comm() -> Result<[u8; 16], i64> {
    let mut comm: MaybeUninit<[u8; 16]> = MaybeUninit::uninit();
    // BPF helper #16 is bpf_get_current_comm
    let helper: unsafe extern "C" fn(*mut u8, u32) -> i64 = core::mem::transmute(16usize);
    let ret = helper(comm.as_mut_ptr() as *mut u8, 16);
    if ret == 0 {
        Ok(comm.assume_init())
    } else {
        Err(ret)
    }
}
use ebpf_common::{
    BLOCK_SIZE, EventType, IoEvent, MAGIC_SAMPLE_LEN,
};

/// Minimum PID to monitor.
const MIN_MONITORED_PID: u32 = 500;

/// Chunk size for incremental user-buffer reads. Must stay small for BPF stack.
const SAMPLE_CHUNK_SIZE: usize = 128;

// ---------------------------------------------------------------------------
// Helpers: zero fields without memset
// ---------------------------------------------------------------------------

/// Zero the byte_counts histogram using volatile writes to prevent
/// LLVM from optimizing the loop back into a memset intrinsic.
#[inline(always)]
fn zero_byte_counts(counts: &mut [u32; 256]) {
    let ptr = counts.as_mut_ptr();
    let mut i = 0;
    while i < 256 {
        unsafe { core::ptr::write_volatile(ptr.add(i), 0u32); }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// VFS Write Handler
// ---------------------------------------------------------------------------

pub unsafe fn handle_vfs_write(
    ctx: &ProbeContext,
    events: &RingBuf,
    trusted: &HashMap<u32, u32>,
    scratch: &PerCpuArray<IoEvent>,
) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if pid < MIN_MONITORED_PID {
        return Ok(());
    }
    if trusted.get(&pid).is_some() {
        return Ok(());
    }

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;
    let comm = get_comm().map_err(|e| e as i64)?;

    let user_buf: *const u8 = ctx.arg(1).ok_or(-1i64)?;
    let count: usize = ctx.arg(2).unwrap_or(0);

    if user_buf.is_null() || count == 0 {
        return Ok(());
    }

    // Get IoEvent from per-CPU map (no stack allocation)
    let event_ptr = scratch.get_ptr_mut(0).ok_or(-1i64)?;
    let event = &mut *event_ptr;

    // Set fields individually (no memset)
    event.pid = pid;
    event.uid = uid;
    event.gid = gid;
    event.event_type = EventType::VfsWrite;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.comm = comm;
    event.data_len = count.min(BLOCK_SIZE) as u32;
    event._pad = 0;

    // Zero path first byte as null terminator sentinel
    event.path[0] = 0;
    event.new_path[0] = 0;

    // Zero byte_counts with bounded loop (no memset)
    zero_byte_counts(&mut event.byte_counts);

    // Read magic sample (first 64 bytes)
    let sample_len = count.min(MAGIC_SAMPLE_LEN);
    if sample_len > 0 {
        let _ = bpf_probe_read_user_buf(user_buf, &mut event.magic_sample[..sample_len]);
    }

    // Sample write buffer and compute byte histogram.
    // Use MaybeUninit for chunk_buf to avoid memset.
    let mut chunk_buf: MaybeUninit<[u8; SAMPLE_CHUNK_SIZE]> = MaybeUninit::uninit();
    let chunk_ptr = chunk_buf.as_mut_ptr() as *mut u8;

    let bytes_to_sample = count.min(BLOCK_SIZE);
    let mut offset: usize = 0;
    let max_iters: usize = BLOCK_SIZE / SAMPLE_CHUNK_SIZE; // 32

    let mut iter = 0;
    // Tell the verifier this loop has a strict static maximum bound (32)
    while iter < max_iters {
        if offset >= bytes_to_sample {
            break;
        }

        let remaining = bytes_to_sample - offset;
        let read_len = if remaining < SAMPLE_CHUNK_SIZE {
            remaining
        } else {
            SAMPLE_CHUNK_SIZE
        };

        // 1. Zero the chunk buffer unconditionally (128 times).
        // This prevents reading garbage bytes past `read_len` in the branchless loop.
        let mut i = 0;
        while i < SAMPLE_CHUNK_SIZE {
            unsafe { core::ptr::write_volatile(chunk_ptr.add(i), 0u8); }
            i += 1;
        }

        let src = user_buf.add(offset);
        let dst = core::slice::from_raw_parts_mut(chunk_ptr, read_len);
        if bpf_probe_read_user_buf(src, dst).is_err() {
            break;
        }

        // 2. Unconditional, branchless histogram accumulation!
        // The verifier loves this because it doesn't spawn new states.
        let mut j = 0;
        while j < SAMPLE_CHUNK_SIZE {
            let byte = *chunk_ptr.add(j);
            event.byte_counts[byte as usize] += 1;
            j += 1;
        }

        // 3. Fix up the extra zeros we accumulated past `read_len`.
        let extra_zeros = (SAMPLE_CHUNK_SIZE - read_len) as u32;
        event.byte_counts[0] -= extra_zeros;

        offset += read_len;
        iter += 1;
    }

    events.output::<IoEvent>(event, 0).map_err(|e| e as i64)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: Rename (sys_enter_renameat2)
// ---------------------------------------------------------------------------

pub unsafe fn handle_rename(
    ctx: &TracePointContext,
    events: &RingBuf,
    scratch: &PerCpuArray<IoEvent>,
) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if pid < MIN_MONITORED_PID {
        return Ok(());
    }

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;
    let comm = get_comm().map_err(|e| e as i64)?;

    let event_ptr = scratch.get_ptr_mut(0).ok_or(-1i64)?;
    let event = &mut *event_ptr;

    event.pid = pid;
    event.uid = uid;
    event.gid = gid;
    event.event_type = EventType::Rename;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.comm = comm;
    event.data_len = 0;
    event._pad = 0;

    // Zero path sentinels
    event.path[0] = 0;
    event.new_path[0] = 0;

    // sys_enter_renameat2 format:
    // oldname is at offset 24, newname is at offset 40
    if let Ok(oldname_ptr) = ctx.read_at::<*const u8>(24) {
        if !oldname_ptr.is_null() {
            let _ = bpf_probe_read_user_str_bytes(oldname_ptr, &mut event.path);
        }
    }

    if let Ok(newname_ptr) = ctx.read_at::<*const u8>(40) {
        if !newname_ptr.is_null() {
            let _ = bpf_probe_read_user_str_bytes(newname_ptr, &mut event.new_path);
        }
    }

    events.output::<IoEvent>(event, 0).map_err(|e| e as i64)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tracepoint: Unlink (sys_enter_unlinkat)
// ---------------------------------------------------------------------------

pub unsafe fn handle_unlink(
    ctx: &TracePointContext,
    events: &RingBuf,
    scratch: &PerCpuArray<IoEvent>,
) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if pid < MIN_MONITORED_PID {
        return Ok(());
    }

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;
    let comm = get_comm().map_err(|e| e as i64)?;

    let event_ptr = scratch.get_ptr_mut(0).ok_or(-1i64)?;
    let event = &mut *event_ptr;

    event.pid = pid;
    event.uid = uid;
    event.gid = gid;
    event.event_type = EventType::Unlink;
    event.timestamp_ns = bpf_ktime_get_ns();
    event.comm = comm;
    event.data_len = 0;
    event._pad = 0;

    event.path[0] = 0;
    event.new_path[0] = 0;

    // sys_enter_unlinkat format:
    // pathname is at offset 24
    if let Ok(pathname_ptr) = ctx.read_at::<*const u8>(24) {
        if !pathname_ptr.is_null() {
            let _ = bpf_probe_read_user_str_bytes(pathname_ptr, &mut event.path);
        }
    }

    events.output::<IoEvent>(event, 0).map_err(|e| e as i64)?;
    Ok(())
}
