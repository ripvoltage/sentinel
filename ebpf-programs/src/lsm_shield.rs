//! # lsm_shield
//!
//! Linux Security Module (BPF-LSM) hook handlers for proactive defense and tamper protection.
//! Uses raw BPF helpers with MaybeUninit to avoid `memset` intrinsic calls.

use core::mem::MaybeUninit;

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    maps::Array,
    programs::LsmContext,
};

// Raw BPF helper for getting current comm without memset
/// Get current process comm name without memset (uses MaybeUninit).
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

/// Linux signal constants
const SIGKILL: i32 = 9;
const SIGTERM: i32 = 15;

/// Return codes for LSM hooks: 0 indicates ALLOW, negative value (-EPERM / -1) indicates BLOCK.
const LSM_ALLOW: i32 = 0;
const LSM_BLOCK_EPERM: i32 = -1;

/// Destructive binary names monitored to block volume / partition wiping.
const BLOCKED_COMMANDS: &[&[u8]] = &[
    b"lvremove",
    b"fdisk",
    b"wipefs",
    b"mkfs",
    b"dd",
];

// ---------------------------------------------------------------------------
// LSM Hook: task_kill
// ---------------------------------------------------------------------------

/// Handle `task_kill` LSM hook.
///
/// Intercepts signals sent between tasks (`security_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)`).
/// If a process attempts to send `SIGKILL` (9) or `SIGTERM` (15) to the registered
/// daemon PID, the signal is blocked with `-EPERM`.
///
/// # Arguments
/// - `ctx`: The LSM execution context containing hook arguments.
/// - `daemon_pid`: Single-element array holding the daemon's PID at index 0.
///
/// # Returns
/// `0` (allow) or `-1` (block / EPERM).
///
/// # Safety
/// Performs kernel memory dereferences via BPF helpers.
pub unsafe fn handle_task_kill(ctx: &LsmContext, daemon_pid: &Array<u32>) -> i32 {
    // STUB: requires bpf-linker + nightly target bpfel-unknown-none

    // Retrieve daemon PID stored by userspace at map index 0
    let target_daemon_pid = match daemon_pid.get(0) {
        Some(&pid) if pid > 0 => pid,
        _ => return LSM_ALLOW,
    };

    // Argument 0: target `struct task_struct *p`
    // Argument 2: `int sig`
    // In aya-ebpf 0.2, LsmContext::arg() returns T directly.
    let task_ptr: *const u8 = ctx.arg(0);
    let sig: i32 = ctx.arg(2);

    if task_ptr.is_null() {
        return LSM_ALLOW;
    }

    // Only protect against forced termination signals
    if sig != SIGKILL && sig != SIGTERM {
        return LSM_ALLOW;
    }

    // In a real kernel environment, PID is read from task_struct->tgid
    // struct task_struct offset for tgid varies across kernel versions (e.g. ~0x928 on x86_64)
    // STUB: reading offset 0x900 as placeholder for task_struct->tgid
    let pid_offset_ptr = task_ptr.add(0x900) as *const u32;
    if let Ok(target_pid) = bpf_probe_read_kernel(pid_offset_ptr) {
        if target_pid == target_daemon_pid {
            // Block signal delivery to protected daemon
            return LSM_BLOCK_EPERM;
        }
    }

    LSM_ALLOW
}

// ---------------------------------------------------------------------------
// LSM Hook: bprm_check_security
// ---------------------------------------------------------------------------

/// Handle `bprm_check_security` LSM hook.
///
/// Intercepts binary execution attempts (`security_bprm_check_security(struct linux_binprm *bprm)`).
/// Checks the process / binary name against dangerous utilities frequently used by
/// ransomware actors to destroy volume backups, partition tables, and file systems.
///
/// # Arguments
/// - `ctx`: The LSM execution context.
///
/// # Returns
/// `0` (allow) or `-1` (block / EPERM).
///
/// # Safety
/// Performs kernel probe reads and memory inspections.
pub unsafe fn handle_bprm_check(ctx: &LsmContext) -> i32 {
    // STUB: requires bpf-linker + nightly target bpfel-unknown-none

    // Read current process comm name
    let comm = match get_comm() {
        Ok(c) => c,
        Err(_) => return LSM_ALLOW,
    };

    // Check if the executing command matches any blocked destructive binary
    for &blocked in BLOCKED_COMMANDS {
        let blocked_len = blocked.len();
        if blocked_len <= comm.len() {
            let mut matches = true;
            let mut i = 0;
            while i < blocked_len {
                if comm[i] != blocked[i] {
                    matches = false;
                    break;
                }
                i += 1;
            }

            // Verify exact string boundary (NUL or end of comm)
            if matches && (i == comm.len() || comm[i] == 0) {
                // Block execution of destructive tool
                return LSM_BLOCK_EPERM;
            }
        }
    }

    // Argument 0: `struct linux_binprm *bprm`
    // Inspect bprm->filename pointer if available
    // In aya-ebpf 0.2, LsmContext::arg() returns T directly.
    let bprm_ptr: *const u8 = ctx.arg(0);
    if !bprm_ptr.is_null() {
        // STUB: inspect bprm->filename for full path matching
    }

    LSM_ALLOW
}
