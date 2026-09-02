//! Process defense and signal management subsystem.
//!
//! Provides atomic, multi-stage process mitigation (SIGSTOP freezing followed by
//! SIGKILL termination) to halt active ransomware threats with microsecond latency.

use std::thread;
use std::time::Duration;
use anyhow::{Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tracing::info;

/// Returns the PID of the running ransomware detector daemon process.
#[inline]
pub fn get_daemon_pid() -> u32 {
    std::process::id()
}

/// Immediately suspends execution of the target process using `SIGSTOP`.
///
/// This halts all threads in the target process instantaneously, preventing any
/// additional file system writes or encryption operations while forensic state
/// is preserved.
pub fn freeze_process(pid: u32) -> Result<()> {
    info!("Freezing suspicious process (PID: {}) via SIGSTOP", pid);

    kill(Pid::from_raw(pid as i32), Signal::SIGSTOP)
        .with_context(|| format!("Failed to deliver SIGSTOP to process PID {}", pid))?;

    info!("Successfully suspended process (PID: {})", pid);
    Ok(())
}

/// Forcefully terminates the target process using `SIGKILL`.
pub fn kill_process(pid: u32) -> Result<()> {
    info!("Terminating malicious process (PID: {}) via SIGKILL", pid);

    kill(Pid::from_raw(pid as i32), Signal::SIGKILL)
        .with_context(|| format!("Failed to deliver SIGKILL to process PID {}", pid))?;

    info!("Successfully terminated process (PID: {})", pid);
    Ok(())
}

/// Neutralizes an identified ransomware process using a two-step defense protocol:
/// 1. Sends `SIGSTOP` to freeze I/O immediately and prevent further destruction.
/// 2. Waits 100ms to allow pending kernel write queues to settle.
/// 3. Sends `SIGKILL` for definitive, uncatchable termination.
pub fn neutralize_threat(pid: u32) -> Result<()> {
    let daemon_pid = get_daemon_pid();
    if pid == daemon_pid {
        anyhow::bail!("Refusing to neutralize self (daemon PID {})", pid);
    }
    if pid <= 1 {
        anyhow::bail!("Refusing to neutralize system init (PID {})", pid);
    }

    info!("Initiating threat neutralization sequence for PID {}", pid);

    // Stage 1: Freeze immediate execution
    freeze_process(pid)?;

    // Stage 2: 100ms pause to ensure execution pipeline is halted
    thread::sleep(Duration::from_millis(100));

    // Stage 3: Unconditional process termination
    kill_process(pid)?;

    info!("Threat neutralization sequence completed for PID {}", pid);
    Ok(())
}
