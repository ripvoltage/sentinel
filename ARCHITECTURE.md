# Sentinel Anti-Ransomware: Technical Architecture & Design

This document details the low-level architectural design and implementation of Sentinel for GNU/Linux environments.

---

## 1. System Overview

Sentinel operates across the boundary between kernel space and userspace, using a dual-engine architecture:

```
+-------------------------------------------------------------+
|                        KERNEL SPACE                         |
|                                                             |
|   [kprobe: vfs_write] --------+                             |
|   [tracepoint: renameat2] ----+-> [eBPF Ring Buffer]        |
|   [tracepoint: unlinkat] -----+           |                 |
|                                           |                 |
|   [Linux VFS Subsystem]                   v                 |
|   +--> [fanotify (FAN_MODIFY / FAN_CLOSE)]                  |
+-------------------------------------------+-----------------+
                                            |
                                            v
+-------------------------------------------------------------+
|                      USERSPACE DAEMON                       |
|                                                             |
|   1. Event Normalization (io_event_t)                       |
|   2. Shannon Entropy Math (256-bin histogram)               |
|   3. Honeypot Canary Detection (~/.canary_sentinel)         |
|   4. Heuristic Scoring (Burst rate, extensions, unlinks)    |
|   5. False-Positive Suppression (proc_inspector)            |
|   6. Three-Stage Neutralization (SIGSTOP -> Pause -> KILL)  |
|   7. Audit Logging (/var/log/ransomware-detector/alerts.log)|
|   8. Desktop Alert Delivery (D-Bus / notify-send)           |
+-------------------------------------------------------------+
```

---

## 2. In-Kernel Probes (eBPF)

When loaded, Sentinel adheres to three kernel attachment points:
- `vfs_write` (kprobe): Intercepts write operations on regular files, samples the first 64 bytes for magic headers, and computes a 256-bin byte frequency histogram branchlessly over 512 bytes.
- `sys_enter_renameat2` (tracepoint): Intercepts file renaming and extension modifications (`oldname` and `newname`).
- `sys_enter_unlinkat` (tracepoint): Intercepts file unlinks and deletions.

### Branchless Histogram Computation
The Linux eBPF verifier limits state space exploration to prevent kernel hangs. Conditional branching inside loops often causes verifier state explosion. Sentinel computes histograms branchlessly:
```c
for (int iter = 0; iter < 4; iter++) {
    // 1. Read fixed 128-byte chunk
    bpf_probe_read_user(chunk, read_len, buf + offset);

    // 2. Unconditional accumulation
    #pragma unroll
    for (int j = 0; j < SAMPLE_CHUNK_SIZE; j++) {
        event->byte_counts[chunk[j]]++;
    }

    // 3. Subtract excess padding zeros
    event->byte_counts[0] -= (__u32)(SAMPLE_CHUNK_SIZE - read_len);
    offset += read_len;
}
```

---

## 3. Native Linux Fanotify Fallback

To achieve zero-dependency distribution on generic Linux kernels without eBPF BTF or compiler requirements, Sentinel implements a native `fanotify` monitor:
- Initializes `fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK, ...)`
- Attaches `FAN_MARK_ADD | FAN_MARK_MOUNT` on `/home` and `/root`
- Inspects `struct fanotify_event_metadata`:
  - `meta->pid`: The kernel-verified PID of the actor process
  - `meta->fd`: File descriptor to read file contents for entropy calculation

---

## 4. Heuristics & Scoring Engine

| Rule | Trigger | Score |
|------|---------|-------|
| Shannon Entropy | $H(X) \ge 7.92$ bits/byte | +40 |
| I/O Burst Rate | > 50 operations in 100ms window | +30 |
| Suspicious Extension | Rename to `.encrypted`, `.locked`, `.cry`, etc. | +20 |
| Destructive Unlink | Deletion within 5s of high-entropy write | +10 |

**Threshold**: A cumulative score of 40 points or higher, or touching a canary honeypot file, triggers the confirmed threat sequence.

---

## 5. False-Positive Filtering (proc_inspector)

To prevent legitimate archiving or compiling from triggering alerts:
1. **Direct Whitelist**: 45+ trusted binaries (`tar`, `gzip`, `xz`, `rsync`, `gcc`, `make`, `python3`, etc.).
2. **Process Ancestry Traversal**: Traverses `/proc/<PID>/stat` up to 5 parent levels. If the process was spawned by an interactive shell (`bash`, `zsh`, `fish`, etc.) hosted within a terminal emulator (`gnome-terminal`, `konsole`, `alacritty`, `kitty`, `tmux`, `screen`), the alert is suppressed as an interactive user command.

---

## 6. Neutralization Sequence

1. `kill(PID, SIGSTOP)`: Halts all process threads immediately, preventing further I/O while preserving process memory.
2. `usleep(100000)`: 100ms pause allowing pending kernel write-back queues to settle.
3. `kill(PID, SIGKILL)`: Permanent, uncatchable termination.
4. **Self-Protection**: The daemon explicitly rejects signals directed at `getpid()` or `PID <= 1`.
