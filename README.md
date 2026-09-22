[README.md](https://github.com/user-attachments/files/32532438/README.md)
# Sentinel Anti-Ransomware

```
  ____  _____ _   _ _____ ___ _   _ _____ _     
 / ___|| ____| \ | |_   _|_ _| \ | | ____| |    
 \___ \|  _| |  \| | | |  | ||  \| |  _| | |    
  ___) | |___| |\  | | |  | || |\  | |___| |___ 
 |____/|_____|_| \_| |_| |___|_| \_|_____|_____|
      Active Behavioral Anti-Ransomware for Linux
```

Sentinel is a high-performance, real-time behavioral anti-ransomware daemon designed for GNU/Linux operating systems. Rather than relying on signature databases or static hash lists, Sentinel monitors active filesystem operations directly at the kernel boundary. It analyzes I/O rate patterns, mathematical entropy distributions, and decoy interaction to intercept and neutralize ransomware payloads within milliseconds of execution.

---

## Architecture Overview

```
+-------------------------------------------------------------------------+
|                           KERNEL SPACE                                  |
|                                                                         |
|  [vfs_write] --------+                                                  |
|  [sys_enter_rename] -+-> [eBPF Probes] -> [BPF Ring Buffer (EVENTS)] --+
|  [sys_enter_unlink] -+                                                 |
|                                                                        |
|  [VFS Subsystem] ------> [Linux Fanotify (FAN_MODIFY / FAN_CLOSE)] ----+
+------------------------------------------------------------------------|
                                                                         |
+------------------------------------------------------------------------v+
|                          USERSPACE DAEMON                               |
|                                                                         |
|   +------------------------------------------------------------------+  |
|   |                    Event Ingestion Pipeline                      |  |
|   +------------------------------------------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|   +------------------------------------------------------------------+  |
|   | Shannon Entropy Calculation  | Canary Path Matcher               |  |
|   | H(X) = -SUM(p * log2(p))     | Path in ~/.canary_sentinel        |  |
|   +------------------------------------------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|   +------------------------------------------------------------------+  |
|   | Behavioral Heuristics Engine                                     |  |
|   | - I/O Frequency Burst (>50 ops / 100ms)                [+30 pts] |  |
|   | - High Shannon Entropy Payload (H >= 7.92)             [+40 pts] |  |
|   | - Suspicious Rename Extension (.encrypted, .locked...) [+20 pts] |  |
|   | - Rapid Deletion Post High-Entropy Write               [+10 pts] |  |
|   +------------------------------------------------------------------+  |
|                                    |                                    |
|                      Score >= 40 OR Canary Trigger                      |
|                                    |                                    |
|                                    v                                    |
|   +------------------------------------------------------------------+  |
|   | Anti-False-Positive Filter (proc_inspector)                      |  |
|   | - Whitelist Check (tar, rsync, gcc, gzip, gpg, etc.)             |  |
|   | - Ancestor Walk (Up to 5 PPID levels): Shell under Terminal?     |  |
|   +------------------------------------------------------------------+  |
|                                    |                                    |
|                           Threat Confirmed                              |
|                                    |                                    |
|                                    v                                    |
|   +------------------------------------------------------------------+  |
|   | Threat Neutralization Protocol                                   |  |
|   | 1. Freeze Process: kill(PID, SIGSTOP)                            |  |
|   | 2. Queue Settling Pause: usleep(100000) (100ms)                  |  |
|   | 3. Terminate Process: kill(PID, SIGKILL)                         |  |
|   +------------------------------------------------------------------+  |
|                                    |                                    |
|         +--------------------------+-------------------------+          |
|         |                          |                         |          |
|         v                          v                         v          |
|  [CoW Snapshot]             [Desktop Alert]           [Forensic Audit]  |
|  Btrfs/ZFS Rollback        notify-send under UID      JSON alerts.log   |
+-------------------------------------------------------------------------+
```

---

## Key Detection Mechanisms

Sentinel evaluates suspicious activity using two independent defense layers:

### 1. The Canary Honeypot System
During initialization, Sentinel automatically provisions decoy directories:
- `~/.canary_sentinel/` (for every user directory under `/home/*`)
- `/root/.canary_sentinel/`

Each directory is populated with six realistic synthetic documents:
- `important_document.docx`
- `financial_report.xlsx`
- `family_photos.zip`
- `passwords.txt`
- `bitcoin_wallet.dat`
- `tax_return_2024.pdf`

Decoy file ownership is mapped to the target user UID/GID so unprivileged malware can access and modify them. Any write, rename, or deletion operation affecting a path containing `.canary_sentinel` is treated as an instantaneous, high-fidelity intrusion indicator. It bypasses the point accumulation requirement and triggers immediate neutralization.

### 2. The Behavioral Heuristics Engine
When general files are modified across the filesystem, the heuristic engine calculates an aggregate threat score for the calling process:

| Heuristic Indicator | Condition | Points | Rationale |
|---------------------|-----------|--------|-----------|
| Shannon Entropy Burst | Write payload entropy >= 7.92 bits/byte | +40 | Encrypted ciphertext exhibits near-maximum random byte distribution |
| Rapid I/O Rate | > 50 filesystem operations in 100ms | +30 | Automated mass encryption occurs at superhuman speeds |
| Suspicious Extension | File renamed to `.encrypted`, `.locked`, `.cry`, `.crypt`, `.locky`, `.enc`, etc. | +20 | Ransomware systematically alters file extensions to notify victim |
| Destructive Unlink | File deletion within 5s of high-entropy write by same PID | +10 | Ransomware frequently writes an encrypted copy and deletes the original |

If a process accumulates a score of **40 points or higher**, or touches a canary honeypot, it is declared an active threat.

### 3. Shannon Entropy Formula
Entropy calculation evaluates the randomness of bytes in write buffers:

$$H(X) = -\sum_{i=0}^{255} p(x_i) \log_2(p(x_i))$$

Where $p(x_i) = \frac{\text{count}(x_i)}{\text{total}}$.
- Plain text typically yields $H \in [3.0, 5.5]$.
- Executable binaries typically yield $H \in [5.5, 6.8]$.
- Compressed archives typically yield $H \in [7.0, 7.7]$.
- Strong modern encryption (AES, ChaCha20) yields $H \ge 7.92$.

Sentinel computes entropy directly from 256-bin frequency histograms with zero heap allocations.

---

## Anti-False-Positive Filtering (proc_inspector)

Legitimate administrative tools (compilers, archivers, package managers) often perform rapid I/O or write compressed data. Sentinel prevents false alarms using a two-stage inspection protocol:

1. **Binary Whitelist**: The process executable name and comm are checked against trusted utilities (`tar`, `gzip`, `xz`, `zstd`, `gpg`, `openssl`, `rsync`, `cp`, `mv`, `dd`, `git`, `cargo`, `rustc`, `gcc`, `clang`, `make`, `cmake`, `ninja`, `python3`, `apt`, `dnf`, `pacman`, `docker`, `podman`, `logrotate`, etc.).
2. **Interactive Ancestor Walk**: If an untrusted process exhibits ransomware-like behavior, Sentinel parses `/proc/<PID>/stat` and walks the parent process chain up to 5 levels. If it detects an interactive user shell (`bash`, `zsh`, `fish`, etc.) running inside a terminal emulator (`gnome-terminal`, `konsole`, `alacritty`, `kitty`, `tmux`, `screen`), the alert is suppressed as an interactive user command.

This design targets background malware payloads (cron jobs, compromised background services, injected web-shell workers) while preserving developer workflows.

---

## Threat Neutralization Protocol

When a threat is confirmed, Sentinel executes an atomic three-stage defense sequence:

1. **Stage 1 (SIGSTOP Freeze)**: Sends `SIGSTOP` to the offending PID. This instantaneously halts CPU scheduling for the malicious threads, freezing disk writes while preserving memory state.
2. **Stage 2 (Queue Settling Pause)**: Waits 100 milliseconds to permit kernel I/O pipelines and filesystem write-back queues to flush.
3. **Stage 3 (SIGKILL Termination)**: Delivers an unconditional `SIGKILL` signal to eradicate the process from memory.

**Self-Defense**: Sentinel verifies process IDs before dispatching signals. It refuses to target its own PID or system init (`PID <= 1`).

---

## Forensic Audit & Remediation

### Structured JSON Audit Logging
All incidents are appended in real time to `/var/log/ransomware-detector/alerts.log` (with fallback to `./logs/alerts.log` if unprivileged):

```json
{
  "timestamp": "2026-09-22T14:48:26-0300",
  "timestamp_utc": "2026-09-22T17:48:26Z",
  "pid": 55500,
  "uid": 1000,
  "gid": 1000,
  "exe": "/home/niko/Documentos/SENTINEL++/bin/canary_tester",
  "cmdline": "./bin/canary_tester",
  "entropy": 7.6012,
  "rule": "Canary File Modified | Suspicious file extension modification to '.encrypted'",
  "action": "Process neutralized: SIGSTOP + SIGKILL",
  "affected_files": [
    "/home/niko/.canary_sentinel/passwords.txt",
    "/home/niko/.canary_sentinel/passwords.txt.encrypted"
  ]
}
```

### Copy-on-Write (CoW) Remediation
Sentinel detects filesystems with subvolume snapshot support (`Btrfs` and `OpenZFS`):
- **Preventive Snapshots**: Creates read-only snapshots of `/home` and `/` on startup (`ransomware-guard-<timestamp>`).
- **Automated Rollback**: Attempts instantaneous subvolume restoration if encrypted files are detected.

### Native Desktop Alerts
Sentinel inspects active interactive sessions under `/run/user/<UID>/bus`. It temporarily assumes the victim's UID credentials, connects to the user's D-Bus session, and dispatches a critical desktop notification via `notify-send` with affected file telemetry.

---

## Dual Event Ingestion for Generic Linux Distribution

To ensure universal portability across any GNU/Linux distribution:

1. **eBPF Mode**: When compiled kernel probes (`sentinel-ebpf.o`) and `libbpf` are present, Sentinel attaches kprobes (`vfs_write`) and tracepoints (`sys_enter_renameat2`, `sys_enter_unlinkat`) using an in-kernel zero-copy ring buffer.
2. **Native Fanotify Mode**: If eBPF probes are absent or unsupported, Sentinel automatically falls back to native Linux `fanotify`. It monitors filesystem mounts directly through the kernel VFS subsystem, providing zero-dependency operation on any modern Linux kernel (3.x+).

---

## Binary Hardening and Security Flags

The build system enforces strict compiler hardening flags:

```makefile
CFLAGS = -std=c99 -D_GNU_SOURCE -O2 \
         -Wall -Wextra -Wpedantic \
         -Wformat=2 -Wformat-security -Werror=format-security \
         -D_FORTIFY_SOURCE=2 \
         -fstack-protector-strong \
         -fstack-clash-protection \
         -fcf-protection=full \
         -fPIE \
         -Iinclude

LDFLAGS = -pie \
          -Wl,-z,relro,-z,now \
          -Wl,-z,noexecstack \
          -lm -lpthread -ldl
```

### Security Properties Verified:
- **Full RELRO (`-z,relro -z,now`)**: Read-Only Relocations prevent Global Offset Table (GOT) overwrite attacks.
- **Stack Canaries (`-fstack-protector-strong`)**: Protects against buffer overflow exploits.
- **Stack Clash Protection (`-fstack-clash-protection`)**: Guards against multi-page stack exhaustion.
- **Control Flow Integrity (`-fcf-protection=full`)**: Intel CET / indirect branch tracking.
- **Position Independent Executable (`-fPIE -pie`)**: Full ASLR compatibility.
- **Non-Executable Stack (`-z,noexecstack`)**: Prohibits shellcode execution in stack pages.
- **Fortified Glibc (`-D_FORTIFY_SOURCE=2`)**: Bounds-checked string and memory functions.

---

## Project Structure

```
SENTINEL++/
├── bin/
│   ├── sentinel              # Compiled hardened daemon binary
│   ├── canary_tester         # Ransomware simulation testing tool
│   └── test_suite            # Comprehensive verification test harness
├── build/                    # Intermediate object files (.o)
├── ebpf/
│   └── sentinel.bpf.c        # Pure C eBPF kernel probes
├── include/
│   ├── sentinel.h            # Primary data models and definitions
│   ├── entropy.h             # Shannon entropy calculations
│   ├── canaries.h            # Honeypot decoy management
│   ├── heuristics.h          # Behavioral scoring and rate tracking
│   ├── proc_inspector.h      # Process tree inspection and whitelist
│   ├── defense.h             # Process freeze and kill operations
│   ├── cow_remediation.h     # CoW snapshot management
│   ├── notification.h        # GNOME desktop notification dispatch
│   ├── logger.h              # Structured JSON audit logging
│   ├── ebpf_loader.h         # Dynamic libbpf loader
│   └── monitor.h             # Dual event monitor (eBPF + fanotify)
├── src/
│   ├── main.c                # Daemon entry point & lifecycle
│   ├── entropy.c             # Entropy implementation
│   ├── canaries.c            # Decoy creation and validation
│   ├── heuristics.c          # Sliding window heuristic logic
│   ├── proc_inspector.c      # /proc parsing & ancestor traversal
│   ├── defense.c             # Signal delivery logic
│   ├── cow_remediation.c     # Btrfs/ZFS snapshot logic
│   ├── notification.c        # D-Bus session alert delivery
│   ├── logger.c              # alerts.log and console output
│   ├── ebpf_loader.c         # eBPF dynamic linking logic
│   └── monitor.c             # Unified event ingestion loop
├── tools/
│   └── canary_tester.c       # Decoy targeting attack tool
├── tests/
│   └── test_suite.c          # 30-assertion validation suite
└── Makefile                  # Hardened build automation
```

---

## Building and Installation

### Prerequisites
- GCC 9+ or Clang
- GNU Make
- Linux Kernel 3.8+ (fanotify support) or 5.8+ (for eBPF probes)
- Standard development headers (`glibc-devel`)

### Compilation
Build all binaries (`sentinel`, `canary_tester`, and `test_suite`):

```bash
make all
```

Run the automated verification suite:

```bash
make test
```

### Installation
Install Sentinel system-wide:

```bash
sudo make install
```

This places the binary at `/usr/local/bin/sentinel` and provisions the log directory at `/var/log/ransomware-detector/`.

---

## Usage Guide

### Starting the Daemon
Sentinel must run as `root` (`CAP_SYS_ADMIN` + `CAP_SYS_PTRACE`) to attach filesystem monitors and terminate malicious processes:

```bash
sudo ./bin/sentinel
```

#### Command-Line Options:
```
Usage: ./bin/sentinel [OPTIONS]

Options:
  -b, --bpf-path <path>  Path to eBPF object file (default: /usr/lib/sentinel/sentinel-ebpf.o)
  -v, --version          Show version information
  -h, --help             Show this help message
```

#### Logging Level:
Adjust logging verbosity using the `SENTINEL_LOG` environment variable:
```bash
sudo SENTINEL_LOG=debug ./bin/sentinel
```

---

## Testing Sentinel with Canary Tester

To verify that Sentinel detects and neutralizes attacks:

1. **Start Sentinel in Terminal 1**:
   ```bash
   sudo ./bin/sentinel
   ```

2. **Run Canary Tester in Terminal 2**:
   ```bash
   ./bin/canary_tester
   ```

3. **Background Simulation (Simulating background malware)**:
   ```bash
   ./bin/canary_tester --background
   ```

When executed, `canary_tester` writes encrypted payloads into the decoy files under `~/.canary_sentinel/` and renames them to `.encrypted`. Sentinel will immediately intercept the operations, freeze the offending process via `SIGSTOP`, terminate it via `SIGKILL`, write an audit entry to `/var/log/ransomware-detector/alerts.log`, and emit a desktop alert.

---

## License

This project is licensed under the GPL-2.0.
