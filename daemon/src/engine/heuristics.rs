//! Behavioral heuristics engine for detecting ransomware activity.
//!
//! Evaluates runtime file system I/O patterns across multiple indicators:
//! - Rapid I/O burst frequency (> 50 operations per 100ms window)
//! - High Shannon entropy in write payloads (>= 7.92 bits/byte)
//! - Suspicious file extension changes (e.g. `.encrypted`, `.locked`)
//! - File unlinking/deletion following recent high-entropy writes

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};

use ebpf_common::EventType;

use super::entropy::ENTROPY_THRESHOLD;

/// Verdict resulting from heuristic analysis of an I/O event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeuristicVerdict {
    /// The event is considered normal system or application activity.
    Benign,
    /// The event matches one or more ransomware behavioral heuristics.
    Suspicious {
        /// Human-readable descriptions of triggered heuristics.
        reasons: Vec<String>,
        /// Cumulative threat score in the range [1, 100].
        score: u32,
    },
}

/// Behavioral heuristics engine tracking process I/O rates and patterns.
pub struct HeuristicsEngine {
    /// Per-PID sliding window of operation timestamps for rate detection.
    pub op_timestamps: HashMap<u32, VecDeque<Instant>>,
    /// Per-PID rename history storing `(old_extension, new_extension)`.
    pub rename_tracker: HashMap<u32, Vec<(String, String)>>,
    /// Set of known suspicious/ransomware file extensions.
    pub suspicious_extensions: HashSet<String>,
    /// Per-PID timestamp of the most recent high-entropy write operation.
    pub recent_high_entropy_writes: HashMap<u32, Instant>,
}

impl HeuristicsEngine {
    /// Creates a new `HeuristicsEngine` with the default known ransomware extension set.
    pub fn new() -> Self {
        let raw_extensions = [
            "encrypted",
            "locked",
            "cry",
            "crypt",
            "locky",
            "cerber",
            "zepto",
            "thor",
            "aaa",
            "zzz",
            "micro",
            "enc",
            "crypted",
            "cryptolocker",
        ];

        let mut suspicious_extensions = HashSet::with_capacity(raw_extensions.len() * 2);
        for &ext in &raw_extensions {
            suspicious_extensions.insert(ext.to_string());
            suspicious_extensions.insert(format!(".{}", ext));
        }

        Self {
            op_timestamps: HashMap::new(),
            rename_tracker: HashMap::new(),
            suspicious_extensions,
            recent_high_entropy_writes: HashMap::new(),
        }
    }

    /// Evaluates an I/O event and returns a [`HeuristicVerdict`].
    ///
    /// # Arguments
    /// * `pid` - Process ID performing the operation.
    /// * `path` - Target file path of the operation.
    /// * `new_path` - Destination file path (for `Rename` operations).
    /// * `event_type` - Type of file system event (`VfsWrite`, `Rename`, `Unlink`).
    /// * `entropy` - Shannon entropy computed for write payloads.
    pub fn evaluate(
        &mut self,
        pid: u32,
        path: &str,
        new_path: Option<&str>,
        event_type: EventType,
        entropy: f64,
    ) -> HeuristicVerdict {
        let now = Instant::now();
        let mut reasons = Vec::new();
        let mut score: u32 = 0;

        // 1. Record timestamp in sliding window for this PID
        let timestamps = self.op_timestamps.entry(pid).or_default();
        timestamps.push_back(now);

        // 2. Count ops in last 100ms. If > 50, add reason and score += 30
        let window_100ms = Duration::from_millis(100);
        let cutoff_100ms = now.checked_sub(window_100ms).unwrap_or(now);

        // Evict older timestamps at head to prevent memory bloat
        while let Some(&front) = timestamps.front() {
            if front < cutoff_100ms && timestamps.len() > 100 {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        let ops_last_100ms = timestamps.iter().filter(|&&ts| ts >= cutoff_100ms).count();
        if ops_last_100ms > 50 {
            reasons.push(format!(
                "High I/O frequency: {} ops/100ms",
                ops_last_100ms
            ));
            score += 30;
        }

        // 3. If entropy >= ENTROPY_THRESHOLD, add reason and score += 40
        if entropy >= ENTROPY_THRESHOLD {
            reasons.push(format!(
                "High entropy write payload: {:.2} (threshold: {:.2})",
                entropy, ENTROPY_THRESHOLD
            ));
            score += 40;
            self.recent_high_entropy_writes.insert(pid, now);
        }

        // 4. If event is Rename, extract extensions from old and new path.
        //    If new extension is in suspicious set, add reason and score += 20
        if event_type == EventType::Rename {
            let old_ext = extract_extension(path);
            let new_ext = new_path.map(extract_extension).unwrap_or_default();

            self.rename_tracker
                .entry(pid)
                .or_default()
                .push((old_ext.clone(), new_ext.clone()));

            if self.suspicious_extensions.contains(&new_ext)
                || self.suspicious_extensions.contains(&format!(".{}", new_ext))
            {
                reasons.push(format!(
                    "Suspicious file extension modification to '.{}' (from '{}' to '{}')",
                    new_ext,
                    path,
                    new_path.unwrap_or("")
                ));
                score += 20;
            }
        }

        // 5. If event is Unlink and entropy was high on recent writes from same PID, add reason and score += 10
        if event_type == EventType::Unlink {
            if let Some(&last_high_entropy) = self.recent_high_entropy_writes.get(&pid) {
                if now.duration_since(last_high_entropy) <= Duration::from_secs(5) {
                    reasons.push(
                        "File deletion (unlink) following recent high-entropy write operation"
                            .to_string(),
                    );
                    score += 10;
                }
            }
        }

        // 6. Return Suspicious if score > 0, else Benign
        if score > 0 {
            HeuristicVerdict::Suspicious {
                reasons,
                score: score.min(100),
            }
        } else {
            HeuristicVerdict::Benign
        }
    }

    /// Removes timestamp and rename tracking records older than `max_age`.
    pub fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        let cutoff = now.checked_sub(max_age).unwrap_or(now);

        // Clean up sliding window timestamps
        self.op_timestamps.retain(|_, timestamps| {
            while let Some(&front) = timestamps.front() {
                if front < cutoff {
                    timestamps.pop_front();
                } else {
                    break;
                }
            }
            !timestamps.is_empty()
        });

        // Clean up high-entropy write markers
        self.recent_high_entropy_writes
            .retain(|_, &mut last_seen| last_seen >= cutoff);

        // Clean up rename tracker for inactive PIDs
        let active_pids: HashSet<u32> = self.op_timestamps.keys().copied().collect();
        self.rename_tracker.retain(|pid, _| active_pids.contains(pid));
    }
}

impl Default for HeuristicsEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts file extension in lowercase without leading dot.
fn extract_extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benign_evaluation() {
        let mut engine = HeuristicsEngine::new();
        let verdict = engine.evaluate(1234, "/home/user/document.txt", None, EventType::VfsWrite, 4.5);
        assert_eq!(verdict, HeuristicVerdict::Benign);
    }

    #[test]
    fn test_high_entropy_detection() {
        let mut engine = HeuristicsEngine::new();
        let verdict = engine.evaluate(1234, "/home/user/document.txt", None, EventType::VfsWrite, 7.95);
        match verdict {
            HeuristicVerdict::Suspicious { reasons, score } => {
                assert_eq!(score, 40);
                assert_eq!(reasons.len(), 1);
                assert!(reasons[0].contains("High entropy write payload"));
            }
            HeuristicVerdict::Benign => panic!("Expected Suspicious verdict for high entropy write"),
        }
    }

    #[test]
    fn test_high_io_frequency_burst() {
        let mut engine = HeuristicsEngine::new();
        let pid = 2345;

        // Perform 50 low-entropy writes (below burst threshold)
        for _ in 0..50 {
            let verdict = engine.evaluate(pid, "/home/user/file.txt", None, EventType::VfsWrite, 4.0);
            assert_eq!(verdict, HeuristicVerdict::Benign);
        }

        // 51st write pushes frequency over 50 ops/100ms
        let verdict = engine.evaluate(pid, "/home/user/file.txt", None, EventType::VfsWrite, 4.0);
        match verdict {
            HeuristicVerdict::Suspicious { reasons, score } => {
                assert_eq!(score, 30);
                assert!(reasons[0].contains("High I/O frequency"));
            }
            HeuristicVerdict::Benign => panic!("Expected High I/O frequency detection"),
        }
    }

    #[test]
    fn test_suspicious_rename_extension() {
        let mut engine = HeuristicsEngine::new();
        let verdict = engine.evaluate(
            3456,
            "/home/user/family_photo.jpg",
            Some("/home/user/family_photo.jpg.encrypted"),
            EventType::Rename,
            5.0,
        );

        match verdict {
            HeuristicVerdict::Suspicious { reasons, score } => {
                assert_eq!(score, 20);
                assert!(reasons[0].contains("Suspicious file extension modification"));
            }
            HeuristicVerdict::Benign => panic!("Expected Suspicious verdict for .encrypted rename"),
        }
    }

    #[test]
    fn test_unlink_after_high_entropy_write() {
        let mut engine = HeuristicsEngine::new();
        let pid = 4567;

        // Initial high-entropy write
        let v1 = engine.evaluate(pid, "/home/user/data.bin", None, EventType::VfsWrite, 7.96);
        assert!(matches!(v1, HeuristicVerdict::Suspicious { score: 40, .. }));

        // Subsequent unlink of another file by same PID
        let v2 = engine.evaluate(pid, "/home/user/original.docx", None, EventType::Unlink, 0.0);
        match v2 {
            HeuristicVerdict::Suspicious { reasons, score } => {
                assert_eq!(score, 10);
                assert!(reasons[0].contains("File deletion (unlink) following recent high-entropy write"));
            }
            HeuristicVerdict::Benign => panic!("Expected Unlink after high-entropy to trigger score"),
        }
    }

    #[test]
    fn test_combined_indicators_score_accumulation() {
        let mut engine = HeuristicsEngine::new();
        let pid = 5678;

        // Build up 50 operations
        for _ in 0..50 {
            engine.evaluate(pid, "/home/user/file.tmp", None, EventType::VfsWrite, 4.0);
        }

        // 51st operation: high entropy + high rate + suspicious rename
        let verdict = engine.evaluate(
            pid,
            "/home/user/report.pdf",
            Some("/home/user/report.pdf.locky"),
            EventType::Rename,
            7.98,
        );

        match verdict {
            HeuristicVerdict::Suspicious { reasons, score } => {
                // Burst (30) + Entropy (40) + Rename (20) = 90
                assert_eq!(score, 90);
                assert_eq!(reasons.len(), 3);
            }
            HeuristicVerdict::Benign => panic!("Expected multiple heuristic triggers"),
        }
    }

    #[test]
    fn test_cleanup_stale_records() {
        let mut engine = HeuristicsEngine::new();
        let pid = 6789;

        engine.evaluate(pid, "/home/user/file.txt", None, EventType::VfsWrite, 7.95);
        assert_eq!(engine.op_timestamps.len(), 1);
        assert_eq!(engine.recent_high_entropy_writes.len(), 1);

        // Immediate cleanup with 0 max_age should purge all entries
        engine.cleanup_stale(Duration::from_millis(0));
        assert!(engine.op_timestamps.is_empty());
        assert!(engine.recent_high_entropy_writes.is_empty());
    }
}
