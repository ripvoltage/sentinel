//! Shannon entropy calculation for data buffers and byte histograms.
//!
//! High Shannon entropy (approaching 8.0 bits/byte) in file write buffers is a strong
//! indicator of encrypted or compressed payloads characteristic of ransomware encryption phases.
//!
//! Uses zero-heap stack-allocated `[u32; 256]` buffers for frequency counting.

/// Shannon entropy threshold (bits per byte) above which data is classified as high-entropy / encrypted.
pub const ENTROPY_THRESHOLD: f64 = 7.92;

/// Calculates the Shannon entropy $H(X) = -\sum_{i=0}^{255} p(x_i) \log_2(p(x_i))$ of a byte slice.
///
/// Returns `0.0` for empty inputs. Operates entirely on the stack with zero heap allocation.
///
/// # Arguments
/// * `data` - Raw byte slice to evaluate.
///
/// # Returns
/// Floating point entropy value in the range `[0.0, 8.0]`.
#[inline]
#[allow(dead_code)]
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    calculate_entropy_from_histogram(&counts, data.len())
}

/// Calculates Shannon entropy from a pre-computed 256-bin byte frequency histogram.
///
/// Used when the histogram is pre-aggregated inside the eBPF kernel probe (`IoEvent::byte_counts`)
/// to avoid transferring raw payload buffers into userspace.
///
/// # Arguments
/// * `counts` - Array of 256 byte frequency counts.
/// * `total` - Total number of bytes represented in the histogram.
///
/// # Returns
/// Floating point entropy value in the range `[0.0, 8.0]`. Returns `0.0` if `total == 0`.
#[inline]
pub fn calculate_entropy_from_histogram(counts: &[u32; 256], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }

    let total_f = total as f64;
    let mut entropy = 0.0;

    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / total_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Evaluates whether a given Shannon entropy value meets or exceeds [`ENTROPY_THRESHOLD`].
///
/// # Arguments
/// * `entropy` - Shannon entropy in bits per byte (`0.0..=8.0`).
///
/// # Returns
/// `true` if `entropy >= ENTROPY_THRESHOLD`, `false` otherwise.
#[inline]
#[allow(dead_code)]
pub fn is_high_entropy(entropy: f64) -> bool {
    entropy >= ENTROPY_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_same_bytes() {
        // Uniform identical bytes should have an entropy of exactly 0.0
        let data = vec![0x55u8; 4096];
        let entropy = calculate_entropy(&data);
        assert!(
            entropy.abs() < 1e-9,
            "Expected entropy ≈ 0.0 for uniform bytes, got {}",
            entropy
        );
        assert!(!is_high_entropy(entropy));
    }

    #[test]
    fn test_perfectly_distributed_bytes() {
        // Exactly equal frequencies of all 256 byte values should yield entropy of 8.0
        let mut data = Vec::with_capacity(256 * 100);
        for i in 0..25600 {
            data.push((i % 256) as u8);
        }

        let entropy = calculate_entropy(&data);
        assert!(
            (entropy - 8.0).abs() < 1e-9,
            "Expected entropy ≈ 8.0 for uniform distribution, got {}",
            entropy
        );
        assert!(is_high_entropy(entropy));
    }

    #[test]
    fn test_pseudo_random_data() {
        // High-quality pseudo-random data (using a 64-bit LCG PRNG) should exceed the 7.92 threshold
        let mut state: u64 = 0x853c49e6748fea9b;
        let mut data = Vec::with_capacity(16384);
        for _ in 0..16384 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            data.push((state >> 33) as u8);
        }

        let entropy = calculate_entropy(&data);
        assert!(
            is_high_entropy(entropy),
            "Expected PRNG data to be classified as high entropy (got {})",
            entropy
        );
        assert!(entropy >= ENTROPY_THRESHOLD);
    }

    #[test]
    fn test_repeated_text_data() {
        // Natural language ASCII text has moderate entropy (typically 3.5 - 5.5)
        let sample = b"The quick brown fox jumps over the lazy dog. Ransomware detection daemon test payload with standard English text distribution.\n";
        let mut data = Vec::new();
        for _ in 0..50 {
            data.extend_from_slice(sample);
        }

        let entropy = calculate_entropy(&data);
        assert!(
            !is_high_entropy(entropy),
            "Repeated text data should not trigger high entropy threshold (got {})",
            entropy
        );
        assert!(
            entropy >= 3.0 && entropy <= 6.0,
            "Expected text entropy in range [3.0, 6.0], got {}",
            entropy
        );
    }

    #[test]
    fn test_empty_data() {
        assert_eq!(calculate_entropy(&[]), 0.0);

        let counts = [0u32; 256];
        assert_eq!(calculate_entropy_from_histogram(&counts, 0), 0.0);
    }

    #[test]
    fn test_direct_calculation_matches_histogram() {
        let mut state: u64 = 0x123456789ABCDEF0;
        let mut data = Vec::with_capacity(4096);
        let mut counts = [0u32; 256];

        for _ in 0..4096 {
            state = state.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
            let byte = ((state >> 24) % 256) as u8;
            data.push(byte);
            counts[byte as usize] += 1;
        }

        let direct = calculate_entropy(&data);
        let from_hist = calculate_entropy_from_histogram(&counts, data.len());

        assert!(
            (direct - from_hist).abs() < 1e-9,
            "Direct calculation ({}) must match histogram calculation ({})",
            direct,
            from_hist
        );
    }
}
