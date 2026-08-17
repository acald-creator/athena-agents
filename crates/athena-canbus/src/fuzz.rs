//! Deterministic CAN Bus fuzzer using xoshiro256++ PRNG.
//!
//! Generates random CAN frames with IDs within a configurable range and
//! random payloads (0–8 bytes), transmitting them via SocketCAN. The
//! deterministic seed ensures reproducibility.

use std::time::Instant;

use rand::Rng;
use rand::SeedableRng;
use rand_xoshiro::Xoshiro256PlusPlus;

use athena_common::CanFuzzSummary;

use crate::socket::{CanSocket, CanSocketError, RawCanFrame};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a CAN fuzz run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanFuzzConfig {
    /// SocketCAN interface name (e.g., "vcan0").
    pub interface: String,
    /// PRNG seed for deterministic reproduction.
    pub seed: u64,
    /// Number of frames to generate and transmit.
    pub iterations: u32,
    /// Start of the CAN ID range (inclusive).
    pub id_range_start: u32,
    /// End of the CAN ID range (inclusive).
    pub id_range_end: u32,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a fuzz configuration.
///
/// Checks:
/// - `iterations` must be 1–1,000,000
/// - `id_range_start` must be <= `id_range_end`
/// - `id_range_end` must not exceed the maximum extended CAN ID (0x1FFFFFFF)
pub fn validate_fuzz_config(config: &CanFuzzConfig) -> Result<(), String> {
    if config.iterations < 1 || config.iterations > 1_000_000 {
        return Err(format!(
            "iterations must be 1–1000000, got {}",
            config.iterations
        ));
    }
    if config.id_range_start > config.id_range_end {
        return Err(format!(
            "id_range_start (0x{:X}) must be <= id_range_end (0x{:X})",
            config.id_range_start, config.id_range_end
        ));
    }
    if config.id_range_end > 0x1FFFFFFF {
        return Err(format!(
            "id_range_end 0x{:X} exceeds maximum CAN ID 0x1FFFFFFF",
            config.id_range_end
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Frame generation (pure, no I/O — testable without sockets)
// ---------------------------------------------------------------------------

/// Generate random CAN frames deterministically without sending.
///
/// Returns a vector of `(id, data)` tuples where:
/// - `id` is within `[id_range.0, id_range.1]`
/// - `data` is 0–8 random bytes
///
/// The same `seed` always produces the same sequence.
pub fn generate_fuzz_frames(
    seed: u64,
    iterations: u32,
    id_range: (u32, u32),
) -> Vec<(u32, Vec<u8>)> {
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed);

    (0..iterations)
        .map(|_| {
            let id = rng.gen_range(id_range.0..=id_range.1);
            let dlc = rng.gen_range(0..=8u8);
            let data: Vec<u8> = (0..dlc).map(|_| rng.gen()).collect();
            (id, data)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Fuzz execution (requires SocketCAN)
// ---------------------------------------------------------------------------

/// Run the CAN fuzzer, transmitting generated frames via SocketCAN.
///
/// On non-Linux platforms this will return `CanSocketError::NotSupported`
/// from `CanSocket::open`.
pub fn run_can_fuzz(config: &CanFuzzConfig) -> Result<CanFuzzSummary, CanSocketError> {
    let socket = CanSocket::open(&config.interface)?;
    let frames = generate_fuzz_frames(
        config.seed,
        config.iterations,
        (config.id_range_start, config.id_range_end),
    );

    let start = Instant::now();
    let mut frame_count = 0u32;

    for (id, data) in &frames {
        // IDs above 0x7FF require extended frame format
        let extended = *id > 0x7FF;
        let raw = RawCanFrame::new(*id, extended, data);
        socket.send_frame(&raw)?;
        frame_count += 1;
    }

    Ok(CanFuzzSummary {
        seed: config.seed,
        interface: config.interface.clone(),
        iterations_completed: config.iterations,
        id_range: (config.id_range_start, config.id_range_end),
        elapsed_ms: start.elapsed().as_millis() as u64,
        frame_count,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- validate_fuzz_config tests ---

    #[test]
    fn test_valid_config() {
        let config = CanFuzzConfig {
            interface: "vcan0".to_string(),
            seed: 42,
            iterations: 100,
            id_range_start: 0,
            id_range_end: 0x7FF,
        };
        assert!(validate_fuzz_config(&config).is_ok());
    }

    #[test]
    fn test_iterations_zero_rejected() {
        let config = CanFuzzConfig {
            interface: "vcan0".to_string(),
            seed: 42,
            iterations: 0,
            id_range_start: 0,
            id_range_end: 0x7FF,
        };
        let result = validate_fuzz_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("iterations"));
    }

    #[test]
    fn test_iterations_above_max_rejected() {
        let config = CanFuzzConfig {
            interface: "vcan0".to_string(),
            seed: 42,
            iterations: 1_000_001,
            id_range_start: 0,
            id_range_end: 0x7FF,
        };
        let result = validate_fuzz_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("iterations"));
    }

    #[test]
    fn test_iterations_at_min_boundary_valid() {
        let config = CanFuzzConfig {
            interface: "vcan0".to_string(),
            seed: 0,
            iterations: 1,
            id_range_start: 0,
            id_range_end: 0,
        };
        assert!(validate_fuzz_config(&config).is_ok());
    }

    #[test]
    fn test_iterations_at_max_boundary_valid() {
        let config = CanFuzzConfig {
            interface: "vcan0".to_string(),
            seed: 0,
            iterations: 1_000_000,
            id_range_start: 0,
            id_range_end: 0x7FF,
        };
        assert!(validate_fuzz_config(&config).is_ok());
    }

    #[test]
    fn test_id_range_inverted_rejected() {
        let config = CanFuzzConfig {
            interface: "vcan0".to_string(),
            seed: 42,
            iterations: 100,
            id_range_start: 0x200,
            id_range_end: 0x100,
        };
        let result = validate_fuzz_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("id_range_start"));
    }

    #[test]
    fn test_id_range_end_exceeds_max_rejected() {
        let config = CanFuzzConfig {
            interface: "vcan0".to_string(),
            seed: 42,
            iterations: 100,
            id_range_start: 0,
            id_range_end: 0x20000000,
        };
        let result = validate_fuzz_config(&config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn test_id_range_equal_start_end_valid() {
        let config = CanFuzzConfig {
            interface: "vcan0".to_string(),
            seed: 42,
            iterations: 10,
            id_range_start: 0x100,
            id_range_end: 0x100,
        };
        assert!(validate_fuzz_config(&config).is_ok());
    }

    // --- generate_fuzz_frames tests ---

    #[test]
    fn test_deterministic_same_seed_same_output() {
        let frames1 = generate_fuzz_frames(42, 50, (0, 0x7FF));
        let frames2 = generate_fuzz_frames(42, 50, (0, 0x7FF));
        assert_eq!(frames1, frames2);
    }

    #[test]
    fn test_different_seeds_different_output() {
        let frames1 = generate_fuzz_frames(42, 50, (0, 0x7FF));
        let frames2 = generate_fuzz_frames(43, 50, (0, 0x7FF));
        // Statistically almost certain to differ
        assert_ne!(frames1, frames2);
    }

    #[test]
    fn test_correct_iteration_count() {
        let frames = generate_fuzz_frames(99, 200, (0, 0x7FF));
        assert_eq!(frames.len(), 200);
    }

    #[test]
    fn test_ids_within_range() {
        let frames = generate_fuzz_frames(1234, 1000, (0x100, 0x200));
        for (id, _) in &frames {
            assert!(
                *id >= 0x100 && *id <= 0x200,
                "ID 0x{:X} outside range [0x100, 0x200]",
                id
            );
        }
    }

    #[test]
    fn test_ids_within_single_value_range() {
        let frames = generate_fuzz_frames(555, 10, (0x42, 0x42));
        for (id, _) in &frames {
            assert_eq!(*id, 0x42);
        }
    }

    #[test]
    fn test_data_length_within_bounds() {
        let frames = generate_fuzz_frames(777, 500, (0, 0x7FF));
        for (_, data) in &frames {
            assert!(
                data.len() <= 8,
                "data length {} exceeds maximum 8",
                data.len()
            );
        }
    }

    #[test]
    fn test_zero_iterations_produces_empty() {
        let frames = generate_fuzz_frames(42, 0, (0, 0x7FF));
        assert!(frames.is_empty());
    }

    #[test]
    fn test_extended_id_range() {
        let frames = generate_fuzz_frames(42, 100, (0x800, 0x1FFFFFFF));
        for (id, _) in &frames {
            assert!(
                *id >= 0x800 && *id <= 0x1FFFFFFF,
                "ID 0x{:X} outside extended range",
                id
            );
        }
    }

    // --- run_can_fuzz (platform) tests ---

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_run_can_fuzz_returns_not_supported_on_non_linux() {
        let config = CanFuzzConfig {
            interface: "vcan0".to_string(),
            seed: 42,
            iterations: 10,
            id_range_start: 0,
            id_range_end: 0x7FF,
        };
        let result = run_can_fuzz(&config);
        assert_eq!(result.unwrap_err(), CanSocketError::NotSupported);
    }
}
