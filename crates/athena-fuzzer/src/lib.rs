//! Protocol fuzzer core logic for Athena offensive primitives.
//!
//! This crate provides deterministic protocol-aware mutation generation using
//! the xoshiro256++ PRNG. Mutations are generated without sending network traffic,
//! producing structured JSON output for analysis and replay.

use athena_common::{FuzzerSummary, MutationRecord};
use rand::Rng;
use rand_xoshiro::Xoshiro256PlusPlus;
use rand::SeedableRng;
use std::time::Instant;

/// Supported protocol types for fuzzing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Tcp,
    Dns,
}

impl Protocol {
    /// Parse a protocol string, returning None for unrecognized values.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "http" => Some(Protocol::Http),
            "tcp" => Some(Protocol::Tcp),
            "dns" => Some(Protocol::Dns),
            _ => None,
        }
    }

    /// Return the protocol as a lowercase string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Tcp => "tcp",
            Protocol::Dns => "dns",
        }
    }
}

/// Configuration for a fuzzer run.
#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    /// Target address (host:port or similar).
    pub target: String,
    /// Protocol to fuzz.
    pub protocol: Protocol,
    /// PRNG seed for deterministic reproduction.
    pub seed: u64,
    /// Number of mutation iterations to generate.
    pub iterations: u32,
}

/// Validate the fuzzer configuration, returning an error message if invalid.
pub fn validate_config(config: &FuzzerConfig) -> Result<(), String> {
    if config.target.is_empty() {
        return Err("target must not be empty".to_string());
    }
    if config.iterations < 1 || config.iterations > 1_000_000 {
        return Err(format!(
            "iterations must be between 1 and 1000000, got {}",
            config.iterations
        ));
    }
    Ok(())
}

/// Generate a single HTTP mutation payload size based on the PRNG state.
///
/// HTTP mutations simulate random header mangling with payload sizes
/// ranging from 16 to 8192 bytes.
fn generate_http_mutation(rng: &mut Xoshiro256PlusPlus) -> usize {
    // HTTP header mangling: payloads range from 16 to 8192 bytes
    rng.gen_range(16..=8192)
}

/// Generate a single TCP mutation payload size based on the PRNG state.
///
/// TCP mutations simulate random flag combinations and payloads with sizes
/// ranging from 1 to 1500 bytes (MTU-aware).
fn generate_tcp_mutation(rng: &mut Xoshiro256PlusPlus) -> usize {
    // TCP flag manipulation + payload: 1 to 1500 bytes (MTU-aware)
    rng.gen_range(1..=1500)
}

/// Generate a single DNS mutation payload size based on the PRNG state.
///
/// DNS mutations simulate random query payloads with sizes ranging from
/// 12 to 512 bytes (standard DNS message limits).
fn generate_dns_mutation(rng: &mut Xoshiro256PlusPlus) -> usize {
    // DNS query payloads: 12 to 512 bytes (DNS message size limits)
    rng.gen_range(12..=512)
}

/// Run the protocol fuzzer with the given configuration.
///
/// Generates deterministic mutation records using xoshiro256++ PRNG seeded
/// from the configuration. Does NOT send network traffic — only generates
/// mutations for analysis.
///
/// Returns a `FuzzerSummary` containing all mutation records and timing data.
pub fn run_fuzzer(config: &FuzzerConfig) -> FuzzerSummary {
    let start = Instant::now();
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(config.seed);

    let protocol_str = config.protocol.as_str().to_string();
    let mut mutations = Vec::with_capacity(config.iterations as usize);

    for i in 0..config.iterations {
        let payload_size_bytes = match config.protocol {
            Protocol::Http => generate_http_mutation(&mut rng),
            Protocol::Tcp => generate_tcp_mutation(&mut rng),
            Protocol::Dns => generate_dns_mutation(&mut rng),
        };

        mutations.push(MutationRecord {
            iteration: i,
            payload_size_bytes,
            protocol: protocol_str.clone(),
        });
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;

    FuzzerSummary {
        seed: config.seed,
        protocol: protocol_str,
        iterations_completed: config.iterations,
        elapsed_ms,
        mutations,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_from_str_valid() {
        assert_eq!(Protocol::from_str("http"), Some(Protocol::Http));
        assert_eq!(Protocol::from_str("HTTP"), Some(Protocol::Http));
        assert_eq!(Protocol::from_str("tcp"), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_str("TCP"), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_str("dns"), Some(Protocol::Dns));
        assert_eq!(Protocol::from_str("DNS"), Some(Protocol::Dns));
    }

    #[test]
    fn test_protocol_from_str_invalid() {
        assert_eq!(Protocol::from_str(""), None);
        assert_eq!(Protocol::from_str("udp"), None);
        assert_eq!(Protocol::from_str("ftp"), None);
    }

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(Protocol::Http.as_str(), "http");
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Dns.as_str(), "dns");
    }

    #[test]
    fn test_validate_config_valid() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 1000,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_empty_target() {
        let config = FuzzerConfig {
            target: "".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 1000,
        };
        assert!(validate_config(&config).is_err());
        assert!(validate_config(&config).unwrap_err().contains("target"));
    }

    #[test]
    fn test_validate_config_iterations_zero() {
        let config = FuzzerConfig {
            target: "127.0.0.1:80".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 0,
        };
        assert!(validate_config(&config).is_err());
        assert!(validate_config(&config).unwrap_err().contains("iterations"));
    }

    #[test]
    fn test_validate_config_iterations_too_high() {
        let config = FuzzerConfig {
            target: "127.0.0.1:80".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 1_000_001,
        };
        assert!(validate_config(&config).is_err());
        assert!(validate_config(&config).unwrap_err().contains("iterations"));
    }

    #[test]
    fn test_validate_config_boundary_min_iterations() {
        let config = FuzzerConfig {
            target: "127.0.0.1:80".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 1,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_boundary_max_iterations() {
        let config = FuzzerConfig {
            target: "127.0.0.1:80".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 1_000_000,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_run_fuzzer_deterministic() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 100,
        };

        let result1 = run_fuzzer(&config);
        let result2 = run_fuzzer(&config);

        // Same seed, same protocol, same iterations => same mutations
        assert_eq!(result1.seed, result2.seed);
        assert_eq!(result1.protocol, result2.protocol);
        assert_eq!(result1.iterations_completed, result2.iterations_completed);
        assert_eq!(result1.mutations.len(), result2.mutations.len());

        for (m1, m2) in result1.mutations.iter().zip(result2.mutations.iter()) {
            assert_eq!(m1.iteration, m2.iteration);
            assert_eq!(m1.payload_size_bytes, m2.payload_size_bytes);
            assert_eq!(m1.protocol, m2.protocol);
        }
    }

    #[test]
    fn test_run_fuzzer_different_seeds_produce_different_results() {
        let config1 = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 50,
        };
        let config2 = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            seed: 99,
            iterations: 50,
        };

        let result1 = run_fuzzer(&config1);
        let result2 = run_fuzzer(&config2);

        // Different seeds should produce different payload sizes
        let sizes1: Vec<usize> = result1.mutations.iter().map(|m| m.payload_size_bytes).collect();
        let sizes2: Vec<usize> = result2.mutations.iter().map(|m| m.payload_size_bytes).collect();
        assert_ne!(sizes1, sizes2);
    }

    #[test]
    fn test_run_fuzzer_http_payload_range() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            seed: 123,
            iterations: 500,
        };

        let result = run_fuzzer(&config);
        for m in &result.mutations {
            assert!(m.payload_size_bytes >= 16, "HTTP payload too small: {}", m.payload_size_bytes);
            assert!(m.payload_size_bytes <= 8192, "HTTP payload too large: {}", m.payload_size_bytes);
        }
    }

    #[test]
    fn test_run_fuzzer_tcp_payload_range() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Tcp,
            seed: 456,
            iterations: 500,
        };

        let result = run_fuzzer(&config);
        for m in &result.mutations {
            assert!(m.payload_size_bytes >= 1, "TCP payload too small: {}", m.payload_size_bytes);
            assert!(m.payload_size_bytes <= 1500, "TCP payload too large: {}", m.payload_size_bytes);
        }
    }

    #[test]
    fn test_run_fuzzer_dns_payload_range() {
        let config = FuzzerConfig {
            target: "127.0.0.1:53".to_string(),
            protocol: Protocol::Dns,
            seed: 789,
            iterations: 500,
        };

        let result = run_fuzzer(&config);
        for m in &result.mutations {
            assert!(m.payload_size_bytes >= 12, "DNS payload too small: {}", m.payload_size_bytes);
            assert!(m.payload_size_bytes <= 512, "DNS payload too large: {}", m.payload_size_bytes);
        }
    }

    #[test]
    fn test_run_fuzzer_iteration_count_matches() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 250,
        };

        let result = run_fuzzer(&config);
        assert_eq!(result.iterations_completed, 250);
        assert_eq!(result.mutations.len(), 250);
    }

    #[test]
    fn test_run_fuzzer_iteration_indices_sequential() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 100,
        };

        let result = run_fuzzer(&config);
        for (i, m) in result.mutations.iter().enumerate() {
            assert_eq!(m.iteration, i as u32);
        }
    }

    #[test]
    fn test_run_fuzzer_protocol_field_consistency() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Tcp,
            seed: 42,
            iterations: 10,
        };

        let result = run_fuzzer(&config);
        assert_eq!(result.protocol, "tcp");
        for m in &result.mutations {
            assert_eq!(m.protocol, "tcp");
        }
    }

    #[test]
    fn test_run_fuzzer_elapsed_ms_nonnegative() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 10,
        };

        let result = run_fuzzer(&config);
        // elapsed_ms is u64, always >= 0, but verify it's reasonable
        assert!(result.elapsed_ms <= 60_000, "Elapsed time unreasonably large");
    }

    #[test]
    fn test_run_fuzzer_single_iteration() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Dns,
            seed: 1,
            iterations: 1,
        };

        let result = run_fuzzer(&config);
        assert_eq!(result.iterations_completed, 1);
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutations[0].iteration, 0);
        assert_eq!(result.mutations[0].protocol, "dns");
    }

    #[test]
    fn test_fuzzer_summary_serialization() {
        let config = FuzzerConfig {
            target: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            seed: 42,
            iterations: 5,
        };

        let result = run_fuzzer(&config);
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: FuzzerSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(result.seed, deserialized.seed);
        assert_eq!(result.protocol, deserialized.protocol);
        assert_eq!(result.iterations_completed, deserialized.iterations_completed);
        assert_eq!(result.mutations.len(), deserialized.mutations.len());
    }
}
