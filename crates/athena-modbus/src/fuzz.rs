//! Deterministic Modbus TCP protocol fuzzer using xoshiro256++.
//!
//! Generates random function codes (1–127) and payloads of varying sizes,
//! sending them as raw Modbus requests to discover firmware implementation
//! vulnerabilities. The PRNG is seeded for reproducibility.

use std::time::Instant;

use athena_common::{ModbusFuzzRecord, ModbusFuzzSummary};
use rand::Rng;
use rand::SeedableRng;
use rand_xoshiro::Xoshiro256PlusPlus;

use crate::client::{ModbusClient, ModbusClientError};

/// Configuration for a Modbus fuzz run.
#[derive(Debug, Clone)]
pub struct ModbusFuzzConfig {
    /// Target host:port for the Modbus TCP connection.
    pub target: String,
    /// Unit ID to target during fuzzing.
    pub unit_id: u8,
    /// PRNG seed for deterministic reproduction.
    pub seed: u64,
    /// Number of fuzz iterations to perform.
    pub iterations: u32,
    /// Timeout in milliseconds for connection and responses.
    pub timeout_ms: u64,
}

/// Validate a fuzz configuration.
///
/// # Errors
///
/// Returns an error string if:
/// - `iterations` is 0 or exceeds 1,000,000
/// - `unit_id` is 0 or exceeds 247
pub fn validate_fuzz_config(config: &ModbusFuzzConfig) -> Result<(), String> {
    if config.iterations == 0 || config.iterations > 1_000_000 {
        return Err(format!(
            "iterations must be between 1 and 1000000, got {}",
            config.iterations
        ));
    }
    if config.unit_id == 0 || config.unit_id > 247 {
        return Err(format!(
            "unit_id must be between 1 and 247, got {}",
            config.unit_id
        ));
    }
    Ok(())
}

/// Generate fuzz records deterministically without sending network traffic.
///
/// This is the core fuzzer logic that can be tested without a network connection.
/// Each iteration generates a random function code (1–127) and a random payload
/// size (0–252 bytes). The `responded` field defaults to `false` and is set to
/// `true` during actual network execution.
///
/// # Arguments
///
/// * `seed` - PRNG seed for deterministic output
/// * `iterations` - Number of fuzz iterations to generate
pub fn generate_fuzz_records(seed: u64, iterations: u32) -> Vec<ModbusFuzzRecord> {
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed);

    (0..iterations)
        .map(|i| {
            let function_code = rng.gen_range(1..=127u8);
            let payload_size = rng.gen_range(0..=252usize);
            ModbusFuzzRecord {
                iteration: i,
                function_code,
                payload_size_bytes: payload_size,
                responded: false,
            }
        })
        .collect()
}

/// Run the Modbus fuzzer against a live target.
///
/// Connects to the target, generates deterministic fuzz records, and sends
/// each one as a raw Modbus request. Records whether the device responded.
///
/// # Errors
///
/// Returns an error string if:
/// - Config validation fails
/// - TCP connection cannot be established
pub async fn run_modbus_fuzz(config: &ModbusFuzzConfig) -> Result<ModbusFuzzSummary, String> {
    validate_fuzz_config(config)?;

    let start = Instant::now();

    let mut client = ModbusClient::connect(&config.target, config.timeout_ms)
        .await
        .map_err(|e| format!("connection failed: {}", e))?;

    let mut records = generate_fuzz_records(config.seed, config.iterations);

    // Generate random payloads and send each record
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(config.seed);

    for record in records.iter_mut() {
        // Re-derive the same function_code and payload_size to stay deterministic
        let _fc = rng.gen_range(1..=127u8);
        let payload_size = rng.gen_range(0..=252usize);

        // Generate random payload bytes
        let payload: Vec<u8> = (0..payload_size).map(|_| rng.gen()).collect();

        match client
            .send_request(config.unit_id, record.function_code, payload)
            .await
        {
            Ok(_) => {
                record.responded = true;
            }
            Err(ModbusClientError::ResponseTimeout { .. }) => {
                record.responded = false;
            }
            Err(ModbusClientError::ModbusException { .. }) => {
                // Device responded with an exception — it still responded
                record.responded = true;
            }
            Err(_) => {
                record.responded = false;
            }
        }
    }

    Ok(ModbusFuzzSummary {
        seed: config.seed,
        unit_id: config.unit_id,
        iterations_completed: config.iterations,
        elapsed_ms: start.elapsed().as_millis() as u64,
        records,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_fuzz_config_valid() {
        let config = ModbusFuzzConfig {
            target: "127.0.0.1:502".to_string(),
            unit_id: 1,
            seed: 42,
            iterations: 100,
            timeout_ms: 5000,
        };
        assert!(validate_fuzz_config(&config).is_ok());
    }

    #[test]
    fn test_validate_fuzz_config_zero_iterations() {
        let config = ModbusFuzzConfig {
            target: "127.0.0.1:502".to_string(),
            unit_id: 1,
            seed: 42,
            iterations: 0,
            timeout_ms: 5000,
        };
        let err = validate_fuzz_config(&config).unwrap_err();
        assert!(err.contains("iterations"));
    }

    #[test]
    fn test_validate_fuzz_config_too_many_iterations() {
        let config = ModbusFuzzConfig {
            target: "127.0.0.1:502".to_string(),
            unit_id: 1,
            seed: 42,
            iterations: 1_000_001,
            timeout_ms: 5000,
        };
        assert!(validate_fuzz_config(&config).is_err());
    }

    #[test]
    fn test_validate_fuzz_config_zero_unit_id() {
        let config = ModbusFuzzConfig {
            target: "127.0.0.1:502".to_string(),
            unit_id: 0,
            seed: 42,
            iterations: 100,
            timeout_ms: 5000,
        };
        let err = validate_fuzz_config(&config).unwrap_err();
        assert!(err.contains("unit_id"));
    }

    #[test]
    fn test_validate_fuzz_config_unit_id_too_high() {
        let config = ModbusFuzzConfig {
            target: "127.0.0.1:502".to_string(),
            unit_id: 248,
            seed: 42,
            iterations: 100,
            timeout_ms: 5000,
        };
        assert!(validate_fuzz_config(&config).is_err());
    }

    #[test]
    fn test_generate_fuzz_records_deterministic() {
        let records_a = generate_fuzz_records(42, 100);
        let records_b = generate_fuzz_records(42, 100);
        assert_eq!(records_a, records_b);
    }

    #[test]
    fn test_generate_fuzz_records_different_seeds_produce_different_output() {
        let records_a = generate_fuzz_records(42, 100);
        let records_b = generate_fuzz_records(99, 100);
        // Extremely unlikely to be equal with different seeds
        assert_ne!(records_a, records_b);
    }

    #[test]
    fn test_generate_fuzz_records_function_codes_in_range() {
        let records = generate_fuzz_records(12345, 1000);
        for record in &records {
            assert!(
                record.function_code >= 1 && record.function_code <= 127,
                "Function code {} out of range [1, 127]",
                record.function_code
            );
        }
    }

    #[test]
    fn test_generate_fuzz_records_payload_sizes_in_range() {
        let records = generate_fuzz_records(67890, 1000);
        for record in &records {
            assert!(
                record.payload_size_bytes <= 252,
                "Payload size {} exceeds max 252",
                record.payload_size_bytes
            );
        }
    }

    #[test]
    fn test_generate_fuzz_records_correct_iteration_count() {
        let records = generate_fuzz_records(1, 50);
        assert_eq!(records.len(), 50);

        for (i, record) in records.iter().enumerate() {
            assert_eq!(record.iteration, i as u32);
        }
    }

    #[test]
    fn test_generate_fuzz_records_all_not_responded_by_default() {
        let records = generate_fuzz_records(42, 10);
        for record in &records {
            assert!(!record.responded);
        }
    }

    #[test]
    fn test_generate_fuzz_records_zero_iterations() {
        let records = generate_fuzz_records(42, 0);
        assert!(records.is_empty());
    }

    #[test]
    fn test_generate_fuzz_records_single_iteration() {
        let records = generate_fuzz_records(42, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].iteration, 0);
        assert!(records[0].function_code >= 1 && records[0].function_code <= 127);
    }
}
