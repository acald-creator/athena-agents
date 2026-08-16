//! Shared types and JSON output formatting for Athena offensive primitives.
//!
//! This crate provides the common data structures used by all Athena Rust binaries
//! (port scanner, protocol fuzzer, packet crafter) to ensure consistent JSON output
//! and error reporting.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Port Scanner types
// ---------------------------------------------------------------------------

/// Result output from the async TCP port scanner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanResult {
    /// Target address that was scanned.
    pub target: String,
    /// List of port entries with their status.
    pub ports: Vec<PortEntry>,
    /// Total scan duration in milliseconds.
    pub scan_duration_ms: u64,
}

/// A single port entry within a scan result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortEntry {
    /// Port number (1-65535).
    pub port: u16,
    /// Whether the port is open or closed.
    pub status: PortStatus,
}

/// Status of a scanned port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PortStatus {
    Open,
    Closed,
}

// ---------------------------------------------------------------------------
// Protocol Fuzzer types
// ---------------------------------------------------------------------------

/// Summary output from the protocol fuzzer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FuzzerSummary {
    /// PRNG seed used for deterministic reproduction.
    pub seed: u64,
    /// Protocol type being fuzzed (e.g., "http", "tcp", "dns").
    pub protocol: String,
    /// Number of mutation iterations completed.
    pub iterations_completed: u32,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Individual mutation records.
    pub mutations: Vec<MutationRecord>,
}

/// A single mutation record from the fuzzer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationRecord {
    /// Iteration index (0-based).
    pub iteration: u32,
    /// Size of the mutated payload in bytes.
    pub payload_size_bytes: usize,
    /// Protocol type for this mutation.
    pub protocol: String,
}

// ---------------------------------------------------------------------------
// Packet Crafter types
// ---------------------------------------------------------------------------

/// Result output from the packet crafter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CraftResult {
    /// Protocol of the crafted packet (tcp, udp, icmp).
    pub protocol: String,
    /// Total packet length in bytes.
    pub total_length_bytes: usize,
    /// Hex-encoded payload.
    pub payload_hex: String,
}

// ---------------------------------------------------------------------------
// Error output types
// ---------------------------------------------------------------------------

/// Structured error output written to stderr on validation failures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorOutput {
    /// Error category (e.g., "validation_error", "connection_error").
    pub error: String,
    /// Human-readable message describing the failure.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Validation error helper
// ---------------------------------------------------------------------------

/// Report a CLI validation error as JSON to stderr and exit with code 1.
///
/// This function writes a JSON-formatted `ErrorOutput` to stderr and terminates
/// the process. It is intended for use when CLI argument validation fails.
///
/// # Example
///
/// ```no_run
/// use athena_common::report_validation_error;
///
/// // This would print JSON to stderr and exit(1):
/// // report_validation_error("validation_error", "start-port must be <= end-port");
/// ```
pub fn report_validation_error(error: &str, message: &str) -> ! {
    let err = ErrorOutput {
        error: error.to_string(),
        message: message.to_string(),
    };
    eprintln!("{}", serde_json::to_string(&err).unwrap());
    std::process::exit(1);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_serialization_roundtrip() {
        let result = ScanResult {
            target: "192.168.1.100".to_string(),
            ports: vec![
                PortEntry {
                    port: 80,
                    status: PortStatus::Open,
                },
                PortEntry {
                    port: 443,
                    status: PortStatus::Open,
                },
                PortEntry {
                    port: 8080,
                    status: PortStatus::Closed,
                },
            ],
            scan_duration_ms: 1523,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_port_status_serializes_to_lowercase() {
        let open = serde_json::to_string(&PortStatus::Open).unwrap();
        let closed = serde_json::to_string(&PortStatus::Closed).unwrap();
        assert_eq!(open, "\"open\"");
        assert_eq!(closed, "\"closed\"");
    }

    #[test]
    fn test_port_status_deserializes_from_lowercase() {
        let open: PortStatus = serde_json::from_str("\"open\"").unwrap();
        let closed: PortStatus = serde_json::from_str("\"closed\"").unwrap();
        assert_eq!(open, PortStatus::Open);
        assert_eq!(closed, PortStatus::Closed);
    }

    #[test]
    fn test_fuzzer_summary_serialization_roundtrip() {
        let summary = FuzzerSummary {
            seed: 42,
            protocol: "http".to_string(),
            iterations_completed: 1000,
            elapsed_ms: 4521,
            mutations: vec![
                MutationRecord {
                    iteration: 0,
                    payload_size_bytes: 128,
                    protocol: "http".to_string(),
                },
                MutationRecord {
                    iteration: 1,
                    payload_size_bytes: 256,
                    protocol: "http".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: FuzzerSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, deserialized);
    }

    #[test]
    fn test_craft_result_serialization_roundtrip() {
        let result = CraftResult {
            protocol: "tcp".to_string(),
            total_length_bytes: 74,
            payload_hex: "48454c4c4f".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: CraftResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_error_output_serialization() {
        let err = ErrorOutput {
            error: "validation_error".to_string(),
            message: "start-port must be <= end-port".to_string(),
        };

        let json = serde_json::to_string(&err).unwrap();
        let deserialized: ErrorOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deserialized);

        // Verify JSON structure
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["error"], "validation_error");
        assert_eq!(value["message"], "start-port must be <= end-port");
    }

    #[test]
    fn test_scan_result_json_structure() {
        let result = ScanResult {
            target: "10.0.0.1".to_string(),
            ports: vec![PortEntry {
                port: 22,
                status: PortStatus::Open,
            }],
            scan_duration_ms: 100,
        };

        let json = serde_json::to_string(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["target"], "10.0.0.1");
        assert_eq!(value["scan_duration_ms"], 100);
        assert_eq!(value["ports"][0]["port"], 22);
        assert_eq!(value["ports"][0]["status"], "open");
    }

    #[test]
    fn test_fuzzer_summary_json_structure() {
        let summary = FuzzerSummary {
            seed: 12345,
            protocol: "tcp".to_string(),
            iterations_completed: 500,
            elapsed_ms: 2000,
            mutations: vec![MutationRecord {
                iteration: 0,
                payload_size_bytes: 64,
                protocol: "tcp".to_string(),
            }],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["seed"], 12345);
        assert_eq!(value["protocol"], "tcp");
        assert_eq!(value["iterations_completed"], 500);
        assert_eq!(value["elapsed_ms"], 2000);
        assert_eq!(value["mutations"][0]["iteration"], 0);
        assert_eq!(value["mutations"][0]["payload_size_bytes"], 64);
        assert_eq!(value["mutations"][0]["protocol"], "tcp");
    }

    #[test]
    fn test_craft_result_json_structure() {
        let result = CraftResult {
            protocol: "udp".to_string(),
            total_length_bytes: 42,
            payload_hex: "deadbeef".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["protocol"], "udp");
        assert_eq!(value["total_length_bytes"], 42);
        assert_eq!(value["payload_hex"], "deadbeef");
    }
}
