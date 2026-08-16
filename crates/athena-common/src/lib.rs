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
// ICS Protocol Types
// ---------------------------------------------------------------------------

/// ICS protocol discriminator for ground-truth records.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IcsProtocol {
    ModbusTcp,
    CanBus,
}

// --- Modbus result types ---

/// Result output from a Modbus TCP read operation (FC 01–04).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModbusReadResult {
    /// Unit (slave) ID that was queried.
    pub unit_id: u8,
    /// Modbus function code used (1–4).
    pub function_code: u8,
    /// Starting register/coil address.
    pub address: u16,
    /// Number of registers/coils requested.
    pub quantity: u16,
    /// Values returned by the device.
    pub values: Vec<u16>,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
}

/// Result output from a Modbus TCP write operation (FC 05, 06, 15, 16).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModbusWriteResult {
    /// Unit (slave) ID that was written to.
    pub unit_id: u8,
    /// Modbus function code used.
    pub function_code: u8,
    /// Starting register/coil address.
    pub address: u16,
    /// Values that were written.
    pub value_written: Vec<u16>,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
}

/// Result output from Modbus unit ID enumeration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModbusEnumerateResult {
    /// Target host:port that was scanned.
    pub target: String,
    /// Unit IDs that responded.
    pub responding_units: Vec<u8>,
    /// Total number of unit IDs scanned.
    pub total_scanned: u16,
    /// Timeout used per unit probe (ms).
    pub timeout_ms: u64,
    /// Total elapsed time in milliseconds.
    pub elapsed_ms: u64,
}

/// Summary output from the Modbus fuzzer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModbusFuzzSummary {
    /// PRNG seed used for deterministic reproduction.
    pub seed: u64,
    /// Target unit ID.
    pub unit_id: u8,
    /// Number of fuzz iterations completed.
    pub iterations_completed: u32,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Per-iteration fuzz records.
    pub records: Vec<ModbusFuzzRecord>,
}

/// A single record from a Modbus fuzz iteration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModbusFuzzRecord {
    /// Iteration index (0-based).
    pub iteration: u32,
    /// Function code used in this iteration.
    pub function_code: u8,
    /// Size of the generated payload in bytes.
    pub payload_size_bytes: usize,
    /// Whether the device responded to the request.
    pub responded: bool,
}

// --- CAN result types ---

/// CAN arbitration ID type (standard 11-bit or extended 29-bit).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CanIdType {
    Standard,
    Extended,
}

/// Result output from CAN frame crafting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanCraftResult {
    /// CAN arbitration ID.
    pub id: u32,
    /// Whether the ID is standard or extended.
    pub id_type: CanIdType,
    /// Data length code (0–8).
    pub dlc: u8,
    /// Hex-encoded payload data.
    pub data_hex: String,
}

/// Result output from CAN frame injection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanInjectResult {
    /// SocketCAN interface used (e.g., "vcan0").
    pub interface: String,
    /// Number of frames transmitted.
    pub frame_count: u32,
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
}

/// A single captured CAN frame from a sniff operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanSniffFrame {
    /// Timestamp in microseconds relative to sniff start.
    pub timestamp_us: u64,
    /// CAN arbitration ID.
    pub id: u32,
    /// Whether the ID is standard or extended.
    pub id_type: CanIdType,
    /// Data length code (0–8).
    pub dlc: u8,
    /// Hex-encoded payload data.
    pub data_hex: String,
}

/// Result output from a CAN sniff operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanSniffResult {
    /// SocketCAN interface used.
    pub interface: String,
    /// Total duration of capture in milliseconds.
    pub duration_ms: u64,
    /// Captured frames.
    pub frames: Vec<CanSniffFrame>,
}

/// Summary output from the CAN fuzzer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanFuzzSummary {
    /// PRNG seed used for deterministic reproduction.
    pub seed: u64,
    /// SocketCAN interface used.
    pub interface: String,
    /// Number of fuzz iterations completed.
    pub iterations_completed: u32,
    /// CAN ID range exercised (start, end).
    pub id_range: (u32, u32),
    /// Elapsed time in milliseconds.
    pub elapsed_ms: u64,
    /// Total number of frames transmitted.
    pub frame_count: u32,
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

    // -----------------------------------------------------------------------
    // ICS Protocol Types tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ics_protocol_serializes_to_kebab_case() {
        let modbus = serde_json::to_string(&IcsProtocol::ModbusTcp).unwrap();
        let canbus = serde_json::to_string(&IcsProtocol::CanBus).unwrap();
        assert_eq!(modbus, "\"modbus-tcp\"");
        assert_eq!(canbus, "\"can-bus\"");
    }

    #[test]
    fn test_ics_protocol_deserializes_from_kebab_case() {
        let modbus: IcsProtocol = serde_json::from_str("\"modbus-tcp\"").unwrap();
        let canbus: IcsProtocol = serde_json::from_str("\"can-bus\"").unwrap();
        assert_eq!(modbus, IcsProtocol::ModbusTcp);
        assert_eq!(canbus, IcsProtocol::CanBus);
    }

    #[test]
    fn test_modbus_read_result_serialization_roundtrip() {
        let result = ModbusReadResult {
            unit_id: 1,
            function_code: 3,
            address: 100,
            quantity: 5,
            values: vec![10, 20, 30, 40, 50],
            elapsed_ms: 42,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ModbusReadResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_modbus_read_result_json_structure() {
        let result = ModbusReadResult {
            unit_id: 247,
            function_code: 1,
            address: 0,
            quantity: 10,
            values: vec![1, 0, 1, 1, 0, 0, 1, 0, 1, 1],
            elapsed_ms: 15,
        };

        let json = serde_json::to_string(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["unit_id"], 247);
        assert_eq!(value["function_code"], 1);
        assert_eq!(value["address"], 0);
        assert_eq!(value["quantity"], 10);
        assert_eq!(value["values"].as_array().unwrap().len(), 10);
        assert_eq!(value["elapsed_ms"], 15);
    }

    #[test]
    fn test_modbus_write_result_serialization_roundtrip() {
        let result = ModbusWriteResult {
            unit_id: 5,
            function_code: 6,
            address: 200,
            value_written: vec![500],
            elapsed_ms: 8,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ModbusWriteResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_modbus_enumerate_result_serialization_roundtrip() {
        let result = ModbusEnumerateResult {
            target: "192.168.1.50:502".to_string(),
            responding_units: vec![1, 5, 10, 247],
            total_scanned: 247,
            timeout_ms: 1000,
            elapsed_ms: 30000,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ModbusEnumerateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_modbus_fuzz_summary_serialization_roundtrip() {
        let summary = ModbusFuzzSummary {
            seed: 99,
            unit_id: 1,
            iterations_completed: 100,
            elapsed_ms: 5000,
            records: vec![
                ModbusFuzzRecord {
                    iteration: 0,
                    function_code: 42,
                    payload_size_bytes: 16,
                    responded: true,
                },
                ModbusFuzzRecord {
                    iteration: 1,
                    function_code: 100,
                    payload_size_bytes: 64,
                    responded: false,
                },
            ],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: ModbusFuzzSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, deserialized);
    }

    #[test]
    fn test_can_id_type_serializes_to_lowercase() {
        let standard = serde_json::to_string(&CanIdType::Standard).unwrap();
        let extended = serde_json::to_string(&CanIdType::Extended).unwrap();
        assert_eq!(standard, "\"standard\"");
        assert_eq!(extended, "\"extended\"");
    }

    #[test]
    fn test_can_id_type_deserializes_from_lowercase() {
        let standard: CanIdType = serde_json::from_str("\"standard\"").unwrap();
        let extended: CanIdType = serde_json::from_str("\"extended\"").unwrap();
        assert_eq!(standard, CanIdType::Standard);
        assert_eq!(extended, CanIdType::Extended);
    }

    #[test]
    fn test_can_craft_result_serialization_roundtrip() {
        let result = CanCraftResult {
            id: 0x7FF,
            id_type: CanIdType::Standard,
            dlc: 8,
            data_hex: "deadbeefcafebabe".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: CanCraftResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_can_inject_result_serialization_roundtrip() {
        let result = CanInjectResult {
            interface: "vcan0".to_string(),
            frame_count: 42,
            elapsed_ms: 1200,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: CanInjectResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_can_sniff_result_serialization_roundtrip() {
        let result = CanSniffResult {
            interface: "vcan0".to_string(),
            duration_ms: 5000,
            frames: vec![
                CanSniffFrame {
                    timestamp_us: 1000,
                    id: 0x100,
                    id_type: CanIdType::Standard,
                    dlc: 4,
                    data_hex: "aabbccdd".to_string(),
                },
                CanSniffFrame {
                    timestamp_us: 2500,
                    id: 0x1FFFFFFF,
                    id_type: CanIdType::Extended,
                    dlc: 8,
                    data_hex: "0102030405060708".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: CanSniffResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_can_fuzz_summary_serialization_roundtrip() {
        let summary = CanFuzzSummary {
            seed: 12345,
            interface: "vcan0".to_string(),
            iterations_completed: 1000,
            id_range: (0, 0x7FF),
            elapsed_ms: 3000,
            frame_count: 1000,
        };

        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: CanFuzzSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, deserialized);
    }

    #[test]
    fn test_can_fuzz_summary_json_structure() {
        let summary = CanFuzzSummary {
            seed: 42,
            interface: "vcan1".to_string(),
            iterations_completed: 500,
            id_range: (0x100, 0x200),
            elapsed_ms: 1500,
            frame_count: 500,
        };

        let json = serde_json::to_string(&summary).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["seed"], 42);
        assert_eq!(value["interface"], "vcan1");
        assert_eq!(value["iterations_completed"], 500);
        assert_eq!(value["id_range"][0], 0x100);
        assert_eq!(value["id_range"][1], 0x200);
        assert_eq!(value["elapsed_ms"], 1500);
        assert_eq!(value["frame_count"], 500);
    }

    #[test]
    fn test_modbus_fuzz_record_json_structure() {
        let record = ModbusFuzzRecord {
            iteration: 5,
            function_code: 127,
            payload_size_bytes: 252,
            responded: true,
        };

        let json = serde_json::to_string(&record).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["iteration"], 5);
        assert_eq!(value["function_code"], 127);
        assert_eq!(value["payload_size_bytes"], 252);
        assert_eq!(value["responded"], true);
    }

    #[test]
    fn test_can_craft_result_json_structure() {
        let result = CanCraftResult {
            id: 0x1FFFFFFF,
            id_type: CanIdType::Extended,
            dlc: 3,
            data_hex: "aabbcc".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["id"], 0x1FFFFFFF_u32);
        assert_eq!(value["id_type"], "extended");
        assert_eq!(value["dlc"], 3);
        assert_eq!(value["data_hex"], "aabbcc");
    }
}
