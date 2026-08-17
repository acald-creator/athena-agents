//! Modbus TCP client library for Athena ICS offensive primitives.
//!
//! This crate provides Modbus TCP read, write, enumeration, and fuzzing
//! operations for security testing of industrial control systems. It implements
//! manual MBAP frame construction for full control over protocol interactions,
//! including malformed packet generation during fuzzing.
//!
//! # Modules
//!
//! - `frame` — MBAP header and PDU encoding/decoding
//! - `client` — Async TCP Modbus client with timeout handling
//! - `fuzz` — Deterministic Modbus protocol fuzzer (xoshiro256++)
//!
//! # Safety Controls
//!
//! Write operations support safe-range validation to prevent writes outside
//! configured boundaries, enforcing safety even in autonomous operation.

pub mod client;
pub mod frame;
pub mod fuzz;

use std::time::Instant;

use athena_common::{ModbusEnumerateResult, ModbusReadResult, ModbusWriteResult};
use client::{ModbusClient, ModbusClientError};

// ---------------------------------------------------------------------------
// Safe-range validation
// ---------------------------------------------------------------------------

/// A configured safe range for a specific Modbus register address.
///
/// Defines the minimum and maximum values that may be written to a particular
/// register. Writes outside this boundary are rejected before transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeRange {
    /// The register address this range applies to.
    pub address: u16,
    /// Minimum acceptable write value (inclusive).
    pub min: u16,
    /// Maximum acceptable write value (inclusive).
    pub max: u16,
}

/// Error returned when a write value violates a configured safe range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyError {
    /// The register address the write targeted.
    pub address: u16,
    /// The value that was attempted.
    pub attempted_value: u16,
    /// The configured minimum for this address.
    pub safe_min: u16,
    /// The configured maximum for this address.
    pub safe_max: u16,
}

impl std::fmt::Display for SafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "safety boundary violation: attempted value {} at address {} is outside safe range [{}, {}]",
            self.attempted_value, self.address, self.safe_min, self.safe_max
        )
    }
}

impl std::error::Error for SafetyError {}

/// Validate a write value against configured safe ranges.
///
/// If a safe range is defined for the given address, the value must be within
/// `[min, max]` (inclusive). If no safe range is defined for the address, the
/// write is allowed (no restriction).
///
/// # Errors
///
/// Returns `SafetyError` if the value is outside the configured range for the
/// given address.
pub fn validate_write_value(
    address: u16,
    value: u16,
    safe_ranges: &[SafeRange],
) -> Result<(), SafetyError> {
    for range in safe_ranges {
        if range.address == address {
            if value < range.min || value > range.max {
                return Err(SafetyError {
                    address,
                    attempted_value: value,
                    safe_min: range.min,
                    safe_max: range.max,
                });
            }
            return Ok(());
        }
    }
    // No range defined for this address — allow
    Ok(())
}

// ---------------------------------------------------------------------------
// Modbus Read Operations
// ---------------------------------------------------------------------------

/// Read coils from a Modbus device (Function Code 01).
///
/// Sends an FC 01 request and parses the response. Coil values are returned
/// as a `Vec<u16>` where each element is 0 or 1.
///
/// # Arguments
///
/// * `client` - Connected Modbus TCP client
/// * `unit_id` - Target device address (1–247)
/// * `address` - Starting coil address
/// * `quantity` - Number of coils to read
pub async fn read_coils(
    client: &mut ModbusClient,
    unit_id: u8,
    address: u16,
    quantity: u16,
) -> Result<ModbusReadResult, ModbusClientError> {
    let start = Instant::now();

    let data = vec![
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (quantity >> 8) as u8,
        (quantity & 0xFF) as u8,
    ];

    let response = client.send_request(unit_id, 0x01, data).await?;
    let values = parse_coil_response(&response.data, quantity);

    Ok(ModbusReadResult {
        unit_id,
        function_code: 0x01,
        address,
        quantity,
        values,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Read discrete inputs from a Modbus device (Function Code 02).
///
/// Sends an FC 02 request and parses the response. Input values are returned
/// as a `Vec<u16>` where each element is 0 or 1.
pub async fn read_discrete_inputs(
    client: &mut ModbusClient,
    unit_id: u8,
    address: u16,
    quantity: u16,
) -> Result<ModbusReadResult, ModbusClientError> {
    let start = Instant::now();

    let data = vec![
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (quantity >> 8) as u8,
        (quantity & 0xFF) as u8,
    ];

    let response = client.send_request(unit_id, 0x02, data).await?;
    let values = parse_coil_response(&response.data, quantity);

    Ok(ModbusReadResult {
        unit_id,
        function_code: 0x02,
        address,
        quantity,
        values,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Read holding registers from a Modbus device (Function Code 03).
///
/// Sends an FC 03 request and parses the response. Register values are
/// returned as a `Vec<u16>` of big-endian 16-bit values.
pub async fn read_holding_registers(
    client: &mut ModbusClient,
    unit_id: u8,
    address: u16,
    quantity: u16,
) -> Result<ModbusReadResult, ModbusClientError> {
    let start = Instant::now();

    let data = vec![
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (quantity >> 8) as u8,
        (quantity & 0xFF) as u8,
    ];

    let response = client.send_request(unit_id, 0x03, data).await?;
    let values = parse_register_response(&response.data);

    Ok(ModbusReadResult {
        unit_id,
        function_code: 0x03,
        address,
        quantity,
        values,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Read input registers from a Modbus device (Function Code 04).
///
/// Sends an FC 04 request and parses the response. Register values are
/// returned as a `Vec<u16>` of big-endian 16-bit values.
pub async fn read_input_registers(
    client: &mut ModbusClient,
    unit_id: u8,
    address: u16,
    quantity: u16,
) -> Result<ModbusReadResult, ModbusClientError> {
    let start = Instant::now();

    let data = vec![
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (quantity >> 8) as u8,
        (quantity & 0xFF) as u8,
    ];

    let response = client.send_request(unit_id, 0x04, data).await?;
    let values = parse_register_response(&response.data);

    Ok(ModbusReadResult {
        unit_id,
        function_code: 0x04,
        address,
        quantity,
        values,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

// ---------------------------------------------------------------------------
// Modbus Write Operations
// ---------------------------------------------------------------------------

/// Write a single coil on a Modbus device (Function Code 05).
///
/// Sends an FC 05 request. The coil value is encoded as 0xFF00 (ON) or
/// 0x0000 (OFF) per the Modbus specification.
///
/// Safe-range validation is applied: the coil is treated as value 1 (ON) or
/// 0 (OFF) for range checking.
pub async fn write_coil(
    client: &mut ModbusClient,
    unit_id: u8,
    address: u16,
    value: bool,
    safe_ranges: &[SafeRange],
) -> Result<ModbusWriteResult, ModbusClientError> {
    let coil_value: u16 = if value { 1 } else { 0 };
    validate_write_value(address, coil_value, safe_ranges)
        .map_err(ModbusClientError::SafetyViolation)?;

    let start = Instant::now();

    let wire_value: u16 = if value { 0xFF00 } else { 0x0000 };
    let data = vec![
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (wire_value >> 8) as u8,
        (wire_value & 0xFF) as u8,
    ];

    let _response = client.send_request(unit_id, 0x05, data).await?;

    Ok(ModbusWriteResult {
        unit_id,
        function_code: 0x05,
        address,
        value_written: vec![coil_value],
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Write a single holding register on a Modbus device (Function Code 06).
///
/// Sends an FC 06 request after validating the value against safe ranges.
pub async fn write_register(
    client: &mut ModbusClient,
    unit_id: u8,
    address: u16,
    value: u16,
    safe_ranges: &[SafeRange],
) -> Result<ModbusWriteResult, ModbusClientError> {
    validate_write_value(address, value, safe_ranges)
        .map_err(ModbusClientError::SafetyViolation)?;

    let start = Instant::now();

    let data = vec![
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (value >> 8) as u8,
        (value & 0xFF) as u8,
    ];

    let _response = client.send_request(unit_id, 0x06, data).await?;

    Ok(ModbusWriteResult {
        unit_id,
        function_code: 0x06,
        address,
        value_written: vec![value],
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Write multiple coils on a Modbus device (Function Code 15).
///
/// Sends an FC 15 request. Coil values are packed as bits (LSB first within
/// each byte). Safe-range validation is applied to each coil.
pub async fn write_multiple_coils(
    client: &mut ModbusClient,
    unit_id: u8,
    address: u16,
    values: &[bool],
    safe_ranges: &[SafeRange],
) -> Result<ModbusWriteResult, ModbusClientError> {
    // Validate each coil against safe ranges
    for (i, &val) in values.iter().enumerate() {
        let coil_address = address.wrapping_add(i as u16);
        let coil_value: u16 = if val { 1 } else { 0 };
        validate_write_value(coil_address, coil_value, safe_ranges)
            .map_err(ModbusClientError::SafetyViolation)?;
    }

    let start = Instant::now();

    let quantity = values.len() as u16;
    let byte_count = ((values.len() + 7) / 8) as u8;

    // Pack coils into bytes (LSB first within each byte)
    let mut coil_bytes = vec![0u8; byte_count as usize];
    for (i, &val) in values.iter().enumerate() {
        if val {
            coil_bytes[i / 8] |= 1 << (i % 8);
        }
    }

    let mut data = Vec::with_capacity(5 + coil_bytes.len());
    data.push((address >> 8) as u8);
    data.push((address & 0xFF) as u8);
    data.push((quantity >> 8) as u8);
    data.push((quantity & 0xFF) as u8);
    data.push(byte_count);
    data.extend_from_slice(&coil_bytes);

    let _response = client.send_request(unit_id, 0x0F, data).await?;

    let value_written: Vec<u16> = values.iter().map(|&v| if v { 1 } else { 0 }).collect();

    Ok(ModbusWriteResult {
        unit_id,
        function_code: 0x0F,
        address,
        value_written,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Write multiple holding registers on a Modbus device (Function Code 16).
///
/// Sends an FC 16 request after validating each value against safe ranges.
pub async fn write_multiple_registers(
    client: &mut ModbusClient,
    unit_id: u8,
    address: u16,
    values: &[u16],
    safe_ranges: &[SafeRange],
) -> Result<ModbusWriteResult, ModbusClientError> {
    // Validate each register value against safe ranges
    for (i, &val) in values.iter().enumerate() {
        let reg_address = address.wrapping_add(i as u16);
        validate_write_value(reg_address, val, safe_ranges)
            .map_err(ModbusClientError::SafetyViolation)?;
    }

    let start = Instant::now();

    let quantity = values.len() as u16;
    let byte_count = (values.len() * 2) as u8;

    let mut data = Vec::with_capacity(5 + values.len() * 2);
    data.push((address >> 8) as u8);
    data.push((address & 0xFF) as u8);
    data.push((quantity >> 8) as u8);
    data.push((quantity & 0xFF) as u8);
    data.push(byte_count);
    for &val in values {
        data.push((val >> 8) as u8);
        data.push((val & 0xFF) as u8);
    }

    let _response = client.send_request(unit_id, 0x10, data).await?;

    Ok(ModbusWriteResult {
        unit_id,
        function_code: 0x10,
        address,
        value_written: values.to_vec(),
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

// ---------------------------------------------------------------------------
// Modbus Enumeration
// ---------------------------------------------------------------------------

/// Enumerate responding Unit IDs on a Modbus TCP endpoint.
///
/// Connects to the target and probes each unit ID from 1 to 247 with an
/// FC 03 read request (address 0, quantity 1). Unit IDs that respond are
/// collected; those that timeout or error are skipped.
///
/// # Arguments
///
/// * `target` - Host:port string for the Modbus TCP gateway
/// * `timeout_ms` - Timeout in milliseconds for the connection and each probe
pub async fn enumerate_units(
    target: &str,
    timeout_ms: u64,
) -> Result<ModbusEnumerateResult, ModbusClientError> {
    let start = Instant::now();

    // Connect once to the target
    let mut client = ModbusClient::connect(target, timeout_ms).await?;

    let mut responding_units: Vec<u8> = Vec::new();

    for unit_id in 1..=247u8 {
        // FC 03: Read Holding Registers, address 0, quantity 1
        let data = vec![
            0x00, 0x00, // address = 0
            0x00, 0x01, // quantity = 1
        ];

        match client.send_request(unit_id, 0x03, data).await {
            Ok(_) => {
                responding_units.push(unit_id);
            }
            Err(ModbusClientError::ResponseTimeout { .. }) => {
                // Non-responding unit, skip
                continue;
            }
            Err(ModbusClientError::ModbusException { .. }) => {
                // Device responded with an exception — it exists
                responding_units.push(unit_id);
            }
            Err(_) => {
                // Other error (I/O, etc.), skip
                continue;
            }
        }
    }

    // Normalize the target address for the result
    let address = if target.contains(':') {
        target.to_string()
    } else {
        format!("{}:502", target)
    };

    Ok(ModbusEnumerateResult {
        target: address,
        responding_units,
        total_scanned: 247,
        timeout_ms,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

// ---------------------------------------------------------------------------
// Response parsing helpers
// ---------------------------------------------------------------------------

/// Parse a coil/discrete-input response into individual bit values.
///
/// Response format: byte_count (1 byte) + packed coil status bytes.
/// Each bit represents one coil (LSB first within each byte).
fn parse_coil_response(data: &[u8], quantity: u16) -> Vec<u16> {
    if data.is_empty() {
        return Vec::new();
    }

    // First byte is the byte count — skip it for data extraction
    let coil_bytes = &data[1..];
    let mut values = Vec::with_capacity(quantity as usize);

    for i in 0..quantity as usize {
        let byte_index = i / 8;
        let bit_index = i % 8;
        if byte_index < coil_bytes.len() {
            let bit = (coil_bytes[byte_index] >> bit_index) & 0x01;
            values.push(bit as u16);
        } else {
            values.push(0);
        }
    }

    values
}

/// Parse a register response into 16-bit values.
///
/// Response format: byte_count (1 byte) + register values (2 bytes each, big-endian).
fn parse_register_response(data: &[u8]) -> Vec<u16> {
    if data.is_empty() {
        return Vec::new();
    }

    // First byte is the byte count
    let register_bytes = &data[1..];
    let mut values = Vec::with_capacity(register_bytes.len() / 2);

    for chunk in register_bytes.chunks_exact(2) {
        values.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }

    values
}

// ---------------------------------------------------------------------------
// Helper to build read request PDU data
// ---------------------------------------------------------------------------

/// Build the 4-byte PDU data for a read request (address + quantity, big-endian).
pub fn build_read_pdu_data(address: u16, quantity: u16) -> Vec<u8> {
    vec![
        (address >> 8) as u8,
        (address & 0xFF) as u8,
        (quantity >> 8) as u8,
        (quantity & 0xFF) as u8,
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Safe-range validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_write_value_in_range_passes() {
        let ranges = vec![SafeRange {
            address: 100,
            min: 0,
            max: 1000,
        }];

        assert!(validate_write_value(100, 0, &ranges).is_ok());
        assert!(validate_write_value(100, 500, &ranges).is_ok());
        assert!(validate_write_value(100, 1000, &ranges).is_ok());
    }

    #[test]
    fn test_validate_write_value_out_of_range_returns_error() {
        let ranges = vec![SafeRange {
            address: 100,
            min: 10,
            max: 500,
        }];

        let err = validate_write_value(100, 501, &ranges).unwrap_err();
        assert_eq!(err.address, 100);
        assert_eq!(err.attempted_value, 501);
        assert_eq!(err.safe_min, 10);
        assert_eq!(err.safe_max, 500);

        let err = validate_write_value(100, 9, &ranges).unwrap_err();
        assert_eq!(err.attempted_value, 9);
    }

    #[test]
    fn test_validate_write_value_no_range_for_address_passes() {
        let ranges = vec![SafeRange {
            address: 100,
            min: 0,
            max: 1000,
        }];

        // Address 200 has no configured range — should pass
        assert!(validate_write_value(200, 65535, &ranges).is_ok());
    }

    #[test]
    fn test_validate_write_value_empty_ranges_always_passes() {
        assert!(validate_write_value(0, 0, &[]).is_ok());
        assert!(validate_write_value(100, 65535, &[]).is_ok());
    }

    #[test]
    fn test_validate_write_value_multiple_ranges() {
        let ranges = vec![
            SafeRange {
                address: 100,
                min: 0,
                max: 1000,
            },
            SafeRange {
                address: 101,
                min: 0,
                max: 500,
            },
            SafeRange {
                address: 200,
                min: 100,
                max: 200,
            },
        ];

        assert!(validate_write_value(100, 999, &ranges).is_ok());
        assert!(validate_write_value(101, 500, &ranges).is_ok());
        assert!(validate_write_value(200, 150, &ranges).is_ok());

        assert!(validate_write_value(101, 501, &ranges).is_err());
        assert!(validate_write_value(200, 99, &ranges).is_err());
    }

    #[test]
    fn test_safety_error_display() {
        let err = SafetyError {
            address: 100,
            attempted_value: 2000,
            safe_min: 0,
            safe_max: 1000,
        };
        let msg = err.to_string();
        assert!(msg.contains("2000"));
        assert!(msg.contains("100"));
        assert!(msg.contains("0"));
        assert!(msg.contains("1000"));
    }

    // -----------------------------------------------------------------------
    // Response parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_coil_response_basic() {
        // byte_count = 1, coil data = 0b00000101 → coils: 1,0,1,0,0,0,0,0
        let data = vec![0x01, 0x05];
        let values = parse_coil_response(&data, 8);
        assert_eq!(values, vec![1, 0, 1, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_parse_coil_response_partial_byte() {
        // 3 coils, byte_count=1, data = 0b00000110 → coils: 0,1,1
        let data = vec![0x01, 0x06];
        let values = parse_coil_response(&data, 3);
        assert_eq!(values, vec![0, 1, 1]);
    }

    #[test]
    fn test_parse_coil_response_multiple_bytes() {
        // 10 coils across 2 bytes
        // byte_count=2, data = [0xFF, 0x03] → first 8 all ON, then bits 0,1 ON
        let data = vec![0x02, 0xFF, 0x03];
        let values = parse_coil_response(&data, 10);
        assert_eq!(values, vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
    }

    #[test]
    fn test_parse_register_response_basic() {
        // byte_count=4, then 2 registers: 0x000A (10), 0x0014 (20)
        let data = vec![0x04, 0x00, 0x0A, 0x00, 0x14];
        let values = parse_register_response(&data);
        assert_eq!(values, vec![10, 20]);
    }

    #[test]
    fn test_parse_register_response_single() {
        // byte_count=2, one register: 0xFFFF (65535)
        let data = vec![0x02, 0xFF, 0xFF];
        let values = parse_register_response(&data);
        assert_eq!(values, vec![65535]);
    }

    #[test]
    fn test_parse_register_response_empty() {
        let values = parse_register_response(&[]);
        assert!(values.is_empty());
    }

    // -----------------------------------------------------------------------
    // Read operation PDU construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_read_pdu_fc01_coils() {
        // FC 01: Read Coils — address=0x0000, quantity=10
        let pdu = build_read_pdu_data(0x0000, 10);
        assert_eq!(pdu, vec![0x00, 0x00, 0x00, 0x0A]);
    }

    #[test]
    fn test_build_read_pdu_fc02_discrete_inputs() {
        // FC 02: Read Discrete Inputs — address=0x00C4 (196), quantity=22
        let pdu = build_read_pdu_data(0x00C4, 22);
        assert_eq!(pdu, vec![0x00, 0xC4, 0x00, 0x16]);
    }

    #[test]
    fn test_build_read_pdu_fc03_holding_registers() {
        // FC 03: Read Holding Registers — address=0x006B (107), quantity=3
        let pdu = build_read_pdu_data(0x006B, 3);
        assert_eq!(pdu, vec![0x00, 0x6B, 0x00, 0x03]);
    }

    #[test]
    fn test_build_read_pdu_fc04_input_registers() {
        // FC 04: Read Input Registers — address=0x0008, quantity=1
        let pdu = build_read_pdu_data(0x0008, 1);
        assert_eq!(pdu, vec![0x00, 0x08, 0x00, 0x01]);
    }

    #[test]
    fn test_build_read_pdu_max_values() {
        // Max address and quantity
        let pdu = build_read_pdu_data(0xFFFF, 0xFFFF);
        assert_eq!(pdu, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
