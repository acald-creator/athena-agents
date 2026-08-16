//! MBAP (Modbus Application Protocol) header and PDU encoding/decoding.
//!
//! Implements the Modbus TCP frame format:
//! ```text
//! ┌────────────────┬────────────────┬────────┬─────────┬──────────────┬──────────┐
//! │ Transaction ID │ Protocol ID    │ Length  │ Unit ID │ Function Code│  Data    │
//! │ (2 bytes BE)   │ (2 bytes, 0x0) │(2 bytes)│ (1 byte)│ (1 byte)     │(variable)│
//! └────────────────┴────────────────┴────────┴─────────┴──────────────┴──────────┘
//! ```

use std::sync::atomic::{AtomicU16, Ordering};

/// MBAP (Modbus Application Protocol) header.
///
/// The 7-byte header precedes the Modbus PDU in Modbus TCP communication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbapHeader {
    /// Client-generated transaction identifier, incremented per request.
    pub transaction_id: u16,
    /// Protocol identifier — always 0x0000 for Modbus.
    pub protocol_id: u16,
    /// Number of following bytes (unit_id + PDU).
    pub length: u16,
    /// Target device address (1–247).
    pub unit_id: u8,
}

/// A Modbus TCP request (MBAP header + function code + data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModbusRequest {
    pub header: MbapHeader,
    pub function_code: u8,
    pub data: Vec<u8>,
}

/// A Modbus TCP response (MBAP header + function code + data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModbusResponse {
    pub header: MbapHeader,
    pub function_code: u8,
    pub data: Vec<u8>,
}

/// A Modbus exception received from the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModbusException {
    /// The original function code (without the 0x80 exception flag).
    pub function_code: u8,
    /// The exception code returned by the device.
    pub exception_code: u8,
}

/// Errors that can occur when decoding a Modbus response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModbusError {
    /// The device returned an exception response.
    Exception(ModbusException),
    /// The response is structurally invalid.
    InvalidResponse(String),
    /// The response buffer is too short to contain a valid frame.
    FrameTooShort,
}

impl std::fmt::Display for ModbusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModbusError::Exception(ex) => write!(
                f,
                "Modbus exception: FC={:#04x}, exception code={:#04x}",
                ex.function_code, ex.exception_code
            ),
            ModbusError::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            ModbusError::FrameTooShort => write!(f, "Frame too short"),
        }
    }
}

impl std::error::Error for ModbusError {}

/// Sequential transaction ID counter with wrapping at `u16::MAX`.
pub struct TransactionCounter {
    counter: AtomicU16,
}

impl TransactionCounter {
    /// Create a new counter starting at 0.
    pub fn new() -> Self {
        Self {
            counter: AtomicU16::new(0),
        }
    }

    /// Get the next transaction ID. Wraps around after `u16::MAX`.
    pub fn next(&self) -> u16 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for TransactionCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a Modbus request into a byte vector (big-endian wire format).
///
/// Wire format:
/// - Transaction ID (2 bytes, big-endian)
/// - Protocol ID (2 bytes, big-endian) — always 0x0000
/// - Length (2 bytes, big-endian) — unit_id(1) + function_code(1) + data.len()
/// - Unit ID (1 byte)
/// - Function Code (1 byte)
/// - Data (variable)
pub fn encode_request(request: &ModbusRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(7 + 1 + request.data.len());

    // MBAP Header
    buf.extend_from_slice(&request.header.transaction_id.to_be_bytes());
    buf.extend_from_slice(&request.header.protocol_id.to_be_bytes());
    buf.extend_from_slice(&request.header.length.to_be_bytes());
    buf.push(request.header.unit_id);

    // PDU
    buf.push(request.function_code);
    buf.extend_from_slice(&request.data);

    buf
}

/// Decode a Modbus TCP response from raw bytes.
///
/// Detects exception responses (function code with high bit set) and returns
/// `ModbusError::Exception` in that case.
pub fn decode_response(bytes: &[u8]) -> Result<ModbusResponse, ModbusError> {
    // Minimum frame: 7 (MBAP header) + 1 (function code) = 8 bytes
    if bytes.len() < 8 {
        return Err(ModbusError::FrameTooShort);
    }

    let transaction_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let protocol_id = u16::from_be_bytes([bytes[2], bytes[3]]);
    let length = u16::from_be_bytes([bytes[4], bytes[5]]);
    let unit_id = bytes[6];
    let function_code = bytes[7];

    // Validate protocol ID
    if protocol_id != 0x0000 {
        return Err(ModbusError::InvalidResponse(format!(
            "unexpected protocol ID: {:#06x}",
            protocol_id
        )));
    }

    // Validate length field: must be at least 2 (unit_id + function_code)
    if length < 2 {
        return Err(ModbusError::InvalidResponse(format!(
            "length field too small: {}",
            length
        )));
    }

    // Validate we have enough bytes for the declared length
    // MBAP header is 6 bytes (transaction_id + protocol_id + length), then `length` more bytes follow
    let expected_total = 6 + length as usize;
    if bytes.len() < expected_total {
        return Err(ModbusError::FrameTooShort);
    }

    // Check for exception response: high bit set on function code
    if function_code & 0x80 != 0 {
        let original_fc = function_code & 0x7F;
        let exception_code = if bytes.len() > 8 { bytes[8] } else { 0 };
        return Err(ModbusError::Exception(ModbusException {
            function_code: original_fc,
            exception_code,
        }));
    }

    // Extract data (everything after function code)
    let data = bytes[8..expected_total].to_vec();

    let header = MbapHeader {
        transaction_id,
        protocol_id,
        length,
        unit_id,
    };

    Ok(ModbusResponse {
        header,
        function_code,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_request_fc03_read_holding_registers() {
        // FC 03: Read Holding Registers
        // Read 2 registers starting at address 0x0000 from unit 1
        let request = ModbusRequest {
            header: MbapHeader {
                transaction_id: 0x0001,
                protocol_id: 0x0000,
                // length = unit_id(1) + FC(1) + data(4) = 6
                length: 6,
                unit_id: 1,
            },
            function_code: 0x03,
            data: vec![
                0x00, 0x00, // start address = 0
                0x00, 0x02, // quantity = 2
            ],
        };

        let encoded = encode_request(&request);

        // Expected wire format:
        // Transaction ID: 00 01
        // Protocol ID:    00 00
        // Length:          00 06
        // Unit ID:        01
        // Function Code:  03
        // Start Address:  00 00
        // Quantity:       00 02
        let expected: Vec<u8> = vec![
            0x00, 0x01, // transaction_id
            0x00, 0x00, // protocol_id
            0x00, 0x06, // length
            0x01, // unit_id
            0x03, // function_code
            0x00, 0x00, // start address
            0x00, 0x02, // quantity
        ];

        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_decode_response_valid() {
        // Valid response to FC 03 (Read Holding Registers)
        // Returns 2 registers (4 bytes of data)
        let response_bytes: Vec<u8> = vec![
            0x00, 0x01, // transaction_id = 1
            0x00, 0x00, // protocol_id = 0
            0x00, 0x07, // length = 7 (unit_id + FC + byte_count + 4 data bytes)
            0x01, // unit_id = 1
            0x03, // function_code = 3
            0x04, // byte count = 4
            0x00, 0x0A, // register 0 = 10
            0x00, 0x14, // register 1 = 20
        ];

        let result = decode_response(&response_bytes);
        assert!(result.is_ok());

        let resp = result.unwrap();
        assert_eq!(resp.header.transaction_id, 0x0001);
        assert_eq!(resp.header.protocol_id, 0x0000);
        assert_eq!(resp.header.length, 7);
        assert_eq!(resp.header.unit_id, 1);
        assert_eq!(resp.function_code, 0x03);
        assert_eq!(resp.data, vec![0x04, 0x00, 0x0A, 0x00, 0x14]);
    }

    #[test]
    fn test_decode_response_exception() {
        // Exception response: FC 03 with exception (FC | 0x80 = 0x83)
        // Exception code 0x02 = Illegal Data Address
        let exception_bytes: Vec<u8> = vec![
            0x00, 0x01, // transaction_id
            0x00, 0x00, // protocol_id
            0x00, 0x03, // length = 3 (unit_id + exception_FC + exception_code)
            0x01, // unit_id
            0x83, // function_code = 0x03 | 0x80
            0x02, // exception code = 2 (Illegal Data Address)
        ];

        let result = decode_response(&exception_bytes);
        assert!(result.is_err());

        match result.unwrap_err() {
            ModbusError::Exception(ex) => {
                assert_eq!(ex.function_code, 0x03);
                assert_eq!(ex.exception_code, 0x02);
            }
            other => panic!("Expected ModbusError::Exception, got {:?}", other),
        }
    }

    #[test]
    fn test_decode_response_frame_too_short() {
        // Only 5 bytes — less than the minimum 8 required
        let short_bytes: Vec<u8> = vec![0x00, 0x01, 0x00, 0x00, 0x00];

        let result = decode_response(&short_bytes);
        assert_eq!(result.unwrap_err(), ModbusError::FrameTooShort);
    }

    #[test]
    fn test_decode_response_frame_too_short_declared_length() {
        // Header says length=10 but we only have 8 total bytes
        let bytes: Vec<u8> = vec![
            0x00, 0x01, // transaction_id
            0x00, 0x00, // protocol_id
            0x00, 0x0A, // length = 10 (declares more data than available)
            0x01, // unit_id
            0x03, // function_code
        ];

        let result = decode_response(&bytes);
        assert_eq!(result.unwrap_err(), ModbusError::FrameTooShort);
    }

    #[test]
    fn test_transaction_counter_sequential() {
        let counter = TransactionCounter::new();
        assert_eq!(counter.next(), 0);
        assert_eq!(counter.next(), 1);
        assert_eq!(counter.next(), 2);
    }

    #[test]
    fn test_transaction_counter_wraps_at_u16_max() {
        let counter = TransactionCounter {
            counter: AtomicU16::new(u16::MAX),
        };

        // Should return u16::MAX then wrap to 0
        assert_eq!(counter.next(), u16::MAX);
        assert_eq!(counter.next(), 0);
        assert_eq!(counter.next(), 1);
    }

    #[test]
    fn test_decode_response_invalid_protocol_id() {
        let bytes: Vec<u8> = vec![
            0x00, 0x01, // transaction_id
            0x00, 0x01, // protocol_id = 1 (invalid, must be 0)
            0x00, 0x03, // length
            0x01, // unit_id
            0x03, // function_code
            0x00, // data
        ];

        let result = decode_response(&bytes);
        match result.unwrap_err() {
            ModbusError::InvalidResponse(msg) => {
                assert!(msg.contains("protocol ID"));
            }
            other => panic!("Expected InvalidResponse, got {:?}", other),
        }
    }
}
