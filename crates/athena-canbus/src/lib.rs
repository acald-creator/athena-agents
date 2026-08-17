//! CAN Bus frame crafting and injection for Athena ICS offensive primitives.
//!
//! This crate provides CAN frame validation, crafting, injection, sniffing,
//! replay, and fuzzing operations over Linux virtual CAN (vcan) interfaces.
//!
//! # Modules
//!
//! - Frame validation and crafting (this file)
//! - `socket` — SocketCAN raw socket wrapper
//! - `sniff` — Frame capture with duration
//! - `replay` — Timed replay from capture file
//! - `fuzz` — Deterministic CAN fuzzer (xoshiro256++)

pub mod fuzz;
pub mod replay;
pub mod sniff;
pub mod socket;

use athena_common::{CanCraftResult, CanIdType};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum valid standard CAN arbitration ID (11 bits).
pub const MAX_STANDARD_ID: u32 = 0x7FF;

/// Maximum valid extended CAN arbitration ID (29 bits).
pub const MAX_EXTENDED_ID: u32 = 0x1FFFFFFF;

/// Maximum number of data bytes in a CAN frame.
pub const MAX_CAN_DATA_BYTES: usize = 8;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a CAN arbitration ID against the appropriate range.
///
/// - Standard (not extended): ID must be 0–0x7FF (11 bits)
/// - Extended: ID must be 0–0x1FFFFFFF (29 bits)
///
/// Returns `Ok(())` if the ID is valid, or a descriptive error message on failure.
pub fn validate_can_id(id: u32, extended: bool) -> Result<(), String> {
    if extended {
        if id > MAX_EXTENDED_ID {
            return Err(format!(
                "extended CAN ID 0x{:X} exceeds maximum 0x{:X} (29 bits)",
                id, MAX_EXTENDED_ID
            ));
        }
    } else if id > MAX_STANDARD_ID {
        return Err(format!(
            "standard CAN ID 0x{:X} exceeds maximum 0x{:X} (11 bits)",
            id, MAX_STANDARD_ID
        ));
    }
    Ok(())
}

/// Validate a hex-encoded data string for CAN frame payload.
///
/// Requirements:
/// - Must be even length (each byte is 2 hex characters)
/// - Must contain only valid hex characters (0-9, a-f, A-F)
/// - Must produce at most 8 bytes (max 16 hex characters)
///
/// Returns the parsed bytes on success, or a descriptive error message on failure.
pub fn validate_data(data_hex: &str) -> Result<Vec<u8>, String> {
    if data_hex.is_empty() {
        return Ok(Vec::new());
    }

    if data_hex.len() % 2 != 0 {
        return Err(format!(
            "data hex string has odd length ({}); must be even",
            data_hex.len()
        ));
    }

    if !data_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("data hex string contains invalid characters; only 0-9, a-f, A-F allowed".to_string());
    }

    let byte_count = data_hex.len() / 2;
    if byte_count > MAX_CAN_DATA_BYTES {
        return Err(format!(
            "data length {} bytes exceeds maximum {} bytes for CAN frame",
            byte_count, MAX_CAN_DATA_BYTES
        ));
    }

    let bytes: Vec<u8> = (0..data_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&data_hex[i..i + 2], 16).unwrap())
        .collect();

    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Frame Crafting
// ---------------------------------------------------------------------------

/// Craft a CAN frame from the given parameters.
///
/// Validates the ID and data, calculates the DLC, and returns a `CanCraftResult`
/// with the data hex normalized to lowercase.
pub fn craft_frame(id: u32, extended: bool, data_hex: &str) -> Result<CanCraftResult, String> {
    validate_can_id(id, extended)?;
    let data_bytes = validate_data(data_hex)?;

    let dlc = data_bytes.len() as u8;
    let id_type = if extended {
        CanIdType::Extended
    } else {
        CanIdType::Standard
    };

    Ok(CanCraftResult {
        id,
        id_type,
        dlc,
        data_hex: data_hex.to_lowercase(),
    })
}

// ---------------------------------------------------------------------------
// Injection
// ---------------------------------------------------------------------------

/// Inject a single CAN frame onto the specified interface.
///
/// Validates the frame parameters, opens a SocketCAN socket, transmits
/// the frame, and returns the injection result with timing information.
///
/// On non-Linux platforms this will return `CanSocketError::NotSupported`
/// from `CanSocket::open`.
pub fn inject_frame(
    interface: &str,
    id: u32,
    extended: bool,
    data_hex: &str,
) -> Result<athena_common::CanInjectResult, socket::CanSocketError> {
    validate_can_id(id, extended)
        .map_err(|e| socket::CanSocketError::SendFailed(e))?;
    let data = validate_data(data_hex)
        .map_err(|e| socket::CanSocketError::SendFailed(e))?;

    let frame = socket::RawCanFrame::new(id, extended, &data);
    let sock = socket::CanSocket::open(interface)?;
    let start = std::time::Instant::now();
    sock.send_frame(&frame)?;

    Ok(athena_common::CanInjectResult {
        interface: interface.to_string(),
        frame_count: 1,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- validate_can_id tests ---

    #[test]
    fn test_standard_id_at_max_boundary_valid() {
        assert!(validate_can_id(MAX_STANDARD_ID, false).is_ok());
    }

    #[test]
    fn test_standard_id_above_max_boundary_invalid() {
        let result = validate_can_id(0x800, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("standard CAN ID"));
    }

    #[test]
    fn test_extended_id_at_max_boundary_valid() {
        assert!(validate_can_id(MAX_EXTENDED_ID, true).is_ok());
    }

    #[test]
    fn test_extended_id_above_max_boundary_invalid() {
        let result = validate_can_id(0x20000000, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("extended CAN ID"));
    }

    #[test]
    fn test_standard_id_zero_valid() {
        assert!(validate_can_id(0, false).is_ok());
    }

    #[test]
    fn test_extended_id_zero_valid() {
        assert!(validate_can_id(0, true).is_ok());
    }

    // --- validate_data tests ---

    #[test]
    fn test_empty_data_valid() {
        let result = validate_data("").unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_max_data_8_bytes_valid() {
        let result = validate_data("0102030405060708").unwrap();
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_data_exceeding_8_bytes_invalid() {
        let result = validate_data("010203040506070809");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum"));
    }

    #[test]
    fn test_invalid_hex_characters_rejected() {
        let result = validate_data("GHIJ");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    #[test]
    fn test_odd_length_hex_rejected() {
        let result = validate_data("ABC");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("odd length"));
    }

    #[test]
    fn test_valid_uppercase_hex() {
        let result = validate_data("AABBCC").unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_valid_mixed_case_hex() {
        let result = validate_data("aAbBcC").unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC]);
    }

    // --- craft_frame tests ---

    #[test]
    fn test_craft_produces_correct_result_with_lowercase_hex() {
        let result = craft_frame(0x100, false, "DEADBEEF").unwrap();
        assert_eq!(result.id, 0x100);
        assert_eq!(result.id_type, CanIdType::Standard);
        assert_eq!(result.dlc, 4);
        assert_eq!(result.data_hex, "deadbeef");
    }

    #[test]
    fn test_craft_extended_frame() {
        let result = craft_frame(0x1FFFFFFF, true, "0102").unwrap();
        assert_eq!(result.id, 0x1FFFFFFF);
        assert_eq!(result.id_type, CanIdType::Extended);
        assert_eq!(result.dlc, 2);
        assert_eq!(result.data_hex, "0102");
    }

    #[test]
    fn test_craft_empty_data() {
        let result = craft_frame(0x7FF, false, "").unwrap();
        assert_eq!(result.dlc, 0);
        assert_eq!(result.data_hex, "");
    }

    #[test]
    fn test_craft_with_invalid_id_returns_error() {
        let result = craft_frame(0x800, false, "AABB");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("standard CAN ID"));
    }

    #[test]
    fn test_craft_with_invalid_data_returns_error() {
        let result = craft_frame(0x100, false, "ZZZZ");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    // --- inject_frame tests ---

    #[test]
    fn test_inject_frame_invalid_id_returns_error() {
        let result = inject_frame("vcan0", 0x800, false, "AABB");
        assert!(result.is_err());
        match result.unwrap_err() {
            socket::CanSocketError::SendFailed(msg) => {
                assert!(msg.contains("standard CAN ID"));
            }
            #[cfg(not(target_os = "linux"))]
            socket::CanSocketError::NotSupported => {
                // On non-Linux, validation happens first, so this
                // should not occur — but handle gracefully.
                panic!("expected SendFailed for invalid ID, got NotSupported");
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_inject_frame_invalid_data_returns_error() {
        let result = inject_frame("vcan0", 0x100, false, "ZZZZ");
        assert!(result.is_err());
        match result.unwrap_err() {
            socket::CanSocketError::SendFailed(msg) => {
                assert!(msg.contains("invalid characters"));
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_inject_frame_returns_not_supported_on_non_linux() {
        // Valid parameters — should pass validation, then fail at socket open
        let result = inject_frame("vcan0", 0x100, false, "AABB");
        assert_eq!(result.unwrap_err(), socket::CanSocketError::NotSupported);
    }
}
