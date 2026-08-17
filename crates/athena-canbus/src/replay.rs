//! CAN Bus timed replay from a capture file.
//!
//! Reads a JSON capture file (array of `CanSniffFrame` objects) and
//! re-transmits them onto a SocketCAN interface, preserving the original
//! timing deltas between consecutive frames.

use std::path::Path;
use std::time::Instant;

use athena_common::{CanIdType, CanInjectResult, CanSniffFrame};

use crate::socket::{CanSocket, CanSocketError, RawCanFrame};

// ---------------------------------------------------------------------------
// Capture file loading
// ---------------------------------------------------------------------------

/// Load a JSON capture file containing an array of `CanSniffFrame` objects.
///
/// Returns the parsed frames on success, or a descriptive error string on
/// failure (file not found, invalid JSON, etc.).
pub fn load_capture_file(path: &Path) -> Result<Vec<CanSniffFrame>, String> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        format!("failed to read capture file '{}': {}", path.display(), e)
    })?;

    let frames: Vec<CanSniffFrame> = serde_json::from_str(&contents).map_err(|e| {
        format!(
            "failed to parse capture file '{}' as JSON: {}",
            path.display(),
            e
        )
    })?;

    Ok(frames)
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert a `CanSniffFrame` back into a `RawCanFrame` for transmission.
pub fn sniff_frame_to_raw(frame: &CanSniffFrame) -> Result<RawCanFrame, CanSocketError> {
    let extended = matches!(frame.id_type, CanIdType::Extended);
    let data = hex_decode(&frame.data_hex)
        .map_err(|e| CanSocketError::SendFailed(e))?;
    Ok(RawCanFrame::new(frame.id, extended, &data))
}

/// Decode a hex string into bytes.
///
/// Requirements:
/// - Must be even length
/// - Must contain only valid hex characters
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.is_empty() {
        return Ok(Vec::new());
    }

    if hex.len() % 2 != 0 {
        return Err(format!(
            "hex string has odd length ({}); must be even",
            hex.len()
        ));
    }

    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hex string contains invalid characters".to_string());
    }

    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();

    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Replay operation
// ---------------------------------------------------------------------------

/// Replay captured CAN frames from a file onto the specified interface.
///
/// Opens a SocketCAN socket, reads the capture file, and transmits each frame
/// with the original timing deltas between consecutive frames.
///
/// On non-Linux platforms this will return `CanSocketError::NotSupported` from
/// `CanSocket::open`.
pub fn replay(interface: &str, capture_file: &Path) -> Result<CanInjectResult, CanSocketError> {
    let frames = load_capture_file(capture_file)
        .map_err(|e| CanSocketError::SendFailed(e))?;

    let socket = CanSocket::open(interface)?;

    let mut frame_count = 0u32;
    let start = Instant::now();
    let mut last_timestamp_us = 0u64;

    for sniff_frame in &frames {
        // Sleep for the delta between consecutive frame timestamps
        let delta_us = sniff_frame.timestamp_us.saturating_sub(last_timestamp_us);
        if delta_us > 0 && frame_count > 0 {
            std::thread::sleep(std::time::Duration::from_micros(delta_us));
        }
        last_timestamp_us = sniff_frame.timestamp_us;

        // Convert CanSniffFrame back to RawCanFrame and send
        let raw = sniff_frame_to_raw(sniff_frame)?;
        socket.send_frame(&raw)?;
        frame_count += 1;
    }

    Ok(CanInjectResult {
        interface: interface.to_string(),
        frame_count,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use athena_common::CanIdType;
    use std::io::Write;

    #[test]
    fn test_hex_decode_empty() {
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_hex_decode_valid_lowercase() {
        assert_eq!(hex_decode("aabbcc").unwrap(), vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_hex_decode_valid_uppercase() {
        assert_eq!(hex_decode("AABBCC").unwrap(), vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_hex_decode_valid_mixed_case() {
        assert_eq!(hex_decode("aAbBcC").unwrap(), vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_hex_decode_odd_length_rejected() {
        let result = hex_decode("ABC");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("odd length"));
    }

    #[test]
    fn test_hex_decode_invalid_chars_rejected() {
        let result = hex_decode("GHIJ");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid characters"));
    }

    #[test]
    fn test_sniff_frame_to_raw_standard() {
        let frame = CanSniffFrame {
            timestamp_us: 1000,
            id: 0x100,
            id_type: CanIdType::Standard,
            dlc: 4,
            data_hex: "deadbeef".to_string(),
        };

        let raw = sniff_frame_to_raw(&frame).unwrap();
        assert_eq!(raw.arbitration_id(), 0x100);
        assert!(!raw.is_extended());
        assert_eq!(raw.can_dlc, 4);
        assert_eq!(&raw.data[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_sniff_frame_to_raw_extended() {
        let frame = CanSniffFrame {
            timestamp_us: 2000,
            id: 0x1ABCDEF,
            id_type: CanIdType::Extended,
            dlc: 2,
            data_hex: "0102".to_string(),
        };

        let raw = sniff_frame_to_raw(&frame).unwrap();
        assert_eq!(raw.arbitration_id(), 0x1ABCDEF);
        assert!(raw.is_extended());
        assert_eq!(raw.can_dlc, 2);
        assert_eq!(&raw.data[..2], &[0x01, 0x02]);
    }

    #[test]
    fn test_sniff_frame_to_raw_empty_data() {
        let frame = CanSniffFrame {
            timestamp_us: 0,
            id: 0x7FF,
            id_type: CanIdType::Standard,
            dlc: 0,
            data_hex: "".to_string(),
        };

        let raw = sniff_frame_to_raw(&frame).unwrap();
        assert_eq!(raw.can_dlc, 0);
    }

    #[test]
    fn test_sniff_frame_to_raw_invalid_hex() {
        let frame = CanSniffFrame {
            timestamp_us: 0,
            id: 0x100,
            id_type: CanIdType::Standard,
            dlc: 2,
            data_hex: "ZZZZ".to_string(),
        };

        let result = sniff_frame_to_raw(&frame);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_capture_file_valid_json() {
        let frames = vec![
            CanSniffFrame {
                timestamp_us: 0,
                id: 0x100,
                id_type: CanIdType::Standard,
                dlc: 2,
                data_hex: "aabb".to_string(),
            },
            CanSniffFrame {
                timestamp_us: 1000,
                id: 0x200,
                id_type: CanIdType::Standard,
                dlc: 4,
                data_hex: "deadbeef".to_string(),
            },
        ];

        let json = serde_json::to_string(&frames).unwrap();
        let dir = std::env::temp_dir();
        let path = dir.join("test_capture_valid.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(json.as_bytes()).unwrap();

        let loaded = load_capture_file(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, 0x100);
        assert_eq!(loaded[1].id, 0x200);
        assert_eq!(loaded[0].data_hex, "aabb");
        assert_eq!(loaded[1].data_hex, "deadbeef");

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_capture_file_missing_file() {
        let path = Path::new("/nonexistent/path/capture.json");
        let result = load_capture_file(path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to read"));
    }

    #[test]
    fn test_load_capture_file_invalid_json() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_capture_invalid.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"not valid json").unwrap();

        let result = load_capture_file(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to parse"));

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_capture_file_empty_array() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_capture_empty.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"[]").unwrap();

        let loaded = load_capture_file(&path).unwrap();
        assert!(loaded.is_empty());

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_replay_returns_not_supported_on_non_linux() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_replay_notsupported.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"[]").unwrap();

        let result = replay("vcan0", &path);
        assert_eq!(result.unwrap_err(), CanSocketError::NotSupported);

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }
}
