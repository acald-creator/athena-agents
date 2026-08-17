//! CAN Bus frame capture (sniffing) for a specified duration.
//!
//! Reads frames from a SocketCAN interface and records each frame with a
//! microsecond-resolution timestamp relative to the sniff start time.

use std::time::Instant;

use athena_common::{CanIdType, CanSniffFrame, CanSniffResult};

use crate::socket::{CanSocket, CanSocketError, RawCanFrame};

// ---------------------------------------------------------------------------
// Conversion helper
// ---------------------------------------------------------------------------

/// Convert a `RawCanFrame` into a `CanSniffFrame` with a timestamp relative
/// to the provided start time.
pub fn raw_frame_to_sniff_frame(frame: &RawCanFrame, start_time: Instant) -> CanSniffFrame {
    let id_type = if frame.is_extended() {
        CanIdType::Extended
    } else {
        CanIdType::Standard
    };

    let dlc = frame.can_dlc.min(8) as usize;
    let data_hex = bytes_to_hex(&frame.data[..dlc]);

    CanSniffFrame {
        timestamp_us: start_time.elapsed().as_micros() as u64,
        id: frame.arbitration_id(),
        id_type,
        dlc: frame.can_dlc,
        data_hex,
    }
}

// ---------------------------------------------------------------------------
// Sniff operation
// ---------------------------------------------------------------------------

/// Capture CAN frames from `interface` for `duration_ms` milliseconds.
///
/// Opens a SocketCAN socket, reads frames in a loop until the duration elapses,
/// and returns the captured frames with relative timestamps.
///
/// On non-Linux platforms this will return `CanSocketError::NotSupported` from
/// `CanSocket::open`.
pub fn sniff(interface: &str, duration_ms: u64) -> Result<CanSniffResult, CanSocketError> {
    let socket = CanSocket::open(interface)?;
    let start = Instant::now();
    let mut frames = Vec::new();

    while (start.elapsed().as_millis() as u64) < duration_ms {
        let elapsed = start.elapsed().as_millis() as u64;
        let remaining_ms = duration_ms.saturating_sub(elapsed);
        if remaining_ms == 0 {
            break;
        }

        // Poll with at most 100ms timeout to allow loop re-evaluation
        let poll_timeout = remaining_ms.min(100);
        match socket.recv_frame(poll_timeout) {
            Ok(Some(frame)) => {
                frames.push(raw_frame_to_sniff_frame(&frame, start));
            }
            Ok(None) => {
                // No frame available, continue
            }
            Err(CanSocketError::Timeout) => {
                // No frame in this interval, keep waiting
            }
            Err(e) => return Err(e),
        }
    }

    Ok(CanSniffResult {
        interface: interface.to_string(),
        duration_ms,
        frames,
    })
}

// ---------------------------------------------------------------------------
// Hex encoding helper
// ---------------------------------------------------------------------------

/// Encode a byte slice as a lowercase hex string.
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_raw_frame_to_sniff_frame_standard() {
        let frame = RawCanFrame::new(0x123, false, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let start = Instant::now();
        // Small sleep to ensure non-zero timestamp
        std::thread::sleep(std::time::Duration::from_micros(10));
        let sniff_frame = raw_frame_to_sniff_frame(&frame, start);

        assert_eq!(sniff_frame.id, 0x123);
        assert_eq!(sniff_frame.id_type, CanIdType::Standard);
        assert_eq!(sniff_frame.dlc, 4);
        assert_eq!(sniff_frame.data_hex, "deadbeef");
        assert!(sniff_frame.timestamp_us > 0);
    }

    #[test]
    fn test_raw_frame_to_sniff_frame_extended() {
        let frame = RawCanFrame::new(0x1ABCDEF, true, &[0x01, 0x02]);
        let start = Instant::now();
        let sniff_frame = raw_frame_to_sniff_frame(&frame, start);

        assert_eq!(sniff_frame.id, 0x1ABCDEF);
        assert_eq!(sniff_frame.id_type, CanIdType::Extended);
        assert_eq!(sniff_frame.dlc, 2);
        assert_eq!(sniff_frame.data_hex, "0102");
    }

    #[test]
    fn test_raw_frame_to_sniff_frame_empty_data() {
        let frame = RawCanFrame::new(0x000, false, &[]);
        let start = Instant::now();
        let sniff_frame = raw_frame_to_sniff_frame(&frame, start);

        assert_eq!(sniff_frame.id, 0x000);
        assert_eq!(sniff_frame.dlc, 0);
        assert_eq!(sniff_frame.data_hex, "");
    }

    #[test]
    fn test_bytes_to_hex_empty() {
        assert_eq!(bytes_to_hex(&[]), "");
    }

    #[test]
    fn test_bytes_to_hex_single_byte() {
        assert_eq!(bytes_to_hex(&[0x0A]), "0a");
    }

    #[test]
    fn test_bytes_to_hex_multiple_bytes() {
        assert_eq!(bytes_to_hex(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn test_bytes_to_hex_leading_zero() {
        assert_eq!(bytes_to_hex(&[0x01, 0x02, 0x03]), "010203");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_sniff_returns_not_supported_on_non_linux() {
        let result = sniff("vcan0", 1000);
        assert_eq!(result.unwrap_err(), CanSocketError::NotSupported);
    }
}
