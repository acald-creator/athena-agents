//! Async Modbus TCP client with timeout handling.
//!
//! Provides connection management and request/response framing over TCP
//! using tokio for async I/O and timeouts.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::frame::{
    decode_response, encode_request, MbapHeader, ModbusError, ModbusRequest, ModbusResponse,
    TransactionCounter,
};

/// Async Modbus TCP client.
///
/// Maintains a TCP connection and a sequential transaction counter for
/// building MBAP headers. All operations use the configured timeout.
pub struct ModbusClient {
    stream: TcpStream,
    transaction_counter: TransactionCounter,
    timeout_ms: u64,
}

impl std::fmt::Debug for ModbusClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModbusClient")
            .field("timeout_ms", &self.timeout_ms)
            .finish_non_exhaustive()
    }
}

/// Errors that can occur during Modbus TCP client operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModbusClientError {
    /// TCP connection timed out.
    ConnectionTimeout { target: String, timeout_ms: u64 },
    /// TCP connection failed (refused, unreachable, DNS failure, etc.).
    ConnectionError { target: String, reason: String },
    /// No response received within the configured timeout.
    ResponseTimeout { timeout_ms: u64 },
    /// The device returned a Modbus exception.
    ModbusException { function_code: u8, exception_code: u8 },
    /// The response frame was structurally invalid.
    InvalidResponse(String),
    /// An I/O error occurred during read/write.
    IoError(String),
    /// A write value violated a configured safe range.
    SafetyViolation(crate::SafetyError),
}

impl std::fmt::Display for ModbusClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModbusClientError::ConnectionTimeout { target, timeout_ms } => {
                write!(
                    f,
                    "connection timeout: failed to connect to {} within {}ms",
                    target, timeout_ms
                )
            }
            ModbusClientError::ConnectionError { target, reason } => {
                write!(f, "connection error to {}: {}", target, reason)
            }
            ModbusClientError::ResponseTimeout { timeout_ms } => {
                write!(
                    f,
                    "response timeout: no response received within {}ms",
                    timeout_ms
                )
            }
            ModbusClientError::ModbusException {
                function_code,
                exception_code,
            } => {
                write!(
                    f,
                    "Modbus exception: FC={:#04x}, exception code={:#04x}",
                    function_code, exception_code
                )
            }
            ModbusClientError::InvalidResponse(msg) => {
                write!(f, "invalid response: {}", msg)
            }
            ModbusClientError::IoError(msg) => {
                write!(f, "I/O error: {}", msg)
            }
            ModbusClientError::SafetyViolation(err) => {
                write!(f, "{}", err)
            }
        }
    }
}

impl std::error::Error for ModbusClientError {}

impl ModbusClient {
    /// Connect to a Modbus TCP target.
    ///
    /// `target` is a `host:port` string. If no port is specified, defaults to 502.
    /// The connection attempt is bounded by `timeout_ms`.
    ///
    /// # Errors
    ///
    /// - `ModbusClientError::ConnectionTimeout` if the TCP connection is not
    ///   established within `timeout_ms`.
    /// - `ModbusClientError::ConnectionError` if the connection is refused or
    ///   otherwise fails.
    pub async fn connect(target: &str, timeout_ms: u64) -> Result<Self, ModbusClientError> {
        // Parse target — append default port 502 if not specified
        let address = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:502", target)
        };

        let duration = Duration::from_millis(timeout_ms);

        let stream = match timeout(duration, TcpStream::connect(&address)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Err(ModbusClientError::ConnectionError {
                    target: address,
                    reason: e.to_string(),
                });
            }
            Err(_elapsed) => {
                return Err(ModbusClientError::ConnectionTimeout {
                    target: address,
                    timeout_ms,
                });
            }
        };

        Ok(Self {
            stream,
            transaction_counter: TransactionCounter::new(),
            timeout_ms,
        })
    }

    /// Send a Modbus request and wait for the response.
    ///
    /// Builds a `ModbusRequest` with the next transaction ID, encodes it,
    /// writes it to the TCP stream, reads the response, and decodes it.
    ///
    /// # Errors
    ///
    /// - `ModbusClientError::IoError` if the write or read fails.
    /// - `ModbusClientError::ResponseTimeout` if no response arrives within
    ///   the configured timeout.
    /// - `ModbusClientError::ModbusException` if the device returns an exception.
    /// - `ModbusClientError::InvalidResponse` if the response frame is malformed.
    pub async fn send_request(
        &mut self,
        unit_id: u8,
        function_code: u8,
        data: Vec<u8>,
    ) -> Result<ModbusResponse, ModbusClientError> {
        let transaction_id = self.transaction_counter.next();

        // length = unit_id (1) + function_code (1) + data.len()
        let length = 1 + 1 + data.len() as u16;

        let request = ModbusRequest {
            header: MbapHeader {
                transaction_id,
                protocol_id: 0x0000,
                length,
                unit_id,
            },
            function_code,
            data,
        };

        let encoded = encode_request(&request);

        // Write the request
        self.stream
            .write_all(&encoded)
            .await
            .map_err(|e| ModbusClientError::IoError(e.to_string()))?;

        // Read response with timeout
        let duration = Duration::from_millis(self.timeout_ms);

        // Read MBAP header first (7 bytes) to determine response length
        let mut header_buf = [0u8; 7];
        match timeout(duration, self.stream.read_exact(&mut header_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                return Err(ModbusClientError::IoError(e.to_string()));
            }
            Err(_elapsed) => {
                return Err(ModbusClientError::ResponseTimeout {
                    timeout_ms: self.timeout_ms,
                });
            }
        }

        // Parse length from header to know how many more bytes to read
        let pdu_length = u16::from_be_bytes([header_buf[4], header_buf[5]]) as usize;

        // length field includes unit_id (already in header_buf[6]) + PDU
        // We already have unit_id in the header, so remaining = pdu_length - 1
        let remaining = if pdu_length > 1 { pdu_length - 1 } else { 0 };

        let mut pdu_buf = vec![0u8; remaining];
        if remaining > 0 {
            match timeout(duration, self.stream.read_exact(&mut pdu_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    return Err(ModbusClientError::IoError(e.to_string()));
                }
                Err(_elapsed) => {
                    return Err(ModbusClientError::ResponseTimeout {
                        timeout_ms: self.timeout_ms,
                    });
                }
            }
        }

        // Reconstruct full response buffer for decode_response
        let mut full_response = Vec::with_capacity(7 + remaining);
        full_response.extend_from_slice(&header_buf);
        full_response.extend_from_slice(&pdu_buf);

        // Decode the response
        match decode_response(&full_response) {
            Ok(response) => Ok(response),
            Err(ModbusError::Exception(ex)) => Err(ModbusClientError::ModbusException {
                function_code: ex.function_code,
                exception_code: ex.exception_code,
            }),
            Err(ModbusError::InvalidResponse(msg)) => {
                Err(ModbusClientError::InvalidResponse(msg))
            }
            Err(ModbusError::FrameTooShort) => Err(ModbusClientError::InvalidResponse(
                "response frame too short".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_timeout_error_display() {
        let err = ModbusClientError::ConnectionTimeout {
            target: "192.168.1.100:502".to_string(),
            timeout_ms: 5000,
        };
        let msg = err.to_string();
        assert!(msg.contains("192.168.1.100:502"));
        assert!(msg.contains("5000"));
        assert!(msg.contains("timeout"));
    }

    #[test]
    fn test_connection_error_display() {
        let err = ModbusClientError::ConnectionError {
            target: "10.0.0.1:502".to_string(),
            reason: "Connection refused".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("10.0.0.1:502"));
        assert!(msg.contains("Connection refused"));
    }

    #[test]
    fn test_response_timeout_error_display() {
        let err = ModbusClientError::ResponseTimeout { timeout_ms: 3000 };
        let msg = err.to_string();
        assert!(msg.contains("3000"));
        assert!(msg.contains("response"));
    }

    #[test]
    fn test_modbus_exception_error_display() {
        let err = ModbusClientError::ModbusException {
            function_code: 0x03,
            exception_code: 0x02,
        };
        let msg = err.to_string();
        assert!(msg.contains("0x03"));
        assert!(msg.contains("0x02"));
    }

    #[test]
    fn test_invalid_response_error_display() {
        let err = ModbusClientError::InvalidResponse("bad protocol ID".to_string());
        let msg = err.to_string();
        assert!(msg.contains("bad protocol ID"));
    }

    #[test]
    fn test_io_error_display() {
        let err = ModbusClientError::IoError("broken pipe".to_string());
        let msg = err.to_string();
        assert!(msg.contains("broken pipe"));
    }

    #[tokio::test]
    async fn test_connect_to_nonexistent_port_returns_connection_error() {
        // Attempt to connect to a port that (almost certainly) has nothing listening.
        // Using localhost on a high ephemeral port to avoid external dependencies.
        let result = ModbusClient::connect("127.0.0.1:19999", 2000).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            ModbusClientError::ConnectionError { target, reason } => {
                assert_eq!(target, "127.0.0.1:19999");
                assert!(!reason.is_empty());
            }
            ModbusClientError::ConnectionTimeout { .. } => {
                // Also acceptable — on some systems a refused connection may
                // appear as a timeout depending on network configuration.
            }
            other => panic!(
                "Expected ConnectionError or ConnectionTimeout, got {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_connect_default_port_appended() {
        // Connecting to just a hostname without port should append :502
        // This will fail to connect, but we verify the target includes :502
        let result = ModbusClient::connect("127.0.0.1", 500).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            ModbusClientError::ConnectionError { target, .. }
            | ModbusClientError::ConnectionTimeout { target, .. } => {
                assert_eq!(target, "127.0.0.1:502");
            }
            other => panic!("Expected connection error variant, got {:?}", other),
        }
    }
}
