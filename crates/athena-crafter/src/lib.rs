//! Core packet crafting logic for the Athena packet crafter.
//!
//! This module provides validation and packet length calculation for
//! TCP, UDP, and ICMP protocols. It validates hex payloads, port ranges,
//! and TCP flag combinations before producing a [`CraftResult`].

use athena_common::CraftResult;

/// IP header size in bytes (standard, no options).
const IP_HEADER_SIZE: usize = 20;
/// TCP header size in bytes (standard, no options).
const TCP_HEADER_SIZE: usize = 20;
/// UDP header size in bytes.
const UDP_HEADER_SIZE: usize = 8;
/// ICMP header size in bytes.
const ICMP_HEADER_SIZE: usize = 8;

/// Supported protocol types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    /// Parse a protocol string (case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            "icmp" => Some(Protocol::Icmp),
            _ => None,
        }
    }

    /// Return the canonical name for this protocol.
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
        }
    }

    /// Return the transport header size for this protocol.
    fn header_size(&self) -> usize {
        match self {
            Protocol::Tcp => TCP_HEADER_SIZE,
            Protocol::Udp => UDP_HEADER_SIZE,
            Protocol::Icmp => ICMP_HEADER_SIZE,
        }
    }
}

/// Valid TCP flags.
const VALID_TCP_FLAGS: &[&str] = &["SYN", "ACK", "FIN", "RST", "PSH", "URG"];

/// Validate that a port number is in the valid range (1-65535).
pub fn validate_port(port: u16, name: &str) -> Result<(), String> {
    if port == 0 {
        return Err(format!("{} must be between 1 and 65535, got 0", name));
    }
    Ok(())
}

/// Validate a hex payload string.
///
/// The payload must:
/// - Contain only valid hex characters (0-9, a-f, A-F)
/// - Have an even number of characters
pub fn validate_payload_hex(payload: &str) -> Result<(), String> {
    if payload.is_empty() {
        // Empty payload is valid (0 bytes).
        return Ok(());
    }

    if payload.len() % 2 != 0 {
        return Err(format!(
            "payload hex must have even number of characters, got {}",
            payload.len()
        ));
    }

    for (i, c) in payload.chars().enumerate() {
        if !c.is_ascii_hexdigit() {
            return Err(format!(
                "payload contains invalid hex character '{}' at position {}",
                c, i
            ));
        }
    }

    Ok(())
}

/// Validate TCP flags string.
///
/// Flags should be a comma-separated list of valid TCP flags:
/// SYN, ACK, FIN, RST, PSH, URG.
///
/// Returns an error if:
/// - The protocol is not TCP
/// - Any flag is not a valid TCP flag
pub fn validate_flags(protocol: Protocol, flags: &str) -> Result<(), String> {
    if protocol != Protocol::Tcp {
        return Err("--flags is only valid for TCP protocol".to_string());
    }

    if flags.is_empty() {
        return Err("flags string must not be empty".to_string());
    }

    for flag in flags.split(',') {
        let trimmed = flag.trim().to_uppercase();
        if !VALID_TCP_FLAGS.contains(&trimmed.as_str()) {
            return Err(format!(
                "invalid TCP flag '{}'; valid flags are: {}",
                flag.trim(),
                VALID_TCP_FLAGS.join(", ")
            ));
        }
    }

    Ok(())
}

/// Calculate the total packet length in bytes.
///
/// Total length = IP header (20) + transport header + payload bytes.
pub fn calculate_total_length(protocol: Protocol, payload_hex: &str) -> usize {
    let payload_bytes = payload_hex.len() / 2;
    IP_HEADER_SIZE + protocol.header_size() + payload_bytes
}

/// Craft a packet and return the result.
///
/// This is the main entry point that validates all inputs and produces
/// a [`CraftResult`] on success.
pub fn craft_packet(
    protocol_str: &str,
    src_port: u16,
    dst_port: u16,
    payload_hex: &str,
    flags: Option<&str>,
) -> Result<CraftResult, String> {
    // Validate protocol
    let protocol = Protocol::from_str(protocol_str)
        .ok_or_else(|| format!("invalid protocol '{}'; must be tcp, udp, or icmp", protocol_str))?;

    // Validate ports
    validate_port(src_port, "src-port")?;
    validate_port(dst_port, "dst-port")?;

    // Validate payload hex
    validate_payload_hex(payload_hex)?;

    // Validate flags if provided
    if let Some(f) = flags {
        validate_flags(protocol, f)?;
    }

    // Calculate total length
    let total_length_bytes = calculate_total_length(protocol, payload_hex);

    // Normalize payload hex to lowercase for consistent output
    let normalized_payload = payload_hex.to_lowercase();

    Ok(CraftResult {
        protocol: protocol.as_str().to_string(),
        total_length_bytes,
        payload_hex: normalized_payload,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Protocol parsing tests ---

    #[test]
    fn test_protocol_from_str_valid() {
        assert_eq!(Protocol::from_str("tcp"), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_str("TCP"), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_str("Tcp"), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_str("udp"), Some(Protocol::Udp));
        assert_eq!(Protocol::from_str("UDP"), Some(Protocol::Udp));
        assert_eq!(Protocol::from_str("icmp"), Some(Protocol::Icmp));
        assert_eq!(Protocol::from_str("ICMP"), Some(Protocol::Icmp));
    }

    #[test]
    fn test_protocol_from_str_invalid() {
        assert_eq!(Protocol::from_str("http"), None);
        assert_eq!(Protocol::from_str(""), None);
        assert_eq!(Protocol::from_str("sctp"), None);
    }

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Udp.as_str(), "udp");
        assert_eq!(Protocol::Icmp.as_str(), "icmp");
    }

    // --- Port validation tests ---

    #[test]
    fn test_validate_port_valid() {
        assert!(validate_port(1, "src-port").is_ok());
        assert!(validate_port(80, "src-port").is_ok());
        assert!(validate_port(65535, "dst-port").is_ok());
    }

    #[test]
    fn test_validate_port_zero() {
        let result = validate_port(0, "src-port");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("src-port"));
    }

    // --- Payload validation tests ---

    #[test]
    fn test_validate_payload_hex_valid() {
        assert!(validate_payload_hex("").is_ok());
        assert!(validate_payload_hex("48454c4c4f").is_ok());
        assert!(validate_payload_hex("DEADBEEF").is_ok());
        assert!(validate_payload_hex("aAbBcCdDeEfF").is_ok());
        assert!(validate_payload_hex("00").is_ok());
    }

    #[test]
    fn test_validate_payload_hex_odd_length() {
        let result = validate_payload_hex("ABC");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("even number"));
    }

    #[test]
    fn test_validate_payload_hex_invalid_chars() {
        let result = validate_payload_hex("GHIJ");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid hex character"));
    }

    // --- Flags validation tests ---

    #[test]
    fn test_validate_flags_valid_tcp() {
        assert!(validate_flags(Protocol::Tcp, "SYN").is_ok());
        assert!(validate_flags(Protocol::Tcp, "SYN,ACK").is_ok());
        assert!(validate_flags(Protocol::Tcp, "FIN, RST, PSH").is_ok());
        assert!(validate_flags(Protocol::Tcp, "URG").is_ok());
    }

    #[test]
    fn test_validate_flags_invalid_flag_name() {
        let result = validate_flags(Protocol::Tcp, "SYN,INVALID");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid TCP flag"));
    }

    #[test]
    fn test_validate_flags_non_tcp_protocol() {
        let result = validate_flags(Protocol::Udp, "SYN");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only valid for TCP"));

        let result = validate_flags(Protocol::Icmp, "ACK");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only valid for TCP"));
    }

    #[test]
    fn test_validate_flags_empty_string() {
        let result = validate_flags(Protocol::Tcp, "");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must not be empty"));
    }

    // --- Total length calculation tests ---

    #[test]
    fn test_calculate_total_length_tcp() {
        // IP(20) + TCP(20) + 5 bytes payload = 45
        assert_eq!(calculate_total_length(Protocol::Tcp, "48454c4c4f"), 45);
    }

    #[test]
    fn test_calculate_total_length_udp() {
        // IP(20) + UDP(8) + 5 bytes payload = 33
        assert_eq!(calculate_total_length(Protocol::Udp, "48454c4c4f"), 33);
    }

    #[test]
    fn test_calculate_total_length_icmp() {
        // IP(20) + ICMP(8) + 5 bytes payload = 33
        assert_eq!(calculate_total_length(Protocol::Icmp, "48454c4c4f"), 33);
    }

    #[test]
    fn test_calculate_total_length_empty_payload() {
        assert_eq!(calculate_total_length(Protocol::Tcp, ""), 40);
        assert_eq!(calculate_total_length(Protocol::Udp, ""), 28);
        assert_eq!(calculate_total_length(Protocol::Icmp, ""), 28);
    }

    // --- Craft packet integration tests ---

    #[test]
    fn test_craft_packet_tcp_success() {
        let result = craft_packet("tcp", 12345, 80, "48454c4c4f", None).unwrap();
        assert_eq!(result.protocol, "tcp");
        assert_eq!(result.total_length_bytes, 45); // 20 + 20 + 5
        assert_eq!(result.payload_hex, "48454c4c4f");
    }

    #[test]
    fn test_craft_packet_tcp_with_flags() {
        let result = craft_packet("tcp", 1024, 443, "AABB", Some("SYN,ACK")).unwrap();
        assert_eq!(result.protocol, "tcp");
        assert_eq!(result.total_length_bytes, 42); // 20 + 20 + 2
        assert_eq!(result.payload_hex, "aabb");
    }

    #[test]
    fn test_craft_packet_udp_success() {
        let result = craft_packet("udp", 5000, 53, "deadbeef", None).unwrap();
        assert_eq!(result.protocol, "udp");
        assert_eq!(result.total_length_bytes, 32); // 20 + 8 + 4
        assert_eq!(result.payload_hex, "deadbeef");
    }

    #[test]
    fn test_craft_packet_icmp_success() {
        let result = craft_packet("icmp", 1, 1, "00112233", None).unwrap();
        assert_eq!(result.protocol, "icmp");
        assert_eq!(result.total_length_bytes, 32); // 20 + 8 + 4
        assert_eq!(result.payload_hex, "00112233");
    }

    #[test]
    fn test_craft_packet_invalid_protocol() {
        let result = craft_packet("http", 80, 80, "AA", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid protocol"));
    }

    #[test]
    fn test_craft_packet_invalid_src_port() {
        let result = craft_packet("tcp", 0, 80, "AA", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("src-port"));
    }

    #[test]
    fn test_craft_packet_invalid_dst_port() {
        let result = craft_packet("tcp", 80, 0, "AA", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("dst-port"));
    }

    #[test]
    fn test_craft_packet_invalid_payload() {
        let result = craft_packet("tcp", 80, 443, "XYZ", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_craft_packet_flags_on_non_tcp() {
        let result = craft_packet("udp", 80, 53, "AA", Some("SYN"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("only valid for TCP"));
    }

    #[test]
    fn test_craft_packet_normalizes_payload_to_lowercase() {
        let result = craft_packet("tcp", 80, 443, "AABBCCDD", None).unwrap();
        assert_eq!(result.payload_hex, "aabbccdd");
    }

    #[test]
    fn test_craft_packet_empty_payload() {
        let result = craft_packet("tcp", 80, 443, "", None).unwrap();
        assert_eq!(result.total_length_bytes, 40); // 20 + 20 + 0
        assert_eq!(result.payload_hex, "");
    }

    // --- JSON output structure test ---

    #[test]
    fn test_craft_result_json_output_matches_spec() {
        let result = craft_packet("tcp", 12345, 80, "48454c4c4f", None).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["protocol"], "tcp");
        assert_eq!(value["total_length_bytes"], 45);
        assert_eq!(value["payload_hex"], "48454c4c4f");
    }
}
