//! CLI entry point for the Athena CAN Bus tool.
//!
//! Usage:
//! ```text
//! athena-canbus --interface <vcan0> --action <craft|inject|sniff|replay|fuzz> \
//!              [--id <hex>] [--data <hex>] [--extended]
//! ```
//!
//! Outputs JSON to stdout on success; JSON error to stderr (exit 1) on failure.

use athena_canbus::fuzz::{CanFuzzConfig, run_can_fuzz, validate_fuzz_config};
use athena_canbus::replay::replay;
use athena_canbus::sniff::sniff;
use athena_canbus::socket::CanSocketError;
use athena_canbus::{craft_frame, inject_frame};
use athena_common::report_validation_error;
use clap::Parser;
use std::path::Path;

/// CAN Bus tool for Athena ICS offensive primitives.
///
/// Provides frame crafting, injection, sniffing, replay, and fuzzing
/// operations over Linux virtual CAN (vcan) interfaces.
#[derive(Parser, Debug)]
#[command(name = "athena-canbus")]
#[command(about = "CAN Bus tool for ICS security testing")]
struct Cli {
    /// SocketCAN interface name (e.g., vcan0)
    #[arg(long)]
    interface: String,

    /// Action to perform (craft, inject, sniff, replay, fuzz)
    #[arg(long)]
    action: String,

    /// CAN arbitration ID (hex string, e.g., "1A3" or "1ABCDEF0")
    #[arg(long)]
    id: Option<String>,

    /// CAN frame data payload (hex string, e.g., "DEADBEEF")
    #[arg(long)]
    data: Option<String>,

    /// Use extended (29-bit) CAN ID format
    #[arg(long, default_value = "false")]
    extended: bool,

    /// Duration for sniff operations in milliseconds
    #[arg(long, default_value = "10000")]
    duration_ms: u64,

    /// Path to capture file for replay operations
    #[arg(long)]
    capture_file: Option<String>,

    /// PRNG seed for fuzz operations
    #[arg(long)]
    seed: Option<u64>,

    /// Number of fuzz iterations (1-1000000)
    #[arg(long, default_value = "1000")]
    iterations: u32,

    /// Start of CAN ID fuzz range (hex string)
    #[arg(long, default_value = "0")]
    id_range_start: String,

    /// End of CAN ID fuzz range (hex string)
    #[arg(long, default_value = "7FF")]
    id_range_end: String,

    /// Timeout in milliseconds for operations
    #[arg(long, default_value = "10000")]
    timeout_ms: u64,
}

/// Parse a hex string into a u32 CAN ID value.
fn parse_hex_id(hex_str: &str) -> Result<u32, String> {
    u32::from_str_radix(hex_str.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|e| format!("invalid hex CAN ID '{}': {}", hex_str, e))
}

/// Handle CanSocketError by printing JSON to stderr and exiting.
fn handle_socket_error(err: CanSocketError) -> ! {
    let (category, message) = match &err {
        CanSocketError::InterfaceNotFound(iface) => (
            "interface_error",
            format!("CAN interface '{}' not found or not accessible", iface),
        ),
        CanSocketError::NotSupported => (
            "interface_error",
            "SocketCAN is not supported on this platform (requires Linux)".to_string(),
        ),
        CanSocketError::SocketCreationFailed(msg) => (
            "interface_error",
            format!("failed to create CAN socket: {}", msg),
        ),
        CanSocketError::BindFailed(msg) => (
            "interface_error",
            format!("failed to bind CAN socket: {}", msg),
        ),
        CanSocketError::SendFailed(msg) => (
            "interface_error",
            format!("failed to send CAN frame: {}", msg),
        ),
        CanSocketError::RecvFailed(msg) => (
            "interface_error",
            format!("failed to receive CAN frame: {}", msg),
        ),
        CanSocketError::Timeout => ("response_timeout", "CAN operation timed out".to_string()),
    };

    report_validation_error(category, &message);
}

fn main() {
    let cli = Cli::parse();

    // Validate action
    let valid_actions = ["craft", "inject", "sniff", "replay", "fuzz"];
    if !valid_actions.contains(&cli.action.as_str()) {
        report_validation_error(
            "validation_error",
            &format!(
                "action must be one of {}; got '{}'",
                valid_actions.join(", "),
                cli.action
            ),
        );
    }

    match cli.action.as_str() {
        "craft" => handle_craft(&cli),
        "inject" => handle_inject(&cli),
        "sniff" => handle_sniff(&cli),
        "replay" => handle_replay(&cli),
        "fuzz" => handle_fuzz(&cli),
        _ => unreachable!(),
    }
}

fn handle_craft(cli: &Cli) {
    let id_hex = cli.id.as_ref().unwrap_or_else(|| {
        report_validation_error("validation_error", "craft action requires --id (hex CAN ID)");
    });

    let id = parse_hex_id(id_hex).unwrap_or_else(|msg| {
        report_validation_error("validation_error", &msg);
    });

    let data_hex = cli.data.as_deref().unwrap_or("");

    match craft_frame(id, cli.extended, data_hex) {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap_or_else(|e| {
                report_validation_error(
                    "serialization_error",
                    &format!("failed to serialize output: {}", e),
                );
            });
            println!("{}", json);
        }
        Err(msg) => {
            report_validation_error("validation_error", &msg);
        }
    }
}

fn handle_inject(cli: &Cli) {
    let id_hex = cli.id.as_ref().unwrap_or_else(|| {
        report_validation_error("validation_error", "inject action requires --id (hex CAN ID)");
    });

    let id = parse_hex_id(id_hex).unwrap_or_else(|msg| {
        report_validation_error("validation_error", &msg);
    });

    let data_hex = cli.data.as_deref().unwrap_or("");

    match inject_frame(&cli.interface, id, cli.extended, data_hex) {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap_or_else(|e| {
                report_validation_error(
                    "serialization_error",
                    &format!("failed to serialize output: {}", e),
                );
            });
            println!("{}", json);
        }
        Err(e) => handle_socket_error(e),
    }
}

fn handle_sniff(cli: &Cli) {
    // Validate duration range
    if cli.duration_ms < 1000 || cli.duration_ms > 300000 {
        report_validation_error(
            "validation_error",
            &format!(
                "duration_ms must be between 1000 and 300000, got {}",
                cli.duration_ms
            ),
        );
    }

    match sniff(&cli.interface, cli.duration_ms) {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap_or_else(|e| {
                report_validation_error(
                    "serialization_error",
                    &format!("failed to serialize output: {}", e),
                );
            });
            println!("{}", json);
        }
        Err(e) => handle_socket_error(e),
    }
}

fn handle_replay(cli: &Cli) {
    let capture_path = cli.capture_file.as_ref().unwrap_or_else(|| {
        report_validation_error(
            "validation_error",
            "replay action requires --capture-file",
        );
    });

    let path = Path::new(capture_path);
    if !path.exists() {
        report_validation_error(
            "capture_file_error",
            &format!("capture file '{}' not found", capture_path),
        );
    }

    match replay(&cli.interface, path) {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap_or_else(|e| {
                report_validation_error(
                    "serialization_error",
                    &format!("failed to serialize output: {}", e),
                );
            });
            println!("{}", json);
        }
        Err(e) => handle_socket_error(e),
    }
}

fn handle_fuzz(cli: &Cli) {
    let seed = cli.seed.unwrap_or_else(|| {
        report_validation_error("validation_error", "fuzz action requires --seed");
    });

    let id_range_start = parse_hex_id(&cli.id_range_start).unwrap_or_else(|msg| {
        report_validation_error("validation_error", &format!("--id-range-start: {}", msg));
    });

    let id_range_end = parse_hex_id(&cli.id_range_end).unwrap_or_else(|msg| {
        report_validation_error("validation_error", &format!("--id-range-end: {}", msg));
    });

    let config = CanFuzzConfig {
        interface: cli.interface.clone(),
        seed,
        iterations: cli.iterations,
        id_range_start,
        id_range_end,
    };

    if let Err(msg) = validate_fuzz_config(&config) {
        report_validation_error("validation_error", &msg);
    }

    match run_can_fuzz(&config) {
        Ok(summary) => {
            let json = serde_json::to_string(&summary).unwrap_or_else(|e| {
                report_validation_error(
                    "serialization_error",
                    &format!("failed to serialize output: {}", e),
                );
            });
            println!("{}", json);
        }
        Err(e) => handle_socket_error(e),
    }
}
