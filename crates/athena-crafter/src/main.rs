//! CLI entry point for the Athena packet crafter.
//!
//! Usage:
//! ```text
//! athena-crafter --protocol <tcp|udp|icmp> --src-port <u16> --dst-port <u16> \
//!                --payload <hex-string> [--flags <string>]
//! ```
//!
//! Outputs JSON to stdout on success; JSON error to stderr (exit 1) on failure.

use athena_common::report_validation_error;
use athena_crafter::craft_packet;
use clap::Parser;

/// Athena packet crafter — crafts packet metadata for offensive simulations.
#[derive(Parser, Debug)]
#[command(name = "athena-crafter")]
#[command(about = "Craft packet metadata for TCP, UDP, or ICMP protocols")]
struct Cli {
    /// Protocol type: tcp, udp, or icmp.
    #[arg(long)]
    protocol: String,

    /// Source port (1-65535).
    #[arg(long)]
    src_port: u16,

    /// Destination port (1-65535).
    #[arg(long)]
    dst_port: u16,

    /// Hex-encoded payload string (must be even length, valid hex characters).
    #[arg(long)]
    payload: String,

    /// Optional TCP flags (comma-separated: SYN, ACK, FIN, RST, PSH, URG).
    /// Only valid when protocol is tcp.
    #[arg(long)]
    flags: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let flags_ref = cli.flags.as_deref();

    match craft_packet(&cli.protocol, cli.src_port, cli.dst_port, &cli.payload, flags_ref) {
        Ok(result) => {
            let json = serde_json::to_string(&result).unwrap();
            println!("{}", json);
        }
        Err(msg) => {
            report_validation_error("validation_error", &msg);
        }
    }
}
