//! CLI entry point for the athena-scanner async TCP port scanner.
//!
//! Usage:
//!   athena-scanner --target <addr> --start-port <u16> --end-port <u16> \
//!                  [--concurrency <u16>] [--timeout-ms <u32>]

use athena_common::report_validation_error;
use athena_scanner::{run_scan, validate_config, ScanConfig};
use clap::Parser;

/// Async TCP port scanner for Athena offensive primitives.
///
/// Scans a range of TCP ports on a target host using concurrent async connections.
/// Outputs results as JSON to stdout.
#[derive(Parser, Debug)]
#[command(name = "athena-scanner", version, about)]
struct Cli {
    /// Target address to scan (IP address or hostname).
    #[arg(long)]
    target: String,

    /// Start of the port range to scan (1-65535).
    #[arg(long)]
    start_port: u16,

    /// End of the port range to scan (1-65535).
    #[arg(long)]
    end_port: u16,

    /// Maximum number of concurrent connection attempts (1-65535, default: 1024).
    #[arg(long, default_value = "1024")]
    concurrency: u16,

    /// Per-connection timeout in milliseconds (100-30000, default: 3000).
    #[arg(long, default_value = "3000")]
    timeout_ms: u32,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let config = ScanConfig {
        target: cli.target,
        start_port: cli.start_port,
        end_port: cli.end_port,
        concurrency: cli.concurrency,
        timeout_ms: cli.timeout_ms,
    };

    // Validate configuration; report JSON error to stderr and exit 1 on failure
    if let Err(msg) = validate_config(&config) {
        report_validation_error("validation_error", &msg);
    }

    let result = run_scan(&config).await;

    // Output JSON to stdout
    let json = serde_json::to_string(&result).expect("failed to serialize scan result");
    println!("{}", json);
}
