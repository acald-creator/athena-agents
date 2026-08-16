//! CLI entry point for the Athena Modbus TCP client.
//!
//! Usage:
//!   athena-modbus --target <host:port> --action <action> --unit-id <1-247> [options]

use clap::Parser;

/// Modbus TCP client for Athena ICS offensive primitives.
///
/// Provides read, write, enumerate, and fuzz operations against Modbus TCP
/// targets for security testing of industrial control systems.
#[derive(Parser, Debug)]
#[command(name = "athena-modbus")]
#[command(about = "Modbus TCP client for Athena ICS offensive primitives")]
struct Cli {
    /// Target address (host:port)
    #[arg(long)]
    target: String,

    /// Action to perform (read-coils, read-holding-registers, write-register, enumerate, fuzz, etc.)
    #[arg(long)]
    action: String,
}

#[tokio::main]
async fn main() {
    let _cli = Cli::parse();

    // TODO: Route to appropriate function based on --action
    eprintln!("athena-modbus: not yet implemented");
    std::process::exit(1);
}
