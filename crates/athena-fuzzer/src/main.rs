//! CLI entry point for the Athena protocol fuzzer.
//!
//! Usage:
//!   athena-fuzzer --target <addr> --protocol <http|tcp|dns> --seed <u64> [--iterations <u32>]

use athena_common::report_validation_error;
use athena_fuzzer::{FuzzerConfig, Protocol, run_fuzzer, validate_config};
use clap::Parser;

/// Deterministic protocol fuzzer for Athena offensive primitives.
///
/// Generates protocol-aware mutations using xoshiro256++ PRNG seeded from
/// the provided seed value. Output is deterministic for a given seed,
/// protocol, and iteration count.
#[derive(Parser, Debug)]
#[command(name = "athena-fuzzer")]
#[command(about = "Deterministic protocol fuzzer for Athena offensive primitives")]
struct Cli {
    /// Target address (host:port)
    #[arg(long)]
    target: String,

    /// Protocol type to fuzz (http, tcp, dns)
    #[arg(long)]
    protocol: String,

    /// PRNG seed for deterministic reproduction (unsigned 64-bit integer)
    #[arg(long)]
    seed: u64,

    /// Number of mutation iterations to generate (1-1000000, default 1000)
    #[arg(long, default_value = "1000")]
    iterations: u32,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Validate protocol
    let protocol = match Protocol::from_str(&cli.protocol) {
        Some(p) => p,
        None => {
            report_validation_error(
                "validation_error",
                &format!(
                    "protocol must be one of http, tcp, dns; got '{}'",
                    cli.protocol
                ),
            );
        }
    };

    // Build config
    let config = FuzzerConfig {
        target: cli.target,
        protocol,
        seed: cli.seed,
        iterations: cli.iterations,
    };

    // Validate configuration
    if let Err(msg) = validate_config(&config) {
        report_validation_error("validation_error", &msg);
    }

    // Run the fuzzer
    let summary = run_fuzzer(&config);

    // Output summary JSON to stdout
    let json = serde_json::to_string(&summary).unwrap_or_else(|e| {
        report_validation_error("serialization_error", &format!("failed to serialize output: {}", e));
    });

    println!("{}", json);
}
