//! CLI entry point for the Athena Modbus TCP client.
//!
//! Usage:
//!   athena-modbus --target <host:port> --action <action> --unit-id <1-247> [options]
//!
//! Outputs JSON to stdout on success; JSON error to stderr (exit 1) on failure.

use athena_common::report_validation_error;
use athena_modbus::client::ModbusClient;
use athena_modbus::fuzz::{ModbusFuzzConfig, run_modbus_fuzz, validate_fuzz_config};
use athena_modbus::{
    enumerate_units, read_coils, read_discrete_inputs, read_holding_registers,
    read_input_registers, write_coil, write_multiple_coils, write_multiple_registers,
    write_register, SafeRange,
};
use clap::Parser;

/// Modbus TCP client for Athena ICS offensive primitives.
///
/// Provides read, write, enumerate, and fuzz operations against Modbus TCP
/// targets for security testing of industrial control systems.
#[derive(Parser, Debug)]
#[command(name = "athena-modbus")]
#[command(about = "Modbus TCP client for ICS security testing")]
struct Cli {
    /// Target address (host:port)
    #[arg(long)]
    target: String,

    /// Action to perform
    #[arg(long)]
    action: String,

    /// Modbus Unit ID (1-247)
    #[arg(long, default_value = "1")]
    unit_id: u8,

    /// Starting register/coil address (0-65535)
    #[arg(long, default_value = "0")]
    address: u16,

    /// Number of registers/coils to read (1-125)
    #[arg(long, default_value = "1")]
    quantity: u16,

    /// Single value for write operations
    #[arg(long)]
    value: Option<u16>,

    /// JSON array of values for write-multiple operations
    #[arg(long)]
    values: Option<String>,

    /// PRNG seed for fuzz operations
    #[arg(long)]
    seed: Option<u64>,

    /// Number of fuzz iterations (1-1000000)
    #[arg(long, default_value = "1000")]
    iterations: u32,

    /// Timeout in milliseconds (500-60000)
    #[arg(long, default_value = "5000")]
    timeout_ms: u64,

    /// Safe range minimum value
    #[arg(long)]
    safe_range_min: Option<u16>,

    /// Safe range maximum value
    #[arg(long)]
    safe_range_max: Option<u16>,
}

/// Build safe ranges from CLI arguments.
///
/// If both --safe-range-min and --safe-range-max are provided, a single
/// SafeRange is created for the target address. Otherwise no ranges apply.
fn build_safe_ranges(cli: &Cli) -> Vec<SafeRange> {
    match (cli.safe_range_min, cli.safe_range_max) {
        (Some(min), Some(max)) => vec![SafeRange {
            address: cli.address,
            min,
            max,
        }],
        _ => Vec::new(),
    }
}

/// Validate common CLI inputs and report errors.
fn validate_inputs(cli: &Cli) {
    // Validate unit_id range (1-247)
    if cli.unit_id == 0 || cli.unit_id > 247 {
        report_validation_error(
            "validation_error",
            &format!("unit_id must be between 1 and 247, got {}", cli.unit_id),
        );
    }

    // Validate timeout range (500-60000)
    if cli.timeout_ms < 500 || cli.timeout_ms > 60000 {
        report_validation_error(
            "validation_error",
            &format!(
                "timeout_ms must be between 500 and 60000, got {}",
                cli.timeout_ms
            ),
        );
    }
}

/// Handle errors from Modbus client operations by printing JSON to stderr and exiting.
fn handle_client_error(err: athena_modbus::client::ModbusClientError) -> ! {
    use athena_modbus::client::ModbusClientError;

    let (category, message) = match &err {
        ModbusClientError::ConnectionTimeout { .. } => ("connection_timeout", err.to_string()),
        ModbusClientError::ConnectionError { .. } => ("connection_error", err.to_string()),
        ModbusClientError::ResponseTimeout { .. } => ("response_timeout", err.to_string()),
        ModbusClientError::ModbusException { .. } => ("modbus_exception", err.to_string()),
        ModbusClientError::SafetyViolation(_) => ("safety_boundary_violation", err.to_string()),
        ModbusClientError::InvalidResponse(_) | ModbusClientError::IoError(_) => {
            ("connection_error", err.to_string())
        }
    };

    report_validation_error(category, &message);
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Validate common inputs
    validate_inputs(&cli);

    // Validate action
    let valid_actions = [
        "read-coils",
        "read-discrete-inputs",
        "read-holding-registers",
        "read-input-registers",
        "write-coil",
        "write-register",
        "write-multiple-coils",
        "write-multiple-registers",
        "enumerate",
        "fuzz",
    ];

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
        "read-coils" | "read-discrete-inputs" | "read-holding-registers"
        | "read-input-registers" => {
            handle_read(&cli).await;
        }
        "write-coil" | "write-register" | "write-multiple-coils"
        | "write-multiple-registers" => {
            handle_write(&cli).await;
        }
        "enumerate" => {
            handle_enumerate(&cli).await;
        }
        "fuzz" => {
            handle_fuzz(&cli).await;
        }
        _ => unreachable!(),
    }
}

async fn handle_read(cli: &Cli) {
    let mut client = ModbusClient::connect(&cli.target, cli.timeout_ms)
        .await
        .unwrap_or_else(|e| handle_client_error(e));

    let result = match cli.action.as_str() {
        "read-coils" => read_coils(&mut client, cli.unit_id, cli.address, cli.quantity).await,
        "read-discrete-inputs" => {
            read_discrete_inputs(&mut client, cli.unit_id, cli.address, cli.quantity).await
        }
        "read-holding-registers" => {
            read_holding_registers(&mut client, cli.unit_id, cli.address, cli.quantity).await
        }
        "read-input-registers" => {
            read_input_registers(&mut client, cli.unit_id, cli.address, cli.quantity).await
        }
        _ => unreachable!(),
    };

    match result {
        Ok(read_result) => {
            let json = serde_json::to_string(&read_result).unwrap_or_else(|e| {
                report_validation_error(
                    "serialization_error",
                    &format!("failed to serialize output: {}", e),
                );
            });
            println!("{}", json);
        }
        Err(e) => handle_client_error(e),
    }
}

async fn handle_write(cli: &Cli) {
    let safe_ranges = build_safe_ranges(cli);

    let mut client = ModbusClient::connect(&cli.target, cli.timeout_ms)
        .await
        .unwrap_or_else(|e| handle_client_error(e));

    match cli.action.as_str() {
        "write-coil" => {
            let value = cli.value.unwrap_or_else(|| {
                report_validation_error(
                    "validation_error",
                    "write-coil requires --value (0 for OFF, non-zero for ON)",
                );
            });
            let bool_value = value != 0;

            let result =
                write_coil(&mut client, cli.unit_id, cli.address, bool_value, &safe_ranges).await;
            match result {
                Ok(write_result) => {
                    let json = serde_json::to_string(&write_result).unwrap_or_else(|e| {
                        report_validation_error(
                            "serialization_error",
                            &format!("failed to serialize output: {}", e),
                        );
                    });
                    println!("{}", json);
                }
                Err(e) => handle_client_error(e),
            }
        }
        "write-register" => {
            let value = cli.value.unwrap_or_else(|| {
                report_validation_error(
                    "validation_error",
                    "write-register requires --value",
                );
            });

            let result =
                write_register(&mut client, cli.unit_id, cli.address, value, &safe_ranges).await;
            match result {
                Ok(write_result) => {
                    let json = serde_json::to_string(&write_result).unwrap_or_else(|e| {
                        report_validation_error(
                            "serialization_error",
                            &format!("failed to serialize output: {}", e),
                        );
                    });
                    println!("{}", json);
                }
                Err(e) => handle_client_error(e),
            }
        }
        "write-multiple-coils" => {
            let values_json = cli.values.as_ref().unwrap_or_else(|| {
                report_validation_error(
                    "validation_error",
                    "write-multiple-coils requires --values (JSON array of booleans)",
                );
            });

            let values: Vec<bool> = serde_json::from_str(values_json).unwrap_or_else(|e| {
                report_validation_error(
                    "validation_error",
                    &format!("--values must be a JSON array of booleans: {}", e),
                );
            });

            let result =
                write_multiple_coils(&mut client, cli.unit_id, cli.address, &values, &safe_ranges)
                    .await;
            match result {
                Ok(write_result) => {
                    let json = serde_json::to_string(&write_result).unwrap_or_else(|e| {
                        report_validation_error(
                            "serialization_error",
                            &format!("failed to serialize output: {}", e),
                        );
                    });
                    println!("{}", json);
                }
                Err(e) => handle_client_error(e),
            }
        }
        "write-multiple-registers" => {
            let values_json = cli.values.as_ref().unwrap_or_else(|| {
                report_validation_error(
                    "validation_error",
                    "write-multiple-registers requires --values (JSON array of integers)",
                );
            });

            let values: Vec<u16> = serde_json::from_str(values_json).unwrap_or_else(|e| {
                report_validation_error(
                    "validation_error",
                    &format!("--values must be a JSON array of integers: {}", e),
                );
            });

            let result = write_multiple_registers(
                &mut client,
                cli.unit_id,
                cli.address,
                &values,
                &safe_ranges,
            )
            .await;
            match result {
                Ok(write_result) => {
                    let json = serde_json::to_string(&write_result).unwrap_or_else(|e| {
                        report_validation_error(
                            "serialization_error",
                            &format!("failed to serialize output: {}", e),
                        );
                    });
                    println!("{}", json);
                }
                Err(e) => handle_client_error(e),
            }
        }
        _ => unreachable!(),
    }
}

async fn handle_enumerate(cli: &Cli) {
    let result = enumerate_units(&cli.target, cli.timeout_ms).await;
    match result {
        Ok(enum_result) => {
            let json = serde_json::to_string(&enum_result).unwrap_or_else(|e| {
                report_validation_error(
                    "serialization_error",
                    &format!("failed to serialize output: {}", e),
                );
            });
            println!("{}", json);
        }
        Err(e) => handle_client_error(e),
    }
}

async fn handle_fuzz(cli: &Cli) {
    let seed = cli.seed.unwrap_or_else(|| {
        report_validation_error(
            "validation_error",
            "fuzz action requires --seed",
        );
    });

    let config = ModbusFuzzConfig {
        target: cli.target.clone(),
        unit_id: cli.unit_id,
        seed,
        iterations: cli.iterations,
        timeout_ms: cli.timeout_ms,
    };

    if let Err(msg) = validate_fuzz_config(&config) {
        report_validation_error("validation_error", &msg);
    }

    match run_modbus_fuzz(&config).await {
        Ok(summary) => {
            let json = serde_json::to_string(&summary).unwrap_or_else(|e| {
                report_validation_error(
                    "serialization_error",
                    &format!("failed to serialize output: {}", e),
                );
            });
            println!("{}", json);
        }
        Err(msg) => {
            report_validation_error("connection_error", &msg);
        }
    }
}
