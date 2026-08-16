//! Core async TCP port scanning logic for the athena-scanner binary.
//!
//! This module provides the scanning engine that uses tokio with a
//! semaphore-bounded connection pool to perform concurrent TCP port scans.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use athena_common::{PortEntry, PortStatus, ScanResult};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Configuration for a port scan operation.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Target address to scan (hostname or IP).
    pub target: String,
    /// First port in the scan range (inclusive).
    pub start_port: u16,
    /// Last port in the scan range (inclusive).
    pub end_port: u16,
    /// Maximum number of concurrent connection attempts.
    pub concurrency: u16,
    /// Per-connection timeout in milliseconds.
    pub timeout_ms: u32,
}

/// Validate scan configuration, returning an error message if invalid.
pub fn validate_config(config: &ScanConfig) -> Result<(), String> {
    if config.start_port == 0 {
        return Err("start-port must be between 1 and 65535".to_string());
    }
    if config.end_port == 0 {
        return Err("end-port must be between 1 and 65535".to_string());
    }
    if config.start_port > config.end_port {
        return Err(format!(
            "start-port ({}) must be <= end-port ({})",
            config.start_port, config.end_port
        ));
    }
    if config.concurrency == 0 {
        return Err("concurrency must be between 1 and 65535".to_string());
    }
    if config.timeout_ms < 100 || config.timeout_ms > 30000 {
        return Err(format!(
            "timeout-ms ({}) must be between 100 and 30000",
            config.timeout_ms
        ));
    }
    Ok(())
}

/// Attempt to connect to a single port and determine if it is open or closed.
async fn scan_port(addr: &str, port: u16, timeout_duration: Duration) -> PortEntry {
    let target = format!("{}:{}", addr, port);
    let status = match target.parse::<SocketAddr>() {
        Ok(sock_addr) => {
            match timeout(timeout_duration, TcpStream::connect(sock_addr)).await {
                Ok(Ok(_)) => PortStatus::Open,
                _ => PortStatus::Closed,
            }
        }
        Err(_) => {
            // If we can't parse as SocketAddr directly, try connecting by string
            // (tokio's connect supports hostname resolution)
            match timeout(timeout_duration, TcpStream::connect(target)).await {
                Ok(Ok(_)) => PortStatus::Open,
                _ => PortStatus::Closed,
            }
        }
    };

    PortEntry { port, status }
}

/// Execute an async TCP port scan using the given configuration.
///
/// Uses a tokio semaphore to bound the number of concurrent connections
/// to the configured concurrency limit.
pub async fn run_scan(config: &ScanConfig) -> ScanResult {
    let start_time = Instant::now();
    let timeout_duration = Duration::from_millis(config.timeout_ms as u64);
    let semaphore = std::sync::Arc::new(Semaphore::new(config.concurrency as usize));

    let mut handles = Vec::new();

    for port in config.start_port..=config.end_port {
        let sem = semaphore.clone();
        let target = config.target.clone();
        let timeout_dur = timeout_duration;

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed unexpectedly");
            scan_port(&target, port, timeout_dur).await
        });

        handles.push(handle);
    }

    let mut ports = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(entry) => ports.push(entry),
            Err(_) => {
                // Task panicked; should not happen in normal operation
            }
        }
    }

    // Sort ports by port number for deterministic output
    ports.sort_by_key(|e| e.port);

    let scan_duration_ms = start_time.elapsed().as_millis() as u64;

    ScanResult {
        target: config.target.clone(),
        ports,
        scan_duration_ms,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_config_valid() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 1,
            end_port: 100,
            concurrency: 1024,
            timeout_ms: 3000,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_start_greater_than_end() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 100,
            end_port: 50,
            concurrency: 1024,
            timeout_ms: 3000,
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.contains("start-port"));
        assert!(err.contains("end-port"));
    }

    #[test]
    fn test_validate_config_zero_start_port() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 0,
            end_port: 100,
            concurrency: 1024,
            timeout_ms: 3000,
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_zero_concurrency() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 1,
            end_port: 100,
            concurrency: 0,
            timeout_ms: 3000,
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_config_timeout_too_low() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 1,
            end_port: 100,
            concurrency: 1024,
            timeout_ms: 50,
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.contains("timeout-ms"));
    }

    #[test]
    fn test_validate_config_timeout_too_high() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 1,
            end_port: 100,
            concurrency: 1024,
            timeout_ms: 31000,
        };
        let err = validate_config(&config).unwrap_err();
        assert!(err.contains("timeout-ms"));
    }

    #[test]
    fn test_validate_config_single_port() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 80,
            end_port: 80,
            concurrency: 1,
            timeout_ms: 100,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_full_range() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 1,
            end_port: 65535,
            concurrency: 65535,
            timeout_ms: 30000,
        };
        assert!(validate_config(&config).is_ok());
    }

    #[tokio::test]
    async fn test_run_scan_returns_correct_port_count() {
        // Scan a small range against localhost (ports likely closed)
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 59990,
            end_port: 59995,
            concurrency: 10,
            timeout_ms: 100,
        };

        let result = run_scan(&config).await;

        // Should have exactly 6 ports (59990..=59995)
        assert_eq!(result.ports.len(), 6);
        assert_eq!(result.target, "127.0.0.1");

        // Ports should be sorted
        for (i, entry) in result.ports.iter().enumerate() {
            assert_eq!(entry.port, 59990 + i as u16);
        }
    }

    #[tokio::test]
    async fn test_run_scan_single_port() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 59999,
            end_port: 59999,
            concurrency: 1,
            timeout_ms: 100,
        };

        let result = run_scan(&config).await;
        assert_eq!(result.ports.len(), 1);
        assert_eq!(result.ports[0].port, 59999);
    }

    #[tokio::test]
    async fn test_scan_result_serializes_correctly() {
        let config = ScanConfig {
            target: "127.0.0.1".to_string(),
            start_port: 59990,
            end_port: 59992,
            concurrency: 10,
            timeout_ms: 100,
        };

        let result = run_scan(&config).await;
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }
}
