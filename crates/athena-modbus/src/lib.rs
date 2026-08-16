//! Modbus TCP client library for Athena ICS offensive primitives.
//!
//! This crate provides Modbus TCP read, write, enumeration, and fuzzing
//! operations for security testing of industrial control systems. It implements
//! manual MBAP frame construction for full control over protocol interactions,
//! including malformed packet generation during fuzzing.
//!
//! # Modules
//!
//! - `frame` — MBAP header and PDU encoding/decoding
//! - `client` — Async TCP Modbus client with timeout handling (planned)
//! - `fuzz` — Deterministic Modbus protocol fuzzer (xoshiro256++) (planned)
//!
//! # Safety Controls
//!
//! Write operations support safe-range validation to prevent writes outside
//! configured boundaries, enforcing safety even in autonomous operation.

pub mod frame;
