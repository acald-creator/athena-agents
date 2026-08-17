//! SocketCAN raw socket wrapper for CAN Bus frame injection and reception.
//!
//! This module provides a cross-platform abstraction over Linux SocketCAN.
//! On Linux, it uses raw AF_CAN sockets via `libc`. On non-Linux platforms
//! (e.g., macOS for development), all socket operations return
//! `CanSocketError::NotSupported`.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Extended frame format flag (bit 31 of can_id).
pub const CAN_EFF_FLAG: u32 = 0x80000000;

/// Address family for CAN sockets.
pub const AF_CAN: libc::c_int = 29;

/// Protocol number for raw CAN.
pub const CAN_RAW: libc::c_int = 1;

/// Socket option level for CAN_RAW.
pub const SOL_CAN_RAW: libc::c_int = 101;

// ---------------------------------------------------------------------------
// RawCanFrame — SocketCAN wire format
// ---------------------------------------------------------------------------

/// CAN frame in SocketCAN wire format (16 bytes).
///
/// The `can_id` field encodes the arbitration ID plus flags:
/// - Bit 31: EFF (Extended Frame Format) flag
/// - Bit 30: RTR (Remote Transmission Request) flag
/// - Bit 29: ERR (Error Frame) flag
/// - Bits 0–10: Standard ID (11-bit)
/// - Bits 0–28: Extended ID (29-bit, when EFF is set)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawCanFrame {
    /// Arbitration ID + flags (bit 31 = EFF, bit 30 = RTR, bit 29 = ERR).
    pub can_id: u32,
    /// Data length code (0–8).
    pub can_dlc: u8,
    __pad: u8,
    __res0: u8,
    __res1: u8,
    /// Payload data (only first `can_dlc` bytes are meaningful).
    pub data: [u8; 8],
}

impl RawCanFrame {
    /// Create a new CAN frame with the given ID, extended flag, and data.
    ///
    /// Sets the EFF flag in `can_id` if `extended` is true.
    pub fn new(id: u32, extended: bool, data: &[u8]) -> Self {
        let can_id = if extended { id | CAN_EFF_FLAG } else { id };
        let dlc = data.len().min(8) as u8;
        let mut frame_data = [0u8; 8];
        frame_data[..dlc as usize].copy_from_slice(&data[..dlc as usize]);

        RawCanFrame {
            can_id,
            can_dlc: dlc,
            __pad: 0,
            __res0: 0,
            __res1: 0,
            data: frame_data,
        }
    }

    /// Returns the arbitration ID without flags.
    pub fn arbitration_id(&self) -> u32 {
        if self.is_extended() {
            self.can_id & 0x1FFFFFFF
        } else {
            self.can_id & 0x7FF
        }
    }

    /// Returns true if this is an extended frame (29-bit ID).
    pub fn is_extended(&self) -> bool {
        self.can_id & CAN_EFF_FLAG != 0
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during CAN socket operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanSocketError {
    /// The specified network interface was not found.
    InterfaceNotFound(String),
    /// Failed to create the raw CAN socket.
    SocketCreationFailed(String),
    /// Failed to bind the socket to the interface.
    BindFailed(String),
    /// Failed to send a frame.
    SendFailed(String),
    /// Failed to receive a frame.
    RecvFailed(String),
    /// Receive operation timed out.
    Timeout,
    /// Operation not supported on this platform (non-Linux).
    NotSupported,
}

impl fmt::Display for CanSocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanSocketError::InterfaceNotFound(iface) => {
                write!(f, "interface not found: {}", iface)
            }
            CanSocketError::SocketCreationFailed(msg) => {
                write!(f, "socket creation failed: {}", msg)
            }
            CanSocketError::BindFailed(msg) => {
                write!(f, "bind failed: {}", msg)
            }
            CanSocketError::SendFailed(msg) => {
                write!(f, "send failed: {}", msg)
            }
            CanSocketError::RecvFailed(msg) => {
                write!(f, "recv failed: {}", msg)
            }
            CanSocketError::Timeout => {
                write!(f, "receive timed out")
            }
            CanSocketError::NotSupported => {
                write!(f, "CAN socket operations are not supported on this platform")
            }
        }
    }
}

impl std::error::Error for CanSocketError {}

// ===========================================================================
// Linux implementation
// ===========================================================================

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::ffi::CString;
    use std::io;
    use std::mem;
    use std::os::unix::io::RawFd;

    /// Opaque sockaddr_can structure for binding.
    #[repr(C)]
    struct SockAddrCan {
        can_family: libc::sa_family_t,
        can_ifindex: libc::c_int,
        // transport protocol–specific address info (unused for raw CAN)
        _rx_id: u32,
        _tx_id: u32,
    }

    /// SocketCAN raw socket wrapper.
    #[derive(Debug)]
    pub struct CanSocket {
        fd: RawFd,
    }

    impl CanSocket {
        /// Open a raw CAN socket bound to the given interface (e.g., "vcan0").
        pub fn open(interface: &str) -> Result<Self, CanSocketError> {
            // Create socket
            let fd = unsafe { libc::socket(AF_CAN, libc::SOCK_RAW, CAN_RAW) };
            if fd < 0 {
                return Err(CanSocketError::SocketCreationFailed(
                    io::Error::last_os_error().to_string(),
                ));
            }

            // Look up interface index
            let iface_cstr = CString::new(interface).map_err(|_| {
                unsafe { libc::close(fd) };
                CanSocketError::InterfaceNotFound(interface.to_string())
            })?;

            let ifindex = unsafe { libc::if_nametoindex(iface_cstr.as_ptr()) };
            if ifindex == 0 {
                unsafe { libc::close(fd) };
                return Err(CanSocketError::InterfaceNotFound(interface.to_string()));
            }

            // Bind to interface
            let addr = SockAddrCan {
                can_family: AF_CAN as libc::sa_family_t,
                can_ifindex: ifindex as libc::c_int,
                _rx_id: 0,
                _tx_id: 0,
            };

            let ret = unsafe {
                libc::bind(
                    fd,
                    &addr as *const SockAddrCan as *const libc::sockaddr,
                    mem::size_of::<SockAddrCan>() as libc::socklen_t,
                )
            };

            if ret < 0 {
                let err = io::Error::last_os_error().to_string();
                unsafe { libc::close(fd) };
                return Err(CanSocketError::BindFailed(err));
            }

            Ok(CanSocket { fd })
        }

        /// Send a CAN frame on the socket.
        pub fn send_frame(&self, frame: &RawCanFrame) -> Result<(), CanSocketError> {
            let written = unsafe {
                libc::write(
                    self.fd,
                    frame as *const RawCanFrame as *const libc::c_void,
                    mem::size_of::<RawCanFrame>(),
                )
            };

            if written < 0 {
                return Err(CanSocketError::SendFailed(
                    io::Error::last_os_error().to_string(),
                ));
            }

            if (written as usize) != mem::size_of::<RawCanFrame>() {
                return Err(CanSocketError::SendFailed(format!(
                    "partial write: {} of {} bytes",
                    written,
                    mem::size_of::<RawCanFrame>()
                )));
            }

            Ok(())
        }

        /// Receive a CAN frame with a timeout.
        ///
        /// Returns `Ok(Some(frame))` if a frame is received, `Ok(None)` is not
        /// used (returns `Err(Timeout)` instead), or an error on failure.
        pub fn recv_frame(&self, timeout_ms: u64) -> Result<Option<RawCanFrame>, CanSocketError> {
            // Set up poll
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let timeout = timeout_ms as libc::c_int;
            let ret = unsafe { libc::poll(&mut pfd, 1, timeout) };

            if ret < 0 {
                return Err(CanSocketError::RecvFailed(
                    io::Error::last_os_error().to_string(),
                ));
            }

            if ret == 0 {
                return Err(CanSocketError::Timeout);
            }

            // Read frame
            let mut frame: RawCanFrame = unsafe { mem::zeroed() };
            let n = unsafe {
                libc::read(
                    self.fd,
                    &mut frame as *mut RawCanFrame as *mut libc::c_void,
                    mem::size_of::<RawCanFrame>(),
                )
            };

            if n < 0 {
                return Err(CanSocketError::RecvFailed(
                    io::Error::last_os_error().to_string(),
                ));
            }

            if (n as usize) != mem::size_of::<RawCanFrame>() {
                return Err(CanSocketError::RecvFailed(format!(
                    "partial read: {} of {} bytes",
                    n,
                    mem::size_of::<RawCanFrame>()
                )));
            }

            Ok(Some(frame))
        }

        /// Close the socket.
        pub fn close(&mut self) {
            if self.fd >= 0 {
                unsafe { libc::close(self.fd) };
                self.fd = -1;
            }
        }
    }

    impl Drop for CanSocket {
        fn drop(&mut self) {
            self.close();
        }
    }
}

// ===========================================================================
// Non-Linux stub implementation
// ===========================================================================

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    /// Stub CanSocket for non-Linux platforms.
    ///
    /// All operations return `CanSocketError::NotSupported`.
    #[derive(Debug)]
    pub struct CanSocket {
        _private: (),
    }

    impl CanSocket {
        /// Stub: always returns `NotSupported` on non-Linux.
        pub fn open(_interface: &str) -> Result<Self, CanSocketError> {
            Err(CanSocketError::NotSupported)
        }

        /// Stub: always returns `NotSupported` on non-Linux.
        pub fn send_frame(&self, _frame: &RawCanFrame) -> Result<(), CanSocketError> {
            Err(CanSocketError::NotSupported)
        }

        /// Stub: always returns `NotSupported` on non-Linux.
        pub fn recv_frame(&self, _timeout_ms: u64) -> Result<Option<RawCanFrame>, CanSocketError> {
            Err(CanSocketError::NotSupported)
        }

        /// Stub: no-op on non-Linux.
        pub fn close(&mut self) {}
    }
}

// Re-export the platform-specific CanSocket at module level.
pub use platform::CanSocket;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_raw_can_frame_size_is_16_bytes() {
        assert_eq!(mem::size_of::<RawCanFrame>(), 16);
    }

    #[test]
    fn test_raw_can_frame_new_standard() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let frame = RawCanFrame::new(0x100, false, &data);
        assert_eq!(frame.can_id, 0x100);
        assert_eq!(frame.can_dlc, 4);
        assert_eq!(&frame.data[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(!frame.is_extended());
        assert_eq!(frame.arbitration_id(), 0x100);
    }

    #[test]
    fn test_raw_can_frame_new_extended() {
        let data = [0x01, 0x02];
        let frame = RawCanFrame::new(0x1ABCDEF, true, &data);
        assert_eq!(frame.can_id, 0x1ABCDEF | CAN_EFF_FLAG);
        assert_eq!(frame.can_dlc, 2);
        assert!(frame.is_extended());
        assert_eq!(frame.arbitration_id(), 0x1ABCDEF);
    }

    #[test]
    fn test_raw_can_frame_empty_data() {
        let frame = RawCanFrame::new(0x7FF, false, &[]);
        assert_eq!(frame.can_dlc, 0);
        assert_eq!(frame.data, [0u8; 8]);
    }

    #[test]
    fn test_error_display_interface_not_found() {
        let err = CanSocketError::InterfaceNotFound("vcan99".to_string());
        assert_eq!(err.to_string(), "interface not found: vcan99");
    }

    #[test]
    fn test_error_display_socket_creation_failed() {
        let err = CanSocketError::SocketCreationFailed("permission denied".to_string());
        assert_eq!(err.to_string(), "socket creation failed: permission denied");
    }

    #[test]
    fn test_error_display_bind_failed() {
        let err = CanSocketError::BindFailed("address in use".to_string());
        assert_eq!(err.to_string(), "bind failed: address in use");
    }

    #[test]
    fn test_error_display_send_failed() {
        let err = CanSocketError::SendFailed("broken pipe".to_string());
        assert_eq!(err.to_string(), "send failed: broken pipe");
    }

    #[test]
    fn test_error_display_recv_failed() {
        let err = CanSocketError::RecvFailed("connection reset".to_string());
        assert_eq!(err.to_string(), "recv failed: connection reset");
    }

    #[test]
    fn test_error_display_timeout() {
        let err = CanSocketError::Timeout;
        assert_eq!(err.to_string(), "receive timed out");
    }

    #[test]
    fn test_error_display_not_supported() {
        let err = CanSocketError::NotSupported;
        assert_eq!(
            err.to_string(),
            "CAN socket operations are not supported on this platform"
        );
    }

    #[test]
    fn test_can_eff_flag_constant() {
        assert_eq!(CAN_EFF_FLAG, 0x80000000);
    }

    #[test]
    fn test_af_can_constant() {
        assert_eq!(AF_CAN, 29);
    }

    #[test]
    fn test_can_raw_constant() {
        assert_eq!(CAN_RAW, 1);
    }

    #[test]
    fn test_sol_can_raw_constant() {
        assert_eq!(SOL_CAN_RAW, 101);
    }

    // --- Non-Linux platform tests ---

    #[cfg(not(target_os = "linux"))]
    mod non_linux_tests {
        use super::super::*;

        #[test]
        fn test_open_returns_not_supported() {
            let result = CanSocket::open("vcan0");
            assert_eq!(result.unwrap_err(), CanSocketError::NotSupported);
        }
    }

    // On Linux we can't easily test open/send/recv without a vcan interface,
    // but we can verify the type compiles and basic construction works.
    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::super::*;

        #[test]
        fn test_open_nonexistent_interface_returns_error() {
            let result = CanSocket::open("vcan_nonexistent_xyz");
            assert!(matches!(
                result,
                Err(CanSocketError::InterfaceNotFound(_))
            ));
        }
    }
}
