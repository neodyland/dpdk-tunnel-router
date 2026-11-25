//! Core driver trait and flow description.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::frame::Frame;

/// Outer IP address family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            4 => Some(Family::V4),
            6 => Some(Family::V6),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Family::V4 => 4,
            Family::V6 => 6,
        }
    }

    pub fn header_len(self) -> usize {
        match self {
            Family::V4 => 20,
            Family::V6 => 40,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Family::V4 => f.write_str("IPv4"),
            Family::V6 => f.write_str("IPv6"),
        }
    }
}

/// Information about the outer packet handed to a driver.
#[derive(Clone, Debug)]
pub struct OuterFlow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub hop_limit: u8,
    pub dscp: u8,
    /// Used as the IPv4 identification or IPv6 flow label by drivers that
    /// need one.
    pub tunnel_id: u32,
}

impl OuterFlow {
    pub fn new(src: IpAddr, dst: IpAddr) -> Self {
        Self {
            src,
            dst,
            hop_limit: 64,
            dscp: 0,
            tunnel_id: 0,
        }
    }

    pub fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }

    pub fn with_tunnel_id(mut self, tunnel_id: u32) -> Self {
        self.tunnel_id = tunnel_id;
        self
    }

    /// The family implied by the outer addresses.
    pub fn family(&self) -> Family {
        match self.src {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }

    /// Return `src`/`dst` as IPv4 octets.
    pub fn v4(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        match (self.src, self.dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => Some((s, d)),
            _ => None,
        }
    }

    /// Return `src`/`dst` as IPv6 octets.
    pub fn v6(&self) -> Option<(Ipv6Addr, Ipv6Addr)> {
        match (self.src, self.dst) {
            (IpAddr::V6(s), IpAddr::V6(d)) => Some((s, d)),
            _ => None,
        }
    }
}

/// Result of a successful decapsulation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecapInfo {
    /// The outer address family that was parsed.
    pub family: Family,
    /// Offset of the inner Ethernet frame from the start of the packet view.
    pub inner_offset: usize,
}

/// Errors returned by tunnel drivers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverError {
    /// The frame is shorter than a required header or has inconsistent
    /// lengths.
    InvalidPacket,
    /// The outer address family is not supported by this driver.
    UnsupportedFamily,
    /// The frame does not fit in its buffer or has insufficient headroom.
    FrameBounds,
    /// The caller did not leave enough headroom for the outer headers.
    BufferTooSmall,
    /// The encapsulation protocol/version is not implemented.
    UnsupportedProtocol,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverError::InvalidPacket => f.write_str("invalid packet"),
            DriverError::UnsupportedFamily => f.write_str("unsupported address family"),
            DriverError::FrameBounds => f.write_str("frame bounds error"),
            DriverError::BufferTooSmall => f.write_str("insufficient headroom"),
            DriverError::UnsupportedProtocol => f.write_str("unsupported protocol"),
        }
    }
}

impl std::error::Error for DriverError {}

/// A tunnel encapsulation implementation.
///
/// Drivers are stateless with respect to packets; per-tunnel state (remote
/// address, MTU, MSS policy) is carried in [`OuterFlow`] and the router
/// configuration.
pub trait TunnelDriver: Send + Sync {
    /// Name used by `set interfaces tunnel <name> encapsulation <name>`.
    fn name(&self) -> &str;

    /// Whether the driver can emit IPv4 outer packets.
    fn supports_v4(&self) -> bool;

    /// Whether the driver can emit IPv6 outer packets.
    fn supports_v6(&self) -> bool;

    /// Number of bytes `encapsulate` adds for the given outer family.
    fn overhead(&self, family: Family) -> usize;

    /// Prepend the outer headers.
    ///
    /// On success, `frame` points at the outer IP header.  The driver must
    /// set every byte of the header it owns, including lengths and checksums.
    fn encapsulate(&self, frame: &mut Frame<'_>, flow: &OuterFlow) -> Result<(), DriverError>;

    /// Validate and strip the outer headers.
    ///
    /// On success, `frame` points at the inner Ethernet frame.
    fn decapsulate(&self, frame: &mut Frame<'_>) -> Result<DecapInfo, DriverError>;

    /// Whether this driver supports the given outer family.
    fn supports(&self, family: Family) -> bool {
        match family {
            Family::V4 => self.supports_v4(),
            Family::V6 => self.supports_v6(),
        }
    }
}
