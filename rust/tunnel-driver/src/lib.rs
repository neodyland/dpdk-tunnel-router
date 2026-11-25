//! # tunnel-driver
//!
//! A small, dependency-free Rust library for writing tunnel drivers for
//! `dpdk-tunnel-router`.
//!
//! A driver only has to describe two operations:
//!
//! * [`TunnelDriver::encapsulate`] — prepend the outer IP header and the
//!   encapsulation header to an inner Ethernet frame.
//! * [`TunnelDriver::decapsulate`] — validate the outer packet and move the
//!   frame window to the inner Ethernet frame.
//!
//! The same implementation can be used:
//!
//! * directly from Rust through [`DriverRegistry`];
//! * from the C data plane by compiling this crate as a `cdylib` and loading
//!   the result with `dpdk-tunnel-router --plugin libtunnel_driver.so`.
//!
//! Ready-made drivers: [`EtherIpDriver::etherip6`] and
//! [`EtherIpDriver::etherip`] implement RFC 3378 EtherIP over IPv6 and
//! IPv4/IPv6 respectively.  See `examples/gre.rs` for a different header
//! layout.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod driver;
pub mod etherip;
pub mod ffi;
pub mod frame;
pub mod registry;

pub use driver::{DecapInfo, DriverError, Family, OuterFlow, TunnelDriver};
pub use etherip::EtherIpDriver;
pub use frame::Frame;
pub use registry::DriverRegistry;

/// EtherIP IP protocol number (RFC 3378).
pub const IPPROTO_ETHERIP: u8 = 97;
/// RFC 3378 EtherIP version.
pub const ETHERIP_VERSION: u8 = 3;
