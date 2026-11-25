//! Example: a minimal GRE transparent-Ethernet-bridging driver.
//!
//! This is intentionally *not* registered by default.  It demonstrates how
//! little code a new encapsulation needs:
//!
//! ```text
//! outer IP | GRE (4 bytes, proto 0x6558) | inner Ethernet
//! ```
//!
//! Build with `cargo build --example gre`.  In a larger deployment the same
//! type would be registered with `DriverRegistry::register` or exported from
//! a `cdylib` through the C ABI in `tunnel_driver::ffi`.

use std::net::{Ipv4Addr, Ipv6Addr};

use tunnel_driver::driver::{DecapInfo, DriverError, Family, OuterFlow, TunnelDriver};
use tunnel_driver::frame::Frame;

pub struct GreEthernet;

fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut it = data.chunks_exact(2);
    for c in &mut it {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [b] = it.remainder() {
        sum += (*b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

impl TunnelDriver for GreEthernet {
    fn name(&self) -> &str {
        "gre-eth"
    }

    fn supports_v4(&self) -> bool {
        true
    }

    fn supports_v6(&self) -> bool {
        true
    }

    fn overhead(&self, family: Family) -> usize {
        family.header_len() + 4
    }

    fn encapsulate(&self, frame: &mut Frame<'_>, flow: &OuterFlow) -> Result<(), DriverError> {
        let family = flow.family();
        let hlen = family.header_len();
        let inner = frame.len();
        let total = inner + hlen + 4;
        let hdr = frame.prepend(hlen + 4)?;
        match family {
            Family::V4 => {
                let (src, dst) = flow
                    .v4()
                    .unwrap_or((Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED));
                hdr[..20].fill(0);
                hdr[0] = 0x45;
                hdr[1] = (flow.dscp & 0x3f) << 2;
                hdr[2..4].copy_from_slice(&(total as u16).to_be_bytes());
                hdr[6] = 0x40;
                hdr[8] = flow.hop_limit.max(1);
                hdr[9] = 47; // GRE
                hdr[12..16].copy_from_slice(&src.octets());
                hdr[16..20].copy_from_slice(&dst.octets());
                let c = checksum16(&hdr[..20]);
                hdr[10..12].copy_from_slice(&c.to_be_bytes());
            }
            Family::V6 => {
                let (src, dst) = flow
                    .v6()
                    .unwrap_or((Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST));
                hdr[..40].fill(0);
                hdr[0] = 0x60;
                hdr[4..6].copy_from_slice(&((inner + 4) as u16).to_be_bytes());
                hdr[6] = 47;
                hdr[7] = flow.hop_limit.max(1);
                hdr[8..24].copy_from_slice(&src.octets());
                hdr[24..40].copy_from_slice(&dst.octets());
            }
        }
        hdr[hlen..hlen + 2].copy_from_slice(&0u16.to_be_bytes()); // flags/version
        hdr[hlen + 2..hlen + 4].copy_from_slice(&0x6558u16.to_be_bytes()); // Ethernet
        Ok(())
    }

    fn decapsulate(&self, frame: &mut Frame<'_>) -> Result<DecapInfo, DriverError> {
        let (hlen, family, total) = {
            let d = frame.data();
            if d.len() < 20 {
                return Err(DriverError::InvalidPacket);
            }
            match d[0] >> 4 {
                4 => {
                    if d[9] != 47 {
                        return Err(DriverError::InvalidPacket);
                    }
                    let ihl = (d[0] & 0x0f) as usize * 4;
                    let total = u16::from_be_bytes([d[2], d[3]]) as usize;
                    if ihl < 20 || total < ihl + 4 || total > d.len() {
                        return Err(DriverError::InvalidPacket);
                    }
                    (ihl, Family::V4, total)
                }
                6 => {
                    if d[6] != 47 {
                        return Err(DriverError::InvalidPacket);
                    }
                    let plen = u16::from_be_bytes([d[4], d[5]]) as usize;
                    if plen < 4 || 40 + plen > d.len() {
                        return Err(DriverError::InvalidPacket);
                    }
                    (40, Family::V6, 40 + plen)
                }
                _ => return Err(DriverError::UnsupportedProtocol),
            }
        };
        {
            let d = frame.data();
            let gre = &d[hlen..hlen + 4];
            if gre[0] != 0 || gre[1] != 0 {
                return Err(DriverError::UnsupportedProtocol);
            }
            if gre[2..4] != [0x65, 0x58] {
                return Err(DriverError::UnsupportedProtocol);
            }
            if total < hlen + 4 + 14 {
                return Err(DriverError::InvalidPacket);
            }
        }
        frame.advance(hlen + 4)?;
        Ok(DecapInfo {
            family,
            inner_offset: frame.offset(),
        })
    }
}

fn main() {
    let gre = GreEthernet;
    let mut buf = vec![0u8; 128];
    let mut frame = Frame::new(&mut buf, 64, 64).unwrap();
    let flow = OuterFlow::new(
        "2001:db8::1".parse().unwrap(),
        "2001:db8::2".parse().unwrap(),
    );
    gre.encapsulate(&mut frame, &flow).unwrap();
    let info = gre.decapsulate(&mut frame).unwrap();
    assert_eq!(info.family, Family::V6);
    assert_eq!(info.inner_offset, 64);
    println!(
        "{}: {} bytes overhead",
        gre.name(),
        gre.overhead(Family::V6)
    );
}
