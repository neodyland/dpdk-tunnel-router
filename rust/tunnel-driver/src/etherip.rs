//! RFC 3378 EtherIP.
//!
//! ```text
//! +----------------+--------+-----------------+
//! | outer IPv4/IPv6| EtherIP| Ethernet frame  |
//! +----------------+--------+-----------------+
//!                  version 3, 2 bytes
//! ```

use crate::driver::{DecapInfo, DriverError, Family, OuterFlow, TunnelDriver};
use crate::frame::Frame;
use crate::{ETHERIP_VERSION, IPPROTO_ETHERIP};

/// EtherIP driver.
///
/// `etherip6()` restricts the outer header to IPv6; `etherip()` also accepts
/// IPv4 (RFC 3378 permits both).
#[derive(Clone, Copy, Debug)]
pub struct EtherIpDriver {
    ipv6_only: bool,
}

impl EtherIpDriver {
    /// EtherIP over IPv6.
    pub const fn etherip6() -> Self {
        Self { ipv6_only: true }
    }

    /// EtherIP over IPv4 or IPv6.
    pub const fn etherip() -> Self {
        Self { ipv6_only: false }
    }

    pub const fn is_ipv6_only(&self) -> bool {
        self.ipv6_only
    }
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

impl TunnelDriver for EtherIpDriver {
    fn name(&self) -> &str {
        if self.ipv6_only {
            "etherip6-rs"
        } else {
            "etherip-rs"
        }
    }

    fn supports_v4(&self) -> bool {
        !self.ipv6_only
    }

    fn supports_v6(&self) -> bool {
        true
    }

    fn overhead(&self, family: Family) -> usize {
        family.header_len() + 2
    }

    fn encapsulate(&self, frame: &mut Frame<'_>, flow: &OuterFlow) -> Result<(), DriverError> {
        let family = flow.family();
        if !self.supports(family) {
            return Err(DriverError::UnsupportedFamily);
        }
        let hlen = family.header_len();
        let overhead = hlen + 2;
        let inner_len = frame.len();
        if inner_len + overhead > u16::MAX as usize {
            return Err(DriverError::InvalidPacket);
        }
        let hdr = frame.prepend(overhead)?;
        let total = inner_len + overhead;

        match family {
            Family::V4 => {
                let (src, dst) = flow.v4().ok_or(DriverError::UnsupportedFamily)?;
                hdr[..20].fill(0);
                hdr[0] = 0x45;
                hdr[1] = (flow.dscp & 0x3f) << 2;
                hdr[2..4].copy_from_slice(&(total as u16).to_be_bytes());
                hdr[4..6].copy_from_slice(&(flow.tunnel_id as u16).to_be_bytes());
                hdr[6] = 0; // DF=0: the core fragments to the underlay MTU.
                hdr[7] = 0;
                hdr[8] = if flow.hop_limit == 0 {
                    64
                } else {
                    flow.hop_limit
                };
                hdr[9] = IPPROTO_ETHERIP;
                hdr[12..16].copy_from_slice(&src.octets());
                hdr[16..20].copy_from_slice(&dst.octets());
                let csum = checksum16(&hdr[..20]);
                hdr[10..12].copy_from_slice(&csum.to_be_bytes());
            }
            Family::V6 => {
                let (src, dst) = flow.v6().ok_or(DriverError::UnsupportedFamily)?;
                hdr[..40].fill(0);
                let vtf: u32 =
                    (6u32 << 28) | ((flow.dscp as u32) << 22) | (flow.tunnel_id & 0x000f_ffff);
                hdr[0..4].copy_from_slice(&vtf.to_be_bytes());
                hdr[4..6].copy_from_slice(&((total - 40) as u16).to_be_bytes());
                hdr[6] = IPPROTO_ETHERIP;
                hdr[7] = if flow.hop_limit == 0 {
                    64
                } else {
                    flow.hop_limit
                };
                hdr[8..24].copy_from_slice(&src.octets());
                hdr[24..40].copy_from_slice(&dst.octets());
            }
        }
        hdr[hlen] = ETHERIP_VERSION << 4;
        hdr[hlen + 1] = 0;
        Ok(())
    }

    fn decapsulate(&self, frame: &mut Frame<'_>) -> Result<DecapInfo, DriverError> {
        let (header_len, family, total) = {
            let data = frame.data();
            if data.len() < 20 {
                return Err(DriverError::InvalidPacket);
            }
            match data[0] >> 4 {
                4 => {
                    if self.ipv6_only {
                        return Err(DriverError::UnsupportedFamily);
                    }
                    let ihl = (data[0] & 0x0f) as usize * 4;
                    if ihl < 20 || data.len() < ihl + 2 || data[9] != IPPROTO_ETHERIP {
                        return Err(DriverError::InvalidPacket);
                    }
                    let total = u16::from_be_bytes([data[2], data[3]]) as usize;
                    if total < ihl + 2 || total > data.len() {
                        return Err(DriverError::InvalidPacket);
                    }
                    (ihl, Family::V4, total)
                }
                6 => {
                    if data.len() < 40 || data[6] != IPPROTO_ETHERIP {
                        return Err(DriverError::InvalidPacket);
                    }
                    let plen = u16::from_be_bytes([data[4], data[5]]) as usize;
                    if plen < 2 || 40 + plen > data.len() {
                        return Err(DriverError::InvalidPacket);
                    }
                    (40usize, Family::V6, 40 + plen)
                }
                _ => return Err(DriverError::UnsupportedProtocol),
            }
        };
        {
            let data = frame.data();
            let e = &data[header_len..header_len + 2];
            if (e[0] >> 4) != ETHERIP_VERSION || (e[0] & 0x0f) != 0 || e[1] != 0 {
                return Err(DriverError::UnsupportedProtocol);
            }
            let inner_len = total - header_len - 2;
            if inner_len < 14 {
                return Err(DriverError::InvalidPacket);
            }
        }
        frame.advance(header_len + 2)?;
        Ok(DecapInfo {
            family,
            inner_offset: frame.offset(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn inner_frame(len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        v[..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        v[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        v[12..14].copy_from_slice(&[0x08, 0x00]);
        for (i, b) in v.iter_mut().enumerate().skip(14) {
            *b = (i & 0xff) as u8;
        }
        v
    }

    #[test]
    fn etherip6_round_trip() {
        let inner = inner_frame(9000);
        let mut buf = vec![0u8; 64 + inner.len()];
        buf[64..].copy_from_slice(&inner);
        let flow = OuterFlow::new(
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()),
        )
        .with_tunnel_id(0x12345);
        let drv = EtherIpDriver::etherip6();
        {
            let mut f = Frame::new(&mut buf, 64, inner.len()).unwrap();
            drv.encapsulate(&mut f, &flow).unwrap();
            assert_eq!(f.offset(), 22);
            assert_eq!(f.len(), inner.len() + 42);
            let d = f.data();
            assert_eq!(d[0] >> 4, 6);
            assert_eq!(d[6], IPPROTO_ETHERIP);
            assert_eq!(d[40], 0x30);
            assert_eq!(d[41], 0x00);
        }
        let mut f = Frame::new(&mut buf, 22, inner.len() + 42).unwrap();
        let info = drv.decapsulate(&mut f).unwrap();
        assert_eq!(info.family, Family::V6);
        assert_eq!(f.offset(), 64);
        assert_eq!(f.data(), inner.as_slice());
    }

    #[test]
    fn etherip4_round_trip() {
        let inner = inner_frame(1500);
        let mut buf = vec![0u8; 64 + inner.len()];
        buf[64..].copy_from_slice(&inner);
        let flow = OuterFlow::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        );
        let drv = EtherIpDriver::etherip();
        {
            let mut f = Frame::new(&mut buf, 64, inner.len()).unwrap();
            drv.encapsulate(&mut f, &flow).unwrap();
            assert_eq!(f.offset(), 42);
            let d = f.data();
            assert_eq!(d[0] >> 4, 4);
            assert_eq!(d[9], IPPROTO_ETHERIP);
            assert_eq!(checksum16(&d[..20]), 0);
            assert_eq!(d[20], 0x30);
        }
        let mut f = Frame::new(&mut buf, 42, inner.len() + 22).unwrap();
        let info = drv.decapsulate(&mut f).unwrap();
        assert_eq!(info.family, Family::V4);
        assert_eq!(f.data(), inner.as_slice());
    }

    #[test]
    fn etherip6_rejects_ipv4() {
        let inner = inner_frame(64);
        let mut buf = vec![0u8; 64 + inner.len()];
        buf[64..].copy_from_slice(&inner);
        let flow = OuterFlow::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        );
        let mut f = Frame::new(&mut buf, 64, inner.len()).unwrap();
        assert_eq!(
            EtherIpDriver::etherip6().encapsulate(&mut f, &flow),
            Err(DriverError::UnsupportedFamily)
        );
    }

    #[test]
    fn truncation_is_rejected() {
        let inner = inner_frame(64);
        let mut buf = vec![0u8; 64 + inner.len()];
        buf[64..].copy_from_slice(&inner);
        let drv = EtherIpDriver::etherip6();
        let flow = OuterFlow::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("2001:db8::2".parse().unwrap()),
        );
        let mut f = Frame::new(&mut buf, 64, inner.len()).unwrap();
        drv.encapsulate(&mut f, &flow).unwrap();
        let mut f = Frame::new(&mut buf, 22, inner.len() + 42).unwrap();
        f.trim_end(50).unwrap();
        assert!(drv.decapsulate(&mut f).is_err());
    }
}
