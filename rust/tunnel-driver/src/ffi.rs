//! C ABI plugin surface.
//!
//! The C data plane can `dlopen` this crate's `cdylib` and call
//! `tunnel_driver_plugin_init`.  Drivers registered here are ordinary C
//! [`struct tr_tnl_driver`] entries whose callbacks enter Rust.
//!
//! Layouts below must stay in sync with `core/src/tunnel.h`.

use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::{Mutex, OnceLock};

use crate::driver::{Family, OuterFlow, TunnelDriver};
use crate::etherip::EtherIpDriver;
use crate::frame::Frame;

pub const ABI_VERSION: u32 = 1;

#[repr(C)]
pub struct TdrFrame {
    pub base: *mut u8,
    pub cap: u32,
    pub off: u32,
    pub len: u32,
}

#[repr(C)]
pub struct TdrFlow {
    pub family: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub hop_limit: u8,
    pub dscp: u8,
    pub tunnel_id: u32,
}

#[repr(C)]
pub struct TdrOps {
    pub encap: Option<
        unsafe extern "C" fn(ctx: *mut c_void, frame: *mut TdrFrame, flow: *const TdrFlow) -> c_int,
    >,
    pub decap: Option<
        unsafe extern "C" fn(ctx: *mut c_void, frame: *mut TdrFrame, flow: *const TdrFlow) -> c_int,
    >,
    pub overhead: Option<unsafe extern "C" fn(ctx: *mut c_void, family: u8) -> u32>,
    pub destroy: Option<unsafe extern "C" fn(ctx: *mut c_void)>,
}

#[repr(C)]
pub struct TdrDriver {
    pub name: [u8; 32],
    pub builtin: u8,
    pub ipv6_only: u8,
    pub ctx: *mut c_void,
    pub ops: TdrOps,
}

#[repr(C)]
pub struct TdrHostApi {
    pub abi_version: u32,
    pub register_driver: Option<
        unsafe extern "C" fn(
            driver: *const TdrDriver,
            err: *mut c_char,
            errlen: u32,
            host_arg: *mut c_void,
        ) -> c_int,
    >,
    pub host_arg: *mut c_void,
}

struct FfiCtx {
    driver: Box<dyn TunnelDriver>,
}

static KEEP_ALIVE: OnceLock<Mutex<Vec<Box<FfiCtx>>>> = OnceLock::new();

fn keep_alive() -> &'static Mutex<Vec<Box<FfiCtx>>> {
    KEEP_ALIVE.get_or_init(|| Mutex::new(Vec::new()))
}

unsafe fn frame_view<'a>(f: *mut TdrFrame) -> Result<Frame<'a>, c_int> {
    if f.is_null() {
        return Err(-1);
    }
    let f = unsafe { &mut *f };
    if f.base.is_null() {
        return Err(-1);
    }
    let cap = f.cap as usize;
    let buf = unsafe { slice::from_raw_parts_mut(f.base, cap) };
    Frame::new(buf, f.off as usize, f.len as usize).map_err(|_| -3)
}

fn write_frame(f: *mut TdrFrame, frame: &Frame<'_>) {
    let f = unsafe { &mut *f };
    f.off = frame.offset() as u32;
    f.len = frame.len() as u32;
}

unsafe fn flow_from_c(flow: *const TdrFlow) -> Result<OuterFlow, c_int> {
    if flow.is_null() {
        return Err(-1);
    }
    let f = unsafe { &*flow };
    let family = Family::from_u8(f.family).ok_or(-2)?;
    let (src, dst) = match family {
        Family::V4 => {
            let mut s = [0u8; 4];
            let mut d = [0u8; 4];
            s.copy_from_slice(&f.src[..4]);
            d.copy_from_slice(&f.dst[..4]);
            (std::net::IpAddr::from(s), std::net::IpAddr::from(d))
        }
        Family::V6 => (std::net::IpAddr::from(f.src), std::net::IpAddr::from(f.dst)),
    };
    Ok(OuterFlow {
        src,
        dst,
        hop_limit: f.hop_limit,
        dscp: f.dscp,
        tunnel_id: f.tunnel_id,
    })
}

unsafe extern "C" fn encap_cb(
    ctx: *mut c_void,
    frame: *mut TdrFrame,
    flow: *const TdrFlow,
) -> c_int {
    let rc = catch_unwind(AssertUnwindSafe(|| unsafe {
        if ctx.is_null() {
            return -1;
        }
        let c = &*(ctx as *const FfiCtx);
        let mut f = match frame_view(frame) {
            Ok(f) => f,
            Err(e) => return e,
        };
        let flow = match flow_from_c(flow) {
            Ok(f) => f,
            Err(e) => return e,
        };
        match c.driver.encapsulate(&mut f, &flow) {
            Ok(()) => {
                write_frame(frame, &f);
                0
            }
            Err(_) => -2,
        }
    }));
    rc.unwrap_or(-4)
}

unsafe extern "C" fn decap_cb(
    ctx: *mut c_void,
    frame: *mut TdrFrame,
    _flow: *const TdrFlow,
) -> c_int {
    let rc = catch_unwind(AssertUnwindSafe(|| unsafe {
        if ctx.is_null() {
            return -1;
        }
        let c = &*(ctx as *const FfiCtx);
        let mut f = match frame_view(frame) {
            Ok(f) => f,
            Err(e) => return e,
        };
        match c.driver.decapsulate(&mut f) {
            Ok(_) => {
                write_frame(frame, &f);
                0
            }
            Err(_) => -2,
        }
    }));
    rc.unwrap_or(-4)
}

unsafe extern "C" fn overhead_cb(ctx: *mut c_void, family: u8) -> u32 {
    let rc = catch_unwind(AssertUnwindSafe(|| unsafe {
        if ctx.is_null() {
            return 0;
        }
        let c = &*(ctx as *const FfiCtx);
        match Family::from_u8(family) {
            Some(f) => c.driver.overhead(f) as u32,
            None => 0,
        }
    }));
    rc.unwrap_or(0)
}

fn c_name(name: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = name.as_bytes();
    let n = bytes.len().min(31);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

unsafe fn register_one(
    api: &TdrHostApi,
    driver: Box<dyn TunnelDriver>,
    ipv6_only: bool,
) -> Result<(), c_int> {
    let ctx = Box::new(FfiCtx { driver });
    let ctx_ptr = Box::into_raw(ctx);
    let mut name = c_name(unsafe { &*ctx_ptr }.driver.name());
    name[31] = 0;
    let desc = TdrDriver {
        name,
        builtin: 0,
        ipv6_only: ipv6_only as u8,
        ctx: ctx_ptr as *mut c_void,
        ops: TdrOps {
            encap: Some(encap_cb),
            decap: Some(decap_cb),
            overhead: Some(overhead_cb),
            destroy: None,
        },
    };
    let register = match api.register_driver {
        Some(f) => f,
        None => {
            drop(unsafe { Box::from_raw(ctx_ptr) });
            return Err(-1);
        }
    };
    let mut err = [0i8; 128];
    let rc = unsafe {
        register(
            &desc,
            err.as_mut_ptr() as *mut c_char,
            err.len() as u32,
            api.host_arg,
        )
    };
    if rc != 0 {
        drop(unsafe { Box::from_raw(ctx_ptr) });
        return Err(rc);
    }
    // The C side copied the descriptor, including ctx.  The allocation must
    // outlive the process (or at least the plugin handle).
    if let Ok(mut keep) = keep_alive().lock() {
        keep.push(unsafe { Box::from_raw(ctx_ptr) });
    } else {
        std::mem::forget(unsafe { Box::from_raw(ctx_ptr) });
    }
    Ok(())
}

/// Plugin entry point called by `dpdk-tunnel-router --plugin`.
///
/// # Safety
/// `api` must point to a valid [`TdrHostApi`] whose function pointers obey
/// the C ABI described in `core/src/tunnel.h`.
#[no_mangle]
pub unsafe extern "C" fn tunnel_driver_plugin_init(api: *const TdrHostApi) -> c_int {
    if api.is_null() {
        return -1;
    }
    let rc = catch_unwind(AssertUnwindSafe(|| unsafe {
        let api = &*api;
        if api.abi_version != ABI_VERSION {
            return -2;
        }
        // Registering one driver is enough for the plugin to load; duplicate
        // names (double load) are reported by the C registry.
        let a = register_one(api, Box::new(EtherIpDriver::etherip6()), true);
        let b = register_one(api, Box::new(EtherIpDriver::etherip()), false);
        match (a, b) {
            (Ok(()), Ok(())) => 0,
            (Ok(()), Err(_)) | (Err(_), Ok(())) => 0,
            (Err(e), Err(_)) => e,
        }
    }));
    rc.unwrap_or(-4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn c_layout_matches_documented_sizes() {
        assert_eq!(std::mem::size_of::<TdrFrame>(), 24);
        assert_eq!(std::mem::size_of::<TdrFlow>(), 40);
        assert_eq!(std::mem::size_of::<TdrDriver>(), 80);
        assert_eq!(std::mem::align_of::<TdrDriver>(), 8);
    }

    #[test]
    fn ffi_encap_decap_roundtrip() {
        let inner = vec![0xAAu8; 128];
        let mut buf = vec![0u8; 64 + inner.len()];
        buf[64..].copy_from_slice(&inner);
        let flow = TdrFlow {
            family: 6,
            src: Ipv6Addr::LOCALHOST.octets(),
            dst: "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets(),
            hop_limit: 64,
            dscp: 0,
            tunnel_id: 7,
        };
        let mut frame = TdrFrame {
            base: buf.as_mut_ptr(),
            cap: buf.len() as u32,
            off: 64,
            len: inner.len() as u32,
        };
        let ctx = FfiCtx {
            driver: Box::new(EtherIpDriver::etherip6()),
        };
        let rc = unsafe { encap_cb(&ctx as *const _ as *mut c_void, &mut frame, &flow) };
        assert_eq!(rc, 0);
        assert_eq!(frame.off, 22);
        assert_eq!(frame.len as usize, inner.len() + 42);
        let rc = unsafe { decap_cb(&ctx as *const _ as *mut c_void, &mut frame, &flow) };
        assert_eq!(rc, 0);
        assert_eq!(frame.off, 64);
        assert_eq!(buf[64..].to_vec(), inner);
        let _ = IpAddr::V6(Ipv6Addr::LOCALHOST);
    }
}
