// Copyright (C) 2026 whispr.dev
// SPDX-License-Identifier: GPL-3.0-only

//! Built-in Linux capture: an `AF_PACKET` socket, no libpcap needed.
//!
//! The ready-built Linux downloads are fully static programs, which can't load
//! libpcap at run time, so they capture with this instead. It needs the same
//! permission as tcpdump (root, or `CAP_NET_RAW`). Filters run in user space after
//! decoding, with the subset of libpcap's language in [`super::filter`].

use std::ffi::{c_int, c_void, CStr, CString};
use std::io;
use std::mem::{size_of, size_of_val, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::null_mut;
use std::time::{SystemTime, UNIX_EPOCH};

use super::filter::Filter;
use super::{libpcap::permission_help, Capture, Device, Next, Opened, Packet, Settings};
use crate::decode::linktype;

// Kernel ABI values from <linux/if_packet.h>, <linux/if_ether.h> and <linux/if_arp.h>.
const SOL_PACKET: c_int = 263;
const PACKET_ADD_MEMBERSHIP: c_int = 1;
const PACKET_STATISTICS: c_int = 6;
const PACKET_MR_PROMISC: u16 = 1;
const PACKET_OUTGOING: u8 = 4;
const ETH_P_ALL: u16 = 0x0003;

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_IEEE802: u16 = 6;
const ARPHRD_RAWIP: u16 = 519;
const ARPHRD_TUNNEL: u16 = 768;
const ARPHRD_TUNNEL6: u16 = 769;
const ARPHRD_LOOPBACK: u16 = 772;
const ARPHRD_SIT: u16 = 776;
const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;
const ARPHRD_NONE: u16 = 0xFFFE;

#[repr(C)]
struct PacketMreq {
    mr_ifindex: c_int,
    mr_type: u16,
    mr_alen: u16,
    mr_address: [u8; 8],
}

#[repr(C)]
#[derive(Default)]
struct TpacketStats {
    tp_packets: u32,
    tp_drops: u32,
}

/// The link type a hardware type's frames arrive as, if the decoder understands it.
fn linktype_for(hatype: u16) -> Option<u32> {
    match hatype {
        // Linux gives loopback frames a dummy Ethernet header.
        ARPHRD_ETHER | ARPHRD_IEEE802 | ARPHRD_LOOPBACK => Some(linktype::ETHERNET),
        ARPHRD_NONE | ARPHRD_RAWIP | ARPHRD_TUNNEL | ARPHRD_TUNNEL6 | ARPHRD_SIT => {
            Some(linktype::RAW)
        }
        _ => None,
    }
}

fn kind_name(hatype: u16) -> String {
    match hatype {
        ARPHRD_ETHER => "Ethernet or Wi-Fi".to_string(),
        ARPHRD_LOOPBACK => "loopback".to_string(),
        ARPHRD_NONE | ARPHRD_RAWIP => "IP tunnel (VPN)".to_string(),
        ARPHRD_TUNNEL | ARPHRD_TUNNEL6 | ARPHRD_SIT => "IP-in-IP tunnel".to_string(),
        ARPHRD_IEEE80211_RADIOTAP => "Wi-Fi monitor mode (not decoded)".to_string(),
        other => format!("hardware type {other} (not decoded)"),
    }
}

struct Iface {
    dev: Device,
    hatype: Option<u16>,
}

fn interfaces() -> Result<Vec<Iface>, String> {
    let mut list: *mut libc::ifaddrs = null_mut();
    // SAFETY: valid out-pointer; freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(format!(
            "cannot list network interfaces: {}",
            io::Error::last_os_error()
        ));
    }
    let mut out: Vec<Iface> = Vec::new();
    let mut cur = list;
    while !cur.is_null() {
        // SAFETY: a node of the list getifaddrs built.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: NUL-terminated interface name.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let flags = ifa.ifa_flags;
        let idx = match out.iter().position(|i| i.dev.name == name) {
            Some(i) => i,
            None => {
                let running = (libc::IFF_UP | libc::IFF_RUNNING) as u32;
                out.push(Iface {
                    dev: Device {
                        name,
                        desc: None,
                        addrs: Vec::new(),
                        loopback: flags & libc::IFF_LOOPBACK as u32 != 0,
                        up: flags & running == running,
                        connected: None,
                    },
                    hatype: None,
                });
                out.len() - 1
            }
        };
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: a sockaddr whose family says how big it is.
        let family = c_int::from(unsafe { (*ifa.ifa_addr).sa_family });
        let entry = &mut out[idx];
        match family {
            libc::AF_INET => {
                // SAFETY: family AF_INET means sockaddr_in.
                let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                entry.dev.addrs.push(IpAddr::V4(ip));
            }
            libc::AF_INET6 => {
                // SAFETY: family AF_INET6 means sockaddr_in6.
                let sin6 = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in6>() };
                entry
                    .dev
                    .addrs
                    .push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
            }
            libc::AF_PACKET => {
                // SAFETY: family AF_PACKET means sockaddr_ll.
                let ll = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_ll>() };
                entry.hatype = Some(ll.sll_hatype);
                entry.dev.desc = Some(kind_name(ll.sll_hatype));
            }
            _ => {}
        }
    }
    // SAFETY: the list from getifaddrs, freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(out)
}

/// Every interface, as the built-in capture sees them.
pub fn devices() -> Result<Vec<Device>, String> {
    Ok(interfaces()?.into_iter().map(|i| i.dev).collect())
}

fn set_opt<T>(fd: &OwnedFd, level: c_int, name: c_int, value: &T) -> io::Result<()> {
    // SAFETY: value points at a T of the given size.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (value as *const T).cast::<c_void>(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// An open `AF_PACKET` capture on one interface.
pub struct Builtin {
    fd: OwnedFd,
    ifindex: c_int,
    loopback: bool,
    linktype: u32,
    buf: Vec<u8>,
    filter: Option<Filter>,
    drops: u64,
}

/// Open the built-in capture on `device`.
pub fn open(device: &str, s: &Settings) -> Result<Opened, String> {
    // Check the filter first: a typo should not need root to be reported.
    let filter = match s.filter.as_deref() {
        Some(f) => Some(Filter::parse(f)?),
        None => None,
    };
    let iface = interfaces()?
        .into_iter()
        .find(|i| i.dev.name == device)
        .ok_or_else(|| format!("no interface {device}; see --mode list-interfaces"))?;
    let c_name = CString::new(device).map_err(|_| "bad interface name".to_string())?;
    // SAFETY: NUL-terminated name.
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    let ifindex = c_int::try_from(ifindex)
        .ok()
        .filter(|&i| i > 0)
        .ok_or_else(|| format!("no interface {device}; see --mode list-interfaces"))?;
    let hatype = iface.hatype.unwrap_or(ARPHRD_ETHER);

    // SAFETY: plain socket call; the result is checked and owned below.
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            c_int::from(ETH_P_ALL.to_be()),
        )
    };
    if raw < 0 {
        let e = io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => {
                format!(
                    "no permission to capture on {device}. {}",
                    permission_help()
                )
            }
            _ => format!("cannot open a capture socket: {e}"),
        });
    }
    // SAFETY: a fresh descriptor we own from here on.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: an all-zero sockaddr_ll is valid; the fields we need are set below.
    let mut addr: libc::sockaddr_ll = unsafe { zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = ETH_P_ALL.to_be();
    addr.sll_ifindex = ifindex;
    // SAFETY: addr is a sockaddr_ll of the size passed.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_ll).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "cannot capture on {device}: {}",
            io::Error::last_os_error()
        ));
    }

    let mut promisc_refused = false;
    if s.promisc {
        let mreq = PacketMreq {
            mr_ifindex: ifindex,
            mr_type: PACKET_MR_PROMISC,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        promisc_refused = set_opt(&fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq).is_err();
    }
    // Best effort: a bigger receive buffer, kernel timestamps, and the read timeout.
    let rcvbuf = c_int::try_from(s.buffer_size).unwrap_or(c_int::MAX);
    let _ = set_opt(&fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &rcvbuf);
    let one: c_int = 1;
    let _ = set_opt(&fd, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, &one);
    let ms = s.timeout_ms.max(1);
    // SAFETY: an all-zero timeval is valid (zeroed, because some libc targets add padding).
    let mut tv: libc::timeval = unsafe { zeroed() };
    tv.tv_sec = (ms / 1000) as libc::time_t;
    tv.tv_usec = ((ms % 1000) * 1000) as libc::suseconds_t;
    set_opt(&fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv)
        .map_err(|e| format!("cannot set the capture timeout: {e}"))?;

    let snap = usize::try_from(s.snaplen)
        .unwrap_or(65_535)
        .clamp(256, 262_144);
    Ok(Opened {
        capture: Box::new(Builtin {
            fd,
            ifindex,
            loopback: iface.dev.loopback || hatype == ARPHRD_LOOPBACK,
            // Undecodable link types still count as traffic ("other").
            linktype: linktype_for(hatype).unwrap_or(u32::MAX),
            buf: vec![0; snap],
            filter,
            drops: 0,
        }),
        promisc_refused,
    })
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl Capture for Builtin {
    fn next_packet(&mut self) -> Result<Next<'_>, String> {
        loop {
            // SAFETY: all-zero sockaddr_ll and msghdr are valid starting points.
            let mut from: libc::sockaddr_ll = unsafe { zeroed() };
            let mut iov = libc::iovec {
                iov_base: self.buf.as_mut_ptr().cast::<c_void>(),
                iov_len: self.buf.len(),
            };
            // u64 elements keep the control buffer aligned for cmsghdr.
            let mut control = [0u64; 16];
            // SAFETY: as above.
            let mut msg: libc::msghdr = unsafe { zeroed() };
            msg.msg_name = (&mut from as *mut libc::sockaddr_ll).cast::<c_void>();
            msg.msg_namelen = size_of::<libc::sockaddr_ll>() as _;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast::<c_void>();
            msg.msg_controllen = size_of_val(&control) as _;
            // MSG_TRUNC: return the real length even when the frame is cut to the buffer.
            // SAFETY: msg points at live buffers of the sizes it declares.
            let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, libc::MSG_TRUNC) };
            if n < 0 {
                let e = io::Error::last_os_error();
                return match e.raw_os_error() {
                    Some(libc::EAGAIN | libc::EINTR) => Ok(Next::Timeout),
                    _ => Err(format!("capture read failed: {e}")),
                };
            }
            // Frames from other interfaces can slip in before bind() takes effect.
            if from.sll_ifindex != self.ifindex {
                continue;
            }
            // On loopback every packet is seen leaving and arriving; keep one copy.
            if self.loopback && from.sll_pkttype == PACKET_OUTGOING {
                continue;
            }
            let mut ts_us = None;
            // SAFETY: walking the control messages the kernel just wrote into msg.
            unsafe {
                let mut c = libc::CMSG_FIRSTHDR(&msg);
                while !c.is_null() {
                    if (*c).cmsg_level == libc::SOL_SOCKET
                        && (*c).cmsg_type == libc::SCM_TIMESTAMPNS
                    {
                        let t =
                            std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::timespec>());
                        let secs = u64::try_from(t.tv_sec).unwrap_or(0);
                        let nanos = u64::try_from(t.tv_nsec).unwrap_or(0);
                        ts_us = Some(secs.saturating_mul(1_000_000).saturating_add(nanos / 1_000));
                    }
                    c = libc::CMSG_NXTHDR(&msg, c);
                }
            }
            let wire = usize::try_from(n).unwrap_or(0);
            let caplen = wire.min(self.buf.len());
            return Ok(Next::Packet(Packet {
                ts_us: ts_us.unwrap_or_else(now_us),
                wire_len: wire,
                data: &self.buf[..caplen],
            }));
        }
    }

    fn linktype(&self) -> u32 {
        self.linktype
    }

    fn dropped(&mut self) -> Option<u64> {
        let mut st = TpacketStats::default();
        let mut len = size_of::<TpacketStats>() as libc::socklen_t;
        // SAFETY: st and len describe a writable tpacket_stats.
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_STATISTICS,
                (&mut st as *mut TpacketStats).cast::<c_void>(),
                &mut len,
            )
        };
        // The kernel resets these counters on every read, so keep a running total.
        if rc == 0 {
            self.drops += u64::from(st.tp_drops);
            Some(self.drops)
        } else {
            None
        }
    }

    fn user_filter(&self) -> Option<&Filter> {
        self.filter.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interfaces_include_loopback() {
        let devs = devices().expect("getifaddrs works without privileges");
        let lo = devs
            .iter()
            .find(|d| d.loopback)
            .expect("a loopback interface");
        assert!(lo.desc.as_deref() == Some("loopback"), "{:?}", lo.desc);
        assert!(lo.addrs.iter().any(IpAddr::is_loopback), "{:?}", lo.addrs);
    }

    #[test]
    fn link_types() {
        assert_eq!(linktype_for(ARPHRD_ETHER), Some(linktype::ETHERNET));
        assert_eq!(linktype_for(ARPHRD_LOOPBACK), Some(linktype::ETHERNET));
        assert_eq!(linktype_for(ARPHRD_NONE), Some(linktype::RAW));
        assert_eq!(linktype_for(ARPHRD_IEEE80211_RADIOTAP), None);
    }

    #[test]
    fn a_bad_filter_is_reported_before_opening_anything() {
        let s = Settings {
            promisc: false,
            snaplen: 65_535,
            buffer_size: 1 << 20,
            timeout_ms: 50,
            filter: Some("tcp[13] & 2 != 0".to_string()),
        };
        let Err(e) = open("lo", &s) else {
            panic!("an unsupported filter must be refused");
        };
        assert!(e.contains("understands"), "{e}");
    }
}
