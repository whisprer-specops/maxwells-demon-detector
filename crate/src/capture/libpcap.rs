// Copyright (C) 2026 whispr.dev
// SPDX-License-Identifier: GPL-3.0-only

//! libpcap (Linux, macOS) or Npcap (Windows), loaded when live capture starts.
//!
//! Nothing here is linked at build time, so building needs no SDK or `-dev`
//! package, and the program starts on machines without Npcap or libpcap: only
//! live capture asks for the library, and says how to get it when it is missing.
//!
//! On Windows, Npcap's `wpcap.dll` is loaded from `System32\Npcap` by full path
//! (Npcap's own advice), then from `System32` (WinPcap-compatible installs), never
//! from the current folder, so a stray `wpcap.dll` next to the program can't be
//! picked up instead.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::{self, null_mut};
use std::sync::OnceLock;

use super::{Capture, Device, Next, Opened, Packet, Settings};

const ERRBUF_SIZE: usize = 256;
const PCAP_NETMASK_UNKNOWN: u32 = 0xffff_ffff;
const PCAP_CHAR_ENC_UTF_8: c_uint = 1;

const PCAP_ERROR: c_int = -1;
const PCAP_ERROR_BREAK: c_int = -2;
const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
const PCAP_ERROR_PERM_DENIED: c_int = -8;
const PCAP_ERROR_IFACE_NOT_UP: c_int = -9;
const PCAP_ERROR_PROMISC_PERM_DENIED: c_int = -11;
const PCAP_WARNING_PROMISC_NOTSUP: c_int = 2;

const PCAP_IF_LOOPBACK: u32 = 0x1;
const PCAP_IF_UP: u32 = 0x2;
const PCAP_IF_RUNNING: u32 = 0x4;
const PCAP_IF_CONNECTION_STATUS: u32 = 0x30;
const PCAP_IF_CONNECTION_STATUS_CONNECTED: u32 = 0x10;
const PCAP_IF_CONNECTION_STATUS_DISCONNECTED: u32 = 0x20;

/// `pcap_t`: opaque.
#[repr(C)]
struct PcapT {
    _private: [u8; 0],
}

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut PcapAddr,
    flags: u32,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *const u8,
    netmask: *const u8,
    broadaddr: *const u8,
    dstaddr: *const u8,
}

#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

/// `struct pcap_stat`, with room to spare: Windows builds of libpcap add fields.
#[repr(C)]
#[derive(Default)]
struct PcapStat {
    ps_recv: c_uint,
    ps_drop: c_uint,
    ps_ifdrop: c_uint,
    _more: [c_uint; 5],
}

/// `struct timeval` as libpcap uses it: two 32-bit `long`s on Windows.
#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal {
    tv_sec: i32,
    tv_usec: i32,
}

#[cfg(not(windows))]
type TimeVal = libc::timeval;

#[repr(C)]
struct PktHdr {
    ts: TimeVal,
    caplen: u32,
    len: u32,
}

type SetInt = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;

struct Api {
    lib_version: unsafe extern "C" fn() -> *const c_char,
    findalldevs: unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int,
    freealldevs: unsafe extern "C" fn(*mut PcapIf),
    create: unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT,
    set_snaplen: SetInt,
    set_promisc: SetInt,
    set_timeout: SetInt,
    set_buffer_size: SetInt,
    set_immediate_mode: Option<SetInt>,
    #[cfg(unix)]
    setnonblock: Option<unsafe extern "C" fn(*mut PcapT, c_int, *mut c_char) -> c_int>,
    #[cfg(unix)]
    get_selectable_fd: Option<unsafe extern "C" fn(*mut PcapT) -> c_int>,
    activate: unsafe extern "C" fn(*mut PcapT) -> c_int,
    geterr: unsafe extern "C" fn(*mut PcapT) -> *mut c_char,
    statustostr: unsafe extern "C" fn(c_int) -> *const c_char,
    compile: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, u32) -> c_int,
    setfilter: unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int,
    freecode: unsafe extern "C" fn(*mut BpfProgram),
    next_ex: unsafe extern "C" fn(*mut PcapT, *mut *mut PktHdr, *mut *const u8) -> c_int,
    datalink: unsafe extern "C" fn(*mut PcapT) -> c_int,
    stats: unsafe extern "C" fn(*mut PcapT, *mut PcapStat) -> c_int,
    close: unsafe extern "C" fn(*mut PcapT),
    open_dead: unsafe extern "C" fn(c_int, c_int) -> *mut PcapT,
}

/// A loaded libpcap or Npcap. The library stays loaded for the life of the program.
pub struct Lib {
    api: Api,
    /// The library's own version line, e.g. "libpcap version 1.10.4".
    pub version: String,
    /// Which file was loaded.
    pub path: String,
}

static SHARED: OnceLock<Result<Lib, String>> = OnceLock::new();

/// The library, loaded on first use.
pub fn shared() -> Result<&'static Lib, String> {
    SHARED
        .get_or_init(|| Lib::load_from(&os::candidates()))
        .as_ref()
        .map_err(Clone::clone)
}

/// What to tell someone whose machine has no usable library.
pub fn missing_help() -> &'static str {
    if cfg!(windows) {
        "Live capture needs Npcap, which isn't installed. Get it from https://npcap.com/#download \
         (Wireshark installs it too), then run mdd again. Everything else in mdd works without it."
    } else if cfg!(target_os = "macos") {
        "Live capture uses the libpcap that comes with macOS, and it could not be loaded."
    } else {
        "Install libpcap for live capture: Debian or Ubuntu `sudo apt install libpcap0.8`, \
         Fedora `sudo dnf install libpcap`, Arch `sudo pacman -S libpcap`."
    }
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: libpcap hands out NUL-terminated strings that live at least this long.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

/// Look up one symbol as a function pointer of type `T`.
///
/// # Safety
/// `T` must be the correct `extern "C" fn` type for that symbol.
unsafe fn sym<T: Copy>(h: os::Handle, name: &CStr) -> Option<T> {
    assert_eq!(size_of::<T>(), size_of::<*mut c_void>());
    let p = os::symbol(h, name);
    if p.is_null() {
        None
    } else {
        // SAFETY: the caller guarantees `T` is this symbol's function type.
        Some(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&p) })
    }
}

impl Lib {
    /// Load the first candidate that opens and has every function we need.
    pub fn load_from(candidates: &[String]) -> Result<Self, String> {
        let mut tried = Vec::new();
        for name in candidates {
            match os::open(name) {
                Ok(h) => match Self::bind(h) {
                    Ok((api, version)) => {
                        return Ok(Self {
                            api,
                            version,
                            path: name.clone(),
                        })
                    }
                    Err(missing) => tried.push(format!("{name}: has no {missing} (too old)")),
                },
                Err(e) => tried.push(e),
            }
        }
        Err(format!("{} (tried: {})", missing_help(), tried.join("; ")))
    }

    fn bind(h: os::Handle) -> Result<(Api, String), &'static str> {
        macro_rules! need {
            ($name:literal) => {
                // SAFETY: each field's type matches the libpcap prototype of that name.
                unsafe { sym(h, $name) }.ok_or_else(|| $name.to_str().unwrap_or("a function"))?
            };
        }
        let api = Api {
            lib_version: need!(c"pcap_lib_version"),
            findalldevs: need!(c"pcap_findalldevs"),
            freealldevs: need!(c"pcap_freealldevs"),
            create: need!(c"pcap_create"),
            set_snaplen: need!(c"pcap_set_snaplen"),
            set_promisc: need!(c"pcap_set_promisc"),
            set_timeout: need!(c"pcap_set_timeout"),
            set_buffer_size: need!(c"pcap_set_buffer_size"),
            // SAFETY: as above; optional (libpcap 1.5 and later). The two after it
            // are Unix-only: Windows has no selectable descriptor.
            set_immediate_mode: unsafe { sym(h, c"pcap_set_immediate_mode") },
            // SAFETY: as above.
            #[cfg(unix)]
            setnonblock: unsafe { sym(h, c"pcap_setnonblock") },
            // SAFETY: as above.
            #[cfg(unix)]
            get_selectable_fd: unsafe { sym(h, c"pcap_get_selectable_fd") },
            activate: need!(c"pcap_activate"),
            geterr: need!(c"pcap_geterr"),
            statustostr: need!(c"pcap_statustostr"),
            compile: need!(c"pcap_compile"),
            setfilter: need!(c"pcap_setfilter"),
            freecode: need!(c"pcap_freecode"),
            next_ex: need!(c"pcap_next_ex"),
            datalink: need!(c"pcap_datalink"),
            stats: need!(c"pcap_stats"),
            close: need!(c"pcap_close"),
            open_dead: need!(c"pcap_open_dead"),
        };
        // Ask for UTF-8 strings (interface descriptions, errors) where supported.
        // SAFETY: pcap_init(unsigned int, char *errbuf) in libpcap 1.10+ and Npcap.
        let init: Option<unsafe extern "C" fn(c_uint, *mut c_char) -> c_int> =
            unsafe { sym(h, c"pcap_init") };
        if let Some(init) = init {
            let mut err = [0 as c_char; ERRBUF_SIZE];
            // SAFETY: err is a writable buffer of the size libpcap expects.
            let _ = unsafe { init(PCAP_CHAR_ENC_UTF_8, err.as_mut_ptr()) };
        }
        // SAFETY: returns a static string.
        let version = cstr(unsafe { (api.lib_version)() });
        Ok((api, version))
    }

    /// Every capture interface the library can see.
    pub fn devices(&self) -> Result<Vec<Device>, String> {
        let mut list: *mut PcapIf = null_mut();
        let mut err = [0 as c_char; ERRBUF_SIZE];
        // SAFETY: valid out-pointer and error buffer.
        let rc = unsafe { (self.api.findalldevs)(&mut list, err.as_mut_ptr()) };
        if rc != 0 {
            return Err(format!(
                "cannot list capture interfaces: {}. {}",
                cstr(err.as_ptr()),
                permission_help()
            ));
        }
        let mut out = Vec::new();
        let mut cur = list;
        while !cur.is_null() {
            // SAFETY: a node of the list pcap_findalldevs just built.
            let d = unsafe { &*cur };
            let mut addrs = Vec::new();
            let mut a = d.addresses;
            while !a.is_null() {
                // SAFETY: a node of the address list; addr may be null.
                let node = unsafe { &*a };
                // SAFETY: a sockaddr from libpcap, or null.
                if let Some(ip) = unsafe { sockaddr_ip(node.addr) } {
                    addrs.push(ip);
                }
                a = node.next;
            }
            let desc = cstr(d.description);
            let status = d.flags & PCAP_IF_CONNECTION_STATUS;
            out.push(Device {
                name: cstr(d.name),
                desc: (!desc.is_empty()).then_some(desc),
                addrs,
                loopback: d.flags & PCAP_IF_LOOPBACK != 0,
                up: d.flags & (PCAP_IF_UP | PCAP_IF_RUNNING) == (PCAP_IF_UP | PCAP_IF_RUNNING),
                connected: match status {
                    PCAP_IF_CONNECTION_STATUS_CONNECTED => Some(true),
                    PCAP_IF_CONNECTION_STATUS_DISCONNECTED => Some(false),
                    _ => None,
                },
            });
            cur = d.next;
        }
        if !list.is_null() {
            // SAFETY: the list from pcap_findalldevs, freed once.
            unsafe { (self.api.freealldevs)(list) };
        }
        Ok(out)
    }

    /// Open a live capture. If promiscuous mode is refused (common on Wi-Fi), it
    /// opens again without it and says so in [`Opened::promisc_refused`].
    pub fn open(&'static self, device: &str, s: &Settings) -> Result<Opened, String> {
        let (handle, refused) = match self.activate(device, s, s.promisc) {
            Ok((h, warning)) => (h, s.promisc && warning == PCAP_WARNING_PROMISC_NOTSUP),
            Err((code, msg))
                if s.promisc && matches!(code, PCAP_ERROR | PCAP_ERROR_PROMISC_PERM_DENIED) =>
            {
                match self.activate(device, s, false) {
                    Ok((h, _)) => (h, true),
                    Err(_) => return Err(msg),
                }
            }
            Err((_, msg)) => return Err(msg),
        };
        if let Some(f) = s.filter.as_deref() {
            handle.set_filter(f)?;
        }
        Ok(Opened {
            capture: Box::new(handle),
            promisc_refused: refused,
        })
    }

    fn activate(
        &'static self,
        device: &str,
        s: &Settings,
        promisc: bool,
    ) -> Result<(Handle, c_int), (c_int, String)> {
        let c_dev =
            CString::new(device).map_err(|_| (PCAP_ERROR, "bad interface name".to_string()))?;
        let mut err = [0 as c_char; ERRBUF_SIZE];
        // SAFETY: valid strings and error buffer.
        let p = unsafe { (self.api.create)(c_dev.as_ptr(), err.as_mut_ptr()) };
        if p.is_null() {
            return Err((
                PCAP_ERROR,
                format!("cannot open {device}: {}", cstr(err.as_ptr())),
            ));
        }
        // From here on the handle closes itself on every path.
        let mut h = Handle {
            lib: self,
            p,
            linktype: 0,
            wait: None,
        };
        let int = |v: u32| c_int::try_from(v).unwrap_or(c_int::MAX);
        // SAFETY: h.p is a created, not yet activated handle.
        unsafe {
            (self.api.set_snaplen)(h.p, int(s.snaplen));
            (self.api.set_promisc)(h.p, c_int::from(promisc));
            (self.api.set_timeout)(h.p, int(s.timeout_ms.max(1)));
            (self.api.set_buffer_size)(h.p, int(s.buffer_size));
            if let Some(f) = self.api.set_immediate_mode {
                f(h.p, 1);
            }
        }
        // SAFETY: as above.
        let rc = unsafe { (self.api.activate)(h.p) };
        if rc < 0 {
            // SAFETY: geterr's string is valid until the next call on this handle.
            let detail = cstr(unsafe { (self.api.geterr)(h.p) });
            return Err((rc, self.activate_error(device, rc, &detail)));
        }
        // SAFETY: activated handle.
        let lt = unsafe { (self.api.datalink)(h.p) };
        h.linktype = u32::try_from(lt).unwrap_or(u32::MAX);
        h.wait = self.waiter(h.p, s.timeout_ms.max(1));
        Ok((h, rc))
    }

    fn activate_error(&self, device: &str, code: c_int, detail: &str) -> String {
        // SAFETY: returns a static string.
        let status = cstr(unsafe { (self.api.statustostr)(code) });
        let detail = if detail.is_empty() {
            status.as_str()
        } else {
            detail
        };
        match code {
            PCAP_ERROR_PERM_DENIED | PCAP_ERROR_PROMISC_PERM_DENIED => {
                format!(
                    "no permission to capture on {device} ({detail}). {}",
                    permission_help()
                )
            }
            PCAP_ERROR_NO_SUCH_DEVICE => {
                format!("no interface {device} ({detail}); see --mode list-interfaces")
            }
            PCAP_ERROR_IFACE_NOT_UP => format!("interface {device} is down ({detail})"),
            _ => format!("cannot capture on {device}: {detail}"),
        }
    }

    /// On Linux and macOS, libpcap's read timeout does not make an idle read return
    /// (its manual says not to rely on it), so reads are made non-blocking and the
    /// wait is done with poll(), which does honour a timeout. Windows (Npcap) returns
    /// from a read when the timeout passes, so it needs none of this.
    #[cfg(unix)]
    fn waiter(&self, p: *mut PcapT, timeout_ms: u32) -> Option<Wait> {
        let (nonblock, selectable) = (self.api.setnonblock?, self.api.get_selectable_fd?);
        // SAFETY: activated handle.
        let fd = unsafe { selectable(p) };
        if fd < 0 {
            return None;
        }
        let mut err = [0 as c_char; ERRBUF_SIZE];
        // SAFETY: activated handle and error buffer.
        if unsafe { nonblock(p, 1, err.as_mut_ptr()) } != 0 {
            return None;
        }
        Some(Wait {
            fd,
            timeout_ms: c_int::try_from(timeout_ms).unwrap_or(1_000),
        })
    }

    #[cfg(not(unix))]
    fn waiter(&self, _p: *mut PcapT, _timeout_ms: u32) -> Option<Wait> {
        None
    }

    /// Check a filter's syntax without opening any interface.
    pub fn check_filter(&'static self, linktype: u32, filter: &str) -> Result<(), String> {
        let lt = c_int::try_from(linktype).map_err(|_| "bad link type".to_string())?;
        // SAFETY: open_dead needs no privileges and returns a handle or null.
        let p = unsafe { (self.api.open_dead)(lt, 65_535) };
        if p.is_null() {
            return Err("libpcap could not make a test handle".to_string());
        }
        let h = Handle {
            lib: self,
            p,
            linktype,
            wait: None,
        };
        h.compile(filter).map(|_| ())
    }
}

/// How to get capture permission on this system.
pub fn permission_help() -> String {
    if cfg!(windows) {
        "Run the terminal as Administrator, or reinstall Npcap with \"Restrict Npcap driver's \
         access to Administrators only\" unticked."
            .to_string()
    } else if cfg!(target_os = "macos") {
        "Run mdd with sudo.".to_string()
    } else {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "mdd".to_string());
        format!("Run mdd with sudo, or allow it once with: sudo setcap cap_net_raw,cap_net_admin=eip {exe}")
    }
}

/// One open capture handle.
pub struct Handle {
    lib: &'static Lib,
    p: *mut PcapT,
    linktype: u32,
    /// Set when reads are non-blocking and waits go through poll().
    wait: Option<Wait>,
}

/// A descriptor to poll before reading, and how long to wait on it (Unix only;
/// on Windows a `Wait` is never made).
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Wait {
    fd: c_int,
    timeout_ms: c_int,
}

impl Wait {
    #[cfg(unix)]
    fn idle(self) {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd. The result doesn't matter: the read after it
        // is non-blocking and reports whatever is there.
        let _ = unsafe { libc::poll(&mut pfd, 1, self.timeout_ms) };
    }

    #[cfg(not(unix))]
    fn idle(self) {}
}

// SAFETY: a pcap handle may move between threads; it is only ever used by one at a time.
unsafe impl Send for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: closed exactly once.
        unsafe { (self.lib.api.close)(self.p) };
    }
}

/// A compiled BPF program, freed on drop.
struct Program<'a> {
    lib: &'a Lib,
    prog: BpfProgram,
}

impl Drop for Program<'_> {
    fn drop(&mut self) {
        // SAFETY: a program pcap_compile filled in, freed once.
        unsafe { (self.lib.api.freecode)(&mut self.prog) };
    }
}

impl Handle {
    fn compile(&self, filter: &str) -> Result<Program<'static>, String> {
        let c = CString::new(filter).map_err(|_| "the filter contains a NUL byte".to_string())?;
        let mut prog = BpfProgram {
            bf_len: 0,
            bf_insns: null_mut(),
        };
        // SAFETY: valid handle, program and string.
        let rc = unsafe {
            (self.lib.api.compile)(self.p, &mut prog, c.as_ptr(), 1, PCAP_NETMASK_UNKNOWN)
        };
        if rc != 0 {
            // SAFETY: geterr on this handle.
            let why = cstr(unsafe { (self.lib.api.geterr)(self.p) });
            return Err(format!("bad capture filter {filter:?}: {why}"));
        }
        Ok(Program {
            lib: self.lib,
            prog,
        })
    }

    fn set_filter(&self, filter: &str) -> Result<(), String> {
        let mut prog = self.compile(filter)?;
        // SAFETY: valid handle and compiled program.
        let rc = unsafe { (self.lib.api.setfilter)(self.p, &mut prog.prog) };
        if rc != 0 {
            // SAFETY: geterr on this handle.
            let why = cstr(unsafe { (self.lib.api.geterr)(self.p) });
            return Err(format!("cannot apply capture filter {filter:?}: {why}"));
        }
        Ok(())
    }
}

impl Capture for Handle {
    fn next_packet(&mut self) -> Result<Next<'_>, String> {
        let mut hdr: *mut PktHdr = null_mut();
        let mut data: *const u8 = ptr::null();
        // SAFETY: valid handle and out-pointers.
        let mut rc = unsafe { (self.lib.api.next_ex)(self.p, &mut hdr, &mut data) };
        if rc == 0 {
            if let Some(w) = self.wait {
                w.idle();
                // SAFETY: as above.
                rc = unsafe { (self.lib.api.next_ex)(self.p, &mut hdr, &mut data) };
            }
        }
        match rc {
            1 if !hdr.is_null() && !data.is_null() => {
                // SAFETY: on success both point at libpcap's buffer until the next call,
                // which needs `&mut self` again, so the borrow can't outlive them.
                let h = unsafe { &*hdr };
                let caplen = usize::try_from(h.caplen).unwrap_or(0);
                // SAFETY: libpcap guarantees `caplen` readable bytes at `data`.
                let bytes = unsafe { std::slice::from_raw_parts(data, caplen) };
                // The field types differ: i32 on Windows, time_t / suseconds_t elsewhere.
                #[allow(clippy::useless_conversion)]
                let (secs, micros) = (
                    u64::try_from(i64::from(h.ts.tv_sec)).unwrap_or(0),
                    u64::try_from(i64::from(h.ts.tv_usec)).unwrap_or(0),
                );
                Ok(Next::Packet(Packet {
                    ts_us: secs.saturating_mul(1_000_000).saturating_add(micros),
                    wire_len: usize::try_from(h.len).unwrap_or(caplen),
                    data: bytes,
                }))
            }
            0 | 1 => Ok(Next::Timeout),
            PCAP_ERROR_BREAK => Ok(Next::End),
            _ => {
                // SAFETY: geterr on this handle.
                Err(cstr(unsafe { (self.lib.api.geterr)(self.p) }))
            }
        }
    }

    fn linktype(&self) -> u32 {
        self.linktype
    }

    fn dropped(&mut self) -> Option<u64> {
        let mut st = PcapStat::default();
        // SAFETY: valid handle; PcapStat is larger than any platform's struct pcap_stat.
        let rc = unsafe { (self.lib.api.stats)(self.p, &mut st) };
        (rc == 0).then(|| u64::from(st.ps_drop) + u64::from(st.ps_ifdrop))
    }
}

const AF_INET: u16 = 2;
#[cfg(windows)]
const AF_INET6: u16 = 23;
#[cfg(not(windows))]
const AF_INET6: u16 = libc::AF_INET6 as u16;

/// The address family in a sockaddr's first two bytes. BSD-style systems (macOS
/// included) start with a length byte, then a one-byte family.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn family_of(head: [u8; 2]) -> u16 {
    u16::from(head[1])
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn family_of(head: [u8; 2]) -> u16 {
    u16::from_ne_bytes(head)
}

/// The IP address in a sockaddr, if it is IPv4 or IPv6.
///
/// # Safety
/// `sa` must be null or point at a complete sockaddr of the family it declares.
unsafe fn sockaddr_ip(sa: *const u8) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: every sockaddr has at least its two family bytes.
    let head = unsafe { ptr::read_unaligned(sa.cast::<[u8; 2]>()) };
    match family_of(head) {
        AF_INET => {
            // SAFETY: sockaddr_in is 16 bytes; the address is bytes 4..8.
            let b = unsafe { ptr::read_unaligned(sa.cast::<[u8; 8]>()) };
            Some(IpAddr::V4(Ipv4Addr::new(b[4], b[5], b[6], b[7])))
        }
        AF_INET6 => {
            // SAFETY: sockaddr_in6 is 28 bytes; the address is bytes 8..24.
            let b = unsafe { ptr::read_unaligned(sa.cast::<[u8; 24]>()) };
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

#[cfg(windows)]
mod os {
    use std::ffi::{c_char, c_void, CStr};

    pub type Handle = *mut c_void;

    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
    const MAX_PATH: usize = 260;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        fn GetLastError() -> u32;
    }

    fn system_dir() -> String {
        let mut buf = [0u16; MAX_PATH];
        // SAFETY: buffer and its length in characters.
        let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), MAX_PATH as u32) } as usize;
        if n == 0 || n >= MAX_PATH {
            r"C:\Windows\System32".to_string()
        } else {
            String::from_utf16_lossy(&buf[..n])
        }
    }

    /// Npcap's own folder first, by full path; then System32 only (WinPcap-compatible mode).
    pub fn candidates() -> Vec<String> {
        vec![
            format!(r"{}\Npcap\wpcap.dll", system_dir()),
            "wpcap.dll".to_string(),
        ]
    }

    pub fn open(name: &str) -> Result<Handle, String> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // A full path also finds Packet.dll beside it; a bare name searches System32 only.
        let flags = if name.contains('\\') {
            LOAD_WITH_ALTERED_SEARCH_PATH
        } else {
            LOAD_LIBRARY_SEARCH_SYSTEM32
        };
        // SAFETY: NUL-terminated wide string.
        let h = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), flags) };
        if h.is_null() {
            // SAFETY: no arguments.
            let code = unsafe { GetLastError() };
            let why = match code {
                126 => "not found".to_string(),
                193 => "not a 64-bit DLL".to_string(),
                c => format!("Windows error {c}"),
            };
            Err(format!("{name}: {why}"))
        } else {
            Ok(h)
        }
    }

    pub fn symbol(h: Handle, name: &CStr) -> *mut c_void {
        // SAFETY: a loaded module and a NUL-terminated name.
        unsafe { GetProcAddress(h, name.as_ptr()) }
    }
}

#[cfg(not(windows))]
mod os {
    use std::ffi::{c_void, CStr, CString};

    pub type Handle = *mut c_void;

    pub fn candidates() -> Vec<String> {
        if cfg!(target_os = "macos") {
            vec![
                "/usr/lib/libpcap.A.dylib".to_string(),
                "libpcap.dylib".to_string(),
            ]
        } else {
            // Fedora and Arch ship .so.1; Debian and Ubuntu ship .so.0.8.
            vec![
                "libpcap.so.1".to_string(),
                "libpcap.so.0.8".to_string(),
                "libpcap.so".to_string(),
            ]
        }
    }

    pub fn open(name: &str) -> Result<Handle, String> {
        let c = CString::new(name).map_err(|_| format!("{name}: bad name"))?;
        // SAFETY: NUL-terminated name; the handle is kept for the life of the program.
        let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if h.is_null() {
            // SAFETY: dlerror returns a thread-local string or null.
            let e = unsafe { libc::dlerror() };
            let why = if e.is_null() {
                "cannot load".to_string()
            } else {
                // SAFETY: NUL-terminated message from dlerror.
                unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned()
            };
            Err(why)
        } else {
            Ok(h)
        }
    }

    pub fn symbol(h: Handle, name: &CStr) -> *mut c_void {
        // SAFETY: a handle from dlopen and a NUL-terminated name.
        unsafe { libc::dlsym(h, name.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(family: u16) -> [u8; 2] {
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        {
            [16, family as u8]
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )))]
        {
            family.to_ne_bytes()
        }
    }

    #[test]
    fn sockaddrs_decode() {
        let mut v4 = [0u8; 16];
        v4[..2].copy_from_slice(&head(AF_INET));
        v4[4..8].copy_from_slice(&[192, 168, 1, 20]);
        // SAFETY: a complete sockaddr_in-sized buffer.
        assert_eq!(
            unsafe { sockaddr_ip(v4.as_ptr()) },
            Some("192.168.1.20".parse().unwrap())
        );
        let mut v6 = [0u8; 28];
        v6[..2].copy_from_slice(&head(AF_INET6));
        let a: Ipv6Addr = "fe80::1234".parse().unwrap();
        v6[8..24].copy_from_slice(&a.octets());
        // SAFETY: a complete sockaddr_in6-sized buffer.
        assert_eq!(unsafe { sockaddr_ip(v6.as_ptr()) }, Some(IpAddr::V6(a)));
        let other = [0u8; 16];
        // SAFETY: family 0 is not decoded beyond its header.
        assert_eq!(unsafe { sockaddr_ip(other.as_ptr()) }, None);
        // SAFETY: null is allowed.
        assert_eq!(unsafe { sockaddr_ip(ptr::null()) }, None);
    }

    #[test]
    fn a_missing_library_says_how_to_get_it() {
        let Err(e) = Lib::load_from(&["definitely-not-a-capture-library-xyz".to_string()]) else {
            panic!("a made-up library name must not load");
        };
        assert!(e.contains(missing_help()), "{e}");
        assert!(e.contains("definitely-not-a-capture-library-xyz"), "{e}");
    }

    /// When the system has libpcap or Npcap, check the struct layouts end to end:
    /// compile filters on a dead handle (no privileges or interfaces needed).
    #[test]
    fn filters_compile_through_the_loaded_library() {
        let Ok(lib) = shared() else {
            eprintln!("no libpcap or Npcap on this machine: skipped");
            return;
        };
        assert!(!lib.version.is_empty());
        lib.check_filter(1, "udp port 53 or (tcp and not port 22)")
            .expect("a valid filter compiles");
        let e = lib
            .check_filter(1, "udp prot 53")
            .expect_err("a typo is refused");
        assert!(e.contains("bad capture filter"), "{e}");
    }
}
