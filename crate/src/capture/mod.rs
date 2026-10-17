// Copyright (C) 2026 whispr.dev
// SPDX-License-Identifier: GPL-3.0-only

//! Live packet capture, set up only when live mode starts.
//!
//! Two backends:
//! * **libpcap / Npcap**, loaded at run time ([`libpcap`]). Used on Windows and
//!   macOS, and on Linux whenever libpcap can be loaded.
//! * **Built-in Linux capture** ([`linux`]), an `AF_PACKET` socket. Used on Linux
//!   when libpcap can't be loaded, which includes the static ready-built downloads.
//!
//! `MDD_CAPTURE=libpcap` or `MDD_CAPTURE=builtin` picks one by hand.

pub mod filter;
pub mod libpcap;
#[cfg(target_os = "linux")]
pub mod linux;

use std::net::IpAddr;

/// A capture interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The name capture opens, e.g. `eth0` or `\Device\NPF_{...}`.
    pub name: String,
    /// A human description, e.g. the network card's name on Windows.
    pub desc: Option<String>,
    pub addrs: Vec<IpAddr>,
    pub loopback: bool,
    /// Up and running, as far as the system reports it.
    pub up: bool,
    /// Connected (Some(true)), disconnected (Some(false)), or not reported.
    pub connected: Option<bool>,
}

impl Device {
    /// The name to show: Windows device names are GUIDs, so their description reads better.
    pub fn display_name(&self) -> &str {
        match &self.desc {
            Some(d) if self.name.starts_with(r"\Device\") => d,
            _ => &self.name,
        }
    }

    /// How likely this is the interface someone means when they don't say.
    fn score(&self) -> u32 {
        let mut s = 0;
        if !self.loopback {
            s += 8;
        }
        if !self.addrs.is_empty() {
            s += 4;
        }
        if self.connected != Some(false) {
            s += 2;
        }
        if self.up {
            s += 1;
        }
        s
    }
}

/// The interface to use when none is given: a connected, addressed, non-loopback one.
pub fn default_device(devices: &[Device]) -> Option<&Device> {
    let best = devices.iter().map(Device::score).max()?;
    devices.iter().find(|d| d.score() == best)
}

/// Capture settings from the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub promisc: bool,
    pub snaplen: u32,
    pub buffer_size: u32,
    pub timeout_ms: u32,
    /// Capture filter; `None` captures everything.
    pub filter: Option<String>,
}

/// One captured frame. `data` is valid until the next read.
#[derive(Debug)]
pub struct Packet<'a> {
    /// Capture time, microseconds since the Unix epoch.
    pub ts_us: u64,
    /// Length on the wire (may exceed `data.len()` when the snapshot length cut it).
    pub wire_len: usize,
    pub data: &'a [u8],
}

/// The result of one read.
#[derive(Debug)]
pub enum Next<'a> {
    Packet(Packet<'a>),
    /// Nothing arrived within the read timeout.
    Timeout,
    /// The capture ended.
    End,
}

/// An open capture.
pub trait Capture: Send {
    fn next_packet(&mut self) -> Result<Next<'_>, String>;
    /// The link type of every frame (pcap LINKTYPE / DLT value).
    fn linktype(&self) -> u32;
    /// Packets the system dropped so far, when it reports that.
    fn dropped(&mut self) -> Option<u64>;
    /// A filter to apply after decoding (the built-in Linux capture filters in user space).
    fn user_filter(&self) -> Option<&filter::Filter> {
        None
    }
}

/// A capture that opened, and whether promiscuous mode had to be dropped to open it.
pub struct Opened {
    pub capture: Box<dyn Capture>,
    pub promisc_refused: bool,
}

/// Which capture backend is in use.
pub enum Backend {
    Libpcap(&'static libpcap::Lib),
    /// The built-in Linux capture, and why libpcap isn't used.
    #[cfg(target_os = "linux")]
    Builtin {
        why: String,
    },
}

impl Backend {
    /// Pick the backend: libpcap or Npcap if it loads, else (Linux) the built-in capture.
    pub fn select() -> Result<Self, String> {
        let choice = std::env::var("MDD_CAPTURE").unwrap_or_default();
        Self::select_with(&choice.to_ascii_lowercase(), libpcap::shared)
    }

    fn select_with(
        choice: &str,
        load: impl FnOnce() -> Result<&'static libpcap::Lib, String>,
    ) -> Result<Self, String> {
        match choice {
            "libpcap" | "npcap" => load().map(Backend::Libpcap),
            "builtin" => Self::builtin("MDD_CAPTURE=builtin".to_string()),
            "" | "auto" => match load() {
                Ok(lib) => Ok(Backend::Libpcap(lib)),
                Err(e) if cfg!(target_os = "linux") => Self::builtin(e),
                Err(e) => Err(e),
            },
            other => Err(format!(
                "MDD_CAPTURE={other} isn't known; use auto, libpcap or builtin"
            )),
        }
    }

    #[cfg(target_os = "linux")]
    fn builtin(why: String) -> Result<Self, String> {
        Ok(Backend::Builtin { why })
    }

    #[cfg(not(target_os = "linux"))]
    fn builtin(_why: String) -> Result<Self, String> {
        Err("the built-in capture exists only on Linux".to_string())
    }

    /// One line saying what captures, for `--mode list-interfaces`.
    pub fn describe(&self) -> String {
        match self {
            Backend::Libpcap(lib) => format!("{} ({})", lib.version, lib.path),
            #[cfg(target_os = "linux")]
            Backend::Builtin { why } => {
                let why = if why.starts_with("MDD_CAPTURE") {
                    why.clone()
                } else {
                    "libpcap isn't loadable here".to_string()
                };
                format!("built-in Linux capture ({why}); --filter takes the common forms only")
            }
        }
    }

    pub fn devices(&self) -> Result<Vec<Device>, String> {
        match self {
            Backend::Libpcap(lib) => lib.devices(),
            #[cfg(target_os = "linux")]
            Backend::Builtin { .. } => linux::devices(),
        }
    }

    pub fn open(&self, device: &str, settings: &Settings) -> Result<Opened, String> {
        match self {
            Backend::Libpcap(lib) => lib.open(device, settings),
            #[cfg(target_os = "linux")]
            Backend::Builtin { .. } => linux::open(device, settings),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str, loopback: bool, addrs: usize, connected: Option<bool>) -> Device {
        Device {
            name: name.to_string(),
            desc: Some(format!("{name} card")),
            addrs: (0..addrs)
                .map(|i| IpAddr::from([10, 0, 0, i as u8]))
                .collect(),
            loopback,
            up: true,
            connected,
        }
    }

    #[test]
    fn default_device_prefers_a_real_connected_interface() {
        let devs = vec![
            dev("lo", true, 1, None),
            dev("wan-miniport", false, 0, None),
            dev("unplugged", false, 1, Some(false)),
            dev("wifi", false, 2, Some(true)),
            dev("wifi2", false, 1, Some(true)),
        ];
        assert_eq!(default_device(&devs).unwrap().name, "wifi");
        assert!(default_device(&[]).is_none());
    }

    #[test]
    fn windows_device_names_show_their_description() {
        let mut d = dev(r"\Device\NPF_{2FFE4896}", false, 1, None);
        d.desc = Some("Intel Wi-Fi 6 AX201".to_string());
        assert_eq!(d.display_name(), "Intel Wi-Fi 6 AX201");
        assert_eq!(dev("eth0", false, 1, None).display_name(), "eth0");
    }

    #[test]
    fn backend_choice() {
        let missing = || Err::<&'static libpcap::Lib, String>("no libpcap".to_string());
        let e = Backend::select_with("libpcap", missing)
            .err()
            .expect("forced libpcap fails");
        assert_eq!(e, "no libpcap");
        assert!(Backend::select_with("bogus", missing).is_err());
        let auto = Backend::select_with("", missing);
        let builtin = Backend::select_with("builtin", missing);
        if cfg!(target_os = "linux") {
            assert!(matches!(auto, Ok(ref b) if b.describe().contains("built-in")));
            assert!(builtin.is_ok());
        } else {
            assert!(auto.is_err() && builtin.is_err());
        }
    }
}
