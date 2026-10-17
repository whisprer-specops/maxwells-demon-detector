// Copyright (C) 2026 whispr.dev
// SPDX-License-Identifier: GPL-3.0-only

//! Live capture through the backend [`crate::capture`] picks (Npcap, libpcap, or the
//! built-in Linux capture).
//!
//! A capture thread decodes packets and hands them over a bounded channel.
//! Capture never blocks on the UI: if the analyser falls behind, packets are
//! dropped and counted (shown as `drop` in the title bar), together with any the
//! system itself reports dropping.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::capture::{self, Backend, Device, Next, Settings};
use crate::cli::Cli;
use crate::decode::Decoder;
use crate::event::PacketEvent;
use crate::source::{Sink, Source, SourceStatus};
use crate::Result;

const QUEUE: usize = 131_072;

pub struct LiveSource {
    rx: Receiver<(PacketEvent, u64)>,
    stop: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    system_dropped: Arc<AtomicU64>,
    error: Arc<Mutex<Option<String>>>,
    handle: Option<JoinHandle<()>>,
    label: String,
    first_ts: Option<u64>,
    last_ts: u64,
    ended: bool,
}

impl LiveSource {
    pub fn start(cli: &Cli, keep_addrs: bool) -> Result<Self> {
        let backend = Backend::select()?;
        let devices = backend.devices()?;
        let device = resolve_device(&devices, cli.interface.as_deref())?.clone();
        let filter = cli
            .filter
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(str::to_string);
        let settings = Settings {
            promisc: cli.promisc,
            snaplen: cli.snaplen,
            buffer_size: cli.buffer_size,
            timeout_ms: cli.pcap_timeout_ms.max(1),
            filter: filter.clone(),
        };
        // Open in the calling thread so permission and filter errors surface immediately.
        let opened = backend.open(&device.name, &settings)?;
        let label = format!(
            "live {}{}{}",
            device.display_name(),
            filter.map(|f| format!(" [{f}]")).unwrap_or_default(),
            if opened.promisc_refused {
                " (own traffic: promiscuous mode refused)"
            } else {
                ""
            }
        );
        let local: Vec<IpAddr> = device.addrs.clone();
        let mut cap = opened.capture;
        let linktype = cap.linktype();
        let user_filter = cap.user_filter().cloned();

        let (tx, rx) = mpsc::sync_channel::<(PacketEvent, u64)>(QUEUE);
        let stop = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicU64::new(0));
        let system_dropped = Arc::new(AtomicU64::new(0));
        let error = Arc::new(Mutex::new(None));
        let (stop2, dropped2, system2, error2) = (
            Arc::clone(&stop),
            Arc::clone(&dropped),
            Arc::clone(&system_dropped),
            Arc::clone(&error),
        );
        let decoder = Decoder { local, keep_addrs };

        let handle = thread::spawn(move || {
            let mut last_stats = Instant::now();
            while !stop2.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(Next::Packet(p)) => {
                        let ts = p.ts_us;
                        let (ev, summary) = decoder.decode_full(linktype, p.data, p.wire_len);
                        let wanted = user_filter.as_ref().is_none_or(|f| f.matches(&summary));
                        if wanted {
                            match tx.try_send((ev, ts)) {
                                Ok(()) => {}
                                Err(TrySendError::Full(_)) => {
                                    dropped2.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(TrySendError::Disconnected(_)) => break,
                            }
                        }
                    }
                    Ok(Next::Timeout) => {}
                    Ok(Next::End) => break,
                    Err(e) => {
                        if let Ok(mut slot) = error2.lock() {
                            *slot = Some(e);
                        }
                        break;
                    }
                }
                if last_stats.elapsed() >= Duration::from_secs(1) {
                    if let Some(n) = cap.dropped() {
                        system2.store(n, Ordering::Relaxed);
                    }
                    last_stats = Instant::now();
                }
            }
        });

        Ok(Self {
            rx,
            stop,
            dropped,
            system_dropped,
            error,
            handle: Some(handle),
            label,
            first_ts: None,
            last_ts: 0,
            ended: false,
        })
    }
}

impl Source for LiveSource {
    fn poll(&mut self, _now: Duration, sink: &mut Sink) -> Result<()> {
        if let Some(msg) = self.error.lock().ok().and_then(|mut s| s.take()) {
            return Err(format!("capture failed: {msg}").into());
        }
        // Bounded drain per poll keeps the UI responsive under floods.
        for _ in 0..200_000 {
            match self.rx.try_recv() {
                Ok((ev, ts)) => {
                    let rel = ts.saturating_sub(*self.first_ts.get_or_insert(ts));
                    self.last_ts = self.last_ts.max(rel);
                    sink.packet(&ev, self.last_ts);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.ended = true;
                    break;
                }
            }
        }
        Ok(())
    }

    fn status(&self) -> SourceStatus {
        SourceStatus {
            label: if self.ended {
                format!("{}: capture stopped", self.label)
            } else {
                self.label.clone()
            },
            ended: self.ended,
            dropped: self.dropped.load(Ordering::Relaxed)
                + self.system_dropped.load(Ordering::Relaxed),
            bad: 0,
        }
    }

    fn realtime(&self) -> bool {
        true
    }
}

impl Drop for LiveSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            // The capture thread notices within one read timeout. If a capture
            // library ever blocks longer, don't hang on exit: leave the thread.
            let deadline = Instant::now() + Duration::from_secs(2);
            while !h.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
    }
}

/// Find the interface named by `--interface`: an index from `--mode list-interfaces`,
/// an exact name or description, or a piece of one (`--interface wi-fi`).
fn resolve_device<'a>(devices: &'a [Device], token: Option<&str>) -> Result<&'a Device> {
    let Some(token) = token.map(str::trim).filter(|t| !t.is_empty()) else {
        return capture::default_device(devices)
            .ok_or_else(|| "no capture interfaces found; see --mode list-interfaces".into());
    };
    if let Ok(idx) = token.parse::<usize>() {
        return devices.get(idx).ok_or_else(|| {
            format!("no interface at index {idx}; see --mode list-interfaces").into()
        });
    }
    if let Some(d) = devices
        .iter()
        .find(|d| d.name == token || d.desc.as_deref() == Some(token))
    {
        return Ok(d);
    }
    let needle = token.to_lowercase();
    let hits: Vec<&Device> = devices
        .iter()
        .filter(|d| {
            d.name.to_lowercase().contains(&needle)
                || d.desc
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(&needle))
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("interface not found: {token}; see --mode list-interfaces").into()),
        many => Err(format!(
            "{token:?} matches {} interfaces ({}); use the number from --mode list-interfaces",
            many.len(),
            many.iter()
                .map(|d| d.display_name())
                .collect::<Vec<_>>()
                .join(", ")
        )
        .into()),
    }
}

pub fn print_interfaces() -> Result<()> {
    let backend = Backend::select()?;
    println!("Capture: {}\n", backend.describe());
    let devices = backend.devices()?;
    if devices.is_empty() {
        println!(
            "No capture interfaces found. {}",
            capture::libpcap::permission_help()
        );
        return Ok(());
    }
    let default = capture::default_device(&devices).map(|d| d.name.as_str());
    for (idx, dev) in devices.iter().enumerate() {
        let mut notes = Vec::new();
        if Some(dev.name.as_str()) == default {
            notes.push("default");
        }
        if dev.loopback {
            notes.push("loopback");
        }
        if dev.connected == Some(false) {
            notes.push("disconnected");
        } else if !dev.up {
            notes.push("down");
        }
        let notes = if notes.is_empty() {
            String::new()
        } else {
            format!("  ({})", notes.join(", "))
        };
        println!("[{idx}] {}{notes}", dev.name);
        println!("    desc:  {}", dev.desc.as_deref().unwrap_or("(none)"));
        let addrs: Vec<String> = dev.addrs.iter().map(IpAddr::to_string).collect();
        println!(
            "    addrs: {}",
            if addrs.is_empty() {
                "(none)".to_string()
            } else {
                addrs.join(", ")
            }
        );
    }
    println!("\nUse:  mdd --mode live-pcap --interface <number, name, or part of the description>");
    println!("Without --interface, mdd uses the one marked default.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str, desc: &str) -> Device {
        Device {
            name: name.to_string(),
            desc: Some(desc.to_string()),
            addrs: vec![IpAddr::from([192, 168, 1, 2])],
            loopback: false,
            up: true,
            connected: Some(true),
        }
    }

    #[test]
    fn interfaces_by_number_name_or_part_of_the_description() {
        let devs = vec![
            dev(r"\Device\NPF_{AAA}", "Intel(R) Wi-Fi 6 AX201"),
            dev(r"\Device\NPF_{BBB}", "Realtek USB GbE Family Controller"),
            dev(r"\Device\NPF_{CCC}", "Hyper-V Virtual Ethernet Adapter"),
        ];
        let find = |t: &str| resolve_device(&devs, Some(t)).map(|d| d.name.clone());
        assert_eq!(find("1").unwrap(), r"\Device\NPF_{BBB}");
        assert_eq!(find(r"\Device\NPF_{CCC}").unwrap(), r"\Device\NPF_{CCC}");
        assert_eq!(find("wi-fi").unwrap(), r"\Device\NPF_{AAA}");
        assert!(find("9").unwrap_err().to_string().contains("index 9"));
        assert!(find("bluetooth")
            .unwrap_err()
            .to_string()
            .contains("not found"));
        let e = find("e").unwrap_err().to_string();
        assert!(e.contains("matches 3 interfaces"), "{e}");
        assert_eq!(
            resolve_device(&devs, None).unwrap().name,
            r"\Device\NPF_{AAA}",
            "no --interface: the default device"
        );
    }
}
