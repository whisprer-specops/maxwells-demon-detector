// Copyright (C) 2026 whispr.dev
// SPDX-License-Identifier: GPL-3.0-only

//! Maxwell's Demon Detector: watch structure flow through a data stream as a
//! scrolling ASCII landscape.
//!
//! Pipeline: [`source`] (demo, files, stdin, pcap, live via [`capture`]) -> [`event`] symbolisation
//! -> [`analysis`] per-lane statistics and detectors -> [`app`] history ->
//! [`render`] frame -> [`screen`] flicker-free terminal output. [`logs`] writes
//! optional CSV logs of alerts and per-tick lane metrics.

#![deny(unsafe_code)]

pub mod analysis;
pub mod app;
// Unsafe code is allowed only here: loading Npcap / libpcap and the Linux capture socket.
#[allow(unsafe_code)]
pub mod capture;
pub mod cli;
pub mod decode;
pub mod event;
pub mod logs;
pub mod pcapfile;
pub mod render;
pub mod rng;
pub mod run;
pub mod screen;
pub mod source;

/// Crate-wide error type: any error, sendable across threads.
pub type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

pub use cli::{Cli, Mode};
pub use run::{run, run_headless};
