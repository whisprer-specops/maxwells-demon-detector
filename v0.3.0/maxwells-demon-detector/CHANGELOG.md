# Changelog

## 0.3.1 (2026-10-15)

The first public Community release, from whisprer-specops/maxwells-demon-detector.

### Changed
- Licence: GPL-3.0-only, copyright whispr.dev. Earlier releases were offered under a hybrid MIT and CC0 licence; copies already received under those terms keep them.
- `--version` prints the version, then the copyright, licence and no-warranty lines; the help ends with a copyright line.
- Every code file opens with the copyright and SPDX lines, and a test enforces it (47 tests in all).
- Rust 1.97.0 is pinned in `rust-toolchain.toml`; the code keeps to Rust 1.87.

### Fixed
- Strict lints (`clippy -D warnings`) are clean on Rust 1.97.0: two link-type checks in the packet decoder became match guards, with the same behaviour.

### New
- Ready-built downloads for Windows, macOS (one program for Apple silicon and Intel) and Linux (x86_64 and ARM64). Each installer shows the licence and asks you to accept it, then asks for a folder and changes nothing else. GitHub Actions builds and checks every release on all three systems.
- `scripts/check.ps1` and `scripts/check.sh` run every check and the headless demo.

## 0.3.0 (2026-09-30)

Rebuilt from the v0.2 ASCII mapper as a new crate (binary `mdd`).

### Fixed
- The default build no longer needs the Npcap SDK or libpcap: live capture moved behind `--features live`.
- Rows no longer overflow the terminal width (the old display wrapped into garbage).
- No staircase output in raw mode on Linux/WSL and no full-screen clear per frame (flicker): frames are diffed and drawn with cursor addressing inside synchronized updates.
- Windows key-release events are ignored (keys no longer fire twice); Ctrl+C quits; the terminal is restored on errors and panics.
- The DNS lane no longer swallows every UDP payload of 12+ bytes; ARP counts as control traffic.

### New
- A real landscape: height = volume, texture = structure class (sparse, noise, flow, order, mono), caps for rhythm and bursts, markers for mix shifts and demons.
- Statistics: bias-corrected entropy, permutation-tested lag-1 dependency, robust multi-lag rhythm detection, per-lane EWMA/CUSUM/KL detectors with warm-up.
- Sources: scripted demo, raw bytes (file or stdin), pcap/pcapng files (pure Rust), CSV/JSONL replay, stdin JSONL, live capture; `--record` to JSONL.
- Headless mode (`--headless --fast`) with an alert log, for CI and screenshots.
- 45 tests (40 unit, 5 end-to-end).
