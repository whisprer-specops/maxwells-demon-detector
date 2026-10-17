# Changelog

## 0.4.0 (2026-10-17)

Live capture for everyone: every copy of `mdd`, the ready-built downloads included, can now watch live traffic.

### New
- Live capture is always built in. Npcap (Windows) or libpcap (macOS, Linux) is loaded when live mode starts, not when the program starts, so `mdd` runs on machines without them and only live capture asks for them. Building needs no Npcap SDK, `libpcap-dev` or `--features live` any more (the feature is kept, empty, so older build commands still work).
- When Npcap is missing, live mode says so and where to get it, instead of the program refusing to start.
- Built-in Linux capture through an `AF_PACKET` socket, used when libpcap can't be loaded. The ready-built Linux programs are fully static and can't load libpcap, so they use it. Its `--filter` understands the common forms with libpcap's meaning and refuses anything else with a list of what it supports. `MDD_CAPTURE=builtin` or `MDD_CAPTURE=libpcap` picks a capture by hand.
- Without `--interface`, live mode picks a connected, addressed, non-loopback interface; `--mode list-interfaces` marks it `default` and says which capture is in use. `--interface` also takes part of a description, such as `--interface wi-fi`.
- If the network card refuses promiscuous mode (common on Wi-Fi), capture opens without it and the title says `own traffic: promiscuous mode refused`.
- Packets the system drops are added to the `drop` count in the title.
- Permission errors say how to fix them for the system in use (Administrator on Windows, `sudo` or a one-line `setcap` on Linux, `sudo` on macOS).
- `--alert-log FILE`: every alert written to a CSV file as it fires, with a UTC timestamp, the session clock and the lane's numbers at that moment. Nothing is lost when alerts scroll off the screen.
- `--metrics-log FILE`: every lane's statistics written to a CSV file once per tick (entropy, order score, entropy rate, KL, rhythm, detector flags), a time series ready to plot.
- Both logs flush every tick, show `LOG` in the title, and refuse to overwrite the input or each other. `--record` gets the same overwrite guard.

### Fixed
- Leaving live mode on an idle interface could wait for the next packet before quitting. Reads now wait with a timeout that libpcap honours on every system, and quitting never waits more than two seconds.

### Changed
- The crate lives in `crate/` for good, instead of a folder named after a version. The packaging, the public export and the documents follow it.
- The `pcap` crate is gone; `libc` (already used by other dependencies) handles Unix system calls. Unsafe code is confined to `src/capture/` by a crate-wide lint.
- 65 tests in all.

### Docs
- The live-capture guide is rewritten for the new set-up, with a table of what each system needs.

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
