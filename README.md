# Maxwell's Demon Detector

A realtime ASCII landscape of the **structure** flowing through a data stream: network packets, event logs, or the raw bytes of any file. Each lane of the stream scrolls past like an SDR waterfall turned on its side. Its height shows how busy the lane is, and its texture shows what kind of structure the data has: random, loosely patterned, rigidly ordered, one-note or metronomic. When order suddenly appears where there was none, a red `@` marks it.

The program is `mdd`. It runs in a terminal on Windows, macOS and Linux, watches live network traffic or replays files and packet captures, and reads packet sizes, directions and timing only, never payloads.

Copyright (C) 2026 whispr.dev. Maxwell's Demon Detector is free software under the GNU General Public License, version 3 only (`LICENSE`), with no warranty.

## Download

Ready-built programs for Windows, macOS and Linux are on the [Releases page](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest). These links always give the newest release:

| System | Installer | Plain archive |
| --- | --- | --- |
| Windows 10 or 11, 64-bit | [`mdd-windows-x86_64-setup.exe`](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest/download/mdd-windows-x86_64-setup.exe) | [`mdd-windows-x86_64.zip`](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest/download/mdd-windows-x86_64.zip) |
| macOS 11 or newer, Apple silicon and Intel | [`mdd-macos-universal.run`](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest/download/mdd-macos-universal.run) | [`mdd-macos-universal.tar.gz`](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest/download/mdd-macos-universal.tar.gz) |
| Linux, x86_64 | [`mdd-linux-x86_64.run`](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest/download/mdd-linux-x86_64.run) | [`mdd-linux-x86_64.tar.gz`](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest/download/mdd-linux-x86_64.tar.gz) |
| Linux, ARM64 | [`mdd-linux-aarch64.run`](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest/download/mdd-linux-aarch64.run) | [`mdd-linux-aarch64.tar.gz`](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest/download/mdd-linux-aarch64.tar.gz) |

Each installer shows the licence and asks you to accept it, then asks which folder to install into. It changes nothing else: no registry entries, no PATH changes and no uninstaller. To remove Maxwell's Demon Detector, delete its folder. The plain archives hold the same files. Every release lists each file's SHA-256 in [`SHA256SUMS.txt`](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest/download/SHA256SUMS.txt).

- **Windows:** run the `-setup.exe`. It isn't code-signed yet, so Windows may say "Windows protected your PC". That's expected: click **More info**, then **Run anyway**.
- **macOS and Linux:** open a terminal and run the installer with `sh`, for example `sh ~/Downloads/mdd-macos-universal.run`. On macOS, running it with `sh` avoids the warning about programs that aren't notarised yet. Page through the licence with Space, then type `y` to accept.

Then, in the folder you chose, `.\mdd.exe --help` on Windows, or `./mdd --help` on macOS and Linux, lists every option. To build it yourself instead, read on.

Run `mdd` with no options for the built-in 60-second demo: a voice call, a DNS tunnel, a beacon and an exfiltration burst, each flagged in its own lane. Press `q` to quit. On Windows, use Windows Terminal for colour and smooth updates.

To watch live traffic, run `mdd --mode live-pcap`. On Windows, install [Npcap](https://npcap.com/#download) first (Wireshark installs it too) and use a terminal opened as Administrator. On macOS and Linux, nothing needs installing: run it with `sudo`. The full guide below has the details.

## The full guide

[`crate/README.md`](crate/README.md) explains how to read the landscape, the demo, feeding it files, captures and live traffic, the event formats, how the statistics work, and their honest limits.

## Build it yourself

Install Rust through [rustup](https://rustup.rs) and, on Windows, the Visual Studio C++ Build Tools. Then, in PowerShell:

```powershell
cd .\crate
cargo build --locked --release
.\target\release\mdd.exe
```

The first build downloads Rust 1.97.0, which `rust-toolchain.toml` pins. `scripts\check.ps1` runs every check (`bash scripts/check.sh` on Linux and macOS). Live capture is built in and needs nothing extra to build.

## What is where

| Path | What it holds |
| --- | --- |
| `crate/` | The Rust source, tests, examples and check scripts of the current release |
| `crate/CHANGELOG.md` | What changed in each version |
| `packaging/`, `.github/workflows/release.yml` | How releases are built, packed and published for Windows, macOS and Linux |

## Licence

Copyright (C) 2026 whispr.dev. You may run, study, share and change Maxwell's Demon Detector under the GNU General Public License, version 3 only. It comes with NO WARRANTY, to the extent permitted by law. The licence does not cover the name or any logo. Releases before 0.3.1 were offered under a hybrid MIT and CC0 licence; copies already received under those terms keep them.
