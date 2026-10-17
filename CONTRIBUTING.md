# Contributing

## Copyright first

whispr.dev holds the copyright in Maxwell's Demon Detector. Before starting work on a change you would like merged, open an issue so the terms for your contribution can be agreed first. Bug reports need no agreement: see the end of this file.

Every code file opens with these two lines, as comments in its own language, after any `#!` line. `crate/tests/notice_contracts.rs` fails a file without them.

```text
Copyright (C) 2026 whispr.dev
SPDX-License-Identifier: GPL-3.0-only
```

## Building and checking

Work in `crate/`. Use Rust 1.97.0, as pinned in `rust-toolchain.toml` (rustup installs it on the first build). The code keeps to Rust 1.87, the declared minimum in `Cargo.toml`.

On Windows, `powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1` runs every check: formatting, the tests, strict lints (`clippy -D warnings`), a release build and the headless demo. `bash scripts/check.sh` does the same elsewhere. Live capture is always compiled, so these checks cover it. A change to `src/capture/` should also be tried for real: `sudo ./target/release/mdd --mode live-pcap` on Linux, both with libpcap and with `MDD_CAPTURE=builtin`.

## Rules for changes

- Tests must never need network access, a capture driver or real traffic. Use the synthetic demo or files in `examples/`.
- Keep the event file formats, the command-line options and the glyph meanings, unless a documented breaking change is needed.
- Explain any dependency change and update `Cargo.lock` intentionally.
- Update the README and `CHANGELOG.md` with any change in behaviour.

Bug reports should include the version (`mdd --version`), the operating system and terminal, the exact command, the expected result and any error output. Keep discussion constructive and follow `CODE_OF_CONDUCT.md`.
