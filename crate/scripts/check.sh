#!/usr/bin/env bash
# Copyright (C) 2026 whispr.dev
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
cargo fmt --all --check
cargo test --locked --all-targets
cargo test --locked --doc
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
# The built-in demo, headless and as fast as it can go: frames as plain text, then the alert log.
mkdir -p target
cargo run --locked --release -- --headless --fast --frames 480 --width 120 --height 36 > target/demo-frame.txt
grep -q 'MAXWELL' target/demo-frame.txt
printf '%s\n' "Demo frame written to target/demo-frame.txt."
printf '%s\n' "Maxwell's Demon Detector validation passed."
