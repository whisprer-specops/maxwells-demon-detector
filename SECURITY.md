# Security notes

This covers Maxwell's Demon Detector 0.4.0, in `crate/`. Report vulnerabilities privately through the repository's security advisory feature: <https://github.com/whisprer-specops/maxwells-demon-detector/security/advisories/new>. Include the version (`mdd --version`), the operating system, the exact command, reproducible steps and the likely impact. Never include real captures of other people's traffic.

- `mdd` reads packet sizes, directions, ports and timing. It never reads or stores payloads.
- Files, captures and standard input are parsed by the program's own pure-Rust readers. Malformed rows and packets are counted and skipped, never fatal.
- Live capture needs administrator rights or capture permissions (Administrator on Windows, `sudo` or `CAP_NET_RAW` on Linux, `sudo` on macOS). Grant them only to a copy you trust, such as a release whose SHA-256 matches `SHA256SUMS.txt`.
- Npcap and libpcap are loaded only when live capture starts. On Windows, `wpcap.dll` is loaded by full path from `System32\Npcap`, then from `System32` only, never from the current folder or the program's folder, so a planted `wpcap.dll` is not picked up.
- `--record` writes what you watch to a JSONL file: sizes, directions, ports, addresses and times. Treat such files as sensitive, and capture only traffic you are allowed to capture.
- The program makes no network requests of its own and writes nothing unless asked to with `--record`, `--alert-log` or `--metrics-log`.
- Unsafe Rust appears only in `src/capture/`, for loading Npcap or libpcap and for the built-in Linux capture socket; a crate-wide lint forbids it anywhere else, and each unsafe block says why it is sound. Dependencies are pinned in `Cargo.lock`.

No formal external security audit has been performed.
