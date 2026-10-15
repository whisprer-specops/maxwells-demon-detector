# Security notes

This covers Maxwell's Demon Detector 0.3.1, in `v0.3.0/maxwells-demon-detector/`. Report vulnerabilities privately through the repository's security advisory feature: <https://github.com/whisprer-specops/maxwells-demon-detector/security/advisories/new>. Include the version (`mdd --version`), the operating system, the exact command, reproducible steps and the likely impact. Never include real captures of other people's traffic.

- `mdd` reads packet sizes, directions, ports and timing. It never reads or stores payloads.
- Files, captures and standard input are parsed by the program's own pure-Rust readers. Malformed rows and packets are counted and skipped, never fatal.
- The ready-built downloads have no live capture. Building with `--features live` links Npcap or libpcap, which usually need administrator rights or capture permissions. Grant them only to a build you trust.
- `--record` writes what you watch to a JSONL file: sizes, directions, ports, addresses and times. Treat such files as sensitive, and capture only traffic you are allowed to capture.
- The program makes no network requests of its own and writes nothing unless asked to with `--record`.
- The program's own code contains no `unsafe` Rust. Dependencies are pinned in `Cargo.lock`.

No formal external security audit has been performed.
