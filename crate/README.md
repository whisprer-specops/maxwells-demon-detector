# Maxwell's Demon Detector (`mdd`) v0.4.0

Copyright (C) 2026 whispr.dev. Free software under the GNU General Public License, version 3 only (GPL-3.0-only), with no warranty. The full terms are in the repository's `LICENSE`.

A realtime ASCII landscape of the **structure** flowing through a data stream:
network packets, event logs, or the raw bytes of any file.

Think of an SDR waterfall turned on its side. Time flows right to left (newest
column on the right). Each horizontal band is one **lane** of the stream. How tall
a column is tells you how busy that lane was; **which symbol it is built from tells
you what kind of structure the data had** at that moment: random, loosely
patterned, rigidly ordered, one-note, metronomic. When order suddenly appears
where there was none (the "demon" sorting molecules), a red `@` hovers over it.

Sample: the built-in demo at 18 s, while a DNS tunnel runs (real output of
`mdd --headless --fast --frames 144 --width 104 --height 30`):

```text
 MAXWELL'S DEMON DETECTOR | demo 00:18/1:00 DNS tunnel -> watch DNS | 349 ev/s 85.0KB/s | tick 125ms
                                                       ~~~~~~~~~~~~ ~~~~~~~~~~~ flow               349/s
            =                               =         ~~~~~~~~~~~~~~~~~~~~~~~~~ H 2.14 dep z    9.0
      ~~~~~ = ~~~~========  =  ==============~~~~~~~=~~~~~~~~~~~~~~~~~~~~~~~~~~ Hr 1.91  cv   -
      ~~~~~===~~~~========~==================~~~~~~~=~~~~~~~~~~~~~~~~~~~~~~~~~~ KL 0.22    85.0KB/s
      ~~~~~===~~~~========~==================~~~~~~~=~~~~~~~~~~~~~~~~~~~~~~~~~~
  ALL ~~~~~===~~~~========~==================~~~~~~~=~~~~~~~~~~~~~~~~~~~~~~~~~~
                                                                                idle                 2/s
  WEB _____;'______':'__::______'__:__________,__,____;_________:~__~_____~_~__ H 2.97 dep z    5.1
                               =            = =       =^^^^^^^^^^^@@@@@@@@@@@@@ ORDER @|           208/s
  DNS ==______=_=_=====_=______=_=_===_==__==_=__=___========================== H 1.28 dep z   55.6
                                                                         :      idle                 3/s
 MAIL __________________________________________________________________';:____ H 3.24 dep z   -0.7
                                               |                                ORDER |            100/s
MEDIA |||||||||||||||||||||||||||||||||||||||||=||||||||||||||||||||||||||||||| H 1.00 dep z  127.3
        ~~       ~    ~                  ~~  ~    ~   ~  ~~~    ~~       ~    ~ flow                14/s
 CTRL ~_~~~_~_~_~~__~_~~~~______~~_______~~~~~~__~~__~~~_~~~_~_~~~~_____~~~~~~~ H 1.85 dep z   22.2
         ~  ~  ~            ~       ~           ~  ~     ~     ~  ~   ~      ~~ flow                18/s
 BULK __~~__~_~~~~___~~_~~__~__~~___~~___~___~_~~__~_~_~~~__~~_~_~~_~~~~_~~~~~~ H 0.90 dep z   50.6
                                                                                noise                3/s
OTHER ___________.___..___.__________________.__.__._______.____;___:________'; H 3.11 dep z    0.1
      --------+-8s------------+-6s------------+-4s------------+-2s----------now
 _ idle  . sparse  :; noise  ~ flow  = order  # mono  | rhythm  ^ burst  ! shift  @ demon
 height = volume
 00:16 DNS   @ order appeared: entropy rate 1.26 -> 0.62 bits/sym (dep z 98.0)
 00:15 DNS   | rhythm locked: repeats every 10ms (cv 0.00)
 00:15 DNS   ^ burst: 24 events in one tick (typical ~0.7)
 00:00 MEDIA | rhythm locked: repeats every 20ms (cv 0.06)
```

## Quick start (Windows 11, PowerShell)

Ready-built programs for Windows, macOS and Linux are on the
[Releases page](https://github.com/whisprer-specops/maxwells-demon-detector/releases/latest);
the repository's top-level README says how to install them. To build it yourself:

1. Install Rust from <https://rustup.rs> (run `rustup-init.exe`; let it install the
   Visual Studio C++ Build Tools when it asks). The first build downloads Rust 1.97.0,
   which `rust-toolchain.toml` pins; the code keeps to Rust 1.87, the declared minimum.
2. Open PowerShell in this folder (`crate` in the repository).
3. Run the demo:

   ```powershell
   cargo run --release
   ```

Use **Windows Terminal** (the default on Windows 11) for colour and smooth updates.
The finished program is `.\target\release\mdd.exe`; every command below uses it.

Keys: `space` pause, `+` / `-` scroll faster / slower, `l` legend, `c` colour,
`q` / `Esc` / `Ctrl+C` quit. Resizing the window is handled live.

## Reading the landscape

```text
   time flows <-- from right to left (newest column on the right)

         @      marker   @ demon: order appeared     ! shift: the mix changed
         |      cap      | rhythm: metronomic timing ^ burst: volume spike
         =      body     # mono   = order   ~ flow   :;', noise   . sparse
         =
   DNS ______   ground   _ nothing happened in this lane this tick
```

**Height** = volume relative to that lane's own typical level (a typical tick stands
at about 70% of the band; twice typical fills it). Absolute rates are in the side panel.

| Glyph | Name   | Exact rule (per lane, over its last 256 observations) |
|-------|--------|--------------------------------------------------------|
| `_`   | idle   | no events in this tick |
| `.`   | sparse | fewer than 16 observations: not enough to judge |
| `:;',`| noise  | symbols mixed, no sequential structure (dependency z < 3) |
| `~`   | flow   | real but loose sequential structure (dependency z >= 3) |
| `=`   | order  | the previous symbol strongly predicts the next (z >= 5 and >= 25% of the entropy explained) |
| `#`   | mono   | one symbol is >= 80% of the window |
| `\|`  | rhythm | gaps between events are regular (robust cv <= 0.15 for 3 ticks), at lag 1, 2 or 3 |
| `^`   | burst  | volume far above this lane's own baseline (z >= 3.5) |
| `!`   | shift  | the symbol mix moved away from this lane's baseline (KL divergence) |
| `@`   | demon  | entropy rate fell well below this lane's normal range: order appeared |

Side panel, per lane: class, active flags, events/s, then
`H` entropy (bits per symbol, 0 to 4), `dep z` (how far real order beats shuffled
copies; above 5 is strong), `Hr` entropy rate (the unpredictable part left after
using the previous symbol), `cv` timing spread (0 = metronome, about 1 = random),
`KL` distance of the current mix from the lane's baseline, and bytes/s.

**Lanes.** Packet modes: `ALL` (overview) plus `WEB DNS MAIL MEDIA CTRL BULK OTHER`,
chosen by port and protocol; each packet's symbol is its size bin (8 bins) times its
direction (in/out). Bytes mode: `ALL` plus `ZERO CTRL TEXT HIGH FF` byte classes;
class lanes use the byte's low nibble, `ALL` uses the high nibble.

## The demo (60-second loop)

| Time    | What happens | Where to look |
|---------|--------------|---------------|
| always  | a voice call (RTP, 50 packets/s each way) | `MEDIA`: `=` with a `\|` fence and **no** `@`. Order that is normal is not a demon |
| 0-15 s  | background only (web, DNS, mail, SSH, pings, a sync client) | detectors learn each lane's normal ("learning" in the title) |
| 15-25 s | DNS tunnel: fixed-size query/response ping-pong, 100 pairs/s | `DNS`: `^` burst, `=` order, `@` demon |
| 30-42 s | C2 beacon: request/response every 400 ms | `OTHER`: `\|` rhythm locks after a few seconds |
| 48-54 s | exfiltration: flood of identical 1280-byte packets | `BULK`: `#` mono, `^` burst, `!` shift, `@` demon |

`--seed N` gives a different (but repeatable) run of the same script.

## Feeding it your own data

```powershell
# Raw bytes of any file (the original Maxwell's-demon question): where is there order?
.\target\release\mdd.exe --mode bytes --input examples\demon_sandwich.bin --loop
.\target\release\mdd.exe --mode bytes --input C:\Windows\explorer.exe --rate 16384

# A packet capture (.pcap or .pcapng from Wireshark, tcpdump or pktmon)
.\target\release\mdd.exe --mode pcap-file --input C:\temp\cap.pcapng --speed 4

# An event log (CSV or JSONL, schema below)
.\target\release\mdd.exe --mode replay --input examples\events.csv --loop

# Record what you watch, replay it later
.\target\release\mdd.exe --record C:\temp\session.jsonl
.\target\release\mdd.exe --mode replay --input C:\temp\session.jsonl
```

`examples\demon_sandwich.bin` is random data with order patches injected: zeros,
0xFF, 0xAA, heavily biased bits, sticky bits, then random again. Watch `ALL` turn
from noise to `#`, then `=`, then back to noise, with a `@` the moment order appears.

Live JSONL on stdin (Linux or WSL shown; one event per line):

```bash
tail -f events.jsonl | ./target/release/mdd --mode stdin-jsonl
cat /dev/urandom | ./target/release/mdd --mode bytes --input -
```

Headless (no TUI: prints frames as plain text, handy for logs, CI and screenshots):

```powershell
.\target\release\mdd.exe --headless --fast --frames 480 --width 120 --height 36
```

prints the frame at 60 s plus the full alert log. `--print-every 8` prints a frame
every second of stream time; `--fast` skips real-time waiting (demo and files only).

### Capturing on Windows with nothing installed (pktmon)

Picture first: `pktmon` is built into Windows 10/11. It writes an `.etl` log, which
it can convert to `.pcapng` for `mdd`. It needs an **Administrator** PowerShell.

1. Open PowerShell as Administrator (Start menu, type `PowerShell`, right-click, *Run as administrator*).
2. Make a folder for the capture:
   ```powershell
   New-Item -ItemType Directory -Force C:\temp
   ```
3. Start capturing at the network cards only (`--comp nics` avoids each packet being
   logged once per stack layer), keeping whole packets (`--pkt-size 0`):
   ```powershell
   pktmon start --capture --comp nics --pkt-size 0 --file-name C:\temp\cap.etl
   ```
4. Use the machine normally for a minute or two, then stop:
   ```powershell
   pktmon stop
   ```
5. Convert to pcapng:
   ```powershell
   pktmon etl2pcap C:\temp\cap.etl --out C:\temp\cap.pcapng
   ```
6. Watch it (a normal PowerShell window is fine for this step):
   ```powershell
   .\target\release\mdd.exe --mode pcap-file --input C:\temp\cap.pcapng --speed 2
   ```

## Live capture

Picture first: live capture watches one network card while traffic flows through it.
It is part of every copy of `mdd`, the ready-built downloads included. What it needs
depends on the system:

| System | Needs | Permission |
|--------|-------|------------|
| Windows | **Npcap**, the capture driver Wireshark installs | an Administrator terminal |
| macOS | nothing: libpcap comes with macOS | `sudo` |
| Linux | nothing: libpcap if it can be loaded, otherwise the built-in capture | `sudo`, or `setcap` once |

Commands below use `.\target\release\mdd.exe` (or `./target/release/mdd`), the program
you built. With a ready-built download, run `.\mdd.exe` (or `./mdd`) in the folder you
installed it to instead.

**Windows**

1. If Wireshark is installed, Npcap already is: go to step 2. Otherwise download the
   Npcap installer from <https://npcap.com/#download> and run it with its default options.
2. Open Windows Terminal as Administrator: right-click the Start button, then
   **Terminal (Admin)**, then **Yes**.
3. List the interfaces:
   ```powershell
   .\target\release\mdd.exe --mode list-interfaces
   ```
   The one marked `default` is used when you don't name one. Its first line says which
   Npcap version is in use.
4. Capture on the default interface, or name one by its number or part of its description:
   ```powershell
   .\target\release\mdd.exe --mode live-pcap
   .\target\release\mdd.exe --mode live-pcap --interface 3
   .\target\release\mdd.exe --mode live-pcap --interface wi-fi --filter "udp port 53"
   ```

If `mdd` says Npcap isn't installed, do step 1. If it says it has no permission, do
step 2 (or reinstall Npcap with "Restrict Npcap driver's access to Administrators only"
unticked, and any terminal will do). If the title ends with
`own traffic: promiscuous mode refused`, the network card (usually Wi-Fi) won't show
other machines' traffic, so `mdd` is watching this machine's own.

**Linux (Lubuntu / DragonOS)**

```bash
sudo ./target/release/mdd --mode list-interfaces
sudo ./target/release/mdd --mode live-pcap --interface eth0
# or allow capture once, then run it without sudo:
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/mdd
```

The first line of `--mode list-interfaces` says which capture is in use. A program built
here uses libpcap when it is installed (`sudo apt install libpcap0.8`), with libpcap's full
filter language. The ready-built Linux downloads are fully static, so they run on any
distribution but can't load libpcap; they use the built-in capture instead. Its
`--filter` understands the common forms, with libpcap's meaning:

```text
tcp  udp  icmp  icmp6  arp  ip  ip6
[tcp|udp] [src|dst] port N          [tcp|udp] [src|dst] portrange N-M
[src|dst] host ADDRESS              [src|dst] net ADDRESS/BITS
not ...   ... and ...   ... or ...   ( ... )      (also ! && ||)
```

Anything else is refused with that list, never silently read differently. As in
tcpdump, `and` and `or` have equal precedence and group left to right, so use brackets:
`udp or (tcp and port 80)`. `MDD_CAPTURE=builtin` or `MDD_CAPTURE=libpcap` in front of
the command picks a capture by hand.

**macOS**

```bash
sudo ./target/release/mdd --mode list-interfaces
sudo ./target/release/mdd --mode live-pcap --interface en0
```

Filters use libpcap's language everywhere except the built-in Linux capture:
`"udp port 53"`, `"tcp and not port 22"`, `"host 192.168.1.10"`, `"net 10.0.0.0/8"`.

## Logging alerts and metrics to CSV

Two optional logs turn a session into data you can graph. Both work in every mode
(live, files, demo, headless) and can run together.

```powershell
.\target\release\mdd.exe --mode live-pcap --interface 3 --alert-log C:\temp\alerts.csv --metrics-log C:\temp\metrics.csv
```

**`--alert-log FILE`** writes one row per alert, the tick it fires. Every alert is
kept, even after it scrolls off the screen.

```text
time_utc,t_s,tick,lane,kind,glyph,events,entropy,entropy_rate,dep_z,kl,message
2026-10-17T09:14:03.125Z,16.500,132,DNS,demon,@,26,1.177,0.353,97.96,1.896,@ order appeared: ...
```

**`--metrics-log FILE`** writes one row per lane per tick: every lane's numbers as a
continuous time series, including the build-up before an alert. At the default
125 ms tick that is 8 rows per lane per second, roughly 20 MB an hour for the 8
packet lanes. A slower tick (`--tick-ms 1000`) cuts that to about 3 MB.

| Column | Meaning |
|--------|---------|
| `time_utc` | wall-clock time the tick closed (ISO 8601, UTC, milliseconds) |
| `t_s`, `tick` | session clock in seconds, and the tick number |
| `lane` | `ALL WEB DNS MAIL MEDIA CTRL BULK OTHER`, or the bytes lanes |
| `events`, `bytes` | volume this tick |
| `height` | column height drawn, 0 to 1 |
| `texture` | `idle sparse noise flow order mono` |
| `entropy` | how mixed the lane's symbols are, in bits (0 to 4) |
| `top_share` | share of the most common symbol |
| `dep_z` | order score: lag-1 dependency against shuffled copies (5 or more is strong) |
| `rho` | share of the uncertainty the previous symbol removes |
| `entropy_rate` | entropy left once order is accounted for; the demon detector watches it fall |
| `kl` | how far the mix is from this lane's baseline, in bits (last computed) |
| `rhythm_ms`, `rhythm_cv` | repeat period and its spread, when timing is regular enough to measure |
| `rhythm`, `burst`, `shift`, `demon` | detector flags, 1 when on |
| `learning` | 1 while detectors are still learning what normal looks like |

A lane with no events in a tick gets blank statistics: there was nothing to measure.
Rows are flushed every tick, so Ctrl+C or a crash loses at most the tick in progress.
If a write fails (disk full, say), that log stops, the title shows `LOG FAILED`, and
the session carries on. A log file is never allowed to be the input file or another
output file. With `--headless --fast`, use `t_s` rather than `time_utc`: the session
clock runs far ahead of the wall clock.

## Event file formats (replay and stdin)

CSV with a header row, or JSONL with one object per line, same field names. Only
`len` is required.

```text
ts_ms,len,proto,src,dst,sport,dport,dir
0,92,dns,10.0.0.2,1.1.1.1,53111,53,out
{"ts_ms":25,"len":120,"proto":"tls","sport":51514,"dport":443,"dir":"out"}
```

`ts_us` (microseconds) may be used instead of `ts_ms`. Rows without a timestamp are
spaced 10 ms apart. `dir` is `in`, `out` or `local`. Malformed rows are counted
(`bad N` in the title) and skipped, never fatal. `--record` writes this same format.

## How it works

```text
 source --> symbolise --> per-lane window --> stats + detectors --> column --> frame --> screen
 (demo,     (lane +       (last 256 obs,      (every tick)          (height,   (layout)  (diff +
  files,     symbol 0-15)  30 s max age)                             texture,             synced
  pcap, live)                                                        cap, mark)           update)
```

Every tick (125 ms by default), each lane asks:

* **How mixed?** Shannon entropy, Miller-Madow bias-corrected.
* **Ordered?** Lag-1 mutual information compared against 16 shuffled copies of the
  same window. Shuffling keeps the mix but destroys order, so this measures order
  and nothing else, and stays honest on small samples where plain MI is badly biased.
* **Rhythmic?** Robust spread (MAD / median) of the gaps between events at lags 1-3.
  A beat must also be slower than the stream's own event spacing, cover most of the
  elapsed time, and hold for 3 ticks, which rules out runs, bursts and flukes.
* **Changed?** Exponentially weighted baselines per lane. Demon = CUSUM on drops of
  the entropy rate beyond max(min(0.5 bit, half the baseline), 3 standard deviations).
  Shift = KL divergence from the baseline mix, with a trigger that adapts to how much
  that lane normally wanders. Burst = z-score of log volume.

Detectors learn each lane's normal first: 8 seconds of history, or 32 windows' worth
of data for fast lanes such as raw bytes. The title shows `learning` meanwhile.

## Honest limits

* Every judgement is relative to the lane's own recent past. `@` means "more ordered
  than this lane has been", not "malicious". If new order persists it becomes the
  new normal and stops being flagged after 10-15 s.
* Packets are judged by size, direction and timing only. Payloads are never read,
  so encrypted traffic is handled exactly like plaintext.
* Lanes are by port and protocol. A beacon hidden inside a busy lane (say, WEB)
  shares that lane's statistics and can be masked; isolate it with `--filter` (live)
  or by filtering the capture first.
* In capture files, "us" (for in/out) means private addresses (10.x, 192.168.x, ...).
  Live capture uses the interface's own addresses.
* 65 tests, clippy clean. Every release is built and fully checked on Windows, Linux
  and macOS by GitHub Actions before it is published. The crate's own system-specific
  code is the Npcap and libpcap loader (`src/capture/libpcap.rs`) and the built-in Linux
  capture (`src/capture/linux.rs`). Live capture itself is tested on Linux, with both
  captures; GitHub's Windows machines have no Npcap, so there the tests check the
  "Npcap missing" path, and live capture on Windows is checked by hand.

## Development

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1   # every check below, a release build and the demo
cargo test                                   # 56 unit, 7 end-to-end and 2 copyright-notice tests
cargo clippy --all-targets -- -D warnings
```

| File | Role |
|------|------|
| `src/source/*` | demo script, CSV/JSONL replay, stdin, raw bytes, pcap files, live capture |
| `src/capture/*` | Npcap / libpcap loaded at run time, the built-in Linux capture and its filter (the only unsafe code) |
| `src/pcapfile.rs`, `src/decode.rs` | pure-Rust pcap/pcapng reader and packet decoder (no libpcap needed) |
| `src/event.rs` | lanes and symbols |
| `src/analysis.rs` | statistics, classification, detectors |
| `src/app.rs` | scrolling history, heights, alerts |
| `src/render.rs`, `src/screen.rs` | layout and glyphs; flicker-free diff presenter |
| `src/logs.rs` | optional CSV logs: alerts as they fire, lane metrics every tick |
| `src/run.rs` | TUI loop (keys, pause, resize, terminal restore) and headless mode |
| `tests/landscape.rs` | end-to-end checks that the right glyphs land in the right lanes |
| `tests/notice_contracts.rs` | every code file opens with the copyright and SPDX lines |
| `scripts/check.ps1`, `scripts/check.sh` | every check, in order: formatting, tests, strict lints, release build, headless demo |

On Linux or macOS, `bash scripts/check.sh` runs the same checks as `check.ps1`. Every code
file opens with `Copyright (C) 2026 whispr.dev` and `SPDX-License-Identifier: GPL-3.0-only`
as comments, and a test enforces it.
