// Copyright (C) 2026 whispr.dev
// SPDX-License-Identifier: GPL-3.0-only

//! End-to-end checks: run the real headless pipeline and verify the landscape
//! puts the right glyphs in the right lanes.
//!
//! Glyphs are read from each lane's band coordinates (via `render::layout`), not
//! from the whole output: the legend row contains every glyph and would make a
//! naive "does the output contain '@'?" check pass trivially.

use std::path::{Path, PathBuf};

use clap::Parser;
use maxwells_demon_detector::render::layout;
use maxwells_demon_detector::{run_headless, Cli};

fn headless(args: &[&str]) -> String {
    let mut argv = vec!["mdd", "--headless", "--fast"];
    argv.extend_from_slice(args);
    let cli = Cli::try_parse_from(argv).expect("valid arguments");
    let mut out = Vec::new();
    run_headless(&cli, &mut out).expect("headless run succeeds");
    String::from_utf8(out).expect("output is UTF-8")
}

/// Split `--print-every` output into frames of `h` lines (after each `--- tick` header).
fn frames(out: &str, h: usize) -> Vec<Vec<String>> {
    let lines: Vec<&str> = out.lines().collect();
    let mut v = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].starts_with("--- tick ") {
            v.push(
                lines
                    .iter()
                    .skip(i + 1)
                    .take(h)
                    .map(|s| s.to_string())
                    .collect(),
            );
            i += h + 1;
        } else {
            i += 1;
        }
    }
    v
}

/// Every character drawn inside one lane's landscape band, across all frames.
fn band_glyphs(frames: &[Vec<String>], w: u16, h: u16, lanes: usize, lane: usize) -> String {
    let lay = layout(w, h, lanes, true).expect("layout fits");
    let (top, bh) = lay.bands[lane];
    let mut s = String::new();
    for frame in frames {
        for y in top..top + bh {
            if let Some(row) = frame.get(usize::from(y)) {
                let bytes = row.as_bytes();
                for x in lay.land_x..lay.land_x + lay.land_w {
                    if let Some(&b) = bytes.get(usize::from(x)) {
                        s.push(b as char);
                    }
                }
            }
        }
    }
    s
}

/// (lane, glyph) pairs from the alert log printed after the final frame.
fn alert_log(out: &str) -> Vec<(String, String)> {
    out.lines()
        .skip_while(|l| !l.starts_with("alerts (newest first):"))
        .skip(1)
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let _time = parts.next()?;
            let lane = parts.next()?.to_string();
            let glyph = parts.next()?.to_string();
            Some((lane, glyph))
        })
        .collect()
}

fn has_alert(log: &[(String, String)], lane: &str, glyph: &str) -> bool {
    log.iter().any(|(l, g)| l == lane && g == glyph)
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mdd-it-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

// Packet lanes: ALL WEB DNS MAIL MEDIA CTRL BULK OTHER
const ALL: usize = 0;
const WEB: usize = 1;
const DNS: usize = 2;
const MEDIA: usize = 4;
const BULK: usize = 6;
const OTHER: usize = 7;

#[test]
fn demo_minute_tells_the_scripted_story() {
    let (w, h) = (140u16, 40u16);
    let out = headless(&[
        "--frames",
        "480",
        "--print-every",
        "8",
        "--width",
        "140",
        "--height",
        "40",
    ]);
    assert!(out.is_ascii(), "frames must be pure ASCII");
    let fr = frames(&out, usize::from(h));
    assert_eq!(fr.len(), 60, "one frame per simulated second");
    let lane = |i| band_glyphs(&fr, w, h, 8, i);

    let dns = lane(DNS);
    assert!(dns.contains('='), "DNS tunnel should show ORDER texture");
    assert!(
        dns.contains('@'),
        "DNS tunnel should raise the demon marker"
    );
    assert!(dns.contains('^'), "DNS tunnel onset is a volume burst");
    let media = lane(MEDIA);
    assert!(
        media.contains('=') && media.contains('|'),
        "voice call: ordered and rhythmic"
    );
    assert!(!media.contains('@'), "the voice call is normal: no demon");
    assert!(lane(OTHER).contains('|'), "C2 beacon should lock a rhythm");
    let bulk = lane(BULK);
    assert!(bulk.contains('#'), "exfil flood should be MONO");
    assert!(
        bulk.contains('@') || bulk.contains('!'),
        "exfil should be flagged"
    );
    let web = lane(WEB);
    assert!(
        web.contains(':') || web.contains(';'),
        "web traffic reads as noise"
    );
    assert!(lane(ALL).contains('~'), "the overview carries flow texture");

    let log = alert_log(&out);
    assert!(has_alert(&log, "DNS", "@"), "demon alert on DNS: {log:?}");
    assert!(
        has_alert(&log, "OTHER", "|"),
        "rhythm alert on OTHER: {log:?}"
    );
    assert!(has_alert(&log, "BULK", "^"), "burst alert on BULK: {log:?}");
    assert!(has_alert(&log, "BULK", "!"), "shift alert on BULK: {log:?}");
    assert!(
        !has_alert(&log, "MEDIA", "@"),
        "no demon on the voice call: {log:?}"
    );
}

#[test]
fn bytes_mode_finds_the_order_patches_in_the_sandwich() {
    // Bytes lanes: ALL ZERO CTRL TEXT HIGH FF
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/demon_sandwich.bin");
    let (w, h) = (120u16, 30u16);
    let out = headless(&[
        "--mode",
        "bytes",
        "--input",
        path,
        "--print-every",
        "4",
        "--width",
        "120",
        "--height",
        "30",
    ]);
    let fr = frames(&out, usize::from(h));
    assert!(fr.len() >= 25, "~14 s of data at 4096 B/s");
    let lane = |i| band_glyphs(&fr, w, h, 6, i);
    assert!(lane(1).contains('#'), "zero patch -> MONO in ZERO lane");
    assert!(lane(5).contains('#'), "0xFF patch -> MONO in FF lane");
    assert!(lane(4).contains('#'), "0xAA patch -> MONO in HIGH lane");
    assert!(
        lane(3).contains(':') || lane(3).contains(';'),
        "random bytes -> TEXT noise"
    );
    let log = alert_log(&out);
    assert!(
        has_alert(&log, "ALL", "@"),
        "order appearing in random data is a demon: {log:?}"
    );
    assert!(out.contains("end of file"), "runs to the end of the input");
}

/// Minimal classic pcap (little-endian, microseconds, Ethernet) of a TLS-ish
/// conversation: small request out, large response in, 10 ms apart.
fn write_pcap(path: &Path, n: usize) {
    let mut v = Vec::new();
    v.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&0i32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&65_535u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    for i in 0..n {
        let out = i % 2 == 0;
        let payload = if out { 40 } else { 1_200 };
        let (src, dst, sport, dport): ([u8; 4], [u8; 4], u16, u16) = if out {
            ([192, 168, 1, 10], [93, 184, 216, 34], 50_000, 443)
        } else {
            ([93, 184, 216, 34], [192, 168, 1, 10], 443, 50_000)
        };
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0];
        ip[2..4].copy_from_slice(&((40 + payload) as u16).to_be_bytes());
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        f.extend_from_slice(&ip);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[12] = 5 << 4;
        f.extend_from_slice(&tcp);
        f.resize(f.len() + payload, 0);
        let ts = 1_000_000u64 + i as u64 * 10_000;
        v.extend_from_slice(&((ts / 1_000_000) as u32).to_le_bytes());
        v.extend_from_slice(&((ts % 1_000_000) as u32).to_le_bytes());
        v.extend_from_slice(&(f.len() as u32).to_le_bytes());
        v.extend_from_slice(&(f.len() as u32).to_le_bytes());
        v.extend_from_slice(&f);
    }
    std::fs::write(path, v).expect("write pcap");
}

#[test]
fn pcap_file_is_decoded_into_the_web_lane() {
    let dir = temp_dir("pcap");
    let pcap = dir.join("conv.pcap");
    write_pcap(&pcap, 400);
    let (w, h) = (120u16, 36u16);
    let out = headless(&[
        "--mode",
        "pcap-file",
        "--input",
        pcap.to_str().expect("utf-8 temp path"),
        "--print-every",
        "4",
    ]);
    let fr = frames(&out, usize::from(h));
    let web = band_glyphs(&fr, w, h, 8, WEB);
    assert!(
        web.contains('='),
        "request/response ping-pong is ORDER: {web:?}"
    );
    assert!(out.contains("pcap conv.pcap"), "title names the capture");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn record_then_replay_round_trip() {
    let dir = temp_dir("rec");
    let rec = dir.join("session.jsonl");
    let rec_s = rec.to_str().expect("utf-8 temp path");
    headless(&["--frames", "40", "--record", rec_s]);
    let text = std::fs::read_to_string(&rec).expect("recording exists");
    assert!(
        text.lines().count() > 500,
        "5 s of demo is hundreds of packets"
    );

    let (w, h) = (120u16, 36u16);
    let out = headless(&["--mode", "replay", "--input", rec_s, "--print-every", "4"]);
    let fr = frames(&out, usize::from(h));
    assert!(
        band_glyphs(&fr, w, h, 8, MEDIA).contains('='),
        "replayed voice call is ORDER"
    );
    assert!(out.contains("end of file"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn helpful_errors() {
    let run = |args: &[&str]| {
        let mut argv = vec!["mdd", "--headless", "--fast"];
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).expect("valid arguments");
        run_headless(&cli, &mut Vec::new()).map_err(|e| e.to_string())
    };
    let e = run(&["--mode", "bytes"]).unwrap_err();
    assert!(e.contains("--input is required"), "{e}");
    let e = run(&[]).unwrap_err();
    assert!(e.contains("--frames"), "demo never ends: {e}");
    let e = run(&["--mode", "pcap-file", "--input", "definitely-missing.pcap"]).unwrap_err();
    assert!(e.contains("cannot open"), "{e}");
}

fn read_csv(path: &Path) -> (Vec<String>, Vec<Vec<String>>) {
    let mut r = csv::Reader::from_path(path).expect("log file exists");
    let header = r
        .headers()
        .expect("header row")
        .iter()
        .map(String::from)
        .collect();
    let rows = r
        .records()
        .map(|rec| rec.expect("valid row").iter().map(String::from).collect())
        .collect();
    (header, rows)
}

#[test]
fn alert_and_metrics_logs_capture_the_demo() {
    let dir = temp_dir("logs");
    let alerts = dir.join("alerts.csv");
    let metrics = dir.join("metrics.csv");
    let out = headless(&[
        "--frames",
        "480",
        "--alert-log",
        alerts.to_str().expect("utf-8 temp path"),
        "--metrics-log",
        metrics.to_str().expect("utf-8 temp path"),
    ]);

    // Alert log: one row per alert, in time order, with the lane's numbers.
    let (header, rows) = read_csv(&alerts);
    assert_eq!(header, maxwells_demon_detector::logs::ALERT_HEADER);
    assert!(!rows.is_empty(), "the demo raises alerts");
    let col = |name: &str| header.iter().position(|h| h == name).expect("column");
    let (t, lane, kind, glyph, msg) = (
        col("t_s"),
        col("lane"),
        col("kind"),
        col("glyph"),
        col("message"),
    );
    assert!(rows.iter().all(|r| r.len() == header.len()));
    assert!(rows.iter().all(|r| r[col("time_utc")].ends_with('Z')));
    let times: Vec<f64> = rows.iter().map(|r| r[t].parse().expect("t_s")).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]), "rows in time order");
    assert!(rows
        .iter()
        .any(|r| r[lane] == "DNS" && r[kind] == "demon" && r[glyph] == "@"));
    for r in &rows {
        assert!(
            r[msg].starts_with(&r[glyph]),
            "glyph matches message: {r:?}"
        );
    }
    // Everything in the on-screen alert list is in the log too.
    for (l, g) in alert_log(&out) {
        assert!(
            rows.iter().any(|r| r[lane] == l && r[glyph] == g),
            "{l} {g} missing from the alert log"
        );
    }

    // Metrics log: one row per lane per tick, lanes in screen order.
    let (header, rows) = read_csv(&metrics);
    assert_eq!(header, maxwells_demon_detector::logs::METRICS_HEADER);
    assert_eq!(rows.len(), 480 * 8, "8 packet lanes x 480 ticks");
    let col = |name: &str| header.iter().position(|h| h == name).expect("column");
    let names = [
        "ALL", "WEB", "DNS", "MAIL", "MEDIA", "CTRL", "BULK", "OTHER",
    ];
    for (i, r) in rows.iter().enumerate() {
        assert_eq!(r[col("lane")], names[i % 8]);
        assert_eq!(r[col("tick")], (i / 8 + 1).to_string());
        if r[col("events")] == "0" {
            assert_eq!(r[col("texture")], "idle");
            assert_eq!(r[col("entropy")], "", "idle lanes have no statistics");
        }
    }
    let dns = col("lane");
    assert!(rows
        .iter()
        .any(|r| r[dns] == "DNS" && r[col("demon")] == "1"));
    assert_eq!(rows[0][col("learning")], "1");
    assert_eq!(rows[rows.len() - 1][col("learning")], "0");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn logs_refuse_to_overwrite_inputs_or_each_other() {
    let dir = temp_dir("clash");
    let input = dir.join("events.csv");
    std::fs::write(&input, "len\n100\n").expect("write input");
    let input_s = input.to_str().expect("utf-8 temp path");
    let run = |args: &[&str]| {
        let mut argv = vec!["mdd", "--headless", "--fast"];
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).expect("valid arguments");
        run_headless(&cli, &mut Vec::new()).map_err(|e| e.to_string())
    };
    let e = run(&[
        "--mode",
        "replay",
        "--input",
        input_s,
        "--alert-log",
        input_s,
    ])
    .unwrap_err();
    assert!(e.contains("is the input file"), "{e}");
    assert_eq!(
        std::fs::read_to_string(&input).expect("input intact"),
        "len\n100\n"
    );
    let same = dir.join("log.csv");
    let same_s = same.to_str().expect("utf-8 temp path");
    let e = run(&[
        "--frames",
        "8",
        "--alert-log",
        same_s,
        "--metrics-log",
        same_s,
    ])
    .unwrap_err();
    assert!(e.contains("give each its own file"), "{e}");
    std::fs::remove_dir_all(&dir).ok();
}
