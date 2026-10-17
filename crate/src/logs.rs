// Copyright (C) 2026 whispr.dev
// SPDX-License-Identifier: GPL-3.0-only

//! Optional CSV logs, written as the session runs.
//!
//! * `--alert-log FILE`: one row per alert (`@ ! ^ |`), the tick it fires, with the
//!   lane's numbers at that moment.
//! * `--metrics-log FILE`: one row per lane per tick, so every lane's statistics
//!   become a time series you can plot.
//!
//! Both files are flushed at the end of every tick in which they were written, so a
//! crash or Ctrl+C loses at most the tick in progress. If a write fails, that log
//! stops, the error is shown on screen, and the session carries on.

use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::analysis::{AlertKind, Body, LaneState};
use crate::app::App;

/// Columns of the alert log.
pub const ALERT_HEADER: [&str; 12] = [
    "time_utc",
    "t_s",
    "tick",
    "lane",
    "kind",
    "glyph",
    "events",
    "entropy",
    "entropy_rate",
    "dep_z",
    "kl",
    "message",
];

/// Columns of the metrics log.
pub const METRICS_HEADER: [&str; 21] = [
    "time_utc",
    "t_s",
    "tick",
    "lane",
    "events",
    "bytes",
    "height",
    "texture",
    "entropy",
    "top_share",
    "dep_z",
    "rho",
    "entropy_rate",
    "kl",
    "rhythm_ms",
    "rhythm_cv",
    "rhythm",
    "burst",
    "shift",
    "demon",
    "learning",
];

/// Name and glyph written for each alert kind.
pub fn kind_label(kind: AlertKind) -> (&'static str, &'static str) {
    match kind {
        AlertKind::Demon => ("demon", "@"),
        AlertKind::Shift => ("shift", "!"),
        AlertKind::Burst => ("burst", "^"),
        AlertKind::Pulse => ("rhythm", "|"),
    }
}

/// Lower-case texture name for a body class.
fn texture(body: Body) -> &'static str {
    match body {
        Body::Void => "idle",
        Body::Sparse => "sparse",
        Body::Noise => "noise",
        Body::Flow => "flow",
        Body::Order => "order",
        Body::Mono => "mono",
    }
}

/// Wall-clock time as ISO 8601 UTC with milliseconds, e.g. `2026-10-17T09:14:03.125Z`.
pub fn utc_iso(t: SystemTime) -> String {
    let ms = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let secs = (ms / 1_000) as i64;
    let milli = (ms % 1_000) as u32;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milli:03}Z",
        sod / 3_600,
        (sod % 3_600) / 60,
        sod % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian calendar.
/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn flag(b: bool) -> String {
    if b { "1" } else { "0" }.to_string()
}

/// One CSV log file plus its name (for error messages).
struct CsvLog {
    out: csv::Writer<File>,
    name: &'static str,
}

impl CsvLog {
    fn create(path: &Path, header: &[&str], name: &'static str) -> Result<Self, String> {
        let mut out = csv::Writer::from_path(path)
            .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        out.write_record(header)
            .and_then(|()| out.flush().map_err(csv::Error::from))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Ok(Self { out, name })
    }
}

/// The alert and metrics logs for one session.
#[derive(Default)]
pub struct Logs {
    alerts: Option<CsvLog>,
    metrics: Option<CsvLog>,
    /// Set when a log stopped because a write failed (shown on screen).
    pub error: Option<String>,
}

impl Logs {
    /// Open the logs that were asked for. Each file is created (or emptied) and
    /// gets its header row straight away.
    pub fn create(alert_path: Option<&Path>, metrics_path: Option<&Path>) -> Result<Self, String> {
        let alerts = alert_path
            .map(|p| CsvLog::create(p, &ALERT_HEADER, "alert log"))
            .transpose()?;
        let metrics = metrics_path
            .map(|p| CsvLog::create(p, &METRICS_HEADER, "metrics log"))
            .transpose()?;
        Ok(Self {
            alerts,
            metrics,
            error: None,
        })
    }

    /// True while at least one log is being written.
    pub fn active(&self) -> bool {
        self.alerts.is_some() || self.metrics.is_some()
    }

    /// Write this tick's rows. Call right after [`App::finish_tick`].
    /// `t` is the session clock in seconds, as passed to `finish_tick`.
    pub fn tick(&mut self, app: &App, t: f64) {
        if !self.active() {
            return;
        }
        let now = utc_iso(SystemTime::now());
        let t_s = format!("{t:.3}");
        let tick = app.ticks.to_string();

        let alert_rows: Vec<Vec<String>> = app
            .new_alerts
            .iter()
            .filter_map(|a| {
                let lane = app.lanes.iter().find(|l| l.spec.name == a.lane)?;
                let (kind, glyph) = kind_label(a.kind);
                let m = &lane.metrics;
                Some(vec![
                    now.clone(),
                    t_s.clone(),
                    tick.clone(),
                    a.lane.to_string(),
                    kind.to_string(),
                    glyph.to_string(),
                    lane.last_n.to_string(),
                    format!("{:.3}", m.h),
                    format!("{:.3}", m.h_rate),
                    format!("{:.2}", m.dep.z),
                    format!("{:.3}", lane.kl_excess),
                    a.msg.clone(),
                ])
            })
            .collect();
        if !alert_rows.is_empty() {
            Self::write(&mut self.alerts, &mut self.error, &alert_rows);
        }

        if self.metrics.is_some() {
            let learning = flag(app.warming_up());
            let rows: Vec<Vec<String>> = app
                .lanes
                .iter()
                .zip(app.history.iter())
                .map(|(lane, hist)| {
                    let (height, body) =
                        hist.back().map_or((0.0, Body::Void), |c| (c.level, c.body));
                    metrics_row(&now, &t_s, &tick, lane, f64::from(height), body, &learning)
                })
                .collect();
            Self::write(&mut self.metrics, &mut self.error, &rows);
        }
    }

    fn write(log: &mut Option<CsvLog>, error: &mut Option<String>, rows: &[Vec<String>]) {
        let Some(l) = log.as_mut() else {
            return;
        };
        let result = rows
            .iter()
            .try_for_each(|r| l.out.write_record(r))
            .and_then(|()| l.out.flush().map_err(csv::Error::from));
        if let Err(e) = result {
            let msg = format!("{} stopped: {e}", l.name);
            *error = Some(match error.take() {
                Some(prev) => format!("{prev}; {msg}"),
                None => msg,
            });
            *log = None;
        }
    }

    /// Flush both logs (also happens on drop).
    pub fn flush(&mut self) -> std::io::Result<()> {
        for l in [self.alerts.as_mut(), self.metrics.as_mut()]
            .into_iter()
            .flatten()
        {
            l.out.flush()?;
        }
        Ok(())
    }
}

/// One metrics row. Statistics are left blank for a lane that had no events this
/// tick, because there is nothing new to measure.
fn metrics_row(
    now: &str,
    t_s: &str,
    tick: &str,
    lane: &LaneState,
    height: f64,
    body: Body,
    learning: &str,
) -> Vec<String> {
    let active = lane.last_n > 0;
    let m = &lane.metrics;
    let stat = |s: String| if active { s } else { String::new() };
    let (rhythm_ms, rhythm_cv) = match (active, m.rhythm) {
        (true, Some(r)) => (
            format!("{:.1}", r.period_us / 1_000.0),
            format!("{:.3}", r.cv),
        ),
        _ => (String::new(), String::new()),
    };
    vec![
        now.to_string(),
        t_s.to_string(),
        tick.to_string(),
        lane.spec.name.to_string(),
        lane.last_n.to_string(),
        lane.last_bytes.to_string(),
        format!("{height:.3}"),
        texture(body).to_string(),
        stat(format!("{:.3}", m.h)),
        stat(format!("{:.3}", m.top_share)),
        stat(format!("{:.2}", m.dep.z)),
        stat(format!("{:.3}", m.rho)),
        stat(format!("{:.3}", m.h_rate)),
        stat(format!("{:.3}", lane.kl_excess)),
        rhythm_ms,
        rhythm_cv,
        flag(lane.pulse),
        flag(lane.burst),
        flag(lane.shift),
        flag(lane.demon),
        learning.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64, ms: u64) -> String {
        utc_iso(UNIX_EPOCH + Duration::from_millis(secs * 1_000 + ms))
    }

    #[test]
    fn utc_timestamps() {
        assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(1_700_000_000, 125), "2023-11-14T22:13:20.125Z");
        assert_eq!(at(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
        assert_eq!(at(951_782_400, 999), "2000-02-29T00:00:00.999Z");
        assert_eq!(at(4_102_444_799, 1), "2099-12-31T23:59:59.001Z");
    }

    #[test]
    fn headers_match_rows() {
        let app = App::new(crate::event::LaneSet::Packets, 64, 10);
        let row = metrics_row("t", "0.000", "0", &app.lanes[0], 0.0, Body::Void, "1");
        assert_eq!(row.len(), METRICS_HEADER.len());
        // An idle lane has no statistics to report.
        assert_eq!(row[8], "");
        assert_eq!(row[7], "idle");
    }
}
