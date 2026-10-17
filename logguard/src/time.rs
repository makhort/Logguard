//! Timestamps are microseconds since the Unix epoch (UTC), matching
//! journald's `__REALTIME_TIMESTAMP`. Small civil-date helpers avoid a
//! date-library dependency.

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub type Micros = i64;
pub const SEC: Micros = 1_000_000;
pub const MIN: Micros = 60 * SEC;

pub fn now() -> Micros {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_micros() as Micros)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn to_micros(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32, frac_us: i64) -> Option<Micros> {
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    let secs = days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(s);
    Some(secs * SEC + frac_us)
}

fn num(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Parses `HH:MM:SS[.fff]` into (h, m, s, micros).
fn parse_clock(s: &str) -> Option<(u32, u32, u32, i64)> {
    let (hms, frac) = s.split_once('.').unwrap_or((s, ""));
    let mut it = hms.split(':');
    let h = num(it.next()?)?;
    let m = num(it.next()?)?;
    let sec = num(it.next()?)?;
    if it.next().is_some() {
        return None;
    }
    let frac_us = if frac.is_empty() {
        0
    } else {
        let digits: String = frac.chars().take(6).collect();
        let v: i64 = digits.parse().ok()?;
        v * 10_i64.pow(6 - digits.len() as u32)
    };
    Some((h, m, sec, frac_us))
}

/// Parses `YYYY-MM-DD HH:MM:SS[.fff]` or the `T`-separated variant at the start of `s`.
/// Returns the timestamp and the number of bytes consumed. Any timezone suffix is ignored
/// (see `parse_iso_offset`). The daemon takes journal records' time from journald itself
/// (always UTC); local-time stamps (ejabberd's, syslog's) only matter in `replay` of text
/// logs, where both are in the same zone.
pub fn parse_iso_prefix(s: &str) -> Option<(Micros, usize)> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b' ' || b[10] == b'T') {
        return None;
    }
    let y = num(&s[0..4])?;
    let mo = num(&s[5..7])?;
    let d = num(&s[8..10])?;
    let end = s[11..].find(|c: char| !(c.is_ascii_digit() || c == ':' || c == '.')).map_or(s.len(), |i| i + 11);
    let (h, mi, sec, frac) = parse_clock(&s[11..end])?;
    Some((to_micros(i64::from(y), mo, d, h, mi, sec, frac)?, end))
}

/// Like `parse_iso_prefix`, but applies a `Z`, `+03:00`, `-0500` suffix: the result is UTC.
pub fn parse_iso_offset(s: &str) -> Option<Micros> {
    let (t, used) = parse_iso_prefix(s)?;
    let rest = &s[used..];
    let sign = match rest.as_bytes().first() {
        Some(b'+') => 1,
        Some(b'-') => -1,
        _ => return Some(t), // `Z` or no zone
    };
    let digits: String = rest[1..].chars().take_while(|c| c.is_ascii_digit() || *c == ':').filter(|c| *c != ':').collect();
    if digits.len() != 4 {
        return Some(t);
    }
    let (h, m): (i64, i64) = (digits[..2].parse().ok()?, digits[2..].parse().ok()?);
    Some(t - sign * (h * 3600 + m * 60) * SEC)
}

pub fn month_from_abbr(s: &str) -> Option<u32> {
    const M: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    M.iter().position(|m| *m == s).map(|i| i as u32 + 1)
}

/// Parses classic syslog `Mon DD HH:MM:SS` given the year.
pub fn parse_syslog(month: &str, day: &str, clock: &str, year: i64) -> Option<Micros> {
    let mo = month_from_abbr(month)?;
    let d = num(day)?;
    let (h, mi, s, frac) = parse_clock(clock)?;
    to_micros(year, mo, d, h, mi, s, frac)
}

pub fn year_of(ts: Micros) -> i64 {
    civil_from_days(ts.div_euclid(86_400 * SEC)).0
}

pub fn fmt_ts(ts: Micros) -> String {
    let secs = ts.div_euclid(SEC);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn fmt_duration(us: Micros) -> String {
    let s = us.max(0) / SEC;
    match s {
        s if s >= 86_400 => format!("{}d{:02}h", s / 86_400, s % 86_400 / 3600),
        s if s >= 3600 => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
        s if s >= 60 => format!("{}m{:02}s", s / 60, s % 60),
        s => format!("{s}s"),
    }
}

/// A configuration duration written as `90s`, `10m`, `12h`, `7d` or plain seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dur(pub u64);

impl Dur {
    pub fn micros(self) -> Micros {
        self.0 as Micros * SEC
    }
}

impl FromStr for Dur {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (n, unit) = s.split_at(split);
        let n: u64 = n.parse().map_err(|_| format!("invalid duration '{s}'"))?;
        let mult = match unit.trim() {
            "" | "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            "w" => 7 * 86_400,
            other => return Err(format!("unknown duration unit '{other}' in '{s}'")),
        };
        // 100 years is plenty, and keeps every `now + duration` in range.
        n.checked_mul(mult).filter(|secs| *secs <= 100 * 365 * 86_400).map(Dur).ok_or_else(|| format!("duration '{s}' is too long"))
    }
}

impl fmt::Display for Dur {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        match s {
            0 => write!(f, "0s"),
            s if s % 86_400 == 0 => write!(f, "{}d", s / 86_400),
            s if s % 3600 == 0 => write!(f, "{}h", s / 3600),
            s if s % 60 == 0 => write!(f, "{}m", s / 60),
            s => write!(f, "{s}s"),
        }
    }
}

impl Serialize for Dur {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Dur {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u64),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(n) => Ok(Dur(n)),
            Raw::S(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_offsets_become_utc() {
        let utc = parse_iso_offset("2026-10-12T15:17:50Z").unwrap();
        assert_eq!(fmt_ts(utc), "2026-10-12 15:17:50");
        assert_eq!(parse_iso_offset("2026-10-12T18:17:50+03:00\",\"remoteAddr\""), Some(utc));
        assert_eq!(parse_iso_offset("2026-10-12T10:17:50-0500"), Some(utc));
        assert_eq!(parse_iso_offset("2026-10-12T15:17:50+00:00"), Some(utc));
        assert_eq!(parse_iso_offset("2026-10-12 15:17:50"), Some(utc));
    }

    #[test]
    fn civil_roundtrip() {
        for days in [-1000, 0, 1, 19_000, 20_681, 30_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn iso_and_syslog_agree() {
        let (iso, used) = parse_iso_prefix("2026-08-16 21:20:19.107 [info] x").unwrap();
        assert_eq!(used, 23);
        let sys = parse_syslog("Aug", "16", "21:20:19", 2026).unwrap();
        assert_eq!(iso - sys, 107_000);
        assert_eq!(fmt_ts(sys), "2026-08-16 21:20:19");
    }

    #[test]
    fn durations() {
        assert_eq!("90s".parse::<Dur>().unwrap().0, 90);
        assert_eq!("10m".parse::<Dur>().unwrap().0, 600);
        assert_eq!("7d".parse::<Dur>().unwrap().to_string(), "7d");
        assert!("5y".parse::<Dur>().is_err());
    }
}
