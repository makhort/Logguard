//! Times as logguard writes them: microseconds since the Unix epoch.

pub type Micros = i64;
pub const SEC: Micros = 1_000_000;

pub fn now() -> Micros {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_micros() as Micros)
}

/// The date (year, month, day) at `t`, UTC.
pub fn ymd(t: Micros) -> (i64, u32, u32) {
    civil_from_days(t.div_euclid(SEC).div_euclid(86_400))
}

/// `2026-10-26 12:00:00 UTC`.
pub fn fmt_ts(t: Micros) -> String {
    let secs = t.div_euclid(SEC);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Howard Hinnant's days-to-date (proleptic Gregorian calendar).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats() {
        assert_eq!(super::fmt_ts(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(super::fmt_ts(1_793_045_277_118_289), "2026-10-26 20:07:57 UTC");
    }
}
