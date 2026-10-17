//! Human-readable durations and the localized date strings of /dt_conv and /maintenance,
//! in the words and time zone of each language (see [`crate::i18n::Texts`]).

use crate::i18n::Language;
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, NaiveTime, Timelike, Utc, Weekday};

const MINUTE: i64 = 60;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * HOUR;
const WEEK: i64 = 7 * DAY;
const MONTH: i64 = 30 * DAY;
const YEAR: i64 = 365 * DAY;

fn plural(value: i64, unit: &str) -> String {
    format!("{value} {unit}{}", if value == 1 { "" } else { "s" })
}

/// "3 hours ago", measured from `now` (both Unix seconds).
pub fn relative_time(ts: f64, now: f64) -> String {
    let diff = (now - ts).max(0.0) as i64;
    let (value, unit) = match diff {
        d if d < MINUTE => return "just now".to_string(),
        d if d < HOUR => (d / MINUTE, "minute"),
        d if d < DAY => (d / HOUR, "hour"),
        d if d < WEEK => (d / DAY, "day"),
        d if d < MONTH => (d / WEEK, "week"),
        d if d < YEAR => (d / MONTH, "month"),
        d => (d / YEAR, "year"),
    };
    format!("{} ago", plural(value, unit))
}

/// "5 minutes", for session uptimes.
pub fn elapsed_time(secs: i64) -> String {
    match secs {
        s if s < MINUTE => plural(s, "second"),
        s if s < HOUR => plural(s / MINUTE, "minute"),
        s if s < DAY => plural(s / HOUR, "hour"),
        s if s < WEEK => plural(s / DAY, "day"),
        s if s < MONTH => plural(s / WEEK, "week"),
        s if s < YEAR => plural(s / MONTH, "month"),
        s => plural(s / YEAR, "year"),
    }
}

fn parse_weekday(s: &str) -> Option<Weekday> {
    Some(match s.to_lowercase().as_str() {
        "mon" | "monday" => Weekday::Mon,
        "tue" | "tuesday" => Weekday::Tue,
        "wed" | "wednesday" => Weekday::Wed,
        "thu" | "thursday" => Weekday::Thu,
        "fri" | "friday" => Weekday::Fri,
        "sat" | "saturday" => Weekday::Sat,
        "sun" | "sunday" => Weekday::Sun,
        _ => return None,
    })
}

/// Parses `dd/mm/YYYY HH:MM:SS` or `<weekday> HH:MM` (both UTC). A weekday means its next
/// occurrence: today if that time is still ahead, otherwise a week later.
pub fn parse_datetime_input(input: &str, now: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let input = input.trim();
    if let Ok(dt) = NaiveDateTime::parse_from_str(input, "%d/%m/%Y %H:%M:%S") {
        return Ok(dt.and_utc());
    }

    let parts: Vec<&str> = input.split_whitespace().collect();
    let [dow, time] = parts[..] else {
        return Err(format!("Invalid datetime format: {input}"));
    };
    let target = parse_weekday(dow).ok_or_else(|| format!("Invalid day of week: {dow}"))?;
    let time = match time.split(':').collect::<Vec<_>>()[..] {
        [h, m] => h.parse().ok().zip(m.parse().ok()).and_then(|(h, m)| NaiveTime::from_hms_opt(h, m, 0)),
        _ => None,
    }
    .ok_or_else(|| format!("Invalid time format: {time}"))?;

    let current = now.weekday().num_days_from_monday() as i64;
    let target = target.num_days_from_monday() as i64;
    let days_ahead = match current.cmp(&target) {
        std::cmp::Ordering::Greater => 7 - current + target,
        std::cmp::Ordering::Less => target - current,
        std::cmp::Ordering::Equal => {
            if (time.hour(), time.minute()) <= (now.hour(), now.minute()) {
                7
            } else {
                0
            }
        }
    };
    let date = (now + Duration::days(days_ahead)).date_naive();
    Ok(date.and_time(time).and_utc())
}

/// "Tomorrow 14:00" in the language's time zone, relative to `now`.
fn format_time_for_lang(dt: DateTime<Utc>, lang: Language, now: DateTime<Utc>) -> String {
    let t = lang.texts();
    let local = dt.with_timezone(&t.tz);
    let now_local = now.with_timezone(&t.tz);
    let delta_days = (local.date_naive() - now_local.date_naive()).num_days();
    let time = format!("{:02}{}{:02}", local.hour(), t.time_separator, local.minute());

    let day = match delta_days {
        0 => t.today.to_string(),
        1 => t.tomorrow.to_string(),
        2..=7 => t.weekdays[local.weekday().num_days_from_monday() as usize].to_string(),
        _ if local.year() == now_local.year() && local.month() == now_local.month() => {
            format!("{:02}", local.day())
        }
        _ => format!("{:02}/{:02}", local.day(), local.month()),
    };
    format!("{day} {time}")
}

/// The time zone's abbreviation at `dt` in the language's zone: "BST", "CET", "MSK", "EEST".
pub fn zone_name(dt: DateTime<Utc>, lang: Language) -> String {
    dt.with_timezone(&lang.texts().tz).format("%Z").to_string()
}

/// One localized time per language of `langs`, with its time zone: "Tomorrow 14:00 (BST)".
pub fn utc_to_local_times(raw: &str, now: DateTime<Utc>, langs: &[Language]) -> Result<Vec<String>, String> {
    let dt = parse_datetime_input(raw, now)?;
    Ok(langs.iter().map(|&lang| format!("{} ({})", format_time_for_lang(dt, lang, now), zone_name(dt, lang))).collect())
}

/// One localized "from … to … (zone)" range per language of `langs`.
pub fn format_maintenance_times(from: &str, to: &str, now: DateTime<Utc>, langs: &[Language]) -> Result<Vec<String>, String> {
    let from = parse_datetime_input(from, now)?;
    let to = parse_datetime_input(to, now)?;
    Ok(langs
        .iter()
        .map(|&lang| {
            let t = lang.texts();
            format!(
                "{} {} {} {} ({})",
                t.range_from,
                format_time_for_lang(from, lang, now),
                t.range_to,
                format_time_for_lang(to, lang, now),
                zone_name(from, lang)
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap()
    }

    #[test]
    fn relative_and_elapsed() {
        assert_eq!(relative_time(100.0, 130.0), "just now");
        assert_eq!(relative_time(130.0, 100.0), "just now");
        assert_eq!(relative_time(0.0, 60.0), "1 minute ago");
        assert_eq!(relative_time(0.0, 3.0 * 3600.0), "3 hours ago");
        assert_eq!(relative_time(0.0, 400.0 * 86400.0), "1 year ago");
        assert_eq!(elapsed_time(1), "1 second");
        assert_eq!(elapsed_time(59), "59 seconds");
        assert_eq!(elapsed_time(7200), "2 hours");
        assert_eq!(elapsed_time(14 * 86400), "2 weeks");
    }

    #[test]
    fn parses_absolute_dates_padded_or_not() {
        let now = utc(2026, 10, 13, 12, 0);
        assert_eq!(parse_datetime_input("01/02/2026 01:00:00", now), Ok(utc(2026, 2, 1, 1, 0)));
        assert_eq!(parse_datetime_input(" 1/2/2026 1:00:00 ", now), Ok(utc(2026, 2, 1, 1, 0)));
    }

    #[test]
    fn weekday_means_next_occurrence() {
        // 2026-10-13 is a Tuesday.
        let now = utc(2026, 10, 13, 12, 0);
        assert_eq!(parse_datetime_input("Sun 01:00", now), Ok(utc(2026, 10, 18, 1, 0)));
        assert_eq!(parse_datetime_input("monday 01:00", now), Ok(utc(2026, 10, 19, 1, 0)));
        assert_eq!(parse_datetime_input("Tue 13:00", now), Ok(utc(2026, 10, 13, 13, 0)));
        assert_eq!(parse_datetime_input("TUE 12:00", now), Ok(utc(2026, 10, 20, 12, 0)));
        assert_eq!(parse_datetime_input("Funday 01:00", now), Err("Invalid day of week: Funday".into()));
        assert_eq!(parse_datetime_input("Sun 25:00", now), Err("Invalid time format: 25:00".into()));
        assert_eq!(parse_datetime_input("Sun", now), Err("Invalid datetime format: Sun".into()));
    }

    #[test]
    fn localized_times() {
        // Summer: London BST (+1), Paris CEST (+2), Moscow (+3), Kyiv EEST (+3).
        let now = utc(2026, 7, 7, 12, 0); // a Tuesday
        let langs = [Language::En, Language::Fr, Language::Ru, Language::Uk, Language::Pl, Language::De];
        let t = utc_to_local_times("Sun 01:00", now, &langs).unwrap();
        assert_eq!(t, ["Sun 02:00 (BST)", "Dim 03h00 (CEST)", "Вс 04:00 (MSK)", "Нд 04:00 (EEST)", "Nd 03:00 (CEST)", "So 03:00 (CEST)"]);

        let t = utc_to_local_times("Wed 22:30", now, &langs[..4]).unwrap();
        assert_eq!(t, ["Tomorrow 23:30 (BST)", "Jeu 00h30 (CEST)", "Чт 01:30 (MSK)", "Чт 01:30 (EEST)"]);

        let t = utc_to_local_times("20/07/2026 10:00:00", now, &[Language::En]).unwrap();
        assert_eq!(t, ["20 11:00 (BST)"]);
        let t = utc_to_local_times("01/09/2026 10:00:00", now, &[Language::En]).unwrap();
        assert_eq!(t, ["01/09 11:00 (BST)"]);
    }

    #[test]
    fn maintenance_ranges() {
        let now = utc(2026, 12, 1, 9, 0); // winter, a Tuesday
        let langs = [Language::En, Language::Fr, Language::Ru, Language::Uk, Language::Pl];
        let r = format_maintenance_times("Tue 10:00", "Tue 11:00", now, &langs).unwrap();
        assert_eq!(r[0], "from Today 10:00 to Today 11:00 (GMT)");
        assert_eq!(r[1], "de Aujourd'hui 11h00 à Aujourd'hui 12h00 (CET)");
        assert_eq!(r[2], "с Сегодня 13:00 по Сегодня 14:00 (MSK)");
        assert_eq!(r[3], "з Сьогодні 12:00 по Сьогодні 13:00 (EET)");
        assert_eq!(r[4], "od Dziś 11:00 do Dziś 12:00 (CET)");
    }
}
