//! Cron expression parsing and next-run computation (WP-62 §3.3): pure
//! functions over plain data, no I/O.
//!
//! Supported specs (verified against the upstream module):
//! - standard 5 fields: `minute hour day-of-month month day-of-week`
//! - 6 fields with leading seconds: `second minute hour dom month dow`
//!   (e.g. `*/30 * * * * *`)
//! - descriptors: `@every <duration>` plus `@yearly`, `@annually`,
//!   `@monthly`, `@weekly`, `@daily`, `@midnight`, `@hourly`
//!
//! Field syntax per column: `*`, `*/step`, single value, `a-b` range and
//! `a-b/step`, comma-separated lists; month and weekday accept English
//! three-letter names (`jan`…`dec`, `sun`…`sat`). Weekdays are 0–7 with
//! both 0 and 7 meaning Sunday. Day-of-month and day-of-week follow
//! standard cron semantics: when both are restricted they OR, otherwise
//! the restricted one wins.
//!
//! All times are UTC ([`OffsetDateTime`]); the global timezone setting
//! (WP-07) is applied by the caller once it is wired in.

use std::fmt;

use time::{Date, Month, OffsetDateTime, Time, ext::NumericalDuration};

/// A failed expression parse, carrying a user-facing reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleError(pub String);

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScheduleError {}

/// Bounds and name tables per cron column.
const MINUTE: Column = Column {
    min: 0,
    max: 59,
    names: None,
};
const HOUR: Column = Column {
    min: 0,
    max: 23,
    names: None,
};
const DAY: Column = Column {
    min: 1,
    max: 31,
    names: None,
};
const MONTH: Column = Column {
    min: 1,
    max: 12,
    names: Some(MONTH_NAMES),
};
const DOW: Column = Column {
    min: 0,
    max: 7,
    names: Some(DOW_NAMES),
};
const MONTH_NAMES: &[(&str, u32)] = &[
    ("jan", 1),
    ("feb", 2),
    ("mar", 3),
    ("apr", 4),
    ("may", 5),
    ("jun", 6),
    ("jul", 7),
    ("aug", 8),
    ("sep", 9),
    ("oct", 10),
    ("nov", 11),
    ("dec", 12),
];
const DOW_NAMES: &[(&str, u32)] = &[
    ("sun", 0),
    ("mon", 1),
    ("tue", 2),
    ("wed", 3),
    ("thu", 4),
    ("fri", 5),
    ("sat", 6),
];

struct Column {
    min: u32,
    max: u32,
    names: Option<&'static [(&'static str, u32)]>,
}

impl Column {
    /// Bit mask covering the whole column.
    fn full_mask(&self) -> u64 {
        let mut mask = 0u64;
        for value in self.min..=self.max {
            mask |= 1 << value;
        }
        mask
    }
}

/// A parsed schedule: expanded field masks or an `@every` interval, plus
/// the original text for the fallback description.
#[derive(Clone, Debug)]
pub struct Schedule {
    repr: Repr,
    spec: String,
}

#[derive(Clone, Debug)]
enum Repr {
    Fields {
        second: u64,
        minute: u64,
        hour: u64,
        dom: u64,
        month: u64,
        dow: u64,
        dom_restricted: bool,
        dow_restricted: bool,
        six_field: bool,
    },
    Every(time::Duration),
}

/// Safety net for the next-run search; a valid schedule always terminates
/// long before this (worst case is a Feb-29 day list, ~1500 day steps).
const NEXT_ITERATION_CAP: u32 = 20_000;

/// Parses a cron expression into a [`Schedule`].
pub fn parse(spec: &str) -> Result<Schedule, ScheduleError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(ScheduleError("表达式不能为空".into()));
    }
    if spec.len() > crate::model::limits::SPEC_MAX_CHARS {
        return Err(ScheduleError(format!(
            "表达式最多 {} 个字符",
            crate::model::limits::SPEC_MAX_CHARS
        )));
    }
    let repr = if let Some(rest) = spec.strip_prefix('@') {
        parse_descriptor(rest.trim())?
    } else {
        parse_fields(spec)?
    };
    Ok(Schedule {
        repr,
        spec: spec.to_owned(),
    })
}

/// Parses `@every`/`@daily`-style descriptors.
fn parse_descriptor(rest: &str) -> Result<Repr, ScheduleError> {
    let expanded = match rest.to_ascii_lowercase().as_str() {
        "yearly" | "annually" => "0 0 1 1 *",
        "monthly" => "0 0 1 * *",
        "weekly" => "0 0 * * 0",
        "daily" | "midnight" => "0 0 * * *",
        "hourly" => "0 * * * *",
        other => {
            let duration = other
                .strip_prefix("every ")
                .ok_or_else(|| ScheduleError(format!("未知的描述符 @{other}")))?;
            return parse_every_duration(duration.trim()).map(Repr::Every);
        }
    };
    parse_fields(expanded)
}

/// Parses a Go-style duration for `@every`: one or more `<number><unit>`
/// chunks with units `ms`, `s`, `m`, `h` or `d` (days). The total must be
/// positive.
fn parse_every_duration(text: &str) -> Result<time::Duration, ScheduleError> {
    let invalid = || ScheduleError(format!("@every 时长无效：{text}"));
    let mut rest = text;
    let mut total = time::Duration::ZERO;
    let mut chunks = 0usize;
    while !rest.is_empty() {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() || digits.len() > 10 {
            return Err(invalid());
        }
        rest = &rest[digits.len()..];
        let value: i64 = digits.parse().map_err(|_| invalid())?;
        let unit_len = rest.chars().take_while(char::is_ascii_alphabetic).count();
        let (unit, tail) = rest.split_at(unit_len);
        let multiplier = match unit {
            "ms" => 1i64.milliseconds(),
            "s" => 1i64.seconds(),
            "m" => 1i64.minutes(),
            "h" => 1i64.hours(),
            "d" => 1i64.days(),
            _ => return Err(invalid()),
        };
        rest = tail;
        let value: i32 = i32::try_from(value).map_err(|_| invalid())?;
        total = total
            .checked_add(multiplier.checked_mul(value).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        chunks += 1;
    }
    if chunks == 0 || total.is_zero() || total.is_negative() {
        return Err(invalid());
    }
    Ok(total)
}

/// Parses the 5/6 field form into expanded masks.
fn parse_fields(spec: &str) -> Result<Repr, ScheduleError> {
    let fields: Vec<&str> = spec.split_whitespace().collect();
    let (second, minute, hour, dom, month, dow) = match fields.as_slice() {
        [minute, hour, dom, month, dow] => (None, *minute, *hour, *dom, *month, *dow),
        [second, minute, hour, dom, month, dow] => {
            (Some(*second), *minute, *hour, *dom, *month, *dow)
        }
        _ => {
            return Err(ScheduleError(
                "表达式应为 5 段（分 时 日 月 周）或 6 段（秒 分 时 日 月 周）".into(),
            ));
        }
    };
    let second_mask = match second {
        Some(text) => parse_field(&MINUTE, text)?,
        None => 1,
    };
    let minute_mask = parse_field(&MINUTE, minute)?;
    let hour_mask = parse_field(&HOUR, hour)?;
    let dom_mask = parse_field(&DAY, dom)?;
    let month_mask = parse_field(&MONTH, month)?;
    let mut dow_mask = parse_field(&DOW, dow)?;
    // Normalize the Sunday alias 7 to 0; "unrestricted" is then every
    // value of 0..=6.
    const DOW_ALL: u64 = (1 << 7) - 1;
    if dow_mask & (1 << 7) != 0 {
        dow_mask |= 1;
        dow_mask &= !(1 << 7);
    }
    Ok(Repr::Fields {
        second: second_mask,
        minute: minute_mask,
        hour: hour_mask,
        dom: dom_mask,
        month: month_mask,
        dow: dow_mask,
        dom_restricted: dom_mask != DAY.full_mask(),
        dow_restricted: dow_mask != DOW_ALL,
        six_field: second.is_some(),
    })
}

/// Parses one cron column into a bit mask (`bit value` = value allowed).
fn parse_field(column: &Column, text: &str) -> Result<u64, ScheduleError> {
    let text = text.trim();
    if text.is_empty() || text.len() > 64 {
        return Err(ScheduleError(format!("字段无效：{text}")));
    }
    let mut mask = 0u64;
    for part in text.split(',') {
        mask |= parse_part(column, part)?;
    }
    Ok(mask)
}

/// Parses one list element: `*`, `*\/step`, `a`, `a-b`, `a-b/step`, `a/step`.
fn parse_part(column: &Column, part: &str) -> Result<u64, ScheduleError> {
    let invalid = || ScheduleError(format!("字段值无效：{part}"));
    let (range, step) = match part.split_once('/') {
        Some((range, step)) => {
            let step: u32 = step.trim().parse().map_err(|_| invalid())?;
            if step == 0 {
                return Err(ScheduleError(format!("步长不能为 0：{part}")));
            }
            (range, step)
        }
        None => (part, 1),
    };
    let (lo, hi) = if range == "*" {
        (column.min, column.max)
    } else if let Some((from, to)) = range.split_once('-') {
        (
            parse_value(column, from.trim())?,
            parse_value(column, to.trim())?,
        )
    } else {
        // A single value with a step ("5/15") starts at 5 and repeats every
        // 15 up to the column maximum, matching standard implementations.
        let value = parse_value(column, range.trim())?;
        (value, if step == 1 { value } else { column.max })
    };
    if lo > hi {
        return Err(invalid());
    }
    let mut mask = 0u64;
    let mut value = lo;
    while value <= hi {
        mask |= 1 << value;
        value += step;
    }
    Ok(mask)
}

/// Resolves a column value, accepting name aliases (jan, mon, …).
fn parse_value(column: &Column, text: &str) -> Result<u32, ScheduleError> {
    if let Ok(value) = text.parse::<u32>() {
        if (column.min..=column.max).contains(&value) {
            return Ok(value);
        }
        return Err(ScheduleError(format!(
            "值超出范围 {}-{}：{text}",
            column.min, column.max
        )));
    }
    let lowered = text.to_ascii_lowercase();
    column
        .names
        .and_then(|names| {
            names
                .iter()
                .find(|(name, _)| *name == lowered)
                .map(|(_, value)| *value)
        })
        .ok_or_else(|| ScheduleError(format!("字段值无效：{text}")))
}

impl Schedule {
    /// The next trigger strictly after `after`.
    pub fn next(&self, after: OffsetDateTime) -> Option<OffsetDateTime> {
        match &self.repr {
            Repr::Every(interval) => after.checked_add(*interval),
            Repr::Fields { .. } => self.next_fields(after),
        }
    }

    /// A human-readable summary for the UI; irregular shapes fall back to
    /// the original expression text.
    pub fn describe(&self) -> String {
        match &self.repr {
            Repr::Every(interval) => format!("每 {}", describe_interval(*interval)),
            Repr::Fields { .. } => self.describe_fields(),
        }
    }

    fn next_fields(&self, after: OffsetDateTime) -> Option<OffsetDateTime> {
        let Repr::Fields {
            second,
            minute,
            hour,
            dom,
            month,
            dow,
            dom_restricted,
            dow_restricted,
            six_field: _,
        } = &self.repr
        else {
            return None;
        };
        let mut current = after
            .replace_nanosecond(0)
            .expect("zero nanoseconds is valid")
            .checked_add(1i64.seconds())?;
        for _ in 0..NEXT_ITERATION_CAP {
            if month & (1 << u8::from(current.month())) == 0 {
                current = first_of_next_month(current)?;
                continue;
            }
            if !day_matches(current, *dom, *dow, *dom_restricted, *dow_restricted) {
                current = start_of_next_day(current)?;
                continue;
            }
            if hour & (1 << current.hour()) == 0 {
                current = match next_allowed(current, Unit::Hour, *hour) {
                    Some(next) => next,
                    None => start_of_next_day(current)?,
                };
                continue;
            }
            if minute & (1 << current.minute()) == 0 {
                current = match next_allowed(current, Unit::Minute, *minute) {
                    Some(next) => next,
                    None => next_hour_boundary(current),
                };
                continue;
            }
            if second & (1 << current.second()) == 0 {
                current = match next_allowed(current, Unit::Second, *second) {
                    Some(next) => next,
                    None => next_minute_boundary(current),
                };
                continue;
            }
            return Some(current);
        }
        None
    }

    fn describe_fields(&self) -> String {
        let Repr::Fields {
            second,
            minute,
            hour,
            dom,
            month,
            dow,
            dom_restricted,
            dow_restricted,
            six_field,
        } = &self.repr
        else {
            return self.spec.clone();
        };
        let full_minute = MINUTE.full_mask();
        let full_hour = HOUR.full_mask();
        let full_month = MONTH.full_mask();
        let clock = |second_mask: u64| -> Option<String> {
            let minute_value = single(*minute)?;
            let hour_value = single(*hour)?;
            if *six_field && second_mask != 1 {
                return None;
            }
            Some(format!("{hour_value:02}:{minute_value:02}"))
        };
        // Every second / every minute (all columns unrestricted).
        let seconds_star = !*six_field || *second == full_minute;
        let minutes_star = *six_field || *minute == full_minute;
        if *month == full_month
            && !*dom_restricted
            && !*dow_restricted
            && *hour == full_hour
            && minutes_star
            && seconds_star
        {
            return if *six_field {
                "每秒".into()
            } else {
                "每分钟".into()
            };
        }
        let plain_days = *month == full_month && !*dom_restricted && !*dow_restricted;
        // Every N minutes / hours.
        if *hour == full_hour && plain_days {
            if *minute != full_minute {
                if let Some(step) = uniform_step(*minute, MINUTE.min, full_minute) {
                    return format!("每 {step} 分钟");
                }
            } else if let Some(step) = uniform_step(*hour, HOUR.min, full_hour) {
                return format!("每 {step} 小时");
            }
        }
        // Hourly at minute M.
        if *hour == full_hour && plain_days {
            if let Some(minute_value) = single(*minute) {
                return format!("每小时第 {minute_value} 分");
            }
            return self.spec.clone();
        }
        // Yearly / monthly / weekly / daily at a fixed clock time.
        if let Some(time_of_day) = clock(*second) {
            let day = match (single(*month), single(*dom), single(*dow)) {
                (Some(month_value), Some(day_value), _) => {
                    format!("每年 {month_value} 月 {day_value} 号")
                }
                (_, Some(day_value), _) if *dom_restricted => format!("每月 {day_value} 号"),
                (_, _, Some(dow_value)) if *dow_restricted => {
                    format!("每周{}", DOW_CN[dow_value as usize])
                }
                _ if plain_days => "每天".to_owned(),
                _ => return self.spec.clone(),
            };
            return format!("{day} {time_of_day}");
        }
        self.spec.clone()
    }
}

const DOW_CN: [&str; 7] = ["日", "一", "二", "三", "四", "五", "六"];

/// The only set value of a single-bit mask.
fn single(mask: u64) -> Option<u32> {
    (mask.count_ones() == 1).then_some(mask.trailing_zeros())
}

/// The step when a mask is exactly the arithmetic sequence
/// `start, start+step, …` covering the rest of the column (`*\/n` shape).
/// `full` is the whole-column mask, which is not a step.
fn uniform_step(mask: u64, start: u32, full: u64) -> Option<u32> {
    if mask == full {
        return None;
    }
    for step in 1..60u32 {
        let mut expected = 0u64;
        let mut value = start;
        while value <= 59 {
            expected |= 1 << value;
            value += step;
        }
        if mask == expected {
            return Some(step);
        }
    }
    None
}

/// Human text for an `@every` interval.
fn describe_interval(interval: time::Duration) -> String {
    let total = interval.unsigned_abs();
    let millis = total.subsec_millis();
    let seconds = total.as_secs();
    if seconds == 0 {
        return format!("{} 毫秒", total.as_millis());
    }
    let (days, rest) = (seconds / 86400, seconds % 86400);
    let (hours, minutes, secs) = (rest / 3600, (rest % 3600) / 60, rest % 60);
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days} 天"));
    }
    if hours > 0 {
        parts.push(format!("{hours} 小时"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes} 分钟"));
    }
    if secs > 0 {
        parts.push(format!("{secs} 秒"));
    }
    if millis > 0 {
        parts.push(format!("{millis} 毫秒"));
    }
    parts.join(" ")
}

/// `true` when `date` satisfies the day-of-month/day-of-week pair using
/// standard cron semantics (both restricted → OR; otherwise the restricted
/// one; neither → every day).
fn day_matches(
    date: OffsetDateTime,
    dom: u64,
    dow: u64,
    dom_restricted: bool,
    dow_restricted: bool,
) -> bool {
    let cron_dow = match date.weekday() {
        time::Weekday::Sunday => 0,
        time::Weekday::Monday => 1,
        time::Weekday::Tuesday => 2,
        time::Weekday::Wednesday => 3,
        time::Weekday::Thursday => 4,
        time::Weekday::Friday => 5,
        time::Weekday::Saturday => 6,
    };
    let dom_hit = dom & (1 << date.day()) != 0;
    let dow_hit = dow & (1 << cron_dow) != 0;
    match (dom_restricted, dow_restricted) {
        (true, true) => dom_hit || dow_hit,
        (true, false) => dom_hit,
        (false, true) => dow_hit,
        (false, false) => true,
    }
}

/// Which column [`next_allowed`] steps within.
#[derive(Clone, Copy)]
enum Unit {
    Hour,
    Minute,
    Second,
}

/// The smallest value strictly greater than the current one allowed by the
/// mask, set in place; `None` when the column is exhausted (caller rolls to
/// the next boundary of the higher unit).
fn next_allowed(at: OffsetDateTime, unit: Unit, mask: u64) -> Option<OffsetDateTime> {
    let (current, max) = match unit {
        Unit::Hour => (u32::from(at.hour()), 23),
        Unit::Minute => (u32::from(at.minute()), 59),
        Unit::Second => (u32::from(at.second()), 59),
    };
    for value in (current + 1)..=max {
        if mask & (1 << value) != 0 {
            return Some(set_unit(at, unit, value));
        }
    }
    None
}

/// Sets one column of the time-of-day, keeping the rest.
fn set_unit(at: OffsetDateTime, unit: Unit, value: u32) -> OffsetDateTime {
    let time = match unit {
        Unit::Hour => Time::from_hms(value as u8, 0, 0),
        Unit::Minute => Time::from_hms(at.hour(), value as u8, 0),
        Unit::Second => Time::from_hms(at.hour(), at.minute(), value as u8),
    }
    .expect("column values are within their ranges");
    at.replace_time(time)
}

/// The next full hour boundary (`minute = second = 0`).
fn next_hour_boundary(at: OffsetDateTime) -> OffsetDateTime {
    if at.hour() == 23 {
        start_of_next_day(at).unwrap_or(at)
    } else {
        at.replace_time(Time::from_hms(at.hour() + 1, 0, 0).expect("hour below 24"))
    }
}

/// The next full minute boundary (`second = 0`).
fn next_minute_boundary(at: OffsetDateTime) -> OffsetDateTime {
    if at.minute() == 59 {
        next_hour_boundary(at)
    } else {
        at.replace_time(Time::from_hms(at.hour(), at.minute() + 1, 0).expect("minute below 60"))
    }
}

/// First day of the following month at 00:00:00.
fn first_of_next_month(at: OffsetDateTime) -> Option<OffsetDateTime> {
    let (year, month) = (at.year(), at.month());
    let (next_year, next_month) = if month == Month::December {
        (year.checked_add(1)?, Month::January)
    } else {
        (year, month.next())
    };
    let date = Date::from_calendar_date(next_year, next_month, 1).ok()?;
    Some(at.replace_date_time(time::PrimitiveDateTime::new(date, Time::MIDNIGHT)))
}

/// Same calendar day, 00:00:00 of the following day.
fn start_of_next_day(at: OffsetDateTime) -> Option<OffsetDateTime> {
    let date = at.date().next_day()?;
    Some(at.replace_date_time(time::PrimitiveDateTime::new(date, Time::MIDNIGHT)))
}

/// Readable description for a spec, when it parses.
pub fn describe(spec: &str) -> Option<String> {
    parse(spec).ok().map(|schedule| schedule.describe())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, m: u8, d: u8, hh: u8, mm: u8, ss: u8) -> OffsetDateTime {
        let date =
            Date::from_calendar_date(y, Month::try_from(m).expect("month"), d).expect("date");
        let time = Time::from_hms(hh, mm, ss).expect("time");
        OffsetDateTime::new_utc(date, time)
    }

    #[test]
    fn parse_five_field() {
        let schedule = parse("*/10 6-18 1,15 * mon-fri").expect("valid spec");
        let Repr::Fields {
            minute,
            hour,
            dom,
            month,
            dow,
            ..
        } = &schedule.repr
        else {
            panic!("expected fields");
        };
        assert_eq!(minute.count_ones(), 6, "0,10,…,50");
        assert_eq!(hour.count_ones(), 13, "6..=18");
        assert_eq!((dom & (1 << 1)) | (dom & (1 << 15)), (1 << 1) | (1 << 15));
        assert_eq!(month.count_ones(), 12, "every month");
        assert_eq!(dow.count_ones(), 5, "mon..fri");
    }

    #[test]
    fn parse_six_field_with_seconds() {
        let schedule = parse("*/30 * * * * *").expect("valid spec");
        let start = at(2026, 1, 1, 0, 0, 0);
        let next = schedule.next(start).expect("next");
        assert_eq!(next.second(), 30);
        let next = schedule.next(next).expect("next");
        assert_eq!(
            (next.minute(), next.second()),
            (1, 0),
            "second 60 rolls into the next minute"
        );
    }

    #[test]
    fn parse_descriptors() {
        let cases = [
            ("@every 10m", "每 10 分钟"),
            ("@every 1h30m", "每 1 小时 30 分钟"),
            ("@daily", "每天 00:00"),
            ("@midnight", "每天 00:00"),
            ("@hourly", "每小时第 0 分"),
            ("@weekly", "每周日 00:00"),
            ("@monthly", "每月 1 号 00:00"),
            ("@yearly", "每年 1 月 1 号 00:00"),
            ("@annually", "每年 1 月 1 号 00:00"),
        ];
        for (spec, expected) in cases {
            let parsed = parse(spec).unwrap_or_else(|error| panic!("{spec}: {error}"));
            assert_eq!(parsed.describe(), expected, "spec {spec}");
        }
    }

    #[test]
    fn parse_rejects_invalid() {
        for spec in [
            "",
            "60 * * * *",           // minute out of range
            "* 24 * * *",           // hour out of range
            "* * 0 * *",            // day-of-month out of range
            "* * * 13 *",           // month out of range
            "* * * * 8",            // weekday out of range (only 0-7, 8 invalid)
            "* * * *",              // too few fields
            "* * * * * * *",        // too many fields
            "a * * * *",            // not a number
            "@nonsense",            // unknown descriptor
            "@every",               // missing duration
            "@every 0m",            // zero duration
            "@every 10x",           // unknown unit
            "* * * * */0",          // zero step
            "*/0 * * * *",          // zero step
            "5-2 * * * *",          // reversed range
            "*/10 6-18 1,15 * fou", // bad weekday name
        ] {
            assert!(parse(spec).is_err(), "should reject {spec:?}");
        }
    }

    #[test]
    fn next_run_time() {
        let daily = parse("0 0 * * *").expect("daily");
        // Crosses into the next day.
        assert_eq!(
            daily.next(at(2026, 3, 15, 23, 30, 0)),
            Some(at(2026, 3, 16, 0, 0, 0))
        );
        // Month end: the 31st only fires in long months.
        let monthly_31 = parse("0 0 31 * *").expect("dom 31");
        assert_eq!(
            monthly_31.next(at(2026, 4, 1, 0, 0, 0)),
            Some(at(2026, 5, 31, 0, 0, 0)),
            "April has no 31st"
        );
        // Leap year: Feb 29 after March 2025 is Feb 29 2028.
        let feb29 = parse("0 0 29 2 *").expect("feb 29");
        assert_eq!(
            feb29.next(at(2025, 3, 1, 12, 0, 0)),
            Some(at(2028, 2, 29, 0, 0, 0))
        );
        // Year boundary.
        let yearly = parse("0 0 1 1 *").expect("yearly");
        assert_eq!(
            yearly.next(at(2026, 12, 31, 23, 59, 59)),
            Some(at(2027, 1, 1, 0, 0, 0))
        );
        // Strictly after: a matching instant yields the following one.
        let every_10_min = parse("*/10 * * * *").expect("step");
        assert_eq!(
            every_10_min.next(at(2026, 1, 1, 5, 30, 0)),
            Some(at(2026, 1, 1, 5, 40, 0))
        );
        // Weekday name form.
        let monday = parse("0 12 * * mon").expect("monday");
        assert_eq!(
            monday.next(at(2026, 11, 28, 0, 0, 0)), // a Saturday
            Some(at(2026, 11, 30, 12, 0, 0))
        );
        // Six-field seconds: fires on :00 and :30 only.
        let seconds = parse("0,30 * * * * *").expect("seconds");
        assert_eq!(
            seconds.next(at(2026, 1, 1, 0, 0, 1)),
            Some(at(2026, 1, 1, 0, 0, 30))
        );
        assert_eq!(
            seconds.next(at(2026, 1, 1, 0, 0, 31)),
            Some(at(2026, 1, 1, 0, 1, 0))
        );
        // @every behaves as a plain interval.
        let every = parse("@every 90m").expect("every");
        assert_eq!(
            every.next(at(2026, 1, 1, 23, 0, 0)),
            Some(at(2026, 1, 2, 0, 30, 0))
        );
    }
}
