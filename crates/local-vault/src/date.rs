//! The dates of the vault: written as `yyyy-MM-ddTHH:mm:ss.SSSZ` in UTC, and read as any
//! ISO-8601 date and time that says its offset from UTC.

const MILLIS_PER_DAY: i64 = 86_400_000;
const SECONDS_PER_DAY: i64 = 86_400;
const NANOS_PER_SECOND: i128 = 1_000_000_000;
const NANOS_PER_MILLI: i128 = 1_000_000;
const MAX_OFFSET_SECONDS: i64 = 18 * 3600;
const MAX_FRACTION_DIGITS: usize = 9;

/// Formats a time, in milliseconds since the epoch, the way dates are stored in the vault.
pub(crate) fn format_date(epoch_millis: i64) -> String {
    let days = epoch_millis.div_euclid(MILLIS_PER_DAY);
    let millis_of_day = epoch_millis.rem_euclid(MILLIS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let seconds_of_day = millis_of_day / 1000;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds_of_day / 3600,
        seconds_of_day / 60 % 60,
        seconds_of_day % 60,
        millis_of_day % 1000,
    )
}

/// Parses an ISO-8601 date and time with its offset, such as `2026-10-11T12:00:00.000Z` or
/// `2026-10-11T14:00+02:00`, to nanoseconds since the epoch. Returns `None` for anything else,
/// among it a date without an offset, which would mean another time on every device.
pub(crate) fn parse_date_nanos(text: &str) -> Option<i128> {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        position: 0,
    };
    let year = reader.digits(4)?;
    reader.expect(b'-')?;
    let month = reader.digits(2)?;
    reader.expect(b'-')?;
    let day = reader.digits(2)?;
    reader.expect_ignore_case(b'T')?;
    let hour = reader.digits(2)?;
    reader.expect(b':')?;
    let minute = reader.digits(2)?;
    let mut second = 0;
    let mut nanos: i128 = 0;
    if reader.next_is(b':') {
        reader.expect(b':')?;
        second = reader.digits(2)?;
        if reader.next_is(b'.') {
            reader.expect(b'.')?;
            nanos = reader.fraction_nanos()?;
        }
    }
    let offset_seconds = reader.offset_seconds()?;
    if !reader.is_at_end()
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let seconds_of_day = hour * 3600 + minute * 60 + second;
    let seconds = days_from_civil(year, month, day) * SECONDS_PER_DAY + seconds_of_day;
    let utc_seconds = i128::from(seconds - offset_seconds);
    Some(utc_seconds * NANOS_PER_SECOND + nanos)
}

/// Parses an ISO-8601 date and time with its offset to milliseconds since the epoch, rounded
/// down.
pub(crate) fn parse_date_millis(text: &str) -> Option<i64> {
    let millis = parse_date_nanos(text)?.div_euclid(NANOS_PER_MILLI);
    i64::try_from(millis).ok()
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn next_is(&self, expected: u8) -> bool {
        self.peek() == Some(expected)
    }

    fn is_at_end(&self) -> bool {
        self.position >= self.bytes.len()
    }

    fn expect(&mut self, expected: u8) -> Option<()> {
        if self.next_is(expected) {
            self.position += 1;
            Some(())
        } else {
            None
        }
    }

    fn expect_ignore_case(&mut self, expected: u8) -> Option<()> {
        if self.peek()?.eq_ignore_ascii_case(&expected) {
            self.position += 1;
            Some(())
        } else {
            None
        }
    }

    /// Reads exactly the given number of digits.
    fn digits(&mut self, count: usize) -> Option<i64> {
        let mut value = 0;
        for _ in 0..count {
            let digit = self.peek().filter(u8::is_ascii_digit)?;
            value = value * 10 + i64::from(digit - b'0');
            self.position += 1;
        }
        Some(value)
    }

    /// Reads the digits of a fraction of a second, one to nine of them, as nanoseconds.
    fn fraction_nanos(&mut self) -> Option<i128> {
        let mut nanos: i128 = 0;
        let mut count = 0;
        while let Some(digit) = self.peek().filter(u8::is_ascii_digit) {
            if count == MAX_FRACTION_DIGITS {
                return None;
            }
            nanos = nanos * 10 + i128::from(digit - b'0');
            count += 1;
            self.position += 1;
        }
        if count == 0 {
            return None;
        }
        for _ in count..MAX_FRACTION_DIGITS {
            nanos *= 10;
        }
        Some(nanos)
    }

    /// Reads `Z`, or an offset of the form `+HH:MM` or `+HH:MM:SS`.
    fn offset_seconds(&mut self) -> Option<i64> {
        let sign = match self.peek()? {
            b'Z' | b'z' => {
                self.position += 1;
                return Some(0);
            }
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        self.position += 1;
        let hours = self.digits(2)?;
        self.expect(b':')?;
        let minutes = self.digits(2)?;
        let mut seconds = 0;
        if self.next_is(b':') {
            self.expect(b':')?;
            seconds = self.digits(2)?;
        }
        if minutes > 59 || seconds > 59 {
            return None;
        }
        let offset = hours * 3600 + minutes * 60 + seconds;
        (offset <= MAX_OFFSET_SECONDS).then_some(sign * offset)
    }
}

fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The number of days since 1970-01-01 of a date of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_from_march = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The date of the proleptic Gregorian calendar that is the given number of days after
/// 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOON: i64 = 1_791_720_000_000;

    #[test]
    fn dates_are_written_in_utc_with_milliseconds() {
        assert_eq!(format_date(NOON), "2026-10-11T12:00:00.000Z");
        assert_eq!(format_date(NOON + 1), "2026-10-11T12:00:00.001Z");
        assert_eq!(format_date(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_date(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(format_date(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn dates_are_read_back_as_they_are_written() {
        let leap_day = 951_782_400_000;
        let next_century = 4_102_444_800_000;

        for millis in [0, -1, NOON, NOON + 999, leap_day, next_century] {
            assert_eq!(parse_date_millis(&format_date(millis)), Some(millis));
        }
    }

    #[test]
    fn dates_with_an_offset_are_read_in_any_iso_8601_form() {
        let noon = Some(i128::from(NOON) * NANOS_PER_MILLI);

        assert_eq!(parse_date_nanos("2026-10-11T12:00:00Z"), noon);
        assert_eq!(parse_date_nanos("2026-10-11T12:00Z"), noon);
        assert_eq!(parse_date_nanos("2026-10-11t12:00:00z"), noon);
        assert_eq!(parse_date_nanos("2026-10-11T14:00:00+02:00"), noon);
        assert_eq!(parse_date_nanos("2026-10-11T11:30:00-00:30"), noon);
        assert_eq!(parse_date_nanos("2026-10-11T12:00:00.0000000Z"), noon);
        assert_eq!(
            parse_date_nanos("2026-10-11T12:00:00.1234567Z"),
            noon.map(|nanos| nanos + 123_456_700)
        );
    }

    #[test]
    fn anything_but_a_date_with_an_offset_is_not_read() {
        for text in [
            "",
            "2026-10-11",
            "2026-10-11T12:00:00",
            "2026-10-11T12:00:00.000",
            "2026-10-11 12:00:00Z",
            "2026-13-11T12:00:00Z",
            "2026-02-29T12:00:00Z",
            "2026-10-11T24:00:00Z",
            "2026-10-11T12:00:60Z",
            "2026-10-11T12:00:00.Z",
            "2026-10-11T12:00:00.1234567890Z",
            "2026-10-11T12:00:00+02",
            "2026-10-11T12:00:00+19:00",
            "2026-10-11T12:00:00Z ",
            "Oct 11 2026",
        ] {
            assert_eq!(parse_date_nanos(text), None, "{text}");
        }
    }
}
