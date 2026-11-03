//! Short-lived credentials, "way C" (ADR 0037 stage 6, contract
//! [`private-sharing-v1`](../../docs/contracts/private-sharing-v1.md), plan s6 unit C1).
//!
//! - [`sigv4`] is the AWS Signature Version 4 code that the STS call, the signing
//!   proxies (E1, E2), and the sign endpoint (H) share.
//! - [`scan`] is the no-secret scan of every test of the plan (section 11).

pub mod scan;
pub mod sigv4;

/// `YYYY-MM-DDTHH:MM:SSZ` of Unix seconds (UTC), or `None` outside the years 1970 to
/// 9999. `AWS_CREDENTIAL_EXPIRATION` has this form (contract section 4.1).
pub fn rfc3339(unix: u64) -> Option<String> {
    let (year, month, day, hour, minute, second) = utc_parts(unix)?;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

/// Unix seconds of `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (a fraction of 1 to 9 digits is
/// dropped). Any other form, an offset other than `Z` included, is `None`.
pub fn parse_rfc3339(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if !text.is_ascii() || bytes.len() < 20 || bytes[bytes.len() - 1] != b'Z' {
        return None;
    }
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators.iter().any(|(at, byte)| bytes[*at] != *byte) {
        return None;
    }
    let tail = &text[19..text.len() - 1];
    if !tail.is_empty() {
        let fraction = tail.strip_prefix('.')?;
        if fraction.is_empty()
            || fraction.len() > 9
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = text.get(range)?;
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    unix_from_parts(
        i32::try_from(number(0..4)?).ok()?,
        u8::try_from(number(5..7)?).ok()?,
        u8::try_from(number(8..10)?).ok()?,
        u8::try_from(number(11..13)?).ok()?,
        u8::try_from(number(14..16)?).ok()?,
        u8::try_from(number(17..19)?).ok()?,
    )
}

/// Year, month, day, hour, minute, and second (UTC) of Unix seconds, for the years 1970
/// to 9999.
pub(crate) fn utc_parts(unix: u64) -> Option<(i32, u8, u8, u8, u8, u8)> {
    let at = time::OffsetDateTime::from_unix_timestamp(i64::try_from(unix).ok()?).ok()?;
    if at.year() > 9999 {
        return None;
    }
    Some((
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
    ))
}

/// Unix seconds of a UTC time, or `None` for a time that does not exist or is before
/// 1970.
pub(crate) fn unix_from_parts(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<u64> {
    let month = time::Month::try_from(month).ok()?;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let at = date.with_hms(hour, minute, second).ok()?.assume_utc();
    u64::try_from(at.unix_timestamp()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_times_round_trip() {
        assert_eq!(
            rfc3339(1_793_700_900).as_deref(),
            Some("2026-11-03T10:15:00Z")
        );
        assert_eq!(parse_rfc3339("2026-11-03T10:15:00Z"), Some(1_793_700_900));
        assert_eq!(
            parse_rfc3339("2026-11-03T10:15:00.359Z"),
            Some(1_793_700_900)
        );
        assert_eq!(rfc3339(0).as_deref(), Some("1970-01-01T00:00:00Z"));
        for bad in [
            "",
            "2026-11-03T10:15:00",
            "2026-11-03T10:15:00+00:00",
            "2026-11-03 10:15:00Z",
            "2026-11-03T10:15:00.Z",
            "2026-11-03T10:15:00.0123456789Z",
            "2026-02-30T10:15:00Z",
            "2026-11-03T24:15:00Z",
            "+026-11-03T10:15:00Z",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }
}
