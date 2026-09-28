//! Versions of the form `MAJOR.MINOR.PATCH[-PRE][+BUILD]`, compared with the
//! precedence rules of Semantic Versioning 2.0.0.
//!
//! - The numbers compare in order.
//! - A pre-release is lower than the release: `0.3.0-rc.1 < 0.3.0`.
//! - Pre-release identifiers compare left to right. A numeric identifier compares
//!   as a number and is lower than an alphanumeric one. More identifiers are higher
//!   when all others are equal: `1.0.0-alpha < 1.0.0-alpha.1`.
//! - Build metadata (`+...`) is checked and then ignored.

use std::cmp::Ordering;
use std::fmt;

/// The longest version text that Apassy accepts.
pub(crate) const MAX_VERSION_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Ident {
    Numeric(u64),
    Alpha(String),
}

/// A parsed version. Two versions are equal when their numbers and pre-release
/// identifiers are equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<Ident>,
}

/// Why a version text is not valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidVersion;

impl fmt::Display for InvalidVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a version of the form 1.2.3 or 1.2.3-rc.1")
    }
}

/// A number without a leading zero.
fn number(text: &str) -> Result<u64, InvalidVersion> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if !digits || (text.len() > 1 && text.starts_with('0')) {
        return Err(InvalidVersion);
    }
    text.parse().map_err(|_| InvalidVersion)
}

/// Dot-separated identifiers of `[0-9A-Za-z-]`, none empty.
fn identifiers(text: &str) -> Result<Vec<&str>, InvalidVersion> {
    let parts: Vec<&str> = text.split('.').collect();
    let valid = parts.iter().all(|part| {
        !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if valid {
        Ok(parts)
    } else {
        Err(InvalidVersion)
    }
}

impl Version {
    pub(crate) fn parse(text: &str) -> Result<Self, InvalidVersion> {
        if text.is_empty() || text.len() > MAX_VERSION_BYTES {
            return Err(InvalidVersion);
        }
        let (rest, build) = match text.split_once('+') {
            Some((rest, build)) => (rest, Some(build)),
            None => (text, None),
        };
        if let Some(build) = build {
            identifiers(build)?;
        }
        let (core, pre) = match rest.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (rest, None),
        };
        let numbers: Vec<&str> = core.split('.').collect();
        let [major, minor, patch] = numbers.as_slice() else {
            return Err(InvalidVersion);
        };
        let pre = match pre {
            None => Vec::new(),
            Some(pre) => identifiers(pre)?
                .into_iter()
                .map(|part| {
                    if part.bytes().all(|b| b.is_ascii_digit()) {
                        number(part).map(Ident::Numeric)
                    } else {
                        Ok(Ident::Alpha(part.to_owned()))
                    }
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(Self {
            major: number(major)?,
            minor: number(minor)?,
            patch: number(patch)?,
            pre,
        })
    }

    /// True for a pre-release such as `0.3.0-rc.1`.
    #[cfg(test)]
    pub(crate) fn is_prerelease(&self) -> bool {
        !self.pre.is_empty()
    }
}

impl Ord for Ident {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.cmp(b),
            (Self::Numeric(_), Self::Alpha(_)) => Ordering::Less,
            (Self::Alpha(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::Alpha(a), Self::Alpha(b)) => a.as_bytes().cmp(b.as_bytes()),
        }
    }
}

impl PartialOrd for Ident {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                // A release is higher than each of its pre-releases.
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                // Identifier by identifier, then the longer list is higher.
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A macOS version such as `15.0` or `15.4.1`, as `(major, minor, patch)`.
pub(crate) fn parse_macos(text: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = text.trim().split('.').collect();
    if parts.is_empty() || parts.len() > 3 || text.trim().len() > 16 {
        return None;
    }
    let mut numbers = [0_u64; 3];
    for (slot, part) in numbers.iter_mut().zip(&parts) {
        if part.is_empty() || part.len() > 4 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    Some((numbers[0], numbers[1], numbers[2]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap_or_else(|_| panic!("{text} parses"))
    }

    #[test]
    fn numbers_compare_in_order() {
        assert!(v("0.2.1") < v("0.3.0"));
        assert!(v("0.3.0") < v("0.3.1"));
        assert!(v("0.9.0") < v("0.10.0"), "numbers, not text");
        assert!(v("1.0.0") > v("0.99.99"));
        assert_eq!(v("0.3.0"), v("0.3.0"));
        assert_eq!(v("0.3.0").cmp(&v("0.3.0")), Ordering::Equal);
    }

    /// The example list of Semantic Versioning 2.0.0, §11.
    #[test]
    fn prerelease_precedence_follows_semver() {
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
            assert!(v(pair[1]) > v(pair[0]), "{} > {}", pair[1], pair[0]);
        }
        assert!(v("0.3.0-rc.1") < v("0.3.0"));
        assert!(v("0.3.0-rc.1") > v("0.2.9"));
        assert!(v("0.3.0-rc.1").is_prerelease());
        assert!(!v("0.3.0").is_prerelease());
    }

    #[test]
    fn build_metadata_is_ignored() {
        assert_eq!(v("0.3.0+abc"), v("0.3.0"));
        assert_eq!(v("0.3.0-rc.1+build.7"), v("0.3.0-rc.1"));
    }

    #[test]
    fn invalid_versions_are_refused() {
        for text in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            " 1.2.3",
            "1.2.3 ",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.3-",
            "1.2.3-01",
            "1.2.3-a..b",
            "1.2.3-a_b",
            "1.2.3+",
            "1.2.3+a..b",
            "-1.2.3",
            "1.2.x",
            "1.2.3-rc.1\n",
            "99999999999999999999.0.0",
        ] {
            assert!(Version::parse(text).is_err(), "{text:?} must be refused");
        }
        let long = format!("1.2.3-{}", "a".repeat(MAX_VERSION_BYTES));
        assert!(Version::parse(&long).is_err(), "too long");
        assert!(Version::parse("0.0.0").is_ok());
        assert!(Version::parse("1.2.3-0.a-b").is_ok());
    }

    #[test]
    fn macos_versions() {
        assert_eq!(parse_macos("15.0"), Some((15, 0, 0)));
        assert_eq!(parse_macos("15.4.1\n"), Some((15, 4, 1)));
        assert_eq!(parse_macos("27"), Some((27, 0, 0)));
        assert!(parse_macos("15.4.1") > parse_macos("15.4"));
        assert!(parse_macos("26.0") > parse_macos("15.7.3"));
        for bad in ["", "15.", "15..1", "a.b", "15.0.0.1", "15.0-beta", "-15"] {
            assert_eq!(parse_macos(bad), None, "{bad:?}");
        }
    }
}
