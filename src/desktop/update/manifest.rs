//! `latest.json` and the identity of the running build.
//!
//! `scripts/build-dmg.sh` writes `latest.json`. The app accepts it only when every
//! field has the expected form. Unknown fields are ignored, so the release can add
//! a field without breaking older apps.

use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::version::{Version, parse_macos};

/// The largest `latest.json` that the app reads.
pub(crate) const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
/// The largest disk image that the app downloads. The image of 0.2.1 has about
/// 111 MB.
pub(crate) const MAX_IMAGE_BYTES: u64 = 1024 * 1024 * 1024;
/// The only file name that `latest.json` may name.
pub(crate) const IMAGE_FILE: &str = "Apassy.dmg";
/// The only architecture of the published app.
pub(crate) const ARCH: &str = "arm64";

/// A checked `latest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) version: String,
    /// The first 7 hex digits of the commit.
    pub(crate) build: String,
    /// The full commit SHA, 40 lowercase hex digits.
    pub(crate) commit: String,
    /// The time of the release, `YYYY-MM-DDTHH:MM:SSZ`.
    pub(crate) date: String,
    /// `date` in seconds since 1970.
    pub(crate) date_unix: i64,
    /// The size of the disk image in bytes.
    pub(crate) size: u64,
    /// The SHA-256 of the disk image, 64 lowercase hex digits.
    pub(crate) sha256: String,
    pub(crate) minimum_macos: String,
}

/// The fields of `latest.json` before the checks.
#[derive(Deserialize)]
struct Raw {
    version: String,
    build: String,
    commit: String,
    date: String,
    file: String,
    size: u64,
    sha256: String,
    notarized: bool,
    minimum_macos: String,
    arch: String,
}

/// Why the app refuses a `latest.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManifestError {
    /// More than [`MAX_MANIFEST_BYTES`].
    TooLarge,
    /// Not JSON, a field is missing, or a field has the wrong type.
    Malformed,
    Version,
    Build,
    Commit,
    Date,
    File,
    Size,
    Sha256,
    NotNotarized,
    MinimumMacos,
    Arch,
    /// The running macOS version cannot be read.
    RunningMacos,
    /// The release needs a later macOS.
    NeedsMacos(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = match self {
            Self::TooLarge => return f.write_str("The update information is too large."),
            Self::Malformed => {
                return f.write_str("The update information is not in the expected format.");
            }
            Self::NotNotarized => {
                return f.write_str("The published build is not notarized by Apple.");
            }
            Self::RunningMacos => {
                return f.write_str("Apassy cannot read the macOS version of this Mac.");
            }
            Self::NeedsMacos(needed) => {
                return write!(
                    f,
                    "The new version of Apassy needs macOS {needed} or later."
                );
            }
            Self::Version => "version",
            Self::Build => "build",
            Self::Commit => "commit",
            Self::Date => "date",
            Self::File => "file",
            Self::Size => "size",
            Self::Sha256 => "sha256",
            Self::MinimumMacos => "minimum_macos",
            Self::Arch => "arch",
        };
        write!(f, "The update information has an invalid \"{field}\".")
    }
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A full commit SHA: 40 lowercase hex digits.
pub(crate) fn is_commit(text: &str) -> bool {
    is_lower_hex(text, 40)
}

/// A SHA-256: 64 lowercase hex digits.
pub(crate) fn is_sha256(text: &str) -> bool {
    is_lower_hex(text, 64)
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (UTC) to seconds since 1970. Other forms of ISO
/// 8601 are refused.
pub(crate) fn parse_utc(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let shape = bytes.len() == 20
        && bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            10 => *b == b'T',
            13 | 16 => *b == b':',
            19 => *b == b'Z',
            _ => b.is_ascii_digit(),
        });
    if !shape {
        return None;
    }
    let num = |range: std::ops::Range<usize>| text[range].parse::<u16>().ok();
    let month = time::Month::try_from(u8::try_from(num(5..7)?).ok()?).ok()?;
    let date = time::Date::from_calendar_date(
        i32::from(num(0..4)?),
        month,
        u8::try_from(num(8..10)?).ok()?,
    )
    .ok()?;
    let clock = time::Time::from_hms(
        u8::try_from(num(11..13)?).ok()?,
        u8::try_from(num(14..16)?).ok()?,
        u8::try_from(num(17..19)?).ok()?,
    )
    .ok()?;
    Some(
        time::PrimitiveDateTime::new(date, clock)
            .assume_utc()
            .unix_timestamp(),
    )
}

impl Manifest {
    /// Parse and check `bytes`. `running_macos` is the output of
    /// `sw_vers -productVersion`.
    pub(crate) fn parse(bytes: &[u8], running_macos: &str) -> Result<Self, ManifestError> {
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge);
        }
        let raw: Raw = serde_json::from_slice(bytes).map_err(|_| ManifestError::Malformed)?;
        Version::parse(&raw.version).map_err(|_| ManifestError::Version)?;
        if !is_commit(&raw.commit) {
            return Err(ManifestError::Commit);
        }
        let build_ok = (7..=40).contains(&raw.build.len())
            && is_lower_hex(&raw.build, raw.build.len())
            && raw.commit.starts_with(&raw.build);
        if !build_ok {
            return Err(ManifestError::Build);
        }
        let date_unix = parse_utc(&raw.date).ok_or(ManifestError::Date)?;
        if raw.file != IMAGE_FILE {
            return Err(ManifestError::File);
        }
        if raw.size == 0 || raw.size > MAX_IMAGE_BYTES {
            return Err(ManifestError::Size);
        }
        if !is_sha256(&raw.sha256) {
            return Err(ManifestError::Sha256);
        }
        if !raw.notarized {
            return Err(ManifestError::NotNotarized);
        }
        if raw.arch != ARCH {
            return Err(ManifestError::Arch);
        }
        let needed = parse_macos(&raw.minimum_macos).ok_or(ManifestError::MinimumMacos)?;
        let running = parse_macos(running_macos).ok_or(ManifestError::RunningMacos)?;
        if needed > running {
            return Err(ManifestError::NeedsMacos(raw.minimum_macos));
        }
        Ok(Self {
            version: raw.version,
            build: raw.build,
            commit: raw.commit,
            date: raw.date,
            date_unix,
            size: raw.size,
            sha256: raw.sha256,
            minimum_macos: raw.minimum_macos,
        })
    }
}

/// The version and the build of the running app. `scripts/build-app.sh` sets the
/// commit and the date. A development build has neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuildIdentity {
    pub(crate) version: String,
    /// The commit and the build time, both or none.
    pub(crate) build: Option<(String, i64)>,
}

impl BuildIdentity {
    /// The identity that the compiler embedded in this program.
    pub(crate) fn current() -> Self {
        Self::from_parts(
            env!("CARGO_PKG_VERSION"),
            option_env!("APASSY_BUILD_COMMIT"),
            option_env!("APASSY_BUILD_DATE"),
        )
    }

    /// An identity from its parts. A commit or a date that is not valid counts as
    /// absent, and so do both when one is absent.
    pub(crate) fn from_parts(version: &str, commit: Option<&str>, date: Option<&str>) -> Self {
        let build = match (commit, date.and_then(parse_utc)) {
            (Some(commit), Some(date)) if is_commit(commit) => Some((commit.to_owned(), date)),
            _ => None,
        };
        Self {
            version: version.to_owned(),
            build,
        }
    }

    /// The first 7 hex digits of the commit, as in `latest.json`.
    pub(crate) fn short_commit(&self) -> Option<&str> {
        self.build.as_ref().map(|(commit, _)| &commit[..7])
    }

    /// "0.3.0 (build abc1234, 2026-09-28)", or "0.3.0 (development build)".
    pub(crate) fn label(&self) -> String {
        match (&self.build, self.short_commit()) {
            (Some((_, date)), Some(short)) => {
                let day = u64::try_from(*date)
                    .map(crate::vault::format_utc)
                    .unwrap_or_default();
                let day = day.split(' ').next().unwrap_or_default();
                format!("{} (build {short}, {day})", self.version)
            }
            _ => format!("{} (development build)", self.version),
        }
    }
}

/// True when `manifest` names a higher version than `current` (Semantic Versioning
/// order). Only a higher version updates the app: another build of the same
/// version does not, so a merge to `main` without a version change reaches no
/// installed app (ADR 0015). A lower version is never newer, so the app refuses a
/// downgrade.
pub(crate) fn is_newer(manifest: &Manifest, current: &BuildIdentity) -> bool {
    let (Ok(offered), Ok(running)) = (
        Version::parse(&manifest.version),
        Version::parse(&current.version),
    ) else {
        return false;
    };
    offered.cmp(&running) == Ordering::Greater
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const COMMIT: &str = "e710914de97c988f775bf180ab1f9f43c2ee20ee";
    pub(crate) const OTHER_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    /// A valid `latest.json` with the fields in `changes` replaced. A `null`
    /// removes the field.
    pub(crate) fn manifest_json(changes: &[(&str, serde_json::Value)]) -> Vec<u8> {
        let mut value = serde_json::json!({
            "version": "0.3.1",
            "build": &COMMIT[..7],
            "commit": COMMIT,
            "date": "2026-10-02T09:30:00Z",
            "file": "Apassy.dmg",
            "size": 111_033_131,
            "sha256": "a".repeat(64),
            "notarized": true,
            "minimum_macos": "15.0",
            "arch": "arm64"
        });
        let object = value.as_object_mut().expect("object");
        for (key, change) in changes {
            if change.is_null() {
                object.remove(*key);
            } else {
                object.insert((*key).to_owned(), change.clone());
            }
        }
        serde_json::to_vec(&value).expect("json")
    }

    fn parse(changes: &[(&str, serde_json::Value)]) -> Result<Manifest, ManifestError> {
        Manifest::parse(&manifest_json(changes), "15.4.1")
    }

    #[test]
    fn a_valid_manifest_parses() {
        let manifest = parse(&[]).expect("valid");
        assert_eq!(manifest.version, "0.3.1");
        assert_eq!(manifest.build, "e710914");
        assert_eq!(manifest.size, 111_033_131);
        assert_eq!(
            manifest.date_unix,
            parse_utc("2026-10-02T09:30:00Z").unwrap()
        );
        // An unknown field does not break an older app.
        let extra = parse(&[("channel", serde_json::json!("stable"))]);
        assert!(extra.is_ok());
        // The same macOS version as the minimum is enough.
        assert!(Manifest::parse(&manifest_json(&[]), "15.0").is_ok());
    }

    /// Each field that is not in the expected form refuses the manifest.
    #[test]
    fn every_invalid_field_is_refused() {
        use serde_json::json;
        let cases: Vec<(&str, serde_json::Value, ManifestError)> = vec![
            ("version", json!("0.3"), ManifestError::Version),
            ("version", json!("v0.3.1"), ManifestError::Version),
            ("version", json!("0.3.1 "), ManifestError::Version),
            ("version", json!(31), ManifestError::Malformed),
            ("build", json!("e71091"), ManifestError::Build),
            ("build", json!("E710914"), ManifestError::Build),
            ("build", json!("abcdef0"), ManifestError::Build),
            ("commit", json!(&COMMIT[..39]), ManifestError::Commit),
            (
                "commit",
                json!(COMMIT.to_uppercase()),
                ManifestError::Commit,
            ),
            (
                "commit",
                json!(format!("{}g", &COMMIT[..39])),
                ManifestError::Commit,
            ),
            ("date", json!("2026-10-02 09:30:00Z"), ManifestError::Date),
            (
                "date",
                json!("2026-10-02T09:30:00+00:00"),
                ManifestError::Date,
            ),
            ("date", json!("2026-02-30T09:30:00Z"), ManifestError::Date),
            ("date", json!("2026-10-02T24:00:00Z"), ManifestError::Date),
            ("date", json!("2026-10-02"), ManifestError::Date),
            ("file", json!("Apassy.app.zip"), ManifestError::File),
            ("file", json!("../Apassy.dmg"), ManifestError::File),
            ("file", json!("apassy.dmg"), ManifestError::File),
            ("size", json!(0), ManifestError::Size),
            ("size", json!(MAX_IMAGE_BYTES + 1), ManifestError::Size),
            ("size", json!(-1), ManifestError::Malformed),
            ("size", json!("111033131"), ManifestError::Malformed),
            ("sha256", json!("a".repeat(63)), ManifestError::Sha256),
            ("sha256", json!("A".repeat(64)), ManifestError::Sha256),
            ("sha256", json!("z".repeat(64)), ManifestError::Sha256),
            ("notarized", json!(false), ManifestError::NotNotarized),
            ("notarized", json!("true"), ManifestError::Malformed),
            (
                "minimum_macos",
                json!("fifteen"),
                ManifestError::MinimumMacos,
            ),
            (
                "minimum_macos",
                json!("15.0.0.1"),
                ManifestError::MinimumMacos,
            ),
            (
                "minimum_macos",
                json!("16.0"),
                ManifestError::NeedsMacos("16.0".into()),
            ),
            (
                "minimum_macos",
                json!("15.4.2"),
                ManifestError::NeedsMacos("15.4.2".into()),
            ),
            ("arch", json!("x86_64"), ManifestError::Arch),
            ("arch", json!("universal"), ManifestError::Arch),
        ];
        for (field, value, expected) in cases {
            let result = parse(&[(field, value.clone())]);
            assert_eq!(result, Err(expected.clone()), "{field} = {value}");
            assert!(!expected.to_string().is_empty());
        }
        for field in [
            "version",
            "build",
            "commit",
            "date",
            "file",
            "size",
            "sha256",
            "notarized",
            "minimum_macos",
            "arch",
        ] {
            assert_eq!(
                parse(&[(field, serde_json::Value::Null)]),
                Err(ManifestError::Malformed),
                "missing {field}"
            );
        }
        assert_eq!(
            Manifest::parse(b"not json", "15.0"),
            Err(ManifestError::Malformed)
        );
        assert_eq!(
            Manifest::parse(b"[]", "15.0"),
            Err(ManifestError::Malformed)
        );
        let mut large = manifest_json(&[]);
        large.truncate(large.len() - 1);
        large.extend(format!(",\"pad\":\"{}\"}}", "x".repeat(17_000)).as_bytes());
        assert_eq!(
            Manifest::parse(&large, "15.0"),
            Err(ManifestError::TooLarge)
        );
        assert_eq!(
            Manifest::parse(&manifest_json(&[]), "unknown"),
            Err(ManifestError::RunningMacos)
        );
    }

    #[test]
    fn utc_times() {
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc("2026-09-28T10:58:05Z"), Some(1_790_593_085));
        assert!(parse_utc("2024-02-29T00:00:00Z").is_some());
        for bad in [
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-09-28T10:58:60Z",
            "2026-09-28t10:58:05z",
            "2026-09-28T10:58:05.000Z",
            " 2026-09-28T10:58:05Z",
            "",
        ] {
            assert_eq!(parse_utc(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn build_identity_needs_both_parts() {
        let full = BuildIdentity::from_parts("0.3.0", Some(COMMIT), Some("2026-09-28T10:58:05Z"));
        assert_eq!(full.short_commit(), Some("e710914"));
        assert_eq!(full.label(), "0.3.0 (build e710914, 2026-09-28)");
        for (commit, date) in [
            (None, Some("2026-09-28T10:58:05Z")),
            (Some(COMMIT), None),
            (Some("e710914"), Some("2026-09-28T10:58:05Z")),
            (Some(COMMIT), Some("yesterday")),
        ] {
            let identity = BuildIdentity::from_parts("0.3.0", commit, date);
            assert_eq!(identity.build, None, "{commit:?} {date:?}");
            assert_eq!(identity.label(), "0.3.0 (development build)");
        }
        // The identity of this test binary: no build script sets it.
        let current = BuildIdentity::current();
        assert_eq!(current.version, env!("CARGO_PKG_VERSION"));
    }

    fn manifest(version: &str, commit: &str, date: &str) -> Manifest {
        Manifest::parse(
            &manifest_json(&[
                ("version", serde_json::json!(version)),
                ("commit", serde_json::json!(commit)),
                ("build", serde_json::json!(&commit[..7])),
                ("date", serde_json::json!(date)),
            ]),
            "15.0",
        )
        .expect("valid")
    }

    #[test]
    fn a_higher_version_is_newer_and_a_lower_one_is_refused() {
        let running =
            BuildIdentity::from_parts("0.3.0", Some(COMMIT), Some("2026-10-01T00:00:00Z"));
        let dev = BuildIdentity::from_parts("0.3.0", None, None);
        for current in [&running, &dev] {
            assert!(is_newer(
                &manifest("0.3.1", OTHER_COMMIT, "2026-09-01T00:00:00Z"),
                current
            ));
            assert!(is_newer(
                &manifest("1.0.0-rc.1", OTHER_COMMIT, "2026-10-02T00:00:00Z"),
                current
            ));
            // A downgrade, also with a later date.
            assert!(!is_newer(
                &manifest("0.2.9", OTHER_COMMIT, "2026-12-01T00:00:00Z"),
                current
            ));
            assert!(!is_newer(
                &manifest("0.3.0-rc.2", OTHER_COMMIT, "2026-12-01T00:00:00Z"),
                current
            ));
        }
    }

    /// Another build of the same version never updates the app: only a higher
    /// version number does.
    #[test]
    fn the_same_version_is_never_newer() {
        let running =
            BuildIdentity::from_parts("0.3.0", Some(COMMIT), Some("2026-10-01T00:00:00Z"));
        let dev = BuildIdentity::from_parts("0.3.0", None, None);
        for current in [&running, &dev] {
            // Another commit, published later.
            assert!(!is_newer(
                &manifest("0.3.0", OTHER_COMMIT, "2026-10-05T00:00:00Z"),
                current
            ));
            // The same commit: this build.
            assert!(!is_newer(
                &manifest("0.3.0", COMMIT, "2026-10-05T00:00:00Z"),
                current
            ));
        }
        // Build metadata does not make a version newer.
        assert!(!is_newer(
            &manifest("0.3.0+2", OTHER_COMMIT, "2026-09-01T00:00:00Z"),
            &running
        ));
    }
}
