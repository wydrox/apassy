//! A reduced key derivation for test vaults (docs/operations/checks.md, "Test vault KDF").
//!
//! Only the `insecure-test-kdf` feature compiles this module. CI tests with
//! `--all-features`; no shipped build names the feature (the last test below reads the
//! release build commands). With the feature, a vault file uses [`REDUCED_KDF_ITER`]
//! PBKDF2 iterations only when both of these hold:
//!
//! - The build has debug assertions. Without them, [`REDUCED_KDF_ITER`] is the SQLCipher
//!   4 default, so a `--release` build never reduces the KDF.
//! - A directory above the file has a name that starts with [`TEST_DIR_PREFIX`], the
//!   prefix of `tempfile::TempDir`. A vault in the data directory of the app, or in a
//!   test directory with another prefix, keeps 256,000 iterations.
//!
//! The open check (`verify_cipher_defaults`) requires the count of the path: a test
//! vault refuses the SQLCipher 4 default, and any other vault refuses the reduced count.

use std::fs::File;
use std::io::Read;
use std::num::NonZeroU32;
use std::path::Path;

use rusqlite::Connection;
use zeroize::Zeroizing;

use super::SQLCIPHER4_KDF_ITER;

/// The PBKDF2 iterations of a test vault: the count that SQLCipher uses for the HMAC
/// key. The key of a test vault is as strong as its passphrase, nothing more.
#[cfg(debug_assertions)]
pub const REDUCED_KDF_ITER: i64 = 2;
/// A build without debug assertions keeps the SQLCipher 4 count, also with the feature.
#[cfg(not(debug_assertions))]
pub const REDUCED_KDF_ITER: i64 = SQLCIPHER4_KDF_ITER;

const _: () = assert!(cfg!(debug_assertions) || REDUCED_KDF_ITER == SQLCIPHER4_KDF_ITER);

/// The name prefix of a `tempfile::TempDir` (`tempfile::tempdir()`).
pub const TEST_DIR_PREFIX: &str = ".tmp";

/// The SQLCipher salt at the start of a vault file, and the AES-256 key size.
const SALT_BYTES: usize = 16;
const KEY_BYTES: usize = 32;

/// The PBKDF2 iterations of the vault file at `path`.
pub fn kdf_iter_for(path: &Path) -> i64 {
    let in_test_dir = path.ancestors().skip(1).any(|dir| {
        dir.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(TEST_DIR_PREFIX))
    });
    if in_test_dir {
        REDUCED_KDF_ITER
    } else {
        SQLCIPHER4_KDF_ITER
    }
}

/// The PBKDF2 iterations of the main database of `conn`.
pub(super) fn kdf_iter(conn: &Connection) -> i64 {
    conn.path()
        .map_or(SQLCIPHER4_KDF_ITER, |path| kdf_iter_for(Path::new(path)))
}

/// Give a raw SQLCipher connection the KDF of its vault file. Call it after `PRAGMA key`
/// and before the first read. A file with the SQLCipher 4 count gets no statement.
pub fn match_vault_kdf(conn: &Connection) -> rusqlite::Result<()> {
    let iterations = kdf_iter(conn);
    if iterations != SQLCIPHER4_KDF_ITER {
        conn.pragma_update(None, "kdf_iter", iterations)?;
    }
    Ok(())
}

/// The key of `ATTACH ... KEY` for the copy at `path`, or `None` for the passphrase.
///
/// SQLCipher derives the key of an attached file with its process-wide default count,
/// not with the count of the connection. A process-wide change would reach the other
/// tests of the process, `sqlcipher_probe` too. So a copy with the reduced count gets a
/// raw key: PBKDF2-HMAC-SHA512 of `passphrase` with the salt at the start of the file,
/// as SQLCipher derives it. SQLCipher derives the HMAC key from it in the same way.
pub(super) fn attach_key(path: &Path, passphrase: &str) -> Option<Zeroizing<String>> {
    let iterations = kdf_iter_for(path);
    if iterations == SQLCIPHER4_KDF_ITER {
        return None;
    }
    let iterations = NonZeroU32::new(u32::try_from(iterations).ok()?)?;
    let mut salt = [0u8; SALT_BYTES];
    // A short or missing file gets the passphrase, as in a build without the feature.
    File::open(path).ok()?.read_exact(&mut salt).ok()?;
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        iterations,
        &salt,
        passphrase.as_bytes(),
        &mut key[..],
    );
    Some(raw_key(&key[..], &salt))
}

/// SQLCipher raw key text with a salt: `x'<key hex><salt hex>'`.
fn raw_key(key: &[u8], salt: &[u8]) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = Zeroizing::new(String::with_capacity(3 + 2 * (key.len() + salt.len())));
    text.push_str("x'");
    for byte in key.iter().chain(salt) {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text.push('\'');
    text
}

#[cfg(test)]
mod tests {
    use super::super::{OPEN_READONLY, Vault, require_pragma_i64};
    use super::*;

    const PASS: &str = "synthetic-test-kdf-passphrase";

    /// A test directory whose vault files keep the SQLCipher 4 count.
    fn real_kdf_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("apassy-real-kdf-")
            .tempdir()
            .unwrap()
    }

    fn vault_in(dir: &Path) -> Vault {
        let mut vault = Vault::create(&dir.join("kdf.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
    }

    /// A raw read-only connection. `kdf_iter` is set after the key; `None` keeps the
    /// SQLCipher 4 default.
    fn raw_reads(path: &Path, key: &str, kdf_iter: Option<i64>) -> bool {
        let conn = Connection::open_with_flags(path, OPEN_READONLY).unwrap();
        conn.pragma_update(None, "key", key).unwrap();
        if let Some(iterations) = kdf_iter {
            conn.pragma_update(None, "kdf_iter", iterations).unwrap();
        }
        conn.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .is_ok()
    }

    #[test]
    fn only_a_file_below_a_tempfile_directory_gets_the_reduced_count() {
        for path in [
            "/private/var/folders/x/T/.tmpAbC123/vault.db",
            "/tmp/.tmpAbC123/home/Library/Application Support/Apassy/vault.db",
        ] {
            assert_eq!(kdf_iter_for(Path::new(path)), REDUCED_KDF_ITER, "{path}");
        }
        for path in [
            "/Users/owner/Library/Application Support/Apassy/vault.db",
            "/tmp/apassy-real-kdf-AbC123/vault.db",
            // The file name itself does not count, only a directory above it.
            "/tmp/.tmpAbC123",
            "vault.db",
            "",
        ] {
            assert_eq!(kdf_iter_for(Path::new(path)), SQLCIPHER4_KDF_ITER, "{path}");
        }
    }

    #[test]
    fn a_vault_outside_a_tempfile_directory_has_the_sqlcipher4_kdf() {
        let dir = real_kdf_dir();
        let vault = vault_in(dir.path());
        let conn = vault.conn_ref().unwrap();
        assert_eq!(require_pragma_i64(conn, "kdf_iter").unwrap(), 256_000);
        // A plain SQLCipher 4 connection opens the file; the reduced count does not.
        assert!(raw_reads(&vault.path, PASS, None));
        if cfg!(debug_assertions) {
            assert!(!raw_reads(&vault.path, PASS, Some(REDUCED_KDF_ITER)));
        }
    }

    #[test]
    fn a_test_vault_has_the_reduced_kdf_only_with_debug_assertions() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(dir.path());
        let conn = vault.conn_ref().unwrap();
        assert_eq!(
            require_pragma_i64(conn, "kdf_iter").unwrap(),
            REDUCED_KDF_ITER
        );
        assert!(raw_reads(&vault.path, PASS, Some(REDUCED_KDF_ITER)));
        if cfg!(debug_assertions) {
            assert_eq!(REDUCED_KDF_ITER, 2);
            assert!(!raw_reads(&vault.path, PASS, None));
        } else {
            assert_eq!(REDUCED_KDF_ITER, SQLCIPHER4_KDF_ITER);
            assert!(raw_reads(&vault.path, PASS, None));
        }
    }

    #[test]
    fn the_attach_key_is_the_key_that_sqlcipher_derives() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = vault_in(dir.path());
        vault.lock().unwrap();
        let key = attach_key(&vault.path, PASS);
        if cfg!(debug_assertions) {
            let key = key.expect("a raw key for a test vault");
            assert_eq!(key.len(), 3 + 2 * (KEY_BYTES + SALT_BYTES));
            assert!(raw_reads(&vault.path, &key, None));
            let wrong = attach_key(&vault.path, "synthetic-test-kdf-wrong").unwrap();
            assert!(!raw_reads(&vault.path, &wrong, None));
        } else {
            assert!(key.is_none());
        }
        let real = real_kdf_dir();
        let real_vault = vault_in(real.path());
        assert!(attach_key(&real_vault.path, PASS).is_none());
    }

    /// Every shipped artifact comes from a release build that names its features. None
    /// names this feature or `--all-features`, and no profile turns on debug assertions.
    #[test]
    fn no_shipped_build_enables_the_reduced_kdf() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let read = |name: &str| std::fs::read_to_string(root.join(name)).unwrap();
        let feature = "insecure-test-kdf";
        let manifest = read("Cargo.toml");
        let uses: Vec<&str> = manifest
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#') && line.contains(feature))
            .collect();
        assert_eq!(uses, [format!("{feature} = []")], "{uses:?}");
        for name in [
            "Cargo.toml",
            "ios/ApassyCore/Cargo.toml",
            "crates/apassy-relay/Cargo.toml",
            ".cargo/config.toml",
        ] {
            assert!(!read(name).contains("debug-assertions"), "{name}");
        }
        for name in [
            "ios/ApassyCore/Cargo.toml",
            "crates/apassy-relay/Cargo.toml",
        ] {
            assert!(!read(name).contains(feature), "{name}");
        }
        for name in [
            ".github/workflows/ci.yml",
            ".github/workflows/relay-image.yml",
            "crates/apassy-relay/Dockerfile",
            "scripts/build-app.sh",
            "scripts/build-ios-core.sh",
        ] {
            let text = read(name);
            // `build-ios-core.sh` passes `--profile "$profile"`, release by default.
            let builds: Vec<&str> = text
                .lines()
                .filter(|line| {
                    line.contains("cargo build")
                        && (line.contains("--release") || line.contains("--profile"))
                })
                .collect();
            assert!(!builds.is_empty(), "{name} has no release cargo build");
            for line in builds {
                assert!(
                    !line.contains("--all-features") && !line.contains(feature),
                    "{name}: {line}"
                );
            }
        }
    }
}
