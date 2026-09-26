# Review: native storage dependencies (V1)

Date: 2026-09-26.
Status: review complete for goal item V1. No license blocks distribution. No known advisory is reachable in the storage path. One RustSec advisory applies to the TLS stack (rustls). The fix is a version bump.
Scope: SQLCipher, SQLite, OpenSSL, rusqlite, and libsqlite3-sys, at the versions in `Cargo.lock` at commit `768bbf3`. Notices: [licenses/THIRD-PARTY-NOTICES.md](../../licenses/THIRD-PARTY-NOTICES.md).
Related: [ADR 0002](../adr/0002-encrypted-state-probe.md) §4 to §7, [ADR 0003](../adr/0003-passphrase-vault.md), [ADR 0010](../adr/0010-closing-open-decisions.md), [key-memory review](key-memory.md).

## 1. Method

Host: macOS 27.0 (build 26A428), arm64, Rust 1.97.0. SIP is on.

- `cargo fetch --locked` got the sources. The SHA-256 of each `.crate` file in `~/.cargo/registry/cache/` is equal to the checksum in `Cargo.lock` (16 crates checked, table in §2).
- I read the build scripts, the license files, and the bundled C sources in `~/.cargo/registry/src/`.
- I compared the bundled sources with the upstream releases (§3).
- A throwaway program in `/tmp` with the same pinned rusqlite and the Apassy `Cargo.lock` read the runtime values (§5). It used a synthetic key and synthetic data only.
- `cargo test --locked --features storage-probe --test sqlcipher_probe -- --test-threads=1` passed: 12 tests, 0 failed, exit code 0.
- `cargo-audit` 0.22.2 checked `Cargo.lock` against the RustSec database (§6). I installed it in a temporary `CARGO_HOME` in `/tmp`. The repository toolchain did not change.
- I read the upstream security pages of OpenSSL, SQLCipher, and SQLite on 2026-09-26 (§6).

## 2. Versions and checksums

| Crate | Version | `Cargo.lock` checksum (SHA-256) | Declared license |
| --- | --- | --- | --- |
| rusqlite | 0.40.2 | `23f2a97da3e3873c73cb2a2e71b35c40ff95e0b1eefa8d72d8499a6928c3b5b3` | MIT |
| libsqlite3-sys | 0.38.2 | `f1d20bef17f513b9b3004532233187769cd072d790971f4e4da0e346eb6401e8` | MIT |
| openssl-sys | 0.9.117 | `b47e7e6bb2c38cd930d25a23b40fa52e068c10e85f3e03a7f5ba5aaca5713695` | MIT |
| openssl-src | 300.6.1+3.6.3 | `46eb8fb9fb3b61ce1c0f8a026c4c1a0714d3a9e138e7fbde78753ce2babc3846` | MIT/Apache-2.0 |
| cc (build) | 1.4.6 | `a3eb0f42d6c360dc3f8a821f6bf2fdea7f72bfd36b3076eb0e6d1e9e0752fff4` | MIT OR Apache-2.0 |
| rustls | 0.23.44 | `6725596c3f2c3a0aef021139e145d4eafe314a6623e4680ca83852b2c67ab2ba` | Apache-2.0 OR ISC OR MIT |
| ring | 0.17.14 | `a4689e6c2294d81e88dc6261c768b63bc4fcdb852be6d1352498b114f61383b7` | Apache-2.0 AND ISC |
| rustls-webpki | 0.103.15 | `f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2` | ISC |
| rustls-platform-verifier | 0.7.0 | `26d1e2536ce4f35f4846aa13bff16bd0ff40157cdb14cc056c7b14ba41233ba0` | MIT OR Apache-2.0 |
| rustls-pki-types | 1.15.1 | `2f4925028c7eb5d1fcdaf196971378ed9d2c1c4efc7dc5d011256f76c99c0a96` | MIT OR Apache-2.0 |
| webpki-root-certs | 1.0.9 | `b96554aa2acc8ccdb7e1c9a58a7a68dd5d13bccc69cd124cb09406db612a1c9b` | CDLA-Permissive-2.0 (not linked on macOS) |
| zeroize | 1.9.0 | `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` | Apache-2.0 OR MIT |
| eframe | 0.36.2 | `55ad41fac6e3149abb4866e93df37dbd33baa95db525c3368c944584e95a5dc2` | MIT OR Apache-2.0 |
| egui | 0.36.2 | `dc938cc27cd911415e1e4d151bc56ff9df063d8db081374e87aeb805ea74b2ba` | MIT OR Apache-2.0 |
| epaint | 0.36.2 | `a0ec0308dc23130fc1a7d4623a8534c2ed069c6dc84e258ee4f3de99615aa1a3` | MIT OR Apache-2.0 |
| epaint_default_fonts | 0.36.2 | `773fa9c96dd0dbef887e39d0ed6177f141cce4d68e6041df77570aa3702dfa13` | (MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0 |

Bundled upstream code:

| Upstream | Version | Where it is | Measured at runtime |
| --- | --- | --- | --- |
| SQLCipher Community Edition | 4.14.0 (`CIPHER_VERSION_NUMBER`, `sqlite3.c:109519`) | `libsqlite3-sys-0.38.2/sqlcipher/sqlite3.c` (amalgamation) | `PRAGMA cipher_version` = `4.14.0 community` |
| SQLite (base of SQLCipher) | 3.51.3, source ID `2026-03-13 10:38:09 737ae4a3…` | same file | `sqlite_version()` = `3.51.3` |
| OpenSSL | 3.6.3, released 9 Jun 2026 (`openssl/VERSION.dat`) | `openssl-src-300.6.1+3.6.3/openssl/` | `PRAGMA cipher_provider_version` = `OpenSSL 3.6.3 9 Jun 2026` |

libsqlite3-sys also contains a plain SQLite 3.53.2 in `sqlite3/`. The `bundled-sqlcipher` feature does not compile it.

## 3. Where the bundled C sources come from

SQLCipher:

- The rusqlite project generates the amalgamation with `libsqlite3-sys/upgrade_sqlcipher.sh` (git commit `e88f112b`, the commit in `.cargo_vcs_info.json`). The crate excludes the script. I read it in the rusqlite repository.
- The script downloads `https://github.com/sqlcipher/sqlcipher/archive/v4.14.0.tar.gz`, runs `./configure` and `make sqlite3.c`, and copies `sqlite3.c`, `sqlite3.h`, and `sqlite3ext.h`. It does not check a checksum of the archive.
- Spot check: I downloaded the same archive (SHA-256 `67fb27e967a4a6968c0905691c89c908e7250dddc581b887c19ef981c737e473`, a GitHub-generated archive). I compared the SQLCipher files with the sections in the bundled amalgamation. `crypto_openssl.c`, `crypto_cc.c`, `crypto_libtomcrypt.c`, and `sqlcipher.h` are identical. `sqlcipher.c` differs only by the inlined `sqlcipher.h` and by 11 `SQLITE_API` prefixes that the amalgamation tool adds.
- I did not regenerate the full amalgamation. The SQLite core part and the SQLCipher changes to the SQLite core are not compared line by line.

OpenSSL:

- `openssl-src` contains the OpenSSL source tree. Its build script runs OpenSSL `Configure` and `make` in `OUT_DIR`.
- I downloaded `openssl-3.6.3.tar.gz` from the OpenSSL GitHub release. Its SHA-256 `243a86649cf6f23eeb6a2ff2456e09e5d77dd9018a54d3d96b0c6bdd6ba6c7f1` is equal to the value in the published `.sha256` files on GitHub and on `www.openssl.org`.
- All 2425 files of the crate's `openssl/` directory are byte-identical to the release. Three crate files are not in the release: `.pre-commit-config.yaml`, `.codespellrc`, and `.clang-format`. The build does not use them. The crate omits tests, docs, and fuzz corpora.

## 4. Licenses and obligations

| Component | License | Obligation for a signed macOS app |
| --- | --- | --- |
| SQLCipher | BSD-3-Clause (Zetetic LLC) | Reproduce the copyright notice, the conditions, and the disclaimer in the documentation or other materials of the app. Do not use the name "Zetetic" to endorse Apassy. |
| SQLite | Public domain (blessing) | None. Attribution is a courtesy. |
| OpenSSL 3.6.3 | Apache-2.0 | Give a copy of the license. Keep the notices in source that you distribute. State changes if you change files. OpenSSL 3.6.3 has no `NOTICE` file, so section 4(d) adds nothing. |
| rusqlite, libsqlite3-sys, openssl-sys | MIT | Include the copyright notice and the license text. |
| openssl-src | MIT or Apache-2.0 | Build script only. Its Rust code is not in the binary. The OpenSSL code that it builds is covered above. |

All licenses permit use in a closed, signed, and notarized app. None has a copyleft term. None requires source distribution.
The TLS stack and eframe/egui licenses are in the notices file. They are MIT, ISC, BSD-3-Clause, Apache-2.0, OFL-1.1, and the Ubuntu Font Licence 1.0. The embedded egui fonts need their license texts in the bundle.

Patent notices:

- Apache-2.0 gives a patent license from each contributor (section 3). SQLCipher (BSD-3-Clause) and SQLite give no patent license.
- The only patent text in the OpenSSL 3.6.3 source is a prior-art comment in `crypto/ec/ec2_oct.c`. SQLCipher does not use that code. SQLCipher and SQLite have no patent notice.
- The algorithms that SQLCipher uses (AES-256-CBC, HMAC-SHA512, PBKDF2) have no known patent restriction.

Result: no license issue blocks distribution. The app bundle must ship `licenses/` (goal item A1).

## 5. Build configuration that matters for security

### 5.1 rusqlite and libsqlite3-sys features

`cargo tree --all-features -e features` shows these features only:

- rusqlite: `bundled`, `bundled-sqlcipher`, `bundled-sqlcipher-vendored-openssl`, `modern_sqlite`.
- libsqlite3-sys: `bundled`, `bundled-sqlcipher`, `bundled-sqlcipher-vendored-openssl`, `bundled_bindings`, `cc`, `openssl-sys`, and the default `min_sqlite_version_3_34_1` (with `pkg-config` and `vcpkg`, not used by the bundled build).

The rusqlite features `load_extension`, `backup`, `loadable_extension`, `functions`, `hooks`, `trace`, and `session` are off.

### 5.2 SQLCipher compile flags

From `libsqlite3-sys-0.38.2/build.rs:151-179`. `PRAGMA compile_options` returned 54 options that agree with the flags.

| Flag | Effect | Assessment |
| --- | --- | --- |
| `SQLITE_HAS_CODEC` | Encryption codec on | Required. |
| `SQLCIPHER_CRYPTO_*` | Not set. `sqlite3.c:109506-109510` then selects `SQLCIPHER_CRYPTO_OPENSSL`. | Correct. Runtime `cipher_provider` = `openssl`. The vault checks this value (`src/vault/mod.rs:650`). |
| `SQLITE_TEMP_STORE=2` | Temporary tables in memory unless a PRAGMA selects a file | Good. The vault also sets `temp_store=MEMORY` and checks it (`src/vault/mod.rs:584-588`). |
| `SQLITE_ENABLE_LOAD_EXTENSION=1` | Sets the `SQLITE_LoadExtension` flag on each new connection (`sqlite3.c:194051`). The C API `sqlite3_load_extension` is then open. | Risk only for code that calls the C API. Apassy cannot: `forbid(unsafe_code)` and no rusqlite `load_extension` feature. The SQL function `load_extension()` needs a second flag. The measured result of `SELECT load_extension(...)` is `not authorized`. |
| `SQLITE_USE_URI` | File names that start with `file:` are URIs for every open | The vault passes only canonical absolute paths, so a `file:` name does not occur. The comment in `src/vault/mod.rs:7-8` ("URI filename semantics are not enabled") is not correct for this build. SQLCipher reads `key`, `hexkey`, and `textkey` URI parameters. |
| `SQLITE_ENABLE_FTS3`, `FTS5`, `RTREE`, `DBSTAT_VTAB`, `STAT4`, `SOUNDEX`, `JSON1` | Extra SQL features | Attack surface for untrusted SQL only. Apassy runs fixed SQL with bound parameters. |
| `SQLITE_ENABLE_API_ARMOR`, `SQLITE_THREADSAFE=1`, `SQLITE_DEFAULT_FOREIGN_KEYS=1` | Defensive API checks, thread safety | Good. |
| (defaults) `DEFAULT_MMAP_SIZE=0`, `SYSTEM_MALLOC`, `MAX_ATTACHED=10` | No memory-mapped I/O | Good. |

Runtime values (measured): `cipher_memory_security` = 0 (off), `cipher_store_pass` = 0 (SQLCipher erases its passphrase copy after key derivation). The vault checks page size 4096, `kdf_iter` 256000, `HMAC_SHA512`, `PBKDF2_HMAC_SHA512`, HMAC on, and plaintext header 0 at each open (`src/vault/mod.rs:635-655`).

SQLCipher logs WARN and higher to the macOS unified log by default (`sqlite3.c:109862-109879`). Its PRAGMA log line skips `key` and `rekey` (`sqlite3.c:112002`).

### 5.3 OpenSSL build

`openssl-src` (`src/lib.rs:197-252`) runs `Configure darwin64-arm64-cc` with `no-shared no-module no-tests no-comp no-zlib no-zlib-dynamic no-ssl3 no-md2 no-rc5 no-weak-ssl-ciphers no-camellia no-idea no-seed`.

- openssl-sys 0.9.117 turns on the `openssl-src` feature `legacy` (`openssl-sys/Cargo.toml:78-81`). So `no-legacy` is not passed, and `libcrypto.a` contains the legacy provider (`ossl_legacy_provider_init`). OpenSSL does not load it unless code or a configuration file asks for it.
- DSO support is on (`DSO_load` is in `libcrypto.a`; `no-dso` is not passed).
- The built library records `OPENSSLDIR: "/usr/local/ssl"` and a `MODULESDIR` in the build directory under `target/`. Both are in the binary.
- OpenSSL 3 loads its configuration file when a provider is first fetched (`crypto/provider_core.c:1538`). The path is `$OPENSSL_CONF`, or `/usr/local/ssl/openssl.cnf`. A configuration file can load a provider module (`OPENSSL_MODULES` or `MODULESDIR`) through DSO. On the review host, `/usr/local` is `root:wheel 0755` and `/usr/local/ssl` does not exist.
- Consequence: a process that can set the environment of Apassy can make OpenSSL load a module. Hardened runtime with library validation stops that load. I measured that hardened runtime blocks `DYLD_INSERT_LIBRARIES` ([key-memory review](key-memory.md) §4). I did not test an OpenSSL module load.
- SQLCipher calls only `EVP_CipherInit_ex`, `EVP_CipherUpdate`, `EVP_CipherFinal_ex` (AES-256-CBC, no padding), `EVP_MAC` HMAC, `PKCS5_PBKDF2_HMAC`, `RAND_bytes`, and `RAND_add` (`crypto_openssl.c` section, `sqlite3.c:113702-114121`).
- The linked test binary has no `SSL_*` function. Only two helper symbols from CMP and QUIC source files are linked.

### 5.4 Build environment variables

These variables change the native build. A release build must not set them unless a checked-in configuration sets them:

- `OPENSSL_NO_VENDOR` (not `0`): openssl-sys links the system OpenSSL instead of 3.6.3.
- `LIBSQLITE3_SYS_USE_PKG_CONFIG`: libsqlite3-sys links a system SQLite without SQLCipher. The vault then fails closed, because `cipher_version` is empty (`src/vault/mod.rs:592-602`).
- `LIBSQLITE3_FLAGS`, `SQLITE_MAX_VARIABLE_NUMBER`, `SQLITE_MAX_EXPR_DEPTH`, `SQLITE_MAX_COLUMN`: extra C flags for SQLCipher.
- `OPENSSL_DIR`, `OPENSSL_LIB_DIR`, `OPENSSL_INCLUDE_DIR`, `OPENSSL_STATIC`, `OPENSSL_CONFIG_DIR` (sets `OPENSSLDIR`), `OPENSSL_SRC_PERL`, `PERL`, `CC`, `CFLAGS`.

The review host had none of these set.

Build note: on this host, `clang` with the default Command Line Tools SDK (`MacOSX27.0.sdk`) failed to link a C program (`libSystem.tbd: unknown architecture arm64e.x1-macos`). `SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk` worked. The Apassy build itself worked without `SDKROOT`. The release build script (A1) must record the Xcode and SDK versions.

## 6. Known advisories

### 6.1 RustSec

`cargo-audit` 0.22.2, database commit `e2111519ba6d`, updated 2026-09-25, 1271 advisories, 371 lockfile packages:

| Advisory | Crate | Title | Fix | Assessment |
| --- | --- | --- | --- | --- |
| RUSTSEC-2026-0285 (GHSA-2mjx-qc3c-rqvc), 2026-09-14 | rustls 0.23.44 | TLS 1.3 handshake messages incorrectly accepted across encryption level boundaries | rustls `>= 0.23.45` (published 2026-09-14) | Low (CVSS C:L). The handshake transcript stays authenticated. Apassy uses rustls only for connector HTTPS, and there are no real connectors in this goal. Bump the pin to `=0.23.45`. |

No advisory applies to rusqlite, libsqlite3-sys, openssl-sys, openssl-src, ring, rustls-webpki, zeroize, or eframe/egui at these versions.

Coverage gap: the RustSec database has no `openssl-src` advisory after February 2023. It has no `libsqlite3-sys` advisory after 2022. A clean `cargo audit` result does not cover the bundled OpenSSL or SQLCipher. The update policy (§8) adds the upstream sources.

### 6.2 OpenSSL upstream

OpenSSL 3.6.4 (25 Aug 2026) fixes 9 issues. Two earlier advisories (5 Aug and 13 Aug 2026) also have their fix in 3.6.4. The bundled 3.6.3 has all 11. The 18 issues of the 9 Jun 2026 advisory are fixed in 3.6.3.

| CVE | Severity | Component | Reachable in Apassy |
| --- | --- | --- | --- |
| CVE-2026-18798 | Moderate | QUIC server double free | No. No QUIC. |
| CVE-2026-63072 | Moderate | CMS key unwrapping | No. No CMS. |
| CVE-2026-63076 | Moderate | CMP server | No. No CMP. |
| CVE-2026-14457 | Low | TLS raw public key server | No. No OpenSSL TLS (rustls does TLS). |
| CVE-2026-54874 | Low | DTLS | No. |
| CVE-2026-63073, CVE-2026-63074 | Low | CMP | No. |
| CVE-2026-63075 | Low | QUIC | No. |
| CVE-2026-75803 | Low | AEAD forgery with empty ciphertext through `EVP_Cipher()` (ChaCha20-Poly1305, AES-OCB) | No. SQLCipher uses AES-256-CBC with `EVP_CipherUpdate`/`EVP_CipherFinal_ex`, not `EVP_Cipher()`, and checks its own HMAC-SHA512. |
| CVE-2026-14456 (13 Aug) | Low | QUIC server | No. |
| CVE-2026-54876 (5 Aug) | Low | OCSP check in X.509 verification | No. macOS Security framework verifies connector certificates. |

No crate release carries OpenSSL 3.6.4. The `openssl-src` 300.x line ends at `300.6.1+3.6.3`. The next release is `400.0.1+4.0.2` (OpenSSL 4.0.2). openssl-sys 0.9.117 (the latest) accepts only `openssl-src` 300.x (`openssl-sys/Cargo.toml:78-79`).

### 6.3 SQLCipher and SQLite upstream

SQLCipher 4.19.0 (2026-09-08) is the latest 4.x release. The bundled 4.14.0 is five minor releases behind. libsqlite3-sys 0.38.2 is the latest crate release, so no crate has a newer SQLCipher.

| Release | Security content | Reachable in Apassy |
| --- | --- | --- |
| 4.15.0 (2026-04-28) | Defensive mode bypass in `sqlcipher_export` (low) | No. Apassy does not call `sqlcipher_export`. It runs no untrusted SQL. |
| 4.19.0 (2026-09-08) | Two low issues: `sqlcipher_export` escaping and invalid `hexkey` URI parameter | No. Apassy opens absolute paths, not URIs, and does not call `sqlcipher_export`. |
| 4.16.0 to 4.18.0 | SQLite base updates to 3.53.x and fixes without a security note | See the SQLite row below. |
| 5.0.0-beta (2026-09-15) | New format (AES-256-GCM, VFS shims). Not compatible with 4.x by default. | Not a candidate. A move needs an ADR and a migration (goal item V6). |

SQLite CVEs fixed after 3.51.3 ([sqlite.org/cves.html](https://www.sqlite.org/cves.html)): CVE-2026-11822 and CVE-2026-11824 (fixed in 3.53.2) need arbitrary SQL, defensive mode off, and FTS5. CVE-2025-70873 (fixed in 3.52.0) is in the zipfile extension, which this build does not include. Apassy runs no untrusted SQL. An attacker without the key cannot make a database page that passes the SQLCipher HMAC. So none is reachable.

Result: no unpatched advisory is reachable in the storage path. The bundled OpenSSL and SQLCipher are behind upstream, and the Rust crates do not offer newer versions yet. §8 defines when this lag needs action.

## 7. Recommended build hardening

Each item is a small change. Other workers own the files.

1. Bump `rustls` to `=0.23.45` in `Cargo.toml` (RUSTSEC-2026-0285). Check with `cargo audit` and `cargo test --locked --features vault`.
2. Remove extension loading and URI names from the C build. Add a checked-in `.cargo/config.toml` with `[env] LIBSQLITE3_FLAGS = "-USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION -USQLITE_USE_URI"`. I tested these flags in the throwaway program. The build links. `compile_options` shows `OMIT_LOAD_EXTENSION` and no `ENABLE_LOAD_EXTENSION` or `USE_URI`. `load_extension()` is then `no such function`. The key, the cipher values, and a wrong-key failure were unchanged. The [key-memory review](key-memory.md) (fix F2) adds `-DSQLITE_DEFAULT_LOOKASIDE=0,0`. I tested the four flags together with the same result. Then correct the comment in `src/vault/mod.rs:7-8`. Test: add a `PRAGMA compile_options` check to `tests/sqlcipher_probe.rs`.
3. Turn on defensive mode for each vault connection: `conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)` in `src/vault/mod.rs` `apply_session_pragmas`. rusqlite 0.40.2 has this without an extra feature. Test: `db_config(SQLITE_DBCONFIG_DEFENSIVE)` returns true after unlock.
4. Sign the release app with hardened runtime and library validation, without `com.apple.security.get-task-allow` and without `com.apple.security.cs.disable-library-validation` (goal item A1). This blocks injected dylibs and OpenSSL provider modules that are not signed by Apple or the same team.
5. Consider `no-dso` for OpenSSL. A direct dependency `openssl-src = { version = "=300.6.1", features = ["no-dso"] }` under the `vault` feature enables it through Cargo feature unification. No new package is added. I did not test this. Test: `nm libcrypto.a` has no `DSO_load`, and the probe and vault tests pass.

## 8. Update policy

Owner: the Apassy owner. The owner can give the task to a worker, but the owner accepts each update.

### 8.1 Checks

| Check | How often | Source |
| --- | --- | --- |
| `cargo audit` on `Cargo.lock` | Each CI run and each week | RustSec database |
| OpenSSL advisories | Each month, and on each post to openssl-announce | <https://openssl-library.org/news/vulnerabilities/> |
| SQLCipher releases | Each month | <https://github.com/sqlcipher/sqlcipher/releases> and the Zetetic blog |
| SQLite CVEs | Each month | <https://www.sqlite.org/cves.html> |
| New crate versions of rusqlite, libsqlite3-sys, openssl-sys, openssl-src, rustls, ring | Each month | crates.io |

The CI workflow does not run `cargo audit` now. Add a step with a pinned `cargo-audit` version (a change to `.github/workflows/ci.yml`).

### 8.2 Triggers and time limits

| Trigger | Action | Time limit |
| --- | --- | --- |
| Advisory with a reachable path in Apassy (for example, OpenSSL AES, HMAC, PBKDF2, SHA-2, RAND, EVP cipher or MAC code; the SQLCipher codec or key handling; SQLite code that a crafted but correctly keyed file or Apassy's own SQL can reach) | Update. If no crate release exists, use a `[patch.crates-io]` fork with the fixed upstream source, and record it in an ADR. | Critical or High: 3 days. Moderate or Low: 30 days. |
| Advisory that is not reachable | Record the assessment in §6 of this file. | 30 days |
| New rusqlite/libsqlite3-sys release with a new SQLCipher base | Update in the next release of Apassy. | 90 days |
| Any RustSec advisory for a crate in `Cargo.lock` | Assess. Update if a fix exists. | 7 days |
| SQLCipher major version (5.x) | Do not update. Write an ADR first. It changes the file format. | Not applicable |

### 8.3 Verification after an update

1. `cargo update -p <crate> --precise <version>`. Review the `Cargo.lock` diff. Each changed package must be one that you expect.
2. `cargo fetch --locked`. Check that the `Cargo.lock` checksums are the crates.io checksums.
3. For a new SQLCipher or OpenSSL: record the bundled versions (`CIPHER_VERSION_NUMBER` in `sqlcipher/sqlite3.c`, `openssl/VERSION.dat`). Compare the OpenSSL tree with the release tarball and its published SHA-256, as in §3.
4. Read the new license files. Compare them with `licenses/`. Update `licenses/` and `THIRD-PARTY-NOTICES.md` when a text changes.
5. Run these commands. Each must pass with exit code 0:

   ```
   cargo test --locked --features storage-probe --test sqlcipher_probe -- --test-threads=1
   cargo test --locked --offline --features vault --lib --test vault_lifecycle --test vault_passphrase -- --test-threads=1
   cargo test --offline --locked --all-features --all-targets -- --test-threads=1
   cargo clippy --offline --locked --all-features --all-targets -- -D warnings
   cargo audit
   ```

6. Check that the probe values stay the same: `cipher_version` has the new version, `cipher_provider` = `openssl`, and page size, KDF, HMAC, and plaintext header size are the SQLCipher 4 values. An existing vault from the previous version must open (goal item V6).
7. Update §2 and §6 of this file.

## 9. What I could not check

- I did not regenerate the SQLCipher amalgamation. The SQLite core part is not compared with upstream.
- I did not audit the OpenSSL or SQLCipher C code for defects. This review checks provenance, configuration, licenses, and published advisories.
- I did not test an OpenSSL configuration file or module load. I did not test `no-dso`.
- The SQLCipher download in §3 is a GitHub-generated archive. Zetetic does not publish a checksum for it.
- The notices file covers the named stacks, not all 371 packages.
