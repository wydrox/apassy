# Development checks

Date: 2026-09-16.
Status: local check commands and a configured CI workflow. This is not a product release.
This document does not complete P1 or MVP.
See [vault verification](vault-verification.md) and [foundation verification](foundation-verification.md) for measured local results and checks not run.

## What these checks are

These commands check current synthetic contracts, models, and fixtures.
The default app and the tests are synthetic.
They must not call a provider.

## What these checks are not

These commands are not a product security review.
They are not a remote CI result.
The file `.github/workflows/ci.yml` is a configured workflow.
This task does not permit a remote run of that workflow.

A Cargo metadata inventory is not a full license review of bundled native code.
It is not a vulnerability review.
SQLCipher and OpenSSL source and license review remain open.
Full product isolation, model, and provider gates remain open.

Cargo `--offline` stops Cargo from getting crates during later check steps.
It does not stop other network use in a test.

## Toolchain

Use Rust 1.97.0 with rustfmt and clippy, as recorded in `rust-toolchain.toml`.

```
rustup toolchain install 1.97.0 --profile minimal --component rustfmt --component clippy
```

## Focused commands

Run each command from the repository root.
Do not add stub tests.
Do not skip a target that fails.

Core contracts:

```
cargo test --locked --all-features --test it contracts::
```

iPhone companion, Swift client against the Rust listener over the loopback wire (needs macOS and Xcode 27, synthetic data only):

```
scripts/companion-interop.sh
```

Desktop model:

```
cargo test --locked --all-features --test it desktop_model::
```

SQLCipher probe:

```
cargo test --locked --all-features --test it sqlcipher_probe::
```

Experimental passphrase vault, with temporary synthetic data only:

```
cargo nextest run --locked --offline --all-features --lib
cargo nextest run --locked --offline --all-features --test it vault_lifecycle:: vault_passphrase::
cargo test --offline --locked --features vault --doc
cargo clippy --locked --offline --features vault --all-targets -- -D warnings
```

Owner vault and item views call this API when both `desktop` and `vault` are enabled. See [desktop vault integration](desktop-vault.md). The tests do not permit real-secret use.

```
cargo nextest run --locked --offline --all-features --test it owner_vault::
```

P0 Node model:

```
node --test design/walkthrough/model.test.mjs
```

Python boundary fixture:

```
python3 tests/isolation/test_fixture_boundary.py
```

For the desktop launch command and model smoke check, see [desktop development](desktop-development.md).
Neither a model check nor headless egui drawing is a native-window visual test.

## Pinned dependency and license inventory

Write Cargo metadata under `target`. Git ignores `target`.

```
mkdir -p target
cargo metadata --locked --all-features --format-version 1 > target/cargo-metadata.json
```

Then write license declarations from that file:

```
python3 << 'PY'
import json
from pathlib import Path
data = json.loads(Path("target/cargo-metadata.json").read_text())
rows = []
for pkg in data["packages"]:
    license_id = pkg.get("license") or "UNDECLARED"
    rows.append(f"{pkg['name']}\t{pkg['version']}\t{license_id}")
Path("target/cargo-license-inventory.txt").write_text("\n".join(sorted(rows)) + "\n")
PY
```

This inventory records crate names, versions, and declared licenses.
It is not a full review of bundled SQLCipher or OpenSSL licenses.

## Configured CI

The workflow `.github/workflows/ci.yml` runs these jobs. A job name in backticks is its check name.
Triggers are `push` to `main` and `pull_request`.
A change only in `site/` or `design/` does not start the workflow.
The workflow does not use secrets.
The workflow does not publish, deploy, or comment on a pull request.
A draft pull request skips the macOS test groups ([CI duration](release.md#ci-duration-and-binary-artifacts)).

- `macos` (`macos-15`): the extension version, `cargo fmt --all -- --check`, the Swift typecheck of the native helper, Clippy with all features, `cargo check --features desktop --bin apassy`, `cargo test --features vault --doc`, the Node model tests, the Python fixture, CI helper, bouncer brain, and release-version tests, and `git diff --check`.
- `linux` (`ubuntu-24.04`): Clippy with all features, Clippy for the relay and the iPhone vault core, `cargo test --features vault --doc`, the Python fixture tests, and the rule packs and provider files two times: with the JSON Schemas in `packs/schema/`, and with `apassy-packs validate`.
- `relay (1)` and `relay (2)` (`ubuntu-24.04`): one half each of `cargo nextest run --profile ci -p apassy-relay -p apassy-core --partition slice:K/2`; `relay (1)` also runs the doc tests of both crates and `crates/apassy-relay/scripts/e2e.sh`.
- `tests (OS, K)`, four groups on `ubuntu-24.04` and two on `macos-15`: `cargo nextest run --profile ci --offline --locked --all-features --all-targets --partition slice:K+1/N`.
- `extension` (`macos-15`): the extension Node models and the Playwright tests in Helium.
- `relay-worker`, `audit` (`cargo audit`), `reuse-pr`, and, on a push to `main` only, `release-binaries`.

Each command runs after `cargo fetch --locked`, with `--offline --locked`. `scripts/ci-install-nextest.sh` installs the pinned cargo-nextest. The nextest settings, the `ci` profile, and the `serial` test group are in `.config/nextest.toml`.

A configured workflow is not a remotely executed check.

## Test vault KDF

The vault keys its file with SQLCipher 4 defaults: PBKDF2-HMAC-SHA512 with 256,000 iterations.
Each create, unlock, owner check, and copy check derives the key one time, about 0.3 s on a CI runner.
To make the tests faster, the test-only feature `insecure-test-kdf` lowers this count to 2 for test vaults (`src/vault/test_kdf.rs`).
CI tests with `--all-features`, so CI uses the lower count.

The lower count applies only when all of these conditions are true:

- The build has the feature. No shipped build names it. The macOS app, the release binaries of CI, the iPhone core, the relay, and the Linux CLI are built with named features or with `-p`.
- The build has debug assertions. In a build without debug assertions, `REDUCED_KDF_ITER` is 256,000, and a constant assertion checks it. Every shipped artifact is a `--release` build.
- A directory above the vault file has the exact name of a default `tempfile::TempDir`: `.tmp` and six letters or digits, such as `.tmpAbC123`. A vault in the data directory of the app, or in a directory such as `.tmpl` or `.tmp-backup`, keeps 256,000 iterations, also in a `cargo r` debug build with `--all-features`. Do not keep real secrets in a vault that a debug build with `--all-features` created inside such a temporary directory.

The connection of a vault gets the count of its path, and `verify_cipher_defaults` checks that setting of the connection. In a build without the feature, the check compares with the constant 256,000, and the code for the lower count is not compiled. The check cannot see the count of the file itself. A file encrypted with another count does not decrypt: its first read fails the HMAC check (`verify_readable_schema`), and the vault reports a wrong passphrase or a damaged file.
So a file with the lower count does not open in a shipped app.

`no_shipped_build_enables_the_reduced_kdf` reads the manifests, the Cargo config, the relay Dockerfile, every workflow and every script, with backslash-continued commands joined. It fails if a release build names the feature or `--all-features`, if a release build uses the `cargo b` alias (`build --all-features`), or if any of these files turns on debug assertions (a profile, `CARGO_PROFILE_*_DEBUG_ASSERTIONS`, or `-C debug-assertions`). It also requires the known release builds, `screenshots.sh` included.

These tests keep the real values: `sqlcipher_probe` uses plain SQLCipher connections, and `vault_migration`, the two file checks of `vault_passphrase`, and the cipher-defaults unit tests use directories with the `apassy-real-kdf-` prefix.
A test that opens a vault file with its own SQLCipher connection calls `common::key_raw` (or `test_kdf::match_vault_kdf` in the library) after the key.
Do not use a test vault of the lower count for real secrets: the passphrase is its only protection.
