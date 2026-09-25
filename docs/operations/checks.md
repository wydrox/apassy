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
cargo test --locked --test contracts
```

Desktop model:

```
cargo test --locked --features desktop --test desktop_model
```

SQLCipher probe:

```
cargo test --locked --features storage-probe --test sqlcipher_probe
```

Experimental passphrase vault, with temporary synthetic data only:

```
cargo test --locked --offline --features vault --lib --test vault_lifecycle --test vault_passphrase -- --test-threads=1
cargo test --offline --locked --features vault --doc
cargo clippy --locked --offline --features vault --all-targets -- -D warnings
```

Owner vault and item views call this API when both `desktop` and `vault` are enabled. See [desktop vault integration](desktop-vault.md). The tests do not permit real-secret use.

```
cargo test --locked --offline --features desktop,vault --test owner_vault -- --test-threads=1
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

The workflow `.github/workflows/ci.yml` uses one `macos-15` job.
Triggers are `push` and `pull_request`.
The workflow does not use secrets.
The workflow does not publish, deploy, or comment on a pull request.

After you install the toolchain, the job runs these steps:

```
cargo fetch --locked
cargo fmt --all -- --check
cargo clippy --offline --locked --all-features --all-targets -- -D warnings
cargo test --offline --locked --all-features --all-targets -- --test-threads=1
cargo test --offline --locked --features vault --doc
node --test design/walkthrough/model.test.mjs
python3 tests/isolation/test_fixture_boundary.py
git diff --check
```

A configured workflow is not a remotely executed check.
