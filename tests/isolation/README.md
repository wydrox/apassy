# Isolation tests

This directory holds two things:

1. `product_profile.rs` — the product isolation test for goal items I1, I2, and
   I4. It uses the real Seatbelt profile in `sandbox/apassy-agent-host.sb` and
   the `apassy-sandbox` launcher.
2. `test_fixture_boundary.py` — the older P0 filesystem boundary fixture. It is
   not product isolation evidence.

Real-secret gate: BLOCKED.

## Product isolation test (I1, I2, I4)

Run it with the normal test command:

```
cargo test --locked --features desktop,vault --test isolation_profile
```

It starts a real broker on a synthetic temporary vault. Then it runs processes
in the product profile and checks the boundary:

- `apassy-mcp` in the profile calls the broker and gets a permitted credential
  result. No secret leaks.
- A process in the profile cannot read, copy, overwrite, or replace the vault,
  a backup, or a file under a fake Laya directory.
- A vault in the vault list outside the data directory is denied too
  (`profile_denies_a_listed_vault_outside_the_data_directory`). The launcher
  passes it as `APASSY_VAULT_FILE_2` and stops on a damaged list or on more
  than 15 such vaults (`launcher_*` tests, ADR 0013).
- A process in the profile cannot read, list, or write the Apassy folder in a
  synthetic iCloud Drive, or move the iCloud Drive folder
  (`profile_denies_the_icloud_folder`). Another iCloud Drive folder stays
  readable. The launcher passes `APASSY_CLOUD_DIR` by default.
- Ordinary work still runs: it reads the project directory and writes a
  temporary file. Child processes of the sandboxed process work.
- `ps eww` and `ps -E` in the profile do not show the environment of a process
  outside the profile (F11). A direct system call can still read it. See the
  limit in `docs/operations/isolation.md`.
- A process in the profile cannot start a program OUTSIDE the sandbox:
  `profile_denies_lsopen_of_an_application` shows `open` of an application is
  denied, and a control shows the same application reads the canary outside the
  profile. `profile_denies_writes_to_autostart_locations` shows the profile
  denies a write to `~/Library/LaunchAgents`, `~/.zshrc`, and the other
  autostart locations, and still allows a read of a startup file. Apple Events,
  Shortcuts, and the browser routes are measured by hand;
  `docs/operations/isolation.md` section 7 has the commands, the results before
  and after, and why there is no automated test for each.

If the host is not macOS, or `sandbox-exec` is absent, the test fails. A skip is
not a pass (goal I4).

- A process in the profile cannot start, read, copy, hard-link, change, or move
  the programs in a synthetic `Apassy.app` with the layout of
  `scripts/build-app.sh`. Its helpers are the real Swift helper without a
  signature. Outside the profile (control), the same helpers start and answer
  `caller_not_allowed`.
- `apassy-mcp` and `apassy-hook` in `Apassy.app/Contents/MacOS` start in the
  profile and reach the broker.
- A copy of the keychain helper that the owner put outside the bundle starts in
  the profile, but it refuses each request with `caller_not_allowed`.
- The launcher passes `/Applications/Apassy.app` and `<target>/Apassy.app` by
  default. The profile protects `APASSY_APP_BUILD` also without `APASSY_APP`.
- A process in the profile cannot read the Touch ID Keychain item
  (`keychain_item_is_not_readable_in_profile`). `/usr/bin/security` runs in the
  profile and finds no item with the Apassy service and account. The Apassy
  keychain helper does not start in the profile. This deny does not depend on
  the signature or on a provisioning profile.

`scripts/build-app.sh` runs the same helper checks with the signed bundle. See
`docs/operations/isolation.md` sections 5 and 6, and
`docs/operations/native-app.md`, section "Caller check".

How to start Claude Code and Codex in the profile, and the measured results, are
in [docs/operations/isolation.md](../../docs/operations/isolation.md).

## P0 filesystem boundary fixture

Run this command from the repository root:

```
python3 tests/isolation/test_fixture_boundary.py
```

The parent runs that command. This task did not run it.

## What the test proves

On macOS with `/usr/bin/sandbox-exec`, the test uses temporary directories only.

It creates synthetic vault and owner-token canaries.
Those files are not secrets.

Then it checks three facts:

1. An ordinary child with the same user ID can read the canaries.
2. A sandboxed child can read a permitted synthetic agent task file.
3. That sandboxed child cannot read or replace the canaries.

The test also uses a path with spaces.
It checks baseline reads and the permitted read so a total-deny profile cannot pass.

The same file checks `tests/fixtures/p0-services.json` for synthetic candidate shape.

## Skip versus failure

If the OS is not macOS, or if `sandbox-exec` is absent, the sandbox tests skip.
The skip message says that the skip is NOT product isolation evidence.

If `sandbox-exec` is present and sandbox activation fails, the test fails.
The test does not fall back to a weaker check.

## Surfaces that stay unverified

This fixture does not prove:

- Memory isolation
- Clipboard isolation
- Automation control
- IPC isolation
- Authenticated owner channels
- Full broker isolation
- Network isolation as a product claim
- Keychain isolation
- Home-directory protection

Grok sandbox probes are not Apassy product isolation evidence.

P0 is not complete.
