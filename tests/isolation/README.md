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
- Ordinary work still runs: it reads the project directory and writes a
  temporary file.

If the host is not macOS, or `sandbox-exec` is absent, the test fails. A skip is
not a pass (goal I4).

A Keychain deny check is pending the Swift Keychain helper. The test
`keychain_check_is_pending` records this gap. It is not a skip of the test.

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
