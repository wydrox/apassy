# Isolation fixture

This directory holds a P0 filesystem boundary fixture.
It is not product isolation evidence for the Apassy broker.

Real-secret gate: BLOCKED.

## Command

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
