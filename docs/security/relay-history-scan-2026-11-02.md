# Relay history scan before publication (ADR 0036, stage 0)

Date: 2026-11-02. Repository: `wydrox/apassy-relay`, every ref (144 commits; gitleaks scanned 124
non-merge commits). No value is in this report.

## Tools

- gitleaks 8.30.1, `gitleaks git --redact` over the whole history.
- A pattern scan of `git log -p --all` (Python `re`) for: real-format Apassy tokens
  (`apassy_{acc,tagt,ses,lnk}_<team id>_<64 hex>`, `apassy_agt_<64 hex>`), private-key blocks,
  APNs `.p8` file names, AWS access key ids, 64-hex values next to `master_key`, `edge_secret`, or
  `push_secret`, and public IPv4 addresses outside documentation ranges.

## Results

| Check | Hits | Verdict |
| --- | --- | --- |
| gitleaks | 22 | All test canaries: `sk_test_…canary…`, `ghp_Syn…canary…`, a repeated-hex APNs token, an `edge-secret…` test string, a fixed `t_…` team id |
| Real-format Apassy tokens | 0 | — |
| `apassy_agt_<64 hex>` | 2 | Fakes made of one or two repeated hex digits (`tests/cli_commands.rs`, `tests/cli_support/mod.rs`) |
| Private-key blocks | 2 | Built at run time from a key that the test generates (`deploy/worker/test/apns.test.ts`) |
| `.p8` names, AWS key ids, 64-hex secrets | 0 | — |
| Public IPv4 / IPv6 | The production VPS addresses | In `deploy/vps/compose.yaml`, `docs/OPERATIONS.md`, a doc comment and a test in `src/config.rs`, and a test in `src/proxy/upstream.rs`. Not secret (the same host serves public mail), but replaced with documentation addresses during the import (stage 1). All other addresses are documentation or special ranges. |

## Decision (D1)

The history is clean of secrets. It is imported with its history, with the VPS addresses replaced by
documentation addresses (`git filter-repo --replace-text`). `.github/workflows/health.yml` and
`deploy/vps/` monitor and run production; they stay in the archived private repository.
