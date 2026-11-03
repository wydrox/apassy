# Changelog

## [0.5.15] - 2026-11-03

Version alignment with the coordinated Apassy 0.5.15 release. No functional,
protocol or schema change.

## [0.5.14] - 2026-11-02

The relay moves into the Apassy workspace as `crates/apassy-relay` under
Apache-2.0 (ADR 0037). The image and both team CLIs build from the Apassy
repository's `relay-image.yml` workflow (tag `image-*`).

- `APASSY_RELAY_TEAM_VAULTS=0` refuses the proxy, MCP, `/v1/access`, `/v1/runs`,
  the host lane and new team-vault content with 410 `team_vaults_retired`.
  Devices, joins, relay sync, questions, feed, push and Connect keep working.
  The hosted image sets `0`; the default is `1`.
- The vendored `tiny_http` drops its unused TLS features and dev-dependencies.

Team schema 6 and directory schema 1003 remain unchanged.

## [0.5.13] - 2026-11-02

Version alignment with Apassy 0.5.13; no protocol or schema change.

No unreleased functional changes since `image-release-0.5.9`
(`67dc722`). Team schema 6, directory schema 1003, and pinned dependencies
remain unchanged. Both binaries share the root Cargo package version.
Earlier release records are in `docs/releases/`.
