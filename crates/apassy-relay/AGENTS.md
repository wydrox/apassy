# apassy-relay: release rules for this crate

The release policy of the whole product is in the root [AGENTS.md](../../AGENTS.md). Since ADR 0037
the relay is a member of this workspace; these rules add what is particular to it.

- The relay is the `relay` surface (server and edge Worker), and `apassy-team` is the `linux-cli`
  surface, until ADR 0037 stage 3 replaces it with the Linux node.
- Keep `crates/apassy-relay/Cargo.toml`, its entry in the workspace `Cargo.lock`, the edge Worker
  package and its lock metadata, both downloadable team CLIs, the relay image label, and public
  release metadata at the shared release version. Do not renumber pinned dependencies, schema
  versions, API versions, toolchains, or third-party packages merely to match the release.
- Release provenance names the exact source commit and artifact hashes. A successful build, upload,
  or CI run alone does not prove public delivery. Verify deployed versions, both download checksums,
  relay health version and commit headers, and each external publication surface.
- Build relay images and both downloadable CLIs in GitHub Actions (`.github/workflows/relay-image.yml`,
  tag `image-*`). Do not build or test containers on the production VPS, and do not start local
  Docker, Colima, or Lima VMs. Docker development uses a devbox, with the user's explicit
  architecture and teardown rules.
- Preserve both Darwin arm64 and Linux x86_64 downloads and their combined SHA256SUMS when deploying
  the Worker. Stage generated release metadata from the verified CI artifacts before deploy; binaries
  under `deploy/worker/public/dl/` are intentionally ignored by git.
- Keep Linux downloadable CLIs compatible with glibc 2.31. The relay runtime image may use Trixie,
  but its CLI is not the portable Linux download.
- Production values (server addresses, the VPS deployment, the health monitor) stay out of this
  public repository. Set Worker values at deploy time.
- Never modify production service configuration, credentials, schemas, or authenticated API
  semantics as part of a version-only release. Deployment, account publication, and credential
  access require the user's applicable authorization.
