# Apassy release policy

- Publish Apassy as one coordinated release across six surfaces: macOS app, iOS companion, Linux team CLI, Chromium extension, relay (server and edge Worker), and website (`apassy.wyderka.cc`).
- Use the same public release version for all six surfaces. Coordinate with the application repository (`wydrox/apassy`); update only product-owned package/manifests and release metadata. Do not renumber pinned dependencies, schema versions, API versions, toolchains, or third-party packages merely to match the release.
- For this repository, keep the root Cargo package and lock entry, the edge Worker package and root lock metadata, both downloadable team CLIs, the relay image label, and public release metadata at the coordinated version.
- Release provenance must name the exact source commit and artifact hashes. A successful build, upload, or CI run alone does not prove public delivery. Verify deployed versions, both download checksums, relay health version/commit headers, and each external publication surface.
- Build relay images and both downloadable CLIs in GitHub Actions. Do not build or test containers on the production VPS, and do not start local Docker/Colima/Lima VMs. If a separate Docker development task requires a devbox, follow the user's explicit architecture and teardown rules.
- Preserve both Darwin arm64 and Linux x86_64 downloads and their combined SHA256SUMS when deploying the Worker. Stage generated release metadata from the verified CI artifacts before deploy; binaries under `deploy/worker/public/dl/` are intentionally ignored by git.
- Keep Linux downloadable CLIs compatible with glibc 2.31. The relay runtime image may use Trixie, but its CLI is not the portable Linux download.
- Never modify production service configuration, credentials, schemas, or authenticated API semantics as part of a version-only release. Deployment, account publication, and credential access require the user's applicable authorization.
