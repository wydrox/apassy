# Manual macOS quality pilot

Status: code preparation only; Apple account configuration, project discovery and
Cloud execution **NOT_RUN**. GitHub `macos` remains active. This package neither
publishes a product nor authorizes replacing a required check.

## Coverage and identity

The audit baseline is `773f02c2aff5456354776f9ef0bb60e4161800e1`. All existing CI
job identifiers remain. New `portable` uses Ubuntu 24.04, Node 22, Python 3.12 and
Rust 1.97.0/rustfmt. It runs with exactly the existing `reuse-pr` dependency and
reuse condition, including drafts. Whole-workflow success remains necessary for
PR evidence reuse and release consumption. No changes to reuse selection, release,
runner types of existing jobs, Rust test shards, or caches are included.

Moved from `macos`: extension version equality (Python TOML/JSON instead of
`plutil`), Cargo format, P0 Node models, CI-helper/extension-package/notary-retry
Python fixtures, isolated torch-free brain tests and dry-run bench, coordinated
version checks/tests, and whitespace check. The Python helper tests use mocks,
inert Mach-O bytes and temporary repositories; the notary tests fake `xcrun`.
The extension packager already supports Linux. Brain tests run in the same fresh
venv with only pinned FastAPI/httpx; optional torch/MPS tests still lack those
dependencies. No Linux skip is credited as Apple coverage. Local execution of
brain/model tests is outside this package's verification.

`tests/isolation/test_fixture_boundary.py` retains both existing invocations,
including **macOS sandbox-exec** through the shared helper. Helium Playwright and extension Node fixtures
stay in the existing macOS `extension` job. The unrelated Mach-O test file
`test_build_ios_core.py` is not in the migrated discovery patterns.

Both GitHub `macos` and Cloud invoke `scripts/ci-macos-quality.sh`. The shared
contract fetches with `--locked`, then preserves:

1. Swift helper typecheck, Swift 5, warnings as errors.
2. Full Clippy, all features/targets, warnings denied.
3. Desktop-without-vault compile check.
4. Additional app-crate Clippy, all targets, warnings denied.
5. Vault doc/compile-fail tests.
6. Both existing watch targets installed; watch simulator core compile without
   default features.
7. Existing Python fixture boundary tests, including sandbox-exec on macOS.

All Cargo quality commands retain `--offline --locked` after fetch. Rust is
explicitly selected as 1.97.0; Cloud installs the same rustfmt/clippy and watch
targets. Cloud supplements GitHub for these commands; the other macOS Rust runtime test
groups, Helium, signing and release validation are outside the pilot. The boundary
script is executed on both providers, but Cloud sandbox results remain unmeasured.

`APASSY_CI_EXPECTED_SHA` must contain exactly 40 lowercase hex characters matching
`git rev-parse HEAD`. Missing, abbreviated, mismatched, or tracked-dirty source
fails before tooling or fetch. GitHub supplies `github.sha`, which for PRs is
usually the **synthetic merge commit**. Comparing a Cloud PR head against that
merge commit is invalid. For the pilot choose a commit present in remote source
control and independently confirm both providers checked out that exact commit.
A main push that reuses PR evidence has not executed the quality helper at that
main SHA; it is not an identical-SHA timing baseline. Root must obtain an actual
GitHub helper run for the selected SHA, or record the comparison as unavailable.
Do not dispatch GitHub Actions as part of code preparation.

## Exact service configuration (root-owned, manual)

- Product: `ApassyCIPilot`, inert macOS framework; bundle ID
  `pl.wyderka.apassy.cipilot`. It is a CI container, not an app/upload deliverable.
- Project/container: `native/ApassyCIPilot/ApassyCIPilot.xcodeproj` (committed).
- Shared scheme: `ApassyCIPilot`; configuration `Release`; platform macOS.
- Workflow name, exactly: `Apassy macOS quality pilot`.
- Environment: nonsecret `APASSY_CI_EXPECTED_SHA=<selected full SHA>`.
- Start conditions: **none** (no branch changes, PR changes, tags or schedule).
  Start one build manually for the chosen remote branch/commit after checking
  its identity. If onboarding proposes an automatic first run, stop and edit the
  workflow before starting it; do not accept an unintended default workflow.
- Actions: exactly **one Build** for the shared scheme, macOS destination.
  No Analyze, Test, Archive, TestFlight, App Store or other distribution action;
  no post-actions. No certificates or signing credentials for this pilot.
- Project settings disable code signing and skip installation. Archive capability
  exists in the scheme because Apple lists it as a discovery requirement; this
  does not configure an Archive workflow action. The hook rejects anything other
  than `CI_XCODEBUILD_ACTION=build` for this workflow and exact project path.
- Select and record an available explicit Xcode/macOS version; compare with the
  GitHub run's logged Xcode and SDK versions. GitHub `macos-15` does not pin Xcode.
  Do not infer parity from runner labels.

Only `native/ApassyCIPilot/ci_scripts/ci_pre_xcodebuild.sh` is introduced, adjacent
to this project. It uses Apple's `CI_PRIMARY_REPOSITORY_PATH`,
`CI_PROJECT_FILE_PATH`, `CI_WORKFLOW` and `CI_XCODEBUILD_ACTION`; other workflow
names do no work. There are no iOS hook/project changes. The pre-build script
requires the primary checkout to be available and fails if it cannot access it.

The helper uses Python supplied by Xcode/macOS and a fresh temporary, user-writable
`CARGO_HOME`/`RUSTUP_HOME`. It downloads the HTTPS rustup bootstrap into that
location (120-second download timeout), installs pinned tooling without sudo or
modifying shell startup files, and runs quality before Xcode builds the inert
framework. The rustup bootstrap itself is fetched from the upstream endpoint,
not digest-pinned; networking/toolchain availability is a measured pilot risk.
No dependency cache is added. Cold Cloud vs cached GitHub timings must be labeled.

Apple's documented general onboarding requirements include an App Store Connect
record/permissions and automatic signing for app projects. Eligibility of this
unsigned framework in the actual account is **unverified**. Root must inspect
onboarding; if it insists on an app, signing, archive or distribution, stop and
report the blocker. Do not silently convert this into an app/release project.

## One-run procedure and evidence

1. Review and commit this package, publish through the separately approved PR
   process, and choose the remote source SHA. Record a GitHub run ID/attempt with
   actual helper execution at the same SHA. Set the Cloud expected-SHA variable.
2. Configure the manual workflow above; review action count/start conditions.
   Check account quota/billing before starting; no availability or free quota is
   assumed. Start **one** manual build. No automatic retries.
3. Budget at most **40 minutes** for tooling, metadata, dependency fetch and
   quality combined; the helper terminates the active process group on timeout
   with status 124. Allow at most **50 minutes of active build time** including
   checkout and the framework Build. Root cancels at that outer bound if needed;
   queue time is recorded separately. Service-level cancellation can truncate
   evidence and must not be called a successful result.
4. In Xcode's Report navigator or App Store Connect's Xcode Cloud build report,
   open/download the build logs. Save the complete pre-xcodebuild log and the
   line prefixed `APASSY_CI_RECEIPT_JSON=`. Strip only that prefix and save the rest
   as `cloud-quality.json`. Do the same for GitHub's shared-helper step. Record
   Cloud workflow/build identifiers, action result, source SHA, elapsed/queue
   time and any reported compute consumption beside the receipts.
5. Compare actual/expected SHAs, metadata (uname/architecture, selected Xcode and
   macOS/watch SDK, rustc/cargo/clippy/rustfmt), ordered quality step names, exit
   statuses and timings. Require every quality step plus the framework action
   to succeed. Investigate any missing receipt, timeout, identity/SDK mismatch,
   warning or failure. Do not rerun or reduce coverage to obtain success.

The receipt is bounded to 24 KiB, written locally to `APASSY_CI_RECEIPT` (default
system temporary directory), and printed as one JSON line on success **and**
ordinary failure. Each attempted command records elapsed seconds and exit status;
execution stops at the first failure and preserves its status. Missing later
steps are not passes. Forced cancellation, missing Python/checkout, or a hook
scope failure can prevent receipt creation: preserve that log and mark incomplete.
The receipt describes the helper only; read the subsequent framework Build result
separately. These are build logs, not a coverage report or performance guarantee.

Apple explicitly says files created by custom scripts are deleted and excluded
from downloadable artifacts. The JSON **log line** is the evidence transport;
no persistence claim is made for the local JSON file or rustup directories. No
upload, xcresult injection or external storage is used.

Acceptance of this one pilot requires root's review of the measured evidence.
Until then GitHub macOS stays authoritative and active. Even a successful pilot
does not establish ARM runtime test equivalence or authorize moving more jobs.
Actual Apple silicon allocation, speed, quota and cloud success remain unknown
until read from this run. Current local verification proves only static structure
and fixture boundaries, not Apple onboarding or execution.

## Primary references

Read for this preparation (2026-11-05):

- [Apple: Writing custom build scripts](https://developer.apple.com/documentation/xcode/writing-custom-build-scripts): hook names/location, workflow scoping, no sudo, log output, and custom files excluded from artifacts.
- [Apple: Environment variable reference](https://developer.apple.com/documentation/xcode/environment-variable-reference): repository/project paths, workflow name and action values.
- [Apple: Setting up your project](https://developer.apple.com/documentation/xcode/setting-up-your-project-to-use-xcode-cloud): stable committed project, shared scheme/archive capability, account and signing requirements.
- [Apple: Configuring your first workflow](https://developer.apple.com/documentation/xcode/configuring-your-first-xcode-cloud-workflow): onboarding, environment/actions, and build reports.
