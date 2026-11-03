# Implementation plan — ADR 0037 stage 8: the iPhone's own tailnet and the Linux window

Date: 2026-11-03. Status: PLAN. Built under the owner's instruction of 2026-11-03: build everything
in the ADRs except the TEE track, as fast as possible, without the owner's approval of intermediate
steps. Decisions: [ADR 0040](../adr/0040-embedded-tailnet-iphone.md) (track T) and
[ADR 0041](../adr/0041-linux-window.md) (track L). Stage 8 of [ADR 0037](../adr/0037-own-relay-open-source.md).

## Outcome and constraints

- **Track T:** an iPhone without the Tailscale app, with another VPN on, approves a run on the Mac
  node over the tailnet. Apassy's own Tailscale node in the app carries the connection.
- **Track L:** a Linux desktop runs the Apassy window from a `.deb`. The owner check uses polkit,
  with the passphrase as the fallback.
- **Not in this plan:**
  - Linux isolation of agents: [implementation-plan-s5-env-0011.md](implementation-plan-s5-env-0011.md)
    (ADR 0011). Track L only reads one check from it (L7).
  - The TEE track (ADR 0037 E1 to E4).
  - The embedded node on the desktop and Linux (ADR 0037 D9, stage 4).
- **Parallel plans.** [implementation-plan-s2-s3.md](implementation-plan-s2-s3.md) (stages 2 and 3)
  and [implementation-plan-s4-teams.md](implementation-plan-s4-teams.md) (stage 4) are written at the
  same time as this plan. Units here name the units of [plan 0037](implementation-plan-0037.md)
  (2B, 2C, 3A, …). If those plans rename a unit, their name wins. If they own a file that a unit
  here needs, their owner wins, and the unit here starts after their merge.
- **Wire contracts stay.** node-pairing-v1 (made by 2C) gains optional fields. ios-core-v1 gains
  one call and one seam.
- **Releases.** Each track ships at the next release of all six components after its acceptance
  passes (AGENTS.md). Until then the code merges dark: release builds of the iPhone app hide the
  setting, and the `apassy-desktop` package is not published.
- **Mac resources.** At most three implementation or validation workers on this Mac, across all
  sessions. Subagents at every depth do not run lint, typechecks, builds, compilation-heavy checks,
  or full test suites. They edit code, write tests, and return the exact commands. The top-level
  agent runs one validation pass for each revision through `~/.local/bin/heavy-check`, and prefers
  CI. Go and Xcode builds of the tailnet library count as heavy. Docker runs only on devbox, never
  on this Mac.

## Facts from the code (release/0.5.16 at dd71868c)

| Area | Fact | Where |
| --- | --- | --- |
| iPhone relay client | Rust core: `std::net::TcpStream` and rustls. A connection is `Socket(TcpStream)` or a request of the external HTTP transport (the watch seam of ADR 0039 §5) | `src/sync/relay_http.rs:22-33`, `:173`, `:379`; `ios/ApassyCore/src/ffi.rs:81` |
| Core C interface | One header and module map | `ios/ApassyCore/include/ApassyCoreFFI/apassy_core.h` |
| iPhone app | iOS 26. Entitlements: App Group, keychain groups, AutoFill, `aps-environment`, time-sensitive. `NSLocalNetworkUsageDescription` is set. Background mode: `remote-notification` only. The watch app has its own keychain group and no sockets | `ios/ApassyCompanion/project.yml` |
| Licenses screen | The app bundles `licenses/` as Settings › Licenses | `project.yml`, `../../licenses` |
| Core build | `scripts/build-ios-core.sh` makes `ApassyCore.xcframework` (not committed) | `ios/README.md` |
| Tailscale on the Mac | The companion finds the tailnet IPv4 address. The cloud-slice node has a Funnel route | `src/companion/hosts.rs`, `src/node/funnel.rs` |
| Desktop size | About 96,600 lines in `src/desktop` | `wc -l` |
| macOS-only desktop parts | The native menu, the Swift helper calls (Touch ID, Keychain, notifications, iCloud status), the updater, the browser guard, Seatbelt | `src/desktop/{mod.rs,native_menu.rs,update}`, `src/native/mod.rs`, `src/browser/caller.rs`, `src/broker/proxy/mod.rs:523` |
| Linux build today | CI runs clippy with all features on ubuntu-24.04, and `cargo check --features desktop --bin apassy` | `.github/workflows/ci.yml:141`, `:146` |
| Window binary | `crates/apassy-app` ("for macOS"), with the relay crate | `crates/apassy-app/Cargo.toml` |
| UI dependencies | eframe `=0.36.2` (no default features: accesskit, default_fonts, glow). winit 0.30.13 in the lock with its X11 and Wayland dependencies. zbus 5.19.0 through `accesskit_unix` | `Cargo.toml:38`, `Cargo.lock` |
| Linux paths | `$XDG_DATA_HOME/apassy`, or `~/.local/share/apassy` | `src/paths.rs:26` |
| Node master key | The `KeyStore` trait: the Keychain behind Touch ID, else a 0600 file | `src/node/master_key.rs` |
| Linux packaging | None. `packaging/` is macOS only (Info.plist, entitlements, icons, DMG background) | `packaging/` |
| Defect 1, Linux aarch64 | `O_NOFOLLOW` is `0o400_000` for every target that is not macOS. On aarch64 Linux, `O_NOFOLLOW` is `0o100_000`, and `0o400_000` is `O_LARGEFILE`. So the capture open follows a last symbolic link on arm64 Linux. The inode check after the open still refuses a swapped file, so one layer of the defense is lost, not all | `src/broker/agent_items.rs:347-350`, `:1007` |
| Defect 2, Linux clocks | The owner-check window and the idle measure use `Instant` on Linux (`CLOCK_MONOTONIC`, which stops during suspend). The code itself says that suspension must count | `src/broker/approvals/owner_window.rs:66-87`, `src/desktop/auto_lock.rs:110-121` |

## Track T — the embedded tailnet on the iPhone (ADR 0040)

**T0 Spike, go or no-go (S).**

- Own: a throwaway branch `spike/s8-ios-tailnet`; the report `docs/reviews/s8-ios-tailnet-spike.md`
  (the only file that merges).
- Work: build libtailscale for `ios-arm64` and `ios-sim-arm64` with a pinned Go toolchain. Link it
  into a development build of the app. Join the owner's tailnet with the sign-in URL. Dial a pinned
  TLS endpoint on the Mac (the companion listener of `examples/companion_dev.rs`, or the stage 2
  front once it exists). Check the pin in Rust over the dialed file descriptor.
- Measure on the owner's iPhone, with another VPN on and the Tailscale app off:
  - the install and download size added (the export thinning report);
  - the time from the app becoming active to the first answer of the node, with saved state: p50 and
    p90 of 10 tries, on Wi-Fi and on cellular;
  - resident memory, and CPU time in 5 minutes in the foreground (Instruments);
  - a packet log: no upload to Tailscale's log servers, no request to `apassy-relay.wyderka.cc`;
  - whether the Local Network permission appears;
  - the go-licenses report;
  - whether the sign-in URL comes through TailscaleKit's LocalAPI part (ADR 0040 D4);
  - whether a dial gives a file descriptor that Swift can pass to the core;
  - a crash in Go and a panic in Rust, each with the other runtime loaded (signal handlers).
- Go if: it works on the device with the other VPN on; p50 is 2 s or less on cellular; it adds at
  most 30 MB to the install size; it uploads no logs; every license is on the allow list.
- No-go: the report updates ADR 0040 with the evidence, and track T stops. Connect stays the
  answer. It does not switch to option A.
- Depends on: nothing in s2 to s4.

**T1 The library build (M).**

- Own: `tailnet/go.mod`, `tailnet/go.sum`, `tailnet/README.md`, `scripts/build-tailnet.sh`,
  `licenses/tailnet/**`, the iOS job lines in `.github/workflows/ci.yml` (a shared file: one editor
  at a time).
- Interface: `scripts/build-tailnet.sh ios ios-sim [macos]` writes
  `ios/ApassyTailnet/build/ApassyTailnet.xcframework` (not committed) with `tailscale.h`. Pins: the
  Go toolchain (`toolchain` line), the libtailscale commit, and the `tailscale.com` module version.
  The license step writes the notices and fails on a license outside the allow list (ADR 0040 §5).
- Shared with stage 4 (D9): if the s4 plan already owns a libtailscale build for macOS and Linux, T1
  adds the iOS slices to that script instead of making a new one.
- Acceptance: a clean clone builds the XCFramework on the macos-15 CI runner. A test fixture with a
  GPL module makes the license step fail. The build log records the SHA-256 of each archive.
- Depends on: T0 go.

**T2 The stream dialer in the core (S–M).**

- Own: `src/sync/relay_http.rs` (2C owns it during stage 2; T2 starts after 2C merges),
  `ios/ApassyCore/src/ffi.rs`, `ios/ApassyCore/include/ApassyCoreFFI/apassy_core.h`, the core's local
  settings (`ios/ApassyCore/src/core/config.rs`, after 2C), `docs/contracts/ios-core-v1.md` (a new
  section).
- Interface:

  ```c
  // 0 and a connected stream in *out_fd, or a negative error code.
  typedef int32_t (*apassy_stream_dial_fn)(void *ctx, const char *host, uint16_t port,
                                           uint32_t timeout_ms, int32_t *out_fd);
  // Once per process, before apassy_core_new. False when a dialer is already set.
  bool apassy_core_set_stream_dialer(apassy_stream_dial_fn dial, void *ctx);
  ```

  JSON calls `relay_route_get` and `relay_route_set {"route": "system" | "embedded"}`. The value is
  a local setting of this iPhone, `system` by default. With `embedded`, a link to a tailnet address
  (100.64.0.0/10, fd7a:115c:a1e0::/48, or a `*.ts.net` name) uses the dialer. A connection becomes
  `Connection::Dialed(OwnedFd)`. The core sets its deadlines on the descriptor, runs the 2C pinned
  rustls over it, and shuts it down on `Cancel::close`.
- Acceptance (Rust tests; the top-level agent runs `cargo nextest run -p apassy-core`):
  - A fake dialer gives a socketpair to the in-process fake node behind the TLS front. The question,
    answer, and settle digests equal those of the system route.
  - A wrong pin is refused.
  - A dialer that sends nothing ends with the long-poll deadline.
  - `Cancel::close` shuts the descriptor.
  - `embedded` without a dialer is a `Connect` error, and a counting listener sees no TCP connect.
  - The hosted relay origin never uses the dialer.
- Depends on: 2C (pinned trust, node-pairing-v1), 2B (the TLS front for the test fake).

**T3 The Swift tailnet service (M).**

- Own: a new package `ios/ApassyTailnetKit/**` and its tests; the app's lifecycle file
  `ios/ApassyCompanion/Sources/Tailnet/TailnetLifecycle.swift` (new); `ios/ApassyCompanion/project.yml`
  (links the XCFramework to the app target only).
- Interface:

  ```swift
  public enum TailnetState: Sendable, Equatable {
      case stopped, starting, needsLogin(URL), needsApproval, running([String]), failed(String)
  }
  public actor TailnetNode {
      public init(stateDirectory: URL, hostname: String, controlURL: URL?)
      public func start(authKey: String?) async throws
      public nonisolated var states: AsyncStream<TailnetState> { get }
      public func dial(host: String, port: UInt16, timeout: Duration) throws -> Int32
      public func stop() async
      public func logout() async throws  // and deletes the state directory
  }
  ```

  The app installs the core dialer at launch. `TailnetLifecycle` starts the node when the scene is
  active, the route is `embedded`, and an unlocked vault has a node membership, or a pairing runs.
  It stops the node 30 s after the app leaves the screen (a background task), and when every vault
  is locked. It sets `TS_NO_LOGS_NO_SUPPORT=1` before the start, and sends the local log to a pipe
  that keeps nothing. The state directory is `Application Support/Tailnet` in the app container,
  excluded from backups, with `completeUntilFirstUserAuthentication`.
- Acceptance:
  - `swift test` on macOS with the macOS slice: the state machine with a fake node; the 30 s stop;
    the stop on lock; the dialer bridge; the backup exclusion and the file protection of the
    directory.
  - An interop check, `scripts/tailnet-headscale-check.sh`, run by the top-level agent. It starts a
    Headscale binary on loopback with its built-in DERP (no Docker), makes a pre-auth key, starts a
    macOS test node with a pinned TLS echo, and lets a Simulator client join and dial it. If
    Headscale does not run on macOS, the server side runs on devbox-arm.
- Depends on: T1.

**T4 Pairing, sign-in, and settings on the iPhone (M).**

- Own: the pairing flow, Settings › Devices › Tailscale connection, and the quiet state of Requests
  in `ios/ApassyCompanion/Sources/**`; `docs/contracts/node-pairing-v1.md` (two optional fields);
  the Mac side of those fields in `src/relay/pairing.rs` (after 2E merges).
- Interface:
  - Link fragment fields: `tsctl=<b64u control URL>` (absent means Tailscale's default) and
    `tsk=<auth key>` (optional, from T5). Like the ADR 0032 handoff, they are stripped before every
    relay call.
  - The flow: scan, then try the system route for 2 s. If it does not answer, offer "Connect without
    the Tailscale app". Sign in (`ASWebAuthenticationSession` with the URL of `.needsLogin`) or use
    `tsk`. At `.running`, go on with the ADR 0019 pairing over the embedded route.
  - Settings: the route ("Tailscale app" or "Built into Apassy"), the device name in the tailnet,
    the state, "Sign in again", and "Disconnect from Tailscale".
  - Simulator launch argument `-ApassyPreviewTailnet needsLogin|approval|running|expired|failed`.
- Acceptance:
  - UI tests in the Simulator with the preview states.
  - A screenshot of each state next to the mockup before any release claim.
  - Contract tests: an older build ignores the new fields; `tsk` never goes into a request, a log,
    or the pasteboard.
- Depends on: T3; 2E (the Mac pairing link), 2G (node links on the iPhone), 2C (the contract).

**T5 A one-use key from the Mac (S–M).**

- Own: `src/node/tailnet_keys.rs` (new); the "Add a device" hook in `src/relay/pairing.rs` (after
  T4); the "Tailscale OAuth client" row of Settings → Devices in `src/desktop/ui/` (after 2H).
- Interface:

  ```rust
  pub fn mint_device_key(client: &TailscaleOAuth, tag: &str, ttl: Duration)
      -> Result<OneUseKey, TailnetApiError>;
  pub fn delete_key(client: &TailscaleOAuth, key_id: &str) -> Result<(), TailnetApiError>;
  pub fn find_device(client: &TailscaleOAuth, hostname: &str)
      -> Result<Option<DeviceId>, TailnetApiError>;
  pub fn delete_device(client: &TailscaleOAuth, id: &DeviceId) -> Result<(), TailnetApiError>;
  ```

  The token comes from `POST https://api.tailscale.com/api/v2/oauth/token` (client credentials),
  with the scopes `auth_keys` and `devices:core`. The key: `POST /api/v2/tailnet/-/keys`, with
  `reusable=false`, `ephemeral=false`, `preauthorized=true`, `tags=["tag:apassy-device"]`, and
  `expirySeconds=600`. The client secret is an Apassy item. The Mac reads it under the owner check
  of the pairing, with no extra prompt.
- If the s4 plan builds a Tailscale API client (for the share invites of ADR 0037 §9), T5 uses it.
  Otherwise T5 makes `src/node/tailscale_api.rs`, and s4 uses that.
- Acceptance (against a fake Tailscale API on loopback):
  - The key request has exactly the values above.
  - The key is deleted when the device appears, and when the pairing ends by expiry, cancel, or
    failure.
  - An API error leaves the sign-in path working.
  - The key and the token appear in no log and in no activity entry (a test greps the captured logs).
- Depends on: T4; the s4 API client if it exists.

**T6 The Mac's view of an embedded iPhone (S).**

- Own: the Settings → Devices rows in `src/desktop/ui/*` (after 2H); the peer rule of the TLS front
  in `src/net/tailnet.rs` (after 2B).
- Interface: the WhoIs rule of 2B also accepts a `tag:apassy-device` peer of the owner's tailnet. A
  device row shows "Apassy's own Tailscale connection" when the WhoIs name has the `apassy-` prefix or
  the tag.
- Acceptance: unit tests of the rule (the owner's user; the tag; a tagged peer of another tailnet is
  refused on a personal node); a screenshot of the row.
- Depends on: 2B, 2H, T4.

**T7 Documents and store texts (S).**

- Own: `ios/README.md` (a section "Tailscale without the app"); `docs/security/trust-model.md` (one
  row); `docs/operations/tailnet-iphone.md` (new: the policy grant, the OAuth client, Headscale,
  troubleshooting); the App Review notes and the App Privacy answers in the release notes of the
  store.
- Acceptance: each command and setting in the guide matches the code; the trust model row matches
  ADR 0040.
- Depends on: T4, T5.

**T8 Acceptance on devices (owner and top-level agent).**

- An iPhone without the Tailscale app, on cellular, with another VPN connected, approves a run on
  the Mac over the embedded node. A packet log shows no request to `apassy-relay.wyderka.cc` and no
  log upload to Tailscale.
- One minute after the app leaves the screen, the node is stopped (no tailnet packets).
- With the Tailscale app connected and the route on "Tailscale app", nothing changes.
- "Disconnect from Tailscale" removes the state. The next start asks to sign in.
- Revoke on the Mac stops the iPhone at its next request.
- Depends on: T1 to T7; the stage 2 acceptance.

## Track L — the Linux window (ADR 0041)

**L0 Linux portability fixes (S).**

- Own: `src/broker/agent_items.rs:343-350`, `src/broker/prompts.rs:61-64`, `src/broker/project.rs:91-94`
  (the flags only); `src/broker/approvals/owner_window.rs:66-87`; `src/desktop/auto_lock.rs:110-121`.
- Work: take the open flags from `rustix::fs::OFlags` (`NOFOLLOW`, `NONBLOCK`) instead of written
  numbers. On Linux, read `ClockId::Boottime` for the owner-check window and the idle measure.
- Acceptance: a test that the capture open refuses a last symbolic link (on the Linux CI runner);
  `cargo check --target aarch64-unknown-linux-gnu --features vault` (top-level agent); the existing
  owner-window and auto-lock tests pass on both systems.
- If the s5 or s2-s3 plan edits these files first, this unit goes to that owner.
- Depends on: nothing.

**L1 The platform layer (M).**

- Own: `src/desktop/platform/{mod.rs,macos.rs,linux.rs}` (new); the call sites in
  `src/desktop/owner_check.rs`, `src/desktop/unlock.rs`, `src/desktop/notify.rs`, and
  `src/desktop/auto_lock.rs`; one `mod platform;` line in `src/desktop/mod.rs` (2D edits that file:
  rebase on 2D).
- Interface:

  ```rust
  pub(crate) trait OwnerAuthenticator: Send + Sync {
      fn availability(&self) -> Availability; // Ready(CheckMethod) or Unavailable(reason)
      fn authenticate(&self, purpose: &OwnerPurpose, cancel: AuthCancel)
          -> Result<CheckMethod, AuthFailure>;
  }
  pub(crate) trait UnlockKeyStore: Send + Sync {
      fn setting(&self, vault: &Path) -> UnlockSetting;
      fn read(&self, vault: &Path, purpose: &OwnerPurpose) -> Result<KeychainSecret, UnlockStoreError>;
      fn store(&self, vault: &Path, secret: &[u8]) -> Result<(), UnlockStoreError>;
      fn forget(&self, vault: &Path) -> Result<bool, UnlockStoreError>;
  }
  pub(crate) trait Notifier: Send + Sync {
      fn post(&self, note: &Notification) -> Result<(), NotifyError>;
  }
  pub(crate) trait SessionWatch: Send + Sync {
      fn idle(&self) -> Option<Duration>;
      fn screen_locked(&self) -> std::sync::mpsc::Receiver<()>;
  }
  pub(crate) struct Platform {
      pub owner: Arc<dyn OwnerAuthenticator>,
      pub unlock: Option<Arc<dyn UnlockKeyStore>>,
      pub notifier: Option<Arc<dyn Notifier>>,
      pub session: Arc<dyn SessionWatch>,
      pub updates: bool,
  }
  ```

  macOS wraps `NativeHelper` exactly as today. Linux starts with the passphrase only, no unlock
  store, no notifier, and the window's input time. L2 and L3 fill it in.
- Acceptance: the existing owner, unlock, notification, and auto-lock tests pass unchanged (CI,
  macOS groups included); a fake `Platform` drives `ask_owner` on both systems.
- Depends on: nothing (rebase on 2D for `mod.rs`).

**L2 The polkit owner check (M).**

- Own: `src/desktop/platform/linux/polkit.rs` (new); `packaging/linux/com.wydrox.apassy.policy`
  (new); `Cargo.toml` (a Linux target dependency: zbus `=5.19.0`, the blocking API); `CheckMethod::System`
  and its label in `src/broker/approvals/owner_auth.rs`; the "Check with" row of Settings › Security.
- Interface: `PolkitAuthenticator::connect() -> Option<Self>` is `None` without polkitd or without the
  action. `authenticate` calls `CheckAuthorization` with the subject `system-bus-name` (Apassy's own
  unique name), the action `com.wydrox.apassy.owner-check`, no details, the flag
  `AllowUserInteraction`, and a cancellation id. Success means `is_authorized` and not
  `is_challenge`. A cancel calls `CancelCheckAuthorization`.
- Acceptance:
  - Tests with a fake authority on a private D-Bus connection: authorized gives `CheckMethod::System`;
    not authorized and challenge fail; cancel calls `CancelCheckAuthorization`; no polkitd gives the
    passphrase route.
  - The policy file passes `xmllint` against the polkit DTD in CI.
  - The owner proof of a polkit check names the exact action, as a Touch ID proof does (ADR 0030
    tests, extended).
- Depends on: L1.

**L3 Notifications, screen lock, idle time, clipboard hint (S–M).**

- Own: `src/desktop/platform/linux/{notify.rs,session.rs}` (new); the Linux part of
  `src/desktop/clipboard.rs`.
- Interface: `Notifier` over `org.freedesktop.Notifications.Notify`, with the Mac's fixed templates.
  `ActionInvoked` opens Requests. `SessionWatch` over the logind session of `XDG_SESSION_ID`: the
  `Lock` signal, `LockedHint`, `IdleHint`, and `IdleSinceHint`. A copy carries
  `x-kde-passwordManagerHint`.
- Acceptance: tests with fake D-Bus services: a `Lock` signal locks the vault; a notification has
  only template text and the bounded agent name; a copy has the hint.
- Depends on: L1.

**L4 The Linux window and the node handover (M).**

- Own: `crates/apassy-app/Cargo.toml` (a Linux target dependency on eframe with `x11` and
  `wayland`; the description); `crates/apassy-app/src/main.rs` (on Linux: `PR_SET_DUMPABLE` 0, core
  limit 0, the node lock, the handover); `src/desktop/platform/linux/handover.rs` (new); the
  in-window menu (a small block in `src/desktop/ui/shell.rs`).
- Interface:
  - `NodeLock::acquire(data_dir) -> Result<NodeLock, Held>`, where `Held` is `Service` or `Window`.
  - `Handover::take(unit) -> Result<Restore, HandoverError>`: `StopUnit` on the systemd user manager
    over D-Bus, then a wait for the lock (at most 10 s).
  - `Restore::give_back()` on quit: `StartUnit` if the unit is enabled. The unit name is the one that
    3D gives.
- Acceptance:
  - Tests: the lock across two processes (temporary directory); the handover with a fake systemd
    manager (stop, wait, start on quit, no start when the unit is disabled); a second start exits
    with "Apassy is already open".
  - `apassy-desktop --version` runs without a display.
  - CI builds `-p apassy-app` on ubuntu-24.04 (the top-level agent adds the job).
- Depends on: L1; 3A (the headless binary), 3D (the user service).

**L5 Linux rows and texts in the UI (M).**

- Own: `src/desktop/ui/settings*.rs`, `src/desktop/ui/settings_rows.rs`, `src/desktop/ui/updates.rs`
  (a notice only on Linux), `src/desktop/ui/start.rs` and `src/desktop/ui/first_steps.rs` (texts
  without Touch ID).
- Interface: the views read the capabilities of `Platform` (L1). No new state.
- Acceptance: a screenshot of each changed view on Linux (headless Weston or Xvfb, on CI or
  devbox). The same views on the Mac do not change. Before any release claim, screenshots of every
  Linux view next to the Mac design.
- Depends on: L1, L2; after 2H (Settings → Devices).

**L6 Packages (M).**

- Own: `packaging/linux/**` (the desktop entry, icons made from `packaging/AppIcon.svg`, the
  AppStream metadata, the polkit action, the control files of `apassy-desktop`);
  `.github/workflows/release.yml` (a Linux desktop job on x86_64 and arm64 runners);
  `scripts/check-release-versions.py` (both packages); AGENTS.md (the Linux component is the CLI and
  the window).
- Interface: `apassy-desktop_<version>_amd64.deb` and `_arm64.deb`, each with a SHA-256 checksum and
  a build attestation. The `.tar.gz` also contains `apassy-desktop`.
- Acceptance:
  - `lintian` has no errors. `appstreamcli validate` and `desktop-file-validate` pass.
  - The release check fails when the desktop package has another version.
  - In fresh Ubuntu 24.04 and Debian 12 containers on devbox, the packages install,
    `apassy-desktop --version` prints the version, and `apassy` alone pulls no GUI library.
- Depends on: L4, 3E.

**L7 Keep the passphrase in the login keyring, with a condition (S–M).**

- Own: `src/desktop/platform/linux/secret_service.rs` (new); its Settings › Security row.
- Interface: an `UnlockKeyStore` over Secret Service (`org.freedesktop.secrets`, the default
  collection, attributes `application=com.wydrox.apassy` and `vault=<vault id>`), with an encrypted
  session, through zbus. The row exists only when the s5 plan's check says that agents run without
  the session bus, or with `org.freedesktop.secrets` filtered.
- Acceptance: tests with a fake Secret Service; the row is hidden when the s5 check is false or
  absent; turning it on needs a fresh owner check and shows the warning of ADR 0041 §4.
- Depends on: L1; the D-Bus filter of s5. Without that check, L7 does not ship.

**L8 Acceptance on Linux desktops (owner and top-level agent).**

- Ubuntu 24.04, GNOME on Wayland: install both packages; open a vault; the owner check with the
  password, and with a finger where fprintd is set up; a run approved on the iPhone through this
  node; the screen lock locks the vault; quit, and the service serves again.
- KDE Plasma on Wayland: the same, without the finger.
- An X11 session: the notice shows; the window works.
- aarch64: the packages install and the window starts.
- Depends on: L0 to L6 (L7 when s5 allows); the stage 3 acceptance.

## Units

| Id | Unit | Size | Depends on |
| --- | --- | --- | --- |
| T0 | Spike, go or no-go | S | — |
| T1 | The library build | M | T0 |
| T2 | The stream dialer in the core | S–M | 2C, 2B (s2-s3) |
| T3 | The Swift tailnet service | M | T1 |
| T4 | Pairing, sign-in, settings on the iPhone | M | T3, 2C, 2E, 2G (s2-s3) |
| T5 | One-use key from the Mac | S–M | T4; Tailscale API client of s4 if any |
| T6 | Mac view of an embedded iPhone | S | T4, 2B, 2H (s2-s3) |
| T7 | Documents and store texts | S | T4, T5 |
| T8 | Acceptance on devices | owner | T1–T7, stage 2 acceptance |
| L0 | Linux portability fixes | S | — |
| L1 | The platform layer | M | — (rebase on 2D) |
| L2 | The polkit owner check | M | L1 |
| L3 | Notifications, screen lock, idle, clipboard | S–M | L1 |
| L4 | The Linux window and the node handover | M | L1, 3A, 3D (s2-s3) |
| L5 | Linux rows and texts | M | L1, L2, 2H (s2-s3) |
| L6 | Packages | M | L4, 3E (s2-s3) |
| L7 | Passphrase in the login keyring | S–M | L1, s5 D-Bus filter |
| L8 | Acceptance on Linux desktops | owner | L0–L6, stage 3 acceptance |

Track T as a whole is L (about three weeks of work, with waits for stage 2). Track L as a whole is L.
Stage 4 is not a hard dependency of either track. Track T shares the libtailscale build and the
Tailscale API client with stage 4, if those exist first.

## Order and merges

1. **Now:** T0, L0, L1. That is at most three workers; T0 is mostly the top-level agent and the
   owner's device.
2. **After T0 go:** T1, L2, L3.
3. **After the stage 2 merges of 2B and 2C, and stage 3's 3A and 3D:** T2, T3, L4.
4. **After 2E, 2G, and 2H, and 3E:** T4, L5, L6.
5. **Then:** T5, T6, T7; L7 when s5 has its D-Bus check.
6. **Last:** T8 and L8, then the release of all six components.

- One editor owns each shared file at a time: `src/sync/relay_http.rs` (2C, then T2),
  `src/relay/pairing.rs` (2E, then T4, then T5), `src/desktop/ui/settings*` (2H, then L5, then T5
  and T6), `.github/workflows/ci.yml` and `release.yml` (one editor per wave).
- Validation is one top-level pass per revision: CI after an authorized push, or a local run through
  `~/.local/bin/heavy-check`. A worker reports the commands and does not run them.
- A synthetic pass is not a device pass. T8 and L8 are their own checks.

## Owner-needed steps

| Step | For | What |
| --- | --- | --- |
| O1 | T0, T8 | The owner's iPhone on cellular, with another VPN connected (a work VPN or any VPN app) and the Tailscale app off or removed; Face ID |
| O2 | T0, T8 | Sign in to Tailscale on the iPhone with the owner's account; the owner gives any second-factor code |
| O3 | T0, T8 | If the tailnet has device approval: approve `apassy-<iPhone name>` in the Tailscale admin console |
| O4 | T5 (optional path) | Create a Tailscale OAuth client with the scopes `auth_keys` and `devices:core` and the tag `tag:apassy-device`. Add the `tagOwners` rule and a grant to the node port to the tailnet policy (an account setting). Save the client secret in Apassy with `apassy_ask_owner_for_credential`, never in a chat |
| O5 | T7, release | App Store Connect: the App Review notes and the App Privacy answers for the embedded node; the review of the export answer (ADR 0023 D4). A TestFlight external group goes through Beta App Review |
| O6 | Only after a T0 no-go, if the owner then chooses option A | The Network Extension capability on `com.wydrox.apassy.companion` and a new `…companion.tunnel` App ID, new App Store profiles, and confirmation that the developer account is enrolled as an organization (guideline 5.4). Option B needs no new entitlement |
| O7 | L8 | A Linux desktop (a machine or a VM): Ubuntu 24.04 with GNOME on Wayland, a KDE Plasma session, and an X11 session; a fingerprint reader with fprintd if there is one; an aarch64 machine, or accept install-and-start on devbox-arm |
| O8 | L5, L6 | devbox runs (paid Hetzner, within the shared 12.50 EUR budget) for package installs and headless screenshots, unless the owner allows them in advance |
| O9 | Release | The usual publication gates: TestFlight to the group, the Linux packages on `/dl` |

## Risks

| Risk | Track | Mitigation |
| --- | --- | --- |
| The in-app node does not survive foreground and background changes on iOS, or TailscaleKit's LocalAPI part lacks the sign-in state | T | T0 tests both on a device. No-go stops track T; Connect stays |
| The app grows by tens of MB (Go runtime and client) | T | T0 limit of 30 MB install size; thinning; only the app target links it |
| App Review treats the app as a VPN (5.4) | T | No VPN configuration; clear review notes; the Tailscale app and Connect stay as routes |
| Two runtimes in one process: signals, crash reports | T | T0 tests a crash in each runtime; in c-archive mode Go installs its handlers for synchronous signals and SIGPIPE, not for the other asynchronous signals |
| Each return to the app waits for the node to start | T | Saved state; start at the scene's first activation; the T0 target of 2 s on cellular |
| Client logs go to Tailscale | T | `TS_NO_LOGS_NO_SUPPORT`; a packet log in T0 and T8 |
| Keys of user-owned devices expire (180 days by default) | T | "Sign in again" in Settings and in the quiet state; tagged devices through T5 have no expiry |
| A photo of a code with `tsk` | T | One use, 10 minutes, a tag with a policy grant to the node port; the Apassy pairing still needs the safety words and the owner check; the Mac deletes the key |
| Large team tailnets: large network maps | T | One tailnet per iPhone (ADR 0040 D5); measure in T0 |
| The watch has no tailnet | T | Out of scope; the watch keeps its own route (ADR 0039) |
| Same-user agents on Linux change what starts next | L | Stated in ADR 0041 "What this does not protect"; the s5 plan; no stored passphrase until s5 |
| X11 keylogging | L | The notice in Settings and in `apassy doctor`; Wayland recommended |
| No polkit agent on some desktops (tiling window managers) | L | The passphrase fallback; `apassy doctor` names the missing agent |
| The polkit action needs a root install | L | The `.deb` installs it; the tarball falls back to the passphrase |
| The handover stops a team host for seconds, and quitting locks it | L | Stated in ADR 0041 §2; an always-on team host runs headless |
| glow under llvmpipe in VMs without a GPU is slow | L | L8 checks a VM; software rendering is acceptable for this UI |
| A new glibc on the build runners breaks older distributions | L | Build on the oldest glibc that stage 3 supports (3E) |
| The parallel plans rename or reorder units 2B to 3E | Both | Units here name the work, not only the id; their owner of a shared file wins |

## Open checks found while mapping

1. Does libtailscale's dial give a file descriptor that Swift can pass to the core (ADR 0040 D4)? (T0)
2. Does `TS_NO_LOGS_NO_SUPPORT` stop every log upload of the embedded node? (T0)
3. Does Headscale run on macOS for the interop check, or does it need devbox-arm? (T3)
4. What name does stage 3 give the user service (3D)? (L4)
5. Does the s5 plan expose a check that agents have no session-bus access? (L7)
6. Does the s4 plan build a Tailscale API client and a libtailscale build that T1 and T5 can use?
7. Which glibc is the oldest that stage 3 supports (3E)? (L6)
8. Defect 1 (`O_NOFOLLOW` on aarch64 Linux) matters for the stage 3 aarch64 packages too: fix it (L0)
   before the first aarch64 package ships.
