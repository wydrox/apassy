# Spike — the embedded tailnet node (tsnet through libtailscale)

Date: 2026-11-03. Status: BUILT, NOT RUN. Every number below is empty until the manual workflow `tailnet-spike.yml` runs; the top-level agent fills in the tables with the run id.
Unit: T0 of [implementation-plan-s4-teams.md](implementation-plan-s4-teams.md) (decision 4). Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) D9. Branch `s4/t0-tailnet-spike`, from `origin/release/0.5.16` at `fdefba07`.

The question: can a team host run its own tailnet machine (`apassy-team-<slug>`, listening only on 8443) inside the Apassy process, through libtailscale (tsnet built as a Go C archive) behind a small Rust FFI crate? Or does Apassy need the fallback of decision 4, a Go helper binary?

## What was built

| Path | Role |
| --- | --- |
| `crates/apassy-tailnet/go/` | libtailscale at the pinned commit, byte for byte (hashes in `go/VENDORED.md`), with `go.mod` and `go.sum` of that commit. Plus `apassy.go`, the only Apassy Go code: it turns off the log upload (`logtail.Disable`) and exports `ApassyTailnetWhoisJSON`, a WhoIs over the in-memory LocalAPI. |
| `crates/apassy-tailnet/pins.env` | The pinned Go version with its SHA-256 per platform, the libtailscale commit, the tailscale.com version, the macOS target. One source for build.rs, the scripts, and the workflow. |
| `crates/apassy-tailnet/build.rs` | With the feature `tailnet`: links `APASSY_LIBTAILSCALE_DIR/libtailscale.a`, else builds `go/` with the pinned Go (`CGO_ENABLED=1 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go build -trimpath -buildvcs=false -buildmode=c-archive`), else fails with "the embedded tailnet needs Go or a prebuilt archive". Link flags: the `#cgo LDFLAGS` of every package (`go list -deps`), plus CoreFoundation, Security, and libresolv on macOS and pthread on Linux. Without the feature it does nothing. |
| `crates/apassy-tailnet/src/ffi.rs` | The C API. The only module with `unsafe` (the crate sets `unsafe_code = "deny"`, lib.rs allows it on this module). It turns each descriptor from libtailscale into an `OwnedFd` once, and frees each `malloc`'d string once. |
| `crates/apassy-tailnet/src/lib.rs` | The safe API of decision 4: `TailnetNode::up(TailnetOptions {dir, hostname, auth_key, control_url, ephemeral, log, up_timeout})`, `new`, `start`, `wait_up`, `listen(port) -> Listener`, `Listener::accept() -> Accepted {stream: UnixStream, remote}`, `whois(addr) -> Peer`, `status() -> Status`, `dial`, `ips`, `loopback` (spike only). `Drop` closes. |
| `crates/apassy-tailnet/src/bin/apassy-tailnet-spike.rs` | The spike: `serve` joins with an auth key from stdin, listens on 8443, and echoes; `dial`, `login-url`, `signals`, `state`, `idle`, `crash`, `info`. |
| `crates/apassy-tailnet/tests/node.rs` | The three acceptance tests of T0, plus `dropping_the_node_ends_a_blocked_accept`. Feature `tailnet`; no control server (127.0.0.1:1). |
| `crates/apassy-tailnet/scripts/` | `install-go.sh` (the pinned Go, checksum checked), `build-archive.sh`, `measure-build.sh` (sizes, link, glibc), `spike_run.py` (everything that runs). |
| `.github/workflows/tailnet-spike.yml` | Manual (`workflow_dispatch`): jobs `macos`, `linux-build` (bullseye container), `linux-run`, `notarize` (opt-in). |

The crate is a workspace member and not a default member. Nothing else depends on it, so `cargo build`, `cargo t`, and CI need no Go. `cargo fmt --all` formats it.

## Pinned inputs

| Input | Value |
| --- | --- |
| Go | 1.27.3 (the newest 1.27 patch on 2026-11-03; the pinned `go.mod` needs 1.27.1). SHA-256 darwin-arm64 `dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2`, linux-amd64 `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`, linux-arm64 `a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49` |
| libtailscale | `ac7ed43af14e19e1c1810ee9f8319872c6beb412` (2026-10-30, "mark handed-out fds close-on-exec") |
| tailscale.com | v1.104.1 (from that `go.mod`) |
| macOS target | 15.0 (`packaging/Info.plist`), passed as `MACOSX_DEPLOYMENT_TARGET` and `-mmacosx-version-min` to cgo |
| Linux baseline | glibc 2.31: `rust:1.97.0-bullseye@sha256:08d3da459cca408754c8071b1f74ed334c40a149e7fa6a150bceb11e2ee924c5`, as the Linux CLI |
| Rust | 1.97.0 (`rust-toolchain.toml`) |
| License | libtailscale and tailscale.com BSD-3-Clause; also Go (BSD-3-Clause), wireguard-go (MIT), gVisor (Apache-2.0); texts in `licenses/`, table in `licenses/THIRD-PARTY-NOTICES.md` "Embedded tailnet node" |

## Go or no-go

From decision 4. GO when all four hold. Otherwise the fallback: a Go helper `apassy-tailnet-helper` in `Contents/Helpers/`, signed with the app, that speaks over a Unix socket and passes connections as descriptors, behind the same safe API.

1. **Notarized.** The `notarize` job answers `Accepted` for a hardened-runtime binary with the archive, and the signed binary runs: `info`, `signals`, and an offline node that ends on SIGTERM.
2. **Stable in process.** SIGTERM, SIGINT, and SIGHUP still end the process. A write to a closed peer gives EPIPE, not a SIGPIPE death. A fault in Rust code still ends the process at once, with a crash report on macOS (with or without `GOTRACEBACK=crash`, which the app can set). No thread or memory growth at idle. Threshold chosen by this spike (the owner can change it): with a node up, at most 40 threads and 80 MiB RSS more than the no-node baseline.
3. **Size.** At most 40 MB added to a stripped binary ("Added by the archive, stripped", on both platforms).
4. **Across tailnets.** The cross-tailnet round trip through a device share works, and the host's WhoIs names the member's user (O1 secrets).

A Go panic always ends the process (see "What the source shows", 9). That holds for the helper binary too, but there it ends only the helper. The verdict must weigh it.

## How to run

The top-level agent runs it. It never runs on the Mac (house rules: no heavy builds here). For a Linux rerun by hand, use `devbox-x86` with the secrets through Apassy (`apassy_run_with_secrets`). Never use `ottervibe`.

1. **Secrets (owner step O1),** as repository secrets. All are optional: without them the workflow measures everything that needs no tailnet, and the results say which part was skipped.

   | Secret | What | Used for |
   | --- | --- | --- |
   | `TS_A_AUTH` | Auth key of tailnet A: reusable, ephemeral, pre-approved; tagged `tag:apassy-team` for the product path | Time to up, idle with a node, loopback LocalAPI, state, log; node A and a second node A2 of the round trips |
   | `TS_B_AUTH` | The same for tailnet B, a second Tailscale account | Node B of the cross-tailnet round trip |
   | `TS_A_API` | API access token of tailnet A | `POST /api/v2/device/{id}/device-invites`; deletes the test devices of A |
   | `TS_B_API` | API access token of a user of tailnet B (an access token, not an OAuth client: accepting acts as a user) | `POST /api/v2/device-invites/-/accept`; deletes the device of B |

   Tailnet A's policy must let tailnet B's user reach port 8443 of the shared node. The default "allow all" policy is expected to (not verified). With a custom policy, use the grant of O1 (`autogroup:shared` to `tag:apassy-team:8443`), shown as a diff before it is applied.
2. **Trigger:**
   - `gh workflow run tailnet-spike.yml --ref s4/t0-tailnet-spike` (online on, notarize off)
   - `gh workflow run tailnet-spike.yml --ref s4/t0-tailnet-spike -f notarize=true` (the notarized test build; release secrets of `provider-check`; it keeps no signed binary)
   - Size experiment, second run: `-f go_tags=ts_omit_aws,ts_omit_bird,ts_omit_kube,ts_omit_completion,ts_omit_ssh,ts_omit_taildrop,ts_omit_tap,ts_omit_tpm,ts_omit_wakeonlan,ts_omit_webclient,ts_omit_webbrowser,ts_omit_drive,ts_omit_capture,ts_omit_relayserver,ts_omit_synology,ts_omit_systray,ts_omit_clientupdate,ts_omit_appconnectors,ts_omit_desktop_sessions`. These are candidates from `feature/buildfeatures` of v1.104.1. Keep `serve` and `netstack`: `tsnet.Up` uses the serve config, and tsnet needs netstack.
3. **Read:** `gh run list --workflow tailnet-spike.yml --branch s4/t0-tailnet-spike -L 1`, then `gh run download <run id> -D spike-results`. The job summaries hold the same tables.

| Artifact | Files |
| --- | --- |
| `tailnet-spike-macos-arm64` | `archive/archive.json`, `archive/go-modules.txt`, `archive/libtailscale.ldflags`, `build/build.json`, `build/linked-libraries.txt`, `build/info.json`, `measure.json`, `go-licenses.csv` |
| `tailnet-spike-linux-x86_64-build` | `archive/…`, `build/build.json`, `build/glibc-symbols.txt`, … |
| `tailnet-spike-linux-x86_64-run` | `measure.json`, `round-trip.json` |
| `tailnet-spike-notarize` | `submit.json`, `log.json`, `codesign-*.txt`, `info.json`, `signals.jsonl`, `serve-exit.json` |

The results hold no auth key, no API token, no login or invite URL, no tsnet log, and no e-mail local part (masked `***@domain`). `spike_run.py` refuses to write results that contain a secret.

## Results

Run id: ___. Commit: ___. Date: ___.

### Build

| Number | Source (artifact: file, key) | macOS arm64 | Linux x86_64 |
| --- | --- | --- | --- |
| Go version | `archive.json`: `go` | | |
| Archive build time | `archive.json`: `build_seconds` | | |
| Archive `libtailscale.a` size | `build.json`: `archive_bytes` | | |
| Spike binary, stripped | `build.json`: `spike_stripped_bytes` | | |
| Baseline binary, stripped | `build.json`: `baseline_stripped_bytes` | | |
| **Added by the archive, stripped** (≤ 40 MB) | `build.json`: `added_stripped_bytes` | | |
| Added with the `go_tags` set (second run) | `build.json` of that run | | |
| `#cgo LDFLAGS` of the packages | `archive.json`: `cgo_ldflags` | | |
| Link flags passed by build.rs | `build.json`: `link_flags` | | |
| Linked libraries (frameworks, `-lresolv`; `-lpthread`) | `build.json`: `linked_libraries` | | |
| macOS minimum (`LC_BUILD_VERSION minos`) | `build.json`: `macos_minos` | | — |
| Newest glibc symbol (≤ 2.31) | `build.json`: `glibc_max` | — | |
| T0 tests: 3 acceptance tests + 1 | job log, "Run the T0 tests" | | |
| Go modules in the graph; license report | `archive.json`: `modules_in_graph`; `go-licenses.csv` | | — |

### In process

| Number | Source (`measure.json`) | macOS arm64 | Linux x86_64 |
| --- | --- | --- | --- |
| Signals with a handler before any node (Go's constructor) | `signals.events[when=before_node]` | | |
| Signals with a handler after a node started | `signals.events[when=after_start]` | | |
| Kernel masks SigIgn / SigCgt | `signals.events[proc_signal_masks]` | — | |
| Write to a closed peer: EPIPE, process lives | `signals.events[sigpipe]` | | |
| Rust fault (`crash rust-segv`): how it ends, message, crash report | `crashes["rust-segv GOTRACEBACK=default"]` | | |
| The same with `GOTRACEBACK=crash` | `crashes["rust-segv GOTRACEBACK=crash"]` | | |
| Rust stack overflow: Rust's message or Go's | `crashes["rust-stack-overflow …"]` | | |
| Rust panic (exit 101 expected) | `crashes["rust-panic …"]` | | |
| Go panic through the C API (exit 2 expected) | `crashes["go-panic …"]` | | |
| SIGTERM: exit, seconds | `terminations.SIGTERM` | | |
| SIGINT: exit, seconds | `terminations.SIGINT` | | |
| SIGHUP: exit, seconds | `terminations.SIGHUP` | | |
| Threads at idle: Go runtime, no node | `idle_no_node.threads` | | |
| Threads at idle: node started, control unreachable | `idle_offline_node.threads` | | |
| Threads at idle: node up, 30 s | `online.idle_up_node.threads` | | |
| Memory at idle, no node (RSS KiB; footprint or HWM) | `idle_no_node` | | |
| Memory at idle, offline node | `idle_offline_node` | | |
| Memory at idle, node up | `online.idle_up_node` | | |

### On a tailnet

| Number | Source | macOS arm64 | Linux x86_64 |
| --- | --- | --- | --- |
| Time to up, cold (fresh state, auth key) | `measure.json`: `online.cold_up_ms` | | |
| Time to up, warm (same state, no auth key) | `online.warm_up_ms` | | |
| Loopback LocalAPI answers status | `online.loopback.loopback.status` | | |
| Loopback LocalAPI answers WhoIs | `online.loopback.loopback.whois` | | |
| In-memory WhoIs (what the crate uses) | `online.loopback.in_memory_whois` | | |
| Login URL readable from status without an auth key (`AuthURL`), host, ms | `login_url` | | |
| State directory: mode; files with sizes and modes | `online.state.dir_mode`, `online.state.files` | | |
| `tailscaled.state` keys (no values) | `online.state.state_keys` | | |
| tsnet log: auth key absent; `tskey-` absent; lines naming log.tailscale.com | `online.log` | | |
| Round trip in tailnet A: A2 up ms, round trip ms, A's WhoIs of A2 | `round-trip.json`: `same_tailnet` | — | |
| Share: invite status, accept status | `cross_tailnet.invite_status`, `accept_status` | — | |
| **Round trip across tailnets** (B to A by IP; by MagicDNS name if the IP fails) | `cross_tailnet.round_trip`, `by_magicdns_name` | — | |
| A's WhoIs of B: user of tailnet B (masked), tags | `cross_tailnet.round_trip.peers_seen_by_a` | — | |
| Without a share, B cannot reach A (run without the API tokens) | `cross_tailnet.reachable_without_share` | — | |
| Test devices deleted (HTTP status) | `devices_deleted` | — | |

### Notarized test build

| Number | Source (`tailnet-spike-notarize`) | Value |
| --- | --- | --- |
| Hardened runtime signature verifies | `codesign-verify.txt`, `codesign-display.txt` | |
| Notarization status, issues | `submit.json`: `status`; `log.json`: `issues` | |
| The signed binary runs (`info`, `signals`) | `info.json`, `signals.jsonl` | |
| Signed offline node ends on SIGTERM (exit 143) | `serve-exit.json` | |

### Verdict

GO / NO-GO: ___. Reasons, per criterion 1–4: ___.

## What the source shows (before the run)

From reading libtailscale `ac7ed43a` and tailscale.com v1.104.1 (`tsnet/tsnet.go`, `logtail/logtail.go`, `client/local/local.go`, `ipn/localapi/localapi.go`). The run confirms or refutes each item. Items 1–7 shaped the safe API.

1. **Log upload is on by default.** tsnet always starts logtail (`startLogger`) and uploads to log.tailscale.com. `TS_NO_LOGS_NO_SUPPORT` is not read in tsnet. `go/apassy.go` calls `logtail.Disable()` in `init`. tsnet still writes `tailscaled.log.conf` and buffer files `tailscaled.log*.txt` into the state directory (the state row shows them).
2. **Ambient credentials.** When a field is empty, tsnet reads `TS_AUTHKEY`, `TS_AUTH_KEY`, `TS_CLIENT_SECRET`, `TS_CLIENT_ID`, `TS_ID_TOKEN`, `TS_AUDIENCE`, `TS_CONTROL_URL` (and `TSNET_FORCE_LOGIN`). `TailnetNode::new` refuses to start while any is set, and `spike_run.py` strips every `TS_*` variable from the spike's environment.
3. **`tsnet.Up` has no failure for a node that cannot connect.** It waits through NeedsLogin and an unreachable control server ("TODO: return an error on NeedsLogin"). `tailscale_up` has no timeout, and `tailscale_close` cancels it only after `tailscale_start`: `TsnetClose` skips `Close` for a server not marked started, and `TsnetUp` marks it only on success. The crate calls `start` first, waits for `up` on its own thread with a timeout, and closes on drop. `UpTimeout` carries the backend state and the health messages.
4. **The last error is unsynchronized.** libtailscale keeps `lastErr` as a plain Go string. Any failing call writes it, including `tailscale_accept` and `tailscale_getremoteaddr`, and `s.started` is written the same way. A torn read of a Go string is memory-unsafe in Go. The crate holds its node lock for every call that sets or reads it, except the blocking ones (`up`, `dial`, `accept`), which take it only to read the message after a failure. A small window remains: a blocking call failing while another thread reads. Report upstream: guard `lastErr` with a mutex.
5. **The log descriptor is Go's.** `tailscale_set_logfd` wraps it in `os.NewFile`, and Go closes it when the server is collected. The crate passes a duplicate of stderr or a file it opened (0600), never fd 2.
6. **Descriptor ownership.** `listen` and `dial` return the C end of a socket pair. Go never closes it, and closing the listener end stops the tailnet listener. `accept` returns the descriptor that `recvmsg` installed; Go closed its own copy. The remote address map of a listener (`ln.m`) never shrinks. It is keyed by descriptor number, so it is bounded.
7. **No loopback port is needed.** `tailscale_loopback` opens 127.0.0.1:<port> for the node's life: the LocalAPI behind a password, and SOCKS5 onto the tailnet behind another. The crate's `status` (`tailscale_status_json`) and `whois` (`ApassyTailnetWhoisJSON`) use the in-memory LocalAPI. A team host opens no local port; only the spike's `--check-loopback` calls `loopback`.
8. **Signals.** A c-archive's Go runtime installs its handlers for SIGSEGV, SIGBUS, SIGFPE, and SIGPIPE in a global constructor, before Rust's `main`. Rust's stack-overflow handler installs itself only when SIGSEGV is still SIG_DFL, so it is expected to be missing. A fault in Rust code then reaches Go's handler first. Rust then sets SIGPIPE to SIG_IGN over Go's handler, so writes to a closed socket give EPIPE. Go installs no handler for SIGTERM, SIGINT, or SIGHUP unless `signal.Notify` is called, and `tsnet.go` does not call it. Expected: those keep their default action. The crash probes measure what a Rust fault prints and whether macOS writes a crash report. `GOTRACEBACK=crash` should make Go re-raise the signal.
9. **A Go panic cannot be contained.** A panic in an exported function or in any tsnet goroutine ends the whole process (exit 2). libtailscale panics on a NULL buffer or a zero length; the safe layer never passes one (only `crash go-panic` does). This is the main cost of the in-process node against the helper binary.
10. **Environment races.** The Go runtime of a c-archive initializes on its own thread while Rust's `main` runs, and Go's `os.Setenv` calls `setenv`. `apassy.go` therefore uses `logtail.Disable` and not `envknob.SetNoLogsNoSupport`, which calls setenv. Whether other tsnet paths call setenv is not checked.
11. **The auth key in memory.** The Rust side keeps it in `Zeroizing` buffers and drops them after `up`. Go copies it into `Server.AuthKey`, which lives as long as the server and is never erased. After the first registration the node needs no key: the warm-up row shows a restart with `--no-auth-key`.
12. **Ports.** A listener works before the node is up (`listen` only starts tsnet). A second listener on the same port fails with "tsnet: listener already open for tcp, :8443". `apassy.go` adds no listener. The team host's "8443 only" also needs no `RunWebClient` and no Funnel, and the crate offers neither.
13. **The admin console sees the app as "libtailscale"** (`hostinfo.SetApp`), with the hostname of `TailnetOptions`.

## Not verified here

- That `go/apassy.go` compiles. No Go build ran on this Mac (house rule); the workflow's first step that builds the archive checks it.
- That `build.rs` and the Rust code compile, and that clippy is clean. No cargo build ran on this Mac. The validation commands are below.
- The Tailscale API calls of the cross-tailnet round trip: the create body (`[{"multiUse": false, "allowExit": false}]`), `POST /api/v2/device-invites/-/accept` with `{"invite": <inviteUrl>}`, and their token kinds. `round-trip.json` records each HTTP status.
- Whether a tagged node can be shared. If the invite fails with a tagged `TS_A_AUTH`, rerun with an untagged key to separate the two questions.
- Whether the shared node keeps its 100.x address in tailnet B. The spike falls back to the MagicDNS name.
- Whether Rust's PIE executables link the Go archive on Linux without extra flags (expected: yes, Go's c-archive uses initial-exec TLS).

## Validation commands for the top-level agent

Not run by this unit. On the Mac, only through the queue:

- `~/.local/bin/heavy-check cargo clippy --locked -p apassy-tailnet --all-targets -- -D warnings` (no feature: the safe layer and the stub, no Go)
- `~/.local/bin/heavy-check cargo test --locked -p apassy-tailnet` (unit tests of lib.rs, status.rs, loopback.rs)
- `cargo fmt --all -- --check`
- `python3 scripts/check-release-versions.py` with Python 3.12: unchanged, because the crate is not a release component

The feature `tailnet` needs Go 1.27.3, so it runs in the workflow, not on the Mac. Both build jobs run `cargo test --locked -p apassy-tailnet --features tailnet` and, as their last step, `cargo clippy --locked -p apassy-tailnet --features spike --all-targets -- -D warnings`.
