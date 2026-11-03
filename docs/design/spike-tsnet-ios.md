# Spike: the embedded tailnet node on the iPhone (go or no-go)

Date: 2026-11-03. Status: READY FOR THE DEVICE RUN. Unit T0 of
[implementation plan s8](implementation-plan-s8.md), decision
[ADR 0040](../adr/0040-embedded-tailnet-iphone.md) (option B). Spike only: nothing here ships.

The spike answers one question with numbers measured on the owner's iPhone: can the iPhone app
run its own Tailscale node (libtailscale, in userspace, without a VPN configuration) well enough
for track T? If yes, T1 starts. If no, this file and ADR 0040 record the evidence, track T stops,
and Connect stays the answer (ADR 0040 decision 6).

## 1. The decision rule

Go only when all five hold (plan s8, T0):

| # | Criterion | Go if |
| --- | --- | --- |
| G1 | It works on the device with another VPN on and the Tailscale app off | yes, on Wi-Fi and on cellular |
| G2 | Time from the app becoming active to the Mac's first answer, with saved state, on cellular with the other VPN on (10 tries) | p50 ≤ 2 s |
| G3 | Install size that the node adds | ≤ 30 MB |
| G4 | Log uploads to Tailscale's log servers | none |
| G5 | Licenses of every Go module in the archive | all on the allow list of ADR 0040 §5 |

Every other row of the results table is a measurement for T1 to T4, not a gate.

## 2. What the spike is

A project of its own, `ios/Spikes/TailnetSpike/` (XcodeGen), with its own bundle ID
`com.wydrox.apassy.tailnetspike`. It is not a target or a scheme of the Apassy app, and it does not
link the vault core.

| Path | What it is |
| --- | --- |
| `pins.env` | The pinned versions (section 3). |
| `scripts/build-spike-libs.sh` | Builds `out/LibTailscale.xcframework` (libtailscale as a Go c-archive, iPhone and Simulator slices) and `out/SpikeRust.xcframework`, and writes `out/build-info.json` (sizes and SHA-256 of each archive) and `out/licenses.csv`. |
| `Native/go/apassy_spike.go` | Go hooks that the script adds to libtailscale's `package main`: the no-logs switch, a Go `getenv`, the traceback level, Go crash tests, Go runtime numbers. |
| `Native/rust/` | The Rust probe: it takes the dialed descriptor, sets deadlines, runs rustls (the vault core's `=0.23.46` with ring `=0.17.14`) with a certificate pin, sends one `GET`, and reports. Also the Rust crash tests. |
| `Sources/` | The SwiftUI app. |
| `scripts/mac-target.sh` | A throwaway TLS listener on the Mac's tailnet address, with a fresh certificate and its pin. |
| `scripts/linkmap-sizes.py` | The bytes that each archive adds to the executable, from the link map. |
| `scripts/licenses.py` | Names the license of each linked Go module and checks the allow list. |
| `ExportOptions.plist` | A development export with an App Thinning Size Report. |

What the app does:

- Joins a tailnet with the sign-in URL (an in-app `ASWebAuthenticationSession` sheet, as T4 plans,
  or Safari) or with a pasted auth key (used once, never saved). The state directory is
  `Application Support/TailnetSpike`, excluded from backups, protection
  `completeUntilFirstUserAuthentication` (ADR 0040 §2).
- Dials one address on the Mac through the node (`tailscale_dial`) and gives the descriptor to the
  Rust probe, which runs TLS with the pin over it.
- Records each try: from the app becoming active (or a button) to the node being up, the dial,
  the TLS handshake, and the Mac's first byte. Each try has the network (Wi-Fi or cellular), the
  "Another VPN is on" switch, and the tunnels that iOS shows. It shows p50 and p90 per group.
- Stops the node when the app is hidden: at once, after 30 s with a background task (the plan's
  rule), or never (iOS then suspends it).
- Shows memory (footprint, peak, resident), threads, CPU time, a 5-minute CPU window, the Go
  runtime's numbers, the executable and bundle sizes.
- Shows the no-logs check, the LocalAPI over loopback, the files in the state directory, the node
  log (memory only), and stderr (a file, for the crash tests).
- Has crash tests: three in Go, three in Rust.
- "Copy the results" puts a Markdown summary on the pasteboard. It holds no auth key and no
  sign-in URL.

## 3. Pins (shared with the desktop spike)

| Pin | Value | Why |
| --- | --- | --- |
| Go toolchain | `go1.27.3` (`GOTOOLCHAIN`, checked against sum.golang.org) | libtailscale's go.mod needs ≥ 1.27.1; newest patch on 2026-11-03 |
| libtailscale | `ac7ed43af14e19e1c1810ee9f8319872c6beb412` (2026-10-30) | newest commit; contains the TS-2026-012 fix (fd record framing) |
| tailscale.com | `v1.104.1` (libtailscale's go.mod and go.sum, unchanged) | the build fails on another version |
| go-licenses | `github.com/google/go-licenses/v2@v2.0.1` | the plan's report, as a second opinion |
| Rust probe | rustls `=0.23.46` (ring, std, tls12), ring `=0.17.14`, Rust 1.97.0 | the vault core's versions |
| iOS | 26.0 | the app's deployment target |

The desktop spike (plan s4, T0) had not pushed a pin when this was written. It should source
`ios/Spikes/TailnetSpike/pins.env`, or the two spikes should agree on one file before T1 (plan
s8 T1: "if the s4 plan already owns a libtailscale build ... T1 adds the iOS slices").

tailscale.com `v1.104.5` is the newest patch release. The bulletins after v1.104.1 that the
spike saw (TS-2026-016, TS-2026-017) are about Serve, which the node does not use. T1 decides on
a bump with its own `go.sum`.

## 4. Build and install (the top-level agent)

Heavy steps go through the queue. The first build fetches the Go toolchain and about 1 to 2 GB of
modules into the shared Go module cache.

```sh
cd ios/Spikes/TailnetSpike
~/.local/bin/heavy-check scripts/build-spike-libs.sh           # device and Simulator slices
xcodegen generate --spec project.yml                           # TailnetSpike.xcodeproj, Info.plist
```

Simulator smoke test (no signing; checks the link, the sign-in URL, and a dial):

```sh
~/.local/bin/heavy-check xcodebuild -project TailnetSpike.xcodeproj -scheme TailnetSpike \
  -configuration Debug -destination 'generic/platform=iOS Simulator' -derivedDataPath out/dd build
xcrun simctl boot "<an iOS 26 Simulator>"
xcrun simctl install booted out/dd/Build/Products/Debug-iphonesimulator/TailnetSpike.app
xcrun simctl launch booted com.wydrox.apassy.tailnetspike
```

Device build, size report, and install. **Signing needs the owner's OK first**: automatic signing
with `-allowProvisioningUpdates` registers the App ID `com.wydrox.apassy.tailnetspike` and makes a
development profile (an account change; the spike agent did not do it). Another bundle ID that
already has a development profile works too: add `SPIKE_BUNDLE_ID=<id>`.

```sh
~/.local/bin/heavy-check xcodebuild -project TailnetSpike.xcodeproj -scheme TailnetSpike \
  -configuration Release -destination 'generic/platform=iOS' -derivedDataPath out/dd \
  -archivePath out/TailnetSpike.xcarchive DEVELOPMENT_TEAM=<team> -allowProvisioningUpdates archive
~/.local/bin/heavy-check xcodebuild -exportArchive -archivePath out/TailnetSpike.xcarchive \
  -exportOptionsPlist ExportOptions.plist -exportPath out/export -allowProvisioningUpdates
xcrun devicectl list devices
xcrun devicectl device install app --device <UDID> out/TailnetSpike.xcarchive/Products/Applications/TailnetSpike.app
python3 -I scripts/linkmap-sizes.py out/linkmap-Release-iphoneos.txt
cat "out/export/App Thinning Size Report.txt"
```

Optional: `~/.local/bin/heavy-check cargo test --manifest-path ios/Spikes/TailnetSpike/Native/rust/Cargo.toml`
from the repository root (after the build script seeded `Native/rust/Cargo.lock`) checks the pin
parsing against the companion-v1 vector.

If the link fails with undefined symbols, the missing framework is most likely one of
CoreFoundation, Security, SystemConfiguration, or `libresolv` (already listed in `project.yml`);
add the one that `ld` names. Clean up with `rm -rf out` (it holds the archives, the scratch
checkout, and the Rust target directory).

## 5. The Mac side

On the Mac that runs Tailscale (the owner's Mac mini):

```sh
ios/Spikes/TailnetSpike/scripts/mac-target.sh            # TLS, port 48700
```

It prints one line: `In the spike: Mac 100.x.y.z   Port 48700   TLS on   Pin <pin>`. It listens
only on the tailnet address and logs each caller's address. Keep it running during the test.
macOS can ask whether `python3` may accept incoming connections: allow it. `--plain` gives the same
without TLS. The Mac app's companion listener (port 48620, when "Allow the iPhone app on this
network" is on) also works as a target: leave the pin empty, and the probe reports the pin it saw.

## 6. The owner's test on the iPhone

Before: the iPhone has the spike installed; the Tailscale app is disconnected (Settings › VPN) or
removed; another VPN app is ready (a work VPN or any VPN app; plan step O1). The Mac runs
`mac-target.sh`. Each step names what to tap and what to read. "Copy the results" (in Measure)
copies everything for the table in section 7.

**A. Join (Wi-Fi, other VPN off).**

1. Open **Tailnet spike**. Leave "Auth key" empty. The device name is `apassy-spike-iphone`.
2. Tap **Start**. Read **Backend**: it becomes `NeedsLogin`, and two sign-in buttons appear. Read
   the lines "Sign-in URL via …": which sources gave the URL (status JSON, LocalAPI over loopback,
   node log) and after how many ms. (Rows R11.)
3. Tap **Sign in to Tailscale (in-app sheet)** and sign in with your tailnet's account (you give any
   second-factor code). If the tailnet has device approval, approve `apassy-spike-iphone` in the
   admin console (step O3). Read: **State** becomes `running`, and the sheet closes by itself. Note
   whether it closed.
4. Note whether iOS asked for the Local Network permission, and when. Tap **Allow**. (Row R10.)

**B. One probe.**

5. In **Target on the Mac**, type the address, the port, and the pin from the Mac. TLS on.
6. Tap **Dial and probe**. Read: Result `answered`, Descriptor `socket`, TLS `TLSv1_3`, Pin check
   `match`, the dial and first-byte times, and **Path to the Mac** (direct or DERP). The Mac's
   terminal shows a line with the iPhone's 100.x address. (Row R12.)
7. Change one letter of the pin and tap **Dial and probe** again. Read: Result `failed`, Pin check
   `mismatch`. Put the right pin back.

**C. Time to the first answer.** In **Measure**: "When the app is hidden" = **Stop at once**; both
start switches on.

8. Wi-Fi, other VPN off, switch "Another VPN is on" off. Ten times: go to the Home Screen, wait
   about 5 s, open the spike. Each return adds a `cold` try. Then tap **Run 10 cold starts here**
   once and wait for it to end.
9. Connect the other VPN. Turn "Another VPN is on" on. Check that **Tunnels seen** names the VPN's
   tunnel. Repeat step 8.
10. Turn Wi-Fi off in Control Center (cellular), the other VPN still on. Repeat step 8. (Gate G2.)
11. Cellular with the other VPN off: repeat step 8.
12. Read the group lines under the series button: p50 and p90 of "up" and "answer" for each
    network, VPN state, and kind. (Rows R2 to R4.)

**D. Foreground and background.** Wi-Fi, other VPN on.

13. "When the app is hidden" = **Stop after 30 s (plan)**. Hide the app for 10 s and return: a
    `kept` try (the node still ran). Hide it for 60 s and return: a `cold` try. In **More ›
    Timeline**, read whether the stop came ("node: stopped (hidden for 30 s)") or iOS ended the
    background time first ("background time ended before the stop").
14. "When the app is hidden" = **Keep it**. Hide the app for 2 minutes and return: a `kept` try.
    Read whether the probe answered and how fast, and the line under **Ask the LocalAPI over
    loopback** (it runs by itself after 10 s or more hidden). Repeat once with the phone locked for
    2 minutes. (Row R14.)

**E. Memory and CPU.** Wi-Fi, node running, the app idle on the screen.

15. In **Resources**, tap **Measure 5 minutes in the foreground** and keep the app on the screen
    for 5 minutes. Read the result line. Read Footprint now and peak, Threads, Go goroutines.
    (Rows R8, R9.)

**F. Logs and privacy.**

16. In **Logs and privacy**, read the first line: whether Go saw Swift's `setenv`, and "no-logs
    on". (Row R16.) Open **State files**: note the names, sizes, and protection. (Row R17.)
17. Packet log, one of two ways (Gate G4, row R15):
    - App Privacy Report: Settings › Privacy & Security › App Privacy Report › Turn On, before
      steps C to E. After them, open it › App Network Activity › Tailnet spike, and note every
      domain. No `log.tailscale.com` (or `log.tailscale.io`), no `apassy-relay.wyderka.cc`.
      Positive control: turn **No logs to Tailscale (next launch)** off, close the spike in the app
      switcher, open it, let the node run 3 minutes, and check that the report now shows the log
      domain. Turn the switch on again and close and open the spike.
    - Or the top-level agent captures with the iPhone on USB: `rvictl -s <UDID>`, then
      `sudo tcpdump -i rvi0 -n -w spike.pcap` during steps C to E, and looks for DNS names and
      TLS SNI of the log servers. (sudo is the owner's.)

**G. Crash tests.** Wi-Fi, node running.

18. **More › Crash tests**. Tap one button; the app ends. Open the spike again, go to **More ›
    Crash tests**, and read "The last crash test" and the stderr of the last run (the Go or Rust
    message). Do this for each of the six buttons. Do "Go: panic in a goroutine" twice: once with
    "Go traceback = crash" off and once on.
19. For each, look in Settings › Privacy & Security › Analytics & Improvements › Analytics Data for
    `TailnetSpike-…` and note whether a report exists and its exception type. (Row R13.)

**H. Sign out.**

20. Tap **Log out and delete the node state**. In the admin console, the device shows as logged
    out (remove it there). Tap **Start**: it asks to sign in again. Optional: join once with a
    one-off auth key from the admin console instead of the sign-in, and remove that device after.
21. In **Measure**, tap **Copy the results** and paste the text into section 7 (or send it to the
    agent).

## 7. Results

Fill in after the device run. "Go if" repeats section 1.

| # | Measurement | Go if | Result |
| --- | --- | --- | --- |
| G1 | Works with another VPN on, Tailscale app off: Wi-Fi / cellular | yes / yes | |
| G2 | First answer, cellular, other VPN on, `cold`: p50 / p90 (10 tries, app returns) | p50 ≤ 2 s | |
| G3 | Install size added: thinning report (uncompressed, spike minus a bare app ~1 MB) / link map line `libtailscale` | ≤ 30 MB | |
| G4 | Log uploads (App Privacy Report or packet log; positive control seen) | none | |
| G5 | `out/licenses.csv` verdict / `out/go-licenses.csv` | all allowed | |
| R1 | Download size (thinning report, compressed) | – | |
| R2 | First answer, Wi-Fi, other VPN on, `cold`: p50 / p90 | – | |
| R3 | First answer, Wi-Fi and cellular, other VPN off, `cold`: p50 / p90 | – | |
| R4 | "up" alone, and the series (`cold (series)`), per network: p50 / p90 | – | |
| R5 | Probe with the node already up (`probe (node up)`): answer p50 | – | |
| R6 | Process start to first activation (Timeline, `launch`) | – | |
| R7 | Archive sizes (`out/build-info.json`): device / Simulator | – | |
| R8 | Footprint idle with the node running / peak; resident; threads; goroutines | – | |
| R9 | CPU in 5 minutes in the foreground | – | |
| R10 | Local Network permission: asked? when? path with Allow / with Don't Allow | – | |
| R11 | Sign-in URL sources and times (status JSON, LocalAPI over loopback, log); sheet closed by itself? | – | |
| R12 | Descriptor to Rust: kind, deadlines, TLS version, pin match and mismatch | works | |
| R13 | Crash tests: app ends? stderr message? crash report and exception type? (6 tests, Go twice) | – | |
| R14 | Background: 30 s stop or background time ended; `kept` after 2 min hidden and after a lock: answered? time? LocalAPI over loopback after return | – | |
| R15 | No request to `apassy-relay.wyderka.cc` | none | |
| R16 | Swift `setenv` seen by Go? no-logs on after the Go call? | – | |
| R17 | State files: names, sizes, protection; directory excluded from backup | – | |
| R18 | Admin console: device name and the app it shows; logout result | – | |

Verdict: GO / NO-GO, with the date and the rows that decided it.

## 8. Found before the device run (from the pinned code)

These come from reading libtailscale `ac7ed43a` and tailscale.com `v1.104.1`. The device run
confirms or corrects them.

1. **tsnet always starts its log uploader.** `tsnet.Server.startLogger` runs except in tests. It
   writes `tailscaled.log.conf` (log IDs) and creates `tailscaled.log1.txt` and `.log2.txt`
   (filch buffers) in the state directory. `TS_NO_LOGS_NO_SUPPORT` makes the upload transport a
   no-op, and `logtail.Disable()` drops each entry before it reaches the buffer. The spike does
   both from Go (`ApassySpikeNoLogs`). The files still exist, likely empty: T3 decides if that
   meets "the local log does not go to disk" (ADR 0040 §2) or patches it.
2. **A `setenv` in Swift may not reach Go.** The Go runtime of a c-archive starts when the library
   loads, before `main`, and Go reads the environment from its own copy. So T3's "sets
   `TS_NO_LOGS_NO_SUPPORT=1` before the start" may do nothing. The spike shows the answer (R16);
   the safe way is a Go call, as the spike does.
3. **`tailscale_dial` has no deadline.** It dials with `context.Background()`. A dial to a peer
   that does not answer blocks until the netstack gives up. The core's dialer of T2 has a
   `timeout_ms`: T1 needs a Go export with a deadline (our own file in package main, as the spike
   adds one) or an upstream change.
4. **The sign-in state needs no TailscaleKit.** `tailscale_up` blocks until `Running` (or until
   `tailscale_close`), so it runs on its own thread. `tailscale_status_json` reads the status
   through tsnet's in-memory LocalAPI, with `BackendState` and `AuthURL`. libtailscale says iOS
   takes the loopback TCP listener of a suspended app, so the loopback LocalAPI (TailscaleKit's
   way) can go stale after a return; R14 checks it. Likely answer to ADR 0040 D4: the C API for
   the dial and for the state.
5. **A Go panic exits without a crash report.** In a c-archive a Go panic ends with `exit(2)`
   unless `GOTRACEBACK=crash`. T3 likely sets `debug.SetTraceback("crash")` at start, so a fault
   in Go reaches the crash reporter (R13).
6. **The descriptor is an AF_UNIX socket pair end**, close-on-exec, which Go copies to the tailnet
   TCP connection. Rust holds it as a `UnixStream`; read and write deadlines are those of the local
   socket. Closing it closes the tailnet connection.
7. **libtailscale names the app.** `hostinfo.SetApp("libtailscale")`: the admin console may show
   the device as such (R18).

## 9. Risks seen

- The spike was written without a compile on this Mac (the shared-Mac rule). The first build can
  need small fixes: the Swift import of the C header (`tailscale_new()` has no prototype), link
  flags, `ASWebAuthenticationSession`'s callback API, `kinfo_proc` field names.
- Signing a device build is an account change (section 4).
- The node runs only in the foreground. A return after a long suspension pays the full start time;
  G2 measures exactly that case.
- Size: the archive holds the whole Tailscale client (gVisor netstack, WireGuard, the control
  client, and maybe the web client assets of `tailscale/web-client-prebuilt`). The link map line
  shows what stays after dead stripping.
