# ADR 0040 — Embedded tailnet on the iPhone

Date: 2026-11-03.
Status: PROPOSED; built under the owner's instruction of 2026-11-03 unless the owner changes it.
ADR 0037 stage 8 names this work: "Embedded tailnet on the iPhone, so it needs no Tailscale app".
The desktop and Linux part of the embedded tailnet is ADR 0037 D9, in stage 4. No release,
account change, App ID registration, or tailnet policy change is authorized by this ADR.
Plan: [implementation plan, stage 8](../design/implementation-plan-s8.md), track T.

## Context

- ADR 0037 makes each Mac and Linux machine a node. The iPhone reaches its node over the tailnet
  with a pinned certificate (D4). Today that needs the Tailscale app on the iPhone.
- iOS connects one VPN at a time. The Tailscale app is a VPN (a packet tunnel). A user whose work
  VPN is on cannot have Tailscale on at the same time, so the tailnet route is gone at work
  (ADR 0037, risks). Today the only answer is paid Connect (D2, D14).
- Some users do not want the Tailscale app, or a VPN icon, on their phone.
- The iPhone app needs the tailnet only for its own connections: questions, feed, and access
  requests (and later sync) to the owner's nodes. Nothing else on the phone needs it.
- The app talks to a node only in the foreground. It never syncs in the background, and its long
  polls run only while it is active (`ios/README.md`). A push through the gateway (ADR 0037 §7)
  tells the owner to open the app.
- The relay client on the iPhone is the Rust core (`src/sync/relay_http.rs` through
  `ios/ApassyCore`), with its own sockets and rustls. Stage 2 adds the pinned trust mode
  (`TlsTrust::Pinned`, plan 0037 unit 2C). ADR 0039 already added one seam to it: an external HTTP
  transport for the watch.
- Tailscale publishes its client as Go code under BSD-3-Clause. `libtailscale` (BSD-3-Clause)
  builds it as a C library (`go build -buildmode=c-archive`). Its Swift package TailscaleKit has
  frameworks for iOS and the iOS Simulator, a dial and listen API, and a URLSession proxy. A node
  joins with an auth key or with a sign-in URL. The screens and the packet tunnel of the Tailscale
  iOS app are not open source.

## Options

| | A. Packet tunnel in Apassy | B. A tailnet node inside the app, without a VPN | C. Keep the Tailscale app |
| --- | --- | --- | --- |
| How | A Network Extension packet tunnel provider runs the Tailscale client and routes 100.64.0.0/10 and fd7a:115c:a1e0::/48 for the whole phone | The app runs the Tailscale client in userspace (its own WireGuard and TCP/IP stack, gVisor netstack) and dials the node through it. Only Apassy's own connections use it | No change: the system route through the Tailscale app |
| Work VPN | Does not help: it is one more VPN, and iOS runs one at a time | Works: WireGuard and DERP packets are ordinary app traffic, also through a work VPN | Does not help |
| Background | The tunnel runs while the app does not | Only while the app is open, and a short grace | The Tailscale app's tunnel |
| Entitlement | Network Extension (packet tunnel) on the app and on a new extension App ID; new profiles | None new | None |
| App Review | Guideline 5.4 (VPN apps): NEVPNManager, organization enrollment only, a data declaration before use | Not a VPN service: no VPN configuration, no traffic of other apps | — |
| Memory | The extension has a hard limit of about 50 MB | The app's normal limit | — |
| Code | A tunnel provider, its configuration and on-demand rules, and VPN screens: in practice a new Tailscale client | One Go library, a dial seam in the core, a sign-in screen | None |
| Conflicts | With the Tailscale app and with every other VPN | None | — |

## Decision

1. **Option B.** The iPhone app runs its own Tailscale node in userspace, with libtailscale, linked
   into the app as a static library. Apassy uses it only for its connections to the owner's nodes.
   It makes no VPN configuration and carries no traffic of other apps.
2. **The Tailscale app stays supported.** A pairing that works through the system route keeps it.
   The embedded node is a setting of this iPhone, "Connect without the Tailscale app". The app
   offers it:
   - in the pairing flow, when the node does not answer over the system route within 2 seconds;
   - in the quiet state "Tailscale is off on this iPhone" of Requests (plan 0037 unit 2G);
   - in Settings › Devices › Tailscale connection.

   When the setting is on, every node route of this iPhone uses the embedded node. There is no
   silent fallback to the system route, so the route is always the one that Settings names.
3. **Only in the app.** The AutoFill extension and the Apple Watch app do not link it. AutoFill
   never syncs (ADR 0023 §5). watchOS gives this kind of app no sockets (ADR 0039 §5), so the watch
   keeps its own route.
4. **Authorization does not change.** Tailscale only connects. The lock stays the pinned TLS of the
   node (D4) and the device-signed requests of ADR 0019. TLS runs in the Rust core over the dialed
   stream, end to end to the node, with the same pin check as the system route.
5. **One tailnet per iPhone.** The owner's tailnet. A team host in another tailnet is reached by node
   sharing, as with the Tailscale app (ADR 0037 §9). Several tailnets at once (a team tailnet) need
   several nodes in the app: later (D5).
6. **If the spike fails, stop.** Plan unit T0 decides go or no-go with measurements. A no-go does
   not switch to option A, because A does not fix the work VPN case and needs a decision on App
   Review 5.4. This ADR then records the evidence, and Connect stays the answer.

## 1. The dial seam

- The app registers a stream dialer with the core: `apassy_core_set_stream_dialer`, once per
  process, before the first relay call (as `apassy_core_set_http_transport` of ADR 0039).
- For a node link whose route is `tailnet-embedded`, `relay_http` asks the dialer for a connected
  stream to the node's address and port. The dialer returns a file descriptor (libtailscale's dial
  gives one). The core owns it from then on.
- The core sets its deadlines on it, runs the pinned rustls client over it, and shuts it down on
  `Cancel::close`. The paths, bearer, body limits, and errors are those of the system route.
- No dialer, or a dialer error, is a `Connect` error. The core never opens a direct socket for such
  a link.
- The core does not link Go. The AutoFill extension and the watch link the same core without the
  library.

## 2. How the iPhone joins the owner's tailnet

| Way | When | What the owner does | The device in the tailnet |
| --- | --- | --- | --- |
| Sign in to Tailscale (default) | Always | Taps "Sign in to Tailscale". The app opens the sign-in URL that the node reports (`ASWebAuthenticationSession`). The owner signs in with the identity provider of the tailnet. With device approval on, the owner also approves the device in the Tailscale admin console | A device of the owner's user, named `apassy-<iPhone name>`. Its key expires with the tailnet's key expiry (180 days by default); then the app asks to sign in again |
| A one-use key from the Mac | The Mac's vault holds a Tailscale OAuth client (an Apassy credential) | Nothing more: the scan of the pairing code also joins the tailnet | A tagged device (`tag:apassy-device`). Tagged devices have no key expiry by default |
| Headscale | The node's pairing link names a control URL | Signs in with the Headscale OIDC login, or uses a pre-auth key from `headscale preauthkeys create` | As above, on the owner's control server |

The one-use key:

- The Mac makes it at "Add a device" with the Tailscale API (`POST /api/v2/tailnet/-/keys`): one
  use, pre-authorized, tag `tag:apassy-device`, not ephemeral, valid for 10 minutes.
- It is in the fragment of the pairing link (a new field of node-pairing-v1). Before it joins, the
  iPhone has no path to the node, so the key cannot come later through the node.
- The Mac deletes the key when the iPhone appears in the tailnet, or when the pairing ends.
- A photo of the code lets one more device join the tailnet once, within 10 minutes, as
  `tag:apassy-device`. It still cannot pair with Apassy: that needs the safety words and the owner
  check on the Mac. The guide gives a policy grant that lets `tag:apassy-device` reach only the
  node port.
- The OAuth client and the tag owner rule are settings of the owner's tailnet. Apassy does not
  change the tailnet policy.

What the node keeps:

- The state directory (the machine key, the node key, the last network map) is in the app's own
  container, not in the App Group. It is excluded from backups and has the file protection
  `completeUntilFirstUserAuthentication`. A restored backup on another iPhone has no tailnet state,
  so that iPhone signs in again.
- "Disconnect from Tailscale" in Settings logs the node out and deletes the directory.
- Revoke on the Mac stops the Apassy device at its next request (ADR 0037 §4). The tailnet device
  stays in the admin console until the owner removes it; with the OAuth client, the Mac removes it
  too.
- The node sends no client logs to Tailscale's log server (`TS_NO_LOGS_NO_SUPPORT`), and its local
  log does not go to disk. T0 confirms this with a packet log.

## 3. Lifetime, background, and battery

- The node starts when the app becomes active and an unlocked vault has a membership with the
  embedded route, or during pairing.
- It stops 30 seconds after the app leaves the screen (a background task), and when every vault is
  locked.
- It never runs in the background. iOS suspends the app, and its sockets with it. The app adds no
  background mode.
- A push through the gateway still tells the owner that a question waits (ADR 0037 §7). A tap opens
  the app, and the node starts from its saved state. The wait for the question grows by the start
  time of the node. Target: under 2 seconds on cellular with saved state (measured in T0).
- Battery: the node runs only while the owner looks at Apassy. While it runs, it keeps one
  connection to the control server, one to its home DERP server, and WireGuard keepalives to the
  node. There is no always-on tunnel, as the Tailscale app has.
- A large tailnet sends a large network map. That costs memory and start time. T0 measures a tailnet
  of the owner's size; a tailnet with hundreds of devices is a known limit.

## 4. App Store, entitlements, and privacy

- No new entitlement, capability, App ID, or provisioning profile. No change to the AutoFill
  extension or the watch.
- Not a VPN app under guideline 5.4: the app makes no VPN configuration and does not carry other
  apps' traffic. The App Review notes say what the connection is for.
- The App Privacy answers name the control server: the owner's Tailscale account (or Headscale)
  receives the device name, the OS version, and the IP addresses. The owner chose that service.
- The export answer stays as decided (ADR 0023 §8). The app already has its own TLS and SQLCipher;
  WireGuard adds standard encryption of the same kind. The review of the export classification
  (ADR 0023 D4) covers it.
- The app grows by the Go runtime and the Tailscale client. T0 measures the download and install
  sizes.
- The app uses the name Tailscale only to describe the connection ("Connect without the Tailscale
  app"). It does not use the Tailscale logo.

## 5. Licenses

- libtailscale and the Tailscale client: BSD-3-Clause. wireguard-go: MIT. gVisor: Apache-2.0. Go:
  BSD-3-Clause. All allow static linking into an Apache-2.0 app with their notices.
- The build writes the notice of every Go module in the archive (go-licenses) into `licenses/`,
  which Settings › Licenses shows.
- The build fails on a license outside the allow list: BSD, MIT, Apache-2.0, ISC, and MPL-2.0 with
  its notice and a source link.

## 6. Work VPN and other networks

- With a work VPN on, the node's packets go through it as ordinary app traffic. If the work network
  allows UDP, WireGuard reaches the Mac directly. If it allows only HTTPS, the node uses a DERP
  relay over TCP 443.
- The tailnet addresses live inside the app's own network stack, so a work VPN that uses
  100.64.0.0/10 does not conflict.
- A network that blocks Tailscale's control and DERP servers blocks the node. Then Connect (paid)
  is the route.
- A managed iPhone can block the app or its servers. Apassy does not try to get around a company
  policy.
- A direct path to a node on the same Wi-Fi needs the Local Network permission, which the app
  already asks for. Without it, the node uses DERP.

## What this does not protect

- **The tailnet key on the phone.** A person who copies the state directory from an unlocked phone
  joins the tailnet as that device and reaches what the tailnet policy allows. The Tailscale app has
  the same property. Limit the device with a policy grant to the node port, and remove the device
  in the admin console after a loss.
- **The control server** sees the device and its addresses, not the traffic. DERP sees WireGuard
  ciphertext (ADR 0037, "Who sees what").
- **Two runtimes in one process.** A fault in the Go code can end the app. The Go code has no vault
  API, but it shares the process memory, as any linked library does.

## Consequences

- A user with a work VPN gets the tailnet route on the iPhone back, for free. ADR 0037's first risk
  gets a second mitigation besides Connect.
- A new user needs a Tailscale account, but not the Tailscale app on the phone. The Mac still needs
  Tailscale until the desktop embedded node of D9 also serves the personal route (a later decision).
- The iPhone app carries a Go library with its own security updates. The pin follows Tailscale's
  security bulletins.
- The trust model (`docs/security/trust-model.md`) gains a row: the embedded iPhone node, its
  control server, and no logs.

## Open decisions

The recommendation of each row is what the plan builds unless the owner changes it.

| # | Decision | Recommendation |
| --- | --- | --- |
| D1 | Option | B: a userspace node inside the app (section "Decision"). |
| D2 | Route of a new pairing | The system route when the node answers through it within 2 seconds; else offer the embedded node. |
| D3 | How the iPhone joins | Sign-in by default; a one-use key when the Mac holds a Tailscale OAuth client; Headscale with its control URL. |
| D4 | libtailscale C API or TailscaleKit | The C API for the dial, because the core needs a file descriptor. TailscaleKit for the sign-in state, if its LocalAPI part is enough. T0 decides. |
| D5 | Several tailnets on one iPhone | Later, with team tailnets (ADR 0037 §9, large teams). |
| D6 | Option A | Not built. Revisit only if delivery over the tailnet in the background is needed and push is not enough. |
