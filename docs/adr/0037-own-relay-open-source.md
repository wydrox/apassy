# ADR 0037 — Your own relay: every Mac and Linux node serves itself, and all of Apassy is open source

Date: 2026-11-02.
Status: ACCEPTED by the owner on 2026-11-02 (all decisions D1 to D14, in the table at the end). TEE
features are an enterprise track that comes later. Progress (2026-11-03): stages 0 and 1 shipped in 0.5.14 (#66): the relay is the crate `crates/apassy-relay`, and the hosted relay serves no team vaults. The cloud slice of stage 2 is in the draft PRs #85, #86, #87, #89 and #92. Stages 3 to 8 have not started.
Cloud slice first (owner, 2026-11-03): [docs/design/implementation-plan-0037-cloud-agents.md](../design/implementation-plan-0037-cloud-agents.md).
When accepted, it replaces the hosted parts of ADR 0016 §5, ADR 0019 (a multi-tenant relay that the
operator runs for teams), the default relay address of ADR 0022, and Connect creation on an
Apassy-run server (ADR 0032). It keeps every wire contract and the device identity of ADR 0019.
Plans and prices: [plans](../product/plans.md) (D2, D3, D7, and D14 in one page).

## Context

The owner wants users to trust Apassy because they own the whole path of their credentials. Today
one part of that path is a server that the owner runs for everyone.

### What the hosted relay holds and sees today

| Function | What the hosted relay or its edge can see |
| --- | --- |
| Team runs, way B (ADR 0016) | The real value, in memory, for each released run session. The relay is the proxy to the upstream host (relay `docs/SPEC.md` §20, §21). |
| Team vaults | Every team file. The master key is a file on the same VPS, so a disk snapshot is a full copy of all teams (ADR 0019 §2). |
| Relay sync (paid) | SQLCipher ciphertext and its salt, sizes, and times (ADR 0022). |
| Questions, feed, access requests (Free, through Connect) | Sealed ChaCha20-Poly1305 envelopes, plus the team id, question id, routing bit, expiry, sizes, and times (relay-questions-v1 §6). |
| Push | The Cloudflare Worker holds the APNs key and sends one fixed notification per device token (SPEC §25.6). |
| Edge | Cloudflare ends TLS and sees all traffic in clear: session keys in paths, placeholders in headers, invite codes in join bodies (SPEC §20, ADR 0019 §3). |

The core (`wydrox/apassy`) is Apache-2.0 and public. The relay (`wydrox/apassy-relay`, about 31,000
lines of Rust, with `apassy-team` and the Worker) is private and under FSL-1.1-ALv2. A user cannot
read or build the server that sees their values.

### What already makes the move possible

- The relay is one binary: a synchronous HTTP server (`tiny_http`), SQLCipher files, and no async
  runtime. It can run as a thread of another process.
- The wire contracts take the relay origin as a value (Connect signs `<origin>`). Device identity
  (ADR 0019 keys, one-use link codes, safety words, owner-confirmed joins) does not depend on who runs
  the server.
- The Mac app already has a network listener with TLS 1.3 and a pinned self-signed certificate
  (`src/companion/`, about 6,900 lines, ADR 0020).
- The desktop UI is eframe (egui), which also runs on Linux. The core builds and passes its tests on
  Linux. Linux has no agent isolation yet (README).

### The T3 Code model

T3 Code solves the same shape of problem for coding agents (from the `t3` CLI help on this Mac,
2026-11-02):

| T3 Code | What it does |
| --- | --- |
| `t3 serve`, `t3 up` | Each machine runs its own server as a background service. `up` chooses the routes. |
| `--tailscale-serve`, `t3 pair --tailscale` | Publish the server on the tailnet with Tailscale Serve HTTPS. |
| `--lan` | LAN and tailnet access, where "a pairing code is the only lock". |
| `t3 pair` | A one-time pairing token as a QR code, with scopes and a TTL (default 5 minutes). |
| `t3 environment link` | Link another machine so agents here can work there. Revocable in Settings → Connections. |
| T3 Connect | An optional account-based route. `t3 connect publish` sends push notifications and Live Activities to mobile clients. |
| `t3 status`, `t3 doctor` | Show the routes and whether other devices reach this machine. Repair. |

Tailscale gives reachability only. Authentication stays with T3's own pairing tokens.

## Decision (proposed)

### 1. The rule

No Apassy-run server holds a key that opens a credential, a vault, a question, or an answer. A value
is opened only on a device of the user or of the user's team. Every part that touches a value is
Apache-2.0, and a user can build it from this repository.

### 2. One node, on macOS and Linux

A **node** is one Apassy process with its vaults, the broker, the bouncer, and the relay server.

- **macOS:** the Mac app runs the node in its backend while the app runs (login item).
- **Linux:** `apassy serve` runs the same node without a window, as a systemd user service. A Linux
  window comes later, from the same egui UI.
- The relay crate moves into this repository as a workspace crate (`crates/apassy-relay`) under
  Apache-2.0. `apassy-team` becomes subcommands of `apassy`.
- The relay server listens on loopback only. A route (section 3) makes it reachable. Nothing listens
  on `0.0.0.0`.

What changes when the relay runs on a node:

| Hosted relay today | On a node |
| --- | --- |
| Master key file on the VPS | In the vault and the Keychain (macOS); systemd credentials or a 0600 file (Linux) |
| `X-Apassy-Edge` secret added by the Worker | Removed. The route and device-signed requests replace it. |
| Operator team codes and Connect capacity limits | The node owner is the operator. A personal node needs no code. Per-member abuse limits stay. |
| One SQLCipher file per team | Stays. One node can host several teams. |
| The upstream filter refuses private addresses | Stays, and matters more: a home node is on a LAN. |

### 3. Routes

| Route | Default | For | Lock |
| --- | --- | --- | --- |
| Local | On | Agents on the same machine | Unix socket and agent token, as today |
| Tailnet | On after setup | iPhone, other Macs, Linux nodes, team members | Device-signed requests (ADR 0019). TLS: a pinned certificate on the tailnet address, or a Tailscale Serve certificate (D4) |
| SSH | Per link | A Linux box, a devbox, or CI without Tailscale | `ssh -R` forward of the node port; the same device identity |
| LAN | Off | Home use without Tailscale | Pinned TLS and pairing. It replaces the companion-v1 protocol (D6). |
| Apassy Connect | Off; paid (D2) | Users without Tailscale, or with a work VPN | A byte relay, like DERP: TLS runs end to end between the two nodes with the pinned certificate, so Connect sees only TLS records. Never way B, never a team key. |
| Public (Tailscale Funnel) | Off | Cloud agent sessions that cannot join a tailnet | Agent tokens; only the `/p/` proxy and MCP |

- Tailscale identity is never authorization. As defense in depth, a node can ask the Tailscale
  LocalAPI (WhoIs) for the peer and refuse peers outside the owner's tailnet.
- A custom control server (Headscale) works, because the node needs only a tailnet address. This is a
  documentation task.

### 4. Pairing

"Add a device" in the app, or `apassy pair`, shows one QR code with the node's route URLs, the
certificate pin, and an ADR 0019 device link code (one use, 10 minutes). Roles: approving iPhone,
sync peer (Mac or Linux), linked environment, team member. The safety words and the owner-confirmed
join stay the authority. Settings → Devices lists each device with its role, route, and last contact,
and has Revoke. `apassy status` and `apassy doctor` show which routes are on, what is exposed, and
whether peers reach the node.

### 5. What each function becomes

| Function | Where it runs | Note |
| --- | --- | --- |
| Questions, feed, access requests to the iPhone | The Mac node that asks | Same contracts (relay-questions-v1, relay-feed-v1, relay-access-request-v1) at a new origin. A sleeping Mac runs no agents, so it has no questions. |
| Vault sync | Node to node. One node is the sync home (D5). | Same relay-sync-v1 contract and signed heads. A peer that was offline catches up. iCloud folder sync stays. Later, the iPhone can sync from a node too. |
| Team vault and way B | The team host node, which is also the key holder | The operator and the key holder become one party: the team. An always-on Linux node is the recommended host. |
| Remote MCP and `apassy run` for agents on other machines | Linked environment → home node or team node | Section 6 |
| Push to the iPhone | Push gateway (section 7) | The only Apassy-run service, and optional |
| Connect onboarding (ADR 0032) | Replaced by pairing with the Mac node | No questions-only team on an Apassy-run server |
| Browser extension | No change | Native messaging to the local app |

### 6. Linked environments

`apassy environment link ssh://host` or `apassy environment link <tailnet name>` (as
`t3 environment link`) installs a thin executor on a Linux machine. An agent there calls
`apassy run` or MCP. The home node decides (local bouncer, owner approval on the iPhone) and is the
proxy: way B, but on the user's own node. The Linux machine gets only placeholders and base URLs, so
the missing Linux isolation does not expose a value.

A full Linux node that runs agents with its own vault and local broker waits for Linux isolation
(Landlock or bubblewrap).

### 7. Push gateway

Only the holder of the APNs key for the app's bundle id can push to the App Store and TestFlight
iOS app. So one small service stays:

- `apassy-push`, Apache-2.0, in this repository (today's Worker push route, moved and published).
  Input: a device push token and a per-registration secret. Output: the fixed notification that the
  relay sends today, with the constant collapse id. No question data.
- What it sees: device tokens, the node's IP address, and times.
- Optional. Without push, the iPhone shows requests when the app opens. A user who builds the iOS app
  with their own bundle id runs their own gateway.
- Later: a Notification Service Extension opens a sealed summary on the phone, so the notification
  can say more while the gateway still sees nothing.

### 8. Proof, not promises

- Reproducible builds for the Linux binaries and the relay. GitHub build attestations and an SBOM for
  each release artifact. For macOS, a documented check that the notarized app contains the binaries
  built from the tagged source. For the extension, a check that the store package equals the build
  from source.
- `docs/security/trust-model.md`: each party (Apassy project, Tailscale control server, DERP relays,
  Apple and APNs, iCloud, push gateway, Connect, team host) and exactly what it can see.
- The relay history becomes public after a secret scan (D1).

### 9. Sharing between two tailnets

Example: Rafal and Konrad each have their own tailnet. Rafal owns the team.

```
Rafal's tailnet                                Konrad's tailnet
┌──────────────────────────────┐   Tailscale   ┌───────────────────────┐
│ team host node               │◄──── share ───│ Konrad's Mac (node)   │
│  key holder, team file,      │  (Konrad's    │ Konrad's iPhone       │
│  way B proxy                 │  devices dial │                       │
│ Rafal's Mac, Rafal's iPhone  │   in; the     └───────────────────────┘
└──────────────────────────────┘   host cannot dial out)
```

- **Network:** Rafal shares one node, the team host, with Konrad's Tailscale user (node sharing).
  Konrad's devices reach it by its full name, `<host>.<Rafal's tailnet>.ts.net`. Nothing else in
  either tailnet is visible. Tailscale quarantines a shared node: it answers connections but cannot
  start them. Every Apassy request is client-started (long polls), so this costs nothing, and a
  compromised team host cannot reach Konrad's tailnet. Rafal's tailnet policy applies to Konrad's
  connections.
- **Authority:** Tailscale only connects. Membership, roles, and grants stay in Apassy (ADR 0019).
  Konrad's device joins with the invite code, both sides compare the safety words, and Rafal confirms
  with Touch ID.

Flow:

1. Rafal: Team → Invite → Konrad, with a role and collections. Apassy makes the ADR 0019 invite and a
   Tailscale device share invite for the team host. Stage 4 opens the Tailscale admin console for the
   share. Later, Apassy calls `POST /api/v2/device/{deviceID}/device-invites` with Rafal's Tailscale
   API token, kept as an Apassy credential. One link goes to Konrad through a private channel.
2. Konrad accepts the share. The team host appears in his tailnet.
3. Konrad opens the Apassy part of the link. His node connects with the certificate pin, sends its
   device key, and both sides show the safety words. Rafal confirms.
4. Konrad's agent asks for a run. His node sends it to the team host, which checks the policy and
   asks the approvers (Rafal's iPhone, through Rafal's tailnet). After approval, the team host opens
   the value and is the proxy. Konrad's agent holds only placeholders. The value never leaves Rafal's
   host.
5. Revoke: removing Konrad in Apassy stops his next request. Revoking the Tailscale share also cuts
   the network path.

Consequences:

- **Never share a personal Mac.** A share exposes the whole node. With the default tailnet policy
  (allow all), Konrad reaches every port that the node listens on in the tailnet. Use a host that
  runs nothing else, or a grant that permits only the Apassy port to Konrad (D9).
- **The host must be online** for every run of every member. Recommend an always-on host.
- **Way B sends the members' API traffic through the host.** Rafal's host sees Konrad's agents'
  requests to the upstream API (Stripe, OpenAI, …) and their answers. This is the price of "the
  value never leaves the key holder". A collection can choose way A instead (D10).
- **Encryption in way B.** Konrad's node to the team host: WireGuard and the pinned TLS (through
  Connect: TLS end to end). Team host to the upstream API: HTTPS. On the host the request is in
  clear, by design: to put the real value in the auth header, the host ends the agent's TLS and opens
  a new TLS connection upstream. Anyone with root on the host can read those requests and answers.
  No practical encryption removes this, because the party that adds the secret must hold the session
  keys (multi-party TLS exists in research, but is not practical here). Limits: only team credentials
  pass through the host, never a member's personal vault. The proxy must store no bodies, and the audit
  must keep only the host, method, status, and sizes (stage 4 checks what the relay logs today). That
  is a property of the code, not of cryptography. Teams that
  need more can later run the host in a confidential VM with attestation.
- **Symmetric.** Konrad can host his own team and share his host with Rafal. One node can host
  teams and be a member of other teams. Each team stays one file.
- **No Tailscale, or a work VPN:** Konrad's node reaches the team host through Apassy Connect (paid),
  with TLS end to end. Connect sees only TLS records.
- **Large teams:** a team tailnet (a company Tailscale account or Headscale). The system Tailscale
  client is signed in to one tailnet at a time, so this needs the embedded node of D9.

### 10. More privacy for shared use

Way B gives the host the members' traffic. Way A gives the member the value. These steps reduce
both, best first.

| Step | How | Traffic | Value | Works for |
| --- | --- | --- | --- | --- |
| 1. Short-lived credentials (way C, D11) | The host keeps the long-lived secret. For each run it makes a new credential, valid for minutes and narrowed to the run's scope, and seals it to the member's device key. | Direct from the member | Only the short-lived credential reaches the member | AWS STS sessions with a session policy, Google Cloud access tokens, GitHub App installation tokens, OAuth access tokens (the host keeps the refresh token), Cloudflare tokens with an expiry, temporary database roles |
| 2. Remote signing | For APIs that sign each request (AWS SigV4): the member's node sends the canonical request with the payload hash, and the host returns the signature. | Direct. The host sees the method, path, signed headers, and payload hash, but not the body. | Stays on the host | AWS without STS, other HMAC-signed APIs |
| 3. A key per member | The host makes one key per member with the provider's key-management API. | Direct | The member gets a key of his own. Removing him deletes that key; the team key stays. | Providers with a key-management API |
| 4. A confidential way B host (section 11; enterprise, E1) | The swap runs in a confidential VM (AMD SEV-SNP or Intel TDX). Each node checks its attestation against the reproducible build before it sends traffic or keys. Without a confidential VM: a host that runs nothing else, with no stored bodies, no swap, and no core dumps. | Through the VM, not the owner's machine. Its operator cannot read it. | Stays in the VM for the run | Static bearer keys (OpenAI, Anthropic, most SaaS APIs) |
| 5. Split TLS (research; enterprise, E3) | The member's node opens the TCP connection to the API and tunnels the TLS handshake to the host. The host checks the API's certificate, sends the request head with the real value, sends a TLS 1.3 KeyUpdate, and gives the member only the new client key and the server key. The old client key does not follow from the new one, so the member cannot open the record with the value. The body and the answer never reach the host. It needs no TEE: the host can be an ordinary VPS or the owner's Mac, because it is not on the data path. | Direct after the request head | Stays on the host | Static keys in a header, HTTP/1.1, one request per connection. Needs a prototype and a cryptography review before any use. |

#### The way A switch

The owner can turn on way A for any collection, production included. The app gives clear
information instead of a hard rule:

- The collection setting "Where members use these credentials" has two answers: "On the team host
  (recommended)" and "On each member's device". Items with way C show "Short-lived credentials" in
  both.
- Turning on "On each member's device" shows one confirmation with the facts: "Members' devices will
  receive the real values of N credentials. A member can keep a copy. To remove a member later, you
  must replace these credentials." When the collection has production credentials, it adds: "This
  collection has production credentials. A copied production credential works until you replace it."
  When some items support way C, it names them and says that they stay short-lived. The change needs
  a fresh owner check.
- The collection and each of its items show a badge: "Values go to members' devices".
- Removing a member lists every credential that member received in way A, with "Replace now" where
  Apassy can rotate it.
- The audit records each value delivery: member, device, item, run, and time. Never the value.

### 11. Confidential team host (enterprise track, later)

The build path does not include this section (D12). When a TEE is needed: only where a server that is not the user's own machine must **use** a static
key (the way B swap). Storage never needs one: vaults, sync copies, and questions are encrypted
with keys that only the user's devices hold, so Connect stores and carries only ciphertext.

| Situation | TEE | Why |
| --- | --- | --- |
| Personal use on the user's own Mac or Linux node | No | Values are opened only on the user's devices |
| Connect as byte relay, sync store, and push | No | Connect has only TLS records and ciphertext |
| Cloud agents through Connect while the user's node is online | No | Connect passes TLS through to the node, which does the swap |
| Items with way C | No | Short-lived credentials go direct |
| A team whose members trust the team host | No | The host is the key holder already |
| A team whose members must not trust the host operator with their traffic | Yes, or split TLS (D13) | The host would see the traffic |
| Connect does the swap because no machine of the user is online (hosted way B) | Yes | The only case where an Apassy-run server uses a value. Without a TEE, section 1 forbids it. |

So Connect launches without a TEE. The confidential relay is a later paid add-on for the last row.

Today's relay is already the machine that gets per-run keys from the key holder and does the swap
(SPEC §21). A confidential VM makes that machine unreadable to whoever runs it. For static keys,
Konrad's traffic then does not pass through Rafal's machine, Rafal cannot read it, and Konrad never
gets the value. This removes the cost of way B.

How it works:

1. **Image.** A reproducible VM image: kernel, initrd, and the node in relay-only mode, with measured
   direct boot. Each release publishes the launch measurement. Anyone can rebuild the image and get
   the same measurement.
2. **Attestation.** At boot the VM makes its TLS key in encrypted memory and asks the CPU for an
   attestation report whose `report_data` is the hash of that key. AMD (SEV-SNP) or Intel (TDX) signs
   the report.
3. **Check.** Before a node sends traffic or keys, it checks the vendor's signature chain, the
   measurement against the published release list, that debug is off, a minimum firmware (TCB)
   version, and the key binding. Then it pins that key (D4).
4. **Use.** The key holder releases per-run keys to the VM, as it does to today's relay. The VM checks
   the server policy and the device-signed approvals, swaps, and proxies. It stores no bodies and no
   long-lived keys.
5. **Updates.** A new release changes the measurement. A node accepts only measurements in the
   published release list, an append-only log, and the app shows each change.

Where it runs:

The node checks the attestation, not the place. The same image runs in all three:

- **Your own hardware:** a server with a CPU that has the feature: AMD EPYC 3rd generation (Milan)
  or newer for SEV-SNP, or an Intel Xeon with TDX. The host runs Linux with SEV-SNP host support
  (for example Ubuntu 25.04 or 26.04 LTS with QEMU and OVMF, or Cloud Hypervisor 52). At home, in a
  colocation rack, or a rented dedicated EPYC server whose BIOS allows SEV-SNP (ask the provider).
- **Your cloud account:** Google Cloud N2D or C3D, Azure DCasv5 or DCesv5, AWS M6a, C6a, or R6a with
  SEV-SNP, or any provider with SEV-SNP or TDX. The CPU vendor signs the attestation, so the
  provider does not need trust.
- **Apassy Connect:** a hosted confidential relay (paid, D2). The project runs it, and the
  attestation proves that the project cannot read it.
- **AWS Nitro Enclaves:** an isolated enclave inside an ordinary EC2 instance (most Nitro instance
  types; the enclave takes at least 2 vCPUs, so in practice a parent with 4 or more). The Nitro
  hypervisor signs the attestation (PCR measurements of the enclave image), so the trust is in AWS,
  not in the CPU vendor. It needs its own image format and a vsock transport.

Prices seen on 2026-11-02 (list prices from provider pages and price aggregators, not quotes):

| Option | About | Note |
| --- | --- | --- |
| A SEV-SNP VPS plan (VPSBG, Sofia) | from €9.38 a month (1 vCPU, 1 GB, one-year term, without VAT) | The Cloud VPS page says SEV-SNP is included; per-plan support, attestation, and an own measured image are to be confirmed. A small provider has physical access. |
| Google Cloud N2D (n2d-highcpu-2), Spot | about $25 a month | Can be stopped at any time |
| Google Cloud N2D (n2d-highcpu-2), on demand | about $55 a month | The confidential surcharge is about $4.50 of it |
| AWS c6a.large with SEV-SNP | about $56 a month (us-east) | Few regions; an extra SEV-SNP charge not confirmed |
| Phala Cloud (TDX, 1 vCPU) | about $50 a month | |
| Own EPYC server | one-time hardware and power | Weak against its owner (TEE.fail) |

One VM can serve many teams (one file per team, ADR 0019), so Connect's cost per team is small.

Not on an ordinary VPS. Only the operator of the physical machine can turn on a TEE: a normal KVM
guest cannot turn it on from inside, and the provider's host can read the guest's memory. Some VPS
providers sell SEV-SNP plans; these count as "any provider with SEV-SNP" above.

Encrypted containers do not help either. A container shares the host kernel, so host root reads its
memory. An encrypted image (ocicrypt) or an encrypted volume protects data at rest only: to run, it
is opened with a key that the host holds. Confidential Containers (the CNCF project: Kata Containers
in a SEV-SNP or TDX VM, with Trustee for key release on attestation) are a TEE in another package
and need the same hardware. They are a possible way to package and attest this image.

What an ordinary VPS can still do: keep the master key and item keys in memory only. After each
boot the owner's node sends the keys over the tailnet, so a disk snapshot or a backup of the VPS
holds only ciphertext. Today a snapshot of the relay VPS holds the master key and every team file
(ADR 0019 §2). This does not protect against a live memory dump by the provider.

Not on a Mac or a desktop CPU. Apple silicon, Ryzen, and Core have no confidential VMs, so a VM on
them is readable by its host. This is a limit of the hardware, not of the design.

Limits:

- Trust moves to the CPU vendor and its firmware. This is a strong layer, not a proof.
- **Physical access defeats it.** TEE.fail (October 2025) used a DDR5 memory bus interposer that
  costs less than $1,000 to extract keys from SEV-SNP and TDX, in some cases the attestation keys of
  fully updated machines, which can forge attestation. AMD and Intel treat physical attacks as out
  of scope and do not mitigate them. So a confidential VM on the owner's own hardware fully protects
  against a compromised host system and against software access, but it protects members only weakly
  against the owner of the hardware. When members must not need to trust the team owner, use a
  cloud or Connect host, where the party with physical access is a data center operator.
- A confidential VM costs about €10 to $55 a month (table above). A node on the team's own Linux
  machine costs nothing.
- New code: attestation checks in Rust on every node, the reproducible image build, and the
  measurement log.
- Later, and a separate decision: the VM also holds the item keys, sealed to its measurement, so runs
  work while the key holder is offline. A break of the VM would then expose every item, not only the
  runs of that time. Start without it.

## Who sees what after this

| Party | Sees |
| --- | --- |
| Apassy project | Nothing at run time. Release artifacts, which users can rebuild and compare. |
| Push gateway (if on) | Device tokens, node IP addresses, times |
| Tailscale control server (or Headscale) | Node names, public keys, addresses. Not traffic. |
| DERP relays | WireGuard ciphertext |
| Apple | Push metadata. iCloud ciphertext if folder sync is on. |
| Apassy Connect (if kept and used) | Sealed envelopes and ciphertext, sizes, times |
| Team host node | The values of its team during released runs. It is the key holder already. |

## Stages

The build path needs no TEE. The TEE features are an enterprise track that comes later (D12).
Until then, no Apassy-run server does the way B swap: a cloud agent that goes through Connect needs
a machine of the user that is online. Each stage ships as a normal release of all six components at
one version (AGENTS.md). Sizes are rough: S is days, M is one to two weeks, L is three weeks or
more. Work units, files, and checks: [implementation plan](../design/implementation-plan-0037.md).

### Build path

| Stage | Work | Size | Acceptance |
| --- | --- | --- | --- |
| 0. Prepare | Write the trust model. Scan the relay history for secrets (gitleaks and `/usr/bin/grep -E`, not ugrep). Remove production values (APNs key id and Apple team id in the Worker settings, VPS alias and backup paths, server addresses in the compose file, launchd labels). Turn off shared team vaults and way B on the hosted relay (D8). | S | The scan report is clean or the history plan is chosen. The scrub list is empty. The hosted relay refuses team-vault and proxy requests, and relay sync and questions still work. |
| 1. Open the relay | Move the relay into this workspace (`crates/apassy-relay`, path dependency on the core), Apache-2.0. One rustls pin, one `.cargo/config.toml`. The relay tests and the image build move into this repository's CI. The Worker source moves to `deploy/`. The release check reads the crate here. Archive the old repository. The hosted relay runs unchanged. | S–M | A clean clone builds the relay, `apassy-team`, and the hosted image. The relay tests pass in CI. |
| 2. Node on the Mac | The relay server in the Mac backend on loopback, behind a TLS front on the tailnet addresses. A pinned trust mode in the relay client (Mac and iPhone). The iPhone pairs with the Mac node. Questions, feed, and access requests over the tailnet. Push gateway with per-device push handles. Settings → Devices. Security review of the listener before release. | L | An iPhone on cellular with Tailscale approves a run on the Mac, and a packet log shows no request to `apassy-relay.wyderka.cc`. Revoke works at the next request. A vault lock stops the listener. |
| 3. Linux node | `apassy serve`, `up`, `pair`, `status`, `doctor`. systemd user service. `.tar.gz` and `.deb` with checksums. It replaces `apassy-team`. | M–L | A fresh Debian or Ubuntu machine on the tailnet pairs with the Mac and the iPhone. |
| 4. Sync and teams on nodes | Node-to-node sync with a sync home. A team host on a node, shared to members across tailnets (section 9), with the embedded tailnet node (D9, starts with a spike). The way A switch (D10). Migration of hosted teams and relay-sync vaults. | L | Two Macs and a Linux sync home converge after one Mac is offline for a day. Konrad's agent, in another tailnet, runs way B on Rafal's team host. |
| 5. Linked environments | `apassy environment link`, the SSH route, remote MCP. The Funnel route, off by default, for cloud sessions. | M | An agent on `devbox-arm` uses a credential through the Mac node and holds only placeholders. |
| 6. Private sharing | Way C for AWS STS, GitHub Apps, Google Cloud, and OAuth refresh tokens. Remote signing for SigV4. Keys per member where a provider has a key-management API (section 10). | M–L | A member's agent uses AWS with STS credentials that expire within 15 minutes. |
| 7. Apassy Connect, and hosted secrets retired | The hosted relay becomes Connect (D2): a byte relay with TLS through to the user's node and a blind sync store, with accounts, Stripe, and the plans of [plans](../product/plans.md) (D3). Push stays the free gateway of D7. Remove way B, team vaults, and the master key from the hosted service. | M–L | The hosted service has no master key, no team file, and no proxy route. A Mac without Tailscale reaches its iPhone and a cloud agent through Connect. |
| 8. Later | Embedded tailnet on the iPhone, so it needs no Tailscale app. Linux isolation. Linux window. | — | Separate ADRs |

### Enterprise track (later, TEE)

| Stage | Work | Needs |
| --- | --- | --- |
| E1. Confidential relay | The reproducible VM image, relay-only mode, attestation checks on every node, and the measurement log (section 11). Self-hosted and Connect-hosted from one image. Also the team host for members who must not trust the owner. | Stage 4 |
| E2. Hosted way B | Connect does the swap for static keys when no machine of the user is online. | E1, stage 7 |
| E3. Split TLS | The prototype and a cryptography review (section 10, step 5; D13). | Stage 4 |
| E4. Item keys in the VM | Always-on key custody, sealed to the measurement. | E1, its own ADR |

## Migration

- **Connect users (approvals only):** the Mac offers "Move approvals to this Mac". The iPhone pairs
  with the Mac node through a new link. The hosted membership is then deleted.
- **Relay sync users:** choose a sync home. The Mac pushes its vault there. Then "Delete the copy on
  the relay" (ADR 0022 §5, exists).
- **Hosted teams (D8, now):** shared team vaults and way B on the hosted relay stop in stage 0.
  The team files stay encrypted on the relay. In stage 4 the key-holder device requests a signed
  export of its team file (new endpoint), sealed to that device key, and the team host node imports
  it. Members join again through a link with the new origin.
- **Free Connect users (D14):** the free questions-only path stays until stage 7. Two releases
  before it ends, the apps say so and offer Tailscale (free) or paid Connect.
- The hosted relay keeps relay sync, questions, feed, and push until stage 7 turns it into Connect.

## Process changes

- Stage 1: AGENTS.md and `scripts/check-release-versions.py` read the relay crate in this
  repository instead of `--relay-checkout`. The relay repository is archived. The six components
  stay; `relay` is the hosted service (later Connect and the push gateway), and `linux-cli` is
  `apassy-team` until stage 3 makes it the Linux node.
- Stage 7: `docs/operations/relay.md` and the relay deployment notes describe Connect.

## Risks

| Risk | Mitigation |
| --- | --- |
| iOS runs one VPN at a time. A user with a work VPN cannot use the tailnet route. | Connect (D2), or an embedded tailnet (stage 8) |
| Onboarding needs a Tailscale account and the app on every device. | `apassy up` and the Mac setup check `tailscale status` and explain each step |
| Availability moves to the user. A team needs an always-on host. | Recommend a Linux node for teams. A power assertion while a linked environment waits. |
| A listener on user machines is new attack surface (ADR 0028 counted it as a cost). | Loopback bind behind the route, tailnet only, request limits, fuzzing of the HTTP parser, a security review before stage 2 |
| Tailscale Serve HTTPS puts machine names in public Certificate Transparency logs. | Pinned certificate as the default (D4) |
| Paid plans today sell relay sync and shared vaults. Self-hosting gives both away. | D3 |
| User-run servers fail in more ways, so support costs more. | `apassy doctor`, clear route status in the app |

## Open decisions

| # | Decision | Recommendation |
| --- | --- | --- |
| D1 | License and history of the relay | **Accepted 2026-11-02.** Apache-2.0. Publish the full history if the secret scan is clean; otherwise publish a new history from one commit. |
| D2 | A hosted Apassy Connect | **Accepted 2026-11-02.** Apassy Connect is paid, optional, and blind, like T3 Connect: a byte relay with end-to-end TLS, a sync store, and push. Never way B or team keys. All of its functions can also be self-hosted, for cost and for security. |
| D3 | Plans | **Accepted 2026-11-02.** Everything is free when self-hosted. Paid: hosted Connect (reachability without Tailscale, an always-on sync home) and support. Stripe stays only for that. |
| D4 | TLS on the tailnet | **Accepted 2026-11-02.** A pinned self-signed certificate on the tailnet address, reusing the companion TLS code. Tailscale Serve as an option. |
| D5 | Sync home | **Accepted 2026-11-02.** The user can change the sync home. Default: the first always-on Linux node, else the first Mac. iCloud folder sync stays. |
| D6 | Wi-Fi companion | **Accepted 2026-11-02.** Remove companion-v1 (ADR 0028). The node's LAN route uses the same relay API as the tailnet route: one protocol and one pairing. Removal follows the two-release notice of ADR 0028 stage 3, after stage 2 ships the node. |
| D7 | Push gateway operator | **Accepted 2026-11-02.** The Apassy project runs the push gateway from the published source, free for everyone, self-hosters included. It sees only push handles, node addresses, and times. |
| D8 | End date for hosted teams and way B | **Accepted 2026-11-02: now.** Turn off shared team vaults and way B on the hosted relay before stage 4 (stage 0, unit 0E). Keep the team identity that relay sync and questions use. Teams wait for their own nodes (stage 4). Deleting team files is a separate step that needs the owner's confirmation. |
| D9 | How the team host joins the tailnet | **Accepted 2026-11-02.** An embedded Tailscale node (tsnet) in the desktop and Linux node for team hosting: its own machine name (for example `apassy-team-acme`) that listens only on the Apassy port, so a share exposes nothing else, and it can join a team tailnet while the Mac stays on its own. This puts the desktop and Linux part of the embedded tailnet into stage 4; the iPhone part stays in stage 8. Until then: a dedicated Linux host and a grant limited to the Apassy port. |
| D10 | Way A or way B for a shared collection | **Accepted 2026-11-02, with the owner's change.** Way B trusts the host with the members' traffic. Way A trusts the member with the value: it reaches the member's broker, sealed to the device key, for one run, and the member's traffic goes direct. Because the app is open source, a member can build a client that keeps the value, so way A means "shared with this member", and removing the member needs a rotation. Way B is the default. Way A is a collection switch that the owner can turn on for any collection, production included. Clear information replaces a hard rule (section 10, "The way A switch"). |
| D11 | Short-lived credentials (way C) | **Accepted 2026-11-02.** Way C applies automatically to every item whose provider supports it, in both modes. Ways A and B then apply only to static keys. |
| D12 | Confidential team host | **Accepted 2026-11-02: an enterprise feature, added later** (enterprise track E1 and E2). One image for both: self-hosted and hosted by Apassy Connect. Proxy only at first (per-run keys from the key holder). |
| D13 | When to prototype split TLS | Follows D12: on the enterprise track (E3), not on the build path. |
| D14 | Free approvals for users without Tailscale | **Accepted 2026-11-02: all of Connect is paid.** Users without Tailscale get remote iPhone approvals only through paid Connect. The free questions-only path of ADR 0032 stays until stage 7, with a notice in the apps two releases before it ends. |
