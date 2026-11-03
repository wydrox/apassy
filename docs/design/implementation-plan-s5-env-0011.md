# Implementation plan — linked environments (ADR 0037 stage 5) and the run proxy stages 2 to 7 (ADR 0011)

Date: 2026-11-03. Status: PLAN under the owner's decision of 2026-11-03: build everything in the ADRs except
the TEE track, as fast as possible, with many parallel agents, and with no owner approval of intermediate
steps. Where an ADR leaves a choice open, this plan takes the recommended option and marks it
**(chosen by this plan; the owner can change it)**.
Decisions: [ADR 0037](../adr/0037-own-relay-open-source.md) §3, §5, §6, stage 5, stage 8 ("Linux
isolation"); [ADR 0011](../adr/0011-run-proxy-placeholders.md) "Next stages" 2 to 7. Related: ADR 0006,
0024, 0031, 0036.
Related plans: [implementation-plan-0037.md](implementation-plan-0037.md) (units 2B, 2C, 3A, 3F),
[implementation-plan-0037-cloud-agents.md](implementation-plan-0037-cloud-agents.md) (the cloud slice),
[implementation-plan-bouncer-section.md](implementation-plan-bouncer-section.md) (U1b OAuth connect, U2b),
[implementation-plan-s2-s3.md](implementation-plan-s2-s3.md) (N0 to N8, its L1 to L4: the node on the tailnet
and the Linux node), [implementation-plan-s4-teams.md](implementation-plan-s4-teams.md) (SH-*, TH-*, SE).
Unit ids of this plan: V, P, X, LE (linked environments), NA (named actions). Releases: S5-R1 to S5-R3.
Format: [implementation-plan-0035.md](implementation-plan-0035.md), [implementation-plan-0037.md](implementation-plan-0037.md).
Base inspected: `origin/release/0.5.16` at `dd71868c`, rebased on `af5d317d`, which adds the S2/S3 and S4
plans; the numbers below are checked against them. Vault schema 26, relay team schema 7, relay directory
1003. The OAuth connect (U1b) is not in this base.

## Outcome and constraints

1. **Linked environments (ADR 0037 stage 5).** `apassy environment link ssh://dev@devbox-arm` links a Linux
   machine to the node of this Mac. An agent on that machine (Claude Code, Codex) uses `apassy-team run` or
   the stdio MCP server `apassy-team mcp`. The Mac decides each run (bouncer, or the owner on the Mac or the
   iPhone) and the Mac is the proxy. The Linux machine holds only placeholders, base URLs, a session key, a
   proxy password, and the certificate of the run. It never holds a value.
2. **ADR 0011 stage 2 and ADR 0037 stage 8.** On Linux a proxied run has no route except the proxy
   (network namespace), and a Linux agent host can run in a profile that is the equivalent of
   `sandbox/apassy-agent-host.sb`.
3. **ADR 0011 stage 3.** Named actions copy a credential to another service ("STRIPE_SECRET_KEY to
   api.vercel.com") after the owner approves that exact copy.
4. **ADR 0011 stage 4 (macOS part).** A loopback base URL for tools that have one (`OPENAI_BASE_URL`,
   `ANTHROPIC_BASE_URL`, and the others of the relay table), and an optional name-constrained Apassy
   authority in the user trust store for Go programs.
5. **ADR 0011 stage 5.** WebSocket and HTTP/2 in the run proxy.
6. **ADR 0011 stage 6.** Process hardening: the macOS hardened runtime (already on, see the facts) and
   `PR_SET_DUMPABLE=0` on Linux.
7. **ADR 0011 stage 7.** The proxy on another computer: the cloud slice covers base URLs; this plan adds the
   forward proxy (`HTTPS_PROXY`) for linked environments.

Constraints:

- **No TEE.** The enterprise track (ADR 0037 E1 to E4) is out.
- **No Windows.** There is no Windows app and no Windows build. The Windows parts of ADR 0011 (stage 4,
  "Go on Windows"; stage 6, "a service account on Windows") are out of this plan.
- **No value on a linked machine.** An item in real-value mode (ADR 0006) cannot be used from a linked
  environment. Only items in placeholder mode are offered there.
- **Contracts.** The cloud slice contracts stay. Changes are additive, or they are new named contracts
  (decision D14).
- **Releases.** Each release bumps all six components to one version (AGENTS.md).
- **Mac resources (copy into every task).** At most three implementation or validation workers run on this
  Mac across all sessions and threads. Workers do not run lint, typechecks, builds, `cargo test`,
  `cargo nextest`, or full suites, also not through `heavy-check`; they return the exact commands. The
  top-level agent runs one validation pass for each revision, through CI after an authorized push, or
  locally only through `~/.local/bin/heavy-check`. Docker runs only on `devbox-arm` or `devbox-x86` (with the
  architecture named) or on GitHub runners in CI; never Colima, never the VPS `ottervibe`.

## What each ADR item becomes

| ADR item | Units | Release |
| --- | --- | --- |
| 0037 stage 5: `apassy environment link`, SSH route | V1, LE1, LE2, LE3, LE4, LE6, LE7 | S5-R1 |
| 0037 stage 5: remote MCP | LE3 (`apassy-team mcp` with a local run tool), LE1 (linked scope of `/mcp`) | S5-R1 |
| 0037 stage 5: Funnel route for cloud sessions | Done by the cloud slice (`src/node/funnel.rs`). OAuth connect is U1b of the bouncer-section plan. No unit here. | — |
| 0037 stage 5: tailnet route | LE8, after N1, N2, N3 of the S2/S3 plan (2B and 2C of plan 0037) | S5-R3 |
| 0037 stage 8: Linux isolation | X1, X2, X3 | S5-R1, S5-R2 |
| 0011 stage 2: Linux network namespace | X1, X2 (local runs), LE3 (linked runs) | S5-R1 |
| 0011 stage 3: named actions | NA1, NA2, NA3, NA4 | S5-R2 |
| 0011 stage 4: loopback base URL | P2 | S5-R2 |
| 0011 stage 4: name-constrained authority (macOS) | P5 | S5-R3 |
| 0011 stage 5: WebSocket | P3 | S5-R2 |
| 0011 stage 5: HTTP/2 | P4 | S5-R3 |
| 0011 stage 6: hardening | P6 | S5-R1 |
| 0011 stage 7: proxy on another computer | Base URLs: done (cloud slice `/p/`). Forward proxy: LE1 + LE3. No route around it on the remote: X1 in LE3. | S5-R1 |
| Shared engine for all of the above | P1 | S5-R1 |

## Facts from the code (base `dd71868c`)

| Area | Fact | Where |
| --- | --- | --- |
| Run proxy listener | `RunProxy::start` binds `127.0.0.1:0`, makes a run authority and a password, and starts one accept thread. Engine and listener are one 1,228-line file. | `src/broker/proxy/mod.rs:388-474` |
| Run proxy network | `network_for` writes the authority and the bundle into a 0700 temp folder and sets the proxy and trust variables. The network rule is a Seatbelt profile on macOS only; on other systems `sandbox_profile` is `None`. | `src/broker/proxy/mod.rs:482-533` |
| Upgrades | A request with `Upgrade` is refused with 501 ("does not support a protocol upgrade (WebSocket) yet"). | `src/broker/proxy/mod.rs:940-947` |
| ALPN | The run authority's server config offers `http/1.1` only. A client that offers only `h2` fails the handshake. | `src/broker/proxy/ca.rs:105-106` |
| Run authority | A new self-signed ECDSA authority for each run, valid one day, name-constrained to the hosts of the run. | `src/broker/proxy/ca.rs:38-68` |
| Other hosts | Local runs use `OtherHosts::Tunnel` and `enforce: true`. A tunnel goes to any address, also on the LAN and the loopback. | `src/broker/run.rs:2014-2018`, `src/broker/proxy/mod.rs:621-633` |
| Run report | `enforced` is "a sandbox profile exists", so `network.only_proxy` is false on Linux. | `src/broker/run.rs:2071`, `:2803-2817` |
| Spawn | `spawn_collect` wraps the program in `/usr/bin/sandbox-exec -p <profile>` when a profile exists; `env_clear`, `process_group(0)`. | `src/broker/exec.rs:36`, `:290-316` |
| Secrets of a run | `read_secrets` mints one placeholder for each item in placeholder mode and keeps the value only in `ProxySecret`. | `src/broker/run.rs:2731-2795` |
| Routes | `hard_rules` → readiness → project → declarations → answers → hosts → foreign project → pattern → model. Cloud runs use `cloud_route`: always the owner. | `src/broker/run.rs:572`, `:697-807`, `:809-817` |
| Hook prompts | A hook prompt counts only after a check against the host transcript; a failed check is the flag `hook_unverified`, which asks the owner. | `src/broker/prompts.rs:1-26`, `:67` |
| Node start | `Node::start_inner` refuses to start without a connected Tailscale and always enables Funnel. There is no other route. | `src/node/mod.rs:348-470` |
| Node config | `NodeConfig { data_dir, master_key, public_url, public_listen }`. | `src/node/backend.rs:92-105` |
| Relay scopes | `Scope::{Node, Public}`; `Public` serves `POST /mcp` and `/p/` only. Agent paths are `/p/`, `/mcp`, `/v1/access`, `/v1/runs`, `/v1/runs/*`. | `crates/apassy-relay/src/server/http.rs:65-82`, `:464-471` |
| Relay listeners | `Relay::start` binds the node listener and the optional public listener (`tiny_http`), each with its own limits. | `crates/apassy-relay/src/server/mod.rs:603-692` |
| Session origin | A release builds the session environment with `core.config.public_url`: one origin for every session of the node. | `crates/apassy-relay/src/server/host.rs:279-286` |
| Base variables | `RESERVED_NAMES` and `provider_vars` (Stripe, OpenAI, Anthropic, GitHub) live in the relay only. | `crates/apassy-relay/src/server/env.rs:16-55` |
| Relay proxy | `/p/<session key>/<host>/…` is a reverse proxy, HTTP/1.1, 8 MiB body cap. CONNECT and upgrades are refused (501) on the public listener. | `crates/apassy-relay/src/proxy/mod.rs:1-34`; `docs/contracts/cloud-agents-v1.md` §3, §9 |
| Public addresses | `is_public_ip` (loopback, private, CGNAT, link-local, unique-local refused) is in the relay crate only. | `crates/apassy-relay/src/proxy/upstream.rs:304` |
| Remote executor today | `apassy-team run -- <cmd>` requests a session, waits, and runs the command with the session environment; `apassy-team mcp` forwards stdio JSON-RPC to `POST /mcp`. The client is `ureq`. | `crates/apassy-relay/src/cli/exec.rs:1-5`, `cli/mcp_stdio.rs:1-5`, `cli/client.rs:1` |
| Vault | Schema 26. `agent.kind` has `CHECK (kind IN ('local', 'cloud'))`. Node tables are local (`LOCAL_TABLES`). | `src/vault/types.rs:22`, `src/vault/schema26.rs:37`, `src/vault/merge.rs:82` |
| Relay team schema | 7 (`agent.items`). | `crates/apassy-relay/src/server/store.rs:31` |
| Owner commands | The owner CLI sends `Command` values over the owner socket; the app handles them. | `src/owner/wire.rs:195`, `src/desktop/owner_cli.rs` |
| Hardened runtime | Every Mac binary is signed with `--options runtime`; the build fails when a binary lacks the runtime flag. The entitlements are an empty dict: no `get-task-allow`, no runtime exceptions. Notarization needs the hardened runtime, and the app already has it. | `scripts/build-app.sh:609-641`, `packaging/Apassy.entitlements` |
| Unsafe | `unsafe_code = "forbid"` in the core and the relay. `rustix` (features `std`, `process`, `termios`, `time`) is a direct dependency. | `Cargo.toml:70`, `:147`; `crates/apassy-relay/src/lib.rs:15` |
| Crates | `Cargo.lock` has no `tokio`, `h2`, `hyper`, `crypto_box`, `xsalsa20poly1305`, `landlock`, or `seccompiler`. | `Cargo.lock` |
| Question cards | One card kind, `v = 1`; a new card field is a new `v`. | `src/questions/envelope.rs:31`; `docs/contracts/relay-questions-v1.md` §7.1, §17 |
| Parallel plans | Vault: 27 bouncer section, 28 S2/S3 (N3), 29 plan 0035 (C2), 30 and 33 S4; 31 to 32 free ("reserved" in S4). Relay team: 8 S2/S3 (N1), 9 S4 (SH-R). Directory: 1004 U1b, 1005 S2/S3, 1006 S4. S2/S3 adds `Scope::Tailnet { agents }`, the TLS front (N2), pinned trust (N3), and the Linux `apassy` binary that keeps `apassy-team` as an alias (its L1). S4 adds Secure Enclave helper commands `se_key_create`, `se_key_sign`, `se_key_delete` (SE). S6 takes vault 32 and the next free relay team schema at merge time, and edits the run proxy (E1 SigV4), the relay proxy and `server/env.rs` (E2), node release and sessions (G), and adds `PUT` to the HTTP client (B). S7 takes vault 34 and directory 1007. S8 points to this plan for Linux isolation. | `docs/design/implementation-plan-s2-s3.md:17`, `:70`, `:131-160`, `:192`; `docs/design/implementation-plan-s4-teams.md:107-108`, `:220`; `docs/design/implementation-plan-s6-sharing.md:107`, `:290-400`; `docs/design/implementation-plan-s7-connect.md:60`, `:240`; `docs/design/implementation-plan-s8.md:15` |
| F11 | macOS: a same-user process can read the environment of a third-party process; no Seatbelt rule closes it. | `docs/operations/isolation.md` §5 "Process information (F11)" |

## Decisions

**D1 Routes for linked environments.** The SSH route ships first, because it meets the stage 5 acceptance
without the TLS front (plan 0037 unit 2B, S2/S3 unit N2), which does not exist yet (`src/net/` is absent).
The tailnet route (LE8) follows N1, N2, and N3 of the S2/S3 plan. Funnel stays the route of cloud
sessions only; Funnel carries no CONNECT. A CI runner or another machine that the Mac cannot reach by SSH is out of stage 5. **(chosen by
this plan; the owner can change it)**

**D2 One transport shape.** The remote machine sees two loopback ports, fixed when the link is made (from
49152 to 65535): `R` for the node API and `/p/`, and `R+1` for the forward proxy. On the SSH route, the Mac
runs `ssh -N -R 127.0.0.1:R:127.0.0.1:<linked> -R 127.0.0.1:R+1:127.0.0.1:<forward> <destination>`. On the
tailnet route (LE8), a small `apassy-team link forward` user service holds the same two ports and forwards
them with pinned TLS. The executor does not know which route carries its ports. Rejected: Unix sockets on
the remote (HTTPS_PROXY clients and the `ureq` client need TCP, and the namespace bridge needs TCP in the
sandbox anyway); one multiplexed port (tiny_http cannot hand a CONNECT stream to another server).

**D3 Where the swap happens.** On the Mac, inside the relay session, with the run proxy engine of the core
(`ProxyCore`, unit P1). The relay crate depends on the core, so it can use the engine. When a session ends
(expiry, revoke, lock, quit), its engine ends with it: one lifecycle. The remote runs a **router** without
TLS interception: CONNECT to a host of the session goes to the Mac (`R+1`); CONNECT to another host goes
direct from the remote (the default) or is refused (a run option); `/p/…` goes to `R`; plain `http://` to a
host of the session is refused. So the other traffic of the agent does not pass through the owner's Mac or
its home connection. On the Mac, the forward front refuses every host that is not a host of the session
(`OtherHosts::Refuse`) and every non-public upstream address. A linked environment cannot reach the Mac's
LAN or loopback through the proxy. **(chosen by this plan; the owner can change it)**

**D4 Identity and lanes.** A linked environment is a node agent: vault `agent.kind = 'cloud'` (the kind
means "reaches this Mac through its node"; this avoids a rebuild of the `agent` table for its CHECK) plus a
row in the new local table `linked_environment`. In the relay, the agent has `lane = 'linked'` (team schema
10). A linked token works only on the linked listener, and a cloud token only on the public listener, so a
linked token that leaks cannot be used from the internet through Funnel. The Mac writes the token to
`~/.config/apassy/link.json` (mode 0600) on the remote through the standard input of `ssh`, never in an
argument list. Revoke = unlink: the relay agent is revoked (sessions end at the next request), the tunnel
stops, and the remote file is removed when the remote is reachable.

**D5 The executor is the Linux CLI.** `apassy-team` (the `linux-cli` component; unit L1 of the S2/S3 plan makes the
Linux binary `apassy` and keeps `apassy-team` as an alias, so both names work) gets `run` and `mcp` in link mode, `hook`, `link check`, and the hidden
`__netns-bridge`. `apassy environment link` installs it at `~/.local/share/apassy/bin/` from the published
Linux download of the same release, after it compares the SHA-256 with the `SHA256SUMS` file that the Mac
downloads itself, or uploads a local build with `--binary PATH` (development and CI). The executor and the
Mac must have the same `linked-environment-v1` contract version; `link check` reports a mismatch with the
fix (`apassy environment link --update <name>`).

**D6 How the Mac decides a linked run.** The full ADR 0031 route, not the always-ask cloud route, as ADR
0037 §6 says ("the home node decides (local bouncer, owner approval on the iPhone)"):

- The executor's `apassy-team hook` is the remote end of `apassy-hook`. It keeps the newest prompt for each
  host session in a 0600 file for one hour. At a run, the executor checks the prompt against the host
  transcript on the remote with the same code as the Mac (`src/broker/prompts.rs`), and sends
  `user_request_source` = `linked_hook` (checked) or `linked_hook_unchecked`, plus `host_session` and
  `project_root` (the git top level of the remote folder). An unchecked prompt or no prompt gives the
  existing flags and reasons (`hook_unverified`, `MissingTask`): the owner decides.
- The project of a linked run is `linked:<environment id>:<remote root>`. Owner answers there never cover
  a project on the Mac, and the other way round.
- Production, Always ask, one-time codes, and foreign database hosts ask as on the Mac. The card says
  "on devbox-arm (linked)" and names the source of the user request.
- A new linked environment sees what a new local agent of the vault sees (the default of
  `Vault::add_agent`, ADR 0012); the owner narrows it in Agents like any agent. Only items in placeholder
  mode are in its catalog.
**(chosen by this plan; the owner can change it to "every linked run asks", which is the cloud route)**

**D7 Linux isolation: bubblewrap.** `bwrap` 0.8 or later, unprivileged, with new user, network, PID, IPC,
UTS, and cgroup namespaces, `--disable-userns`, `--die-with-parent`, `--new-session`, a fresh `/proc`, and a
mount plan (deny list below). In a new network namespace the process has only `lo`. A bridge in the
namespace (`__netns-bridge`: listens on `127.0.0.1:<port>` inside, forwards to a Unix socket that is
bind-mounted from outside) is the only way out, and it leads to the proxy or the router. Abstract Unix
sockets belong to the network namespace, so they do not reach outside. The PID namespace hides the other
processes of the user, so the F11 read of another process's environment does not work in the sandbox, and
when the run ends its namespace ends with every descendant. Why not the others:

- **Landlock** controls files and, from ABI 4 (Linux 6.7), TCP bind and connect by port only. It has no
  rule for UDP, for an address, or for a namespace, so it cannot give "no route except the proxy". Not used.
- **seccomp** cannot read the address of a `connect` (a pointer), and it needs a BPF compiler crate. The
  properties above come from the namespaces, `--disable-userns`, and `--new-session` (TIOCSTI). Not used;
  reconsider only when a measured escape needs it.
- **`unshare` alone** gives the namespaces but not the mount plan and the bridge setup; bubblewrap does
  both in one tested program.

When bubblewrap is missing or user namespaces are blocked (Ubuntu's
`kernel.apparmor_restrict_unprivileged_userns`, or a container): a linked run and a local Linux proxied run
start without the rule and report `network.rule = "none"` (they still hold only placeholders); the Linux
agent-host launcher (X3) refuses to start, as `apassy-sandbox` fails closed on macOS. `apassy doctor` and
`link check` name the fix. **(chosen by this plan; the owner can change it)**

**D8 Named actions.** Apassy calls the destination API itself. The proxy never puts a value into a body.
Reasons: the body of `vercel env add` is not seen by the proxy anyway (ADR 0011 measured that the Vercel
CLI sends only its telemetry through the proxy); `gh secret set` seals the value before it sends it; and a
body matcher would be new parsing of agent-built data on the swap path. The first catalog:
`vercel.env` (project environment variable, type `sensitive` by default), `github.actions_secret`
(repository), `github.environment_secret`. Each transfer asks the owner with an owner check (Touch ID),
is never remembered and never decided by the bouncer, and writes an `item_copy` row (vault schema 31), so
the credential page lists its copies and offers "Update copies" after a rotation. The question uses the v1
run card with a fixed argument list (`["apassy", "transfer", "<action>", …]`) and a risk text, so the
iPhone answers it with no app change. The broker refusal of a placeholder in a body names the transfer
tool. **(chosen by this plan; the owner can change it)**

**D9 Loopback base URLs (all systems).** The run proxy port also serves origin-form requests
`/b/<base token>/<host>[/<path>]` over plain HTTP: the same swap rules, then HTTPS to the host. A run with an
item for that host gets `APASSY_BASE_<ENV_NAME>` and the provider variables of the relay table
(`OPENAI_BASE_URL` with `/v1`, `ANTHROPIC_BASE_URL`, `STRIPE_API_BASE`, `GITHUB_API_URL`). One table for
local, linked, and cloud runs: P1 moves it into the core. Go does not use a proxy for `localhost`, so a Go
program connects straight to the proxy port, which the Seatbelt rule allows.

**D10 Local authority for Go on macOS (optional, off by default).** One long-lived root, ECDSA P-256, whose
key is in the Secure Enclave (in the Keychain when the Mac has no Secure Enclave) and usable only by the
signed Apassy helper, through the `se_key_create` and `se_key_sign` commands that unit SE of the S4 plan adds. Its name constraints are the placeholder hosts of every vault on this Mac. It is
trusted in the user domain after the macOS trust prompt. Each run gets an intermediate under the root,
constrained to the hosts of the run, with its key in broker memory; the leaves are made as today. A new
placeholder host makes a new root (one more prompt). Off removes the trust setting and the key. Rejected:
an unconstrained root (a broken app could then intercept every site of the user in Safari). A CI measurement
(P5) records whether macOS enforces the name constraints of a root; the intermediate constraint holds in
every verifier. **(chosen by this plan; the owner can change it)**

**D11 WebSocket.** Allowed only to a host of the run, on GET with `Upgrade: websocket`. The handshake goes
through the swap rules (auth header or key query parameter). `Sec-WebSocket-Extensions` is removed, so no
compression is negotiated. After `101`, the proxy reads frames: a placeholder in a client frame closes the
connection with 1008 and a refusal event; a real value in a server frame becomes its placeholder (same
length, also across frames). The relay `/p/` stays without upgrades.

**D12 HTTP/2.** Only for a client whose ALPN list has `h2` and not `http/1.1` (gRPC and other h2-only
clients). Clients that offer both stay on the HTTP/1.1 path, so curl, Go, Node, and Python do not change.
The proxy reads the ClientHello (rustls `Acceptor`), opens the upstream connection with `h2`, and serves the
client with the same protocol. The implementation uses the `h2` crate on a current-thread `tokio` runtime,
only in `src/broker/proxy/h2.rs`, behind the cargo feature `proxy-h2`. HEADERS map to the existing request
head, so `swap_request` applies unchanged; DATA frames use the existing scanner and replacer; trailers are
replaced too; the crate's limits for reset streams, header list size, and concurrent streams are set. The
relay `/p/` stays HTTP/1.1. Rejected: an own HTTP/2 implementation (HPACK, flow control, and the 2023 and
2024 rapid-reset and CONTINUATION attacks). **(chosen by this plan; the owner can change it)**

**D13 Hardening.** macOS: the hardened runtime is already on with no exceptions (facts), so no signing
change; add `RLIMIT_CORE = 0` in the app and a build check that no binary has `get-task-allow`. Linux:
`PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0` (through `rustix`, no `unsafe`) at the start of every Apassy
process that holds a value or a token: the node and broker, `apassy-team`, and `apassy-relay`. A process
that is not dumpable has its `/proc/<pid>/environ`, `mem`, and `ptrace` closed to the same user.

**D14 Numbers and contracts.**

| Thing | Value |
| --- | --- |
| Vault schema | **31**: tables `linked_environment` and `item_copy`, both local (`LOCAL_TABLES`). Down-migration as for 26. |
| Relay team schema | **10** (8 is the S2/S3 plan's push handles, 9 is the S4 plan's delivery keys; S6 takes the next free number when it merges, so the second of LE1 and S6 to merge takes 11; migrations merge in number order): `agent.lane TEXT NOT NULL DEFAULT 'public' CHECK (lane IN ('public','linked'))`, `run.user_request_source TEXT NULL`, `run.host_session TEXT NULL`, `run.project_root TEXT NULL`. |
| New contract | `docs/contracts/linked-environment-v1.md`: link file, linked scope, forward front, session `forward` view, router rules, executor run, routes, codes, limits. |
| New contract | `docs/contracts/transfer-actions-v1.md`: catalog, broker action `transfer`, MCP tools, card, audit, copies. |
| Additive | `broker-v0` (run answer: `network.rule` = `seatbelt`, `netns`, or `none`; `network.base_urls`; `requests[].protocol` = `http/1.1`, `h2`, or `websocket`; §4d `transfer`). `cloud-agents-v1` §6 (`apassy_transfer_secret`, `apassy_transfer_status`). `owner-cli-v1` (`environment`). Relay `docs/SPEC.md` (linked scope, forward front, team schema 10). |
| iPhone | No change: linked runs and transfers use v1 run cards. |

## Work units

Sizes: S is days, M is one to two weeks, L is three weeks or more. Each unit is a draft PR from its own
worktree off `main`; it is marked ready when complete and merged after the ready run is green (macOS groups
included). Each worker returns: unit, base revision, files changed, interface, tests added ("not run"),
the validation commands for the top-level agent, deviations, open questions, risks. A unit marked
**panel** gets a read-only judge panel (2× opus + 1× fable, xhigh) before it is marked ready.

| Id | Unit | Size | Depends on | Owned files (short) | Release |
| --- | --- | --- | --- | --- | --- |
| V1 | Vault schema 31 | S | — (merges after schema 30 of S4) | `src/vault/{schema31,linked,copies}.rs` (new), `types.rs`, `mod.rs`, `merge.rs` | S5-R1 |
| P1 | Proxy engine split | M | — (before S6 E1, which then edits the split files) | `src/broker/proxy/{mod,engine,listener,network,public_addr,base_env}.rs`, `ca.rs` (ALPN parameter); relay `proxy/upstream.rs`, `server/env.rs`; `run.rs` (2 lines) | S5-R1 |
| X1 | Linux sandbox module (**panel**) | M–L | — | `src/isolation/**` (new), `docs/operations/isolation-linux.md` (new), `ci.yml` (bwrap steps) | S5-R1 |
| X2 | Linux rule for local proxied runs | S | P1, X1 | `src/broker/exec.rs`, `proxy/network.rs`; Linux cases in `tests/run_proxy.rs` | S5-R1 |
| LE1 | Relay: linked scope, forward front, team schema 10 (**panel**) | L | P1; U1b, N1 (S2/S3), SH-R and TH-R (S4) merged | relay `config.rs`, `api.rs`, `session.rs`, `embedded.rs`, `server/{mod,http,host,sessions,store,forward}.rs`; `src/node/backend.rs`; relay `SPEC.md`; `linked-environment-v1.md` | S5-R1 |
| LE2 | Node routes and the SSH tunnel | M | V1, LE1; N4 (S2/S3) and TH-N (S4) merged | `src/node/{mod,ssh,linked}.rs`, `src/desktop/node.rs` | S5-R1 |
| LE3 | Executor on Linux (**panel** with LE1) | L | LE1 (contract), X1; L1 of S2/S3 merged | relay `cli/{link,router,hook,exec,mcp_stdio,args,settings,mod}.rs` | S5-R1 |
| LE4 | Owner commands and the install | M | LE2, LE3 | `src/cli/{mod,commands,help}.rs`, `src/owner/wire.rs`, `src/desktop/owner_cli.rs`, `src/node/install.rs` (new), `owner-cli-v1.md` | S5-R1 |
| LE5 | Decision route of linked runs (**panel**) | M | LE1, V1; U2b and TH-N (S4) merged | `src/broker/{run,decide}.rs`, `src/node/host.rs` | S5-R1 |
| LE6 | Linked end-to-end tests in CI | M | LE2 to LE5, X1 | relay `tests/linked_e2e.rs` (new), `tests/fixtures/linked-remote/**` (new), `ci.yml` | S5-R1 |
| LE7 | UI: linked environments | M | LE2, LE4 | `src/desktop/ui/linked.rs` (new), `ui/agents.rs`, mockup frames in `docs/design/cloud-agents-mockup.html` | S5-R1 |
| P6 | Process hardening | S | — | `src/harden.rs` (new), the `main` of each bin, `scripts/build-app.sh` (check), `isolation.md` (hardening section) | S5-R1 |
| NA1 | Transfer engine (**panel**) | M | S6 B (`PUT` in `src/broker/http.rs`; NA1 does not edit that file) | `src/broker/transfer/**` (new), `Cargo.toml`, `Cargo.lock`, `docs/reviews/transfer-dependencies.md` (new), `transfer-actions-v1.md` | S5-R2 |
| NA2 | Transfers in the broker (**panel** with NA1) | M | NA1, V1, LE5 | `src/broker/{transfer_run.rs (new), decide.rs}`, `src/agent/mcp.rs`, `proxy/engine.rs` (refusal text), `broker-v0.md` §4d | S5-R2 |
| NA3 | Transfers over the node | S–M | NA2, LE1 | relay `server/{mcp,transfers}.rs`, `embedded.rs`; `src/node/{backend,host}.rs`; `cloud-agents-v1.md` §6 | S5-R2 |
| NA4 | UI: transfer card and copies | M | NA2 | `src/desktop/ui/` question card and credential page files | S5-R2 |
| P2 | Loopback base URLs | M | P1, X2 | `proxy/{base.rs (new), listener.rs, network.rs}`, `broker-v0.md` | S5-R2 |
| P3 | WebSocket (**panel**) | M | P1 | `proxy/{ws.rs (new), engine.rs}`; WebSocket cases in `tests/run_proxy.rs` | S5-R2 |
| X3 | Linux agent-host launcher (**panel**) | M | X1 | `src/bin/apassy-sandbox.rs` (Linux mode), `src/isolation/linux/host.rs` (new), `isolation-linux.md` | S5-R2 |
| P4 | HTTP/2 for h2-only clients (**panel**) | L | P1, P3, NA1 | `proxy/{h2.rs (new), engine.rs}`, `Cargo.toml`, `Cargo.lock`, `docs/reviews/proxy-h2-dependencies.md` (new) | S5-R3 |
| P5 | Local authority for Go on macOS (**panel**) | L | P1, P6; SE (S4) merged | `proxy/ca.rs`, `src/native/mod.rs`, `native/ApassyHelper/**`, `src/desktop/ui/settings*.rs`, `docs/security/trust-model.md` | S5-R3 |
| LE8 | Tailnet route | M | N1, N2, N3 (S2/S3), LE3 | relay `cli/link.rs` (forward service), `src/node/linked.rs`, pairing role | S5-R3 |

### V1 — Vault schema 31

- `linked_environment(agent_id PK REFERENCES agent, uuid TEXT UNIQUE (16 random bytes, hex), name TEXT,
  route TEXT CHECK (route IN ('ssh','tailnet')), target TEXT (ssh destination or tailnet name),
  api_port INTEGER CHECK (49152..65534), executor_version TEXT, isolation TEXT CHECK (isolation IN
  ('netns','none','unknown')), enabled INTEGER, last_seen_at INTEGER, last_error TEXT)`. The forward port is
  `api_port + 1`.
- `item_copy(id PK, item_id REFERENCES item, action TEXT, destination TEXT (JSON of the approved parameters,
  never a value), agent_id INTEGER NULL, item_revision INTEGER, at INTEGER, outcome TEXT CHECK (outcome IN
  ('copied','failed')))`.
- Both in `LOCAL_TABLES`. Accessors: `Vault::{add_linked_environment, linked_environments,
  linked_environment, set_linked_status, remove_linked_environment, record_item_copy, item_copies,
  stale_copies(item_id)}`.
- Acceptance: `schema_30_to_31_and_back` (a schema 30 fixture, or the newest schema in the tree when V1
  starts; the migration chain stays in order); `linked_tables_are_local` (a pushed copy has no rows, a merge
  never reads them); a bad route, port, or outcome is refused by the CHECK; `item_copy.destination` with a
  value-shaped text is refused by the accessor (no field named `value`).

### P1 — Proxy engine split (no behavior change for local runs)

- `engine.rs`: `ProxyCore` = today's `Shared` plus `serve`, `connect`, `intercept`, `serve_requests`.
  `pub fn new(secrets: Vec<ProxySecret>, options: CoreOptions) -> io::Result<Arc<ProxyCore>>`;
  `ca_pem()`, `hosts()`, `serve_connection(self: &Arc<Self>, stream: TcpStream, preread: Vec<u8>,
  auth: Auth)` (`Auth::Password(Zeroizing<String>)` or `Auth::Checked`), `close_all()`, `events()`.
  `CoreOptions { tls, other_hosts, upstream: UpstreamPolicy, sink: Option<Arc<dyn Fn(&ProxyEvent) + Send + Sync>>, alpn: Alpn }`;
  `UpstreamPolicy::{Any, PublicOnly { fixed: Vec<(String, SocketAddr)> }}` (`fixed` for tests, as the
  relay's `UpstreamOptions`).
- `listener.rs`: `RunProxy` with the same public signature (`start`, `start_with_access`, `network`,
  `finish`).
- `network.rs`: `network_for` and `RunNetwork { env, rule: NetworkRule, sandbox_profile, ca_file }`,
  `NetworkRule::{Seatbelt, Netns, None}`; `run.rs:2071` reads `rule` (the only run.rs edit).
- `public_addr.rs`: `is_public_ip` moved from relay `proxy/upstream.rs:304`, which now calls it.
- `base_env.rs`: `base_var`, `provider_vars` (with the OpenAI `/v1` suffix), `RESERVED_BASE_NAMES`, moved
  from relay `server/env.rs`, which now calls them.
- `ca.rs`: `server_config(host, alpn)`.
- Acceptance: `tests/run_proxy.rs` and `tests/agent_run.rs` pass with no change; the relay proxy and env
  tests pass with no change; new `serve_connection_uses_the_preread_bytes`,
  `public_only_refuses_private_loopback_and_tailnet_addresses`, `the_sink_gets_each_event`.

### X1 — Linux sandbox module

- `src/isolation/linux/{mod,bwrap,bridge,probe}.rs`, Linux only, `std` only.
- `probe() -> Availability::{Ready { version }, Missing, TooOld { version }, UsernsBlocked { hint }}`
  (runs `bwrap --unshare-all --die-with-parent -- /bin/true` once and caches the result).
- `Sandbox::builder()`: `net(NetPlan::{Bridged(Vec<Bridge>), Host})`, `deny(paths)`, `read_only(paths)`,
  `rw(paths)`, `bind_socket(path)`, `cwd`, `env`; `command(program, args) -> Command`. A `Bridge { inside:
  u16, outside: PathBuf }` becomes an `--ro-bind` of the Unix socket and a `__netns-bridge` prefix.
- `bridge_main(args) -> i32`: listens on each `127.0.0.1:<inside>` in the namespace, forwards each
  connection to its Unix socket, runs the program as its child, and exits with its code.
- The default mount plan for a run: `/` read-only, the working directory and a private `/tmp` writable,
  `$XDG_RUNTIME_DIR` hidden (the user bus and `systemd --user` start programs outside the sandbox), the
  Apassy data directory hidden, the link file hidden, `/proc` new.
- CI (this unit owns the steps first): `sudo apt-get install -y bubblewrap` and `sudo sysctl -w
  kernel.apparmor_restrict_unprivileged_userns=0` on ubuntu-24.04, and `APASSY_REQUIRE_BWRAP=1`, so the tests
  fail instead of skip there.
- Unix sockets are not covered by a network namespace (judge finding M1, 2026-11-03): a run refuses a
  working directory in `/tmp`, `/var/tmp`, `/run`, or `/dev/shm`, the home folder itself, and a folder
  above a denied path; it skips `PATH` folders in those folders; it always denies `/run/user/<real
  uid>` (from `getuid()`, not `XDG_RUNTIME_DIR`); and the deny list has the cloud and container
  credentials (`~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.config/gh`, `~/.docker`, `~/.kube`,
  `~/.netrc`). The path rules are in `src/isolation/run_paths.rs`, tested on every system.
- The probe caches only a definite answer; a timeout or a full namespace limit (`EAGAIN`, `ENOSPC`)
  is probed again on the next run (judge finding L3). CI checks the rule of a run on the stock runner
  before the sysctl change, following the measurement: `none` with `userns_blocked` where user
  namespaces are restricted, else `netns`.
- Known limit (judge finding L5): no seccomp filter, so a run can open an `AF_VSOCK` socket, which a
  network namespace does not cover; on a virtual machine with vsock it reaches the hypervisor host.
  The run holds only placeholders. Follow-up: a seccomp filter for `socket(AF_VSOCK)`.
- Acceptance (Linux): `netns_reaches_only_the_bridged_port` (a direct TCP connection to a listener of the
  host, also on 127.0.0.1, fails); `netns_has_no_udp` (UDP to 1.1.1.1:53 fails); `netns_abstract_socket_of_the_host_is_unreachable`;
  `netns_cannot_see_outside_processes`; `netns_run_ends_with_its_descendants` (a `setsid` grandchild does not
  outlive the stop); `sandbox_hides_the_apassy_data_dir_and_the_runtime_dir`; `probe_reports_userns_blocked`
  (with a fake `bwrap` script); on other systems the module is absent.

### X2 — Linux rule for local proxied runs

- `network_for` on Linux: with `probe()` ready, `rule = Netns` and a plan with one bridge to the proxy port;
  without it, `rule = None`. `exec::Network` gets `linux: Option<&LinuxNet>`; `spawn_collect` builds the
  `bwrap` command. The macOS path does not change.
- Acceptance (Linux CI): the Linux twins of the macOS rule tests in `tests/run_proxy.rs`
  (`linux_direct_connection_fails_in_a_proxied_run`, `linux_proxied_run_reports_netns`); a run without
  bubblewrap reports `none` and still holds only placeholders.

### LE1 — Relay: linked scope, forward front, team schema 10

- Config: `EmbeddedOptions { …, linked_listen: Option<SocketAddr>, forward_listen: Option<SocketAddr> }`,
  both loopback only (`check_listeners`). `Relay::start` binds a third `tiny_http` listener
  (`Scope::Linked`: the agent paths of `is_agent_path` and nothing else, its own limits and failed-auth
  limiter) and the forward front (`server/forward.rs`, plain `std::net`).
- Lanes: `agent.lane`; a token whose lane does not match the listener's scope is 401 `unauthenticated`
  and counts as a failed authentication.
- Runs: `RunRequest` gains optional `user_request_source`, `host_session`, `project_root`, accepted only on
  the linked scope, stored in `run` (team schema 10), and passed in `PendingRun`.
- Release: `host::release_values(core, run_id, values, reason, ReleaseOptions { origin: Option<String>,
  forward: bool })`. `origin` must be `http://127.0.0.1:<port>`. With `forward`, `sessions.create` builds a
  `ProxyCore` from the session secrets (`OtherHosts::Refuse`, `UpstreamPolicy::PublicOnly`, a sink that
  writes `proxy_request` audit rows) and a forward password (`TokenKind::Forward`, stored as a hash). The
  `SessionView` gets `forward: { user: "apassy", password, ca_pem, hosts }`. Removing the session calls
  `close_all` and drops the engine.
- Front: reads one request head (8 KiB cap, 10 s), needs `CONNECT`, looks the password up, and hands the
  stream to the session's engine. A wrong password is 407 and counts in the limiter; a session of another
  lane is 407.
- Core: `NodeConfig.linked: Option<LinkedListen { api: SocketAddr, forward: SocketAddr }>`,
  `RunningNode::linked_addrs()`, `RunningNode::release(team, run, values, reason, ReleaseOptions)`,
  `NewCloudAgent.lane`.
- Acceptance (relay `tests/linked.rs`): `linked_scope_serves_agent_paths_only` (`/v1/me`, `/healthz`,
  `/oauth/*` are 404); `linked_token_refused_on_the_public_listener_and_back`;
  `forward_front_wrong_password_is_407_and_trips_the_limiter`; `forward_front_refuses_hosts_outside_the_session`;
  `forward_front_refuses_private_upstreams` (502 `upstream_failed`); `forward_swaps_against_a_local_tls_upstream`
  (test root, fixed address); `session_end_closes_live_tunnels`; `revoke_stops_the_next_request`;
  `the_view_never_has_a_value` (search the serialized view for the value bytes);
  `release_origin_must_be_loopback_http`; `team_schema_9_to_10_and_back`; the hosted config binds neither new
  listener.

### LE2 — Node routes and the SSH tunnel

- `Node::start` starts when the Funnel route is on **or** a linked environment is enabled. Tailscale and
  Funnel are needed only for the Funnel route. The node binds the linked listener and the forward front on
  free loopback ports for each start.
- `src/node/ssh.rs`: `trait SshRunner { fn spawn(&self, args: &[String]) -> io::Result<Box<dyn SshChild>> }`;
  `Tunnel::supervise(destination, forwards) -> TunnelHandle { status(), stop() }`. Fixed arguments: `-N -T
  -o BatchMode=yes -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=yes -o ServerAliveInterval=15 -o
  ServerAliveCountMax=3 -o ControlMaster=no -o ControlPath=none -R 127.0.0.1:R:127.0.0.1:<linked> -R
  127.0.0.1:R+1:127.0.0.1:<forward>`. Never `-g`, never a forward without `127.0.0.1`. Restart with backoff
  (1 s to 60 s); stop on lock, on quit, and on unlink.
- `src/node/linked.rs`: the list of enabled environments, their tunnels, and the status for the UI and
  `apassy environment list` (up, down with the last ssh error, host key changed).
- The host loop passes `ReleaseOptions { origin: "http://127.0.0.1:R", forward: true }` for an agent of a
  linked environment.
- Acceptance (fake `SshRunner`): `ssh_arguments_are_fixed`; `the_tunnel_restarts_with_backoff`;
  `lock_and_quit_stop_every_tunnel`; `the_node_starts_for_a_linked_route_without_tailscale`;
  `funnel_stays_off_when_only_linked_routes_are_on`.

### LE3 — Executor on Linux

- `cli/link.rs`: `link.json` v1 `{ v, environment, node, api, forward, token, installed_at }`, refused when
  its mode is not 0600 or a field is unknown; `apassy-team link check` (version, `GET /v1/access`, `probe()`,
  prints no token).
- `cli/exec.rs` in link mode: bind the router on `127.0.0.1:0`; `POST /v1/runs` with `cwd`,
  `project_root`, `host_session`, the prompt and its source; wait; write the trust files from
  `forward.ca_pem` in a 0700 folder; set the session `env`, `HTTPS_PROXY` and the other variables of ADR
  0011 §4 (pointing at the router, with the forward password); run the command through X1 with bridges for
  the router port and `R`; mask each placeholder, the session key, and the forward password in the output as
  `[apassy:NAME]`; report `network.rule` and the requests.
- `cli/router.rs`: CONNECT to a host of the session → a new TCP connection to `R+1`, sending the original
  head; CONNECT to another host → direct, or 403 when the run asked `other_hosts = refuse`; origin-form
  `/p/…` → `R`; `http://` to a host of the session → 403; a wrong password → 407.
- `cli/mcp_stdio.rs` in link mode: a local tool `apassy_run_with_secrets` with the schema of the Mac's tool
  (`src/agent/mcp.rs`), served by the executor; other tools forwarded to `/mcp`.
- `cli/hook.rs`: `apassy-team hook` stores the newest prompt per host session (0600, one hour).
- Acceptance (unit tests): `router_sends_hosts_of_the_session_to_the_node`;
  `router_tunnels_or_refuses_other_hosts`; `router_refuses_plain_http_to_a_host_of_the_session`;
  `router_needs_the_password`; `output_masks_placeholders_keys_and_the_password`;
  `link_file_must_be_0600_and_strict`; `the_local_run_tool_matches_the_mac_schema`;
  `the_hook_store_keeps_the_newest_prompt_for_one_hour`.

### LE4 — Owner commands and the install

- `apassy environment link ssh://user@host[:port] [--name NAME] [--binary PATH] [--update]`, `list`,
  `check NAME`, `unlink NAME`. Owner wire: `Command::{EnvironmentLink, EnvironmentList, EnvironmentCheck,
  EnvironmentUnlink}`. `link` and `unlink` need the owner check.
- `src/node/install.rs`: the first `ssh` runs in the owner's terminal with
  `StrictHostKeyChecking=accept-new`, so the owner sees the host key once; `uname -m` (`x86_64` or `aarch64`,
  else refuse); the binary from the release download or `--binary` (sent through `ssh` standard input);
  the SHA-256 check on the remote against the Mac's own `SHA256SUMS`; `link.json` written through standard
  input with `umask 077`; then `apassy-team link check` through the new tunnel. The answer prints the two
  lines that add the MCP server on the remote (Claude Code and Codex) and the hook line.
- Acceptance (fake `SshRunner` transcripts): `the_token_is_never_in_an_argument_list`;
  `a_checksum_mismatch_stops_and_removes_the_binary`; `an_unknown_architecture_is_refused`;
  `link_and_unlink_need_the_owner_check`; `unlink_revokes_stops_and_removes`.

### LE5 — Decision route of linked runs

- `broker::run::evaluate_linked(ctx, agent_id, &RunRequest, LinkedContext { relay_run, environment,
  remote_cwd, remote_root, host_session, request_source, stop })` = `run_inner` with `evaluation_only`,
  without `authenticate` and `prompts.resolve`, with the project `linked:<uuid>:<root>`, the prompt source
  of D6, and `ReasonKind::LinkedEnvironment` only for the card text. `src/node/host.rs` dispatches by the
  environment of the agent: linked → `evaluate_linked`, cloud → `evaluate_cloud`.
- Acceptance: `a_checked_linked_prompt_goes_to_the_bouncer`; `an_unchecked_prompt_asks`;
  `production_asks_in_a_linked_environment`; `a_linked_answer_does_not_cover_a_mac_project`;
  `a_real_value_item_is_refused_for_a_linked_environment`; `the_card_names_the_environment_and_the_source`.

### LE6 — Linked end-to-end tests in CI (the stage 5 acceptance without the paid devbox)

One test file, `crates/apassy-relay/tests/linked_e2e.rs`, in the relay test shard. Every tier uses a
synthetic item `E2E_TOKEN` for `api.e2e.apassy.test`, a local TLS upstream with a test root and a fixed
address, the in-process Mac node (`apassy::node::Node` with `EmbeddedRelay`, a file key store, and no
Tailscale), a test asker that answers Allow once, and the built `apassy-team` binary
(`CARGO_BIN_EXE_apassy-team`) as the executor with its own `HOME`. The upstream echoes the
`Authorization` header and records what it got. The command is `sh -c 'env > out/env.txt; curl -sS
https://api.e2e.apassy.test/echo -H "Authorization: Bearer $E2E_TOKEN"'`.

| Tier | Where | Transport | Extra checks |
| --- | --- | --- | --- |
| A `linked_run_holds_only_placeholders` | ubuntu-24.04 and macos-15 | The remote ports are the linked listener and the forward front themselves (test route) | — |
| B `linked_run_over_ssh` | ubuntu-24.04 | A real non-root `sshd -D -f <temp config> -p <free port>` on 127.0.0.1, a temp host key and client key, `AcceptEnv APASSY_LINK_CONFIG`; the real LE2 supervisor and LE4 install with `--binary` | The tunnel comes back after `kill` of `ssh` |
| C `linked_netns_has_no_other_route` | ubuntu-24.04 with bubblewrap | As B | `network.rule == "netns"`; `curl --noproxy '*'` to the upstream fails; UDP fails |
| D `linked_container_remote_never_sees_the_value` | ubuntu-24.04, job `linked-remote-container` | A Docker container (`tests/fixtures/linked-remote/Dockerfile`: Debian slim, `openssh-server`, `bubblewrap`, `curl`) published on 127.0.0.1 | `docker exec … grep -rF` for the value over the whole container file system finds nothing |

Every tier asserts: the upstream got `Bearer <value>`; the command output shows the placeholder (the swap
back) and never the value; `env.txt`, the remote `HOME`, and the executor's output have no byte of the
value; the run answer lists one `swapped` request; after the session ends, the router gets 407 and the
upstream gets nothing more; after unlink, the next request is 401. The value is synthetic; the test never
prints it. Owns `ci.yml` after X1: installs `openssh-server` on ubuntu-24.04 and adds the container job.

### LE7 — UI: linked environments

- Bouncer → Agents of this Mac: one row for each linked environment (name, route, tunnel up or down with the
  reason, last contact, executor version, network rule), and Unlink (owner check). "Link an environment…"
  opens a sheet with one field (`user@host`) that runs the LE4 flow and shows its progress.
- Frames are added to `docs/design/cloud-agents-mockup.html` in the approved style before code. Before the
  release claim, each view gets a screenshot next to its frame.
- Acceptance: screenshots next to the frames; Unlink needs the owner check; a tunnel error shows the ssh
  reason and the fix.

### P6 — Process hardening

- `src/harden.rs`: `pub fn process()`. Linux: `rustix::process::set_dumpable_behavior(NotDumpable)` and
  `RLIMIT_CORE = 0`; macOS: `RLIMIT_CORE = 0`. Called first in `main` of the app, `apassy-mcp`,
  `apassy-team`, and `apassy-relay`. `scripts/build-app.sh` fails when any binary has `get-task-allow`.
  `isolation.md` gets a "Hardening" section with the facts above.
- Acceptance: `a_linux_child_cannot_read_the_environ_of_a_hardened_parent` (EACCES on
  `/proc/<pid>/environ`); `the_core_limit_is_zero`; the build check is in the script.

### NA1 — Transfer engine

- `src/broker/transfer/{mod,vercel,github,seal}.rs`. `Action` catalog (id, destination host, parameters
  with rules, request builder, result parser), `Plan` (action + checked parameters), `describe(&Plan) ->
  String` (the card sentence), `execute(&Plan, &TlsClient, source: &Zeroizing<String>, auth:
  &Zeroizing<String>) -> Result<Outcome, TransferError>`. No redirect is followed; `UpstreamPolicy::PublicOnly`;
  parameters are percent-encoded into paths; answers above 64 KiB are refused.
- `vercel.env`: `POST /v10/projects/{project}/env?upsert=true[&teamId=…]`, body `{ key, value, type,
  target }`. `github.actions_secret` and `github.environment_secret`: `GET …/public-key`, a libsodium
  sealed box (`crypto_box` with the `seal` feature, a new dependency with its review file), then
  `PUT …/secrets/{name}` with `encrypted_value` and `key_id`.
- Acceptance: against local TLS fakes: `vercel_body_has_the_value_only_at_value`;
  `github_value_is_sealed_to_the_repository_key` (a known-answer vector made once with libsodium, with the
  command that made it in the test comment); `parameters_are_encoded_into_the_path`; `a_redirect_is_not_followed`;
  `the_auth_item_must_cover_the_action_host`; `errors_and_outcomes_hold_no_value`.

### NA2 — Transfers in the broker

- Broker action `{"kind":"transfer","action":"vercel.env","item_id":12,"auth_item_id":4,"params":{…},"purpose":"…"}`
  → `{"status":"copied","destination":"…","copy_id":7}` or a code. MCP tool `apassy_transfer_secret`.
  Checks: both items visible to the agent; the auth item covers the action host; the source item is not a
  one-time code; then the owner question (always, owner check, no remembered answer), then a recheck of
  the vault and both items, then `execute`, then `record_item_copy` and one activity row (action,
  destination, outcome; never a value).
- The proxy refusal of a placeholder in a body adds: "To copy a credential to another service, use
  apassy_transfer_secret."
- Acceptance: `a_transfer_always_asks_with_the_owner_check`; `a_denied_transfer_sends_nothing`;
  `a_transfer_records_its_copy_without_a_value`; `the_body_refusal_names_the_tool`;
  `a_transfer_after_a_lock_sends_nothing`.

### NA3 — Transfers over the node

- Relay `/mcp` tools `apassy_transfer_secret` and `apassy_transfer_status` on the public and linked scopes;
  an in-memory table of pending transfers (300 s, gone at a restart); `RunningNode::wait_pending` returns
  `Pending::{Run, Transfer}`; `RunningNode::finish_transfer(id, outcome)`; the host loop calls the NA2 path.
- Acceptance: `the_node_lists_the_transfer_tools`; `transfer_status_goes_to_copied`;
  `a_restart_forgets_pending_transfers`; `a_cloud_transfer_names_the_cloud_agent_on_the_card`.

### NA4 — UI: transfer card and copies

- The Mac card of a transfer: "<agent> wants to copy <credential> to <service> (<host>): <destination>.
  <service> will keep a copy." The credential page: "Copies" with each destination, its date, "stale" after
  a rotation, and "Update copies" (one owner check, then one transfer for each copy).
- Acceptance: screenshots next to new mockup frames; "Update copies" makes one transfer for each copy and
  each needs the owner's approval.

### P2 — Loopback base URLs

- `base.rs`: origin-form `/b/<base token>/<host>[/<path>]` on the run proxy port; the token is 32 random
  hex for the run (not the proxy password); the host must be a host of the run; the request goes through the
  same swap and answer rules. `network.rs` adds the variables of `base_env.rs`; `RESERVED_VARIABLES` gets
  them.
- Acceptance: `a_base_url_reaches_the_service_with_the_swap`; `a_wrong_base_token_is_403`;
  `a_host_outside_the_run_is_403`; `a_go_client_works_with_a_base_url_in_the_seatbelt_rule` (macOS, skips
  without `go`).

### P3 — WebSocket

- `ws.rs`: the frame relay of D11 (masking, fragments, control frames, 1 MiB frame cap).
- Acceptance: `websocket_handshake_swaps_the_auth_header`; `websocket_query_token_is_swapped`;
  `a_server_frame_with_the_value_reaches_the_client_as_the_placeholder` (also split across two frames);
  `a_client_frame_with_a_placeholder_closes_with_1008`; `the_extension_offer_is_removed`;
  `websocket_to_another_host_is_a_tunnel`.

### X3 — Linux agent-host launcher

- `apassy-sandbox` on Linux: the bubblewrap equivalent of `sandbox/apassy-agent-host.sb`. The network of the
  host is kept. Denied: the Apassy data directory (`$XDG_DATA_HOME/apassy`), every vault of the vault
  list, the backup, the synced files, the link file; only the broker socket node is bound back. Read-only
  (the launcher creates the empty folders first): `~/.config/systemd/user`, `~/.config/autostart`,
  `~/.config/environment.d`, the shell startup files, the browsers' `NativeMessagingHosts` folders.
  Hidden: `$XDG_RUNTIME_DIR` (the user bus, `systemd-run --user`). A new PID namespace. It fails closed
  without bubblewrap, as on macOS.
- Acceptance: the Linux twins of the macOS measurements in `isolation.md` §5 and §7, each with a control
  outside the profile: data dir read fails; broker socket works; owner socket fails; each autostart write
  fails; `systemd-run --user` fails; other processes are not visible; normal work (git, cargo, network)
  works.

### P4 — HTTP/2 for h2-only clients

- `h2.rs` behind `proxy-h2` (on in app and Linux builds after the panel): the D12 design; limits:
  100 concurrent streams, 16 KiB header list, the crate's reset-stream limit, the same body cap as HTTP/1.1.
- Acceptance: `an_h2_only_client_gets_h2_and_the_swap`; `a_placeholder_in_data_resets_the_stream_and_logs_a_refusal`;
  `trailers_get_the_placeholder_back`; `a_client_with_h2_and_http11_stays_on_http11`;
  `an_upstream_without_h2_fails_closed_for_an_h2_only_client`; a rapid-reset client is cut off.

### P5 — Local authority for Go on macOS

- Helper: the root key through `se_key_create` and `se_key_sign` of unit SE (S4); new commands
  `ca_trust_install(der)` (user domain; macOS shows its prompt) and `ca_trust_remove`. `ca.rs`:
  `RunCa::under(root, hosts)`. Settings → this Mac: "Trust Apassy for Go programs (gh and others)" with the
  facts of D10, behind an owner check.
- Acceptance: `a_run_chain_under_the_root_verifies` (`security verify-cert`); a macOS CI job with `sudo
  security add-trusted-cert` of a test root records whether a Go client accepts a leaf outside the root's
  constraints (the measurement of D10, written to `isolation.md`); `switch_off_removes_the_trust_and_the_key`;
  the root key is not exportable.

### LE8 — Tailnet route (after N1, N2, N3 of the S2/S3 plan)

- `apassy-team link forward` (a systemd user unit) holds `R` and `R+1` and forwards them with pinned TLS to
  the node's TLS front. Pairing role "linked environment" in the pairing QR; `apassy environment link
  <tailnet name>`. Peers outside the owner's tailnet are refused (WhoIs, ADR 0037 §3).
- Acceptance: tier A of LE6 with a pinned TLS front between the executor and the node; a wrong pin is
  refused.

## One editor per shared file

Units of the parallel plans are named with their plan. When two of them are ready at the same time, the
first to merge wins and the other rebases; no two units edit one file at the same time.

| File | Order of editors |
| --- | --- |
| `src/broker/proxy/mod.rs`, `listener.rs` | P1 → E1 (S6, `ProxySecret.signer`) → P2 |
| `src/broker/proxy/engine.rs` | P1 → E1 (S6, SigV4 in `serve_requests`) → P3 → NA2 (one sentence) → P4 |
| `src/broker/proxy/network.rs` | P1 → X2 → P2 |
| `src/broker/proxy/ca.rs` | P1 → P5 |
| `src/broker/run.rs` | P1 (2 lines) → E1 and F (S6, `read_secrets`) → TH-N (S4, `evaluate_team`) → LE5 → NA2 (if needed) |
| `src/broker/decide.rs` | LE5 → NA2 |
| `src/broker/exec.rs` | X2 |
| `src/agent/mcp.rs` | NA2 |
| `src/node/backend.rs` | U1b → N1 (S2/S3) → SH-R, TH-R (S4) → G (S6) → LE1 → NA3 |
| `src/node/host.rs` | U2b → TH-N (S4) → G (S6) → LE5 → NA3 |
| `src/node/mod.rs`, `src/desktop/node.rs` | U2b → N4 (S2/S3) → TH-N (S4) → LE2 (→ LE8) |
| `src/vault/{types,mod,merge}.rs` | in schema order: U3a (27), N3 (28), C2 (29), SH-V (30), V1 (31), SE (33); LE2 and NA2 use V1's accessors |
| relay `server/http.rs`, `embedded.rs`, `config.rs` | U1b → N1 (S2/S3) → SH-R → TH-R (S4) → LE1 → NA3 |
| relay `server/mcp.rs` | U1b → NA3 |
| relay `server/store.rs` | N1 (team 8) → SH-R (team 9) → LE1 (team 10) |
| relay `server/{sessions,host}.rs`, `session.rs` | TH-R (S4) → G (S6) → LE1 |
| relay `server/mod.rs`, `api.rs` | N1 (S2/S3), SH-R (S4) where they touch them → LE1 |
| relay `proxy/upstream.rs` | P1 |
| relay `server/env.rs` | P1 → E2 and G (S6) |
| relay `cli/{mod,settings}.rs` | L1 (S2/S3) → LE3 (→ LE8) |
| relay `cli/exec.rs` | G (S6, lease expiry line) → LE3 (→ LE8) |
| relay `cli/{mcp_stdio,args}.rs` and the new `cli/{link,router,hook}.rs` | LE3 (→ LE8) |
| `src/cli/**`, `src/owner/wire.rs`, `src/desktop/owner_cli.rs` | LE4 |
| `src/desktop/ui/agents.rs`, `ui/linked.rs` | LE7 |
| `src/desktop/ui/settings.rs` | SE (S4) → P5 |
| `src/desktop/ui/` question card and credential page | NA4 |
| `Cargo.toml`, `Cargo.lock` | NA1 → P4 (P6 only if a `rustix` feature is missing) |
| `.github/workflows/ci.yml` | X1 → LE6 → P5 |
| `docs/contracts/broker-v0.md` | X2 → P2 → NA2 |
| `docs/contracts/cloud-agents-v1.md` | NA3 |
| `docs/operations/isolation.md` | X2 (pointer) → P6 → P5 (measurement) |
| `docs/operations/isolation-linux.md` | X1 → X3 |
| `docs/security/trust-model.md` | N8 (S2/S3) → LE1 → P5 |
| `src/native/mod.rs`, `native/` helper sources | SE (S4) → P5 |
| relay `docs/SPEC.md` | LE1 → NA3 |
| `CHANGELOG.md`, ADR status lines, `release-versions.json` | the top-level agent only |

## Order and waves (at most three workers at once on this Mac, across all threads)

Before each wave the top-level agent counts the running agents of all threads and starts at most three
minus that count.

1. Wave 1: P1, V1, X1 (no shared files).
2. Wave 2: LE1 (after U1b, N1, SH-R, TH-R merge), X2, NA1.
3. Wave 3: LE2, LE3, P6.
4. Wave 4: LE4, LE5 (after U2b and TH-N merge), P3.
5. Wave 5: LE6, LE7, NA2. Panel on LE1 + LE3 + LE5 before LE6 is marked ready.
6. Wave 6: NA3, NA4, P2. Panel on NA1 + NA2.
7. Wave 7: X3, P4, P5. Panels on X1 + X3, P3, P4, P5 as each completes.
8. Wave 8: LE8, when N1, N2, and N3 of the S2/S3 plan are merged.

A FAIL from a judge goes back to the implementer of that file (SendMessage), not to a new agent. The
top-level agent runs one validation pass for each revision and keeps every rerun.

## Physical acceptance (owner-gated; CI tier B to D already proves the design)

1. `devbox up arm` (paid, owner step 2). On the devbox: `sudo apt-get install -y bubblewrap`.
2. On the Mac: `apassy environment link ssh://dev@devbox-arm` → owner check → install → `link check` is
   green and says `network rule: netns`.
3. On the devbox, Claude Code with `apassy-team mcp` as its MCP server: `apassy_run_with_secrets` with a
   synthetic `HTTPBIN_TOKEN` for `httpbingo.org`: `curl -sS https://httpbingo.org/bearer -H "Authorization:
   Bearer $HTTPBIN_TOKEN"`. The Mac or the iPhone shows the card "on devbox-arm (linked)"; the owner
   approves.
4. The answer has `"authenticated": true` and shows the placeholder. `grep -rF` for the synthetic value in
   the devbox home and in `/proc/*/environ` finds nothing. The Mac's activity log has the decision row and
   the session summary.
5. Lock the vault: the next run fails and `ssh` is gone on the Mac. Unlock: the tunnel returns. Unlink: the
   next call is 401 and `link.json` is gone.
6. `devbox down arm`.

## Release grouping

Each release bumps all six components to one version (AGENTS.md): the version is the next free one when the
group is complete, after the release that ships the cloud slice and U1b. If two groups are complete at the
same time, they ship as one release.

| Release | Units | What users get | Components with functional changes |
| --- | --- | --- | --- |
| S5-R1 | V1, P1, X1, X2, LE1 to LE7, P6 | Linked environments over SSH; the Linux network rule; hardening | Mac app, Linux CLI (executor), relay (team schema 10; the hosted relay binds no new listener). Extension, iOS, website: version and changelog. |
| S5-R2 | NA1 to NA4, P2, P3, X3 | Named actions; loopback base URLs; WebSocket; the Linux agent-host launcher | Mac app, relay (transfer tools), Linux CLI |
| S5-R3 | P4, P5, LE8 | HTTP/2 for h2-only clients; the local authority; the tailnet route | Mac app, Linux CLI |

Upgrade notes: vault schema 31 (update every Mac of a vault together, as for 26); relay team schema 10 with
its down-migration in `docs/OPERATIONS.md`; the executor must match the Mac's release (`apassy environment
link --update`). `python3.12 scripts/check-release-versions.py` before publication; each live artifact is
read back before a release is called complete.

## Owner-needed steps (all others are done by agents)

1. **Release gates of each release:** the relay image and backup before the compose change on `ottervibe`;
   TestFlight to the group "Apassy"; the Chrome Web Store submission (as G4 and G5 of the 0.5.16 plan; one
   "release go" answer each).
2. **One paid devbox session** (`devbox up arm`, shared 12.50 EUR budget, about 30 minutes) for the physical
   stage 5 acceptance. CI tiers A to D need no paid server.
3. **Presence for approvals** in the physical checks: Touch ID on the Mac or Face ID on the iPhone for one
   linked run and one transfer.
4. **The macOS trust prompt** of P5 when the owner turns on "Trust Apassy for Go programs". Only the owner
   can type the password. The feature is off by default; S5-R3 ships without the owner turning it on.
5. **A scratch Vercel project and a scratch GitHub repository** for the transfer check, because a transfer
   writes into the owner's accounts.
6. **The screenshot pairs** (mockup frame next to the app) of LE7 and NA4 before each release claim.

The owner can stop any of these choices without a new plan: D6 (bouncer for linked runs), D8 (Apassy calls
the API), D10 (the authority design), the new dependencies `crypto_box` (NA1) and `tokio` + `h2` (P4).

## Risks and reviews

| Risk | Mitigation | Review |
| --- | --- | --- |
| The forward front makes the Mac a proxy for another machine (requests into the LAN or loopback) | Only hosts of the session, public upstream addresses only, lane-bound tokens, failed-auth limiter, loopback listeners, every request in the audit | Panel on LE1 + LE3 |
| The local authority is a trust anchor in the user's keychain | Off by default; root key in the Secure Enclave, usable only by the signed helper; name constraints; per-run constrained intermediates; the CI measurement of root constraint enforcement; removed when off | Panel on P5 |
| A named action sends the value out of Apassy by design | Always the owner with Touch ID; exact destination on the card; no redirects; public addresses only; copies recorded for rotation; no remembered answer | Panel on NA1 + NA2 |
| A linked run decided by the bouncer with a prompt that the remote checked | The same transcript check as on the Mac; unchecked or missing prompt asks; production asks; linked projects never cover Mac projects; the owner can switch D6 to always ask | Panel on LE5 (with LE1 + LE3) |
| Linux isolation is a new boundary (mount plan, bridge, namespaces) | bubblewrap, not own code; tests with controls; fail closed for the host launcher | Panel on X1 + X3 |
| HTTP/2 is a large parser surface and the first async code | Only for h2-only clients; `h2` crate limits; behind a feature; dependency review | Panel on P4 |
| WebSocket frames can carry a placeholder out or a value in | Frame scan both ways, no compression, close 1008 | Panel on P3 |
| On a multi-user remote, other users reach the loopback ports | They need the token, a session key, or the forward password; the remote holds no value | — |
| A same-user process on the remote reads the placeholders and the forward password (F11 on Linux) | Only placeholders; the session ends after its TTL; `PR_SET_DUMPABLE=0` for the executor; the PID namespace for runs | — |
| Ubuntu blocks unprivileged user namespaces, or the remote is a container | `network.rule = none` is reported; `link check` and `doctor` print the fix; values never reach the remote anyway | — |
| SSH depends on the owner's setup (agent prompts, host keys of recreated devboxes) | `BatchMode`, clear tunnel errors ("host key changed: run link again"), the first ssh in the owner's terminal | — |
| The Mac must be awake, unlocked, and running | As the cloud slice; status shown on the remote (`link check`) | — |
| Migration order across plans: vault 31 must follow 27 to 30, relay team 10 must follow 8 and 9 | V1 and LE1 merge only after the lower numbers; if a lower number stalls, the top-level agent renumbers and updates this file | — |
| Shared files are owned by the OAuth, Bouncer-section, S2/S3, and S4 units first | The one-editor table orders them; LE1, LE2, LE3, LE5 and P5 start from the merged state of their predecessors | — |
| Vercel and GitHub APIs change | Fakes in CI follow the documented shapes; the physical check uses the real APIs | — |

## Not verified in the code

- Whether `rustix 1.1.4` with the `process` feature exposes `set_dumpable_behavior` and `setrlimit` on Linux,
  or a feature must be added.
- Whether bubblewrap can make user namespaces on the devbox images and on GitHub's ubuntu-24.04 runners with
  `kernel.apparmor_restrict_unprivileged_userns=1`, and whether Ubuntu's AppArmor profile for `bwrap`
  changes that. X1 measures it first.
- Whether GitHub's ubuntu-24.04 runners have `sshd`; LE6 installs `openssh-server` in any case. Whether a
  non-root `sshd` with `AcceptEnv` works there as planned.
- Whether macOS (and Chrome on macOS) enforce the name constraints of a user-trusted root (P5 measures it).
- Whether the Swift helper can make a Secure Enclave key whose use needs no user presence and is limited to
  the signed helper, and whether Intel Macs without a Secure Enclave are still supported.
- The Vercel endpoint version and fields (`/v10/projects/{id}/env`, `upsert`, type `sensitive`) and the
  GitHub secret endpoints; the audit status of `crypto_box` 0.9.
- The paths of the Linux downloads and `SHA256SUMS` of a release (`/dl` or GitHub Releases).
- Whether `apassy-team`'s settings accept an `http://127.0.0.1:<port>` relay URL; LE3 adds it if not.
- Whether the Mac's MCP tool schema in `src/agent/mcp.rs` is reachable from the relay crate with its
  features; if not, LE3 copies the schema and a test compares the two.
- The default of `see_all` for a new local agent (D6 follows it).
- Whether the OAuth unit U1b changes `RunningNode` or `Scope` in a way that LE1 must follow; LE1 starts from
  its merged state.
