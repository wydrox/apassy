# The node on Linux

Date: 2026-11-03. Plan: [implementation plan S2–S3](../design/implementation-plan-s2-s3.md), decision D8, unit L1 (the service details of unit L2 and the packages of unit L3 come later). Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) stage 3. Contract: [node-pairing-v1](../contracts/node-pairing-v1.md).

A Linux machine on your tailnet runs the Apassy **node** without a window: the relay of the questions, the feed, the access requests, and relay sync for your devices, and a team host for `apassy team`. The Mac and the iPhone reach it at `https://<Tailscale IPv4>:8444`, behind a self-signed certificate that they pin. It needs no vault and no unlock.

## Words

On Linux, `apassy` is the node. On macOS, `apassy status` and `apassy doctor` are the owner commands of the app (with a "Node" section later); `apassy serve`, `up`, `pair`, and `team` are node commands on both.

| Command | What it does |
| --- | --- |
| `apassy up` | Checks Tailscale, makes the node's files, installs and starts the systemd user service `apassy-node.service`, waits for the node, and prints `status` and a pairing link |
| `apassy serve` | Runs the node in the foreground. The service runs this |
| `apassy serve --stop` | Stops the node of this data directory and waits until it has stopped |
| `apassy pair [--minutes N] [--json]` | A one-use link and QR code that pairs a Mac with this node, 1 to 10 minutes (default 10) |
| `apassy status [--json]` | The service, the tailnet route, the pin, the teams, the push gateway, the key source |
| `apassy doctor [--json]` | The checks, each with the next step |
| `apassy team ...` | The team command line, the same as `apassy-team ...` |

Every command takes `--data-dir DIR`. The default is `$XDG_DATA_HOME/apassy/node`, or `~/.local/share/apassy/node`. On a Mac the default is refused: the Mac's own node runs inside the app.

Exit codes: 0 success; 1 a check failed (`doctor`) or the node did not start; 2 usage; 3 the node is not running (`status`, `pair`); 4 the node or the network failed.

## Set up

1. Install Tailscale and sign in: `curl -fsSL https://tailscale.com/install.sh | sh`, then `sudo tailscale up`.
2. Run `apassy up`. It refuses with the next step when Tailscale is missing, not connected, or has no address on an interface of this machine.
3. To start the node at boot without a login, turn on linger once: `sudo loginctl enable-linger $USER`. `apassy up` and `apassy doctor` say when it is off.
4. In Apassy on the Mac, choose "Your own node" and scan the QR code that `apassy up` printed, or paste the link (unit L4). Run `apassy pair` for a new link: each link works once, for at most 10 minutes.

Options of `apassy up`:

| Option | Meaning |
| --- | --- |
| `--port N` | The port of the node on the tailnet (default 8444; never 443, 8443, or 10000). A change after the first pairing changes the node origin: every device pairs again |
| `--route direct` | The default: the TLS front binds the Tailscale addresses of this machine |
| `--route serve-tcp` | For Tailscale with userspace networking (no `tailscale0` interface): the front binds `127.0.0.1:<port>`, and Tailscale Serve in TCP mode forwards the tailnet port to it. Serve does not end TLS, so the pin holds end to end. It needs `sudo tailscale set --operator=$USER` once |
| `--push-gateway URL` | Another push gateway (default `https://push.apassy.wyderka.cc`) |
| `--no-push` | No push notifications |
| `--no-service` | Only the files and the settings; start `apassy serve` yourself |
| `--no-pair` | No pairing link at the end |

## What listens

Nothing listens on `0.0.0.0` or `::`.

| Listener | Address | Serves |
| --- | --- | --- |
| TLS front | The Tailscale IPv4 and IPv6 of this machine, port 8444 (`--route serve-tcp`: `127.0.0.1:8444` behind Tailscale Serve) | TLS 1.3 only, the node certificate; it refuses peers outside `100.64.0.0/10` and `fd7a:115c:a1e0::/48` before the handshake, and it forwards bytes to the tailnet listener |
| Tailnet listener of the relay | `127.0.0.1:<free port>` | The device routes and the team routes (`Scope::Tailnet { agents: true }`); never the operator routes, `/v1/connect`, or the OAuth endpoints |
| Node listener of the relay | `127.0.0.1:<free port>` | Every route, plain HTTP, for local tools; no Funnel, no public listener |
| Operator socket | `<data>/relay/admin.sock`, mode 0600 | `apassy pair` and `apassy status` |
| Control socket | `<data>/serve.sock`, mode 0600 | `apassy serve --stop` |

The front follows Tailscale: when the addresses change, it moves within 10 s. The node origin is the Tailscale IPv4 address of the first start; when it changes (the machine left and joined the tailnet again), `apassy doctor` says so and every device must pair again.

## Files

The data directory has mode 0700.

| File | What |
| --- | --- |
| `settings.json` | The port, the route, the push gateway, the last origin |
| `master.key` | The master key, 64 hex characters, mode 0600. With a systemd credential `apassy-node-key` (unit L2), the node takes that instead |
| `front/cert.der`, `front/key.sealed` | The node certificate (P-256, self-signed, 10 years) and its key, sealed under the master key |
| `relay/` | The relay's directory: `relay.db`, the team files, the backups |
| `state.json` | The running node's origin, pin, and addresses; removed when it stops |

Back up the whole directory, `master.key` with it: without the key the node cannot open its teams. A new certificate changes the pin, and every device pairs again.

## Stop and signals

`systemctl --user stop apassy-node.service` runs `apassy serve --stop` (`ExecStop=`): the node stops its TLS front first, then the relay (every session and run key ends), then removes `state.json` and `serve.sock`. The node installs no signal handler (the relay crate forbids `unsafe` code, and no safe API installs one): a bare `SIGTERM` or `Ctrl-C` ends the process at once; the kernel closes every listener and SQLite keeps the files consistent.

## `status --json`

```json
{
  "version": "0.5.17",
  "data_dir": "/home/me/.local/share/apassy/node",
  "running": true,
  "pid": 4242,
  "started_at": 1793709296,
  "service": {"unit": "apassy-node.service", "installed": true, "enabled": "enabled", "active": "active"},
  "routes": {
    "tailnet": {
      "origin": "https://100.64.0.7:8444",
      "port": 8444,
      "route": "direct",
      "bound": ["100.64.0.7:8444", "[fd7a:115c:a1e0::7]:8444"],
      "alternatives": ["build-box.tail0123.ts.net", "[fd7a:115c:a1e0::7]"]
    },
    "funnel": "n/a",
    "lan": "off"
  },
  "pin": "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE",
  "teams": [
    {"id": "t_7k2m5q4x3c", "name": "Mac mini", "state": "active", "members": 1, "open_questions": 0, "last_activity": 1793709000}
  ],
  "push_gateway": "https://push.apassy.wyderka.cc",
  "key": {"source": "file", "path": "/home/me/.local/share/apassy/node/master.key"}
}
```

- `running` is true when a `serve` answers on the control socket; the exit code is then 0, else 3. A stopped node has `pid`, `started_at` null, `bound` empty, `teams` empty, and `origin` of its last start.
- `service.enabled` and `service.active` are the words of `systemctl --user is-enabled` and `is-active`, or null without systemd.
- `pin` is null before the first start.
- `teams` come from the running relay's operator socket (counts and the last activity only). When they cannot be read, `teams_error` says why. The devices of a team with their last contact are not in `status` yet: the operator socket shows no device by design, and a read-only device list for the node is a follow-up.
- `key.source` is `credential`, `file`, or `none` (no key yet).

## `doctor --json`

```json
{
  "ok": true,
  "checks": [
    {"id": "tailscale_installed", "status": "pass", "detail": "Tailscale is installed."},
    {"id": "linger", "status": "warn", "detail": "Linger is off: the node runs only while you are logged in.", "hint": "sudo loginctl enable-linger $USER"}
  ]
}
```

Each check has `id`, `status` (`pass`, `warn`, `fail`, `skip`), `detail`, and, when there is a next step, `hint`. `ok` is false when a check fails; the exit code is then 1. The checks, in order:

| Id | Checks |
| --- | --- |
| `tailscale_installed` | A Tailscale command line at a known path |
| `tailscale_running` | `BackendState` is `Running` (else: `sudo tailscale up`) |
| `tailscale_address` | The Tailscale IPv4 is on an interface (else: `--route serve-tcp`) |
| `origin` | The origin of now equals the origin of the last start (else: pair again) |
| `port` | The port is the running node's, or free; when taken, `ss` names the program |
| `data_dir` | The data directory has mode 0700 |
| `key` | The key is a systemd credential, or a 0600 file |
| `service` | `apassy-node.service` is installed, enabled, and active |
| `linger` | `loginctl` says linger is on |
| `clock` | The clock is within 60 s of the push gateway's `Date` (a fail from 240 s: the gateway refuses pushes 5 minutes off) |
| `old_host_service` | No `apassy-team-host*.service` still runs the `apassy-team` binary (else: `apassy team host install`, which writes the same service for `apassy team host`) |

## `pair --json`

```json
{"link": "https://100.64.0.7:8444/pair#apassy_tcd_…&pin=…&alt=build-box.tail0123.ts.net&name=build-box", "expires_at": 1793709896, "pin": "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE", "origin": "https://100.64.0.7:8444"}
```

The link is a node pairing link of [node-pairing-v1](../contracts/node-pairing-v1.md) section 6: the one-use team code of kind `node`, the pin, the alternatives (the MagicDNS name, the Tailscale IPv6), and the machine name. It holds a secret: share it only with your own Mac.

## `apassy team` and `apassy-team`

`apassy team <words>` is `apassy-team <words>`: the same commands, settings in `~/.config/apassy-team` for one more release, keys in `keys.json`. `apassy team host install` writes the host service with `apassy team` in its command. The `apassy-team` binary stays one release as an alias: on a terminal it prints one line to stderr that the name goes away (set `APASSY_TEAM_DEPRECATION=1` to see it elsewhere); scripts and MCP clients see no change.

## What the node holds

- The relay's team files: what relay sync, the questions, the feed, and the access requests of your devices hold on any relay (end-to-end encrypted where the contracts say so), and for `apassy team` hosts what `apassy-team` teams hold today.
- The master key in `master.key`: who can read the data directory as your user can be the node. The systemd credential of unit L2 keeps the key encrypted at rest.
- No vault, no owner passphrase, no item value: item keys of a team host stay in `keys.json` of `apassy team host`.

## Not yet

- The encrypted systemd credential (`LoadCredentialEncrypted=`, unit L2), the `.tar.gz` and `.deb` packages and `install.sh` (unit L3), the Mac's relay sheet for "Your own node" (unit L4).
- `apassy team` against this node's own tailnet origin: the team command line trusts public certificates only; a pinned client for it is a follow-up.
- The device list with last contact in `status`.
