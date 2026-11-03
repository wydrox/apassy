# The node on Linux

Date: 2026-11-03. Plan: [implementation plan S2–S3](../design/implementation-plan-s2-s3.md), decision D8, units L1 (the commands), L2 (the service and the key), and L3 (the packages). Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) stage 3. Contract: [node-pairing-v1](../contracts/node-pairing-v1.md).

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
| `apassy uninstall [--json]` | Stops and removes `apassy-node.service`; the node's files stay |

Every command takes `--data-dir DIR`. The default is `$XDG_DATA_HOME/apassy/node`, or `~/.local/share/apassy/node`. On a Mac the default is refused: the Mac's own node runs inside the app.

Exit codes: 0 success; 1 a check failed (`doctor`) or the node did not start; 2 usage; 3 the node is not running (`status`, `pair`); 4 the node or the network failed.

## Install

| Download (from `<relay>/dl/`, with `SHA256SUMS`) | For |
| --- | --- |
| `apassy-<version>-linux-x86_64.tar.gz`, `apassy-<version>-linux-aarch64.tar.gz` | Any Linux with glibc 2.31 or later (Debian 11, Ubuntu 20.04, and later) |
| `apassy_<version>_amd64.deb`, `apassy_<version>_arm64.deb` | Debian and Ubuntu: `sudo apt install ./apassy_<version>_<arch>.deb` |

- `curl -fsSL https://apassy-relay.wyderka.cc/install.sh | sh` checks the SHA-256 of the tarball for this machine against `SHA256SUMS` and installs `apassy` and `apassy-team` into `~/.local/bin` (`APASSY_INSTALL_DIR` changes it). It never runs as root unless `APASSY_INSTALL_AS_ROOT=1`.
- The tarball holds `apassy`, `apassy-team` (a shell shim that runs `apassy team` from the same directory), `apassy-node.service` (the unit template), `LICENSE`, `NOTICE`, `README.md`, and `licenses/`.
- The `.deb` installs `/usr/bin/apassy`, `/usr/bin/apassy-team`, `/usr/lib/systemd/user/apassy-node.service`, and `/usr/share/doc/apassy/`. It starts nothing: each user who runs a node runs `apassy up`.
- Check a download: `sha256sum -c --ignore-missing SHA256SUMS`, and its build attestation: `gh attestation verify <file> --repo wydrox/apassy --signer-workflow wydrox/apassy/.github/workflows/relay-image.yml` ([release](release.md), "Attestations and SBOMs").

## Set up

1. Install Tailscale and sign in: `curl -fsSL https://tailscale.com/install.sh | sh`, then `sudo tailscale up`.
2. Run `apassy up`. It refuses with the next step when Tailscale is missing, not connected, or has no address on an interface of this machine.
3. To start the node at boot without a login, turn on linger once: `sudo loginctl enable-linger $USER`. `apassy up` and `apassy doctor` say when it is off.
4. In Apassy on the Mac, open Settings > Vault > Sync, pick "Apassy relay" for the vault, choose "Your own node", and paste the link that `apassy up` printed ([sync](sync.md) section 17.6). Run `apassy pair` for a new link: each link works once, for at most 10 minutes.

Options of `apassy up`:

| Option | Meaning |
| --- | --- |
| `--port N` | The port of the node on the tailnet (default 8444; never 443, 8443, or 10000). A change after the first pairing changes the node origin: every device pairs again |
| `--route direct` | The default: the TLS front binds the Tailscale addresses of this machine |
| `--route serve-tcp` | For Tailscale with userspace networking (no `tailscale0` interface): the front binds `127.0.0.1:<port>`, and Tailscale Serve in TCP mode forwards the tailnet port to it. Serve does not end TLS, so the pin holds end to end. It needs `sudo tailscale set --operator=$USER` once |
| `--push-gateway URL` | Another push gateway (default `https://push.apassy.wyderka.cc`) |
| `--no-push` | No push notifications |
| `--no-service` | Only the files and the settings; start `apassy serve` yourself |
| `--no-encrypt` | Keep the key in the 0600 file; do not make an encrypted systemd credential |
| `--no-pair` | No pairing link at the end |
| `--print-unit` | Print the unit that `up` would write, and change nothing (no Tailscale check) |

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
| `master.key` | The master key, 64 hex characters, mode 0600, where systemd cannot encrypt it for a user service (see "Service and key") |
| `master.key.cred` | The same key as an encrypted systemd credential, mode 0600; then `master.key` is gone |
| `front/cert.der`, `front/key.sealed` | The node certificate (P-256, self-signed, 10 years) and its key, sealed under the master key |
| `relay/` | The relay's directory: `relay.db`, the team files, the backups |
| `state.json` | The running node's origin, pin, and addresses; removed when it stops |

Back up the whole directory, the key with it: without the key the node cannot open its teams. A new certificate changes the pin, and every device pairs again. An encrypted credential opens only on this machine (see "Service and key"): keep a plain copy of the key in your password manager or on offline media.

## Service and key

`apassy up` writes `~/.config/systemd/user/apassy-node.service` (under `$XDG_CONFIG_HOME` when it is set), then runs `systemctl --user daemon-reload`, `enable --now`, and `restart`:

```ini
[Unit]
Description=Apassy node
Documentation=https://github.com/wydrox/apassy/blob/main/docs/operations/linux-node.md

[Service]
Type=simple
ExecStart=/usr/bin/apassy serve
ExecStop=/usr/bin/apassy serve --stop
LoadCredentialEncrypted=apassy-node-key:/home/me/.local/share/apassy/node/master.key.cred
Restart=on-failure
RestartSec=10
TimeoutStopSec=20
UMask=0077
NoNewPrivileges=yes

[Install]
WantedBy=default.target
```

`ExecStart` and `ExecStop` name the program that ran `up`, with `--data-dir` when you gave one. The `LoadCredentialEncrypted=` line is there only with an encrypted key. `apassy up --print-unit` prints the unit without changing anything. The `.deb` also installs this unit without the credential line as `/usr/lib/systemd/user/apassy-node.service` (from `packaging/linux/apassy-node.service`); the unit of `apassy up` has the same name and takes precedence.

**The key.** Where the key comes from, in order:

1. `$CREDENTIALS_DIRECTORY/apassy-node-key`: systemd decrypts `master.key.cred` for the service only, at each start (`key.source` is `credential`).
2. `master.key.cred` outside the service (`apassy serve` by hand): the node opens it with `systemd-creds --user decrypt` (`encrypted`).
3. `master.key`, mode 0600 (`file`).

`apassy up` encrypts the key with `systemd-creds --user --name=apassy-node-key encrypt` when systemd can give a credential to a user service: systemd 256 or later (Debian 13, Ubuntu 24.10, Fedora 41, and later). systemd chooses the key of the credential: the machine's TPM2 together with its host key when it has a TPM2, else the host key alone. `up` checks that the credential gives the same key back, and only then removes `master.key`. On older systemd (Debian 12: 252; Ubuntu 24.04: 255), without `systemd-creds`, or with `--no-encrypt`, the key stays in the 0600 file and `up` says why in one line. Neither way protects the key from your own user account: anything that runs as you can ask systemd to decrypt it. The credential keeps the plain key off the disk and off backups of the directory.

An encrypted credential opens only on this machine, with this TPM2 and host key: a new installation, a cleared TPM2, or a copy of the directory to another machine cannot open it. To keep a copy of the key, run `systemd-creds --user --name=apassy-node-key decrypt ~/.local/share/apassy/node/master.key.cred -` and store the 64 characters in your password manager. To go back to the file: stop the service, write that output to `master.key` with mode 0600, remove `master.key.cred`, and run `apassy up --no-encrypt`.

When the service cannot decrypt the credential, it does not start (`systemctl --user status apassy-node.service` shows `status=243/CREDENTIALS`); `apassy doctor` shows the key source.

**Linger.** A user service runs only while you are logged in, unless linger is on. Linger needs root, so `apassy up` never turns it on: it prints `sudo loginctl enable-linger <user>` when linger is off, and `apassy doctor` checks it (`linger`). Run that command once; after a reboot, the node starts without a login.

**Remove the service.** `apassy uninstall` runs `systemctl --user disable --now apassy-node.service` (its `ExecStop` stops the node), removes the unit file, and reloads systemd. The node's directory stays: the key and the teams of your devices. Remove it yourself only when no device uses this node. Removing the `.deb` (`sudo apt remove apassy`) does not touch your user unit or your files: run `apassy uninstall` first.

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
- `key.source` is `credential` (the service got it from systemd), `encrypted` (the encrypted `master.key.cred`, read outside the service), `file` (the 0600 `master.key`), or `none` (no key yet).

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
| `key` | The key is a systemd credential, an encrypted credential (a warning when a plain `master.key` is left beside it), or a 0600 file |
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

- The encrypted systemd credential (`LoadCredentialEncrypted=`, unit L2), the `.tar.gz` and `.deb` packages and `install.sh` (unit L3).
- `apassy team` against this node's own tailnet origin: the team command line trusts public certificates only; a pinned client for it is a follow-up.
- The device list with last contact in `status`.
