# Running apassy-relay

> Since ADR 0037 the relay is the crate `crates/apassy-relay` of `wydrox/apassy`. The production
> deployment files (`deploy/vps/`) and the health monitor stay in the archived private
> repository `wydrox/apassy-relay`, with the server addresses; references to them below
> point there. Images and the downloadable CLIs build from this workspace with
> `.github/workflows/relay-image.yml` (tag `image-*`).

## Current release runbook: GitHub artifacts only

This is the only current release procedure. Sections 19–21 describe feature and
schema history; they do not authorize a deployment. Release approval is separate
from merging a PR. Keep one public version across all six Apassy surfaces. Do not
bump schemas or dependencies to match a product version. No build or test container
runs on the production VPS, and no local Docker/Colima/Lima VM runs on the Mac.

1. Prepare the coordinated release version in the app and relay repositories.
   Review the exact relay commit and require all CI checks, including dependency
   advisories. Only after owner approval, push `image-*` on that exact commit.
   `.github/workflows/image.yml` builds on GitHub; it never deploys. Download
   `relay-image`, `apassy-team-linux-x86_64`, `apassy-team-darwin-arm64`,
   `apassy-node-linux-x86_64`, `apassy-node-linux-aarch64`, and `apassy-node-sha256sums`
   from the **same successful image run** (its `linux-node-verify` jobs green too),
   recording its URL and full source SHA.
2. Verify `relay-image.tar.gz.sha256`, `relay-image.id`,
   `relay-image.inspect.json`, and `relay-image.release.json`. The metadata version
   must equal Cargo/Worker versions; the full commit must equal the approved SHA.
   Architecture must be `amd64`, and OCI version/revision labels, recorded image ID,
   version tag `apassy-relay:release-<version>`, and immutable tag
   `apassy-relay:sha-<full SHA>` must agree. Archive these artifacts and the previous
   image/compose configuration for rollback. Tags alone are not identity proof.
   CI's `relay-image.id` records the image **config digest**. Docker's containerd
   image store can instead report a **manifest digest** as the loaded image ID.
   In that case, require the archive's `index.json` descriptor to match the loaded
   ID, hash the referenced manifest blob to verify that digest, then require its
   `config.digest` and the hashed config blob to match CI's recorded ID. Check the
   config's architecture and OCI version/revision labels against the approved
   release, and verify the archive checksum above. Record both digests and commands;
   a digest-type difference alone is not a failed identity check. With a config-ID
   store, the loaded ID must match CI's config digest directly. Stop on any mismatch.
3. Verify both CLI artifacts against their platform checksum files and
   `release-linux.json` / `release-darwin.json`. Both metadata files must name the
   approved version and full commit. CI runs each binary's `--version`, verifies
   Darwin arm64, and builds Linux on pinned Bullseye with GLIBC requirements no
   higher than 2.31. Never extract the portable CLI from the relay image. Verify the
   four Linux node packages against `SHA256SUMS-node` and `release-linux-x86_64.json` /
   `release-linux-aarch64.json` (version, full commit, glibc at most 2.31).
   Stage verified files and combined metadata as shown below. In `deploy/worker`,
   run `npm ci --no-audit --no-fund`, `npm test`, `npm run typecheck`, and
   `npm run preflight`. The Wrangler build hook repeats the preflight even for a
   direct `npx wrangler deploy`; do not bypass it with `--no-bundle` or an alternate
   config. A fresh checkout with missing downloads must fail. The preflight also refuses a
   `RELAY_MODE` in `wrangler.jsonc` that is not the mode the relay reports on `GET /healthz`
   (`x-apassy-relay-mode`, section 29; `scripts/check-relay-mode.mjs`).
4. With the owner's explicit deployment approval, verify account/bindings/secrets
   and deploy the Worker with `npm run deploy`. Preserve routing, limits and secrets.
   Read back its deployment ID, both public download hashes, `SHA256SUMS`,
   `release.json`, installer and guide with the public gate below. Run the same
   gate before deploy as a connectivity check against the currently verified
   release files (not the candidate files). A Worker deploy alone does not update relay.
   Stop before the relay restart unless all six candidate responses are HTTP 200
   with the exact verified bytes; exhausted retries, challenges and redirects fail.
5. On the approved target, record the running image ID and service settings and
   check free disk. Transfer and load the verified candidate GitHub image archive
   without restarting. Run `apassy-relay admin backup` on the current relay and
   complete the isolated restore drill in `deploy/vps/backup/`, selecting that
   candidate with `APASSY_RELAY_RESTORE_IMAGE=apassy-relay:sha-<full SHA>`.
   The default is the running image; an older running image does not implement the
   new validation command. The updated drill runs `snapshot-check` before
   startup: current and previous snapshot heads of every team, including suspended teams, must have
   its file, size and digest. Keep the master-key backup separately. A failed
   backup or restore check stops the rollout. Hidden `.partial` folders are failed
   attempts, never recovery points; inspect and remove them only after diagnosing.
6. Confirm the loaded image identity/OCI labels using the digest chain in step 2,
   select its immutable tag in the approved compose
   configuration, then restart with the existing service/data settings. Read back
   `/healthz` HTTP 200, `ok\n`, `x-apassy-relay-version`, and
   `x-apassy-relay-commit`. Check authenticated team/approval/sync paths and the
   backup timer. Public liveness alone is not acceptance for those paths.
7. Rollback: stop the relay and select the archived previous image and compose
   settings. From the release with team schema 8 and directory 1005 (section 25) back
   to an image of schema 7 and directory 1004, run `apassy-relay downgrade-schema-7`
   (section 25.2), then `apassy-relay downgrade-directory-1004` (section 25.3), with
   the relay stopped. From the release with directory 1004 (section 24) back to an image of
   directory 1003, run `apassy-relay downgrade-directory-1003` with the relay stopped
   (section 24.3), after any team downgrade below. From the release with team
   schema 7 (section 23) back to a schema-6 image, first run
   `apassy-relay downgrade-schema-6` with the relay stopped (section 23.3); between
   two images of the same schemas no DB downgrade is needed. Restart discards sessions and ends pending runs with
   `run_interrupted`; users explicitly request a new run. Restore the entire
   verified backup only for data recovery, while stopped, reconciling all access
   changes since it was taken (restoring can revive revoked identities). Revalidate
   snapshots before reopening. An older image reintroduces the audited defects.
   From `APASSY_RELAY_MODE=connect` (section 29) no downgrade command applies: the way
   back is the stopped backup of the cutover and the image before it (section 29.6).
   Worker rollback must retain both downloads from its matching verified artifacts.
8. Verify the other application publication surfaces separately. Record pending
   store reviews and old public versions explicitly; the relay does not publish them.

Stage both CLI artifacts and the four node packages from an extracted, verified CI run
(example paths; `node` holds the files of both `apassy-node-linux-*` artifacts):

```sh
python3 - /tmp/relay-release/linux /tmp/relay-release/darwin /tmp/relay-release/node <<'PY_STAGE'
import hashlib, json, pathlib, re, shutil, subprocess, sys
root = pathlib.Path.cwd()
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
version = re.search(r'^version = "([^"]+)"', (root/'Cargo.toml').read_text(), re.M)[1]
out = root/'deploy/worker/public/dl'
out.mkdir(parents=True, exist_ok=True)
artifacts = {}
for folder, platform, meta in [(sys.argv[1], 'linux-x86_64', 'release-linux.json'),
                                (sys.argv[2], 'darwin-arm64', 'release-darwin.json')]:
    folder = pathlib.Path(folder)
    data = json.loads((folder/meta).read_text())
    name = 'apassy-team-' + platform
    blob = (folder/name).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    assert data['version'] == version and data['commit'] == commit
    assert data['filename'] == name and data['sha256'] == digest
    shutil.copyfile(folder/name, out/name)
    artifacts[platform] = dict(filename=name, sha256=digest, size=len(blob))
node = {}
folder = pathlib.Path(sys.argv[3])
for arch in ['x86_64', 'aarch64']:
    data = json.loads((folder/f'release-linux-{arch}.json').read_text())
    assert data['version'] == version and data['commit'] == commit
    for entry in data['files']:
        blob = (folder/entry['filename']).read_bytes()
        digest = hashlib.sha256(blob).hexdigest()
        assert entry['sha256'] == digest and entry['size'] == len(blob)
        shutil.copyfile(folder/entry['filename'], out/entry['filename'])
        node[entry['filename']] = dict(sha256=digest, size=len(blob))
assert len(node) == 4
(out/'release.json').write_text(json.dumps(dict(version=version, commit=commit, artifacts=artifacts, node=node), indent=2)+'\n')
lines = [f"{a['sha256']}  {a['filename']}" for a in artifacts.values()]
lines += [f"{n['sha256']}  {name}" for name, n in sorted(node.items())]
(out/'SHA256SUMS').write_text(''.join(line + '\n' for line in lines))
PY_STAGE
(cd deploy/worker && npm run preflight)
```

Public delivery gate, from the repository root after staging and the approved
Worker deployment (replace values with the approved artifact version/source and
use a new evidence directory):

```sh
python3 deploy/worker/scripts/check-public-assets.py \
  --version 0.5.8 \
  --commit 9dd5172897268862e9806893bcf2b5fe8e463b92 \
  --evidence-dir /tmp/relay-public-0.5.8-attempt-3
```

This sends full GETs with `User-Agent: apassy-release-check/<version>`, without
credentials, Range or an edge secret. Four attempts per file use 2, 4, 8 second
backoff for network errors, 403/404/429/5xx and stale HTTP-200 bytes. It prints
response headers and `cf-mitigated` (including its absence), retains a JSON record
per request and up to 4 KiB of each failed body, and compares both binaries,
`SHA256SUMS`, `release.json`, installer and guide byte-for-byte. Archive the output
and evidence directory with the release receipt. `--base-url http://127.0.0.1:8787`
uses the same gate with `npx wrangler dev --local`; no production bindings are needed.

For an existing artifact retry, keep the release checkout at its approved source
SHA so staging and the deploy preflight still match those artifacts. If these
operations changes were merged later, extract the checker from that reviewed
operations commit to a temporary file with `git show <operations-merge-SHA>:deploy/worker/scripts/check-public-assets.py`.
Run that file with `--public-dir "$PWD/deploy/worker/public"` and the same explicit
version/source arguments above. Documentation or checker commits do not change
the provenance of already built artifacts. Delete the temporary checker afterwards.

Diagnose a failed gate before continuing: `cf-mitigated: challenge` plus HTML
identifies a Cloudflare Challenge Page; its absence does not rule out a block.
A 403 body `error code: 1010` indicates browser-signature filtering, including
Browser Integrity Check. A 429/`Retry-After` or 1015 suggests a rate limit. Retain
UTC time and `CF-Ray` for correlation in Cloudflare Security Events; an event's
service/rule/action distinguishes WAF, bot and rate-limit decisions (some
Cloudflare-managed-zone blocks are absent from your zone's events). Record
`CF-Cache-Status`, `Age`, status and body hashes across retries to investigate stale
delivery; a later pass alone does not establish why the earlier request failed.
Do not change Cloudflare settings or substitute challenge HTML for a download.
See [the 0.5.8 investigation](WORKER-DOWNLOAD-403.md) for the user-agent failure.

For the 2026-10-31 audit patch, version remains **0.5.7**; the owner coordinates the
later release bump. Preparation and CI do not grant deployment authorization.

## 1. What runs where

The relay runs in a Linux container behind Cloudflare Worker, Workers VPC and a
named tunnel (section 16). TLS terminates at Cloudflare; the origin accepts plain
HTTP with the edge secret. The owner runs `apassy-team host` separately.

The relay refuses requests without the edge secret except `/healthz`. Item values
remain sealed at rest; the owner keeps item keys outside relay backups. The Worker
applies route/size limits before forwarding. The origin also enforces transport
deadlines; see [the parser mitigation](HTTP-SECURITY.md).

## 2. Secrets

The relay needs two secrets: the master key and the edge secret. Make them with `openssl rand -hex 32`, into files that only you can read:

```sh
mkdir -p ~/.apassy-relay && chmod 700 ~/.apassy-relay
openssl rand -hex 32 > ~/.apassy-relay/master_key
openssl rand -hex 32 > ~/.apassy-relay/edge_secret
chmod 600 ~/.apassy-relay/master_key ~/.apassy-relay/edge_secret
```

The examples below use `master_key` as the file name.

- Never put a secret in a shell history, a repo, or an image.
- The master key opens `relay.db`, which holds the random key of each team file (section 17). If you lose it, every team is lost. Back it up somewhere apart from the vault backup.
- The edge secret must be the same text in the relay and in the Worker.
- Every secret the CLI needs (a member token, an invite code, an item value) is read from stdin. The CLI refuses to read it from a terminal.
- The vault holds only sealed item values, so the master key protects less than before: a stolen vault or backup gives only ciphertext. The item keys are in `keys.json` on each owner's machine (section 9). Back that file up apart from the vault.

## 3. Obtain the image

Use the GitHub artifacts and verification steps in the current release runbook.
The image holds `apassy-relay` and `apassy-team`, runs as UID 10001, and stores data
in `/data`. The initial setup examples below assume an already verified image;
their `alpha` names are placeholders, not a separate build procedure.

## 4. Create the relay and the first team

Run this once. It creates the directory `relay.db`, the first team, and its owner. It prints the owner token once. Copy the token into `~/.apassy-relay/owner_token.txt` at once (mode 0600). The file must hold only the token. More teams come later from team codes (section 17). Without `--team` and `--owner`, `init` makes a relay with no team.

```sh
docker run --rm -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/master_key \
  -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret \
  -e APASSY_RELAY_PUBLIC_URL=https://apassy-relay.wyderka.cc \
  apassy-relay:alpha init --team <name> --owner <name>
```

`APASSY_RELAY_PUBLIC_URL` is the URL that agents use. The relay puts it in the base URLs of a session. If it is wrong, agents get wrong base URLs.

If the volume already holds a relay, or a `team.db` from before teams, `init` refuses.

## 5. Start

The same command, with `-d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080` and `serve`:

```sh
docker run -d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080 \
  -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/master_key \
  -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret \
  -e APASSY_RELAY_PUBLIC_URL=https://apassy-relay.wyderka.cc \
  apassy-relay:alpha serve
```

The port is bound to the loopback address only. Only the tunnel reaches it.

Optional variables:

| Variable | Meaning | Default |
| --- | --- | --- |
| `APASSY_RELAY_SESSION_TTL` | session lifetime, 60 to 3600 s | 900 |
| `APASSY_RELAY_APPROVAL_TIMEOUT` | wait for the owner's host to decide a run, 30 to 86400 s | 600 |

A restart ends every session and atomically ends pending runs with `run_interrupted`. Their one-time keys are discarded; the retry note asks the user to request a new run. Commands are never rerun automatically.

A vault from the first alpha (it held plaintext values) is refused at start. There is no migration: start with a new data volume and add the items again.

## 6. Tunnel

Start a quick tunnel to the container:

```sh
cloudflared tunnel --url http://127.0.0.1:8080
```

Copy the `https://<random>.trycloudflare.com` URL from its output into the Worker var `RELAY_ORIGIN`.

- The URL changes at each cloudflared restart. Then the Worker needs the new URL and a deploy.
- Errors 1016 and 530 from Cloudflare mean that the tunnel is down or that the URL in the Worker is old.
- A quick tunnel has no SLA. It does not carry server-sent events.
- Keep cloudflared running. A launchd job or a `tmux` session works for the alpha.

## 7. Worker

The Worker lives in `deploy/worker/`. It has three settings:

- The var `RELAY_ORIGIN`, in `wrangler.jsonc`: the tunnel URL.
- The secret `EDGE_SECRET`: the same text as the edge secret file. Set it with `wrangler secret put EDGE_SECRET`.
- The custom domain `apassy-relay.wyderka.cc`, in `wrangler.jsonc`. The zone must be in the same Cloudflare account.

A fourth setting, the Workers VPC binding `RELAY`, replaces `RELAY_ORIGIN` when it is set (section 16).

Without the edge secret, or without both `RELAY` and `RELAY_ORIGIN`, the Worker answers 503 "relay not configured". If the relay is not reachable, it answers 502.

The Worker makes the target URL by string concatenation: origin, path, query. It does not use `new URL(path, origin)`, so a path like `//evil.example/x` cannot send the edge secret to another host. It deletes any `X-Apassy-Edge` from the client and sets its own. It does not log URLs, because paths hold session keys.

Who deploys: the owner of the Cloudflare account. The repository holds the code only. Deploy with `npm run deploy` from `deploy/worker/` only through the current release runbook and asset preflight. Test the Worker before that with:

```sh
node --test 'deploy/worker/test/*.test.ts'
```

This needs Node 22.18 or later. It needs no npm install.

## 8. Check

```sh
curl https://apassy-relay.wyderka.cc/healthz
```

The command prints `ok`. For a team from `apassy-relay init`, the owner can use the bootstrap token:

```sh
apassy-team init --relay https://apassy-relay.wyderka.cc < ~/.apassy-relay/owner_token.txt
apassy-team me
```

`init` checks the token with the relay. It saves legacy member-token settings, not a device key.
Legacy member tokens expire 14 days after team creation or migration to server schema version 3.
Enroll a device before this period ends. See section 9.

Settings version 2 keeps several teams in `settings.json`.
The path is `$XDG_CONFIG_HOME/apassy-team/settings.json` or `~/.config/apassy-team/settings.json`.
The directory has mode 0700. The file has mode 0600.
The file contains the current team and each team's relay URL, member name, and device ID.
The CLI reads old settings and writes version 2 at the next save.

```sh
apassy-team team list
apassy-team team use TEAM_ID
apassy-team --team TEAM_ID me
APASSY_TEAM=TEAM_ID apassy-team me
```

`--team ID` selects a team for a member command. Otherwise, `APASSY_TEAM` selects it, then the current team.
In `create --team NAME`, `--team` gives the new team's name.

The CLI stores each device private key separately.
On macOS, it uses the login Keychain: service `apassy-team`, account `<relay host> <team id>`.
On other systems, it uses `device-<team id>.key` next to `settings.json`, with mode 0600.
It never prints the private key or puts it in `settings.json`.
`APASSY_TEAM_KEY_STORE=file` selects the file store for tests only.
Tests must not use the real login Keychain.

Each member command signs in with its device key.
Its access token lasts 15 minutes and stays only in process memory.
A 401 causes one new sign-in and one retry. A second 401 fails.
If the relay's sign-in origin differs from the saved URL, the CLI stops.

For direct access to the container, set the edge secret and the local URL:

```sh
export APASSY_EDGE_SECRET="$(cat ~/.apassy-relay/edge_secret)"
apassy-team init --relay http://127.0.0.1:8080 < ~/.apassy-relay/owner_token.txt
```

The CLI accepts plain `http://` only for `127.0.0.1`, `::1`, and `localhost`.

| Variable | Meaning |
| --- | --- |
| `APASSY_RELAY_URL` | The relay origin. |
| `APASSY_TEAM` | The team ID for a member command. |
| `APASSY_TEAM_TOKEN` | A legacy member token, before its expiry. |
| `APASSY_TOKEN` | An agent token for `access`, `run`, and `mcp`. |
| `APASSY_EDGE_SECRET` | An optional secret for `X-Apassy-Edge`. |

## 9. Team setup walkthrough

For a new team, get a one-time team code from the operator.
Read the code from stdin:

```sh
apassy-team create --relay https://apassy-relay.wyderka.cc --team myteam \
  --name olga --device "Olga Mac" < team-code-file
```

`create` always makes an owner device. This device is the team's key holder.
The CLI saves the team as current. It does not save a new owner token.

For an existing team, use `device enroll` with its legacy member token.
`create`, `join`, `device link`, and `device enroll` refuse an existing key or settings entry for that team.
Thus, do not enroll in the directory where `init` saved the legacy settings.
Use an unused configuration directory and the token in the environment:

```sh
export XDG_CONFIG_HOME="$HOME/.config/apassy-device"
export APASSY_RELAY_URL=https://apassy-relay.wyderka.cc
export APASSY_TEAM_TOKEN="$(cat ~/.apassy-relay/owner_token.txt)"
apassy-team device enroll --name "Olga Mac"
unset APASSY_TEAM_TOKEN
apassy-team me
```

Enrollment removes the member token from the settings. The relay invalidates that member's old token.
The first device becomes the key holder only for the sole live owner when no key holder exists.
If the host already has item keys, copy `keys.json` into the new configuration directory before you start it.
Keep the new `XDG_CONFIG_HOME` for later commands and the host service.
On macOS, another configuration directory still uses the same Keychain account for that relay and team.
Use another machine for a second member of the same team on macOS.

The owner makes a collection, adds an item, and makes an invite link:

```sh
apassy-team collection create payments --mode bouncer
apassy-team item add --collection 1 --name "Stripe test" --env STRIPE_API_KEY \
  --environment staging --provider stripe < stripe-test-key-file
apassy-team invite --role member --hours 72 --name bob --grant 1 > invite-link-file
```

`item add` reads the value from stdin. It checks the value on this machine.
It seals the value and saves the item key in `keys.json` next to `settings.json`.
The directory has mode 0700. The file has mode 0600.
Only the sealed value goes to the relay.
Add items on the key-holder machine that runs `apassy-team host`.
A key on another machine cannot release an item from this host.

Back up `keys.json`. Item keys remain plain text in this file.
Without the keys, add the items again. Keep this backup separate from the relay's vault backup.

A known provider, such as `stripe`, supplies API hosts.
For another API, use `--host api.example.com` with the exact API host.
A host also covers its subdomains.
The relay refuses public suffixes and whole domains.
Use `--allow-broad-host` only if you own every subdomain. The audit records this choice.
Use `--environment production` for a production credential. The host asks for every run with it.

`invite` prints a link once: `<relay URL>/join#<code>`.
Use `--name NAME` to set the member name and repeat `--grant ID` for collection grants.
Use `--shared` only for role `member` on a shared device.
Only an owner can invite a manager or another owner.
Send the invite link through a private channel. The code works once.

The member reads the link or raw invite code from stdin:

```sh
apassy-team join --relay https://apassy-relay.wyderka.cc --device "Bob laptop" < invite-link-file
```

If the invite has no name, add `--name bob`.
The CLI saves the device key before it sends the request.
It prints two safety words and checks them against words it computes locally.
If the words differ, it stops. Tell the inviter the words through a trusted channel.

The inviter lists requests and confirms with the words from the member:

```sh
apassy-team joins
apassy-team confirm JOIN_ID --words "W1 W2"
```

Replace `W1 W2` with the member's words. `--words` is mandatory.
`joins` does not print safety words. Never confirm from a list or from the invite code alone.
Use `apassy-team refuse JOIN_ID` to refuse the request.

`join` waits up to 10 minutes. A pending join can remain open for 72 hours.
Use `--no-wait` to return immediately, then `apassy-team join --resume` to wait again.
The CLI uses the same saved key after an uncertain request result.
Do not remove the key or make another join request with a new key.

For a join or device link, settings can contain `safety_verified`.
It starts as `false` and becomes `true` only after the local safety-word check.
The nonsecret `recovery-<team id>.json` file saves the pending name, device name, request kind, and blocked state.
It contains no code, private key, or token.

If a network error or `busy` leaves the request result unknown, supply the original code or link on stdin.
For a join, use `apassy-team join --resume < original-code-file`.
For a device link, use `apassy-team device link --resume < original-code-file`.
The CLI repeats the request with the same saved key, checks the safety words, then waits.
After a successful `--no-wait`, resume needs no stdin.

A safety-word mismatch blocks resume.
Stop and tell the person who supplied the code.
Do not remove the saved key or change the recovery file.

Shared members cannot make device links.
To add another device for the same person, use the existing device:

```sh
apassy-team device add > device-link-code-file
```

On the new machine:

```sh
apassy-team device link --relay https://apassy-relay.wyderka.cc \
  --device "Second laptop" < device-link-code-file
```

On the existing device, get the words from the new device and confirm:

```sh
apassy-team device pending
apassy-team device confirm LINK_ID --words "W1 W2"
```

`device pending` does not print safety words. Device links expire after 10 minutes.
Use `--no-wait` with `device link`, then `apassy-team device link --resume` to wait again.
Use `device refuse LINK_ID` to refuse a link and `device revoke DEVICE_ID` to revoke a device.
A new device does not become the key holder automatically.

```sh
apassy-team device list
apassy-team device key-holder DEVICE_ID
```

Before you move the key-holder flag, copy `keys.json` to the new owner's device.
Protect the copy with mode 0600. The command moves the flag, not the item keys.
Only the current key-holder device can move the flag when one exists.

The member can make an agent token. The CLI prints it once:

```sh
apassy-team agent create ci --days 30 > agent-token-file
APASSY_TOKEN="$(cat agent-token-file)" apassy-team access
```

An owner can change a member role with `member role MEMBER_ID ROLE`.
Use `member`, `manager`, or `owner` for `ROLE`.
Move the key-holder flag before you change its member's owner role.
Use `leave` to leave a team. The last live owner cannot leave or lose the owner role.

Policy flags for `collection create` and `collection policy ID`:

| Flag | Meaning |
| --- | --- |
| `--mode ask\|bouncer` | `ask` suggests a question for every run. `bouncer` suggests release for a known safe command. The host checks each run. |
| `--allow-prefix P` | The command must start with a permitted prefix. Repeat for more prefixes. |
| `--forbid WORD` | The relay denies a command with this word. Repeat for more words. |
| `--max-runs-per-hour N` | At most N runs per hour. |
| `--instruction TEXT` | A note for the owner. |
| `--rule-expires-at UNIX` | The rule stops at this time. |

`collection policy` replaces the whole policy. Omitted flags return to their defaults.
Secrets enter input commands through stdin, never command arguments.
This includes team codes, invite codes, device-link codes, item values, and legacy tokens for `init`.
The CLI refuses a secret from a terminal. Agent tokens use `APASSY_TOKEN`.

## 10. Agents

The agent uses an agent token. Device access tokens stay in member processes.
There are three ways to run an agent.

The CLI requests a run, waits for the key-holder host, and starts the command with the session environment:

```sh
export APASSY_RELAY_URL=https://apassy-relay.wyderka.cc
export APASSY_TOKEN="$(cat agent-token-file)"
apassy-team run --items 1 --purpose "Check the balance" \
  --request "Show me the Stripe balance" -- stripe balance retrieve
```

The command does not inherit `APASSY_TOKEN`, `APASSY_TEAM_TOKEN`, or `APASSY_EDGE_SECRET`.
`run` returns the command's exit code, or 128 plus its signal number.
It returns 3 for a denied run or timeout, 4 for a relay or network error, and 2 for usage errors.
Use `--wait SECONDS` to limit the wait. The default is 900 seconds.

For remote MCP with Claude Code, put this configuration in `.mcp.json`:

```json
{"mcpServers": {"apassy": {"type": "http", "url": "https://apassy-relay.wyderka.cc/mcp",
  "headers": {"Authorization": "Bearer ${APASSY_TOKEN}"}}}}
```

For stdio MCP, use this configuration:

```json
{"mcpServers": {"apassy": {"command": "apassy-team", "args": ["mcp"]}}}
```

The adapter needs `APASSY_RELAY_URL` and `APASSY_TOKEN` in its environment.
With MCP, the agent starts its own command with `session.env`.
Thus, placeholders can enter its transcript. A placeholder needs the relay to work.
The CLI keeps the session environment outside the agent's transcript.

Cloud sessions need `apassy-relay.wyderka.cc` in their network allowlist and `APASSY_TOKEN` in their environment.
Use that exact token variable name for Claude Code MCP headers.

Each item supplies a placeholder variable and `APASSY_BASE_<NAME>`, a relay base URL.
Known providers also supply `STRIPE_API_BASE`, `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, or `GITHUB_API_URL`.
The command must send API requests to the relay base URL.
The relay inserts the real value only in a permitted authentication position.
It refuses placeholders in other positions.

The host signs in as the selected team's key-holder device. One host serves one team.
Other owner devices cannot release the item keys.
Terminal prompts, desktop dialogs, and the host service still work. See section 11 for service commands and logs.

## 11. Runs and the host

Each run that passes the hard rules waits for the host of the owner. A run cannot start without a release. The relay cannot approve a run because it does not hold the keys.

Use the key-holder device of the selected team on the machine that holds `keys.json`.
For a legacy team, enroll the device with the procedure in section 9.
Use `apassy-team team use TEAM_ID` to select the enrolled team.
Replace `TEAM_ID` with the team ID from the enrollment output.
After enrollment, make a new agent token:

```sh
apassy-team agent create NAME --days 30 > agent-token-file
```

Replace `NAME` with the name of the agent.
Use the new token for the agent.
Legacy `apassy_agt_` tokens without a team ID stop at the member-token deadline of the team.
Enrollment does not extend this deadline.

To start the host on a terminal, use:

```sh
apassy-team host
```

To use desktop dialogs in the foreground, use:

```sh
apassy-team host --dialog
```

After an update to `apassy-team`, macOS can show one Keychain prompt for access to the device key.
Before you start the background host, run `apassy-team me` in a terminal.
If macOS shows this Keychain prompt, select **Always Allow**.
The background host cannot run before you select **Always Allow**.

To use file storage on macOS, set `APASSY_TEAM_KEY_STORE=file` before you make or enroll the device.
The CLI saves the key in `device-<team id>.key` next to `settings.json`, with mode 0600.
Use this variable for all foreground commands with the device.
The CLI does not copy a key from the Keychain to the file store.

The foreground host can also use file storage.
For a host service with file storage, set `APASSY_TEAM_KEY_STORE=file` in the service environment before the host starts.
A shell setting does not set the service environment.

To install and start the host as a user service, use:

```sh
apassy-team host install
apassy-team host status
```

The service must use the same saved relay URL and selected team as the shell.
The service must also use the key-holder device key.
Installation stops with different shell settings. The service file contains no token.
A service cannot use `APASSY_EDGE_SECRET` from the shell. Use a relay endpoint that operates without this variable.

The service starts at login and uses desktop dialogs. On macOS, it uses a LaunchAgent. On Linux, it uses a systemd user service. Keep the desktop session open for approval dialogs.

After installation, the host starts at each login until you remove the service. `--ask-all` and `--auto-limit N` also apply to `host install`:

```sh
apassy-team host install --ask-all --auto-limit 0
```

On Linux, the user service needs the environment of the desktop session. If dialogs cannot open, import the applicable variables:

```sh
systemctl --user import-environment DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS
systemctl --user restart apassy-team-host.service
```

To stop and remove the user service, use:

```sh
apassy-team host uninstall
```

The host must be online for each run. Without the host, a run expires after `APASSY_RELAY_APPROVAL_TIMEOUT` seconds (600 by default). The agent sees `timed_out`.

The host checks one run at a time, oldest first. It uses the metadata in `keys.json` and its own command analysis:

Each item must exist in `keys.json` for this relay. Otherwise, the host denies the run with "Unknown item on this host."

Automatic release requires all conditions below:

- `--ask-all` is absent.
- The relay suggests release without flags.
- No item has the `production` environment in `keys.json`.
- The host analysis identifies a known safe command without flags.
- Each item stays below the automatic release limit (30 per hour by default). `--auto-limit N` changes this limit.

`git status`, `ls -la`, `cargo test`, and `stripe balance retrieve` with a staging item are known safe commands.

Other runs need a decision from the owner. The host shows the agent, member, command, purpose, user request, working directory, items, environments, and flags. It also shows the relay note and the reason for approval.

On the terminal, the host asks `Release the keys for run 7? [y/N]`. Only `y` or `yes` releases the keys. All other answers deny the run. Without a terminal, the terminal mode denies the run with "No one at the host."

In dialog mode, only an explicit click on `Release` releases the keys. `Deny` is the default button. Return, Escape, a closed dialog, or a dialog error denies the run. A dialog timeout expires the request without a release. If fewer than five seconds remain, the host records an expired request without a dialog. A dialog never stays open beyond the expiry time of the run.

The host holds `host.lock` next to `keys.json` while it runs. A second host for the same key store cannot start. This lock also prevents a foreground host and the user service from running together.

Each request adds one line to `host.log` next to `keys.json`. The line gives the time, run id, agent, member, item uids, item names, and decision. Decisions are `auto`, `approved`, `denied`, `unknown_item`, `expired`, or `error`. The log contains no key.

The service writes process output to `~/Library/Logs/apassy-team-host.log` on macOS. On Linux, it writes process output to `service.log` next to `host.log`. Use `host.log` to check decisions and the process log to check service errors.

`--ask-all` requires approval for each run. `--auto-limit 0` prevents automatic release. Neither option permits an automatic approval of an unknown command.

The owner or a manager can examine and deny waiting runs from another machine:

```sh
apassy-team pending
apassy-team deny 7 --reason "Not this key"
```

`apassy-team approve` cannot release keys. The relay answers `approve_on_host`. The CLI says "The keys are on the owner's host. Approve there with apassy-team host."

- A run without a decision expires. The agent sees `timed_out`.
- If a member revokes an agent, grant, member, or item, the relay denies its waiting run with `approval_invalidated`.
- A wrong run, changed text, or wrong item set causes `release_invalid`. Each run key works once.
- The owner decides on the host terminal or in its desktop dialog.
- The host can release a run of the agent of the owner.

## 12. Audit

```sh
apassy-team audit --limit 50
apassy-team audit --after 120 --json
```

The audit records team changes, runs, decisions, sessions, and proxy requests. It never holds a value, a placeholder, a token, or a session key. Only the owner and managers can read it. No endpoint changes or deletes a row.

## 13. Backup

`apassy-relay admin backup` copies `relay.db`, every team file, and the vault sync snapshots of each team (`teams/<id>.sync/`, the current and the previous version) while the relay runs. Each file is copied while its connection is locked, so the copy is whole. A snapshot is copied while no push of its team can commit. The copy goes to a new folder `<APASSY_RELAY_BACKUP_DIR>/<UTC time>` (default `/backups`; mode 0700, files 0600), with `MANIFEST.json`: the name, size, and SHA-256 of each file, and the number of teams.

```sh
docker compose exec -T relay apassy-relay admin backup
```

- The files stay encrypted. `relay.db` opens with the master key; each team file opens with its own key, which is in `relay.db`. Keep the master key apart from the backups: a backup with the master key opens every team's metadata (never an item value).
- A suspended team is copied too.
- On the VPS the folder is `/opt/apassy/backups/relay`. `deploy/vps/backup/` has a daily timer (03:30 UTC, 14 days kept, at least the 3 newest), a weekly restore test, and a pull to the owner's Mac (see its README).
- To restore: stop the relay; put `relay.db` and `teams/` of one backup into an empty data volume (owner 10001, mode 0700, files 0600); start with the same master key. A team deleted after the backup comes back with it.
- A restored relay can hold an older vault snapshot than the Macs saw. The Macs then refuse it ("The relay has an older copy than this Mac saw") and keep their vaults; the owner turns relay sync off and on again on one Mac, and that Mac pushes again.
- Snapshots are each vault's SQLCipher file: encrypted with the vault's passphrase, which is not on the relay. They add up to about 128 MiB per team to a backup.

Also back up `keys.json` on each owner's machine (`~/.config/apassy-team/keys.json`, or under `$XDG_CONFIG_HOME`). It is plain text in the alpha, so keep the copy private and apart from the relay backups. Losing it means adding the items again. With a relay backup alone nobody can read a value, and with `keys.json` alone nobody can open anything.

## 14. Revocation

```sh
apassy-team agent revoke 2      # an agent token
apassy-team revoke --grant 5    # a grant
apassy-team member revoke 3     # a member (owner only)
apassy-team item archive 4      # an item
```

A revocation works at the next request. The relay looks up each token every time. Revoking an agent, a grant, a member, or an item ends the live sessions that depend on it at once, and denies the runs that are pending on it (`approval_invalidated`) and drops their keys.

To rotate a credential, archive the item and add a new one (`item add` makes a new key). There is no edit in the alpha.

To rotate the edge secret, change the file, restart the container, and run `wrangler secret put EDGE_SECRET` with the new text. The master key cannot be rotated in the alpha.

## 15. Limits and what this does not protect

What this does not protect:

- The relay does not store a readable value, but it sees a value in memory while its session lives. Root on the Mac or the VM, or a taken-over relay while it runs, can read the values of the sessions of that time. A stolen vault or backup gives only ciphertext.
- A relay that is taken over can make up a run. The host releases a known-safe command with a non-production item by itself, and one release is enough to learn a value, so such a relay can get the values of those items. Read `host.log`. Start the host with `--ask-all` (or `--auto-limit 0`) if you want to be asked every time. Production items always ask.
- `keys.json` on the owner's Mac is plain text in the alpha. Whoever reads it holds the item keys. Back it up, and protect it like the vault key.
- The host must be online for every run. Only the owner's host holds keys: a manager can deny a run but cannot release one, and there is no sharing of keys to another machine yet.
- A session key and a placeholder together work as a credential for the hosts of that item, in auth positions only, until the session ends. They can end up in an agent transcript if the agent runs the command itself.
- The relay and the host approve a stated command. They cannot check what the agent really runs with the session. The relay controls which hosts get the value, where the value goes in a request, and for how long.
- Cloudflare sees all traffic in clear, including session keys in paths and placeholders in headers. It no longer sees a value when an item is added: the CLI seals it first.
- The quick tunnel has no SLA and a changing URL.

What the alpha does not do:

- Way A (the member's Mac app gets a value for one run), and the model sidecar. With no model, only known-safe commands are released by the host by itself. Every other command asks the owner at the host.
- `CONNECT` and a run certificate. Workers cannot do `CONNECT`, so the relay rewrites base URLs.
- Team rule packs, grants to one agent, item edit, access requests from agents.
- Approvals in an app, on the web, or in Slack. The owner decides at the terminal of the host.
- Keep-alive to upstream hosts, HTTP/2, WebSocket, `Upgrade`, server-sent events through the tunnel.
- Rewriting of redirects. A `Location` header passes through. A client that follows it goes to the real host with a placeholder and fails.
- Compressed upstream responses (a 502), request bodies over 8 MiB (a 413), AWS SigV4 and other signed requests.
- Items that are not HTTP API keys, such as a Postgres URL.
- The `gh` CLI. Only `GITHUB_API_URL` is set.
- Sessions that survive a restart.
- TLS in the relay, several teams per relay, a key typed at start.

The full list is in section 2 of [SPEC.md](SPEC.md). The threat notes are in sections 20 and 21.

## 16. On a VPS

The live relay runs on a Linux VPS since 2026-10-01: `ssh ottervibe`, Debian 12, x86_64. Nothing on the VPS is public. The Worker reaches the relay through a Workers VPC binding and a named tunnel. The tunnel URL never changes, so a restart needs no Worker deploy.

```
agent ──HTTPS──▶ Worker apassy-relay.wyderka.cc   adds X-Apassy-Edge
   ──Workers VPC binding RELAY──▶ VPC service apassy-relay ──▶ tunnel apassy-relay
   ──▶ container apassy-relay-tunnel (cloudflared, outbound only)
   ──HTTP──▶ container apassy-relay  relay:8080, volume apassy-relay-data
```

| What | Where |
| --- | --- |
| Compose project | `apassy` in `/opt/apassy`, a copy of `deploy/vps/compose.yaml` |
| Image | `apassy-relay:host-keys-<commit>`, built on the VPS from `git archive` of that commit |
| Data | the volume `apassy-relay-data`: `relay.db` and `teams/` (owner 10001, mode 0600 and 0700) |
| Relay secrets | `/opt/apassy/secrets/relay/master_key` and `edge_secret`, owner 10001, mode 0400. `vault_key` is the key of the old `team.db.pre-teams` only |
| Tunnel token | `/opt/apassy/secrets/tunnel/token`, owner 65532 (cloudflared), mode 0400 |
| Tunnel | `apassy-relay`, id `044bd7e2-2257-4927-925b-f1f8c0796700` |
| VPC service | `apassy-relay`, id `01a0f70c-70ec-7882-9121-853d63b9eece`: host `relay`, HTTP port 8080 |
| Owner's check port | `127.0.0.1:8787` on the VPS only |

- The VPC service names the relay by the host name `relay`. Cloudflared looks it up with the DNS of its own container, which is Docker's DNS. Keep both containers in the same Compose project.
- The Worker uses the binding `RELAY` when it is set, and `RELAY_ORIGIN` only when it is not.
- `/opt/apassy/secrets` is root's, mode 0711. The user `otter` cannot read the files in it. Change them with `sudo`.
- The VPS also runs other services (Pretix, mail). The relay has its own limits: 2 CPUs, 512 MiB, 512 processes.

Check it:

```sh
curl https://apassy-relay.wyderka.cc/healthz
ssh ottervibe 'cd /opt/apassy && docker compose ps && docker compose logs --tail 20'
apassy-team me
```

Deploy a reviewed commit through the current release runbook above. Load the
verified GitHub image archive and use its recorded immutable tag and image ID.
Never copy source to the VPS for a build.

A restart ends every session (section 5).

Back up the vault as in section 13: `docker compose exec -T relay apassy-relay admin backup` writes to `/opt/apassy/backups/relay` on the VPS. The timer of `deploy/vps/backup/` does it every day.

The operator commands of section 17 run in the container:

```sh
ssh ottervibe 'cd /opt/apassy && docker compose exec relay apassy-relay admin teams'
```

Changing the production topology requires a separately reviewed owner plan.
Do not start a local VM as a fallback.

## 17. Teams

One relay holds several teams (ADR 0019 of the core). Each team is its own file in `teams/`, with its own key, its own audit, and its own sessions. A token, an invite code, and a session key name their team (`apassy_mbr_t_7k2m5q4x3c_...`), and the relay looks a token up only in that team. People in one team cannot see another team, and the same person in two teams is two members.

The operator works on the server, with `apassy-relay admin` in the container. It talks to the running relay through `admin.sock` in the data directory. There is no operator page or endpoint.

**A new team.** The operator makes a one-time team code and gives it to the future owner, like a password:

```sh
docker compose exec relay apassy-relay admin team-code --hours 72 > team-code-file
```

The code is printed once. The future owner creates the team. It becomes the owner, and the settings are saved like `init` does:

```sh
apassy-team create --relay https://apassy-relay.wyderka.cc --team "Family" --name rafal < team-code-file
apassy-team me          # team Family (t_...): member rafal (id 1, owner)
```

A code works once. A typo in a name does not use it. The owner then invites members (section 9) and runs `apassy-team host` for the team's items (section 11). A host serves the team of its owner token.

**The teams.** `admin teams` shows the id, name, state, and effective limits of each team. For an active team, it also shows the member, item, and agent counts, the time of the last audit row, the vault sync version and the size of its snapshot (`sync_version`, `sync_size`; 0 without a snapshot), and the counts of open questions and push tokens (`open_questions`, `push_tokens`). It shows no names of people or items, no runs, and no audit.

**Team limits.** Each team starts with these limits:

| Field | Default |
| --- | --- |
| `members` | 50 |
| `items` | 500 |
| `agents` | 100 |
| `runs_per_hour` | 1000 |
| `pending_runs` | 50 |
| `agent_requests` | 56 |
| `sync_bytes` | 67108864 (64 MiB) |
| `sync_pushes_per_hour` | 600 |
| `sync_transfers` | 2 |
| `open_questions` | 20 |
| `questions_per_hour` | 300 |
| `member_open_questions` | 15 |
| `member_questions_per_hour` | 225 |
| `device_open_questions` | 10 |
| `device_questions_per_hour` | 150 |
| `question_bytes` | 8388608 (8 MiB) |
| `feed_bytes` | 4194304 (4 MiB; 1 MiB in a Connect team, section 21) |
| `feed_actions_per_hour` | 60 |

Read all effective values:

```sh
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c
```

Change only the necessary fields:

```sh
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --members 25 --items 200
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --agents 40 --runs-per-hour 500 --pending-runs 20 --agent-requests 28
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --sync-bytes 33554432 --sync-pushes-per-hour 300 --sync-transfers 4
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --open-questions 40 --questions-per-hour 600
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --device-open-questions 20 --member-open-questions 30 --question-bytes 16777216
docker compose exec relay apassy-relay admin limits t_7k2m5q4x3c --feed-bytes 8388608 --feed-actions-per-hour 120
```

The command prints all eighteen effective values. If a field has no flag, its value stays the same. Values must be integers from 1 to 1000000; `items` and `agents` may also be 0 (none, as in a Connect team, section 20). The `agent_requests` range is 1 to 224. The `sync_bytes` range is 0 (no vault sync: a push answers 403 `plan_required`) or 1048576 to 67108864 (the largest vault snapshot, in bytes; 64 MiB is also the most that the app and the head grammar allow), and the `sync_transfers` range is 1 to 8 (snapshot uploads and downloads of the team at once; over it, 503 `busy`). The relay also allows at most 16 snapshot transfers of all teams at once. The `open_questions` range is 1 to 1000 (questions that wait for an answer; over it, 403 `too_many_questions`, see section 19); `questions_per_hour` is 1 to 1000000. `member_open_questions` and `device_open_questions` (1 to 1000) and `member_questions_per_hour` and `device_questions_per_hour` (1 to 1000000) are the shares of one member and of one asking device, so one Mac cannot use the team's whole quota. `question_bytes` (1048576 to 268435456) bounds the sealed questions and answers that the team file holds at once. `feed_bytes` (1048576 to 67108864) bounds the sealed feeds of the Macs that the team file holds at once (403 `feed_limit` over it, section 21), apart from `question_bytes`; `feed_actions_per_hour` is 1 to 1000000.

A question limit changed away from its default is stored in `relay.db` in a form the image before questions cannot read: a rollback to it then needs the backup of `relay.db` (section 19.3). Change question limits only when no rollback is planned, or note the change. The same holds for a feed limit changed away from the preset of the team's kind and the image before feeds (section 21.3).

Use the command for active or suspended teams. A change adds `limits_changed` with actor `operator` to the team audit and relay audit.

Members without revocation use member slots. Items without archive status use item slots. Agents without revocation or expiry use agent slots. Agents of revoked members do not use slots. The hourly limit counts all run rows from the last 3600 seconds. It also counts denials.

The pending limit counts runs with status `pending`.

A count limit returns HTTP 403 `team_limit`. A full agent request limit returns HTTP 503 `busy`, with `Retry-After: 2`. Member requests and the host of the owner keep the global member reserve. The team audit records a limit refusal at most once per field per ten seconds.

New limits apply immediately. A lower limit does not remove existing data or stop existing runs. New operations can start only if the applicable limit permits them. Limits stay in `relay.db` after a restart.

The relay automatically changes directory version 1001 to 1002 at start. The new nullable `limits TEXT` column holds JSON. A null column or an absent JSON field uses the default. The column change and version change use one transaction. Unknown versions stop the relay.

**Vault sync.** A team can hold one vault snapshot of the Apassy app (docs/SPEC.md section 24): the encrypted SQLCipher file of the vault, with a head signed by the device that pushed it. The relay keeps the current and the previous version in `teams/<id>.sync/` and never opens them. A team made by the app for its vault has one owner and the owner's Macs as devices. The audit of the team records `sync_pushed`, `sync_fetched`, `sync_received`, and `sync_deleted`, with versions, device ids, and sizes only.

The first start of this version moves each team file to schema version 4: it copies the file to `teams/<id>.db.pre-v4` (the way back for an older image), then adds the two sync tables. A team whose copy cannot be made stays at version 3 and does not open; free disk space and start again. Delete `.pre-v4` files when you no longer need the older image.

**Suspend, resume, delete.**

```sh
docker compose exec relay apassy-relay admin suspend t_7k2m5q4x3c
docker compose exec relay apassy-relay admin resume t_7k2m5q4x3c
docker compose exec relay apassy-relay admin delete t_7k2m5q4x3c   # only a suspended team; no undo
docker compose exec relay apassy-relay admin delete t_7k2m5q4x3c --free-connect-key   # a Connect team: its device key may connect again (21.3)
```

A suspended team's tokens fail at the next request; its sessions and waiting runs end. Each action is a row in the audit of the team (actor `operator`) and of the relay. Delete waits for the requests that started before the suspension, then removes the team's key from `relay.db`, its file, and its vault snapshots. Old backups still hold them (section 13).

**A team that does not open.** If a team file is missing or damaged, the relay still starts and serves the other teams. It logs the team, and `admin teams` shows it with `"open": false`. Suspend and delete it, or put the file back, then suspend and resume it.

**One relay per data directory.** `serve`, `init`, and `migrate` hold `relay.lock` in the data directory. A second relay on the same volume (for example `docker compose run relay` while the relay runs) refuses to start.

**The relay's own addresses.** The proxy refuses private addresses by itself. Add the public addresses of the VPS so that a team cannot reach its other services through the proxy: `APASSY_RELAY_BLOCKED_ADDRESSES=9.9.9.117,2620:fe:0:7491::/64` (in `deploy/vps/compose.yaml`).

**What the operator can see.** The master key and every team file are on the same machine. The operator, root on the VPS, or a disk snapshot can open the names, members, hosts, commands, and audit of every team. Item values stay sealed: their keys are on each owner's machine. Tell the owners this.

**From a relay before teams.** A data volume with one `team.db` must be migrated once. With the relay stopped:

```sh
openssl rand -hex 32 > master_key                 # the new master key
docker compose run --rm \
  -e APASSY_RELAY_KEY_FILE=/run/secrets/relay/master_key \
  -e APASSY_RELAY_OLD_KEY_FILE=/run/secrets/relay/vault_key \
  relay migrate                                     # prints the new team id
```

`migrate` copies `team.db` into `teams/<id>.db` with a new random key, makes `relay.db` with the master key, and renames the old file to `team.db.pre-teams` (it opens with the old key only). The master key must be new: `migrate` refuses the old vault key. A failure before `relay.db` is written leaves `team.db` as it was, and a new `migrate` starts over. A stop after it is finished by the next start. The old owner token, member tokens, agent tokens, and `keys.json` keep working for the migrated team. New tokens of that team name it. An invite code made before the migration stops working: make a new one. Delete `team.db.pre-teams` and the old vault key when you no longer need a way back.

## 18. Install, guide, and limits at the edge

The Worker serves three things itself, without the relay and without the edge secret:

| Path | What |
| --- | --- |
| `/install.sh` | after a SHA-256 check: on Linux (x86_64, aarch64) the node `apassy` and the `apassy-team` shim from the node tarball, on macOS `apassy-team`, into `~/.local/bin`; with `APASSY_COMPONENT=vault` as root, the Linux vault package (`.deb` with apt, or the tarball), on Debian 12+ and Ubuntu 22.04+ only (`deploy/worker/public/install.sh`) |
| `/guide` | the guide for owners and members of a relay that they run (`deploy/worker/public/guide.html`; source `docs/ONBOARDING.md`) |
| `/dl/*` | the CLI binaries, the Linux node packages and the Linux vault packages (`.tar.gz` and `.deb` for x86_64 and aarch64 each), and `SHA256SUMS` (ten lines). Workers static assets serve at most 25 MiB per file; the build refuses a larger package |

Users install with:

```sh
curl -fsSL https://apassy-relay.wyderka.cc/install.sh -o install.sh && sh install.sh
```

The binaries are ignored by git. Stage both GitHub CI artifacts and their verified
combined checksums/metadata through the current release runbook; the Worker asset
preflight refuses missing, modified or mismatched files.

The installer refuses a binary whose checksum is not in `SHA256SUMS`. A missing platform is a clear error.

`POST /v1/join`, `POST /v1/teams`, `POST /v1/devices/link`, and `POST /v1/devices/link/cancel` have a limit per IP address at the Worker: about 10 a minute (Workers Rate Limiting, binding `CREATE_LIMITER`). `POST /v1/connect` has its own, 1 a minute per IPv4 address or IPv6 /64 (`CONNECT_LIMITER`, section 20). Device sign-in (`POST /v1/auth/challenge` and `/v1/auth/token`) has a looser one, about 60 a minute (`AUTH_LIMITER`), because a waiting CLI asks every 5 seconds and several people can share one address. Vault snapshot pushes (`PUT /v1/sync/snapshot`) have their own, about 60 a minute (`SYNC_LIMITER`). Over it, the Worker answers 429 `rate_limited` and the request does not reach the relay. The count is kept in each Cloudflare location and is approximate, so a burst can pass a few more. If the limiter fails, or its binding is missing, requests go on: the relay checks every code itself. The four bindings are in `wrangler.jsonc`; a deploy creates them.

The Worker also checks the declared length of every request body before it forwards it, because the relay reads every declared byte of a body even when it answers early, on any path (docs/SPEC.md section 24.10). A snapshot push (exactly `PUT /v1/sync/snapshot`) with `Transfer-Encoding` or with a missing or non-numeric `Content-Length` gets 400 `invalid_request`; one that declares more than 64 MiB plus 64 KiB gets 413 `payload_too_large`. A body under `/p/` (the agent proxy) may declare up to 8 MiB plus 64 KiB; a feed (exactly `PUT /v1/feed`, section 21) must declare its length as a push does, and may declare up to 352 KiB; every other body, on any other path or method (`PUT /v1/sync/snapshot/`, `POST /v1/sync/snapshot`, and the other feed routes included), up to 128 KiB. Above that: 413; a non-numeric length: 400. The relay keeps its own checks. Origin header/body/handle deadlines and a bounded refusal lane additionally limit stalled reads; see [HTTP-SECURITY.md](HTTP-SECURITY.md).

A workflow in `.github/workflows/health.yml` checks `/healthz` and `/v1/me` (401) every hour. A failed run is the alert: GitHub notifies the owner of the repository.

## 19. Questions and push (team schema 5)

The relay carries the questions of an agent broker from the asking Mac to the other devices of the vault, and wakes iPhones with a push notification without content (docs/SPEC.md section 25; the app's contract is `docs/contracts/relay-questions-v1.md` of the core). It stores sealed envelopes for at most 24 hours and never reads them. The Worker sends the Apple pushes; the relay asks it to, with its own push secret.

What changes at the first start of this version:

- Each team file moves to schema version 5: the relay copies it to `teams/<id>.db.pre-v5` (the way back for an older image, mode 0600), then adds the tables `question`, `question_answer`, `push_token`, `device_wrapped_key`, and the column `team.question_seq` in one transaction. The change is additive: no table is rebuilt, sync rows stay. A team whose copy cannot be made stays at version 4 and does not open; free disk space and start again. The previous image (`sync-*`, schema 4) refuses a version 5 file.
- New routes in the member lane: `/v1/questions`, `/v1/questions/{qid}/answers`, `/v1/questions/{qid}/settle`, `/v1/push/token`. Question long polls have their own 128 threads, apart from the 256 of section 15, so they never take the member reserve.
- New team limits, section 17: `open_questions` (20) and `questions_per_hour` (300) of the team, the shares of one member (15, 225) and of one asking device (10, 150), and `question_bytes` (8 MiB of sealed questions and answers at once). Over any: 403 `too_many_questions` (for an answer over `question_bytes`: 403 `too_many_answers`), and the question stays on the asking Mac. A question has at most 20 answers.
- Ten minutes after a question is settled or expired, the relay deletes its answers and its sealed card and settle; the row (devices, times, state) goes 24 hours after the post.
- One team holds at most 32 of the 128 question long-poll threads; more polls of that team return at once. A long poll of a device that is revoked, or whose member's role changes, ends with 401 at once.
- `to: "approvers"` questions are refused (403 `not_routed`) until shared vaults. `APASSY_RELAY_QUESTIONS_TO_APPROVERS=1` turns them on; leave it unset.
- The audit gets `question_*` and `push_*` rows with device ids and counts only.

### 19.1 Push: what is where

| What | Where | Kind |
| --- | --- | --- |
| `APNS_KEY` | Worker | secret: the text of the Apple `.p8` key (APNs, team `7S3F9767BM`) |
| `PUSH_SECRET` | Worker | secret: 64 hex characters, the same as the relay's push secret |
| `APNS_KEY_ID` | Worker, `wrangler.jsonc` `vars` | the Key ID of the `.p8` key (empty in git: set it before the deploy) |
| `APNS_TEAM_ID`, `APNS_TOPIC` | Worker, `wrangler.jsonc` `vars` | `7S3F9767BM`, `com.wydrox.apassy.companion` |
| `/opt/apassy/secrets/relay/push_secret` | VPS | the push secret, owner 10001, mode 0400 |
| `APASSY_RELAY_PUSH_URL`, `APASSY_RELAY_PUSH_TOPIC`, `APASSY_RELAY_PUSH_SECRET_FILE` | `/opt/apassy/compose.yaml`, service `relay`, `environment` | `https://apassy-relay.wyderka.cc/internal/push`, `com.wydrox.apassy.companion`, `/run/secrets/relay/push_secret` |

- The relay needs all three push variables or none. None: push is off and the relay logs `push is off` once at start; questions still reach the devices by their long polls, and `PUT /v1/push/token` answers 409 `push_unavailable`. Some but not all: the relay does not start.
- The `.p8` key never goes on the VPS, into git, or into an image. It is only a Worker secret.
- The push secret goes only from the relay to the Worker (`X-Apassy-Push`); the edge secret only from the Worker to the relay. Rotate it like the edge secret (section 14): a new file on the VPS, a restart, and `wrangler secret put PUSH_SECRET` with the same text.

### 19.2 Owner steps for the deploy (historical)

Use the current release runbook at the top of this document. This feature is
already represented in schema 6 / directory 1003. Do not repeat its old migration
or build/deploy recipe on an existing installation. For an older installation,
review migration copies, free disk and access changes before any owner-approved
rollout; the rollback analysis below describes that historical boundary.

### 19.3 Rollback

- **Push only.** Remove the three `APASSY_RELAY_PUSH_*` lines from `compose.yaml` and `docker compose up -d --wait`: push is off, questions still work. Or leave the relay and remove `PUSH_SECRET` from the Worker (`npx wrangler secret delete PUSH_SECRET`): `/internal/push` answers 404 and the relay records `push_failed`.
- **The Worker.** The new Worker serves every old route as before. To go back: `npx wrangler rollback` (to the previous version), or deploy the previous commit of `deploy/worker/`.
- **The relay image.** The previous image refuses the version 5 team files, so a rollback puts the version 4 copies back. It also refuses a `limits` column in `relay.db` with a field it does not know: the new relay writes the question limits there only when one differs from its default (section 17). If any `admin limits` call changed a question limit after the deploy, restore `relay.db` from the backup of step 5 too (below), or set every question limit back to its default with the new image still running before you stop it:

  ```sh
  docker compose exec relay apassy-relay admin limits <team id> --open-questions 20 --questions-per-hour 300 \
    --member-open-questions 15 --member-questions-per-hour 225 --device-open-questions 10 \
    --device-questions-per-hour 150 --question-bytes 8388608
  ```

  Restoring `relay.db` from the backup also undoes every other change of the directory since step 5 (teams made, suspended, or deleted, other limits).

  Putting the version 4 copies back loses every change of the teams since the migration: questions and push tokens (the iPhones send their tokens again), and also members, devices, and vault sync heads made after it. A Mac that pushed a snapshot after the migration then sees an older copy on the relay (section 13). Prefer a fix forward when the problem is not the migration itself.

  On the VPS (`ssh ottervibe`, then `cd /opt/apassy`):

  ```sh
  docker compose stop relay
  docker compose run --rm --no-deps --entrypoint bash relay -c '
    set -e
    for j in /data/teams/*.db-journal /data/relay.db-journal; do
      if [ -e "$j" ]; then echo "$j is left: the relay did not stop cleanly. Stop here." >&2; exit 1; fi
    done
    for f in /data/teams/*.db.pre-v5; do cp -p "$f" "${f%.pre-v5}"; done
    ls -l /data/teams'
  ```

  A `*.db-journal` next to a file means a write was cut off (the relay uses `journal_mode=DELETE`). SQLite would replay it into the copied version 4 file at the next open and break it. Do not delete it and do not copy over it: start the new image once (`docker compose up -d --wait`), let it open and close the files cleanly, stop it, and run the step again. If the journal stays, restore the backup of step 5 instead.

  When a question limit was changed after the deploy (above), also put `relay.db` of the step 5 backup into the volume now, with the relay stopped (section 13).

  Then set the image noted in step 5 (for example `apassy-relay:sync-4208643`) in `/opt/apassy/compose.yaml`, remove the three `APASSY_RELAY_PUSH_*` lines, and start:

  ```sh
  ssh ottervibe 'cd /opt/apassy && docker compose up -d --wait && docker compose exec relay apassy-relay admin teams'
  ```

  Every team must be `"open": true`. If the relay does not start and the log names the directory or a team's limits, `relay.db` holds a question limit (above): restore it from the backup of step 5. A team made after the migration has no `.pre-v5` and is version 5 from the start: the old image cannot open it; suspend it, or restore the backup of step 5 instead (section 13: put `relay.db` and `teams/` of that folder into the volume with the relay stopped). The backup of step 5 is the same state as the `.pre-v5` files, plus `relay.db` and the snapshots.

## 20. Connect teams (directory 1003)

On the Free plan the Mac app makes its own team, without a team code, the first time its owner adds a device: a Connect team (docs/SPEC.md section 26). It is an ordinary team with one member, `owner`, whose devices are the Mac that made it and the devices it confirmed with safety words. It carries questions (section 19) and no vault sync. Nobody gives out a code, so the bounds below are what keeps the relay small: every write path and long poll that such a team can reach has a count, a rate, or a byte cap.

What changes at the first start of this version:

- `relay.db` moves from version 1002 to 1003 in one transaction: the column `team.kind` (every existing team becomes `operator`), the column `team.suspend_reason`, and the table `connect_key` (the SHA-256 of each public key that made a Connect team, with the id of its team while the team exists). The change is additive. A failure leaves 1002 and the relay does not start. The images before (`sync-*` and `questions-*`, directory 1002) refuse a 1003 file: see 20.3. This image also carries questions (section 19): from `sync-*` the team files move to schema 5 at the same start (19, with its `.pre-v5` copies).
- A new edge route, `POST /v1/connect`. Its body carries a signature of the device key (SPEC 26.3), so only the holder of a key can make a team with it. `POST /v1/teams` and team codes work as before.
- Three settings, sized for the production container (2 cores, 512 MiB, 20.5), and a fourth for relay sync without a code (20.6):
  - `APASSY_RELAY_CONNECT_TEAMS_PER_DAY` (default 50, 0 to 100000): the Connect teams of the whole relay in any 24 hours. Over it, 503 `busy` with `Retry-After: 3600`.
  - `APASSY_RELAY_CONNECT_TEAMS_MAX` (default 100, 0 to 1000000): the Connect teams the relay holds at once, active or suspended. At it, 503 `busy` ("no room") with `Retry-After: 3600`. A deleted team frees its place. Raise it only after the measurement of 20.5.
  - `APASSY_RELAY_CONNECT_LONG_POLLS` (default 96, 0 to 1024): the long polls of all Connect teams together (below).

  Either of the first two at `0` turns Connect off without a deploy; `deploy/vps/compose.yaml` ships with `APASSY_RELAY_CONNECT_TEAMS_PER_DAY: "0"`, and step 5 of 20.2 turns it on. Each refusal writes a `connect_refused` row to the relay audit (at most one per reason and ten seconds).
- One device key creates at most one Connect team. An old creation proof still gets 409 `connect_key_used`; a fresh possession proof can recover the same active team (section 22). Suspended/deleted teams are never recovered.
- One client network (an IPv6 /48 or an IPv4 /24) makes at most 5 Connect teams per UTC day, and never more than a tenth of the daily cap; over it 429 `rate_limited` until the next UTC day. The Worker sends the network in `X-Apassy-Client-Prefix` and, beside it, `X-Apassy-Client-Prefix-Mac`: an HMAC-SHA256 of the network under the edge secret. **The relay takes the network only when that HMAC verifies** (compared in constant time); without it, or with a wrong one, the call counts as the one network `unknown`. A Worker from before this one forwarded a client's own `X-Apassy-Client-Prefix`, so the header alone proves nothing. The relay counts **in memory only**: it keeps an HMAC of the prefix under a random salt that it makes at the first call of each UTC day and forgets with the counts at the next. No file, log line, or audit row of the relay holds an address or a prefix, and a restart forgets the counts.
- A Connect team starts with these limits, and every other limit at its default (section 17):

  | Field | Connect | Why |
  | --- | --- | --- |
  | `members` | 1 | one person; more devices come by device links (10 per member). Invites are refused |
  | `items`, `agents` | 0 | no runs and no use of the agent proxy: a free team must not be an open HTTP proxy. Collections, policies, and grants are refused |
  | `sync_bytes` | 0 | no vault sync on the relay: a snapshot push and a receipt answer 403 `plan_required` |
  | `question_bytes` | 2097152 (2 MiB) | about 60 waiting questions |

- A Connect team's file is capped at `question_bytes` + 8 MiB (10 MiB at the preset; more when `admin limits` gives it items or members). **Nothing is ever deleted to stay under it** (the owner's decision of 2026-10-13): at the cap, the team's writes are 403 `team_limit` (a sign-in too, when it writes its hourly `device_signed_in` row) until the operator raises its limits (`admin limits <id> --question-bytes <bytes>`: each byte more is a byte more of file) or deletes the team. Old questions still go by themselves (their deletion writes no row). The relay warns in its log at about 90 % (`is near its cap`) and about 100 % (`is full`), at most once an hour for each team unless the level rises, and `admin teams` shows each team's `file_bytes`, `file_cap`, and `file_level` (`ok`, `near`, `full`). Operator teams have no file cap.
- Refusals that someone outside the team can cause, knowing only the team id (it is in every device link code), never go into a Connect team's file: a forged or expired token (`auth_failed`), a failed sign-in (`device_sign_in_refused`), a used invite (`invite_reused`), a join over the member limit, and a proxy request over the team's slots before its session is checked. They go to the relay audit with the `team_id`, at most one row per kind and ten seconds for all Connect teams together. Rows that the team's own signed-in devices cause stay in its file; its 300 requests a minute bound them. Operator teams keep all of these rows in their own audit, as before.
- A Connect team makes at most 300 authenticated requests a minute (429 `rate_limited` over it). All Connect teams together hold at most `APASSY_RELAY_CONNECT_LONG_POLLS` long polls (96: the 128 threads of the question lane less one team's share of 32, so an operator team always finds its share), and one Connect team at most 2 question polls (its Mac and one other device). A poll over a bound answers at once, as with `wait=0`; the app backs off before it polls again. Connect teams have at most half of the push queue (2 jobs per team). Long polls that can get nothing (`GET /v1/sync/head` with `sync_bytes` 0, `GET /v1/host/requests` with `agents` 0) answer at once.
- Each Connect team's SQLite connection keeps a page cache of 64 KiB instead of SQLite's 2 MiB; operator teams keep the default.
- A Connect team whose file cap cannot be set at open is not served (the log names it; it is out of service like a team that fails to open, section 17). It is never served without a cap.
- At start the relay removes every `teams/<id>.db` that no row of `relay.db` names, with its journal, `.pre-v*` copies, and snapshots, and logs `removed the file of team <id>`: a team whose creation stopped between its file and its row (a crash). The key of such a file was only in the row that never committed, so nothing can open it. Other names in `teams/` stay. So restore `relay.db` and `teams/` of the same backup together (section 13), never a `relay.db` older than the team files under this image.
- For every team: a repeated sync receipt or push token writes no new audit row; expired or refused device links go after 7 days (at most 100 stay); a public key must be a point on P-256 (`/v1/teams`, `/v1/join`, `/v1/devices/link`, and sign-in refuse others).
- A grant is refused (403 `team_limit`) only when the team's `items` is 0. A team of one member with items, such as a solo operator team, grants its owner and runs.
- The maintenance pass of every team runs on its own thread; a Connect team without requests is passed every 60 seconds instead of every 5. At start the team files open on up to 8 threads, no more than the cores (20.5).
- The ranges of three limits change for every team: `--items 0` and `--agents 0` are allowed (none), and `--sync-bytes 0` is allowed (no vault sync). To give one Connect team vault sync by hand: `apassy-relay admin limits <id> --sync-bytes 67108864`. `--sync-bytes 0` later blocks pushes and receipts only: snapshots pushed before can still be downloaded until `DELETE /v1/sync` or the team's deletion.
- `admin teams` shows `kind` (`operator` or `connect`), `suspend_reason`, and the file use above for each team. The sign-in answer and `GET /v1/me` carry `team_kind`.
- A new admin command, `connect-sweep` (20.4). It does not run by itself.
- The Worker has two new rate limit bindings for `POST /v1/connect`: `CONNECT_LIMITER` (namespace `1004`, 1 a minute per IPv4 address or IPv6 /64) and `CONNECT_PREFIX_LIMITER` (namespace `1005`, 3 a minute per IPv4 /24 or IPv6 /48). Workers Rate Limiting counts only per 10 or 60 seconds, so the daily bounds are the relay's. Like the others, the bindings fail open. The Worker sets `X-Apassy-Client-Prefix` and `X-Apassy-Client-Prefix-Mac` on that route only and removes a client's copy of both everywhere.

### 20.1 What to watch

- `admin teams`: the number of `connect` teams against `APASSY_RELAY_CONNECT_TEAMS_MAX`, and every team with `"file_level": "near"` or `"full"`.
- The relay log: `warning: the file of Connect team <id> is near its cap` or `is full`. A full team cannot sign in or post until you raise its limits (20 above) or delete it. Many full teams mean the preset is too small for real use: raise `question_bytes` for them, and tell the owner of the app.
- The relay audit (`relay.db`, section 12): `team_created` rows with `"kind":"connect"`, and `connect_refused` rows with their `reason`: `busy` (the daily cap is full), `full` (the room is full), `rate_limited` (one network made its teams of the day), `prefixes_full` (more than 65536 networks in a day). Many `busy` or `full` refusals mean someone makes teams in bulk, or the app grew: raise or lower the caps, set either to 0 and restart the relay, or run the sweep. Many `rate_limited` refusals mean the relay counts every call as `unknown`: the Worker does not send the prefix with a valid HMAC (an older Worker, or a different edge secret in the Worker and on the VPS).
- The relay audit, `auth_failed` and `device_sign_in_refused` rows with a `team_id`: someone sends forged tokens or sign-ins to a Connect team. They cost the team nothing; at one row per kind and ten seconds they cost `relay.db` at most about 17 000 rows a day per kind.
- Disk: Connect teams take at most `APASSY_RELAY_CONNECT_TEAMS_MAX` × 10 MiB (about 1 GiB at the defaults), plus one journal while a transaction runs. The backup copies each file (section 13), so a backup can be as large.
- The start time of the relay, its memory, and its open files (20.5).

### 20.2 Owner steps for the deploy (historical)

Use the current release runbook at the top of this document. This feature is
already represented in schema 6 / directory 1003. Do not repeat its old migration
or build/deploy recipe on an existing installation. For an older installation,
review migration copies, free disk and access changes before any owner-approved
rollout; the rollback analysis below describes that historical boundary.

### 20.3 Rollback

1. **First, stop new Connect teams.** Set `APASSY_RELAY_CONNECT_TEAMS_PER_DAY: "0"` (or `APASSY_RELAY_CONNECT_TEAMS_MAX: "0"`) and `docker compose up -d --wait`. Existing Connect teams keep working; new calls get 503. This needs no rollback of anything, and it is the step to take before any rollback below. Prefer it and a fix forward.
2. **The Worker.** The new Worker serves every old route as before; `npx wrangler rollback` goes back. **Keep the Connect cap at 0 while any Worker older than this one is live**: an older Worker has no Connect limiters (or only the first one) and sends no prefix HMAC, so the relay counts every call as the one network `unknown` (at most 5 new teams a day for the whole relay) and still applies its daily cap and room; a client's own `X-Apassy-Client-Prefix` through such a Worker counts for nothing. Deploy the new Worker again before you turn the cap on (the Worker always goes before the relay).
3. **The relay image, back to `sync-4208643`.** The old image refuses directory 1003 and team schema 5, and the limits of a Connect team (`sync_bytes` 0, `items` 0, `agents` 0) are out of its ranges. So the rollback puts back both: the version 4 team files from their `.pre-v5` copies (19.3) **and** `relay.db` from the backup of 20.2 step 2. Do step 1 first.

   On the VPS (`ssh ottervibe`, then `cd /opt/apassy`):

   ```sh
   docker compose stop relay
   docker compose run --rm --no-deps --entrypoint bash relay -c '
     set -e
     for j in /data/teams/*.db-journal /data/relay.db-journal; do
       if [ -e "$j" ]; then echo "$j is left: the relay did not stop cleanly. Stop here." >&2; exit 1; fi
     done
     for f in /data/teams/*.db.pre-v5; do cp -p "$f" "${f%.pre-v5}"; done
     ls -l /data/teams'
   ```

   A `*.db-journal` means a write was cut off: do as 19.3 says (start the new image once, stop it, run the step again; if the journal stays, restore the whole backup of step 2 instead).

   Then put `relay.db` of the step 2 backup into the volume, with the relay stopped (section 13: owner 10001, mode 0600). The backups are mounted at `/backups` in the container:

   ```sh
   docker compose run --rm --no-deps --entrypoint bash relay -c '
     set -e
     cp "/backups/<UTC time>/relay.db" /data/relay.db.restore
     chmod 0600 /data/relay.db.restore && mv /data/relay.db.restore /data/relay.db
     ls -l /data/relay.db'
   ```

   Then in `/opt/apassy/compose.yaml` set `image: apassy-relay:sync-4208643`, remove `APASSY_RELAY_CONNECT_TEAMS_PER_DAY`, `APASSY_RELAY_CONNECT_TEAMS_MAX`, and `APASSY_RELAY_CONNECT_LONG_POLLS` (the old image ignores them; remove them so the file says what runs), keep `ulimits` and `start_period`, and start:

   ```sh
   docker compose up -d --wait && docker compose exec relay apassy-relay admin teams
   ```

   Every team must be `"open": true`. Restoring all of `relay.db` and `teams/` of the step 2 backup instead (section 13) gives the same state plus the snapshots of that moment.

   What the rollback loses: everything since step 2. In the teams that existed then: questions and push tokens, and members, devices, and vault sync heads made after the migration (19.3); a Mac that pushed a snapshot since then sees an older copy on the relay (section 13). In `relay.db`: every team made after the backup, Connect or operator (its file stays in `teams/` with no key anywhere; the old relay ignores it; delete those files when you are sure, or let a later start of this image remove them), and every change since (limits set, teams suspended, resumed, or deleted, team codes made). Every Mac with a Connect team then gets 401 at sign-in, and `/v1/connect` is 404 on the old image, so Free users have relay questions again only after a fix forward.

### 20.4 Idle Connect teams

A Connect team whose devices have not signed in for 30 days is most likely abandoned, however many devices it linked. The sweep suspends such teams, then deletes them 30 days after their suspension. It touches only Connect teams whose limits are still a Connect preset (`TeamLimits::connect()`, or the same with the `sync_bytes` of `APASSY_RELAY_CONNECT_SYNC_BYTES`) and that have no vault sync head: never operator teams, teams a plan or `admin limits` lifted, teams that synced a vault, or teams the operator suspended:

```sh
docker compose exec relay apassy-relay admin connect-sweep --dry-run       # names the teams, changes nothing
docker compose exec relay apassy-relay admin connect-sweep --apply         # --idle-days 30 --delete-days 30
```

The answer lists `suspended`, `deleted`, and `failed` team ids. A suspended team gets `"suspend_reason": "idle"` in `admin teams` and `team_suspended {"reason":"idle"}` in the team and relay audit. Its devices get 401 at the next sign-in, and the app connects again with a new key. During the suspension, `admin resume <id>` brings a team back (and clears the reason). A deleted team's key stays used, and no longer names the team. Suspended teams still count against `APASSY_RELAY_CONNECT_TEAMS_MAX` until they are deleted. Take a backup before the first real run.

The packaged systemd timer and its dry-run default are described in section 22. Installation and activation require a separate owner decision.

### 20.5 Start time, memory, and open files

The relay container has 2 cores, 512 MiB, and 2048 tasks (`pids_limit`, `deploy/vps/compose.yaml`).

**Threads.** tiny_http 0.12 runs one pool thread per open TCP connection, blocked for the whole request and while a keep-alive connection is idle, and the relay runs each request in flight on a thread of its own. So each request costs two tasks: at the limits about 2 × (256 request threads + 128 question polls + 64 feed polls) + about 8 (accept, maintenance, operator socket, push) ≈ 904, plus a pool thread for each idle connection. Before the feed it was already 2 × 384 + 8, over the old `pids_limit` of 512. When tiny_http cannot start a thread, its accept thread panics and the listener closes; the relay probes its listener every 10 s and, after three failed probes (or an accept error), exits with an error, so `restart: unless-stopped` starts it again. The 2048 tasks leave room for idle connections; memory (512 MiB, a thread's stack is mostly not resident) is the bound that matters.

Every active team is opened at start, and each open derives the key of its file with PBKDF2-HMAC-SHA512 at 256 000 rounds: about 0.11 s of one core (measured on the build Mac; a shared VPS core is slower, about 0.15 to 0.25 s). The relay opens the files on up to 8 threads, no more than the cores it sees (2 here), and it does not listen until all are open, so `/healthz` is down meanwhile. At the default room (100 Connect teams) that is about 15 to 25 s of CPU, so about 8 to 13 s on the 2 cores. The healthcheck of `deploy/vps/compose.yaml` has a start period of 300 s, so a slow start is not counted as a failure; `docker compose up --wait` waits for it.

Each open team holds one SQLite connection for as long as the relay runs: one file descriptor (two while a transaction has a journal) and its page cache, 64 KiB for a Connect team and SQLite's default (2 MiB) for an operator team. Suspended teams hold none. The container has `nofile` 65536.

**Before you raise `APASSY_RELAY_CONNECT_TEAMS_MAX` above 100**, measure what one Connect team costs, on the devbox (never on the VPS, which is production):

1. Check the shared budget with `devbox status`. Start `devbox up x86` through
   Apassy `apassy_run_with_secrets` using item `devbox tailscale auth key`.
   Copy the reviewed checkout to `dev@devbox-x86:/home/dev/relay-review/` with
   `rsync` (exclude `target/` and `.git/`). Remote Docker bind mounts refer to that
   remote path. Build without the production memory limit, then measure with it:

   ```sh
   cache="-v apassy-cargo-registry:/usr/local/cargo/registry -v apassy-cargo-git:/usr/local/cargo/git"
   docker --context devbox-x86 run --rm $cache -v /home/dev/relay-review:/src -w /src rust:1.97.0-trixie cargo test --release --test server_connect --no-run
   docker --context devbox-x86 run --rm $cache --cpus 2 --memory 512m --pids-limit 2048 --ulimit nofile=65536 -v /home/dev/relay-review:/src -w /src rust:1.97.0-trixie \
     sh -c 'APASSY_MEASURE_TEAMS=100 cargo test --release --test server_connect measure_connect_teams -- --ignored --nocapture'
   ```

   It makes the teams on a relay in the test process, each with a signed-in device and a question, and prints the resident memory and open files per team, and the start time of the relay with them. Run it again with the room you want (for example 500), then `devbox down x86`.
2. The room fits when the memory of all teams, plus the threads of the request, question, and feed lanes (two tasks per request, above), stays well under 512 MiB, the open files under 65536, and the start time under the 300 s start period. Write the numbers in this section with the date, then raise the room, or raise the container's limits first.

Opening Connect teams only when they are first used, and closing idle ones, would remove this cost. It is not built: `Hub::team` is how every request, the sweep, `admin teams`, and the backup find a team, and an open on first use would let an unauthenticated sign-in call with a known team id start a key derivation. Lower the room, or run the sweep, if the start grows too long.

### 20.6 Relay sync without a code (`APASSY_RELAY_CONNECT_SYNC_BYTES`)

Plans section 4.1: until Apassy Connect starts, relay sync on the hosted relay is free and needs no team code. The Mac makes a Connect team (`POST /v1/connect`) with the purpose `sync`, or uses the Connect team that the vault has for questions, and pushes version 1. The relay setting that allows it:

- `APASSY_RELAY_CONNECT_SYNC_BYTES` (default `0`; `0` or 1048576 to 67108864, another value stops the start): `sync_bytes` of each **new** Connect team (SPEC 26.4). `0` keeps 403 `plan_required` on a push, as before. The hosted relay sets `"67108864"` in the release that ships the Mac's codeless relay copy (plan s7, R1), and the relay deploys before the apps.
- A team keeps the value it was made with. Connect teams made before the setting (questions teams) get the same size by hand, one team at a time: `docker compose exec relay apassy-relay admin limits <id> --sync-bytes 67108864`. The app asks for nothing: a vault whose questions team still has `sync_bytes` 0 sees "The relay does not keep vault copies for this connection yet" when it turns relay sync on.
- **Capacity, before you set it.** Each Connect team then holds up to two snapshots (the current and the previous version) of up to `sync_bytes` each, in `teams/<id>.sync/`, plus one temporary file for each push in flight (`sync_transfers`, 2), plus a team file capped at 27 MiB (20 above; 16 MiB more than without sync). At the default room (`APASSY_RELAY_CONNECT_TEAMS_MAX` 100, `APASSY_RELAY_CONNECT_TEAMS_PER_DAY` 50) that is at most 100 × 128 MiB = 12.5 GiB of snapshots, 2.6 GiB of team files, and the temporary files of the pushes that run; real vaults are far smaller. `admin backup` copies all of it, so the backup volume needs as much again. Check the free disk of the VPS for both (`df -h /opt/apassy`) before the setting goes live, and raise `APASSY_RELAY_CONNECT_TEAMS_MAX` only after this check and 20.5, and only with the owner.
- **Rate, and the disk again.** A Connect team pushes at most 30 snapshots an hour (`sync_pushes_per_hour` of the preset; 403 `team_limit`) and at most 512 MiB of snapshots an hour (429 `rate_limited` with `Retry-After`, SPEC 24.3 check 4). The relay keeps only the current and the previous snapshot, so the rate bounds the write load and the churn of the disk, not the size at rest: the capacity check above still decides. Check `df -h /opt/apassy` again before you set `APASSY_RELAY_CONNECT_SYNC_BYTES`, and do not set it when the data or the backup volume cannot hold the worst case of that check.
- Watch: `admin teams` (`kind: connect` teams with a `sync_head`, their `file_level`), the disk of the data and the backup volume, `sync_refused {reason: "too_large"}` rows, and `limit_reached` rows with `sync_pushes_per_hour` or `sync_bytes_per_hour`.
- Rollback: set the variable back to `"0"` (or remove it) and `docker compose up -d --wait`. New Connect teams get no relay sync again; the teams made with it keep their limit until `admin limits <id> --sync-bytes 0`, which stops pushes and receipts but keeps the copies downloadable. An image before this setting ignores the variable and reads the stored limits as they are (no directory change).
- The cutover of stage 7 (plan s7, O2) sets it to `"0"` again.

## 21. The feed of a Mac (team schema 6)

Each Mac of a vault publishes a sealed list of its agents through the relay, so the Agents tab of the iPhone shows real data, and the iPhone sends back one kind of sealed action: remove an exception of an agent (docs/SPEC.md section 27; the app's contract is `docs/contracts/relay-feed-v1.md` of the core). The relay keeps the latest feed of each device and routes actions to their target Mac. It never reads either: both are sealed with the vault's question key.

What changes at the first start of this version:

- Each team file moves to schema version 6: the relay copies it to `teams/<id>.db.pre-v6` (the way back for the previous image, mode 0600, encrypted like the file), then adds the tables `feed` and `feed_action` and the columns `team.feed_change` and `team.feed_action_seq` in one transaction. The change is additive: no table is rebuilt; questions, push tokens, sync, and devices stay. A team whose copy cannot be made stays at version 5 and does not open; free disk space and start again. The previous image (`connect-3510b68`, schema 5) refuses a version 6 file. `relay.db` keeps version 1003.
- New routes: `/v1/feed` (PUT, GET, DELETE), `/v1/feed/actions` (POST, GET), `/v1/feed/actions/{id}` (GET), `/v1/feed/actions/{id}/settle` (POST). They are for the access tokens of devices; only the devices of one member see each other's feeds and actions.
- `PUT /v1/feed` takes a body of up to 352 KiB (the Worker and the relay); every other body keeps its cap. One feed per device, replaced by each `PUT`, at most one every 10 s (403 `feed_limit`).
- New team limits, section 17: `feed_bytes` (4 MiB of sealed feeds at once; 1 MiB in a Connect team) and `feed_actions_per_hour` (60). An action is open for 300 s; 20 are open at once in a team, 10 of one iPhone. One member gets at most three quarters of each (3 MiB, 45 an hour, 15 open), so one member cannot block the others; a Connect team has one member and gets all. Over any: 403 `feed_limit` or `too_many_actions`. Feeds never count in `question_bytes`.
- One device gets at most 16 MiB of feed text a minute from `GET /v1/feed` (a read of everything is up to about 1.33 MiB a page, and up to about 4 MiB with its `more` pages at the default budget), and has at most two feed reads in flight; each read reserves a whole page of the budget before it reads. Over either: 403 `feed_rate`. Its other calls go on: a 403, not a 429.
- A Connect team's file cap grows by its `feed_bytes`: 11 MiB at the preset (was 10 MiB).
- The three feed long polls have a lane of their own, so question and answer polls keep all of their capacity (128 threads, 32 of a team, 2 of a Connect team, `APASSY_RELAY_CONNECT_LONG_POLLS`): 64 threads, 16 of an operator team, 3 of a Connect team, 48 of all Connect teams. Of a team's feed seats the iPhones' list polls hold at most half and their status polls a quarter, so they leave seats to the Macs' action polls and to each other; one member's polls leave a seat for each other member that has a feed. In a Connect team: one list poll, one status poll, and the Mac's action poll. Each request in flight costs two tasks (20.5): about 904 at the limits, so `pids_limit` goes from 512 to 2048 in `deploy/vps/compose.yaml`; the old value was already too low before the feed. If the listener stops (out of tasks), the relay now exits and restarts.
- An action leaves the Mac's list when it is settled or expires; 10 minutes later its sealed envelopes go; its row goes 24 hours after the post. A feed goes with `DELETE /v1/feed`, when its device or member is revoked, and 30 days after its last update.
- The audit gets `feed_started`, `feed_deleted`, `feed_action_posted`, and `feed_action_settled` with device ids and the outcome only. **No row per feed update**: a Mac publishes up to every 10 s, and a Connect team never deletes audit rows. For the same reason a device writes at most one `feed_started` or `feed_deleted` (of its own `DELETE /v1/feed`) an hour; a change within the hour is written by maintenance once the hour has passed, if the feed is still so. A revocation always writes its row. `limit_reached` of the feed limits: at most one row per kind and hour for a team.
- `admin limits` takes `--feed-bytes` and `--feed-actions-per-hour` and prints eighteen values.
- New commands for the way back (21.3): `apassy-relay rollback-check` (reads only, with or without a running relay) and `admin delete <id> --free-connect-key`.

### 21.1 What to watch

- The relay log at the start: no `cannot be moved to schema version 6`.
- `admin teams`: every team `"open": true`; Connect teams with `"file_cap": 11534336`, and their `file_level`.
- The team audit: `limit_reached {"limit": "feed_bytes"}` means the Macs of a team publish more than its budget (many Macs, or many agents): raise `feed_bytes` for it. `member_feed_bytes` means one member's Macs do: raising `feed_bytes` raises the share too. `open_feed_actions`, `feed_actions_per_hour`, or their `member_` rows mean an iPhone sends actions in bulk. Each kind writes at most one row an hour.
- Disk: each team holds at most its `feed_bytes` of feeds (4 MiB, or 1 MiB for a Connect team) and a few KiB of actions.

### 21.2 Owner steps for the deploy (historical)

Use the current release runbook at the top of this document. This feature is
already represented in schema 6 / directory 1003. Do not repeat its old migration
or build/deploy recipe on an existing installation. For an older installation,
review migration copies, free disk and access changes before any owner-approved
rollout; the rollback analysis below describes that historical boundary.

### 21.3 Rollback

**What a rollback of the relay undoes.** The way back copies each `teams/<id>.db.pre-v6` over its team file. That copy is the team as it was at the migration (step 4), so the rollback undoes everything every team file got since then, not only the feeds:

- **Every change of access since the migration comes back undone.** A device removed since then signs in again with its key; a member removed since then, and its devices and its open invites, work again; a revoked agent token works again, and an agent bound to a device since then is unbound (a later removal of the device no longer revokes it); a revoked access grant gives access again; an archived item (a credential deleted or rotated out) is live again for its grants; a used invite can be used again; a member token ended by a device enrollment works again; a demoted member has its old role, a collection its old policy, and the key holder is the old device. The old image has no record of these changes, and nobody is told.
- **The audit rows since the migration are gone,** also the rows that recorded those changes.
- The questions, push tokens, devices, members, and sync heads made since then are gone too (19.3), and the feeds and actions (harmless: the old image answers 404 on `/v1/feed`, the Macs stop publishing, and the iPhones keep their interim Agents screen).

So the first steps are a look, with the new image still up. Nothing is stopped yet.

1. **No new Connect teams, then check.** A Connect team made from now on would have no `.pre-v6` and would not be in the check. In `/opt/apassy/compose.yaml` set `APASSY_RELAY_CONNECT_TEAMS_PER_DAY: "0"` (as 20.3 says for any rollback), then, on the Mac:

   ```sh
   ssh ottervibe 'cd /opt/apassy && docker compose up -d --wait'                  # the new image again, with Connect off
   ( umask 077
     ssh ottervibe 'cd /opt/apassy && docker compose exec -T relay apassy-relay rollback-check' > rollback-check.json
     echo "rollback-check exit $?"
     jq '[.[] | select(.clean | not)]' rollback-check.json > needs-decision.json )
   jq -e 'length == 0' needs-decision.json && echo "nothing to decide"
   ```

   `rollback-check` reads `relay.db` and every team file read-only and needs no running relay: if the new image cannot serve, run it with the relay stopped, `docker compose run --rm --no-deps -T relay rollback-check`. Its reads take SQLite's shared locks for a moment, and a write of the relay waits for them (up to 5 s) while it runs. Inside the live container it shares the 2 cores with the relay: about two key derivations (0.15 to 0.25 s each) per team, on up to 2 threads, so about 25 to 50 s of both cores for 100 Connect teams. It exits 0 when every team is clean, and 1 otherwise or when it cannot read `relay.db` (then `rollback-check.json` is empty and `jq` fails). For each team it prints `clean`, `pre_v6` (whether the copy exists), `schema`, `revocations` (each device, member, agent, grant, or invite revoked since the migration: `{kind, id, revoked_at}`, oldest first), `changes` (`member_role`, `member_token`, `collection_policy`, `key_holder`, `item_archived`, `invite_used`, `agent_device`: `{kind, id}`), `audit_lost` (the audit rows that go, by action), `access_rows_lost` (those of them that record a change of access), and `feed_limits_stored`. A team is clean when the rollback undoes nothing of its access: nothing in `revocations`, `changes`, or `access_rows_lost`, no stored feed limit, no `error`, and a copy, or a file below version 6 (a team suspended through the migration, 21.2 step 5). `needs-decision.json` keeps the teams that are not clean; `jq -e` prints "nothing to decide" only when it is `[]`, and exits 1 otherwise, also when a file is empty or not JSON. Both files are mode 0600 (they name team ids); keep them until the rollback is over.

2. **Decide, team by team of `needs-decision.json`.**
   - **Any revocation, change, or access row: fix forward** (a new image from `feat/feed` with the fix, built as step 2 of 21.2), and do not roll back, unless the new image cannot run at all.
   - If the rollback is the only way: suspend each such **Connect** team now, with the new image still up (`admin suspend <id>`). The suspension is in `relay.db`, which the rollback keeps, so the old image never serves the undone changes; its devices get 401, and the app offers its owner a new team (relay-connect-v1 section 6). The operator cannot revoke for a Connect team's owner. In each such **operator** team its owner re-applies each listed change right after the old image starts (step 4), before you tell anyone the relay is back, with the ids of the list: `apassy-team device revoke <id>`, `apassy-team member revoke <id>` (it also revokes the member's devices and invites again), `apassy-team agent revoke <id>` (also for `agent_device`: the agent is unbound), `apassy-team revoke --grant <id>`, `apassy-team member role <id> <role>` for `member_role`, `apassy-team collection policy <id> [policy flags]` with the policy it should have for `collection_policy`, `apassy-team device key-holder <id>` for `key_holder`, `apassy-team item archive <id>` for `item_archived`, a new device enrollment of that member for `member_token` (it ends the token again), and for `invite_used` nothing but a watch on the team's joins (an invite cannot be revoked alone). An invite in `revocations` goes again with its member. A team with only `access_rows_lost`: its owner reads `apassy-team audit` for those actions since the migration and re-applies what still applies.
   - **`feed_limits_stored: true`:** the schema 5 image refuses the whole `relay.db` with a feed limit away from the preset, and does not start. With the new image still up, set it back to the preset of the team's kind:

     ```sh
     docker compose exec relay apassy-relay admin limits <operator team id> --feed-bytes 4194304 --feed-actions-per-hour 60
     docker compose exec relay apassy-relay admin limits <connect team id> --feed-bytes 1048576 --feed-actions-per-hour 60
     ```

     Never restore `relay.db` from the backup for this: it drops every team made since the backup, and the old image's start removes their files as orphans.
   - **`pre_v6: false` and `schema: 6`:** made after the migration. The old image cannot open it. With the new image still up: a Connect team, `admin suspend <id>` then `admin delete <id> --free-connect-key` (the answer says `"connect_key": "freed"`): its file goes, and its device key may make a new team, so the Mac does not stay on 409 `connect_key_used` after the rollback (its next call gets 401, and once Connect is on again the app connects with the same key and a new team). An operator team: tell its owner, then `admin suspend <id>` (the old image leaves a suspended team closed; resume it after a later deploy of schema 6), or restore the whole backup of step 3 instead (section 13: `relay.db` and `teams/` of that folder, with the relay stopped), which also undoes every other change since then.
   - A team with an `error` could not be read: look at it before going on (`admin teams`).

3. **The Worker.** `npx wrangler rollback` (to the previous version), or deploy the previous commit of `deploy/worker/`. The old Worker answers a feed body over 128 KiB with 413; the Mac then fits its feed to 96 KiB until its next start. Nothing else changes. The Worker alone can go back without the relay.

4. **The relay image, back to `connect-3510b68`.** Stop the relay, then check again with it stopped: this is the gate, since changes and teams may have come until the stop. On the Mac:

   ```sh
   ssh ottervibe 'cd /opt/apassy && docker compose stop relay'
   ( umask 077
     ssh ottervibe 'cd /opt/apassy && docker compose run --rm --no-deps -T relay rollback-check' > rollback-check.json
     echo "rollback-check exit $?"
     jq '[.[] | select((.clean | not) and (.state == "active" or .feed_limits_stored))]' rollback-check.json > needs-decision.json
     jq -r '.[] | select(.pre_v6) | .team' rollback-check.json > copy-teams.txt )
   jq -e 'length == 0' needs-decision.json && echo "gate passed"
   ```

   The gate passes when every team that is not clean is suspended (step 2) and no team holds a stored feed limit (the old image refuses `relay.db` for one, also of a suspended team): `needs-decision.json` holds the others. If it is not `[]`, start the new image again (`docker compose up -d --wait`), go back to step 2 for those teams, and stop and check again. `copy-teams.txt` names the teams that have a copy; only their files are copied, so an orphan `.pre-v6` of a deleted team stays out:

   ```sh
   ssh ottervibe 'cd /opt/apassy && docker compose run --rm --no-deps -T --entrypoint bash relay -c '"'"'
     set -e
     for j in /data/teams/*.db-journal /data/relay.db-journal; do
       if [ -e "$j" ]; then echo "$j is left: the relay did not stop cleanly. Stop here." >&2; exit 1; fi
     done
     while read -r id; do
       case "$id" in t_[a-z2-7]*) ;; *) echo "not a team id: $id" >&2; exit 1 ;; esac
       cp -p "/data/teams/$id.db.pre-v6" "/data/teams/$id.db"
     done
     ls -l /data/teams'"'"'' < copy-teams.txt
   ```

   A `*.db-journal` means a write was cut off: do as 19.3 says (start the new image once, stop it, and run this step again from the gate; if the journal stays, restore the backup of step 3 instead).

   Then set `image: apassy-relay:connect-3510b68` in `/opt/apassy/compose.yaml` (and `deploy/vps/compose.yaml`), change nothing else (Connect stays at `"0"` for now), and start:

   ```sh
   ssh ottervibe 'cd /opt/apassy && docker compose up -d --wait && docker compose exec relay apassy-relay admin teams'
   ```

   Every team must be `"open": true`, except the teams suspended in step 2. If the relay does not start and its log says "The team vault failed." or names a team's limits, `relay.db` still holds a feed limit: start the new image, set the limit back (step 2), stop it, and run this step again from the gate. Do not restore `relay.db` from the backup for it (step 2). Now the owners of the listed operator teams re-apply their changes (step 2), and only then tell the owners the relay is back. Then set `APASSY_RELAY_CONNECT_TEAMS_PER_DAY` back to `"50"` and `docker compose up -d --wait`, so the Macs of deleted Connect teams can connect again. The iPhones send their push tokens again at their next start.

5. **When the new image cannot run at all** (not even `rollback-check` starts), there is no list. Treat every team as not clean, and let nothing reach the old image until the teams are closed:

   ```sh
   ssh ottervibe 'cd /opt/apassy && docker compose stop cloudflared relay'
   ```

   Then the copy of step 4 for every team with a copy (`ls /data/teams/*.db.pre-v6` in place of `copy-teams.txt`), the old image in `compose.yaml`, and `docker compose up -d --wait relay` (the relay only; the tunnel stays down, so only the operator socket reaches it). Suspend every Connect team (`admin teams` lists them, `admin suspend <id>` each), tell the owner of every operator team that changes of access since the migration are undone and must be re-applied (step 2), and only then start the tunnel: `docker compose up -d --wait cloudflared`. If the old image does not start because of a stored feed limit (step 4), there is no way to set it back without the new image: restore `relay.db` from the backup of step 3 as the last resort, knowing that the teams made since then are lost.


## 22. Relay audit recovery, push, readiness and reclamation

Prepared for review only: no deployment or timer installation is implied. Package
versions and team/directory schemas remain 0.5.8 and 6/1003.

**Connect recovery (F06, contract change requiring owner approval before deploy).**
Creation is unchanged. Save the private device key before the first request. If its
response is lost, POST `/v1/connect/challenge` with `{"public_key":"<base64url>"}`.
The response uses the normal envelope and returns `nonce`, `expires_at` (60 seconds)
and `origin`, independent of whether the key has a team. POST `/v1/connect` with the
original v/team/device_name/public_key fields, `recovery_nonce`, and a new `signature`
over `connect_message(origin, public_key) || 0x00 || "recovery" || 0x00 || nonce`.
The server consumes the nonce before checking the signature. A valid proof returns
the original team/member/device ids only while the team and device/member remain
active. Names are not updated. Old creation signatures still get `connect_key_used`;
that code now directs callers to fresh-challenge recovery. A deleted or suspended
team gets the same 409 as an unavailable key, without a team id. Recovery never
creates/resumes a team or clears a tombstone, and bypasses creation quotas. A team
DB that failed to open needs operator repair/restart, then recovery works. Challenges
are memory-only, capped at 1000 outstanding and 1000 issued per minute globally,
and must be requested again after restart. The Worker applies AUTH_LIMITER to the
challenge route; it does not spend the one-per-minute creation allowance on a
challenge. Recovery POSTs retain the Connect edge limits and count against the
team's request rate. Honor `Retry-After` (the next minute for recovery throttles). Clients
0.5.7/0.5.8 retain their existing request/response shapes; fresh recovery is additive
and needs a future app integration. The explicit operator rollback flag
`--free-connect-key` retains its separately authorized destructive meaning.

**Push (F07).** Four bounded senders use round-robin team queues, one in-flight
question per team, 256 total held jobs including retries, 16 per operator team,
2 per Connect team and 128 for Connect together. Pending qids coalesce. Worker
network/timeouts, HTTP 429/5xx, missing/malformed 200 results, and APNs transient
results retry only the remaining targets with exponential 1..60-second backoff
plus 0..2-second team jitter. Backoff releases the sender. Attempts stop at the
question TTL; each request is bounded by 10 seconds. Final bad-token results mark
the token failed and do not retry. Worker APNs calls and error-body reads abort
after eight seconds (before the relay retry deadline), with error bodies capped
at 4 KiB. Each attempt rechecks the unanswered open question, current
route, live asker/member/recipient, current token and team suspension. Restart
replays up to the newest 256 unanswered open/unexpired questions per active team through the
same admission bounds. This is best-effort replay, not an exactly-once outbox:
queue overflow can drop intent and restart may repeat a previously successful
notification (the constant APNs collapse id coalesces it). No schema change.
APNs acceptance is not proof of device receipt. Existing push audit rows contain
counts/status/reason/device ids, never token values.

**Readiness (F08).** `apassy-relay admin readiness` uses the private operator socket.
It returns `ready`, active team ids with database `readable`/`file_full` checks,
push queue counts, and Connect held/capacity/80-percent high-water status. It exits
1 for an unreadable/missing active team or a full file, 0 otherwise. Public
`/healthz` remains process liveness (`ok`), with no team ids. Unknown tokens and
failed-team tokens keep uniform refusal. Readiness does not prove backup freshness,
restore success, APNs delivery, filesystem writeability or alert delivery; the owner
must select monitoring/alerts separately. Use `admin teams` for detailed file use.

**Reclamation (F09).** `admin connect-sweep` now defaults to dry-run. `--apply`
is required to mutate; `--dry-run` remains explicit and cannot accompany `--apply`.
Each run attempts at most ten suspensions/deletions together, including failures;
`action_limit` and `capped` report the bound. More candidates wait for a later run.
Defaults: suspend after 30 days without a live device sign-in or authenticated use
(creation time if never used), then delete only sweep-suspended teams after another 30 days.
Limits must still equal the Connect preset; operator/upgraded/synced/operator-held
teams are excluded. Failed actions are listed and make the CLI exit 1. Suspensions
still hold a capacity seat; deletion frees it and preserves the key tombstone.

Eligibility is rechecked with directory and team activity locked before suspension.
Before deletion the relay waits for outstanding requests and push jobs, then
refuses a team with recent activity or any sync head. Before automatic deletion,
the full team DB, including every append-only audit
row, is snapshotted to immutable `DATA/audit-archive/<team>-<time>.db`, encrypted
with the relay master key (folder 0700, file 0600), synced and read-verified. Archive
failure prevents deletion. Neither the directory audit nor archived team audits
are pruned. Archives intentionally retain disk use: reclamation frees active-team
capacity, not historical audit storage. Include `audit-archive/` in the owner's
separate encrypted/off-host retention process; the current `admin backup` manifest
covers directory/current team files, not this archive folder. Do not delete archives
without a separate retention decision. Repeated failed deletions can leave multiple
immutable archives; inspect them manually without overwriting history.

Packaged units: `deploy/vps/reclamation/apassy-relay-connect-sweep.{service,timer}`.
After an authorized backup/restore drill, inspect a manual dry-run first. The owner
may install the units into `/etc/systemd/system/`, then enable the timer. It runs
daily at 04:17 UTC with up to 15 minutes jitter and persistent catch-up, logging JSON
and failures to the journal. Its default `SWEEP_MODE=--dry-run` changes nothing.
Only after reviewing candidates/thresholds should the owner create
`/etc/apassy-relay-connect-sweep` with `SWEEP_MODE=--apply`, then inspect the next
service result and readiness high-water counts. No units are installed by this PR.

**Rollout/rollback.** Review the Connect semantics and retention policy, then deploy
only through a separately authorized release. No schema migration is needed.
Rollback to the preceding schema-6/1003 binary restores one-shot pushes and old
Connect retry refusal. Stop/disable the new sweep timer before rollback: the old
CLI has different default sweep semantics and does not support `--apply`. Keep all
immutable audit archives and the master key. No version bump is part of this patch.

## 23. Embedded nodes and the item list of an agent (team schema 7)

An Apassy Mac runs its own node: this relay inside the app, with no edge, listeners on
the loopback only, and a public listener that Tailscale Funnel reaches (docs/SPEC.md
section 30). It is configured in code (`RelayConfig::embedded`), not from the
environment, and it needs no operator. It serves no operator socket: the node
directory belongs to the Mac user, whose coding agents run as the same user, so
`admin` commands (`suspend`, `delete`, `team-code`) are not available there (review
0.5.16, SPEC 30.1). The hosted relay does not change:
`APASSY_RELAY_EDGE_SECRET` stays required, there is no public listener, and the
failed-auth limiter is off.

What changes for the hosted relay at the first start of this version:

- Each team file moves to schema version 7: the relay copies it to
  `teams/<id>.db.pre-v7` (the way back, mode 0600, encrypted like the file), then adds
  the column `agent.items` (`TEXT`, `NULL` for every existing agent) in one transaction.
  The change is additive. A team whose copy cannot be made stays at version 6 and does
  not open; free disk space and start again. The previous image (schema 6) refuses a
  version 7 file. `relay.db` keeps version 1003.
- `agent.items` is `NULL` for every agent that `POST /v1/agents` makes: such an agent
  sees every item of its member's grants, as before. Only an embedded node writes a
  list. No route, body, or answer changes.
- The proxy also drops every `tailscale-*` request header before the upstream.
- New command: `apassy-relay downgrade-schema-6` (23.3).

### 23.1 What to watch

- The relay log at the start: no `cannot be moved to schema version 7`.
- `admin teams`: every team `"open": true`.
- `ls /data/teams/*.db.pre-v7`: one copy for each team that existed before the start.

### 23.2 Owner steps for the deploy

Use the current release runbook at the top of this document; it names the schema 7
rollback in its step 7. Before the deploy, check the free disk: each team file is
copied once (`.pre-v7`). Take a backup (`admin backup`, section 13) as usual.

### 23.3 Rollback

Two ways back to a schema-6 image. Both keep `relay.db`.

**In place (preferred).** It keeps every change since the migration. With the relay
stopped:

```sh
docker compose stop relay
docker compose run --rm --no-deps -T relay downgrade-schema-6 > downgrade.json
jq -e 'all(.[]; .error == null and (.to // 0) <= 6)' downgrade.json && echo "every team is at schema 6"
```

It takes `relay.lock`, so it refuses to run beside a relay. For each team file of
version 7 it revokes every live agent that has an item list (the schema 6 image does
not know `agent.items` and would give such an agent every item of its member's grants),
denies their pending runs, writes an `agent_revoked` row with
`{"reason": "schema_rollback"}`, clears every list, and sets the version to 6. The
empty column stays; the schema 6 image does not read it. A file of another version is
left as it is. `agents_revoked` names how many agents each team lost; on the hosted
relay it is 0, since only embedded nodes make lists. It exits 1 when any team has an
`error`: that team is still at version 7 and the old image cannot open it. Look at its
error, fix it (disk space, the file), and run the command again: a team that is at 6
already is left as it is. Then select the old image in `compose.yaml` and
`docker compose up -d --wait`.

**From the copy.** `cp -p "/data/teams/$id.db.pre-v7" "/data/teams/$id.db"` for each
team with a copy, with the relay stopped. As in section 21.3, the copy is the team at
the migration: every change of access since then comes back undone (revoked devices,
members, agents, and grants work again) and the audit rows since then are gone. Use it
only when the in-place way fails for a team. A team made after the migration has no
copy and is version 7: use the in-place way for it, or suspend it with the new image
first.

A later start of a schema-7 image moves the files to 7 again (a new `.pre-v7`) and keeps
the empty column. Agents revoked by the downgrade stay revoked: their members make new
ones.

## 24. The MCP authorization flow (directory 1004)

An embedded node (section 23) serves the MCP authorization flow (docs/SPEC.md section
31): remote agents register, the owner allows each connection on the Mac, and the
agent gets a 24-hour access token and a 90-day refresh token. The hosted relay does not
serve it: `RelayConfig.oauth` is `None` there, and every `/oauth/...` and
`/.well-known/oauth-...` path stays 404. No variable, route, body, or answer of the
hosted relay changes.

What changes for the hosted relay at the first start of this version:

- `relay.db` moves from version 1003 to 1004 in one transaction: the tables
  `oauth_client`, `connect_request`, and `oauth_refresh` and their indexes. The change
  is additive and the tables stay empty on the hosted relay. A failure leaves 1003 and
  the relay does not start. The image before (directory 1003) refuses a 1004 file: see
  24.3.
- Team files do not change (schema 7).
- New command: `apassy-relay downgrade-directory-1003` (24.3).

On a Mac the node's `relay.db` moves the same way at the first start of the app of this
version. Codes and refresh tokens are kept as SHA-256 hashes only.

### 24.1 What to watch

- The relay log at the start: no error about `relay.db`.
- `admin teams`: every team `"open": true`, as before.
- On a node: relay audit rows of the actor `oauth` (`oauth_client_registered`,
  `connect_requested`, `connect_replaced`, `connect_allowed`, `connect_denied`,
  `oauth_code_redeemed`, `oauth_family_revoked`) and team audit rows `agent_token_issued` and
  `agent_token_dropped`. A run of `oauth_family_revoked` with `code_reused` or
  `refresh_reused` means that someone else used a client's code or token.

### 24.2 Owner steps for the deploy

Use the release runbook at the top of this document. Take a backup (`admin backup`,
section 13) before the deploy, as usual: it holds `relay.db` at 1003.

### 24.3 Rollback

**In place (preferred).** With the relay stopped:

```sh
docker compose stop relay
docker compose run --rm --no-deps -T relay downgrade-directory-1003
```

It takes `relay.lock`, so it refuses to run beside a relay. It drops the three OAuth
tables and sets the version to 1003 in one transaction, and prints
`{"from": 1004, "to": 1003}`; a 1003 file is left as it is (`{"from": 1003, "to":
1003}`). Any other version exits 1 and changes nothing. On the hosted relay the tables
are empty, so nothing is lost. On a node, every client loses its connection: access
tokens already issued work until they end (at most 24 hours), no refresh works, and the
agents connect again after the next upgrade. Run it after `downgrade-schema-6` when both
are needed: that command opens the directory and would move it to 1004 again. Then
select the old image and `docker compose up -d --wait`.

**From the backup.** Restore `relay.db` from the backup of 24.2 with the relay stopped.
As in section 20.3, every change of the directory since the backup comes back undone
(teams made or deleted, their limits, the relay audit). Use it only when the in-place
way fails.

A later start of a 1004 image moves the file to 1004 again, with empty tables.

**An Apassy app before this version on a Mac** refuses the node's `relay.db` at 1004:
its node does not start, and the app has no command for the way back. Start the app of
this version again. (Releases ship all components at one version, so a Mac app is not
downgraded on its own.)


## 25. A node on the tailnet: push handles (team schema 8) and node pairing codes (directory 1005)

A node (the relay inside the Mac app, later `apassy serve` on Linux) serves the devices
of its teams on its tailnet address through a TLS front, signs devices in with its node
origin, makes teams of devices in process or with a one-use node pairing code, and
pushes through the push gateway with per-device handles (docs/SPEC.md section 32). It
is configured in code (`RelayConfig::embedded` with a node origin), not from the
environment. The hosted relay serves none of it: it has no tailnet listener, one
sign-in origin (`APASSY_RELAY_PUBLIC_URL`), and its Worker push as before. No variable
of the hosted relay changes.

What changes for the hosted relay at the first start of this version:

- Each team file moves to schema version 8: the relay copies it to
  `teams/<id>.db.pre-v8` (mode 0600, encrypted like the file), then adds the table
  `push_handle` in one transaction. The change is additive; `push_token` is untouched.
  A team whose copy cannot be made stays at version 7 and does not open; free disk space
  and start again. The previous image (schema 7) refuses a version 8 file.
- `relay.db` moves from version 1004 to 1005 in one transaction: the column
  `team_code.kind` (`operator` for every existing code). The image before (directory
  1004) refuses a 1005 file.
- New routes `PUT` and `DELETE /v1/push/handle`: the hosted relay answers 409
  `push_unavailable` (it has no gateway). Its table of handles stays empty.
- New commands: `apassy-relay downgrade-schema-7` (25.2),
  `apassy-relay downgrade-directory-1004` (25.3), and
  `apassy-relay admin node-code [--minutes <n>]`, which makes a code that only a node
  takes (on the hosted relay `POST /v1/teams` refuses it as `invite_invalid`).

On a Mac the node's team files and `relay.db` move the same way at the first start of
the app of this version.

### 25.1 What to watch

- The relay log at the start: no `cannot be moved to schema version 8` and no error
  about `relay.db`.
- `admin teams`: every team `"open": true`.
- `ls /data/teams/*.db.pre-v8`: one copy for each team that existed before the start.
- `admin readiness` and the push status: the hosted relay keeps `"mode": "worker"`
  (or `off`); a node with a gateway shows `"mode": "gateway"`.
- On a node: team audit rows `push_handle_set`, `push_handle_removed`, `push_sent` with
  `"via": "gateway"`, and `push_failed`. A run of `push_failed {"reason": "clock"}` means
  the node's clock and the gateway's differ by more than 300 s: fix the clock. Relay
  audit rows `node_code_created` and `team_created` with `code_kind` or
  `"kind": "device"`.

Owner steps: use the release runbook at the top of this document; it names these
rollbacks in its step 7. Before the deploy, check the free disk (each team file is
copied once, `.pre-v8`) and take a backup (`admin backup`, section 13) as usual: it
holds `relay.db` at 1004 and the team files at 7.

### 25.2 Rollback of team schema 8

**In place (preferred).** It keeps every change since the migration. With the relay
stopped:

```sh
docker compose stop relay
docker compose run --rm --no-deps -T relay downgrade-schema-7 > downgrade.json
jq -e 'all(.[]; .error == null and (.to // 0) <= 7)' downgrade.json && echo "every team is at schema 7"
```

It takes `relay.lock`, so it refuses to run beside a relay. For each team file of
version 8 it sets the version to 7 and changes nothing else: the schema 7 image never
reads `push_handle`. A file of another version is left as it is. It exits 1 when any
team has an `error`: that team is still at version 8. Fix it (disk space, the file) and
run the command again. To go further back to a schema-6 image, run
`downgrade-schema-6` instead: it takes a file of version 7 or 8 to 6 (23.3). Both
commands open `relay.db` and move it to the directory version of this image, so run any
directory downgrade (25.3, 24.3) after them. Then select the old image in
`compose.yaml` and `docker compose up -d --wait`.

On a node, its devices get no push while it runs the image of schema 7. A later start of
a schema-8 image moves the files to 8 again (a new `.pre-v8`), keeps the handles, and
deletes those of the devices and members revoked meanwhile.

**From the copy.** `cp -p "/data/teams/$id.db.pre-v8" "/data/teams/$id.db"` for each
team with a copy, with the relay stopped. As in section 21.3, every change of access
since the migration comes back undone (revoked devices, members, agents, and grants
work again) and the audit rows since then are gone. Use it only when the in-place way
fails for a team.

### 25.3 Rollback of directory 1005

**In place (preferred).** With the relay stopped, after any team downgrade of 25.2:

```sh
docker compose stop relay
docker compose run --rm --no-deps -T relay downgrade-directory-1004
```

It takes `relay.lock`. It deletes the unused node pairing codes (the image of 1004 would
take one for an operator code) and sets the version to 1004 in one transaction, and
prints `{"from": 1005, "to": 1004}`; a 1004 file is left as it is (`{"from": 1004,
"to": 1004}`). Any other version exits 1 and changes nothing. Used codes stay as
history, and the `kind` column stays: the 1004 image never reads it. On the hosted
relay no node code exists unless an operator made one, so nothing is lost; operator
codes keep working. To go back to an image of directory 1003, run
`downgrade-directory-1003` instead: it takes a 1004 or 1005 file to 1003 with the same
step first (24.3). Then select the old image and `docker compose up -d --wait`.

**From the backup.** Restore `relay.db` from the backup of 25.1 with the relay stopped,
as in 24.3. Use it only when the in-place way fails.

A later start of a 1005 image moves the file to 1005 again and keeps the column.

**An Apassy app before this version on a Mac** refuses the node's files at schema 8 and
`relay.db` at 1005: its node does not start, and the app has no command for the way
back. Start the app of this version again. (Releases ship all components at one
version, so a Mac app is not downgraded on its own.)

## 26. Apassy Connect accounts (directory 1006)

Apassy Connect accounts (ADR 0037 stage 7, contract connect-account-v1, docs/SPEC.md
section 33): accounts, their devices, vault stores (one relay-sync team for each vault),
recovery, and the entitlement token. They are off unless the operator turns them on.

Settings (all optional; the defaults change nothing):

- `APASSY_RELAY_CONNECT_ACCOUNTS=1`: the account routes beside every other route (the
  transition). Without it every account route is 404.
- `APASSY_CONNECT_SIGNING_KEY_FILE=/run/secrets/connect_signing_key`: the Ed25519 key of
  the entitlement token, PKCS#8 (DER or PEM). Make it once with
  `openssl genpkey -algorithm ed25519 -out connect_signing_key.pem` on a machine of the
  owner, keep a copy with the other secrets, and mount it read-only like the master key.
  The well-known document `/.well-known/apassy-connect.json` publishes its public key and
  its id (`ek_` and 16 hex characters of the key's SHA-256). A signing key that this relay
  did not have before signs one hour after its first start with it (services must see it
  published first); until then `GET /v1/account/entitlement` answers 503 `busy`. The first
  key a relay ever has signs at once.
- `APASSY_CONNECT_PUBLISHED_KEYS_FILE=/run/secrets/connect_published_keys.json`: more
  public keys for the well-known document, `{"keys":[{"kid","public_key"}]}` (at most 8;
  each `kid` is the key id of its key). Only the signing key and these are published.
  A rotation: add the next key here and restart; an hour later make it the signing key,
  move the old public key here, and restart; a day later remove the old key and restart.
- `APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY` (default 1000, 0 to 100000; `0`: no new
  accounts) and `APASSY_RELAY_CONNECT_ACCOUNTS_MAX` (default 100000): over either,
  `POST /v1/account` is 503 `busy` with `Retry-After: 3600`. One client prefix (proven by
  the Worker) makes at most 5 accounts a UTC day (429).
- `APASSY_CONNECT_SITE_URL`: the site of the Stripe return pages (default
  `https://apassy.wyderka.cc`).
- `APASSY_RELAY_MODE=connect` is the cutover of R3 (unit C5, section 29), not this step: it
  refuses a master key (`APASSY_RELAY_KEY` and `_FILE` must be unset) and keeps `relay.db`
  and the vault stores as plain files. Do not set it on the running relay before the
  cutover: a keyed `relay.db` does not open plain, and the start fails.

What changes at the first start of this version:

- `relay.db` moves from 1005 to 1006 in one transaction: the table `team` is rebuilt with
  the same rows (the new kind `account` and the columns `account_id`, `vault_id`), and
  the tables of stage 7 are made, empty (accounts, devices, links, joins, the store map,
  the brain events, groups, Stripe, the tunnel, the entitlement keys). A failure leaves
  the file at 1005 and stops the start. The image before (directory 1005) refuses a 1006
  file.
- No team file changes. A vault store, when an account makes one, is a new team file of
  the usual schema.
- The new command `apassy-relay downgrade-directory-1005` (26.3).

Nothing in the new tables is secret: public keys, names, ids, hashes, and Stripe ids.
Account tokens live in memory only (15 minutes; a restart ends them and the devices sign
in again), and link codes and recovery codes never reach the relay.

### 26.1 What to watch

- The relay log at the start: no error about `relay.db`.
- `admin teams`: vault stores appear with `"kind": "account"`; they do not count for
  `APASSY_RELAY_CONNECT_TEAMS_MAX` and `connect-sweep` never touches them.
- Relay audit rows: `account_created`, `account_device_added`, `account_device_revoked`,
  `account_join_requested`, `account_join_refused`, `account_link_created`,
  `account_recovered`, `account_deleted`, `vault_store_created`, `vault_store_deleted`
  (actor `account:<account id>`, ids only), and `auth_failed` refusals of kind
  `account_token`. Many 429 answers of `POST /v1/account/recover` are failed recovery
  signatures: the relay counts five for each account and twenty for each client prefix an
  hour.
- `account_store_removal` rows are removals of a device from a vault store file that
  waited (the store was suspended, or its file refused the write). The device is out of the
  store at once; the row goes when the store opens or a maintenance pass applies it. A row
  that stays with a growing `attempts` names a store whose file does not take writes:
  look at its file cap (`admin teams`).
- The maintenance pass deletes links a day after they end (with their joins) and the
  relay audit rows of accounts after 90 days.
- `brain_event` rows queue the I-4 events for the bouncer brain; nothing sends them yet
  (a later unit). They are small; leave them.

### 26.2 Owner steps for the deploy

Use the release runbook at the top of this document. Before the deploy take a backup
(`admin backup`, section 13): it holds `relay.db` at 1005. To turn the accounts on, add
`APASSY_RELAY_CONNECT_ACCOUNTS=1` and the signing key file to the compose file in a
separate step after the image runs; until then the deploy changes only the directory
version.

### 26.3 Rollback of directory 1006

**In place (preferred).** With the relay stopped, before any team downgrade of 25.2:

```sh
docker compose stop relay
docker compose run --rm --no-deps -T relay downgrade-directory-1005 --delete-vault-stores
```

Without `--delete-vault-stores` a `relay.db` that holds vault stores is refused (exit 1,
nothing changed): those stores may be paid ones of Apassy Connect, so the operator says so
explicitly. `downgrade-directory-1004` and `-1003` take the same flag.

It takes `relay.lock`. In one transaction it deletes the vault store rows (kind
`account`) and their device map and sets the version to 1005; then it deletes the files
of those stores (the snapshots of the accounts' vaults: each Mac pushes its vault again
after the next upgrade). It prints `{"from": 1006, "to": 1005, "vault_stores_deleted":
<n>}`; a 1005 file is left as it is (`{"from": 1005, "to": 1005, ...}`). Any other version
exits 1 and changes nothing. The accounts, their devices, and every other new table stay:
the 1005 image never reads them, and the next start of a 1006 image keeps them, so the
accounts and their devices work again after the upgrade. To go further back, run
`downgrade-directory-1004` or `downgrade-directory-1003` instead: they take a 1006 file
down with the same step first. Then select the old image in `compose.yaml` and
`docker compose up -d --wait`.

**From the backup.** Restore `relay.db` from the backup of 26.2 with the relay stopped,
and delete `teams/<id>.db` and `teams/<id>.sync/` of every vault store (`admin teams`
before the stop lists them with `"kind": "account"`; the 1005 image removes a team file
without a row at its start anyway). Every account made since the backup is gone. Use it
only when the in-place way fails.

A later start of a 1006 image moves the file to 1006 again.

## 27. Connect billing (Stripe)

SPEC section 34; contract `connect-billing-v1` of the core. Billing runs only with the
account routes on (`APASSY_RELAY_CONNECT_ACCOUNTS=1`, section 26) **and** both Stripe files
of 27.1 set; with the routes on and no files, the billing routes answer 503 `busy` and no
account has a plan. Nothing here changes the hosted relay without the owner's
confirmation; the live Stripe account changes only with it.

### 27.1 Keys as files

Two secrets, each in its own file readable by the relay user only (`chmod 0400`), next to
the master key and the edge secret, never in the compose file or the environment:

| File | Content | Setting |
| --- | --- | --- |
| `stripe-key` | A **restricted** key (`rk_live_…`; in a sandbox `rk_test_…`). The relay refuses a live secret key (`sk_live_…`). | `STRIPE_SECRET_KEY_FILE` |
| `stripe-webhook-secret` | The signing secret of the webhook endpoint (`whsec_…`) | `STRIPE_WEBHOOK_SECRET_FILE` |

The restricted key needs these permissions and no other: Checkout Sessions (write: make,
read back, and expire a session), Customer portal (write), Customers (write: the relay
makes each account's customer before its first checkout), Subscriptions (write: item
quantity and cancel; read: the maintenance pass reads a subscription before it deletes
stores, and one whose period ended without an event), Prices and Products (read), Events
(read; for support and the sandbox job). To
rotate either secret: make the new one in the Stripe dashboard, replace the file, restart
the relay, then revoke the old key (or roll the webhook secret with an overlap; Stripe
signs with both while the old one lives, and the relay accepts any matching `v1`).

### 27.2 The webhook endpoint

In the Stripe dashboard (sandbox first, then live), Developers › Webhooks › Add endpoint:

- URL: `https://apassy-relay.wyderka.cc/v1/stripe/webhook` (through the edge Worker).
- API version: `2025-03-31.basil` (the relay's pinned `Stripe-Version`).
- Events: `checkout.session.completed`, `customer.subscription.created`,
  `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.paid`,
  `invoice.payment_failed`. Others are stored and ignored.

The Worker caps this path at 256 KiB and does not rate-limit it (SPEC 34.8). The relay
answers `400` to a bad or stale signature (the clock of the VPS must be right within 5
minutes: check `timedatectl`), and `200` with `duplicate: true` to a repeat. Stripe's
dashboard shows each delivery and its answer; the relay log has one line per event with its
id, type, and effect, never an email.

### 27.3 The Customer Portal

Settings › Billing › Customer portal, in the sandbox and the live account:

- Cancellations: on, **at the end of the billing period**; no immediate cancel.
- Payment methods: update on. Invoices: history on.
- Subscriptions: switch plans on, products Connect Personal and Connect Family (both
  intervals); **quantity changes off** (people and seats change through Connect, SPEC 34.4).
  A switch from Family to Personal ends the family's plan for its members (read-only, then
  suspended; their stores are never deleted for it); the owner pays Personal from the
  switch. A switch back to Family restores the family. Stripe's documentation does not
  say whether a switch keeps the quantity: if Personal arrives with the family's people,
  the relay records the problem `personal_quantity` (27.8) and its next pass sets the
  quantity to 1 at Stripe (27.7). Check the switch in the sandbox and the invoice it makes.
- Settings › Billing › Subscriptions and emails › Manage failed payments: after the last
  retry, **cancel the subscription** or **mark it as unpaid**. A subscription that Stripe
  leaves `past_due` keeps its stores: the relay deletes stores only when Stripe also shows
  the subscription ended.
- Business information: the terms and privacy URLs of the site; the return link is set by
  Connect (`<APASSY_CONNECT_SITE_URL>/connect/done`).

Whether the portal can switch to the tiered Family price is confirmed in the sandbox (plan,
"Not verified"). If it cannot, Personal ↔ Family goes through a new checkout.

### 27.4 The products script

`crates/apassy-relay/scripts/stripe-products.sh` makes the three products
(`apassy_connect_personal`, `_family`, `_team`) and the six prices with their lookup keys,
idempotently: a price whose lookup key exists with the same amounts is kept; other amounts
get a new price that takes the lookup key (`transfer_lookup_key=true`) and the old one is
archived. Every price carries `metadata[apassy_plan]` (`personal`, `family`, `team`); a
price of an earlier run gets it. It needs the Stripe CLI and jq.

A price change moves only new checkouts to the new price. Existing subscriptions keep the
old price until they change plan in the portal; their events then carry no lookup key. The
relay reads their plan from `metadata[apassy_plan]` and the price's interval, or keeps the
plan and interval it stored, and always applies their status: a cancellation, a failed
payment, and an `unpaid` end apply as before. Run the script with `--dry-run` first and
check that it names every replaced price with its metadata.

```sh
stripe login                                   # the sandbox account
crates/apassy-relay/scripts/stripe-products.sh --dry-run
crates/apassy-relay/scripts/stripe-products.sh
# live, only with the owner's confirmation, after the sandbox run was reviewed:
APASSY_STRIPE_OLD_PERSONAL_PRODUCT=prod_… APASSY_STRIPE_OLD_TEAM_PRODUCT=prod_… \
  CONFIRM_LIVE=yes crates/apassy-relay/scripts/stripe-products.sh --live --dry-run
```

The amounts are environment settings of the script (defaults: the owner's prices of
2026-11-03). `APASSY_CONNECT_FAMILY_EXTRA_CENTS` and `_YEAR_CENTS` must be the same for the
script and the relay: the relay refuses Family checkouts (`503 busy`, logged) while tier 2
differs. The relay reads new prices within an hour, or at a restart. `CONNECT_TAX_CODE`
sets the product tax code of new products; otherwise set it in the dashboard (owner step 1
of the plan).

### 27.5 The sandbox job

`.github/workflows/connect-sandbox.yml` runs `tests/connect_billing_sandbox.rs` against the
Stripe sandbox on a test clock (renewal, failed payment, cancellation). Manual only
(`workflow_dispatch`). It needs the repository secret `STRIPE_SANDBOX_KEY` (a test-mode key)
and the sandbox prices of 27.4. Record each run in the pull request as "run on <date>", or
"not run".

### 27.6 Settings

`APASSY_CONNECT_SITE_URL`, `APASSY_CONNECT_FAMILY_EXTRA_CENTS`,
`APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS`, `APASSY_CONNECT_GRACE_DAYS` (14),
`APASSY_CONNECT_READ_ONLY_DAYS` (30), `APASSY_CONNECT_DELETE_DAYS` (90),
`APASSY_CONNECT_AUTO_RAISE_SEATS` (`0`; `1` lets the hourly pass raise a group's quantity at
Stripe to its active members, with a proration; turn it on only with the owner, since it
charges without an action of the group's owner): SPEC 34.7. A
change takes effect at the next start; durations apply to every plan at once, including
plans already lapsed. A bad value, or only one of the two Stripe files, stops the start
with a message that names the setting. No setting points the relay at another Stripe API
than `https://api.stripe.com`.

### 27.7 What the relay does on its own

- **At start:** it reads the six prices from Stripe on a thread of its own (a failure is
  logged as `the Stripe prices could not be read at start` and the next `GET /v1/plans`
  asks again); the start never waits for Stripe.
- **Each hour** (the billing pass, on its own thread `relay-billing`, so a slow Stripe
  never holds the teams' pass): event ids older than 30 days go. A live subscription whose
  period ended more than two days ago without an event is read from Stripe (once a day at
  most) and Stripe's state applies. A live Family or Team subscription without a group is
  bound again, or recorded as `no_group` (27.8). A live Connect Personal subscription with
  a quantity above 1 gets quantity 1 at Stripe. Only with
  `APASSY_CONNECT_AUTO_RAISE_SEATS=1`: a group with more active members than its quantity at
  Stripe gets the quantity raised to them, with prorations; a raise Stripe refuses is
  recorded as `raise_refused` and not asked again until the operator resolves it. By
  default (`0`) the pass raises no quantity: members beyond the paid people or seats stay
  read-only until the owner raises the seats in the app (`POST /v1/account/group/seats`),
  so no higher charge happens without an action of the owner. Each ended plan at its
  deletion day (end + `APASSY_CONNECT_DELETE_DAYS`) is read from Stripe first: only when
  Stripe shows it ended, and the relay's clock is within a day of Stripe's, it loses its
  vault stores and tunnel nodes, with those of its group's active members whose plan is
  over too (never for a plan that is not the group's own, and never while another
  subscription of the group gives a plan). Before anything goes, the relay asks Stripe for
  each such account: an open problem (27.8), a checkout session that Stripe shows open or
  complete, or another subscription of its customer that is not over keeps its data, and
  while the buying account is kept nothing of the plan goes; a Stripe error keeps it too.
  One audit row `plan_stores_deleted` (actor `billing`, counts only, `failed` for accounts
  that could not be deleted, `waiting` for accounts kept) and an I-4 `forget` for each
  account whose data went are written when something went, an account failed, or the plan
  is done. A plan that waits or failed is read from Stripe again a day later; the pass goes
  on with the other plans. The accounts and their devices stay. The rows are in the relay
  audit of `relay.db` (`audit` table); a failed pass logs `the billing maintenance pass
  failed`.
- **After a gap:** when a pass runs more than two days after the last one (the relay was
  down, or the clock jumped), no store is deleted until the operator checks the clock
  (`timedatectl`) and runs `apassy-relay admin billing --resume-deletions` (audit row
  `billing_deletions_resumed`). `apassy-relay admin readiness` shows
  `billing.deletions_held_since` meanwhile.
- **On `DELETE /v1/account`:** every subscription of the account that is not final
  (`unpaid` and `paused` included, and those Stripe lists for its customer) is canceled at
  Stripe first, and an open checkout session ends; if Stripe fails, nothing is deleted and
  the app can ask again.
- **On a join:** an account that joins a family or team has its open checkout session
  ended at Stripe.

### 27.8 Problems for the operator

When Stripe reports a subscription that charges, or a completed checkout, that the relay
cannot apply for a known account or customer (an account bound to another customer, an
account that was deleted, a price that is not Connect's), or a Family or Team subscription
that has no group (`no_group`: its buyer is in another group), a Connect Personal
subscription with a quantity above 1 (`personal_quantity`), or a raise of seats that
Stripe refused (`raise_refused`), the relay answers Stripe 200 and records it: one row in
`billing_problem`, the audit row `billing_problem_recorded` (ids only), and the count
`billing.open_problems` in `apassy-relay admin readiness`. While a problem names an
account, the relay deletes no data of that account for an ended plan.

```sh
apassy-relay admin billing                    # the open problems and the deletion clock
apassy-relay admin billing --resolve <id>     # after the cancel or refund in the dashboard
```

Look the subscription up in the Stripe dashboard by its id, cancel it (and refund if it
charged), then resolve the row. A later event of the same subscription reopens it.

### 27.9 Groups

Family and Team groups (SPEC section 36) need no setting of their own: the webhook makes a
group for a Family or Team subscription, and the invite links use
`APASSY_CONNECT_SITE_URL` (`/connect/join#apassy_gin_…`; the site page reads only the
fragment, which never reaches a server). The relay keeps the SHA-256 of each invite code,
never the code. A support question about a member: `group_member` in `relay.db` names the
group, the role, and the state (`pending` until the owner or an admin confirms).

## 28. The Connect tunnel and the ingress

The broker and the ingress (docs/SPEC.md section 35) run on a relay with the account routes (`APASSY_RELAY_CONNECT_ACCOUNTS=1`, or `APASSY_RELAY_MODE=connect`). `Relay::start` makes the broker, restores this month's usage from `relay.db`, and starts each ingress listener whose address is set; without the account routes nothing of the tunnel exists and every `/v1/tunnel/...` path is 404. The routes: `POST`/`GET /v1/tunnel/nodes`, `DELETE /v1/tunnel/nodes/{node_id}`, `GET /v1/tunnel/node` and `GET /v1/tunnel/dial/{node_id}` (WebSocket upgrades), `POST`/`GET /v1/tunnel/grants`, `DELETE /v1/tunnel/grants/{grant_id}`. Every other route answers an `Upgrade` with 400 `invalid_request`. This section is the plan for the hosted Connect host; the owner does every step.

### 28.1 Ports, DNS, and keys

- `APASSY_CONNECT_INGRESS_LISTEN` (hosted `0.0.0.0:443`) and `APASSY_CONNECT_ACME_LISTEN` (hosted `0.0.0.0:80`): raw TCP listeners on the Connect host, not through the Cloudflare Worker (it carries HTTP only). Open both in the host firewall and publish both ports of the container. Unset, that listener is off. A port that cannot be bound stops the start ("The tunnel ingress cannot listen on …").
- `APASSY_CONNECT_NODE_ZONE` (default and hosted `node.apassy.wyderka.cc`): a DNS-only (grey cloud) wildcard record `*.node.apassy.wyderka.cc` to the Connect host's address. A proxied record would end TLS at Cloudflare and break the ingress.
- The limits of the contract (section 8) are keys with the contract's defaults: `APASSY_CONNECT_TUNNEL_STREAMS` (64), `_NODES` (8), `_DIALS_PER_MINUTE` (60), `_GIB_PER_MONTH` (20 for each person or member), `_PING_SECS` (30), `_IDLE_SECS` (90), `_STREAM_IDLE_SECS` (900), `_STREAM_BUFFER_KIB` (256: the window that Connect grants a node for each stream, at least the 64 KiB of the initial window). The limits of the ingress and of other accounts' dials have keys too: `APASSY_CONNECT_TUNNEL_INGRESS_STREAMS` (16 open `public` streams of an account), `_INGRESS_PER_MINUTE` (60 new `public` streams of a node a minute), `_INGRESS_FIRST_BYTE_SECS` (10), `_INGRESS_GIB_PER_MONTH` (5 for each person or member), `_GRANTEE_STREAMS` (16 open dials of one other account), `_GRANTEE_STREAMS_TOTAL` (32 of all other accounts together; unset, at most half of `_STREAMS`), `_GRANTEE_BYTES_PERCENT` (50). The whole broker: `APASSY_CONNECT_TUNNEL_MAX_STREAMS` (4096 open streams of every account) and `_INGRESS_SHARE_PERCENT` (50: the `public` and `acme` streams of all nodes together hold at most this share of them, so the dials always keep the rest). docs/SPEC.md sections 35.4 and 35.11 have their bounds; a value out of bounds, or a grantee limit above the one it is part of, stops the start with a message that names the key. A change takes effect at the next start.
- The tunnel routes stay behind the Worker. It forwards a WebSocket upgrade only on `GET /v1/tunnel/*`, unchanged, returns the relay's `101` as it is, refuses an upgrade anywhere else, and limits dials with `TUNNEL_LIMITER` (namespace 1007, 60 a minute for each address or IPv6 /64) and node WebSockets with `TUNNEL_NODE_LIMITER` (namespace 1008, 60 a minute, the same key, a budget of its own; `wrangler.jsonc`). The namespace 1008 must be free in the Cloudflare account before the deploy. **Not verified**: whether the Workers VPC binding (`RELAY`) carries WebSocket upgrades. Check it on a staging deploy with one dial before nodes use Connect; if it does not, the fallback is a Cloudflare Tunnel public hostname for `/v1/tunnel/*`, or the routes directly on the Connect host behind its own TLS.
- Let's Encrypt allows 50 new certificates a week for one registered domain; every node is one. A dedicated registered domain for node names keeps the site's and the relay's certificates out of that count.

### 28.2 What to watch

- `IngressHandle::stats` of both listeners (once exported): `rate_limited` and `busy` rising together is one or few addresses flooding; `timeouts` and `malformed` rising is scanning; `unrecognized` is names of no online node; `limited` is accounts at their public or ACME slots, a node at its open rate, or a public budget; `accept_errors` is the host out of descriptors (the loop waits up to 1 s between tries).
- `tunnel_usage` in `relay.db` (`account_id`, `month`, `dials`, `streams`, `bytes`): the counters of each account and month, written every 60 seconds and at stop. A row whose `account_id` is an account id counts all of it; `<account>/ingress` counts its public streams, `<account>/acme` its ACME streams (4 slots of their own, in no budget), and `<account>/dial/<other account>` the dials of another account to its nodes. A deleted account's rows go with it, also its rows as a dialing account. Accounts whose dial bytes (all bytes without the ingress and ACME rows) near 20 GiB for each person or member are near their budget; compare the sum of the account rows with the host's own traffic allowance. Rows older than 13 months are deleted at the start and with each write.
- The relay audit: `tunnel_node_registered`, `tunnel_node_updated`, `tunnel_node_removed`, `tunnel_grant_created`, `tunnel_grant_removed`, `tunnel_grants_ended` (ids only).
- The thread count of the relay process: each open stream uses two threads and each node WebSocket two, bounded by `APASSY_CONNECT_TUNNEL_MAX_STREAMS` (4096) and `max_nodes` (4096). Raise `_MAX_STREAMS` only with the host's thread and memory room measured on the devbox. When ingress connections are refused while dials still open, the ingress share of the broker is full: many nodes have their `public` streams open at once (or strangers hold them, each bounded by its node's open rate and the first-frame deadline); dials keep their own part of the broker.
- Dials that end with 1013 (devices dial again at once with their backoff) mean the recheck could not read plans or grants from `relay.db` for four rounds of 60 s in a row: look at the store first. New dials meanwhile get 503 `busy`.
- Nothing in the logs names a client address or carries stream bytes. If a line ever does, it is a bug: stop and report it. The one tunnel line is "the tunnel usage cannot be written" (a `relay.db` write failed).

### 28.3 Rollback

- The ingress alone: unset the two listen keys and restart; nodes keep their WebSockets for devices, and cloud agents get no answer on 443 and 80.
- The whole tunnel goes only with the account routes (`APASSY_RELAY_CONNECT_ACCOUNTS=0`); nodes reconnect with backoff and devices fall back to the tailnet.
- The tunnel's rows (`tunnel_node`, `tunnel_grant`, `tunnel_usage`) are part of directory 1006 and stay. A restart keeps the month's budgets (the stop writes them). Deleting `tunnel_usage` rows resets budgets: do it only to correct a counting bug, with a backup first.
- The vendored HTTP change (`GET` upgrades reach the handler) stays; `http::handle` refuses an upgrade on every route but the two tunnel routes.

## 29. The end of the free paths, Connect-only mode, and the cutover

SPEC section 37; plan s7 unit C5 and release R3. The owner's runbook, with each production
step, its effect, and its undo, is [docs/operations/connect.md](../../../docs/operations/connect.md);
this section is the operator's reference for the settings and the two commands. Nothing here
changes the hosted relay by itself: each step is the owner's.

### 29.1 The transition switches

Both default to the behaviour before C5, so a self-run relay is unchanged.

| Setting | What the relay does |
| --- | --- |
| `APASSY_RELAY_FREE_CONNECT=0` | `POST /v1/connect` and `/v1/connect/challenge`: 410 `free_connect_ended`. Free Connect teams: their questions, feed, and push routes are 410 `free_connect_ended`; their devices, sign-in, leaving, and relay sync stay |
| and `APASSY_RELAY_CONNECT_SYNC_BYTES=0` (or unset) | Free Connect teams: a push or a receipt is 403 `plan_required` whatever their `sync_bytes`; pulls and downloads work, so their Macs can move the vault |

Operator teams (made with a team code) and vault stores of accounts are never affected.
`admin limits --sync-bytes` on a free Connect team has no effect while both are set. A
change takes effect at the next start.

What to watch: `sync_refused` rows with `plan_required` in the free teams' audits, and 410
answers in the Worker's analytics for `/v1/connect`, `/v1/questions`, and `/v1/feed`: devices
of users who have not moved yet. Undo: unset the setting and restart.

### 29.2 `APASSY_RELAY_MODE=connect`

Only Apassy Connect is served: accounts, vault stores (relay-sync-v1), billing, groups, the
tunnel and its ingress, `/healthz`, and the well-known document; every other route of the
relay answers 410 `hosted_retired` before its body is read; `/p/` and `/mcp` never reach a
handler (no proxy is built). The start refuses `APASSY_RELAY_KEY` and `APASSY_RELAY_KEY_FILE`,
every push setting (`APASSY_RELAY_PUSH_*`), and `APASSY_RELAY_CONNECT_ACCOUNTS=0`. `relay.db`
and the stores are plain SQLite files. `/healthz` sends `x-apassy-relay-mode: connect` beside
the version and the commit. `admin team-code`, `admin node-code`, `init --team`, `migrate`,
`rollback-check`, and every `downgrade-*` command are refused with a message; the way back is
29.6.

The relay does not start on a cutover that is not finished, in either mode, and changes no file
then: a plain `relay.db` beside `relay.db.keyed` is refused in both modes; `connect` mode also
refuses an encrypted `relay.db`. The message says to run the cutover again (29.5) with the
configuration before it. A `cutover.json` that cannot be read or is not `done` stops `connect`
mode only when the files are not those of a finished cutover (then: restore the stopped
backup); on the files of a finished cutover the relay starts, logs it, and leaves the record
as it is. A vault store that does not open at start is logged as out of service with the
advice to keep its file and restore it from a backup, never to delete it.

### 29.3 Backups

- `admin backup` works in both modes; in `connect` mode it copies plain files, and its
  `MANIFEST.json` says `"mode": "connect"`. `snapshot-check` reads plain files there.
- `apassy-relay backup` is the backup of a **stopped** relay (it takes `relay.lock`): a
  byte-for-byte copy of `relay.db`, every file of `teams/` (with the snapshots, `.pre-v*`
  copies, and files of team ids without a row) but the cutover's `.plain` copies of the
  files of a vault store, `team.db`, `team.db.pre-teams`, `relay.db.migrating` and its
  journal, and `audit-archive/`,
  with `MANIFEST.json` (`"stopped": true`, sizes and SHA-256). It refuses while the relay runs,
  while a write journal remains (start and stop the relay once), and on a committed cutover
  (`relay.db` plain beside `relay.db.keyed`). A `relay.db.keyed` beside a keyed `relay.db` (a
  cutover that stopped before its commit point) is left out of it.

```sh
docker compose stop relay
docker compose run --rm --no-deps -T relay backup
```

A restore of either kind: stop the relay, put the backup's `relay.db` and `teams/` (and, from
a stopped backup, its other files) into an empty data volume (owner 10001, mode 0700, files
0600), and start the relay in the mode of the backup (`MANIFEST.json`: no `mode` or
`"relay"` needs the master key of that time; `"connect"` needs none). Check it first with
`docker compose run --rm --no-deps -T relay snapshot-check` on the restored volume.

### 29.4 `apassy-relay connect-cutover`

```sh
docker compose run --rm --no-deps -T relay connect-cutover > cutover-plan.json   # the dry run
docker compose run --rm --no-deps -T relay connect-cutover \
  --confirm-delete-teams "$(jq -r .plan_sha256 cutover-plan.json)"
```

It runs with the configuration **before** the cutover (the master key set, `APASSY_RELAY_MODE`
unset) and the relay stopped. The dry run (the default) checks everything and prints the plan
as JSON (the stores that stay, the teams that go, the files with their hashes, the backup it
checked, and `plan_sha256`, the SHA-256 of that plan and of the relay's version and commit:
a new image needs a new dry run); it writes nothing. A file of a vault store that does not
open with the store's key refuses it before any change (restore it or move it out of the data
directory, then a new stopped backup); `admin delete` never deletes a vault store.
`--confirm-delete-teams <plan_sha256>` goes on only if the plan is still that one (a newer
backup or a changed file refuses it: run the dry run again and read it). It keeps `relay.db`
and the vault stores of the accounts as plain files (a keyed `.pre-v*` copy of a store too),
deletes every other team with its file, snapshots, `.pre-v*` copies, and key, and writes
`cutover.json` in the data directory. It edits and vacuums a keyed working copy of `relay.db`
(`relay.db.work`) and exports only the result: no team key reaches the disk in plain. An error
before the commit point removes the side files it wrote. `--backup <folder>` names the
stopped backup to check; otherwise the newest one is checked. Exit 0 with the JSON on stdout,
or exit 1 with the reason on stderr.

**The backup check:** the stopped backup holds a byte-identical copy (size and SHA-256) of
every file that the cutover keeps or deletes, and its own files still match its
`MANIFEST.json`. Any write to the data directory after the backup (a start of the relay
included) fails it: make the stopped backup right before the cutover. The confirmed run checks
the backup again before each step that deletes (also when it finishes a stopped run): keep the
backup folder in place, unchanged, until the cutover is done.

`cutover.json` holds `state` (`committing` or `done`), the stores kept, the files made plain,
the teams deleted, the counts and the file list with SHA-256 before and after, the rows deleted
from `relay.db`, the files deleted (every file of the list before that is gone), the entries
left, `plan_sha256`, and the backup checked with the SHA-256 of its manifest. Keep a copy with
the backup.

Deleted files are freed blocks, not overwritten ones. What the cutover deletes is SQLCipher or
snapshot ciphertext, and it writes no key in plain, so those blocks open only with the master
key; to leave none at all, restore a stopped backup of Connect into a new volume and destroy
the old one (docs/operations/connect.md, section 9.6).

### 29.5 A cutover that stopped

Run it again with `--confirm-delete-teams <plan_sha256>`: before its commit point (the plain
`relay.db` in place) it starts over; after it, it finishes, with the `plan_sha256` of
`cutover.json`. `relay.db.keyed` exists from the commit point to the end; it is the keyed
directory with the team keys, the second run needs it, and it is deleted only when it is, byte
for byte, the `relay.db` of the inventory. A dry run says which case it is (`state`, `pending`)
and names the plan; after the commit point it makes every check of the confirmed run and
lists `to_convert` and `to_delete`. A plain copy of the stopped run is written again. The
relay does not start in either mode until the run ends with
`"state": "done"` (29.2). The stopped backup restores the relay as it was at any point (29.3).

### 29.6 Rollback from Connect

There is no in-place way back. Stop the relay, restore the stopped backup of the cutover into
an empty volume (29.3), select the previous image and compose settings (relay mode, the master
key, the push settings), start, and read back `/healthz` (`x-apassy-relay-mode: relay`). Every
account change since the cutover is lost with it (accounts, devices, vault stores, Stripe
state). Stripe does not send again an event that the relay already answered: resend the
events of the subscriptions that changed since the backup from the Stripe dashboard
(Developers › Events › the event › Resend), or reconcile them by hand. The Worker goes back
with `RELAY_MODE=relay`.
