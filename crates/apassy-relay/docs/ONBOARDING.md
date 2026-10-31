# Apassy team relay — alpha guide

This guide is for a team owner and a member.
The relay URL is `https://apassy-relay.wyderka.cc`.
The CLI is `apassy-team`.

## Install

Run these commands on the owner's machine and each member's machine.

```sh
curl -fsSL https://apassy-relay.wyderka.cc/install.sh -o install.sh
sh install.sh
```

The installer checks the SHA-256 checksum before it installs the CLI.
It installs the CLI in `$HOME/.local/bin`.
It prints the installed path and the version.
If that directory is not in `PATH`, use the line that the installer prints.

The first binaries are for macOS ARM64 (`darwin-arm64`) and Linux x86-64 (`linux-x86_64`).
If your binary is not available, the installer stops with an error.
Use `APASSY_RELAY_URL` to change the download URL.
Use `APASSY_INSTALL_DIR` to change the install directory.
The installer refuses root unless `APASSY_INSTALL_AS_ROOT=1`.
It does not use `sudo`.

## Create a team (owner)

Get a one-time team code from the relay operator.
The code starts with `apassy_tcd_`.
Save the code in `team-code-file`.
Replace `NAME` with the team name.
Replace `OWNERNAME` with the owner's name.

```sh
apassy-team create --relay https://apassy-relay.wyderka.cc --team "NAME" \
  --name OWNERNAME --device "Owner laptop" < team-code-file
apassy-team me
```

`create` always makes an owner device and saves the team as current.
This device becomes the team's key holder.
The CLI does not create a new owner token.
Each member command signs in with the device key.
The access token lasts 15 minutes and stays only in process memory.
The CLI stops if the relay's sign-in origin differs from the saved URL.

The CLI reads secrets from stdin, never from command arguments.
This applies to team codes, invite codes, device-link codes, item values, and legacy tokens for `init`.
The CLI refuses to read a secret from a terminal.
Use a file as stdin, as shown above.
Agent tokens use `APASSY_TOKEN` in the environment.

## Select a team and protect device keys

Settings version 2 keeps several teams in one file.
The path is `$XDG_CONFIG_HOME/apassy-team/settings.json` or `~/.config/apassy-team/settings.json`.
The directory has mode 0700. The file has mode 0600.
The CLI reads old settings and writes version 2 at the next save.

```sh
apassy-team team list
apassy-team team use TEAM_ID
apassy-team --team TEAM_ID me
APASSY_TEAM=TEAM_ID apassy-team me
```

Replace `TEAM_ID` with the team ID.
`--team ID` selects a team for a member command.
Otherwise, `APASSY_TEAM` selects it, then the current team.
In `create --team NAME`, `--team` gives the new team's name.

On macOS, the login Keychain stores the device private key.
Its service is `apassy-team`. Its account is `<relay host> <team id> <settings dir>`.
The settings directory is an absolute path.
On other systems, `device-<team id>.key` stores the key next to `settings.json`, with mode 0600.
The CLI never prints this key or puts it in `settings.json`.

To use file storage on macOS, set `APASSY_TEAM_KEY_STORE=file` before you make or enroll the device.
The CLI saves the key in `device-<team id>.key` next to `settings.json`, with mode 0600.
Use this variable for all foreground commands with the device.
The CLI does not copy a key from the Keychain to the file store.
Tests must not use the real login Keychain.

`create`, `join`, and `device link` stop if the team has a key or settings entry in this directory.
Do not remove a saved key to bypass this check.
For a different member of the same team on macOS, use a different `XDG_CONFIG_HOME`.
Each configuration directory uses a different Keychain account for the same relay and team.

## Enroll a legacy member

A legacy team from `apassy-relay init` has an owner token.
Legacy member tokens expire 14 days after team creation or migration to server schema version 3.
Enroll a device before this period ends.
Use a configuration directory without an enrolled device for this team.
`init` and `device enroll` do not change the current team.
Keep `APASSY_TEAM_TOKEN` set until enrollment succeeds.

```sh
export XDG_CONFIG_HOME="$HOME/.config/apassy-device"
export APASSY_RELAY_URL=https://apassy-relay.wyderka.cc
export APASSY_TEAM_TOKEN="$(cat owner-token-file)"
apassy-team device enroll --name "Owner laptop"
unset APASSY_TEAM_TOKEN
apassy-team team use TEAM_ID
apassy-team me
```

Replace `TEAM_ID` with the team ID from the enrollment output.
If enrollment stops before the result is known, run `apassy-team device enroll` again.
Keep the same configuration directory for the retry.
The CLI uses the same saved key for the retry.
If the enrollment request returns an HTTP error, the CLI removes the new key.
`device enroll` stops if this directory has an enrolled device for the team.

Enrollment removes the member token from the settings.
The relay invalidates that member's old token.
The first device becomes the key holder only for the sole live owner when no key holder exists.
If item keys already exist, copy `keys.json` into the new configuration directory before you start the host.
Keep the new `XDG_CONFIG_HOME` for later commands and the host service.

After enrollment, make a new agent token:

```sh
apassy-team agent create NAME --days 30 > agent-token-file
```

Replace `NAME` with the name of the agent.
Use the new token for the agent.
Legacy `apassy_agt_` tokens without a team ID stop at the member-token deadline of the team.
Enrollment does not extend this deadline.

## Add members

Owner: make a collection, then make an invite link.
Replace `1` with the collection ID.

```sh
apassy-team collection create payments
apassy-team invite --role member --name bob --grant 1 > invite-link-file
```

`invite` prints `<relay URL>/join#<code>` once.
Send the file to the member through a private channel.
The invite code works once.

Use `--name NAME` to set the member's name.
Repeat `--grant ID` for more collection grants.
Use `--shared` only for role `member` on a shared device.
Only an owner can invite a manager or another owner.

Member: read the invite link or raw code from stdin.
If the invite has no name, add `--name NAME`.

```sh
apassy-team join --relay https://apassy-relay.wyderka.cc \
  --device "Bob laptop" < invite-link-file
```

The CLI saves the device key before it sends the request.
It prints two safety words and checks them against words it computes locally.
If the words differ, the CLI stops.
Tell the inviter these words through a trusted channel.

Owner: list requests, then confirm with the words from the member.

```sh
apassy-team joins
apassy-team confirm JOIN_ID --words "W1 W2"
```

Replace `JOIN_ID` with the request ID.
Replace `W1 W2` with the member's words.
`--words` is mandatory.
`joins` does not print safety words.
Never confirm from the list or from the invite code alone.
Use `apassy-team refuse JOIN_ID` to refuse a request.

The member's command waits up to 10 minutes for confirmation.
A pending join can remain open for 72 hours.
Use `--no-wait` to return immediately.
Use `apassy-team join --resume` to wait again.
After an uncertain request result, the CLI uses the same saved key.

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

After confirmation, the member can check access:

```sh
apassy-team me
```

For a later collection grant, find the member ID and make the grant:

```sh
apassy-team members
apassy-team grant --collection 1 --member 2
```

## Add another device

Shared members cannot make device links.

On an existing device, make a link code:

```sh
apassy-team device add > device-link-code-file
```

Send the file to the new device through a private channel.
On the new machine, read the code from stdin:

```sh
apassy-team device link --relay https://apassy-relay.wyderka.cc \
  --device "Second laptop" < device-link-code-file
```

Get the safety words from the new device.
On the existing device, list requests and confirm with those words:

```sh
apassy-team device pending
apassy-team device confirm LINK_ID --words "W1 W2"
```

Replace `LINK_ID` with the request ID and `W1 W2` with the new device's words.
`device pending` does not print safety words.
Device links expire after 10 minutes.
Use `--no-wait` to return immediately, then `apassy-team device link --resume` to wait again.
Use `device refuse LINK_ID` to refuse a link.
Use `device list` to see devices and `device revoke DEVICE_ID` to revoke one.

## Add credentials

Owner: add items on the key-holder machine that runs `apassy-team host`.
Use the collection ID from the previous section.
Save the API key in `value-file`.
Add a Stripe staging key:

```sh
apassy-team item add --collection 1 --name "Stripe test" --env STRIPE_API_KEY \
  --environment staging --provider stripe < value-file
```

For another HTTP API, use its exact API host instead of a provider:

```sh
apassy-team item add --collection 1 --name "API test" --env API_KEY \
  --environment staging --host api.example.com < value-file
```

Replace `api.example.com` with the API host.
Replace `API_KEY` with the environment variable that your tool reads.
For a production key, use `--environment production`.
The host asks the owner before every run with a production item.
Use the item ID that the CLI prints in the run command below.

The CLI seals the value on the key-holder machine.
It keeps item keys in `keys.json` next to `settings.json`.
This file remains plain text, with mode 0600.
Make a backup of this file.
Keep the backup separate from the relay's vault backup.
If you lose the keys, add the items again.

A second owner device does not become the key holder automatically.
Before you move the key-holder flag, copy `keys.json` to the new owner's device.
Protect the copy with mode 0600.
On the current key-holder device, move the flag:

```sh
apassy-team device key-holder DEVICE_ID
```

The command moves the flag, not the item keys.

## Let agents use them

Owner or member: make an agent token file.
Replace `NAME` with the name of the agent.

```sh
apassy-team agent create NAME --days 30 > agent-token-file
```

Keep the token file private.
Read the token into `APASSY_TOKEN`.
Keep the key-holder host online before you start a run.
Replace `1` with the item ID:

```sh
APASSY_TOKEN="$(cat agent-token-file)" apassy-team run --items 1 \
  --purpose "Check the balance" --request "Show me the Stripe balance" \
  -- stripe balance retrieve
```

The alpha supports only HTTP API keys.
The tool must accept a base URL.
The run gives the tool a placeholder and a relay base URL.
The tool must send API requests to that base URL.
The base URL variables are `APASSY_BASE_<NAME>`, `STRIPE_API_BASE`, `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, and `GITHUB_API_URL`.
The alpha does not support the `gh` CLI, database URLs, or compressed responses.

For remote MCP, set the token in the client's environment:

```sh
export APASSY_TOKEN="$(cat agent-token-file)"
```

Put this configuration in `.mcp.json`:

```json
{
  "mcpServers": {
    "apassy": {
      "type": "http",
      "url": "https://apassy-relay.wyderka.cc/mcp",
      "headers": {
        "Authorization": "Bearer ${APASSY_TOKEN}"
      }
    }
  }
}
```

With MCP, the agent must run the command with `session.env` from the relay.
Each MCP run also waits for the key-holder host.

## Keep the host running

After an update to `apassy-team`, macOS can show one Keychain prompt for access to the device key.
Before you start the background host, run `apassy-team me` in a terminal.
If macOS shows this Keychain prompt, select **Always Allow**.
The background host cannot run before you select **Always Allow**.

The foreground host can also use file storage.
For a host service with file storage, set `APASSY_TEAM_KEY_STORE=file` in the service environment before the host starts.
A shell setting does not set the service environment.

Owner: install the host service on the key-holder machine with `keys.json`:

```sh
apassy-team host install
apassy-team host status
```

The service starts at login and uses desktop dialogs. Each saved team has its own
service and log. Use `apassy-team --team TEAM_ID host install`, `host status`, or
`host uninstall` to manage that team; changing the current team does not replace a
previous team's service. Installing also migrates a pinned legacy single service
to its original team's name, preserving its options. An unpinned/custom legacy file
requires manual identification before migration; its file is retained on failure.
Use `apassy-team --team TEAM_ID host uninstall` to stop and remove one team's service.
Explicit-team status/removal also work after saved credentials were removed, without
contacting the relay.
After a CLI update, run `host install` for each team to restart its running host,
then `host status`. `cli_version` is the CLI being queried; the service startup log
prints the actual host version. Replacing a binary alone does not restart hosts.
For a foreground host with terminal prompts, keep this command active:

```sh
apassy-team host
```

Use `apassy-team host --dialog` for foreground desktop dialogs.
The host signs in with the selected team's key-holder device.
One host serves one team.
Another owner device cannot release the keys.

Every run waits for the host.
The host can release a known safe command with non-production items without a question.
For other runs, the terminal asks:

```text
Release the keys for run N? [y/N]
```

Read the command, the purpose, the request, and the items before you answer.
Enter `y` only if you permit the run.

In a desktop dialog, only `Release` releases keys.
`Deny` is the default button.
Return, Escape, a closed dialog, or a dialog error denies the run.
A timeout expires the request without a release.
A production item always requires the owner's answer.
The host must be online for every run.

## What the alpha does not protect

The relay operator or root on the VPS can read each team's metadata.
This includes team, member, collection, and item names, hosts, commands, and audit records.
The operator cannot read stored item values without the item keys.
Stored item values stay sealed with keys on the key-holder machine.
The relay opens item values in memory for a run that the host permits.

Cloudflare sees traffic in clear.
Old settings can retain invalid legacy member tokens in plain text after enrollment.
Device access tokens stay only in process memory.
Item keys remain plain text in `keys.json`.
With file storage, anyone who reads a device key file can use that device until revocation.
Protect these files and the key-holder machine.

Safety words do not protect against the relay operator or a party in the network path.
Always get the words from the person with the new device before confirmation.
Keep two owners with separate devices to reduce the risk of losing all owner access.
The operator cannot add an owner device through the relay.

The key-holder host must be online for every run.
This is an alpha with no SLA.
Relay backups are daily.
You must also make a backup of the host's `keys.json` file.

## Get help

Contact the relay operator who gave you the team code.


## Script output and installer updates

Add `--json` anywhere before a child command's `--` delimiter for one JSON document
on stdout. Successful finite commands return `{"ok":true,"result":...,"exit_code":0}`;
errors return `{"ok":false,"error":{"code":"...","message":"...","status":null,
"retryable":false,"retry_after":null},"exit_code":2}`. HTTP refusals retain their
code/status and numeric Retry-After seconds when supplied; unknown values are null.
Progress goes to stderr. Lists now use this envelope too: use `.result` instead of
reading an old bare array/object. Mutations return their ids/state. Invite URLs,
agent tokens and device-link codes occur once under `result.url`, `result.token`
or `result.code`, never on stderr. Keep those outputs private as before.

Exit codes remain 0 success, 2 usage/local setup, 3 denied/timed out, and 4 relay or
transport failure. For `run --json`, `result.child_exit_code` and the process exit
code preserve the child's code (including 128 + signal); child stdout/stderr both
go to stderr so stdout remains one document. Child flags after `--` are untouched.
MCP and foreground `host` use streaming protocols and reject the JSON wrapper.
For example: `apassy-team --json --team TEAM_ID device list` and
`apassy-team --json collection create Secrets`.

The installer supports macOS arm64 and Linux x86_64 only, and rejects other pairs
before fetching anything. curl has a 10-second connect / 120-second total deadline;
the wget fallback requires GNU timeout/gtimeout (120 seconds, kill after 5 more).
After checksum verification, staged `--version` must execute and identify
`apassy-team` before atomic replacement. A validation failure leaves the previous
binary in place. Successful updates print restart/status commands for detected
per-team services and guidance for legacy/foreground hosts. No service restarts
without the user's explicit `host install` invocation.
