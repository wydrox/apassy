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
apassy-team create --relay https://apassy-relay.wyderka.cc --team "NAME" --name OWNERNAME < team-code-file
apassy-team me
```

The CLI reads secrets from stdin, never from command arguments.
This applies to team codes, invite codes, item values, and tokens.
The CLI refuses to read a secret from a terminal.
Use a file as stdin, as shown above.

## Add members

Owner: make an invite code file.

```sh
apassy-team invite --role member > invite-code-file
```

Send the file to the member through a private channel.
The invite code works once.
Member: replace `NAME` with your name.
Use the invite code file to join the team.

```sh
apassy-team join --relay https://apassy-relay.wyderka.cc --name NAME < invite-code-file
apassy-team me
```

Owner: find the member ID.

```sh
apassy-team members
```

Create a collection for the credentials.

```sh
apassy-team collection create payments
```

Give the member access to that collection.
Replace `1` with the collection ID.
Replace `2` with the member ID.

```sh
apassy-team grant --collection 1 --member 2
```

## Add credentials

Owner: add items on the machine that will run `apassy-team host`.
Use the collection ID from the previous section.
Save the API key in `value-file`.
Add a Stripe staging key.

```sh
apassy-team item add --collection 1 --name "Stripe test" --env STRIPE_API_KEY \
  --environment staging --provider stripe < value-file
```

For another HTTP API, use its host instead of a provider.
Use the exact API host.
Replace `api.example.com` with that host.
Replace `API_KEY` with the environment variable that your tool reads.

```sh
apassy-team item add --collection 1 --name "API test" --env API_KEY \
  --environment staging --host api.example.com < value-file
```

For a production key, use `--environment production` instead of `--environment staging`.
The host asks the owner before every run with a production item.
Use the item ID that the CLI prints in the run command below.

The CLI seals the value on the owner's machine.
It keeps the key in `~/.config/apassy-team/keys.json`.
Make a backup of this file.
Keep the backup separate from the relay's vault backup.
If you lose the keys, you must add the items again.

## Let agents use them

Owner or member: make an agent token file.
Replace `NAME` with the agent's name.

```sh
apassy-team agent create NAME --days 30 > agent-token-file
```

Keep the token file private.
Read the token from the file into `APASSY_TOKEN`.
Keep the owner's host online before you start a run.
Replace `1` with the item ID.

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

For remote MCP, set the token in the client's environment.

```sh
export APASSY_TOKEN="$(cat agent-token-file)"
```

Put this configuration in `.mcp.json`.

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
Each MCP run also waits for the owner's host.

## Keep the host running

Owner: run the host on the machine with `keys.json`.
Keep this command active in a terminal.

```sh
apassy-team host
```

Every run waits for the owner's host.
The host can release a known-safe command with non-production items without a question.
For other runs, the host asks:

```text
Release the keys for run N? [y/N]
```

Read the command, the purpose, the request, and the items before you answer.
Enter `y` only if you permit the run.
A production item always requires the owner's answer.
The host must be online for every run.

## What the alpha does not protect

The relay operator or root on the VPS can read each team's metadata.
This includes team, member, collection, and item names, hosts, commands, and audit records.
The operator cannot read stored item values without the owner's keys.
Stored item values stay sealed with keys on the owner's machine.
The relay opens item values in memory for a run that the host permits.

Cloudflare sees traffic in clear.
Tokens are plain text in `~/.config/apassy-team/settings.json`.
Item keys are plain text in `~/.config/apassy-team/keys.json`.
Protect these files and the owner's machine.

The owner's host must be online for every run.
This is an alpha with no SLA.
Relay backups are daily.
You must also make a backup of the owner's `keys.json` file.

## Get help

Contact the relay operator who gave you the team code.
