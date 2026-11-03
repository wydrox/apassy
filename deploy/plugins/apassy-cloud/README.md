# Apassy for cloud agents

This plugin connects a hosted cloud agent (Grok Bot, Cursor, or another MCP client) to the Apassy app
on your own Mac. The agent can use the API keys that you pick for it, but it never gets their values.
It asks for each run, you allow it on your Mac or iPhone, and your Mac puts the real value into the API
request. No Apassy-run server is on the path: the agent connects to your Mac through Tailscale Funnel.

The wire contract is [docs/contracts/cloud-agents-v1.md](../../../docs/contracts/cloud-agents-v1.md).
The agent's instructions are in [skills/apassy/SKILL.md](skills/apassy/SKILL.md).

## What you need

- A Mac with Apassy (the version of this plugin or later), unlocked, awake, and online while the agent
  works.
- Tailscale on the Mac, signed in, with Funnel allowed for this Mac in your tailnet policy.
- The items that the agent may use, in your Apassy vault, each with a variable and its API hosts.

## 1. Make the setup in Apassy (each user)

1. Open Apassy → **Settings** → **Cloud agents**.
2. Turn on **Public route (Tailscale Funnel)**. Apassy asks you to confirm with Touch ID or the
   passphrase. It shows the URL
   `https://<Mac>.<tailnet>.ts.net:8443/mcp`. The machine name and the tailnet name become public in
   the Certificate Transparency logs when the route is on.
3. Click **Add a cloud agent…**. Give it a name, pick its kind (Grok Bot or another MCP client), pick
   the items it may use, and pick the token lifetime (30, 90, or 365 days).
4. Click **Copy setup**. Apassy shows the token once. The setup holds two values:
   - the MCP URL: `https://<Mac>.<tailnet>.ts.net:8443/mcp`
   - the header: `Authorization: Bearer apassy_tagt_…`

Keep the token like a password. Do not commit it, and do not paste it into a shared chat. To stop the
agent, click **Revoke…** next to it. The next call of the agent fails.

## 2. Grok Bot

Grok Bot adds a custom MCP server when you ask it in chat. In a chat with the Bot, send:

```text
Add a custom MCP server named "apassy" with the URL https://<Mac>.<tailnet>.ts.net:8443/mcp
and the header Authorization with the value "Bearer apassy_tagt_…".
```

Use your own URL and token from **Copy setup**. Grok Bot keeps the header on the server entry. The
server entry is for your whole account, not for one chat. Then ask the Bot:

```text
Use Apassy: list the credentials that you can use.
```

## 3. Cursor

Set two variables in the environment of Cursor, with your values from **Copy setup**:

```sh
export APASSY_MCP_URL="https://<Mac>.<tailnet>.ts.net:8443/mcp"
export APASSY_TOKEN="apassy_tagt_…"
```

The plugin's [`mcp.json`](mcp.json) declares the remote server `apassy` with
`"url": "${APASSY_MCP_URL}"` and `"Authorization": "Bearer ${APASSY_TOKEN}"`.

> **Not verified:** this interpolation syntax (`${NAME}`) is not yet verified in Grok Bot or in Cursor.
> Some clients use another form (for example `${env:NAME}`), and Grok Bot may use only the URL and the
> header that you give it in chat (section 2). If a client sends the text `${APASSY_TOKEN}` as it is,
> the node answers 401: put the URL and the header into the client's own MCP setting instead.

## 4. A team marketplace (Cursor)

To give this plugin to your team before it is in a public marketplace:

1. Mirror this directory (`deploy/plugins/apassy-cloud/`) to its own Git repository, with
   `.cursor-plugin/plugin.json` at the root.
2. In the Cursor dashboard, open **Plugins & MCPs** → **Add Marketplace** → **Import from Repo**, and
   pick that repository.
3. Each user then does section 1 and section 3 with their own Mac and token. A token is for one user's
   Mac only. Never share one token in a team.

## Files

| File | Contents |
| --- | --- |
| `.cursor-plugin/plugin.json` | The plugin manifest: name `apassy`, version, author, homepage, license |
| `mcp.json` | The remote MCP server `apassy`, from your URL and token |
| `skills/apassy/SKILL.md` | How an agent uses Apassy: list, request, wait, run, never print |
| `LICENSE` | Apache-2.0, as the repository |

## Releases

This directory follows the version of the repository (`release-versions.json`), but it is not one of the
six release components. A public marketplace listing is published separately, only after the release is
live and with the owner's OK. The listing draft is
[docs/store/grok-bot-submission.md](../../../docs/store/grok-bot-submission.md).

## License

Apache-2.0, the same as the Apassy repository. See [LICENSE](LICENSE).
