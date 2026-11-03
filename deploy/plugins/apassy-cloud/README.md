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

## 1. Turn on remote access in Apassy (each user)

1. Open Apassy → **Bouncer** → **Agents**.
2. Turn on **Remote access**. Apassy asks you to confirm with Touch ID or the passphrase. It shows the
   MCP address `https://<Mac>.<tailnet>.ts.net:8443/mcp` and a **Copy** button. The machine name and
   the tailnet name become public in the Certificate Transparency logs when remote access is on.

That is all the setup. You give the agent the address only: no token, no header.

## 2. Connect the agent: add the MCP server by URL, press Authorize, allow on your Mac

1. In the agent, add a remote MCP server by URL: the MCP address from step 1.
2. The agent offers to sign in: press **Authorize** (or **Connect**). A browser page of your Mac opens.
   It shows the agent's name, your Mac, and a short code such as `K7Q-4MD`. The page has no button:
   nothing on it can allow the connection.
3. On your Mac, **Bouncer** → **Decisions** shows "<agent> wants to connect" with the same code (also on
   your iPhone, when it gets your questions). Check that the codes match, then click **Allow** and
   confirm with Touch ID (Face ID on the iPhone). Click **Deny** when you did not start it.
4. The browser page says "Connected", and the agent lists the tools `apassy_list_access`,
   `apassy_request_run`, and `apassy_run_status`.

The agent appears in **Bouncer** → **Agents** with a **Remote** cap and no credentials. Click **Choose
Credentials…** on its page to pick the items it may use. Every run of a remote agent still asks you, on
the Mac or the iPhone.

The request ends after 5 minutes without an answer: press Authorize again. Allow only a request whose
code the browser page shows, and deny any request that you did not start. Each allowed connect makes a
new Apassy agent with no credentials, also for an agent that connected before: the second one is
"Grok Bot 2". Disconnect the old one when you no longer need it. To stop an agent, click
**Disconnect…** on its page: its next call fails with 401, and it must connect and be allowed again.

### Grok Bot

In a chat with the Bot, send:

```text
Add a custom MCP server named "apassy" with the URL https://<Mac>.<tailnet>.ts.net:8443/mcp.
```

Use your own address. Press **Authorize** when the Bot offers it, and allow on your Mac (step 2). The
server entry is for your whole account, not for one chat. Then ask the Bot:

```text
Use Apassy: list the credentials that you can use.
```

### Cursor

Set the address in the environment of Cursor:

```sh
export APASSY_MCP_URL="https://<Mac>.<tailnet>.ts.net:8443/mcp"
```

The plugin's [`mcp.json`](mcp.json) declares the remote server `apassy` with
`"url": "${APASSY_MCP_URL}"`. Cursor then shows **Needs login** or **Connect** for it: press it and allow
on your Mac (step 2).

> **Not verified:** this interpolation syntax (`${NAME}`) is not yet verified in Grok Bot or in Cursor.
> Some clients use another form (for example `${env:NAME}`). If a client sends the text
> `${APASSY_MCP_URL}` as it is, put the address into the client's own MCP setting instead.

## 3. A client without the authorization flow (token fallback)

A client that cannot sign in with the MCP authorization flow (OAuth 2.1) can use a bearer token. With
remote access on, in Terminal:

```sh
eval "$(apassy login)"
apassy agent add-remote "My agent" --days 90
```

Apassy asks you to confirm with Touch ID, then prints the token once with the MCP address. Give the
client the address and the header `Authorization: Bearer apassy_tagt_…`. The token lives 1 to 365 days
(default 90). The agent has no credentials until you choose some, and every run asks you. Keep the
token like a password: do not commit it, and do not paste it into a shared chat.

## 4. A team marketplace (Cursor)

To give this plugin to your team before it is in a public marketplace:

1. Mirror this directory (`deploy/plugins/apassy-cloud/`) to its own Git repository, with
   `.cursor-plugin/plugin.json` at the root.
2. In the Cursor dashboard, open **Plugins & MCPs** → **Add Marketplace** → **Import from Repo**, and
   pick that repository.
3. Each user then does sections 1 and 2 with their own Mac. A connection (or a fallback token) is for
   one user's Mac only. Never share one token in a team.

## Files

| File | Contents |
| --- | --- |
| `.cursor-plugin/plugin.json` | The plugin manifest: name `apassy`, version, author, homepage, license |
| `mcp.json` | The remote MCP server `apassy`, from your MCP address; it signs in with the authorization flow |
| `skills/apassy/SKILL.md` | How an agent uses Apassy: list, request, wait, run, never print |
| `LICENSE` | Apache-2.0, as the repository |

## Releases

This directory follows the version of the repository (`release-versions.json`), but it is not one of the
six release components. A public marketplace listing is published separately, only after the release is
live and with the owner's OK. The listing draft is
[docs/store/grok-bot-submission.md](../../../docs/store/grok-bot-submission.md).

## License

Apache-2.0, the same as the Apassy repository. See [LICENSE](LICENSE).
