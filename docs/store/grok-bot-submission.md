# Grok Bot Marketplace submission (draft)

Date: 2026-11-03. Status: DRAFT.

> **DO NOT SUBMIT.** Submit only when the release with cloud agents is live on all six components
> (AGENTS.md) and the owner says yes. The owner decided on 2026-11-03: list Apassy in the owner's
> private team plugins now; submit publicly only after the release and the owner's OK
> ([plan](../design/implementation-plan-0037-cloud-agents.md), owner decision 3). The Grok Bot
> Publisher Terms apply to a submission: the owner reads and accepts them, not an agent.

Form: `x.ai/bot/marketplace/submit-a-plugin`. The plugin is
[`deploy/plugins/apassy-cloud/`](../../deploy/plugins/apassy-cloud/README.md), mirrored to a public
repository before the submission.

## Form fields

| Field | Value |
| --- | --- |
| Name | Apassy |
| Work email | The owner fills it in. |
| Organization name | The owner fills it in. |
| Organization handle | The owner fills it in. |
| Website | https://apassy.wyderka.cc |
| Logotype URL | A public URL of a 1:1 logo (see "Logo" below). |
| Where to list | Grok Bot, and Cursor. Not Grok. |
| MCP server URL or public GitHub repository | The public mirror repository of `deploy/plugins/apassy-cloud/` (there is no shared server URL: each user has their own Mac's URL). |
| Brief description | The short description below. |
| Testing instructions | The section "Testing instructions" below. |
| "Tested locally and in-app" | Tick it only after the owner ran the test below in Grok Bot with the released app. |

## Short description

Use the API keys in your own Apassy vault from Grok Bot, without giving the Bot the keys. You allow
each run on your Mac or iPhone.

## Long description

Apassy is an open source password and API key manager for people who work with AI agents. With this
plugin, Grok Bot can call an API with your key, but it never sees the key.

- You pick which credentials the Bot may use, in Apassy on your Mac.
- The Bot asks for a run with the exact command, its purpose, and your request.
- Apassy asks you on your Mac or iPhone. Nothing runs until you allow it.
- The Bot gets placeholders and a base URL, not the values. Your Mac puts the real value into the API
  request, only for the API hosts of that credential, and puts the placeholder back in the answer.
- No Apassy server is on the path. The Bot connects to your own Mac through Tailscale Funnel. You can
  turn the route off, or revoke the Bot, at any time.

You need a Mac with Apassy and Tailscale. Apache-2.0. Source: https://github.com/wydrox/apassy

## Logo

- 1:1, SVG or PNG. A PNG has a background plate (not transparent).
- Source: `packaging/AppIcon.svg` (the app icon), or `design/promo/launch/logo/apassy-icon-light.svg`.
  Export it at 1:1 and put it at a stable public URL (for example on the website).
- The owner checks the file before the submission.

## Testing instructions

Text for the form:

> A reviewer needs a Mac (macOS 15 or later, Apple silicon) with Apassy and Tailscale. Apassy runs on the reviewer's
> own Mac, and Grok Bot connects to it through Tailscale Funnel. Use only the synthetic credential below.
>
> **Setup on the Mac (about 10 minutes)**
>
> 1. Install Tailscale, sign in, and allow Funnel for this Mac in the tailnet policy (Tailscale admin
>    console → Access controls: the `funnel` node attribute for this Mac).
> 2. Install Apassy from https://apassy.wyderka.cc, create a vault, and add a synthetic item:
>    name `httpbin test`, value `httpbin-test-7f3a9c1e5b2d4f60a8e1c3b5d7f9a2c4`, variable
>    `HTTPBIN_TOKEN`, host `httpbingo.org`. If Apassy says that `httpbingo.org` is a whole domain, allow it
>    for this test item.
> 3. In Apassy → Settings → Cloud agents, turn on **Public route (Tailscale Funnel)**. Click
>    **Add a cloud agent…**, name it `Grok Bot`, kind Grok Bot, pick only `httpbin test`, and click
>    **Copy setup**. Keep Apassy open and the vault unlocked during the test.
>
> **In Grok Bot**
>
> 1. Prompt: `Add a custom MCP server named "apassy" with the URL <the MCP URL from Copy setup> and the
>    header Authorization with the value "Bearer <the token from Copy setup>".`
>    Expected: the Bot adds the server and lists the tools `apassy_list_access`, `apassy_request_run`,
>    and `apassy_run_status`.
> 2. Prompt: `Use Apassy: list the credentials that you can use.`
>    Expected: exactly one item, `httpbin test`, variable `HTTPBIN_TOKEN`, host `httpbingo.org`. No value.
> 3. Prompt: `Use Apassy to call https://httpbingo.org/bearer with my HTTPBIN_TOKEN as a bearer token,
>    and show me the response body.`
>    Expected: the Bot calls `apassy_request_run` with a command like
>    `curl -s -H "Authorization: Bearer $HTTPBIN_TOKEN" "$APASSY_BASE_HTTPBIN_TOKEN/bearer"` and says that
>    the run waits for approval. A question appears in Apassy on the Mac. It names the agent `Grok Bot`,
>    the command, and the request "from the cloud agent, not verified".
> 4. On the Mac, click **Allow**.
>    Expected: the Bot runs the command. The response is `{"authenticated": true, "token": "…"}`, and the
>    token in it is a placeholder: the same length as the synthetic value, but not
>    `httpbin-test-7f3a9c1e5b2d4f60a8e1c3b5d7f9a2c4`. The synthetic value never appears in the chat.
> 5. Optional: in Apassy, click **Revoke…** next to `Grok Bot`, and repeat prompt 2.
>    Expected: the call fails with `unauthenticated` (HTTP 401).
>
> Every run asks the owner in this release, also a safe command. If no one answers in 5 minutes, the
> run times out and the Bot says so.

## Before the submission (owner checklist)

- [ ] The release with cloud agents is live on all six components at one version.
- [ ] The test above passed in Grok Bot with the released app (this ticks "tested locally and in-app").
- [ ] The public mirror repository of `deploy/plugins/apassy-cloud/` exists, with the full Apache-2.0
      `LICENSE` and the released `version` in `.cursor-plugin/plugin.json`.
- [ ] The interpolation of `mcp.json` is checked in Cursor, or the README says what works.
- [ ] The logo URL is public and 1:1.
- [ ] The owner read the Publisher Terms.
- [ ] The owner says yes.

The Cursor Marketplace has its own form (`cursor.com/marketplace/publish`). Cursor reviews every plugin,
and a plugin must be open source. Use the same mirror repository and the same texts.
