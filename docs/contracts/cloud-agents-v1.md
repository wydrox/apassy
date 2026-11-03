# Cloud agents contract v1

Date: 2026-11-03.
Status: proposed, for the cloud slice of [ADR 0037](../adr/0037-own-relay-open-source.md) (§3 "Public", §6)
and [ADR 0011](../adr/0011-run-proxy-placeholders.md) stage 7. Plan:
[implementation-plan-0037-cloud-agents.md](../design/implementation-plan-0037-cloud-agents.md), decisions 3
to 8. The relay side (the public listener, its scope, the failed-auth limiter, the item list of an
agent, the in-process release) is in `crates/apassy-relay` (its `docs/SPEC.md` sections 11, 12, 14, and
30). The app side (the node, the host loop, Funnel, Settings → Cloud agents) is in work units U2 and U3
and is not released yet. A change to this document changes the relay, the app, and the plugin in
[`deploy/plugins/apassy-cloud/`](../../deploy/plugins/apassy-cloud/README.md) together.

## 1. Purpose and scope

A **cloud agent** is an agent that runs on a server of its vendor, not on the owner's Mac. The first one
is xAI Grok Bot. It adds one MCP server by its HTTPS URL and connects with the MCP authorization flow
(section 4); the owner allows the connection on the Mac. It lists the credentials
that the owner chose for it, asks for a run, waits while the owner decides, and then calls the API
through the Mac's proxy (way B). It holds placeholders, base URLs, and a session key. It never holds a
value.

No Apassy-run server is on the path. The relay runs as threads of the Apassy app on the owner's Mac
(the **node**), and Tailscale Funnel carries the traffic from the internet to it.

This document is the whole surface that a cloud agent sees. Everything else of the node is out of its
reach (section 3).

## 2. Words

| Word | Meaning |
| --- | --- |
| Node | The relay inside the Apassy app on the owner's Mac, with a personal team for one vault. |
| Public listener | The node's second listener, on `127.0.0.1:<port>`. Tailscale Funnel is its only way in. |
| Public URL | `https://<Mac>.<tailnet>.ts.net:8443`: the Funnel origin of the Mac. `<Mac>` is the machine name and `<tailnet>` the tailnet name of `tailscale status`. |
| Agent token | The bearer token of one cloud agent: `apassy_tagt_<team id>_<64 hex>`. From the authorization flow it is the access token (24 h, refreshed); from the CLI fallback it lives 30 to 365 days. |
| Connect request | A remote client's request to connect, made by `/oauth/authorize`. It waits 300 s for the owner, with a match code that the browser page and the app both show. |
| Run | One request to use some items for one stated command. |
| Session | A released run: a session key, placeholders, and base URLs, for a limited time. |
| Session key | `apassy_ses_…`. It is in every base URL. With a placeholder, it is a credential for the hosts of that item, in auth positions only, until the session ends. |
| Placeholder | A text of the same length as the value, with the same known prefix, and at least 64 random bits. The proxy swaps it for the value. |
| Owner's host | The Apassy app itself. It decides each run and releases the values of the items from the vault. |

## 3. The route

- The public URL is `https://<Mac>.<tailnet>.ts.net:8443`. Port 8443, never 443. The route is off by
  default. The owner turns it on in Settings → Cloud agents.
- TLS ends in `tailscaled` on the Mac. `tailscaled` connects to the public listener from the loopback.
- The public listener serves these routes only:
  - `POST /mcp`: the MCP endpoint (section 5).
  - `ANY /p/...`: the proxy (section 9). `CONNECT` and upgrades are refused there (501).
  - The authorization flow (section 4): `GET /.well-known/oauth-protected-resource` and
    `…/oauth-protected-resource/mcp`, `GET /.well-known/oauth-authorization-server` and
    `/.well-known/openid-configuration`, `POST /oauth/register`, `GET /oauth/authorize`,
    `GET /oauth/wait/<id>`, `POST /oauth/token`, `POST /oauth/revoke`.
- Every other request is 404 `not_found`, before any other check: `GET /mcp`, `/mcp/...`, `/healthz`,
  `GET /`, every `/v1/...` path (the owner API, the host lane, teams, devices), and every unknown path.
  The hosted relay serves none of the flow: all its paths are 404 there.
- The listener trusts no request header. The identity headers of Tailscale Serve are not read. Funnel
  requests have none. The proxy drops every `tailscale-*` header before the upstream.
- The route works only while the app runs, the vault with the cloud agents is unlocked, the route is on,
  and the Mac is awake and online. Locking the vault or quitting the app turns Funnel off and stops the
  node (section 11).

## 4. Authentication and the token

A cloud agent connects with the authorization flow of the MCP specification: OAuth 2.1 with PKCE (S256),
the protected resource metadata of RFC 9728, the server metadata of RFC 8414, and dynamic client
registration (RFC 7591). The relay side is in its `docs/SPEC.md` section 31. The bearer token of the CLI
(4.3) is the fallback for a client without the flow.

### 4.1 The flow

1. The client sends `POST /mcp` without a token. The answer is 401 `unauthenticated` with
   `WWW-Authenticate: Bearer resource_metadata="<public URL>/.well-known/oauth-protected-resource/mcp",
   scope="apassy"`.
2. It reads that document (also at `/.well-known/oauth-protected-resource`): `resource` is
   `<public URL>/mcp`, `authorization_servers` is `[<public URL>]`. It reads
   `/.well-known/oauth-authorization-server` (also `/.well-known/openid-configuration`).
3. It registers: `POST /oauth/register` with `redirect_uris` (each `https://…`, or `http://localhost`,
   `127.0.0.1`, or `[::1]` with any port; at most 512 bytes) and an optional `client_name`. The answer is
   201 with a `client_id` and `token_endpoint_auth_method = "none"`: every client is public; there is no
   client secret.
4. It opens `GET /oauth/authorize?response_type=code&client_id=…&redirect_uri=…&state=…&code_challenge=…
   &code_challenge_method=S256` in the user's browser (`scope=apassy` and `resource=<public URL>/mcp` are
   optional). The node makes a connect request and sends the browser to `/oauth/wait/<id>`. A client
   has one waiting request: a new `authorize` of it with other parameters ends the waiting one (its
   page says "The request ended.") and makes a new one with its own page and code. A client id is
   public, so a request that someone else keeps open never stands in for this browser's. A bad
   request (response type, PKCE, `resource`, `state` over 512 bytes) goes back to `redirect_uri` with
   `error` only for a client that the owner allowed before; for a new client it is the page "This
   connection link is not valid.", so a link of the node is never an open redirect.
5. The page says "<client> wants to connect to your Mac" (never the computer name: the page is public),
   shows a match code such as `K7Q-4MD`, and reloads
   every 3 seconds. It has no button: the owner allows the request in Apassy on the Mac (Decisions, with
   Touch ID) or on the iPhone, where the same code shows. Apassy must be open and unlocked; the request
   ends after 300 seconds.
6. Allowed: the next reload of the page sends the browser to `<redirect_uri>?code=…&state=…&iss=<public
   URL>`, once. Denied: the page says "You denied the connection.". Not answered in time: "The request
   ended.".
7. The client sends `POST /oauth/token` (a form) with `grant_type=authorization_code`, `code`,
   `code_verifier`, `client_id`, and `redirect_uri`. The answer: `access_token` (the agent token,
   `apassy_tagt_…`), `token_type = "Bearer"`, `expires_in` (86400), `refresh_token`, `scope = "apassy"`.
8. Each `POST /mcp` has `Authorization: Bearer <access token>`. Before it ends, or after a 401
   `token_expired`, the client sends `grant_type=refresh_token` with `refresh_token` and `client_id`: a
   new access token and a new refresh token. The old refresh token is used up.

A new agent has no credential. It appears in Apassy → Agents; the owner chooses what it may use. Every
allowed connect makes a new agent, also for a client that already has one: a second connect of Grok Bot
is "Grok Bot 2", with no credential. A connect never takes over an agent that exists; the old agent
stays until the owner disconnects it.

### 4.2 Rules

- A code lives 300 seconds and works once. A wrong verifier, client, or redirect URI uses it up. A second
  use of a code, or of a refresh token that was already used, is `invalid_grant` and ends the connection:
  its refresh token and its access token stop working, and the client must start at step 4 again.
- The access token lives 24 hours. The refresh token lives 90 days from its last use. One access token
  is live for each agent: a new one replaces the old one.
- Bad codes and refresh tokens count for their client only: after 20 `invalid_grant` answers for one
  client in 60 seconds, its token requests get 429 `rate_limited` with `Retry-After: 60` until the
  window ends. They never count in the failed-auth limiter of the listener (section 10).
- `POST /oauth/revoke` (RFC 7009) with the refresh or the access token ends the connection. It answers 200
  always.
- Limits of the node, not of a caller (Funnel forwards no client identity): 10 registrations in 10
  minutes and 100 stored clients (429, `Retry-After: 600`), counting only clients that the owner allowed
  at least once. A client that was never allowed fills no limit: when 100 clients are stored the oldest
  of those goes, and each goes 1 hour after its registration (an authorize does not renew it); 3 connect requests waiting at once (429 page
  "Too many connection requests wait. Deny requests on your Mac that you did not start, then connect
  again."); 1 of each client, and a new one replaces it (step 4).
- The node stores only hashes of codes and refresh tokens, and of the access token.
- A missing, unknown, revoked, or replaced token on `POST /mcp`: HTTP 401 `unauthenticated`. An expired
  token: HTTP 401 `token_expired`. Both have `WWW-Authenticate` as in step 1, with `error="invalid_token"`.
  The body of these answers is the relay envelope (section 14), not a JSON-RPC message.
- The proxy path does not take the agent token. The session key in the path is its credential.
- Each tool call reads the agent again, so a revocation counts at the next call, also inside one MCP
  client session.
- If the request has an `Origin` header, it must be the public URL. Else: HTTP 403 `forbidden`. A request
  with no `Origin` header passes this check.

### 4.3 The CLI fallback

`apassy agents add-remote <name> [--days 90]` (with an owner check) makes the agent with no credential and
prints its bearer token once, with the MCP address. The token lives 30 to 365 days (90 by default) and
cannot be refreshed or extended: to renew it, the owner disconnects the agent and adds it again. The node
stores only its SHA-256 hash. The client sends it as `Authorization: Bearer apassy_tagt_…`.

## 5. The MCP endpoint

`POST /mcp`, Streamable HTTP with JSON responses only. No SSE. No `Mcp-Session-Id`: the endpoint is
stateless.

- The body is one JSON-RPC 2.0 message, at most 64 KiB (else HTTP 413 `payload_too_large`). A JSON
  array (a batch): error -32600. Not JSON: error -32700.
- A notification (no `id`) or a response from the client: HTTP 202 with an empty body.
- `initialize`: `protocolVersion` is the client's version if it is `2025-11-25`, `2025-06-18`,
  `2025-03-26`, or `2024-11-05`, else `2025-06-18`. `capabilities` is `{"tools": {"listChanged":
  false}}`. `serverInfo` is `{"name": "apassy-relay", "version": <relay version>}`. `instructions` is the
  text below.
- `tools/list` and `tools/call` work without a prior `initialize`. `ping` answers `{}`. Any other method:
  error -32601.
- `MCP-Protocol-Version` and other unknown headers are ignored.
- A tool result on success: `{"content": [{"type": "text", "text": <the result as pretty JSON>}],
  "structuredContent": <the result>, "isError": false}`.
- A tool failure is a tool result, not a JSON-RPC error: `{"content": [{"type": "text", "text": "<code>:
  <message>"}], "isError": true}`. An unknown tool or arguments that do not match the schema:
  `isError` with `invalid_request`.

The `instructions` text of `initialize`:

> Apassy relay. Call apassy_list_access to see the credentials you can use. Call apassy_request_run with
> the exact command, the purpose, and the user's request. The status is pending until the owner's host
> releases the keys of the items: it does so by itself for a known safe command, and it asks the owner
> for any other. Call apassy_run_status until it is ready, denied, timed_out, or ended. An ended run is
> terminal, including an unknown reason code. Do not automatically retry an interrupted run; ask the
> user before requesting another run. When it is ready, run the command yourself with every variable of
> session.env set. The variables hold placeholders and base URLs, not real values; the relay swaps them.
> Do not print or store the variables. If apassy-team is installed, prefer `apassy-team run`, which does
> all of this and keeps the variables out of the transcript.

The text is the same as on any relay. On a node, the owner's host asks the owner about every cloud run
(section 13), so no run is released by itself.

## 6. Tools

Every `inputSchema` has `"type": "object"` and `"additionalProperties": false`.

### 6.1 `apassy_list_access`

Arguments: none (`{}` or no `arguments`). Any argument: `invalid_request`.

Result (`AccessView`):

| Field | Type | Meaning |
| --- | --- | --- |
| `agent_id` | integer | The agent. |
| `agent` | string | The agent's name, as the owner typed it. |
| `member` | string | The owner member of the personal team. |
| `items` | array | The items that the owner chose for this agent. |
| `note` | string | What to do next. With no item: "No collection is granted to your member yet. Ask the owner for a grant." |

Each item (`AccessItem`):

| Field | Type | Meaning |
| --- | --- | --- |
| `item_id` | integer | The id to use in `apassy_request_run`. |
| `item_name` | string | The name of the item. |
| `collection` | string | `cloud`. |
| `env_name` | string | The variable that holds the placeholder, for example `HTTPBIN_TOKEN`. |
| `hosts` | array of string | The hosts that may get the value. A host covers its subdomains. |
| `environment` | string | `local`, `development`, `staging`, or `production`. |
| `base_url_vars` | array of string | The base URL variables that a run gets for this item (section 8). |
| `approval` | string | In words: when the owner is asked. On a node: "Every run waits for the owner's host, which asks the owner (the policy of the collection)." |
| `rule` | object | The hard rules of the collection (`ExecRule`). |

The list holds only the items that the owner picked for this agent (the agent's item list, relay
schema 7). It never holds a value, a placeholder, or a key.

### 6.2 `apassy_request_run`

| Argument | Type | Required | Rule |
| --- | --- | --- | --- |
| `items` | array of integer ≥ 1 | yes | 1 to 16 distinct item ids from `apassy_list_access`. |
| `command` | array of string | yes | The exact argv that the agent will run. 1 to 64 arguments, each at most 4096 bytes, no NUL. The first is not empty and does not start with `-`. |
| `purpose` | string | yes | Why, in the agent's words. 1 to 500 bytes after trim. |
| `user_request` | string | yes | The user's words that led to this run. At most 32 KiB, no NUL. |
| `cwd` | string | no | An absolute path, for the audit only. |
| `ttl_secs` | integer | no | The session lifetime, 60 to 600 seconds. Default 600. |

Result: a `RunView` (section 7). A run that passes the checks is `pending`. The call does not wait.

Tool failures (`isError`, with the code):

| Code | When |
| --- | --- |
| `invalid_request` | The arguments do not match the schema or the rules above, or two items have the same `env_name`. |
| `not_granted` | An item is unknown, or is not in the agent's list. The same answer for both, so ids do not leak. |
| `item_archived` | An item is in the agent's list but left the node's catalog (archived). |
| `rule_expired`, `rule_command_not_permitted`, `rule_forbidden_word`, `rule_rate_limit` | A hard rule of the collection refused the run. The run is stored as `denied`. |
| `team_limit` | The team has 120 runs in the last hour, or 10 pending runs. |
| `unauthenticated`, `token_expired` | The agent was revoked or expired since the HTTP check. |

### 6.3 `apassy_run_status`

| Argument | Type | Required | Rule |
| --- | --- | --- | --- |
| `run_id` | integer ≥ 1 | yes | A run of this agent. A run of another agent is `not_found`. |
| `wait_secs` | integer, 0 to 25 | no | While the run is `pending`, wait up to this many seconds for a change. Default 20. |

Result: a `RunView`. The call returns at once when the run is not `pending`, or at the end of the wait.
When the node has too many waiting calls, it returns at once. Call it again until the status is not
`pending`.

## 7. Runs: states and codes

`RunView`:

| Field | Type | Meaning |
| --- | --- | --- |
| `run_id` | integer | The run. |
| `status` | string | `pending`, `ready`, `denied`, `timed_out`, or `ended`. |
| `decided_by` | string, optional | `host`, `approver`, `revocation`, or `timeout`. |
| `approver` | string, optional | Not used on a node. |
| `code` | string, optional | Why a run is `denied`, `timed_out`, or `ended` early (table below). |
| `note` | string | The relay's verdict while the run waits, then the reason of the owner's host. |
| `flags` | array of string | The flags of the command analysis, for example `secret_output`, `foreign_host`, `injection_phrase`. |
| `created_at` | integer | Unix seconds. |
| `expires_at` | integer, optional | When a pending run times out: 300 seconds after the request. |
| `session` | object, optional | Only when `ready`, and only for this agent (section 8). |

States:

```text
pending ──► ready ──► ended
   │
   ├──► denied
   └──► timed_out
```

| Status | Meaning | What the agent does |
| --- | --- | --- |
| `pending` | The owner has not decided yet. | Call `apassy_run_status` again. |
| `ready` | The owner allowed the run. The session is live. | Run the stated command with every variable of `session.env` set. |
| `denied` | The owner, a revocation, or a failed release refused the run. | Stop. Tell the user. Do not ask again without the user. |
| `timed_out` | No decision in 300 seconds. `code` is `approval_timeout`. | Stop. Ask the user before a new run. |
| `ended` | The session expired or ended, or a restart of the node ended the pending run. | Stop. The run is terminal, also with an unknown code. |

Codes in `RunView.code`:

| Code | Status | Meaning |
| --- | --- | --- |
| `approval_denied` | `denied` | The owner denied the run. `note` has the reason. |
| `approval_invalidated` | `denied` | The agent, an item, or the agent's item list changed or was revoked while the run waited. |
| `release_invalid` | `denied` | The values did not pass the release check. No session was made. |
| `rule_*` | `denied` | A hard rule refused the run. `apassy_request_run` already answered with a tool failure (section 6.2). |
| `approval_timeout` | `timed_out` | No decision in time. |
| `run_interrupted` | `ended` | The node stopped (lock, quit, restart) while the run waited. Do not retry it by yourself. |

## 8. The session environment

`session` of a `ready` run (`SessionView`):

| Field | Type | Meaning |
| --- | --- | --- |
| `session_id` | integer | The session. |
| `expires_at` | integer | Unix seconds. The lifetime starts at the release: `ttl_secs`, or 600 seconds. |
| `env` | object | Variable name to text. Set every one of them for the command. |
| `placeholders` | array of string | The names in `env` that hold a placeholder. |
| `base_urls` | object | Host (`host` or `host:port`) to its base URL. |

`base(host)` is `https://<Mac>.<tailnet>.ts.net:8443/p/<session key>/<host>`. The host has no port for 443.

| Variable | When | Text |
| --- | --- | --- |
| `<ENV_NAME>` | each item | The placeholder of the item. |
| `APASSY_BASE_<ENV_NAME>` | each item | `base(the first host of the item)`. |
| `STRIPE_API_BASE` | an item with a host that covers `api.stripe.com` | `base(api.stripe.com)` |
| `OPENAI_BASE_URL` | a host that covers `api.openai.com` | `base(api.openai.com) + "/v1"` |
| `ANTHROPIC_BASE_URL` | a host that covers `api.anthropic.com` | `base(api.anthropic.com)` |
| `GITHUB_API_URL` | a host that covers `api.github.com` | `base(api.github.com)` |
| `APASSY_RELAY_SESSION_EXPIRES` | always | The session expiry, Unix seconds. |

- If two items give the same provider variable, the item with the lower id wins.
- `GH_HOST` and `AWS_ENDPOINT_URL` are not set (`gh` cannot use a path; SigV4 is not supported).
- The command must send its API requests to the base URL, with the placeholder in an auth position
  (section 9). A request straight to the upstream host gets the placeholder, not the value, and fails
  there.
- The variables are not values, but a placeholder and the session key together are a credential until
  the session ends. The agent must not print, log, or store them.

Example (synthetic):

```json
{
  "session_id": 7,
  "expires_at": 1793700600,
  "env": {
    "HTTPBIN_TOKEN": "httpbin-test-Qm4tZ8rV1xK0pL6sYw2nC9dF3hJ5aB7e",
    "APASSY_BASE_HTTPBIN_TOKEN": "https://my-mac.tailnet-example.ts.net:8443/p/apassy_ses_…/httpbingo.org",
    "APASSY_RELAY_SESSION_EXPIRES": "1793700600"
  },
  "placeholders": ["HTTPBIN_TOKEN"],
  "base_urls": {"httpbingo.org": "https://my-mac.tailnet-example.ts.net:8443/p/apassy_ses_…/httpbingo.org"}
}
```

## 9. The proxy `/p/`

`ANY /p/<session key>/<host>[/<rest>][?<query>]` goes to `https://<host>/<rest>?<query>`. HTTPS only,
HTTP/1.1, one connection for each request. Nothing goes upstream before every check passes.

**Where a placeholder may be.** The proxy puts the value in place of a placeholder only here:

- `Authorization`: exactly a placeholder; `<scheme> <placeholder>` (`Bearer`, `token`, any scheme); or
  `Basic <base64(user:password)>` where the user, the password, or both are exactly a placeholder.
- The key headers `x-api-key`, `api-key`, `apikey`, `x-auth-token`, `x-api-token`, `x-access-token`,
  `private-token`, `x-goog-api-key`, `x-figma-token` (any case): exactly a placeholder, or
  `Bearer <placeholder>`.
- The key query parameters `key`, `api_key`, `apikey`, `api-key`, `access_token`, `token`, `auth`: the
  decoded value is exactly a placeholder.

A request with no placeholder goes upstream as it is (a public endpoint of the host).

**Refusals.** The proxy's own answers have `X-Apassy-Relay: refused` (or `upstream-error` for 502) and
an envelope body:

| HTTP | Code | When |
| --- | --- | --- |
| 403 | `session_invalid` | The key is malformed, unknown, expired, or its session ended. Counts as a failed authentication (section 10). |
| 403 | `host_not_in_session` | The host is not a host of the session, or does not parse. The node is not an open proxy. |
| 403 | `wrong_host` | A placeholder goes to a host that its item does not cover. |
| 403 | `misplaced_placeholder` | A placeholder is in the path, another header, another query parameter, or a Basic part with more text. |
| 403 | `placeholder_in_body` | A placeholder of the session is in the request body. |
| 413 | `payload_too_large` | The request body is larger than 8 MiB. |
| 501 | `not_supported` | `CONNECT`, an upgrade, a `101` answer, or no same-length encoded form for an echo. |
| 502 | `upstream_failed` | The host does not resolve, resolves only to a non-public address, does not answer, or fails TLS. One message for all, so the agent cannot map the network. |
| 502 | `encoded_response` | The answer has a `Content-Encoding` other than `identity`, so it cannot be searched for the value. |

**The answer.** The upstream status and headers come back. The proxy replaces each value of the session
with its placeholder in every header and in the body, also when the value is split across reads. So an
API that echoes the token gives back the placeholder. Hop-by-hop headers are dropped.

**Upstream addresses.** Only public internet addresses are used. Loopback, private, link-local, CGNAT
(Tailscale's `100.64.0.0/10` too), unique-local, multicast, documentation, and reserved addresses are
refused. A cloud agent cannot reach the Mac, its tailnet, or its LAN through the proxy.

**Headers that do not go upstream:** `host` (set again), hop-by-hop headers, `accept-encoding`,
`content-length` (set again), `x-apassy-edge`, `cdn-loop`, `x-forwarded-*`, `x-real-ip`, `cf-*`, and
`tailscale-*`. `Connection: close` is added.

Every proxy request writes one audit row: method, host, path without the query, status, outcome, code,
and the names of the swapped variables. Never a header, a query, a body, a placeholder, a value, or a key.

## 10. Limits

| Limit | Value | Answer |
| --- | --- | --- |
| Cloud agents of a node | 20 | The node refuses a 21st (`team_limit`). The app shows it. |
| Runs of the team in one hour | 120 | `team_limit` (tool failure) |
| Pending runs of the team | 10 | `team_limit` (tool failure) |
| Agent requests of the team at once | 16 | HTTP 503 `busy`, `Retry-After: 2` |
| Requests on the public listener at once | 32 | HTTP 503 `busy`, `Retry-After: 2` |
| `POST /mcp` body | 64 KiB | HTTP 413 `payload_too_large` |
| Proxy request body | 8 MiB | HTTP 413 `payload_too_large` |
| Wait for a decision | 300 s | `timed_out`, `approval_timeout` |
| Session lifetime | 60 to 600 s, default 600 | The run becomes `ended`. |
| `wait_secs` of one status call | 0 to 25 s | The call returns. |

**The failed-auth limiter.** The public listener counts its failed authentications: a bearer token that
names no team or that the node refuses (401 `unauthenticated` or `token_expired`), and a proxy path whose
session key names no live session. A code or refresh token that `POST /oauth/token` refuses counts for
its client only (section 4.2). The window is 60 seconds from the first failure. With 20 failures in
the window, every further request of the public listener in that window gets HTTP 429 `rate_limited`
with `Retry-After: 60`, also a request with a good token. Then the window ends and the count starts
again. The check comes after the 404 of section 3 and before the token, the body, or the proxy. The node
writes at most one audit row in 10 seconds for it (`rate_limited`, scope `public`). The count is in
memory only.

A stranger with bad tokens can hold the public listener at 429 for the rest of each window, and the
owner's cloud agents with it. A client that gets 429 waits `Retry-After` seconds and does not send bad
tokens in a loop.

## 11. Revocation, lock, and quit

| Event | Effect for the agent |
| --- | --- |
| The owner disconnects the agent (Agents → Disconnect…, with an owner check) | The next `POST /mcp` is 401 `unauthenticated`. Its refresh token stops working and a connect request of its client that waits is denied. Pending runs become `denied` (`approval_invalidated`). Live sessions end at once: the next `/p/` request is 403 `session_invalid`. |
| The access token expires | 401 `token_expired`. The client refreshes it (4.1 step 8). A CLI token (4.3): the owner adds the agent again. |
| The refresh token expires (90 days unused) or the connection ends (4.2) | The refresh is `invalid_grant`. The client connects again from step 4; the owner allows it again. |
| The owner removes an item from the agent, or the item changes or leaves the vault | Pending runs with it are `denied` (`approval_invalidated`). Its sessions end. The item leaves `apassy_list_access`. |
| The vault locks, or the app quits | Funnel is turned off and the node stops. The public URL does not answer. Sessions and run keys are gone. After the next unlock, a run that waited is `ended` with `run_interrupted`. |
| The tailnet name or machine name changes | The public URL changes. Sessions end. The owner copies the new setup to the client. |

The token, the item list, and the route belong to the owner. A cloud agent cannot change them.

## 12. What the agent never gets

- A value of an item, in any answer of the node. The proxy puts the placeholder back in every answer.
- An item key, a sealed value, a run key, or any key material.
- The owner token, a device token, or another agent's token. The node's owner token is made, hashed,
  and dropped: nobody holds it.
- The owner API (`/v1/...`), the host lane, the audit, the approvals, the team, devices, or `/healthz`:
  all 404 on the public listener.
- Items that the owner did not pick for this agent, or the items of other agents. They are not in the
  list, and a run with one is `not_granted`.
- The vault, its metadata outside the agent's catalog, or other vaults.
- The tailnet, the Mac, or its LAN through the proxy (section 9, upstream addresses).
- A remembered permission. Each run is one decision of the owner (section 13).

What it does get: its item list (names, variables, hosts, environments), the `RunView` of its own runs,
and, for a ready run, the placeholders, the base URLs with the session key, and the API answers with the
placeholders back in them.

## 13. The owner decides every run (this release)

A cloud agent has no prompt hook, so the node cannot see the user's real words. `user_request` is the
agent's own text. The card shows it as "from the cloud agent, not verified". The injection check still
applies to it.

In this release every cloud run asks the owner:

- The collection `cloud` has the policy `ask`. The broker routes each cloud run to the owner, with no
  project, nothing remembered, and no automatic allow, also for a known safe command.
- The question reaches the Mac and the iPhone. The Apple Watch does not get run questions (ADR 0039 §3).
  The first answer wins.
- The card names the agent, the items, the exact command, the purpose, and the agent's request.
- If no one answers in 300 seconds, the run is `timed_out`.

A later release may add a switch for each agent: "allow known safe, non-production commands". Until
then, a client must expect a person in the loop for each run.

## 14. Errors

An HTTP-level error has the relay envelope `{"ok": false, "error": {"code": "...", "message": "..."}}`.
A message never holds a value, a placeholder, a token, or a session key.

| HTTP | Code | Where |
| --- | --- | --- |
| 401 | `unauthenticated`, `token_expired` | `/mcp`: the bearer token, with `WWW-Authenticate` (section 4) |
| 400 | `invalid_request`, `invalid_grant`, `unsupported_grant_type`, `invalid_target`, `invalid_redirect_uri`, `invalid_client_metadata` | `/oauth/token`, `/oauth/register`: an OAuth error object `{"error", "error_description"}`, not the envelope |
| 429 | `rate_limited` | `/oauth/register` at its limit, `Retry-After: 600`; `/oauth/token` for a client with 20 bad codes or refresh tokens in 60 s, `Retry-After: 60` (OAuth error object) |
| 403 | `forbidden` | `/mcp`: an `Origin` header that is not the public URL |
| 403 | `session_invalid`, `host_not_in_session`, `wrong_host`, `misplaced_placeholder`, `placeholder_in_body` | `/p/` |
| 404 | `not_found` | Any route outside section 3 |
| 413 | `payload_too_large` | `/mcp` over 64 KiB, `/p/` over 8 MiB |
| 429 | `rate_limited` | The failed-auth limiter, `Retry-After: 60` |
| 501 | `not_supported` | `/p/` |
| 502 | `upstream_failed`, `encoded_response` | `/p/` |
| 503 | `busy` | Too many requests at once, `Retry-After: 2` |

Tool failures inside a 200 answer are in section 6.2. Run codes are in section 7.

## 15. Client setup

The per-user steps for Grok Bot and Cursor are in the plugin
[README](../../deploy/plugins/apassy-cloud/README.md). The agent's steps are in its
[skill](../../deploy/plugins/apassy-cloud/skills/apassy/SKILL.md).

- **With the authorization flow (the default).** Add the MCP server by its URL,
  `https://<Mac>.<tailnet>.ts.net:8443/mcp`, with no header. Press Authorize (or the client's word for
  it). The browser shows a code; allow the request on the Mac or the iPhone only when it shows the same
  code, and deny any request that you did not start. Then choose the agent's credentials in Apassy →
  Agents. Each allowed connect is a new agent: disconnect the old one when the client connects again.
- **With the CLI token (the fallback).** For a client without the flow: `apassy agents add-remote <name>`
  prints the MCP URL and the header `Authorization: Bearer apassy_tagt_…`, once.

## 16. Not verified

- Grok Bot's OAuth client: whether it registers dynamically, which metadata path it reads, its redirect
  URI scheme, whether it sends `resource`, and whether it refreshes. The node serves both metadata paths,
  takes https and loopback redirect URIs, makes `resource` optional, and keeps the CLI token as the
  fallback. The physical end-to-end test of the plan decides.

- How Grok Bot's MCP client sends `Origin`, handles HTTP 202, and shows `isError` results. The physical
  end-to-end test of the plan decides.
- Whether Grok Bot reads a plugin's `mcp.json`, or only the URL and the header that the user gives in
  chat.
- The interpolation syntax of `mcp.json` in Grok Bot and Cursor.
