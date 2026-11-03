# Trust model

Date: 2026-11-02. Updated 2026-11-03: cloud agents through Tailscale Funnel. Decision:
[ADR 0037](../adr/0037-own-relay-open-source.md). This page says who can see what. Update it in the
same change as any code that changes an answer here.

## The rule

No Apassy-run server holds a key that opens a credential, a vault, a question, or an answer. A value
is opened only on a device of the user, or of the user's team. Every part that touches a value is
Apache-2.0 and builds from this repository.

## Parties

| Party | Holds | Sees | Cannot see |
| --- | --- | --- | --- |
| Your Mac or Linux node | Your vaults, the broker, the bouncer, your relay server, item keys of the teams it hosts | Everything of your vaults while they are unlocked; the values of runs it releases | — |
| Your iPhone | A vault opened from iCloud Drive or a node; its device and answer keys (Secure Enclave or Keychain) | Questions, feed, and access requests, after it opens them | Values in a question (a card never carries one) |
| A team host node | The team file and its item keys | The values of runs that it releases. In way B, the members' requests to the upstream API and the answers | Members' personal vaults |
| A team member's node | Its device key; in way A, a value for one run | Its own runs; in way A, the value (it can keep a copy) | In way B, the value |
| Tailscale control server (or Headscale) | Node keys and names | Which nodes exist and their addresses | Traffic |
| Tailscale DERP relays | — | WireGuard ciphertext, sizes, times | Traffic |
| Push gateway (Apassy project) | The APNs key | Push handles, node IP addresses, times | Tokens of other gateways, any question data |
| Apple (APNs, iCloud) | Push delivery; iCloud copies if folder sync is on | Push metadata; SQLCipher ciphertext of iCloud copies | Vault contents |
| Apassy Connect (paid, optional) | Sealed envelopes and sync snapshots | TLS records, ciphertext, sizes, times | Values, vault contents, questions, answers, except the opt-in bouncer brain service below, which sees the bouncer state |
| Bouncer brain service of Apassy Connect (paid, opt-in, ADR 0035) | The shared encoder; the owner's head sets while Apassy hosting is on; the examples of a training job for at most 24 h | The state of each bouncer request (user request, command, relative directory, purpose, variable names, owner rule), in memory for one request; the examples of a training job | Values, the vault, the vault path, absolute project paths. It cannot allow a run: the bouncer gate on the Mac decides |
| Apassy project | Release signing keys | Nothing at run time | Anything of a user |
| Upstream API (Stripe, OpenAI, …) | — | The requests made with its credential | Other credentials |

## Not covered

- A device administrator can read what that device opens: the vault while unlocked, and in way A the
  value of a run.
- A team host operator (or root on that host) can read the members' way B traffic. The enterprise
  track (a confidential VM, ADR 0037 section 11) is for teams whose members must not trust the host.
- Physical attacks on a confidential VM's memory are out of scope of SEV-SNP and TDX (TEE.fail,
  2025).
- Tailscale Funnel, when a user turns it on, exposes the node's agent endpoints and its connect
  endpoints (the MCP authorization flow) to the internet, behind agent tokens and the owner's Allow
  (next section).

## Cloud agents through Tailscale Funnel

A hosted cloud agent (first: Grok Bot) reaches the Mac's node at
`https://<Mac>.<tailnet>.ts.net:8443`: `POST /mcp`, `/p/`, and the endpoints of the MCP authorization
flow (OAuth 2.1: the metadata, `/oauth/register`, `/oauth/authorize`, `/oauth/wait/<id>`,
`/oauth/token`, `/oauth/revoke`) ([contract](../contracts/cloud-agents-v1.md)). Remote access is off by
default. The owner gives an agent only the MCP address; the agent connects by itself and the owner
allows it on the Mac (Touch ID) or the iPhone (Face ID) after comparing the code of the connect page.

| Part | Holds | Sees | Cannot see or do |
| --- | --- | --- | --- |
| Tailscale Funnel relays (ingress servers of Tailscale) | — | TLS records, the server name (SNI), client addresses, sizes, times. TLS ends on the Mac, not here | Requests, tokens, session keys, placeholders, values |
| `tailscaled` on your Mac | The Funnel certificate and its key | Each cloud request and answer in clear, on the Mac: the token, session keys, placeholders. It ends TLS and connects to the public listener from the loopback | Values: the proxy sends them upstream on its own TLS connection, and the answers come back with placeholders. The vault |
| Certificate Transparency logs | The Funnel certificate | The machine name and the tailnet name (`<Mac>.<tailnet>.ts.net`), for ever, once the route is on | Whether the route is on now, any traffic |
| The public listener (`127.0.0.1:<port>`) | Nothing of its own | The cloud requests from `tailscaled`, and any request of a program on the Mac: the loopback bind keeps other computers away, not the programs of the Mac (review 0.5.16) | It serves no other route: `/v1/...`, the host lane, `/healthz`, and everything else are 404. It trusts no header for identity or authority. Failed authentications on `/mcp` and `/p/` count for each source address that Funnel forwards (`X-Forwarded-For`): after 20 in 60 s, 429 for that address only; requests without an address share a limit of 600. The flow is in neither count: bad codes and refresh tokens count for their client only; clients that the owner never allowed fill no limit of the flow |
| The connect page (`/oauth/wait/<id>`) | Nothing | The client name that the agent registered (not verified), "your Mac" (never the computer name: anyone with the address reads the page), the match code, and the state of the request | It has no script, form, cookie, or button: nothing on it can allow a connection. Never an item, an agent list, or the owner's name. Strict CSP, no framing, no referrer, no cache |
| A connect request | The node: its id, the OAuth client, the PKCE challenge, the match code, 300 s | — | It allows nothing by itself. Only the owner's Allow (Touch ID on the Mac, Face ID on the iPhone) connects it, always to a new agent with no credential: a client id is public, so a connect never takes over an agent that exists. At most 3 open per node and 1 per client: a new request of the client ends its waiting one, so the browser shows the code of its own request. The owner allows only when the browser page shows the same code |
| The access and refresh tokens of the flow | The cloud agent's vendor; the node keeps only their hashes | The items that the owner chose for that agent (names, variables, hosts) and the agent's own runs | A value, another agent's items, the owner API. An access token lives 24 h; a refresh token 90 days, rotated at each use, and a reused one revokes the family. A disconnect revokes the agent, its family, and the open requests of its client at the next request |
| The fallback agent token (`apassy_tagt_…`, `apassy agent add-remote`) | The cloud agent's vendor holds it, in its MCP server setting | As the tokens of the flow | As the tokens of the flow. It lives 1 to 365 days (default 90); a disconnect counts at the next request |
| The cloud agent's vendor (xAI, …) | The token; for a ready run, the session key, placeholders, and base URLs, until the session ends (at most 600 s) | Its runs, and the API answers with the placeholders back in them | A value. The node puts a placeholder back where the API echoes the value |
| The node's store at rest (`<data dir>/node`, SQLCipher under a Keychain key) | Team and item metadata (names, variables, hosts, declarations), agent token hashes, run rows (masked command, purpose, user request), the audit | — | It never holds a value or an item key: the value stays in the vault and goes into a session only in memory |

Known limits of the connect flow. Each is a denial of service only: none gives a token, an agent, or a
credential.

- A leaked authorize URL (or the address of its waiting page) can burn the code. Its holder opens the
  same request; after the owner's Allow, the code goes to whichever browser loads the page first. Without
  the client's PKCE verifier it gives no token, but the client's own browser then gets no code, and a
  redemption with a wrong verifier uses the code up and revokes its family. The same URL with other
  parameters ends the client's waiting request, since a new request of a client replaces it. The client
  connects again; the owner allows only a request whose code its own browser shows.
- A stranger can hold the 3 open connect requests of the node until the owner denies them, or they end
  after 300 s.
- A stranger who sends 20 bad codes or refresh tokens with the public id of a client holds that client's
  token requests at 429 for the rest of each 60 s window. Its access token keeps working until it ends.
- A flood of registrations can drop a client that registered and was not allowed yet; it registers again.
- A program on this Mac (a coding agent too) can connect to the public listener on the loopback and run
  the whole flow as any client name ("Grok Bot"), so its card looks like a real one (review 0.5.16).
  The owner's prompts and the iPhone card name where the code goes back: "Returns to <host of the
  redirect URI>", or "Returns to a program on a computer (localhost)" for a loopback redirect, and the
  Mac adds "A program on this Mac can start this request." Allow only a request that you started, whose
  code your browser shows, and that returns to your agent's site. A program that registers an
  `https://` redirect of a site it controls is not told apart by this line. An Allow gives a new agent
  with no credential. Planned for 0.5.17: the listener accepts only connections of the Tailscale
  process (a peer-process check).
- A program on this Mac can forge `X-Forwarded-For` and so hold the shared failed-auth count, or a
  guessed source address, at 429. A stranger with thousands of addresses can fill the source table
  (4096) and then the shared count.

The owner decides every cloud run in this release, on the Mac or the iPhone, one question of an agent
at a time. A remote agent starts with no credential. A node has at most 20 agents that are not
revoked, also those of the flow without a live token. The node trusts the app process: code that runs
in it can release any run, but it can read the vault anyway. The embedded node serves no operator
socket (`admin.sock`): its directory belongs to the Mac user, as the coding agents do, so no local
program can suspend or delete the personal team or make team codes through it (review 0.5.16).

The catalog mirror (`src/node/catalog.rs`) reads the value of each item that it mirrors with
`Vault::reveal`, without an owner check, when the item is new to the mirror or its revision changed. It
does this in the app process, only to run the node's `check_value` (`hostkeys::check_value`: a value
that the proxy could not swap, such as an empty one, one over the size limit, one with a byte outside
printable ASCII or a `"` or `\`, or one of no placeholder shape, keeps the item out of the mirror). The
value is held in zeroizing memory (`NodeSecret`) for that check only: it is not stored in the node, not
sent anywhere, and not logged; the node stores the marker `VALUE_ON_HOST` instead (SPEC 30.6). The owner check guards
values that leave the vault: a release of a run, a reveal or copy in the app. This read leaves nothing
outside the process (review 0.5.16).

## The hosted relay today (until ADR 0037 stage 7)

| Function | State on 2026-11-02 | Sees |
| --- | --- | --- |
| Shared team vaults and way B | Off: the only team vault (`apassy-alpha`, the owner's alpha team) is suspended (D8) | Nothing new; its file stays encrypted for the stage 4 export |
| Relay sync | On | SQLCipher ciphertext and salt, sizes, times |
| Questions, feed, access requests | On | Sealed envelopes, ids, routing bit, expiry, sizes, times |
| Push | On, through the Cloudflare Worker | Device tokens, times |
| Edge | Cloudflare ends TLS | Request metadata and bodies of the above (all sealed or ciphertext) |
