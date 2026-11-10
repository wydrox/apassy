# Connect tunnel contract v1

Date: 2026-11-03. Status: proposed, for ADR 0037 stage 7 (unit D1 of [the stage 7 plan](../design/implementation-plan-s7-connect.md)). Not implemented. The relay side is C4 (`crates/apassy-relay/src/server/{tunnel,ingress}.rs`), the node side M4 (`src/node/tunnel.rs`), the device side I2 (`ios/ApassyCore/src/core/transport.rs`) and M5 (the pairing route). Synthetic vectors: frames, invalid frames, and frame sequences.
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) sections 1 and 9, stage 7; [connect-account-v1](connect-account-v1.md); [trust model](../security/trust-model.md).

The tunnel is a blind byte relay. A node (the Mac app, later the Linux node) keeps one outbound WebSocket to Connect; Connect carries streams to it from the devices of the account (a dial) and from cloud agents (the SNI ingress). TLS ends on the node: Connect sees TLS records, sizes, and times. A dial is pinned to the node's own certificate, so Connect never sees its requests or tokens. A cloud agent's TLS is ordinary Web PKI for the node's public name: whoever operates Connect, or controls the DNS of the node zone or the port 80 of those names, can get a certificate for that name and read that agent's traffic (section 1). The encodings, the account token, and the error table are those of [connect-account-v1](connect-account-v1.md) sections 2 to 4. MUST and MUST NOT below are requirements on both sides.

## 1. Rules

- Connect forwards bytes unchanged and stores none of them. It logs no stream content and no client address; the audit holds counts and bytes for each account.
- A device dials only a node of its own account, or of another account that granted its account (section 6). A cloud agent reaches only the public listener of a node (`Scope::Public`: `/mcp` and `/p/`).
- Inside a `device` stream the client runs pinned TLS to the node certificate (the pin of the pairing: base64url SHA-256 of the leaf certificate DER, plan 0037 unit 2C). Inside a `public` stream the agent runs ordinary TLS to the node's publicly trusted certificate for its public name. The node serves the pinned certificate only to `device` streams and the public certificate only to `public` streams.
- The trust of a `public` stream is the trust of a public name, as with a Tailscale Funnel name: a CA issues a certificate for the name to whoever passes its challenge, so the operator of Connect (which answers port 80 and runs the zone's records), or anyone who controls the zone's DNS or that port 80, can get one of their own and end an agent's TLS. A `device` stream does not depend on it: the device checks the pin of the node's own certificate, which no CA issues.
- A `device` stream reaches the node's device routes, the same as the tailnet: every device of the node's account, every device of an account with a grant (section 6), and Connect itself (which can open any stream) can reach them; each route needs its own token, except the sign-in steps, a device link with its one-use code, and the health check. Through a stream of the tunnel the node refuses the team-code, invite, and join routes (`404`).
- The tunnel needs an entitled plan of the node's account ([connect-billing-v1](connect-billing-v1.md) section 8); push is not part of it (the free gateway of D7).

## 2. Ids and names

| Value | Form |
| --- | --- |
| Node id | `node_` and 10 characters of `a-z2-7`; one node for each account device, stable |
| Public name | the 10 characters of the node id, `.`, and the zone `APASSY_CONNECT_NODE_ZONE` (hosted: `node.apassy.wyderka.cc`), e.g. `k7m2q4x3ca.node.apassy.wyderka.cc`. The node takes a `NodeView` only when its `public_name` is exactly its node id's label in the zone it is configured with (`APASSY_CONNECT_NODE_ZONE` of the node, the same default) |
| Pin | base64url without padding of SHA-256 of the node's pinned leaf certificate DER (43 characters) |
| Grant id | `tgr_` and 10 characters of `a-z2-7` |
| Stream id | `u32`, assigned by Connect, from 1, strictly increasing on one node WebSocket; 0 is reserved |

## 3. Routes

| Route | Auth | Section |
| --- | --- | --- |
| `POST /v1/tunnel/nodes` | account token | 3.1 |
| `GET /v1/tunnel/nodes` | account token | 3.1 |
| `DELETE /v1/tunnel/nodes/{node_id}` | account token | 3.1 |
| `GET /v1/tunnel/node` | account token, WebSocket upgrade | 3.2 |
| `GET /v1/tunnel/dial/{node_id}` | account token, WebSocket upgrade | 3.3 |
| `POST /v1/tunnel/grants` | account token | 6 |
| `GET /v1/tunnel/grants` | account token | 6 |
| `DELETE /v1/tunnel/grants/{grant_id}` | account token | 6 |

### 3.1 Nodes

- `POST /v1/tunnel/nodes` with `{"name":"MacBook Pro","pin":"<b64u>"}` registers the node of the calling device, or updates its name and pin, and answers the `NodeView`: `{"node_id":"node_k7m2q4x3ca","account_id":"acc_…","device_id":"dev_…","name":"MacBook Pro","pin":"<b64u>","public_name":"k7m2q4x3ca.node.apassy.wyderka.cc","online":false,"created_at":1790000000}`. More than 8 nodes for the account: `403 account_limit`.
- `GET /v1/tunnel/nodes` lists the nodes that this account may dial: its own and those of granted accounts.
- `DELETE /v1/tunnel/nodes/{node_id}` (a device of the node's account) removes the node, closes its tunnel, and answers `{"node_id":"node_…"}`. A revoked device's node goes the same way.

### 3.2 The node's WebSocket

`GET /v1/tunnel/node` with `Authorization: Bearer <account token of the node's device>`, `Connection: Upgrade`, `Upgrade: websocket`, `Sec-WebSocket-Version: 13`, `Sec-WebSocket-Key`, and `Sec-WebSocket-Protocol: apassy-tunnel-v1`. Connect answers `101 Switching Protocols` with `Sec-WebSocket-Protocol: apassy-tunnel-v1`. A device without a registered node: `404 node_unknown`. A second WebSocket of the same node replaces the first: Connect closes the old one (close code 4005) and resets its streams.

On this WebSocket each binary message is exactly one frame (section 4). Text messages are refused (close 1003). The node pings every 30 s; Connect closes a WebSocket with no message or pong for 90 s. The node reconnects with backoff (1 s, doubling, at most 60 s), each wait a random time between half and all of it; the backoff starts again at 1 s only after a WebSocket that stayed open for 60 s. After close 4005 (replaced) the node waits 5 minutes; after close 4002, `429 tunnel_limit`, or `403 account_limit`, 15 minutes; after `403 plan_required`, 15 minutes. The account token ends after 15 minutes; an open WebSocket stays open, and the node signs in again before it reconnects.

### 3.3 The dial

`GET /v1/tunnel/dial/{node_id}` with `Authorization: Bearer <account token>` and the same upgrade headers. After the `101` each binary message carries raw bytes of one stream, 1 to 16384 bytes; the client runs pinned TLS inside them. A WebSocket close is the end of the stream. The checks before the `101`, in this order:

1. `400 invalid_request`: not a WebSocket upgrade, or another subprotocol.
2. `401 unauthenticated`: no valid account token. `403 account_required`: a team token.
3. `404 node_unknown`: no such node.
4. `403 not_in_group`: the node is of another account, and that account granted none to the caller's account.
5. `403 plan_required`: the node's account is not entitled.
6. `429 tunnel_limit`: the dial rate, the open dials, or the dial budget of the node's account, or, for a device of another account, that account's own rate, slots, or share (section 8).
7. `503 tunnel_offline`: the node has no open WebSocket.

The pairing QR (M5) carries `alt=wss://apassy-relay.wyderka.cc/v1/tunnel/dial/<node id>` and `node=<node id>` beside the tailnet address in its fragment, which never reaches a server; a device tries the tailnet first and Connect second.

## 4. The frame

```
[stream u32 BE][kind u8][flags u8][len u16 BE][payload: len bytes]
```

An 8-byte header and the payload; the binary message length MUST equal 8 + `len`.

| Field | Values |
| --- | --- |
| `stream` | 1 to 2^32 − 1; 0 is reserved |
| `kind` | `1` device (a dial), `2` public (TLS through the ingress, port 443), `3` acme (plain HTTP through the ingress, port 80, section 7.2) |
| `flags` | bit 0 `open` (0x01), bit 1 `close` (0x02), bit 2 `reset` (0x04); the other bits MUST be 0 |
| `len` | 0 to 16384 |

A receiver checks a frame in this order and closes the WebSocket with code 1002 on the first failure: `short_header` (fewer than 8 bytes), `length_mismatch` (the message is not 8 + `len` bytes), `payload_too_large` (`len` over 16384), `reserved_stream` (stream 0), `unknown_kind`, `unknown_flags`, `bad_reset` (`reset` with another flag or with a payload), `empty_frame` (no flag and no payload).

Stream rules (both sides keep the state of each stream):

- Only Connect opens streams. The first frame of a stream is `open` from Connect with a stream id above every id opened before on this WebSocket; it may carry the first bytes (the ClientHello that the ingress read, or the ACME request). `open` from the node is `open_by_node`; `open` for a live stream is `already_open`; `open` for an id at or below an earlier id is `reused`.
- Every frame of a stream carries the kind of its `open` (`kind_mismatch` otherwise).
- `close` ends one direction: the sender sends no more bytes on that stream (`closed` otherwise); it may carry the last bytes. A stream ends when both directions are closed, or at a `reset` from either side.
- The node's `close` ends the stream for its client: Connect delivers the node's last bytes, then closes the client's connection (a dial with 1000) and sends `close` for the client's direction. Connect forwards no client byte that comes after the node's `close`, and counts none.
- A frame other than `open` for an id above every opened id is `not_open`. A frame for a stream that ended is dropped without an error (a `reset` can cross data in flight).
- Connect never sends a `reset` ahead of the `open` of its stream. When it ends a stream whose `open` it has not sent yet, it sends nothing of that stream.
- A side forgets a stream that it ended: after its `reset`, or the node after its `close` that follows its last bytes; later frames for it are dropped. A side whose own direction is closed resets the stream when the other side sends nothing on it for 10 s.
- Each side buffers at most 256 KiB for one stream; over it, it sends `reset` for that stream. A stream with no bytes for 15 minutes is reset by Connect. The node sends a first frame on a `public` or `acme` stream within 10 s, else Connect resets it.

A broken stream rule resets that stream (`reset` from the side that saw it); it does not close the WebSocket. A `reset` is never answered with a `reset`. `frames.json` names each rule with the codes above.

**WebSocket close codes**: 1000 normal; 1002 a malformed frame; 1003 a text message; 4001 the node went offline (to a dialing device); 4002 `tunnel_limit` during a stream; 4003 the device or the plan was revoked or ended; 4004 the stream was reset by the node; 4005 a newer WebSocket of the same node replaced this one.

## 5. Mapping a dial to the node

For each dial Connect opens a `device` stream on the node's WebSocket with `open` and no payload, then copies each binary message of the dial into frames of up to 16384 bytes, and each frame from the node into one binary message of the dial. The dial's close sends `close`; a `close` from the node closes the dial with 1000 after the last bytes, and Connect sends `close` for the dial's direction; a `reset` from the node closes it with 4004. The node feeds the stream into its TLS front as an accepted connection of kind `device` (plan 0037 unit 2B). Connect tells the node nothing about the caller: the node authenticates the device inside the pinned TLS, as on the tailnet.

## 6. Grants

A grant lets the devices of another account dial the nodes of the granting account: what a team host on a node needs across tailnets without Tailscale (ADR 0037 section 9).

- `POST /v1/tunnel/grants` with `{"node_id":"node_…","account_id":"acc_…"}`, from a device of the node's account, answers the `GrantView`: `{"grant_id":"tgr_…","node_id":"node_…","account_id":"acc_…","created_at":1790000000}`. The grantee must be an active member of a group with the granting account ([connect-billing-v1](connect-billing-v1.md) section 6), else `403 not_in_group`.
- `GET /v1/tunnel/grants` lists the grants that this account made and those made to it.
- `DELETE /v1/tunnel/grants/{grant_id}` (either account) answers `{"grant_id":"tgr_…","closed_streams":1}` and resets the grantee's open streams to that node at once. Removing a member from the group deletes the grants between it and the group.

## 7. The ingress

### 7.1 Port 443: SNI

A TCP listener on the Connect host (`APASSY_CONNECT_INGRESS_LISTEN`, hosted `0.0.0.0:443`, with a DNS-only wildcard record `*.node.apassy.wyderka.cc`; not through the Cloudflare Worker, which is HTTP only).

1. Read the first TLS record, at most 16 KiB, within 5 seconds. Parse only the `server_name` extension of the ClientHello (one `host_name` entry).
2. The name must be `<10 characters>.<zone>` of a registered node with an open WebSocket, whose account is entitled. Else send a fatal alert record `15 03 03 00 02 02 70` (`unrecognized_name`) and close; the same answer for an unknown, offline, or not entitled node.
3. Open a `public` stream with the exact bytes read so far as the payload of `open`, then copy both ways unchanged. Connect writes nothing else into the stream. The stream uses the ingress slots, open rate, and budget of section 8; over them the connection is closed.

### 7.2 Port 80: ACME HTTP-01

A TCP listener (`APASSY_CONNECT_ACME_LISTEN`, hosted `0.0.0.0:80`) for the node's own certificate (Let's Encrypt, HTTP-01; the key never leaves the node).

1. Read the request head, at most 8 KiB, within 5 seconds.
2. Forward only `GET /.well-known/acme-challenge/<token>` (`token` of `[A-Za-z0-9_-]`, 1 to 128 characters), HTTP/1.1, with `Host:` the public name of a registered node with an open WebSocket. Open an `acme` stream with the exact bytes read as the payload of `open` and copy the node's answer back.
3. Anything else gets `HTTP/1.1 404 Not Found`, `Connection: close`, an empty body, and is not forwarded.

The node answers only the token of its own pending order and serves nothing else on `acme` streams.

The ingress keeps client addresses in memory only, for a per-address limit (chosen: 30 new connections a minute), and never logs them.

## 8. Limits

Chosen defaults; configuration, not wire constants.

Each stream of an account's nodes is in one of three classes with their own counts, so no class makes another fail: the dials of the account's own devices, the dials of devices of other accounts with a grant, and the `public` and `acme` streams of the ingress.

| Limit | Value | Over it |
| --- | --- | --- |
| Open dials of one account (its nodes) | 64; of them, at most 16 for each other account and 32 for all other accounts together | `429 tunnel_limit` on the dial |
| Open `public` and `acme` streams of one account | 16, apart from the dials | the ingress closes the connection (port 80: `404`) |
| Nodes of one account | 8 | `403 account_limit` |
| Dials a minute | 60 of the account's own devices; 60 of each other account to the account's nodes, counted apart; the Worker's `TUNNEL_LIMITER` (namespace 1007) 60 a minute for each address | `429 tunnel_limit`; `429 rate_limited` |
| New `public` and `acme` streams of one node a minute | 60 (refused ones count) | the ingress closes the connection |
| Dial bytes of one account a month (both directions) | 20 GiB for each person (Family) or member (Team); other accounts' dials together at most half of it | `429 tunnel_limit` until the first day of the next month (UTC); the open dials of that class close with 4002 |
| Bytes of `public` and `acme` streams of one account a month | 5 GiB for each person or member, apart from the dial bytes | the ingress closes new connections until the first day of the next month (UTC); open ingress streams end |
| The node's first frame on a `public` or `acme` stream | 10 s | `reset` |
| Ping interval / idle WebSocket | 30 s / 90 s | close |
| Idle stream | 15 minutes | `reset` |
| A closed side's wait for the other side | 10 s | `reset` |
| Buffer of one stream | 256 KiB | `reset` |

Connect checks the plan of each account with open streams, and the grant of each open dial of another account, again every 60 s: a plan that ended (also at the end of a period) or a grant that no longer holds (a removed member, a group that ended) ends those streams with 4003.

## 9. What Connect stores and sees

Stored: nodes (id, account, device, name, pin, public name, created_at), grants (id, node, grantee account, created_at), and for each account and month the counts of dials and streams and the bytes, also apart for its ingress and for each other account that dialed its nodes; 13 months with the current one. Sees in memory: the TLS records and plain ACME requests in the streams (not kept), the server names, the client addresses of the ingress, sizes, and times. The node's private keys, the devices' tokens, and what they carry stay inside TLS that ends on the node and is pinned to its certificate. The agents' tokens, session keys, placeholders, and values stay inside TLS that ends on the node for the node's public certificate: Connect does not see them as long as no one else holds a certificate for that name (section 1).

## 10. Not in this contract

Push to the iPhone (the free gateway of plan 0037 unit 2F), the pairing fragment (M5 and relay-questions-v1), the questions, feed, and sync bodies inside the TLS (their own contracts, unchanged), and the TLS front of the node (2B).

## 11. Test vectors

`tests/fixtures/connect-tunnel-v1/frames.json` (made by `generate_frames.py`): valid frames with their fields (an `open` without a payload, data, `close`, a `public` `open` carrying the start of a ClientHello, an `acme` `open` with a request, `reset`, the highest stream id, the largest payload); invalid frames with the code of the first failed check of section 4; and frame sequences on one WebSocket with the index and code of the first broken stream rule. `examples.json` holds one example of every request and result body of section 3 and section 6, and the error bodies.

Both suites must show: every valid frame decodes to its fields and encodes back to the same bytes; every invalid frame fails with its code; every sequence gives its first error; every example parses with strict types. The relay's tests: C4 (`tests/server_tunnel.rs`); the node's: M4 (`tests/connect_tunnel.rs`); the fixture check: `contracts::connect_tunnel_v1_frames_round_trip`.
