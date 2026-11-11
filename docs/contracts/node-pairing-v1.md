# Node pairing contract v1

Date: 2026-11-03.
Status: frozen for [implementation plan S2–S3](../design/implementation-plan-s2-s3.md) (unit N0). Section 7a (the Connect route) added 2026-11-10 by [plan s7](../design/implementation-plan-s7-connect.md) unit I2, additive: every link of the earlier text reads as before. Units N3 (the parser and the pinned client, Rust, Mac and iPhone core), N4 (the Mac node's links), L1 (`apassy pair` on the Linux node), L4 (the Mac's relay sheet), and N6 (the iPhone app) implement it. Fixtures: `tests/fixtures/node-pairing-v1/`, checked by `contracts::node_pairing_v1_fixtures_match_the_contract` in `tests/contracts.rs`.
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) §2 to §4 and D4; plan decisions D1, D2, D4, D5.

MUST and MUST NOT are implementation requirements.

## 1. Purpose and scope

A Mac or a Linux machine runs a **node**: the relay of the questions, the feed, the access requests, and relay sync, served on its own tailnet address behind a self-signed certificate. A device reaches the node only when it knows two things that a link carries: the **origin** (the address that the device stores, signs at sign-in, and shows) and the **pin** (the SHA-256 of the node's certificate). This contract defines:

- the node origin (section 3);
- the pin and the pinned trust of a client (section 4);
- the fragment grammar of two link kinds: the **device link** (`/link#`, ADR 0019 device link code) and the **node pairing link** (`/pair#`, a one-use team code of kind `node`) (sections 5 to 7);
- the Connect route of a node (section 7a, Apassy Connect, ADR 0037 stage 7);
- how the ADR 0032 handoff and the pin go together (section 8);
- what a reader stores and does (section 9).

The wire contracts relay-sync-v1, relay-questions-v1, relay-feed-v1, and relay-access-request-v1 do not change: a node serves them at its origin. The fragment never reaches a server (it is the part after `#`).

Out of scope: Tailscale Serve certificates (ADR 0037 D4, an option for later), the LAN route (D6, later; it will use the same grammar), the rest of Apassy Connect (stage 7: accounts, the tunnel itself, [connect-tunnel-v1](connect-tunnel-v1.md)), WhoIs checks.

## 2. Words

| Word | Meaning |
| --- | --- |
| Node | The relay inside the Mac app (`RelayConfig::embedded`) or `apassy serve` on Linux, with its TLS front on the tailnet addresses |
| Node origin | `https://<Tailscale IPv4>:<port>`: the string every device stores as `relay_url`, signs, and shows |
| Alternative | Another destination of the same node (its MagicDNS name, its Tailscale IPv6). A client connects to it with the **same** origin string and pin |
| Pin | `b64u(SHA-256(DER of the node certificate))`, 43 characters |
| Pinned origin | An origin that a device stores with a pin. Every connection to it checks the pin and nothing else |
| Hosted origin | An origin without a pin (`https://apassy-relay.wyderka.cc` and self-hosted relays with a public certificate). System trust, as today |

## 3. The node origin

- Form: `https://<host>:<port>`, the canonical text of `RelayUrl::as_str()` (relay-sync-v1 §3): lowercase, no path, query, user, or trailing slash, and an **explicit port** that is not 443. A pinned link with another form is refused (section 7, `bad_origin`).
- The node uses its Tailscale IPv4 address (in `100.64.0.0/10`) as `<host>`. It is stable while the node stays in the tailnet; MagicDNS can be off, so the name is not the origin. Clients do not check the range: the pin is the authority, not the address.
- The default port is **8444** (next to the Funnel port 8443; never 443, which serves T3 Code through Tailscale Serve on the owner's Mac). It is a node setting. A change after the first pairing changes the origin, so every device must pair again; Settings and `apassy doctor` say so.
- `http://` is never a pinned origin. A link with `http://` and a pin is refused.
- The relay of a node accepts sign-ins signed with any origin of its set `sign_in_origins` (the node origin, and on a Mac with the public route on, the Funnel `public_url`). The sign-in message of ADR 0019 §5 (`apassy-relay sign-in v1\0<origin>\0<team>\0<key>\0<nonce>`) does not change. The hosted relay keeps exactly one origin.
- The Mac's own clients reach its node over the loopback without TLS (plan D1, the local route table). That is internal to the Mac: it signs the node origin and never appears in a link.

## 4. The pin and pinned trust

- The node certificate: P-256, self-signed, 10 years, subject `CN=Apassy node <machine name>`, made at the first start and kept (plan D2). The pin is `b64u(SHA-256(DER))` of the leaf certificate, without padding: exactly 43 characters of `A-Za-z0-9-_`, the canonical b64u of 32 bytes. It is the format of the Wi-Fi companion and of `PinnedTLS.pinText` on the iPhone.
- A client with a pinned origin (`TlsTrust::Pinned`) MUST:
  - use TLS 1.3 only, with ALPN `http/1.1`;
  - compare the SHA-256 of the presented **leaf** DER with the pin in constant time and accept the connection only when they are equal;
  - ignore the names, the dates, and the issuer of the certificate, and any further certificates in the chain (a chain whose leaf does not match is refused even if a later certificate matches);
  - never fall back to system trust, to another pin, or to `http://` for that origin, also not after an error;
  - refuse before it sends a request byte when the pin does not match (`pin_mismatch`).
- A client with a hosted origin (`TlsTrust::System`) is unchanged: rustls with the platform verifier on the Mac and the iPhone, URLSession with ATS on the watch.
- The watch (ADR 0039 §5) uses URLSession: a request to a pinned origin carries the pin, and the transport accepts only the pinned leaf (`PinnedTLSDelegate`).
- A pin changes only with a new node certificate. A device that meets another certificate says "This node's certificate changed. Pair again." and does not connect. A new pairing (a new link) replaces the stored pin; nothing else does.

### 4a. Node words

The **node words** are six words that a person compares between the Mac and the iPhone to see that both mean the same node certificate (Settings › Devices on the Mac, "via your Mac" on the iPhone). They are a visual check, never the trust: a client compares the whole pin (section 4). The words are the first six bytes of the pin, about 48 bits, and the pinned verifier ignores the certificate's own signature, so a certificate with the same words can be ground out with about 2^48 hashes. No text presents them as proof of the node: the apps call them safety words to compare ("Node words to compare" on the iPhone), and a "certificate changed" flow never accepts a node because its words match ([N8-7](../reviews/node-tailnet-2026-11/n8-panel.md)).

- Input: the 32 bytes of the pin, that is `SHA-256(DER of the leaf certificate)` before base64url (so the decoded 43-character pin text gives the same bytes).
- Words: for `i` = 0 to 5, `WORDS[pin[i]]`, where `pin[i]` is the byte at index `i` (0 to 255) and `WORDS` is the list of relay-sync-v1 section 16 (256 words, index order, all lowercase ASCII). Bytes 6 to 31 are not used.
- Text: the six words in this order, lowercase, joined with one ASCII space (`0x20`), without a leading or trailing space and without any other separator.
- Source: Rust `Pin::words` in `src/net/pin.rs` (`apassy::net::pin::Pin`), used by the Mac (`node::tailnet::pin_words`) and by the iPhone core (field `node_words`, [ios-core-v1](ios-core-v1.md) section 5.2 and the questions `node` info). The Swift app shows the field and never computes the words.
- Vector: the certificate of section 12 has the pin bytes `bb b4 62 ef 89 7f …`, which are the word indexes 187, 180, 98, 239, 137, 127, and the node words `noodle monkey dinner sled guitar garden`.

## 5. Link grammar

ABNF (RFC 5234). The text is ASCII; `name` carries UTF-8 through percent-encoding.

```
link          = device-link / pair-link
device-link   = origin "/link#" link-code [ pinned ] [ "&handoff=" handoff ]
pair-link     = origin "/pair#" team-code pinned
pinned        = "&pin=" pin [ "&alt=" alt-list ] [ "&node=" node-id ] [ "&name=" name ]
origin        = "https://" host [ ":" port ]          ; section 3; a pinned link needs the port
link-code     = "apassy_lnk_" team-id "_" 64hexlower  ; relay-sync-v1 §2
team-code     = "apassy_tcd_" 64hexlower              ; a team code of kind node (section 6)
pin           = 43b64u                                ; section 4
alt-list      = alt *3( "," alt ) / *3( alt "," ) route ; 1 to 4 entries in all
alt           = alt-host [ ":" port ]
route         = "wss://" alt-host [ ":" port ] "/v1/tunnel/dial/" node-id   ; section 7a, the last entry
node-id       = "node_" 10( %x61-7A / "2" / "3" / "4" / "5" / "6" / "7" )   ; connect-tunnel-v1 §2
alt-host      = ipv4 / "[" ipv6 "]" / dns-name
name          = 1*( unreserved / pct-encoded )        ; section 7
handoff       = "2." qid "." b64u-32 "." b64u-65      ; relay-questions-v1 §21, unchanged
unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
pct-encoded   = "%" UPHEX UPHEX
UPHEX         = DIGIT / %x41-46                       ; uppercase A to F only
```

Rules of the fragment:

1. The keys come in the order `pin`, `alt`, `node`, `name`, `handoff`. Each appears at most once. `alt`, `node`, and `name` need `pin` (a hosted link has none of them). `handoff` is always last and only in a device link.
2. An unknown key (also a key without `=`), a repeated key, a key out of order, or an empty value refuses the whole link. There is no `?` and no second `#`.
3. A link is at most 2048 bytes. The reader trims ASCII white space at both ends of a pasted text (as today) and nothing inside.
4. A link without `pin` is a hosted link: today's form, today's behaviour, system trust.
5. A future key needs a new contract version. An app of this version refuses a link with it and says "Update Apassy to use this code."

## 6. The two link kinds

| Kind | Path | Code | Made by | Used for |
| --- | --- | --- | --- | --- |
| Device link | `/link#` | `apassy_lnk_<team>_<64 hex>`, one use, the lifetime of relay-sync-v1 §7 (`POST /v1/devices/links`) | A device of the team on the node (the Mac: "Add an iPhone or a Mac…") | A new device joins an existing team: `POST /v1/devices/link` at the origin, safety words, owner confirmation (relay-sync-v1 §7.2) |
| Node pairing link | `/pair#` | `apassy_tcd_<64 hex>`, a `team_code` of kind `node`, one use, **10 minutes** | `apassy pair [--minutes 10]` on the node (Linux, plan D8) | A Mac makes a new team on that node: `POST /v1/teams` at the origin (relay-sync-v1 §6). Relay directory 1005 holds the kind |

- A node pairing link is always pinned and never has a handoff.
- The Mac's own device links name the **node origin** (never the loopback destination) and the node's pin (`LinkCode::for_origin`).
- A Mac whose questions team is on its own node makes the team in-process; it needs no node pairing code.
- `--minutes` is 1 to 10; the default and the maximum are 10.

## 7. Values

**`pin`** — section 4. Not 43 characters, a character outside the b64u alphabet, or a non-canonical last character (padding bits set): `bad_pin`.

**`alt`** — 1 to 4 alternative destinations, separated by `,`:

- `ipv4`: four decimal octets 0 to 255 without leading zeros (`100.64.0.7`).
- `[ipv6]`: the RFC 5952 text (lowercase, the longest run of zeros compressed, no zone), in brackets (`[fd7a:115c:a1e0::7]`).
- `dns-name`: 1 to 253 characters of lowercase LDH labels, each 1 to 63 characters, no label starting or ending with `-`, no trailing dot, at least two labels (`apassy-mini.tail0123.ts.net`).
- `port`: 1 to 65535 without leading zeros. Without a port, the origin's port.
- An entry equal to the origin's host and port, a repeated entry, `0.0.0.0`, `::`, a loopback, or a link-local address: `bad_alt`.

The client connects to the origin's host first, then each alternative of the tailnet in order, until one connects (the Connect route of section 7a comes after them). A refused or timed-out connection tries the next; a pin mismatch stops at once (no alternative is tried after a wrong certificate). Every attempt sends the same `Host` (the origin's host and port) and signs the same origin. The connect deadline of relay-sync-v1 §3 holds per address, and the total for all addresses is at most 30 s.

**`name`** — the node's display name, UTF-8, percent-encoded in one canonical form: each byte of `A-Za-z0-9-._~` is literal, every other byte is `%` and two **uppercase** hex digits. A literal byte written as `%XX`, lowercase hex, invalid UTF-8, more than 40 Unicode scalar values after decoding, a control character (Unicode `Cc`), U+2028, or U+2029: `bad_name`. The name is a label ("via Mac mini “Studio”"), never an authority: the safety words and the owner confirmation are.

**`node`** — section 7a.

**Codes** — not of their form: `bad_code`. A `/pair#` link with a link code, or a `/link#` link with a team code: `bad_code`.

**`handoff`** — the bytes of relay-questions-v1 §21, unchanged. Out of form: `bad_handoff`.

When a link has several faults, the reason is the first of: `too_long`, `bad_origin` (no `/link#` or `/pair#`, a `?`, or a second `#`), `unknown_key`, `repeated_key`, `key_order`, `empty_value`, `bad_code`, `needs_pin`, `handoff_on_pair`, `bad_origin` (the form of section 3), `bad_pin`, `bad_alt`, `bad_connect`, `bad_node`, `bad_name`, `bad_handoff`. Within `alt`, every tailnet entry is checked (`bad_alt`) before the route (`bad_connect`).

## 7a. The Connect route

A node on Apassy Connect (ADR 0037 stage 7, [connect-tunnel-v1](connect-tunnel-v1.md)) can also be reached through the Connect dial when no tailnet address answers. Its link carries that second route beside the tailnet address:

```
…&pin=<pin>&alt=<tailnet entries,>wss://<Connect host>/v1/tunnel/dial/<node id>&node=<node id>[&name=…][&handoff=…]
```

- **The route** is one `alt` entry and always the last one: `wss://`, the Connect host (a host of the `alt-host` form: lowercase, no user; the port only when it is not 443), the path `/v1/tunnel/dial/`, and the node id (`node_` and 10 characters of `a-z2-7`, connect-tunnel-v1 section 2), with nothing after it. It counts as one of the 4 entries. A link has at most one route.
- **The Connect host** of the route MUST be the host and port of the Connect origin that the reader is configured with (the Mac: `APASSY_CONNECT_URL` or `https://apassy-relay.wyderka.cc`; the iPhone core: `connect_url` of its config, the same default). A route through any other host is refused, so a code cannot send a device's account token to another server.
- **`node`** is the node id again, and MUST equal the node id of the route. A route without `node`, a `node` without a route, or two different ids: `bad_node`.
- **Refusals**: an `alt` entry with a scheme (`://`) that is not the canonical route (`ws://`, `https://`, another path, a trailing slash, a port 443 written, uppercase, a user, a node id of another form), a second route, a route that is not the last entry, or a route through another Connect host: `bad_connect`. Five entries with the route: `bad_alt`.
- **What a reader does** (section 9, more): it keeps the route as the last entry of the stored alternatives (`RelayLink.alt`, `relay_membership.alt`, `VaultEntry.alt` of `phone.json`; no new column, no schema change), tries the origin's host and the tailnet alternatives first, and only then the dial: `GET /v1/tunnel/dial/{node id}` at its own Connect origin with its account token (connect-tunnel-v1 section 3.3), and inside that byte pipe the same pinned TLS of section 4 to the node, with the same `Host` and the same signed origin. A pin mismatch through the dial stops at once, as on the tailnet. A device without a Connect account never dials; the route is kept.
- **The fragment never reaches a server**: Connect sees the node id in the path of the dial, never the link, the code, or the pin.
- **Old readers**: a reader of the earlier text of this contract refuses a link with `node` (`unknown_key`, "Update Apassy to use this code."). The Mac adds the route only for a node that is on Connect (plan s7 unit M5).
- **Builder and reader**: one of each, shared by the Mac and the iPhone core: `PairedLink::format_with(kind, url, code, name, Some(route))` (or `format` of an address with its route, `RelayUrl::with_tunnel`), and `PairedLink::parse`. Vectors: `tests/fixtures/node-pairing-v1/connect-route.json` (the four links of section 12 read without a route, three new links, and every refusal with its reason). Reasons are for logs and tests; every refusal shows one text: "This code isn't valid. Make a new code on the node." (the iPhone core's `link_invalid`).

## 8. The handoff and the pin

- The ADR 0032 handoff AAD and safety-word input contain "the original full link without handoff". For a pinned link that is the link text up to, not including, `&handoff=`: the origin, the code, and the `pin`, `alt`, and `name` parameters exactly as written. So the safety words cover the pin: a link with a changed pin gives other words on the two devices.
- For a link without a pin, the text is the same as before this contract, so the vectors of ADR 0032 and relay-questions-v1 §21 do not change.
- The device strips the handoff (and only the handoff) before any relay call, as today. The pin, `alt`, and `name` are never sent to a server either: the reader uses them locally.

## 9. What a reader does

1. Parse the whole text with this grammar (`PendingJoin::parse_link` → `PairedLink { origin, kind, code, pin, alt, name, handoff }`). A refusal makes no request.
2. Connect with `TlsTrust::Pinned(pin)` when there is a pin, else `TlsTrust::System`, to the origin and then the alternatives (section 7).
3. Run the flow of the link kind (section 6) with the origin as the signed and stored value.
4. Store the trust with the membership, never in synced data:
   - Mac: `RelayLink { url, team_id, device_id, pin, alt }` in `vaults.json`, and `relay_membership.pin`, `relay_membership.alt` (a JSON list) in the vault (**vault schema 28**, a local table, no sync change);
   - iPhone: `VaultEntry { pin, alt }` in `phone.json` (list version stays 1; missing fields read as no pin and no alternatives), and the same membership columns; the Connect route of section 7a is the last entry of `alt`;
   - watch: the same membership columns in its replica vault (ADR 0039 §4); the iPhone forwards the full link (ADR 0039 §6) and keeps nothing.
5. Never replace a stored pin or alternatives except through a new pairing of that team. A membership with a pin never connects without it.

## 10. Numbers

| What | Value |
| --- | --- |
| Contract | `node-pairing-v1` |
| Default node port | 8444 |
| Pin | 43 characters, b64u of SHA-256 |
| Alternatives | at most 4, the Connect route included (section 7a) |
| Connect route | at most 1, the last `alt` entry, through the configured Connect host |
| Name | at most 40 Unicode scalar values |
| Link length | at most 2048 bytes |
| Node pairing code | one use, 10 minutes (at most), kind `node` |
| Vault schema (pin and alternatives) | 28 |
| Relay team schema | 8 (push handles, [push-gateway-v1](push-gateway-v1.md)) |
| Relay directory | 1005 (`team_code.kind`) |
| Handoff | version `2`, relay-questions-v1 §21 |

## 11. What this does not protect

- A person who can replace the QR code or the pasted text can give a device another node and pin. The safety words and the owner's confirmation on a device of the team are the check, as for hosted links.
- The origin's address can change when the node leaves and rejoins the tailnet; the devices then need a new pairing (`apassy doctor` says so). Alternatives do not help: the origin is the signed value.
- The pin proves the certificate, not the tailnet peer. Tailscale identity is never authorization (ADR 0037 §3).
- Who holds the node's certificate key (sealed under the node master key, plan D2) can be that node.

## 12. Test vectors

These values are synthetic. `contracts::node_pairing_v1_fixtures_match_the_contract` recomputes the pin, parses every accepted link with a reference parser of this grammar, and refuses every refused link with its reason. Unit N3 checks `PendingJoin::parse_link` against the same table.

| Name | Value |
| --- | --- |
| Certificate | `tests/fixtures/node-pairing-v1/node-cert.der` (297 bytes, P-256, `CN=Apassy node Test Mac`) |
| SHA-256 of the certificate (hex) | `bbb462ef897fc4c066ef85e76435a9382e99e29ea7e1a52ac169ac57a7e2acb1` |
| Pin | `u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE` |
| Node words (section 4a) | `noodle monkey dinner sled guitar garden` |
| Origin | `https://100.64.0.7:8444` |
| Link code | `apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab` (relay-sync-v1 §15) |
| Team code | `apassy_tcd_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` |
| Name | `Mac mini “Studio”`, encoded `Mac%20mini%20%E2%80%9CStudio%E2%80%9D` |
| Handoff qid (bytes `a0` to `af`) | `oKGio6SlpqeoqaqrrK2urw` |
| Handoff secret (bytes `00` to `1f`) | `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8` |
| Handoff Mac public key (the X9.63 point of the scalar of 32 bytes `11`) | `BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q` |

**Accepted links** (the text is one line):

1. A device link with every key (430 bytes):

```
https://100.64.0.7:8444/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=Mac%20mini%20%E2%80%9CStudio%E2%80%9D&handoff=2.oKGio6SlpqeoqaqrrK2urw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q
```

   Parsed: kind device, origin `https://100.64.0.7:8444`, the link code, the pin, alternatives `apassy-mini.tail0123.ts.net:8444` and `[fd7a:115c:a1e0::7]:8444`, name `Mac mini “Studio”`, the handoff. The handoff AAD's "original full link without handoff" is:

```
https://100.64.0.7:8444/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=Mac%20mini%20%E2%80%9CStudio%E2%80%9D
```

2. A handoff right after a pin:

```
https://100.64.0.7:8444/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&handoff=2.oKGio6SlpqeoqaqrrK2urw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q
```

3. A node pairing link:

```
https://100.64.0.7:8444/pair#apassy_tcd_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=build-box
```

4. A hosted link with a handoff (no pin, today's form; today's `PendingJoin::parse_link` accepts it):

```
https://apassy-relay.wyderka.cc/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&handoff=2.oKGio6SlpqeoqaqrrK2urw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q
```

**Refused links.** Each is link 1 or link 3 with one change (written as the change):

| Change | Reason |
| --- | --- |
| `&foo=1` before `&handoff=` | `unknown_key` |
| a second `&pin=…` after the first | `repeated_key` |
| `&name=…` before `&pin=…` | `key_order` |
| `&pin=…` after `&handoff=…` | `key_order` |
| `&alt=…` without `&pin=…` (a hosted origin) | `needs_pin` |
| `&pin=` (empty) | `empty_value` |
| a pin of 42 characters | `bad_pin` |
| the pin with its last character `E` changed to `F` (padding bits set) | `bad_pin` |
| origin `http://100.64.0.7:8444` | `bad_origin` |
| origin `https://100.64.0.7` (no port) | `bad_origin` |
| origin `https://100.64.0.7:8444/` (trailing slash) | `bad_origin` |
| five alternatives | `bad_alt` |
| alternative `100.64.0.7:8444` (the origin) | `bad_alt` |
| alternative `[FD7A:115C:A1E0::7]` (not RFC 5952) | `bad_alt` |
| alternative `127.0.0.1` | `bad_alt` |
| name `Mac%20mini%20%e2%80%9cStudio%e2%80%9d` (lowercase hex) | `bad_name` |
| name `%4Dac` (a literal byte encoded) | `bad_name` |
| name `Mac%0Amini` (a control character) | `bad_name` |
| name of 41 letters `a` | `bad_name` |
| `/pair#` with the link code | `bad_code` |
| `/pair#…` with `&handoff=…` | `handoff_on_pair` |
| `/pair#…` without `&pin=…` | `needs_pin` |
| a link of 2049 bytes | `too_long` |
