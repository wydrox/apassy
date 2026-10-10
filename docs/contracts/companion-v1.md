# Companion wire contract v1

Date: 2026-09-30.
Status: experimental. This contract supports the iPhone companion in [ADR 0020](../adr/0020-iphone-companion.md). The Rust side (`src/companion/`) and the Swift side (`ios/ApassyCompanionKit`) implement it. A change to this document changes both sides in the same pull request.

## 1. Parts

| Part | Location | Feature or target |
| --- | --- | --- |
| Wire types, signatures, pairing, device store | `src/companion/` | `vault` |
| The companion owner check | `src/broker/approvals/owner_auth.rs` (`OwnerCheck::Companion`) | `vault` |
| HTTPS listener on the local network | `src/companion/server.rs` | `vault` |
| Settings > Notifications > iPhone companion in the Mac app | `src/desktop/ui/` | `desktop` |
| Paired devices and listener settings | the vault, schema version 15 | `vault` |
| Wire client, key store, pinned TLS | `ios/ApassyCompanionKit` (Swift package) | iOS 26, and macOS 15 for `swift test` |
| iPhone app | `ios/ApassyCompanion` (XcodeGen project) | iOS 26 |

## 2. Encodings

- **b64u**: base64url without padding (RFC 4648 section 5). Every binary value on this wire uses it: keys, signatures, nonces, the pairing secret, the certificate pin. The Rust side extends its own encoder (`src/native/base64.rs`); it adds no base64 dependency.
- **hex**: lowercase hexadecimal.
- **Public key**: a P-256 point in X9.63 uncompressed form, 65 bytes, first byte `0x04`. Swift: `P256.Signing.PublicKey.x963Representation`. Rust: `ring::signature::UnparsedPublicKey` with `ECDSA_P256_SHA256_ASN1`.
- **Signature**: ECDSA P-256 with SHA-256 over the UTF-8 bytes of a signing string, DER encoded. Swift: `signature(for: Data(string.utf8)).derRepresentation`. Rust: `ECDSA_P256_SHA256_ASN1`.
- **Signing string**: lines joined with `\n` (0x0A). No trailing newline. No field in a line may contain a control character; a request with one gets `400 bad_request` before any signature check.
- **Time**: Unix seconds, a decimal integer.
- **IDs**: run IDs, access request IDs, and activity IDs are decimal strings in JSON (`"123456789012345"`), not numbers. A device ID is 32 lowercase hex characters (16 random bytes), chosen by the phone.
- Every JSON body is UTF-8. Unknown fields in a request cause `bad_request`. A client ignores unknown fields in a response.
- **Characters**: a length in characters counts Unicode scalar values. A control character is a scalar of general category `Cc` (Rust `char::is_control`). A space at the start or the end means any Unicode `White_Space` scalar (Rust `char::is_whitespace`). Both sides use these definitions.

## 3. Transport

- HTTPS, HTTP/1.1 only, TLS 1.3 only. The listener accepts IPv4 on all interfaces on the port in the vault (default `48620`).
- The listener runs only while the setting "Allow the iPhone app on this network" is on **and** the vault is unlocked. A lock stops the listener and drops its TLS configuration and private key from memory. The phone then gets a connection error and says that the Mac is not reachable.
- The listener closes a connection whose peer address is a loopback address or any address of the Mac itself, on any interface. It tests an address by binding a local UDP socket to it, which sends nothing. A program on the Mac, such as an agent, cannot use the companion. Tests and the development server turn this off with an explicit option; the app never does.
- The server certificate is self-signed: ECDSA P-256, made with `rcgen` when the owner turns the setting on the first time, kept in the vault with its private key. It changes only when the owner selects "Reset pairing", which also removes every paired device. A restore from a backup also removes the paired devices and the certificate, as it revokes the agents.
- TLS: one certificate, no SNI needed (the phone may connect by IP), 0-RTT off (the `rustls` default), no session tickets needed. ALPN offers `http/1.1` only.
- **Pin**: `b64u(SHA-256(certificate DER))`. The phone accepts a TLS server only when the leaf certificate has the pin from the pairing link. It ignores the host name and the system trust store, and never falls back to the system trust.
- **Framing**: a request line and headers at most 8 KiB (`413 too_large`). A body needs `Content-Length`, at most 16 KiB (`413`). `Transfer-Encoding` and HTTP/1.0 are refused with `400 bad_request`. A `GET` or `DELETE` with a body gets `400`. The server sends `Connection: close` and closes after each response.
- **Deadlines**: 10 s from accept to the end of the headers, 5 s more for the body. At most 16 connections at the same time, at most 4 from one IP address.
- **Rates**: a request without a valid signature gets at most 30 answers per minute from one IP address; more get `429`. A pair status poll with a correct proof does not count in that limit. A paired device gets at most 120 requests per minute.

## 4. Errors

Each error has an HTTP status and this body:

```json
{"error":{"code":"not_waiting","message":"The run no longer waits. Nothing was approved."}}
```

| Status | Code | When |
| --- | --- | --- |
| 400 | `bad_request` | Malformed JSON, an unknown field, a field out of range or with a control character, a wrong path, a wrong header format, `Transfer-Encoding`, HTTP/1.0. |
| 401 | `unauthorized` | A bad request signature, a missing header, a reused nonce. For `POST /v1/pair`: no open window, a used window, or a bad proof. These three give the same answer. |
| 401 | `clock_skew` | The request time is more than 60 s from the Mac time. The message names the difference in seconds. |
| 401 | `unpaired` | The device ID is not paired, or the owner removed it. The phone deletes its pairing. |
| 403 | `owner_check_failed` | The approval signature does not verify with the approval key of the device. |
| 403 | `stale` | The approval time is more than `PROOF_LIFETIME` (60 s) old, or more than 60 s in the future. |
| 404 | `not_waiting` | The run or the access request no longer waits. |
| 404 | `not_found` | An unknown path, or a pair status with a wrong device ID or proof. |
| 409 | `changed` | The digest does not match the run that waits now. |
| 409 | `nothing_to_remember` | "Approve and remember" for a run without a pattern offer. |
| 409 | `already_paired` | A pair request with a device ID that is already paired. |
| 413 | `too_large` | The body or the headers are over the limit. |
| 423 | `vault_locked` | The vault was locked or changed during the request. |
| 429 | `too_many_requests` | A rate limit. |
| 500 | `internal` | Anything else. The message has no secret value, no path of the vault, and no key. |

The message is text for the owner. The phone shows it as it is. The Mac may log the exact cause of a `401` locally; it never sends it.

Which code wins:

- A missing or malformed signed header (section 6) gets `401 unauthorized`, not `400`.
- On `GET /v1/pair/<device_id>`, a malformed device ID or a missing or malformed `X-Apassy-Pair-Proof` gets `400`. A well-formed but wrong one gets `404 not_found`.
- An unknown path, or an unknown method on a known path, gets `404 not_found`. A malformed ID in a known route (for example `/v1/runs/abc/deny`) gets `400`, and only after the signature check, so an unsigned caller learns nothing.

## 5. Pairing

### 5.1 The pairing link

The owner selects "Pair an iPhone" in Settings > Notifications > iPhone companion. The Mac makes a 32-byte random secret and opens a pairing window for 5 minutes. It shows the link as a QR code only. It never puts the link on the pasteboard: an agent can read the pasteboard (isolation section 4).

```
apassy://pair?v=1&h=Mac-mini.local,192.168.1.20&p=48620&c=<pin b64u>&s=<secret b64u>&n=Mac%20mini&e=1790000300
```

| Parameter | Meaning |
| --- | --- |
| `v` | Contract version, `1`. |
| `h` | Hosts to try, comma-separated: the active, locally assigned Tailscale IPv4 address first, then the `.local` name of the Mac (`scutil --get LocalHostName` + `.local`), then its primary IPv4 address on the local network. The Tailscale CLI must report `Running` and identify the address in `Self.TailscaleIPs`. Other tunnel addresses, loopback addresses, and link-local addresses (`169.254.0.0/16`) are excluded. Duplicate hosts are removed. At most 4. The phone tries Tailscale first to avoid a Bonjour timeout when it is away from the local network. |
| `p` | Port. |
| `c` | Certificate pin (section 3). |
| `s` | Pairing secret. |
| `n` | Mac name for the phone, percent-encoded, at most 40 characters. |
| `e` | Window expiry, Unix seconds. |

The link is the payload of the QR code, not a URL that iOS opens: the app registers no URL scheme in v1, and it scans the code inside the app. A simulator build, which has no camera, may take the link from a launch argument for development; a device build never does. The phone refuses a link with another `v`, a missing parameter, a pin or a secret that is not 32 bytes, or an expiry in the past. The link works for one pairing, for 5 minutes, and only with the owner's confirmation on the Mac (5.4).

### 5.2 Device keys

The phone makes a device ID (16 random bytes) and two P-256 keys in the Secure Enclave before it pairs:

| Key | Access control | Signs |
| --- | --- | --- |
| Request key | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `.privateKeyUsage` | every request (section 6) |
| Approval key | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `.privateKeyUsage` + `.biometryCurrentSet`. No `.devicePasscode`: there is no passcode fallback. | the pair string once (5.3), then only approvals (section 7) |

Each signature by the approval key uses a new `LAContext` with `touchIDAuthenticationAllowableReuseDuration = 0`, so the Secure Enclave asks for Face ID or Touch ID each time. The prompt reason is `approve a run of agent "NAME"`, where NAME is the agent name with control characters and `"` removed, at most 40 characters, as on the Mac. For the pair string the reason is `pair with Apassy on "MAC NAME"`.

A device without a Secure Enclave or without enrolled biometry cannot pair. The iOS Simulator has no Secure Enclave: a simulator build uses software keys in the keychain and says so on the pairing screen. A new Face ID enrollment makes the approval key unusable; the phone then asks the owner to pair again.

### 5.3 Pair request

`POST /v1/pair` has no request signature. It works only while a pairing window is open.

```json
{"v":1,"device_id":"d4c0ffee00000000000000000000beef","device_name":"Test iPhone","request_key":"<b64u>","approval_key":"<b64u>","request_key_signature":"<b64u>","approval_key_signature":"<b64u>","proof":"<b64u>"}
```

The pair string:

```
apassy-companion-pair-v1
<device_id>
<device_name>
<request_key b64u>
<approval_key b64u>
```

- `device_name` is 1 to 40 characters, with no control character and no space at the start or the end. The server refuses another name with `400` before it computes anything. The proof and the signatures are over the name exactly as sent.
- `proof` = `b64u(HMAC-SHA256(key: secret, message: pair string))`.
- `request_key_signature` and `approval_key_signature` are signatures of the pair string by each key. They prove that the phone holds both keys. The approval key signature asks for Face ID once.

The server checks, in this order: the fields and their formats (`400 bad_request`); a window is open and has no request yet, and the proof matches, compared in constant time (`401 unauthorized` for all three); both keys parse as P-256 points and both signatures verify (`401 unauthorized`); the device ID is not paired (`409 already_paired`). A valid request moves the window to "waiting for the owner". The window then accepts no other pair request.

Answer `200`: `{"expires_at":1790000300}`.

The phone then shows the **code** and asks the owner to type it on the Mac. Only the phone shows the code; the Mac never shows it. The phone computes it:

```
code string = apassy-companion-code-v1
              <secret b64u>
              <request_key b64u>
              <approval_key b64u>
h = SHA-256(code string)
n = big-endian u32 of h[0..4]
code = n mod 1000000, 6 digits with leading zeros, shown as "ddd ddd"
```

When the phone gets `401` for its pair request while the link is not expired, it says: "This link does not work. Another device may have used it. Select Cancel on your Mac and make a new code."

### 5.4 The owner confirms on the Mac

Settings > Notifications > iPhone companion shows: `"Test iPhone" wants to pair. Type the 6-digit code that the iPhone shows.` The owner types the code and selects **Pair**. The Mac compares the typed code, in constant time, with the code it computes from the waiting request. A wrong code pairs nothing; three wrong codes close the window. A right code starts the owner check (Touch ID or the passphrase) for `OwnerAction::PairCompanion { device_id, device_name, request_key, approval_key }`. After the check, the vault stores the device and the window closes. **Cancel** closes the window; it needs no check. The Mac has one window at a time. A leaked link alone pairs nothing: the attacker's request has a code that only the attacker's device shows.

### 5.5 Pair status

`GET /v1/pair/<device_id>` with the header `X-Apassy-Pair-Proof: <proof b64u>` (the proof of 5.3). The phone asks every 2 s.

```json
{"state":"waiting"}
{"state":"paired","mac_name":"Mac mini"}
{"state":"denied"}
{"state":"expired"}
```

A wrong device ID or proof gets `404 not_found`, and so does a window that has no pair request yet. The server keeps the answer for 5 minutes after the window ends, then answers `404`. A phone that missed the answer checks with a signed `GET /v1/status`: `200` means paired, `401 unpaired` means not.

## 6. Signed requests

Each request after pairing has four headers:

| Header | Value | Format |
| --- | --- | --- |
| `X-Apassy-Device` | Device ID | 32 lowercase hex |
| `X-Apassy-Time` | Unix seconds | decimal, at most 12 digits |
| `X-Apassy-Nonce` | 16 random bytes | 22 b64u characters |
| `X-Apassy-Signature` | Signature of the request string by the request key | b64u |

Request string:

```
apassy-companion-request-v1
<METHOD>
<path>
<device ID>
<time>
<nonce>
<hex SHA-256 of the body bytes>
```

`<path>` is the request target as sent, for example `/v1/runs/123456789012345/approve`. The body hash is over the exact bytes of the body. An empty body hashes to `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

The server checks, in this order: all four headers and their formats (`401 unauthorized`); the device is paired (`401 unpaired`); the time is within 60 s (`401 clock_skew`); the nonce is new for this device in the last 5 minutes (`401 unauthorized`); the signature (`401 unauthorized`). Only then does it record the nonce and update "last seen" of the device.

## 7. Endpoints

### `GET /v1/status`

```json
{"v":1,"mac_name":"Mac mini","app_version":"0.2.1","approval_timeout_seconds":120,"device":{"id":"d4c0ffee00000000000000000000beef","name":"Test iPhone","paired_at":1790000000}}
```

### `GET /v1/inbox`

```json
{
  "runs": [
    {
      "id": "123456789012345",
      "agent": "claude-code",
      "command": ["npm", "run", "migrate"],
      "cwd": "/Users/me/Dev/shop",
      "env_names": ["DATABASE_URL"],
      "purpose": "Apply the new migration.",
      "risk": "production credential: always asks the owner",
      "user_request": "Deploy the new schema to staging.",
      "request_source": "from the host hook",
      "agent_request": "",
      "remember": {"pattern": "npm run migrate", "approvals": 1, "needed": 3},
      "digest": "<64 hex>",
      "waiting_seconds": 12
    }
  ],
  "access_requests": [
    {"id": "42", "agent": "codex", "item_name": "Stripe test key", "reason": "The user asked me to test checkout.", "cwd": "/Users/me/Dev/shop", "requested_at": 1790000000}
  ],
  "activity": [
    {"id": "991", "at": 1790000000, "agent": "claude-code", "decision": "deny", "summary": "stripe charges list", "reason": "The command prints a secret."}
  ]
}
```

- `runs` are the runs in the approval queue, oldest first. Each field comes from `PendingRun`. `remember` is `null` when there is no offer. `waiting_seconds` is the time since the run started to wait, or `null` when the Mac does not know it; it is not part of the digest.
- `digest` is `hex(SHA-256(...))` of an injective encoding of every field of the `PendingRun` (a version tag, then length-prefixed fields; lists with their length). Only the Mac computes it. The phone treats it as opaque and sends it back.
- `access_requests` are the open access requests (ADR 0012), newest first, at most 50. `cwd` is `null` when the request has none.
- `activity` is the newest 50 entries of the activity log, newest first. `decision` is `allow`, `deny`, or `error`. `summary` (the operation or command) and `reason` have at most 300 characters each. The vault keeps the operation at 64 bytes, so only `reason` can reach the cut.
- No field ever has a secret value, a placeholder value, an agent token, a note, or a hidden detail.

### `POST /v1/runs/<id>/approve`

```json
{"digest":"<64 hex>","remember":false,"time":1790000000,"approval_signature":"<b64u>"}
```

Approval string, signed by the **approval key** (Face ID):

```
apassy-companion-approve-v1
<device ID>
<approve | approve_and_remember>
<run ID>
<digest>
<time>
```

`approve_and_remember` when `remember` is true. After section 6, the server checks in this order:

1. The vault is unlocked (`423 vault_locked`).
2. A run with this ID waits (`404 not_waiting`).
3. The digest matches that run (`409 changed`).
4. When `remember` is true, the run has a remember offer (`409 nothing_to_remember`).
5. `OwnerGate::authorize(action, OwnerCheck::Companion { device_id, time, signature })`, with `action` = `OwnerAction::ApproveRun(run)` or `OwnerAction::ApproveAndRemember(run)` for the run as it waits. The gate, not the server, does the check: it loads the approval key of the device from the vault (the device must still be paired), rebuilds the approval string from the action (the action name, `run.id`, the digest of `run`) and `time`, checks the time against `PROOF_LIFETIME`, verifies the signature, and checks the vault session before and after, as for Touch ID. Errors: a time out of range gives `403 stale`; an unpaired device or a bad signature gives `403 owner_check_failed`; a locked or changed vault gives `423 vault_locked`.
6. `ApprovalQueue::approve(proof)`. A refusal maps to `404 not_waiting`, `409 changed`, or `409 nothing_to_remember`.

The vault mutex is taken before the queue mutex, never the other way, as in the broker. Answer: `{"outcome":"approved"}` or `{"outcome":"approved_and_remembered"}`.

The approval string has no nonce, by design. After a network error, a `423`, or a `500`, the phone may send the same `approval_signature` again with a new request nonce while the time is within 60 s. The owner does not need a second Face ID. A run settles once, so a second approval finds no waiting run.

The phone fixes `time` before the Face ID prompt, so a slow prompt uses part of the 60 s. It retries only while the approval is less than 55 s old. When a retry after a network error or a `500` gets `404 not_waiting`, the first attempt may have reached the Mac: the phone does not show "Nothing was approved"; it says "The Mac may have approved this run. Check Activity."

The phone signs the digest of the run snapshot that the owner sees. When the inbox later shows another digest for the same run ID, the phone shows the new run before the owner can approve it. The Mac's `409 changed` is the backstop.

### `POST /v1/runs/<id>/deny`

Body `{}`. It needs no approval signature. Answer: `{"outcome":"denied"}`, or `404 not_waiting`. A denial by the owner is recorded as today, so it also blocks a remembered pattern (ADR 0010).

### `POST /v1/access-requests/<id>/deny`

Body `{}`. Answer: `{"outcome":"denied"}`, or `404 not_waiting`. The phone cannot give access in v1; it says "Give access in Apassy on your Mac".

### `DELETE /v1/device`

The phone removes its own pairing. Answer: `{"outcome":"unpaired"}`. The phone then deletes its keys and its pairing record.

## 8. The phone

- It stores in the keychain, this device only, never synchronized: the device ID, the Mac name, the hosts, the port, the pin, the pairing time, and the two key references (Secure Enclave `dataRepresentation`). It stores no inbox, no activity, and no command on disk; its URL session is ephemeral with no cache.
- It needs `NSLocalNetworkUsageDescription`, `NSCameraUsageDescription`, and `NSFaceIDUsageDescription`. When iOS refuses local network access, it says: "Allow local network access for Apassy in Settings > Privacy & Security > Local Network."
- The URL session permits cellular access, but each request permits it only for a numeric Tailscale IPv4 destination in `100.64.0.0/10`. Bonjour and other destinations retain the cellular restriction. The certificate pin check remains mandatory.
- It tries the hosts in order. After a connection error, a TLS error, or a pin mismatch it tries the next host. It remembers the last host that answered. When every host fails with a pin mismatch, it offers "Forget this Mac": the Mac was reset, or another device answers.
- It asks `GET /v1/inbox` every 2 s while the app is in the foreground and stops in the background. The app hides its content in the app switcher.

## 9. Test vectors

These values are synthetic. Both test suites use them. The private keys are the raw 32-byte scalars.

| Name | Value |
| --- | --- |
| Request key, private (hex) | `71c2b0317a434582145879f70d13e172c602ea37c2c4fada95a83679867a2676` |
| Approval key, private (hex) | `bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b` |
| Request key, public (b64u) | `BIcY3rZ6TdzHFNUttUCSdryZE3YayizgQ0KT5D1LKMdwv4E2AxLTggQEYU3HYfQzwIm-fdsPZYt5aEYV6-EJskE` |
| Approval key, public (b64u) | `BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts` |
| Pairing secret (b64u) | `s9IIzFKuwMPGM-IW92PJK8U5dG0y14hgHYP9lX4UI0g` |
| Device ID | `d4c0ffee00000000000000000000beef` |
| Device name | `Test iPhone` |
| Pair proof (b64u) | `KGSWHAv-NdQat1HFN0hqCLYCiGJnuQaxbQ3kogGaqFE` |
| Pair string signature by the request key (b64u) | `MEYCIQCDKleQt7-bz06sJBuMu2Mgxo4-sOmKfR8ZnRk3WX-xPgIhAMidi2mo3Lbz1aK4ROOSYNlvsoWqc-RI7Zbi5oLDHujf` |
| Pair string signature by the approval key (b64u) | `MEUCIQC-Lswfys1i6xzmUbXHou1gX-N5cpBnnrH6wkqo4LU46gIgIqEtSlpfzZhyiJuHgALfdyQ0Uu6XlIC3w_dL60VmQUQ` |
| Code hash (hex) | `7050e20eb0016a113bfb886cf0ca8e4eefc9bccd1861d2d9f292aa637ca28555` |
| Code | `348 942` |
| Nonce (b64u) | `AAECAwQFBgcICQoLDA0ODw` (bytes 0 to 15) |
| Time | `1790000000` |
| SHA-256 of `{"remember":false}` (hex) | `c21638494d6f31b1eb753c01dc27df1491cafaa42e908bf82eaede49134884c3` |
| Certificate pin of the DER bytes `30 00` | `5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU` |

The pair string of these vectors:

```
apassy-companion-pair-v1
d4c0ffee00000000000000000000beef
Test iPhone
BIcY3rZ6TdzHFNUttUCSdryZE3YayizgQ0KT5D1LKMdwv4E2AxLTggQEYU3HYfQzwIm-fdsPZYt5aEYV6-EJskE
BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts
```

Request string (`GET /v1/inbox`, empty body), signed by the request key; the signature must verify:

```
apassy-companion-request-v1
GET
/v1/inbox
d4c0ffee00000000000000000000beef
1790000000
AAECAwQFBgcICQoLDA0ODw
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Signature (b64u): `MEQCICGLPWDhC0B33p0zHBaApsO593Vzug0WuvtkmZ5F6Wx3AiB5QXmACxIlrPnUhtpTMplEC2h1h6fqwvAyUIOA2PFipw`

Approval string (digest = `ab` repeated 32 times), signed by the approval key; the signature must verify:

```
apassy-companion-approve-v1
d4c0ffee00000000000000000000beef
approve
123456789012345
abababababababababababababababababababababababababababababababab
1790000000
```

Signature (b64u): `MEUCIEdCbu0iVNdaKys-5EkPMdAn4R79c0p0wtlE9Jnk5QtfAiEAtyrTuQWKWoTxZRvziO4_A-NK1QD5B-gXMiuV5Pvs9wo`

ECDSA signatures are randomized: a new signature of the same string differs and still verifies. A test must also show that each signature fails after one changed character of its string, and fails with the other key.
