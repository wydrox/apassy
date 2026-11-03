# Private sharing contract v1

Date: 2026-11-03 (revised 2026-11-03, section 13). Status: frozen for implementation (wave 1 of the plan).
Fixtures: [`tests/fixtures/private-sharing-v1/`](../../tests/fixtures/private-sharing-v1/), checked by
`contracts::private_sharing_v1_*` in `tests/contracts.rs`.
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) stage 6, section 10 steps 1 to 3, D11. Plan:
[implementation-plan-s6-sharing.md](../design/implementation-plan-s6-sharing.md) (unit A; decisions S6-1
to S6-14).

This contract defines short-lived credentials ("way C"), remote SigV4 signing, and the wire and storage
shapes that the units C1, C2, D, E1, E2, F, G, H, I, J1, K, and L share: the kinds and their fields and
settings, the lease, the session view additions, the access item credential form, the sign endpoint, the
codes, and the audit and activity rows. MUST and MUST NOT are requirements on every implementation. A
change to a field, a name, a code, or a rule of this document needs a dated revision here and the
fixtures in the same change.

## 1. Words

| Word | Meaning |
| --- | --- |
| Key holder | The process that holds the long-lived secret: the owner's app for local runs and for its node (cloud agents), the team host node for members (stage 4). |
| Source | A vault item with a `short_lived` row (section 3). Its fields hold the long-lived secret. |
| Lease | The short-lived credential that the key holder makes from a source for one run (section 4). |
| Way C | Delivery of a lease instead of a value or a placeholder. |
| Signed requests | Delivery of a placeholder for an AWS secret access key; a proxy or the key holder signs each request with the real secret (section 7). |
| Agent's side | Everything that the agent can read: the child's environment, the run output, the session view, the MCP answers, and the member's or the cloud machine's disk. |

## 2. The rules

1. **The long-lived secret never leaves the key holder (S6-1).** The key holder calls the provider with
   it and releases only the lease. The agent's traffic goes direct to the provider.
2. **Automatic (D11).** Way C applies to every item whose kind is in section 3 and whose `short_lived`
   row is `enabled`, in way A and in way B. Ways A and B then apply only to static keys. A run with a
   source ignores the delivery of the item's `env_binding` (S6-3).
3. **Off only by the owner.** The owner can turn way C off for one item. The change MUST pass the owner
   check `OwnerAction::ChangeDelivery { item, kind, on }`. Nothing else turns it off. A change of the
   kind or the settings of an existing row (section 3.2: what a lease can do and where the long-lived
   secret goes) MUST pass the owner check `OwnerAction::ChangeShortLivedSettings { item, kind,
   settings_sha256 }`, where `settings_sha256` is the SHA-256 (lowercase hex) of the canonical
   settings text; the global owner window never covers it.
4. **No fallback.** A lease that cannot be made fails the run with `lease_failed` (section 9). The key
   holder MUST NOT deliver the long-lived value, a placeholder of it, or an older lease instead. The
   command does not start; on the relay the run is `denied` with `code` `lease_failed`.
5. **After the decision.** The key holder makes the lease only after the owner's decision (and the
   second check of the broker), right before the release. A denied run, an evaluation
   (`evaluate_run`), and a timed-out run make no provider call.
6. **No-secret rule.** No answer, view, audit row, activity row, log line, notification, or error text
   holds a long-lived value, a lease value, a placeholder, a signature, a payload hash, or a header
   value. The only exceptions are the delivery channels themselves: the child's environment (local
   runs), `SessionView.env` (relay sessions), and the in-process lease of section 4.
7. **Presigned URLs and streaming payloads are refused (S6-8).** A request with `X-Amz-Signature`,
   `X-Amz-Credential`, or `X-Amz-Algorithm` in its query is a credential that anyone can use. A proxy
   that signs (E1, E2) and the sign endpoint (section 7) MUST refuse it, and MUST refuse a
   `STREAMING-*` payload hash. Only the `Authorization: AWS4-HMAC-SHA256 …` header form is signed.
8. **Nothing is sealed to a device key on a node.** The lease reaches a member's node in the session
   view over TLS pinned end to end (ADR 0037 D4) or through Connect with TLS end to end. No second
   envelope is added (chosen by the plan; a later revision can add one).

## 3. Kinds, fields, and settings

A source is a vault item with one `short_lived` row (vault schema 32, synced, plan unit D):

| Column | Rule |
| --- | --- |
| `item_id` | The item. One row per item. |
| `kind` | One of `aws_sts`, `github_app`, `google_service_account`, `oauth_refresh`, `cloudflare_token`, `planetscale_password`, `neon_role`. |
| `settings` | A JSON object, the settings of the kind below. Default `{}`. MUST NOT hold a secret. |
| `enabled` | `1` (way C on) or `0` (the owner turned it off). |
| `created_at`, `updated_at` | Unix seconds. |

`cloudflare_token`, `planetscale_password`, and `neon_role` are reserved for unit K, which adds their
fields and settings in a dated section of this document. Until that section exists, writing a row of a
reserved kind is `invalid_request`.

### 3.1 Fields

The fields are the item's `Field {name, value, secret}`. The key holder reads only the fields named
here. A missing required field, or a field whose `secret` flag differs from the table, is
`invalid_request` when the row is written and `lease_failed` when a lease is asked for. Other fields of
the item are ignored.

| Kind | Field | Secret | Required | Value |
| --- | --- | --- | --- | --- |
| `aws_sts` | `access_key_id` | no | yes | `AKIA` and 16 characters `A-Z0-9` (an IAM user key; an `ASIA` key is already temporary and is refused). |
| `aws_sts` | `secret_access_key` | yes | yes | 40 characters `A-Za-z0-9/+`. |
| `github_app` | `app_id` | no | yes | A decimal integer ≥ 1. |
| `github_app` | `installation_id` | no | yes | A decimal integer ≥ 1. |
| `github_app` | `private_key` | yes | yes | A PEM `RSA PRIVATE KEY` (PKCS#1) or `PRIVATE KEY` (PKCS#8). |
| `google_service_account` | `key_json` | yes | yes | A service-account key JSON with `"type": "service_account"`, `client_email`, `private_key`, and `token_uri`. |
| `oauth_refresh` | `client_id` | no | yes | Text, 1 to 512 bytes. |
| `oauth_refresh` | `client_secret` | yes | no | Text, 1 to 512 bytes. A public client has none. |
| `oauth_refresh` | `refresh_token` | yes | yes | Text, 1 to 4096 bytes. |

### 3.2 Settings

Every settings object is strict: an unknown field, a duplicate field, or a wrong type is
`invalid_request`. All settings are optional unless marked. A URL is `https://` with a host and no
userinfo, query, or fragment (an `http://` loopback URL is allowed only in tests through
`ProviderEndpoints`, never in a stored row).

| Kind | Setting | Type and rule | Default |
| --- | --- | --- | --- |
| `aws_sts` | `role_arn` | `arn:aws:iam::<12 digits>:role/<path and name>`, at most 2048 bytes. With it the key holder calls `AssumeRole` (recommended). | none: `GetFederationToken` |
| `aws_sts` | `policy` | JSON text of an IAM session policy object, at most 2048 bytes. | none: with `services`, both calls send a policy that allows `<service>:*` for each listed service; without them, `AssumeRole` sends no policy and `GetFederationToken` sends an allow-all policy (S6-4) |
| `aws_sts` | `region` | `[a-z]{2}(-[a-z]+)+-[0-9]+`, for example `eu-central-1`. The STS endpoint is `sts.<region>.amazonaws.com`. | `us-east-1` |
| `aws_sts` | `services` | 1 to 16 distinct AWS service names, each `[a-z0-9-]{1,32}`, for example `s3`. Used by signed requests (section 7), `AWS_ENDPOINT_URL_<SERVICE>` (section 5.3), and, without a `policy`, the session policy of a lease (`{"Effect":"Allow","Action":["<service>:*", …],"Resource":"*"}`; the names are IAM service prefixes). | none: no restriction |
| `github_app` | `repositories` | 1 to 500 distinct repository names (`[A-Za-z0-9._-]{1,100}`, without the owner). | none: every repository of the installation |
| `github_app` | `permissions` | Object of a permission name (`[a-z_]{1,64}`) to `read`, `write`, or `admin`, 1 to 64 entries. | none: the installation's permissions |
| `github_app` | `api_url` | URL. | `https://api.github.com` |
| `google_service_account` | `scopes` | 1 to 16 distinct OAuth scope URLs. | `["https://www.googleapis.com/auth/cloud-platform"]` |
| `google_service_account` | `impersonate` | A service-account email `<name>@<project>.iam.gserviceaccount.com`. | the key's own `client_email` |
| `oauth_refresh` | `token_url` | URL. **Required.** | — |
| `oauth_refresh` | `client_auth` | `basic` (HTTP Basic, RFC 6749 §2.3.1) or `body` (`client_id` and `client_secret` in the form). **Required.** | — |
| `oauth_refresh` | `revoke_url` | URL of an RFC 7009 endpoint, on the host (and port) of `token_url`. | none: no revocation |
| `oauth_refresh` | `scope` | Space-separated scopes, 1 to 1024 bytes. | none: the grant's scope |

A single-field AWS item (only the key id) is not a source. Its sheet offers "Add the secret key to make
temporary credentials" (S6-14).

### 3.3 Provider calls (summary)

| Kind | Call | Lifetime |
| --- | --- | --- |
| `aws_sts` | `AssumeRole` with `role_arn`, else `GetFederationToken`; `DurationSeconds=900`; `RoleSessionName` or `Name` = `apassy-<run id>`; SigV4 with the long-lived key, service `sts`. `GetSessionToken` MUST NOT be used. | `Expiration` at most 900 s + 300 s (clock skew) after the request, else `lease_failed`. |
| `github_app` | RS256 JWT (`iat` 60 s back, `exp` at most 9 minutes ahead, `iss` = `app_id`) → `POST {api_url}/app/installations/{installation_id}/access_tokens` with `repositories` and `permissions`. | GitHub's `expires_at` (one hour), at most 3600 s + 300 s (clock skew) after the request, else `lease_failed`. Revoked at run end (section 4.2). |
| `google_service_account` | RS256 JWT of the key → `token_uri`, which MUST be `https://oauth2.googleapis.com/token` (another `token_uri` is `lease_failed` before any call: the key JSON comes from a paste) (bootstrap token, kept on the key holder and dropped after the next call) → `iamcredentials.googleapis.com` `generateAccessToken` for `impersonate` with `scopes` and `lifetime: "900s"`. | `expireTime` at most 900 s + 300 s (clock skew) ahead, else `lease_failed`. |
| `oauth_refresh` | `POST token_url` with `grant_type=refresh_token`, the client auth of `client_auth`, and `scope`. | `expires_in`, the real expiry. Without `revoke_url`: a missing `expires_in` or one over 3600 s is `lease_failed`. With `revoke_url` (revoked at run end): a longer `expires_in` is reported as it is; a missing one gives `expires_at = made_at + 3600`, and the activity row says that the expiry is unknown and the token is revoked at run end. |

The whole exchange of one lease has a deadline of 20 seconds. Every secret is held in `Zeroizing`
buffers and dropped before the process spawns.

The expiry window (revision 2026-11-03). A provider refuses a request whose time is far from its clock
(STS: 5 minutes), so the key holder accepts a provider expiry up to 300 s past `made_at` plus the
kind's lifetime, and refuses a later one: a provider that ignores the asked lifetime (the STS defaults
are 1 and 12 hours) is refused, while a clock that is a little off is not. The lease never claims more
than the kind allows: `expires_at = min(provider expiry, made_at + max)`, with max 900 s for `aws_sts`
and `google_service_account` and 3600 s for `github_app`. The real credential can therefore outlive
`expires_at` by up to the window, and it lives as follows:

| Kind | How long the real credential can live |
| --- | --- |
| `aws_sts` | Until its `Expiration`: 900 s, the STS minimum of `DurationSeconds`, and at most 1200 s after `made_at` by the window. STS credentials cannot be revoked one by one; they end when they expire. |
| `github_app` | Until GitHub's `expires_at`: one hour (at most 3900 s after `made_at` by the window). The key holder revokes it at run end with `DELETE {api_url}/installation/token` (section 4.2), so it normally ends with the run. |
| `google_service_account` | Until its `expireTime`: the asked 900 s, at most 1200 s after `made_at` by the window; Google's own limit for an access token is one hour. It is not revoked at run end. The bootstrap token (one hour) never leaves the key holder. |
| `oauth_refresh` | Until the provider's `expires_in`; without a `revoke_url` at most one hour, with one revoked at run end (see the table above). |

## 4. The lease

A lease exists only inside the key holder and on its way to the agent's side. Its JSON form below is the
form of the fixtures and of the in-process node-to-relay release (`Released::Direct`). It MUST NOT be
written to a file, a database, a log, or an audit row.

```json
{
  "kind": "aws_sts",
  "secrets": [{"name": "AWS_ACCESS_KEY_ID", "value": "ASIA…"}, {"name": "AWS_SECRET_ACCESS_KEY", "value": "…"},
              {"name": "AWS_SESSION_TOKEN", "value": "…"}],
  "plain": [{"name": "AWS_CREDENTIAL_EXPIRATION", "text": "2026-11-03T12:15:00Z"}],
  "made_at": 1793700000,
  "expires_at": 1793700900,
  "revoke": null,
  "update_field": null
}
```

| Field | Rule |
| --- | --- |
| `kind` | The source's kind. |
| `secrets` | 1 to 4 variables. The first is the item's bound variable (`env_binding.env_name`). Each value is printable ASCII without `"` and `\`, 1 to 4096 bytes (`check_value`). Masked in the run output; replaced in relay answers. |
| `plain` | 0 to 4 variables that are not secrets. Not masked. |
| `made_at` | Unix seconds when the key holder sent the provider request. |
| `expires_at` | Unix seconds. `made_at < expires_at`. At most `made_at + 900` for `aws_sts` and `google_service_account`; at most `made_at + 3600` for `github_app`, and for `oauth_refresh` without `revoke`. |
| `revoke` | `null`, or `{"type": "github", "url": "<api_url>/installation/token"}`, or `{"type": "oauth", "url": "<revoke_url>"}`. The token to revoke is always the first secret; it is not repeated here. |
| `update_field` | `null`, or `{"field": "refresh_token", "value": "…"}` when an OAuth answer rotated the refresh token (only `oauth_refresh`). |

Variable names are `[A-Z_][A-Z0-9_]{0,127}`, distinct within the lease.

### 4.1 Fixed variable names

| Kind | `secrets` | `plain` |
| --- | --- | --- |
| `aws_sts` | bound variable (the `ASIA…` key id), `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | `AWS_CREDENTIAL_EXPIRATION` (RFC 3339 UTC, `YYYY-MM-DDTHH:MM:SSZ`, equal to `expires_at`) |
| `github_app` | bound variable (the `ghs_…` token) | — |
| `google_service_account` | bound variable (the access token) | — |
| `oauth_refresh` | bound variable (the access token) | — |

Detection (S6-14) binds an AWS source to `AWS_ACCESS_KEY_ID` and a service-account source to
`CLOUDSDK_AUTH_ACCESS_TOKEN`. A lease name that collides with another variable of the run (another
item's binding, another lease, a base URL variable, or `RESERVED_VARIABLES`) is `invalid_request` for a
local run, before the owner is asked, and `release_invalid` on the relay.

### 4.2 Revocation and rotation

- When the run ends (the process exits, or the relay session ends or is ended), the key holder revokes
  each lease with a `revoke`: GitHub `DELETE /installation/token` with the token as bearer; OAuth an RFC
  7009 `POST revoke_url` with `token` and `token_type_hint=access_token`. Best effort: a failure writes
  `lease_revoke_failed` (section 10) and nothing else.
- An `update_field` MUST be written to the item before the lease is delivered. A failed write still
  delivers the lease (the old token is already dead) and writes an activity row with the error and
  "authorize again". A token answer that rotates the refresh token but is otherwise unusable (no
  access token, not a bearer token, a bad `expires_in`) is `lease_failed`, and its new refresh token
  MUST be written before the run fails: the error carries it (`LeaseError.update_field`).
- Single flight. The key holder refreshes one item at a time: one lock per item covers the read of the
  source, the token request, and the write of a rotated refresh token, so a second run of the item
  sends the token that the first run stored. The write is a compare-and-swap
  (`Vault::swap_secret_field`): it stores the new token only while the field still holds the token
  that was sent, and raises the item revision. When the field changed meanwhile (a synced copy, or the
  owner), the newer stored token stays and the token of the answer is dropped. When the token endpoint
  refuses the refresh token (400 or 401), the key holder reads the source once more and, when the
  stored token differs from the one sent, tries it once.
- Only the device that runs the lease refreshes; a synced copy never calls the token endpoint. Synced
  copies converge by the compare-and-swap and the item revision. Limit: a provider with refresh-token
  reuse detection can still revoke the grant when two Macs refresh the same item within the same
  second, before either copy has synced; the owner then authorizes the item again.

## 5. Delivery on the agent's side

### 5.1 Local runs (broker)

The child gets every `secrets` and `plain` variable of each lease; the `secrets` values are added to the
output masks. The run answer of the broker gains `leases`: an array of `LeaseView` (section 5.2), one per
source, in item order. `apassy_list_access` gains, per catalog entry of a source, `env_holds:
"temporary credentials"`, `extra_env_names` (the lease names after the bound variable), and `lease_secs`
(900, or 3600 for `github_app`). Plan unit F writes these into `broker-v0.md`.

### 5.2 `SessionView` additions (relay, frozen for G, H, L, and stage 4)

Two arrays are added to `SessionView` (`crates/apassy-relay/src/api.rs`). Both are omitted when empty, so
a session without way C keeps today's bytes; a client reads a missing array as empty.

```rust
pub struct SessionView {
    pub session_id: SessionId,
    pub expires_at: u64,
    pub env: BTreeMap<String, String>,
    pub placeholders: Vec<String>,
    pub base_urls: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub short_lived: Vec<LeaseView>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<SignerView>,
}

pub struct LeaseView {
    pub item_id: ItemId,
    pub kind: LeaseKind,          // snake_case, section 3
    pub env_names: Vec<String>,   // the lease's secrets, then its plain names, in lease order
    pub expires_at: u64,          // the lease's expires_at
}

pub struct SignerView {
    pub item_id: ItemId,
    pub env_name: String,         // the variable that holds the placeholder of the secret access key
    pub access_key_id: String,    // the AKIA… id, not a secret; also in env as AWS_ACCESS_KEY_ID
}
```

| Rule | |
| --- | --- |
| Lease variables | Every name of `env_names` is in `env` with the lease value, is not in `placeholders`, and has no `APASSY_BASE_<NAME>` and no provider base URL variable. |
| Session expiry | `expires_at` ≤ `min(now + ttl, lease.expires_at − 30)` for every lease. A lease that has less than 60 seconds left at release is `release_invalid`. `APASSY_RELAY_SESSION_EXPIRES` equals `expires_at`. |
| Signer variables | `env_name` is in `env` and in `placeholders`; the placeholder has the length of the secret (40). `AWS_ACCESS_KEY_ID` is in `env`, equals `access_key_id`, and is not in `placeholders`. A signer has no `APASSY_BASE_<NAME>`. |
| Masks | The lease values are in the session's masks and in the answer replacement set, as placeholders are today. |
| Collisions | A name in two items of one session is `release_invalid`. |
| Order | `short_lived` and `signers` are sorted by `item_id`. |

### 5.3 `AWS_ENDPOINT_URL_<SERVICE>` (cloud route, unit E2)

For a session served by the public listener, each signer item with `services` gets
`AWS_ENDPOINT_URL_<SERVICE>` = `base(<service>.<region>.amazonaws.com)` (the service name upper-cased,
`-` → `_`; `region` from the settings, default `us-east-1`) and the matching `base_urls` entry. The relay
proxy verifies and re-signs (section 7.1). `AWS_ENDPOINT_URL` is never set. A session for a member's node
has no such variable: the member's own run proxy signs through `POST /v1/sign` (unit L).

### 5.4 `AccessItem.credential_form` and `ItemView.credential_form`

`AccessItem` (`GET /v1/access`, `apassy_list_access`) and `ItemView` gain `credential_form`, always
serialized; a client reads a missing field as `placeholder`. The relay item gets the column
`credential_form TEXT NOT NULL DEFAULT 'placeholder'` (team schema 8, or the next free number at merge).
The name is not `delivery`: stage 4 uses `delivery` for another thing (`collection.delivery`,
`run.delivery`, the way A switch).

| Value | Meaning | `env_name` holds | `base_url_vars` |
| --- | --- | --- | --- |
| `placeholder` | Today's way B. | a placeholder | as today |
| `temporary_credentials` | Way C: a lease per run. | a short-lived value | empty |
| `signed_requests` | An AWS key whose requests are signed by the proxy or the key holder. | a placeholder of the secret | the `AWS_ENDPOINT_URL_<SERVICE>` names on the cloud route, else empty |

## 6. Where way C runs

| Run | Key holder | Delivery |
| --- | --- | --- |
| The owner's own agent (local run) | The owner's app | The child's environment (5.1). |
| A cloud agent through the owner's node | The owner's app, behind its node | `SessionView` (5.2). |
| A member's agent (stage 4) | The team host node | `SessionView` in the member's run answer. |

## 7. Signed requests

The agent's SDK signs each request with the placeholder secret. The signer first verifies that signature
against the placeholder: this proves the canonical request as the SDK built it. It then signs the same
canonical request with the real secret and replaces only the `Signature=` value (64 lowercase hex, the
same length).

### 7.1 Proxies (E1, E2)

The local run proxy (E1) and the relay proxy (E2) do this themselves. They buffer the body (at most
8 MiB, else 413), take the payload hash from `x-amz-content-sha256` or compute it, and keep every header
that `SignedHeaders` lists, `accept-encoding` included. The relay proxy verifies the request as the SDK
built it (host of the node, path with the `/p/<key>/<host>` prefix) and signs the upstream form (the
upstream host, the path without the prefix). A request that does not verify against the placeholder is
403 and sends nothing upstream. A presigned URL or a `STREAMING-*` hash is 403 `not_supported` with the
reason.

### 7.2 `POST /v1/sign` (team host, unit H)

`Need::Member`: the device access token of a member (ADR 0019 §5). `Scope::Public` does not serve it.
Request body at most 64 KiB (above: 413 `payload_too_large`). Strict: unknown, duplicate, or missing
fields are 400 `invalid_request`.

```json
{
  "session_id": 7,
  "item_id": 9,
  "scope": {"date": "20150830", "region": "us-east-1", "service": "service"},
  "canonical_request": "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c442…b855"
}
```

| Field | Rule |
| --- | --- |
| `session_id`, `item_id` | Integers ≥ 1. |
| `scope.date` | `YYYYMMDD`. |
| `scope.region`, `scope.service` | `[a-z0-9-]{1,32}`. |
| `canonical_request` | The SigV4 canonical request, lines joined by `\n` (no `\r`): method (`[A-Z]{1,16}`), canonical URI (starts with `/`), canonical query, one `name:value` line per signed header (names lowercase, sorted, distinct), an empty line, the signed header names joined by `;` (equal to the header lines' names), and the payload hash. |

Answer: `{"ok": true, "result": {"signature": "<64 lowercase hex>"}}`, where the signature is
`HMAC-SHA256(signing_key, string_to_sign)` of the SigV4 specification: `string_to_sign =
"AWS4-HMAC-SHA256\n" + x-amz-date + "\n" + date/region/service/aws4_request + "\n" +
hex(SHA-256(canonical_request))` and `signing_key` derived from `"AWS4" + secret` over the scope. The
fixture pair is the `get-vanilla` vector of the AWS SigV4 test suite.

403 `sign_refused` (one message per reason, never a value of the request):

| Reason | Message |
| --- | --- |
| The session is not live, or is not a session of the calling member (`LiveSession.member_id`) | "This session is not yours or has ended." |
| The item is not a signer of the session | "This item does not sign requests in this session." |
| The `host` header is missing, or not covered by the item's hosts | "The host is not covered by this item." |
| `x-amz-date` is missing, its day differs from `scope.date`, or it is more than 15 minutes from the host's clock | "The request date does not match." |
| `scope.service` is not in the item's `services` (when set) | "The service is not covered by this item." |
| The query has `X-Amz-Signature`, `X-Amz-Credential`, or `X-Amz-Algorithm` | "Presigned URLs are not signed." |
| The payload hash is `STREAMING-*`; or `UNSIGNED-PAYLOAD` when the method is not `GET`, `HEAD`, or `DELETE` or a `content-length` other than `0` is signed; or it is not 64 lowercase hex; or `x-amz-content-sha256` is signed and differs from it | "This payload hash is not signed." |
| More than 120 signatures in the last minute for this session | "Too many signatures for this session. Wait a second." (with `Retry-After: 1`) |

The limit is 403, not 429, because the app's relay client holds every call to the relay after a 429
(relay `error.rs`, `TOO_MANY_QUESTIONS`).

The sign endpoint never sees the body. It sees the method, the path, the query, the signed headers, and
the payload hash (S6-9). It MUST NOT store or log any of them except the audit row of section 10.

## 8. Keys per member (units J1, J2)

A member key is a new vault item of the team host, linked by the synced table `member_key` (vault
schema 32): `item_id`, `source_uuid`, `team_id`, `member_id`, `manager` (`cloudflare_token` or
`aws_iam`), `remote_id` (the provider's id of the key, not a secret), `created_at`. `source_uuid` is the
sync UUID of the team item, because row IDs differ between synced copies (as `item_home.home_uuid`); the
vault API reads it back as the local `source_item_id`, which the audit rows of section 10 carry. The member's catalog
shows the member key item instead of the team item. An AWS member key is itself an `aws_sts` source.
Removing the member, revoking the grant, or archiving the source deletes the remote key and archives the
item; a failed delete stays listed with "Replace now".

## 9. Codes

| Code | Where | Meaning |
| --- | --- | --- |
| `lease_failed` | Local run: the broker's wire error. Relay: `RunView.code` of a `denied` run. | The lease could not be made. The command does not run and nothing is delivered. The message names the kind and the provider's HTTP status or `timeout` / `unreachable` / `invalid answer`, never the provider's body. |
| `lease_revoke_failed` | Activity row and audit row only. Never an error of a run. | A revocation at run end failed. |
| `sign_refused` | `POST /v1/sign`, HTTP 403. | Section 7.2. |
| `not_supported` | Proxies, HTTP 403 (local) or 501 (relay, as today). | A presigned URL or a streaming payload (section 7.1). |

Example (`lease_failed`, local run):

```json
{"ok": false, "error": {"code": "lease_failed", "message": "AWS STS answered 403. No temporary credentials were made, so the command did not run."}}
```

## 10. Audit and activity rows

The relay writes audit rows (`AuditEntry`); the Mac writes the same facts as activity rows. The `detail`
object holds exactly the fields below. It MUST NOT hold a value, a placeholder, a token, a signature, a
payload hash, a header, a query, or a provider body.

| `action` | `actor` | `detail` fields |
| --- | --- | --- |
| `lease_made` | `relay` | `item_id`, `kind`, `expires_at` (the run is `run_id` of the row) |
| `lease_revoked` | `relay` | `item_id`, `kind` |
| `lease_revoke_failed` | `relay` | `item_id`, `kind`, `status` (the provider's HTTP status, or `timeout` / `unreachable`) |
| `lease_failed` | `relay` | `item_id`, `kind`, `status` |
| `sign_request` | `member:<id>` | `session_id`, `item_id`, `method`, `path` (the canonical URI, without the query), `service`, `region` |
| `member_key_made` | `relay` | `item_id`, `source_item_id`, `member_id`, `manager` |
| `member_key_deleted` | `relay` | `item_id`, `source_item_id`, `member_id`, `manager` |

## 11. What the agent's side never gets

The long-lived fields of section 3.1, the bootstrap token of a Google lease, a rotated refresh token,
the GitHub App JWT, a signature made by the key holder for another request, and the item's `settings`
(the settings are shown to the owner only). A test of every unit that holds a synthetic long-lived
secret scans the agent's side, the audit rows, and the activity log for it and fails when it is there.

## 12. Fixtures

| File | What |
| --- | --- |
| `kinds.json` | The tables of sections 3.1 and 4.1, machine-readable. |
| `sources.json` | One synthetic source per kind (fields with synthetic values). Its secret values are the canaries of the no-secret check. |
| `settings-<kind>.json` | One settings object per kind of section 3.2. |
| `lease-<kind>.json` | One lease per kind of section 4. |
| `session-view.json` | A `SessionView` of the member's-node form (section 5.3: no `AWS_ENDPOINT_URL_<SERVICE>`) with a placeholder item, a `github_app` lease, and a signer. |
| `access-view.json` | An `AccessView` with one item of each `credential_form`. |
| `sign-request.json`, `sign-answer.json` | The AWS `get-vanilla` vector as a sign request and its answer (secret `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, the published test-suite value). |
| `error-lease-failed.json`, `error-sign-refused-*.json` | The error answers of sections 7.2 and 9. |
| `run-lease-failed.json` | A `RunView` denied with `code` `lease_failed`. |
| `audit-rows.json` | One audit row of each action of section 10. |

## 13. Revisions

| Date | Change |
| --- | --- |
| 2026-11-03 | The access item field `delivery` (section 5.4) is renamed `credential_form`, with the relay column, `kinds.json`, and `access-view.json`, because stage 4 uses `delivery` for the way A switch (`collection.delivery`, `run.delivery`). The values are unchanged; a missing field still reads as `placeholder`. |
| 2026-11-03 | Security review of units C1, C2, and D. Section 3.3: the expiry window of 300 s for clock skew is stated, with how long each kind's real credential can live; an OAuth answer without `expires_in`, or with one over 3600 s, is `lease_failed` unless the source has a `revoke_url` (then the token is revoked at run end and the real expiry is reported; a missing one shows one hour); a Google `token_uri` other than `https://oauth2.googleapis.com/token` is `lease_failed`. Section 3.2: `revoke_url` is on the host of `token_url`; without a `policy`, `services` narrows the session policy of an AWS lease. Rule 3: a change of the settings needs `OwnerAction::ChangeShortLivedSettings`. Section 4.2: a rotated refresh token of a failed answer is stored before the run fails; single flight per item, compare-and-swap, and the limit of reuse detection across two Macs. Section 4: `expires_at` of an OAuth lease without `revoke` is at most `made_at + 3600`. Detection makes `Custom` items (plan unit D). |
| 2026-11-03 | The vault table `member_key` (section 8) stores `source_uuid`, the sync UUID of the team item, instead of `source_item_id`: a row ID is not the same on two synced copies. The vault API and the audit rows keep `source_item_id`. A `short_lived` row that is off keeps its kind and settings (a signer reads `region` and `services` from it). |
