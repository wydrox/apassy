# Connect billing contract v1

Date: 2026-11-03. Status: proposed, for ADR 0037 stage 7 (unit D1 of [the stage 7 plan](../design/implementation-plan-s7-connect.md)). Not implemented. The relay side is C2 (`crates/apassy-relay/src/server/{billing,stripe}.rs`) and C3 (`group.rs`), the Mac side M2 (`src/desktop/ui/connect.rs`), the iPhone side I1 (the plan row only), the site W1 (`site/src/lib/plans.ts`). Synthetic vectors: the default price configuration, totals, six webhook events signed with a known endpoint secret, and the plan states.
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) D3; [plans](../product/plans.md) sections 3 and 5; [connect-account-v1](connect-account-v1.md).

This contract defines the plans and their prices as Connect publishes them, the Stripe Checkout and Customer Portal sessions, the Stripe webhook, the plan state of an account, and Family and Team groups. The encodings, the transport, the account token, and the error table are those of [connect-account-v1](connect-account-v1.md) sections 2 to 4. MUST and MUST NOT below are requirements on both sides.

## 1. Rules

- **Prices are configuration, not wire constants.** The amounts live in the Stripe prices that `crates/apassy-relay/scripts/stripe-products.sh` makes from its configuration (section 2). Connect resolves them by lookup key at start and publishes them at `GET /v1/plans`. No client, page, or test outside the fixtures hardcodes an amount; the Mac reads `GET /v1/plans`, and the site's `site/src/lib/plans.ts` is checked against `tests/fixtures/connect-billing-v1/plans.json` (`scripts/check-site-plans.py`, W1).
- **State only from Stripe.** Connect changes a plan only on a verified Stripe event (section 7), or on Stripe's answer to Connect's own read of a subscription (`GET /v1/subscriptions/{id}`, the maintenance pass of section 8), with the same rules; never on the browser's return from Checkout and never on a client's word. Connect writes its own facts only: the Stripe customer it makes for an account (section 4), the open checkout session, a quantity Stripe accepted from Connect (section 6), and the deletion of stores.
- **Purchase is on the Mac only**, in the default browser, through Stripe Checkout and the Customer Portal. The iPhone shows the plan and nothing that leads to a purchase (section 10).
- Connect sends Stripe only the account id (`client_reference_id`, metadata), customer, price, session, and subscription ids, quantities, and its own URLs. It never sends a device key, a token, a vault id, a device name, or a value. Stripe collects the email, the address, and the payment method itself.
- **Only Stripe's pages.** A checkout `url` is a page of `https://checkout.stripe.com/`, a portal `url` a page of `https://billing.stripe.com/`. Connect refuses another answer from Stripe (`502 upstream_failed`), and the Mac opens no other.
- Every Stripe call uses the restricted key (`STRIPE_SECRET_KEY_FILE`), form encoding, one pinned `Stripe-Version` (`STRIPE_API_VERSION`, the version of the webhook endpoint), and an `Idempotency-Key` on every POST, reused on a retry of the same action. Tests use the sandbox or the fake Stripe server (`tests/common/fake_stripe.rs`); no test makes a live charge.

## 2. Plans and prices

The default configuration (plans section 3, owner 2026-11-03; EUR, VAT included; a year is 10 months):

| Plan | Lookup keys | Month | Year | Unit | Included | Each further unit |
| --- | --- | --- | --- | --- | --- | --- |
| Connect Personal | `connect_personal_month`, `connect_personal_year` | 3 | 30 | account | 1 | — |
| Connect Family | `connect_family_month`, `connect_family_year` | 5 | 50 | person | 4 | 1 a month, 10 a year |
| Connect Team | `connect_team_month`, `connect_team_year` | 4 | 40 | member | 1 | 4 a month, 40 a year |

- Stripe prices: currency `eur`, `tax_behavior=inclusive`, recurring month or year. Personal and Team are `per_unit` (Team quantity = seats). Family is `tiered` with `tiers_mode=graduated`: tier 1 `up_to=4` with `flat_amount` 500 or 5000 and `unit_amount` 0; tier 2 `up_to=inf` with `unit_amount` = the Family extra. The Family extra is configuration: `APASSY_CONNECT_FAMILY_EXTRA_CENTS` (default 100) and `APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS` (default 1000). The products script reads them; Connect compares them with tier 2 of the resolved prices at start and refuses Family checkouts (`503 busy`, logged) while they differ. If the sandbox shows that the Customer Portal cannot switch to a tiered price, C2 uses two prices for Family (`connect_family_<interval>` quantity 1 and `connect_family_extra_<interval>` quantity people − 4); the wire of this contract does not change.
- Connect resolves the prices at start with `GET /v1/prices?lookup_keys[]=…&active=true&expand[]=data.tiers` and caches them; no price id is in code or configuration. A missing lookup key keeps that plan out of `GET /v1/plans`.
- **Total** for `n` units (people or seats; Personal `n` = 1): `amount + max(0, n − included) × extra`, for `1 ≤ n ≤ max`. A Family of 2 pays the price of 4. A year price is a price of its own, not a coupon.

### `GET /v1/plans` (public, no `Authorization`)

The `PlansView`, as `tests/fixtures/connect-billing-v1/plans.json` (the default configuration):

```json
{"currency":"eur","tax":"inclusive","plans":[{"plan":"family","name":"Connect Family","unit":"person","included":4,"max":10,"prices":[{"interval":"month","lookup_key":"connect_family_month","amount":500,"extra":100},{"interval":"year","lookup_key":"connect_family_year","amount":5000,"extra":1000}]}]}
```

`amount` and `extra` are cents with VAT included; `extra` is `null` when `max` equals `included`. `plan` is `personal`, `family`, or `team`; `unit` is `account`, `person`, or `member`; `interval` is `month` or `year`. `max` is a limit of this contract (section 6), not of Stripe.

## 3. Routes

| Route | Auth | Section |
| --- | --- | --- |
| `GET /v1/plans` | none | 2 |
| `POST /v1/account/checkout` | account token | 4 |
| `POST /v1/account/portal` | account token | 5 |
| `GET /v1/account/plan` | account token | 8 |
| `GET /v1/account/group` | account token | 6 |
| `POST /v1/account/group/invites` | account token, owner or admin | 6 |
| `POST /v1/account/group/join` | account token | 6 |
| `POST /v1/account/group/members/{account_id}/confirm` | account token, owner or admin | 6 |
| `DELETE /v1/account/group/members/{account_id}` | account token | 6 |
| `POST /v1/account/group/seats` | account token, owner | 6 |
| `POST /v1/stripe/webhook` | `Stripe-Signature` | 7 |

## 4. Checkout

`POST /v1/account/checkout` with `{"plan":"personal","interval":"month"}`, `{"plan":"family","interval":"year","people":6}`, or `{"plan":"team","interval":"month","seats":5}`. `people` is required for Family and refused for the others; `seats` likewise for Team. Answer: `{"url":"https://checkout.stripe.com/c/pay/cs_test_…","session_id":"cs_test_…","expires_at":1790086400}`.

- Refused: an account with an entitled plan or a pending member state (`409 conflict`: the portal changes a plan); an account that is an active member of a group (`409 conflict`); a count outside `1 ≤ n ≤ max` (`409 seat_limit`). The owner of a group with other active members (its plan ended, and it buys again) buys for them: a plan of another kind is `409 conflict`, a count below the active members, the owner included, `409 seat_limit`.
- Before an account's first session Connect makes its Stripe customer (`POST /v1/customers` with `metadata[account_id]`, one idempotency key for each account) and stores it; every session names it, so every subscription of one account belongs to one customer.
- Connect creates the session with `POST /v1/checkout/sessions` and these fields (the example `stripe_checkout_form` in `examples.json`): `mode=subscription`, `line_items[0][price]` (the price id of the lookup key), `line_items[0][quantity]` (people, seats, or 1), `automatic_tax[enabled]=true`, `billing_address_collection=required`, `client_reference_id=<account id>`, `metadata[account_id]` and `subscription_data[metadata][account_id]` (the account id), `consent_collection[terms_of_service]=required`, `success_url=https://apassy.wyderka.cc/connect/done?session_id={CHECKOUT_SESSION_ID}`, `cancel_url=https://apassy.wyderka.cc/connect/cancel`; for Team also `tax_id_collection[enabled]=true`; then `customer=<customer id>` and `customer_update[address]=auto`. The site URLs come from `APASSY_CONNECT_SITE_URL`.
- A repeated request (the same plan, interval, count, and price) gets the session that Stripe still shows `open` (`GET /v1/checkout/sessions/{id}`). After a completed or expired session, or for another price, it is a new session with a new idempotency key; a new session for another request first ends the open one (`POST /v1/checkout/sessions/{id}/expire`). Two requests at once get one session.
- The Mac opens `url` in the default browser and polls `GET /v1/account` every 3 s while the sheet is open; it stops on an entitled plan, on Cancel, or after 30 minutes. The done page offers `apassy://connect/done?session=<session id>`, which only wakes the polling. Neither the page nor the app link carries a secret.

## 5. The Customer Portal

`POST /v1/account/portal` with `{}` from a device of the account that owns the Stripe customer (a group's owner) answers `{"url":"https://billing.stripe.com/p/session/…"}`. Connect calls `POST /v1/billing_portal/sessions` with `customer` and `return_url=https://apassy.wyderka.cc/connect/done`. No Stripe customer: `404 not_found`; a group member: `403 forbidden`. The portal (configured by the owner) handles the payment method, invoices, the cancel at the end of the period, and the switch between Personal and Family. It needs no owner check. People and seats do not change in the portal; they change by section 6.

A switch from Family to Personal ends the family's plan for its members: from the switch they have the read-only window of an ended plan (section 8, `read_only` then `suspended`, then `none`), with no deletion day, and their stores are never deleted for the owner's Personal plan. The owner pays Personal from the switch (Stripe's proration of the portal). The group stays without a plan (no invite, confirm, or seats change: `403 plan_required`); a switch back to Family gives it its plan again.

## 6. Groups

A group is made by the webhook when a Family or Team subscription is bound (section 7), with the buying account as `owner`. Family: one organizer (`owner`) and `member`s, no admins, 4 people included, at most 10 (chosen). Team: `owner`, `admin`s, `member`s, one seat each, at most 250 (chosen). A member has an account of their own; its devices and stores stay its own.

- `GET /v1/account/group` answers the `GroupView`: `{"group_id":"grp_…","kind":"family","role":"owner","owner_account":"acc_…","included":4,"quantity":4,"members":[{"account_id":"acc_…","name":"Rafal","role":"owner","state":"active","joined_at":1790000000}]}`. An account without a group: `404 not_found`. `quantity` is the quantity at Stripe (people or seats) of the group's plan: its subscription of the group's kind with the best state (section 8); without one, of the group's newest subscription.
- **Paid seats.** A subscription pays for its quantity of active members, for Family at least the 4 it includes: the owner first, then the earliest confirmed. A member beyond them is `read_only` without times (no deletion day) until the quantity is raised. The maintenance pass raises the quantity of an entitled group whose active members exceed it to the member count (at most `max`), with `create_prorations`; Stripe's webhook stores whatever quantity Stripe has, and this rule decides who it covers.
- `POST /v1/account/group/invites` with `{"role":"member"}` (Team: `member` or `admin`; only the owner invites an admin) answers `{"invite_id":3,"url":"https://apassy.wyderka.cc/connect/join#apassy_gin_<group id>_<64 hex>","expires_at":1790604800}`. The code works once, for 7 days; Connect stores its SHA-256 only.
- `POST /v1/account/group/join` with `{"code":"apassy_gin_…"}` from a device of the invited account (pasted into Settings › Connect › Join a family or team) answers `{"group_id":"grp_…","kind":"family","state":"pending","owner_name":"Rafal"}`. An account with its own entitled plan or another group: `409 conflict`. A pending member has no entitlement.
- `POST /v1/account/group/members/{account_id}/confirm` with `{}` (owner or admin, after an owner check on that device: `OwnerAction::ChangeConnectGroup`) makes the member `active` and answers its member view. Under one lock of the group, with a seats change and the maintenance pass: the group's plan must be entitled (`403 plan_required`); the active members are counted with the new one (above `max`: `409 seat_limit`); the member becomes active; when the count exceeds the quantity at Stripe, Connect asks Stripe for the count in the same call, and when Stripe refuses, the member is pending again and the answer is Stripe's error. A quantity Stripe accepted from Connect counts as the quantity at Stripe until a subscription event carries Stripe's word again.
- `DELETE /v1/account/group/members/{account_id}` (owner or admin; only the owner removes an admin; a member may remove itself; the owner cannot be removed) answers `{"account_id":"acc_…","removed_from_stores":1}`. The removed account keeps a free account and loses the entitlement at its next request; its devices leave the group's shared stores, and the tunnel grants between it and the group end ([connect-tunnel-v1](connect-tunnel-v1.md) section 6).
- `POST /v1/account/group/seats` with `{"quantity":6}` (owner) answers `{"quantity":6,"pending":true}`, under the lock of the group. Below the active members, or outside `1 ≤ n ≤ max` (Family: the count is people; a count below 4 pays the price of 4): `409 seat_limit`. The quantity at Stripe again: `{"quantity":6,"pending":false}` without a call.
- A quantity change calls `POST /v1/subscription_items/{item}` with `quantity` and `proration_behavior=create_prorations`. Connect applies the new quantity only when `customer.subscription.updated` arrives.
- A group route by an account that is not in the group: `403 not_in_group`; a role that may not do it: `403 forbidden`.

## 7. The webhook

`POST /v1/stripe/webhook`, through the Worker: a body cap of 256 KiB on this exact path and no per-address limiter (Stripe sends from its own addresses); the Worker refuses, before the relay, a `Stripe-Signature` without one `t` of digits or without a `v1`, longer than 4 KiB, or with a `t` more than 300 s from its clock (`400 invalid_request`). The relay checks, in this order: the declared size (`413 payload_too_large`), then, before it reads a byte of the body, the `Stripe-Signature` header and its `t` (`400 invalid_request`); the body, read up to 256 KiB (`413`); the HMAC (`400 invalid_request`), the event JSON (`400 invalid_request`), the event id (a repeat answers 200 with `duplicate: true` and changes nothing), then it applies the event. Every refusal changes nothing.

**Signature** (Stripe's documented scheme): the header `Stripe-Signature: t=<unix seconds>,v1=<hex>[,v1=<hex>…]` (other schemes such as `v0` are ignored). The expected value is the lowercase hex of HMAC-SHA256 with the endpoint secret (`STRIPE_WEBHOOK_SECRET_FILE`, the whole `whsec_…` string as UTF-8 bytes) over the exact bytes `<t>` `.` `<body>`. The event is accepted when any `v1` equals it in a constant-time compare (`ring::hmac::verify`) and `|now − t| ≤ 300`. A header without `t` or without `v1` is refused.

**Idempotency**: by `event.id` in `stripe_event`, kept 30 days. Stripe does not keep the order of events: for each subscription Connect keeps the `created` time of the last applied subscription event and ignores an older one. `canceled` and `incomplete_expired` are final: a later event of that subscription with another status changes nothing.

| Event | Connect reads | Effect |
| --- | --- | --- |
| `checkout.session.completed` | `id`, `mode`, `client_reference_id`, `metadata.account_id`, `customer`, `subscription`, `customer_details.email` | Binds the customer and the subscription to the account named by `client_reference_id`, which must equal `metadata.account_id` and be a known account; else logged and ignored (200). Copies the email. Makes the group for a Family or Team price. |
| `customer.subscription.created`, `customer.subscription.updated` | `id`, `customer`, `status`, `cancel_at_period_end`, `ended_at`, `metadata.account_id`, `items.data[0].id`, `.price.lookup_key`, `.price.metadata.apassy_plan`, `.price.recurring.interval`, `.quantity`, `.current_period_end` (the top-level `current_period_end` of older API versions if the item has none) | Stores the subscription and always applies its status. The plan and the interval come from the lookup key; for a price without a Connect key (one that a newer price of the products script took over), from `metadata.apassy_plan` and the price's monthly or yearly interval; else a stored subscription keeps the ones it has. A price Connect cannot map gives no plan. Recomputes the plan state. |
| `customer.subscription.deleted` | as above | Status `canceled`; the end is `ended_at`. |
| `invoice.paid` | `customer`, `parent.subscription_details.subscription` (or `subscription` of older API versions) | Clears the first failure time. |
| `invoice.payment_failed` | as `invoice.paid` | Sets the first failure time if none is set: the grace starts. |
| any other type | `id`, `type` | Stored id, no effect, 200. |

An event that Connect cannot apply (an account bound to another customer, a customer or subscription bound elsewhere, an account that no longer exists, a price it cannot map) is answered 200 and stored, so Stripe does not retry it. When its subscription charges (`active`, `trialing`, `past_due`, `incomplete`, `unpaid`, or a completed checkout) and its account or customer is known, Connect also records it for the operator (`billing_problem`, the audit row `billing_problem_recorded` with ids only, the count in `apassy-relay admin readiness`), who resolves it in the Stripe dashboard.

The webhook body is Stripe's: Connect reads the fields of the table and ignores every other field (unlike the strict requests of this contract). The answer is `{"received":true,"duplicate":false}`. The fixtures use the API version `2025-03-31.basil`.

## 8. The plan state

`GET /v1/account/plan` answers the `PlanView`; `GET /v1/account` carries the same object:

```json
{"plan":"personal","status":"active","entitled":true,"interval":"month","quantity":1,"renews_at":1792592000,"ends_at":null,"grace_until":null,"read_only_until":null,"delete_at":null,"group_id":null}
```

The state comes from the stored subscriptions and the time: those the account bought, and for an active member every subscription bound to its group. The best state wins: an entitled one, then `read_only`, `suspended`, `pending`; then the newest. A late event of an older subscription never hides a paid one. For a member, a subscription of the group's kind gives its state only to the members it pays for (section 6, paid seats); one that left the group's kind (section 5) gives the read-only window from the switch, without a deletion day.

`end` is the time the plan stopped: Stripe's `ended_at`; for `unpaid`, `incomplete_expired`, or `paused` without one, the `created` time of the event that brought that status; for a `past_due` beyond its grace, `grace_until`; without any of these, the period end. Durations are configuration: `APASSY_CONNECT_GRACE_DAYS` 14, `APASSY_CONNECT_READ_ONLY_DAYS` 30, `APASSY_CONNECT_DELETE_DAYS` 90.

| `status` | From Stripe | Entitled | New store, push, dial, entitlement token | Pull and download | Times |
| --- | --- | --- | --- | --- | --- |
| `none` | no subscription, or none of a price Connect can map; a pending or removed member; a member of a group whose plan is over; after the deletion | no | no | no | — |
| `pending` | `incomplete` | no | no | no | — |
| `active` | `active` | yes | yes | yes | `renews_at`, or `ends_at` with `cancel_at_period_end` |
| `trialing` | `trialing` | yes | yes | yes | as `active` |
| `past_due` | `past_due`, `now < grace_until` (first failure + 14 days) | yes | yes | yes | `grace_until` |
| `read_only` | `past_due` beyond the grace; `canceled`, `unpaid`, `incomplete_expired`, `paused`; `now < end + 30 days`. Also a member beyond the paid seats (no times), and a member after a switch to Personal (no `delete_at`) | no | no (`403 plan_required`) | yes | `read_only_until`, `delete_at` |
| `suspended` | the same, `end + 30 days ≤ now < end + 90 days` | no | no | no (`403 plan_required`) | `delete_at` |

At `end + 90 days` the maintenance pass deletes the vault stores and the nodes of the buying account and, for a plan of its group's kind, of each active member of the group whose plan is `none` too (a member with a plan of its own, or of another subscription of the group, keeps them); never for a plan of another kind than the group's. It writes an audit row with counts and sends I-4 `forget` for each account ([connect-account-v1](connect-account-v1.md) section 11); the status is `none`; the accounts stay. Before it deletes, under the lock of the account: Stripe must show the subscription ended too (Connect reads it and applies what Stripe shows; Stripe out of reach: the next pass tries again), the relay's clock must be within a day of the latest time it saw from Stripe (a webhook's `t`, an answer's `Date`), and the plan must still be due. A pass more than two days after the last one deletes nothing until the operator resumes deletions (`apassy-relay admin billing --resume-deletions`). One failed account is logged and the pass goes on. A payment (`unpaid` to `active`) or a new subscription before that returns the account to its plan with its stores. The app shows the notice from the first day of `read_only`. `tests/fixtures/connect-billing-v1/plan-states.json` has the cases.

The pass also reads from Stripe, at most once a day each, a live subscription (`active`, `trialing`, `past_due`) whose period ended more than two days ago without an event, and applies Stripe's state.

## 9. Account deletion and Stripe

`DELETE /v1/account` ([connect-account-v1](connect-account-v1.md) section 6) cancels the subscription at once (`DELETE /v1/subscriptions/{id}`) and ends an open checkout session (`POST /v1/checkout/sessions/{id}/expire`), then deletes the account's rows. The Stripe customer and its invoices stay at Stripe (legal retention); Connect keeps `stripe_customer` with the account id for support and deletes the email copy.

## 10. The iPhone

The iPhone reads `GET /v1/account/plan` and shows only the plan's name and state: "Apassy Connect · Connect Personal · renews 3 Dec 2026", "Connect Family · 3 of 4 people", "Not on Connect", "Past due", "Ends 12 Jan 2027", and "Managed in Apassy on your Mac" as text. It MUST NOT show a price, a currency, a comparison of plans, a trial, or any button or link that leads to `GET /v1/plans`, a checkout, the portal, or a page of the site (App Store Review Guideline 3.1.1 and 3.1.3(f); plan section 6). It never calls `POST /v1/account/checkout` or `POST /v1/account/portal`. A `403 plan_required` shows "Not on Connect", without a purchase hint.

## 11. What Connect stores

`stripe_customer` (account id, customer id, the email copy, the open checkout session), `stripe_subscription` (subscription id, item id, account or group, lookup key, quantity, status, period end, `cancel_at_period_end`, first failure time, end time, `created` of the last applied event, a quantity Stripe accepted from Connect, the time its plan left its group's kind, the time of the last read), `stripe_event` (event id, type, time; 30 days), `billing_problem` (the Stripe objects of section 7 recorded for the operator: ids, reason, times), `billing_clock` (the last pass, the latest time seen from Stripe, a held deletion), `group`, `group_member` (account, role, state, times), `group_invite` (the SHA-256 of the code, role, expiry, use). No card data, no address, no tax id: those stay at Stripe.

## 12. Test vectors

`tests/fixtures/connect-billing-v1/`:

- `plans.json`: the `PlansView` of the default configuration (section 2). `totals.json`: totals for each plan, interval, and count, including a Family of 6 (700 a month, 7000 a year).
- `webhook/*.json`: one event of each handled type, the exact signed bytes (the final newline included); `webhook-vectors.json`: the synthetic endpoint secret `whsec_SYNTHETIC_apassy_connect_billing_v1_fixture`, each event's `t`, `v1`, and header, and headers that must be accepted or refused at a given `now` (two `v1` values, a wrong secret, 301 s late, exactly 300 s, a changed `t`, no `v1`, no `t`). `generate_webhooks.py` makes both.
- `plan-states.json`: inputs (Stripe status, period end, first failure, end, `cancel_at_period_end`, now) and the expected `status`, `entitled`, times, and permissions of section 8.
- `examples.json`: one example of every request and result body of this contract, the error bodies, and the form of a checkout session request to Stripe.

Both suites must show: each event body with its header verifies with the endpoint secret, and fails with a changed byte, another secret, or a time outside the tolerance; the totals follow the formula of section 2 from `plans.json`, and each year price is 10 times its month price in the default configuration; every case of `plan-states.json` follows section 8; every example parses with strict types. The relay's tests: C2 (`tests/server_billing.rs`), C3 (`tests/server_group.rs`); the fixture check: `contracts::connect_billing_v1_webhook_fixtures_verify_with_the_endpoint_secret`.
