//! A relay with Apassy Connect on for the tests of billing, groups, and the end-to-end
//! flow: the account routes, the entitlement signing key, and billing against the fake
//! Stripe server (`fake_stripe.rs`) on its loopback address, with a synthetic webhook
//! secret so a test signs and delivers Stripe's events itself. Free loopback ports and
//! temporary directories only; synthetic values only.
//!
//! A test binary declares `mod relay;`, `mod fake_stripe;`, and `mod connect;` with their
//! `#[path]`s.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use apassy_relay::config::{
    BillingSettings, ConnectConfig, ConnectSigningKey, RelayConfig, UpstreamOptions,
};
use apassy_relay::device::{self, DeviceKey};
use apassy_relay::hostkeys::encode_b64;
use apassy_relay::secret::SecretString;
use apassy_relay::server::stripe::signature_header;
use serde_json::{Value, json};

use crate::fake_stripe::{FAKE_KEY, FakeStripe};
use crate::relay::{EDGE_SECRET, TestRelay, VAULT_KEY, call_raw, call_url, start_with};

/// The synthetic endpoint secret of the tests' webhooks.
pub const WEBHOOK_SECRET: &str = "whsec_SYNTHETIC_apassy_connect_relay_tests";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex"))
        .collect()
}

/// The Ed25519 seed of the account vectors (bytes 32 to 63) as a PKCS#8 v1 DER file.
pub fn signing_key() -> ConnectSigningKey {
    let mut der = unhex("302e020100300506032b657004220420");
    der.extend((32u8..64).collect::<Vec<_>>());
    ConnectSigningKey::from_file_bytes(&der).expect("signing key")
}

/// The billing settings of the tests: the fake Stripe at `base`.
pub fn billing_settings(base: &str) -> BillingSettings {
    let mut settings = BillingSettings::new(
        SecretString::new(FAKE_KEY.to_string()),
        SecretString::new(WEBHOOK_SECRET.to_string()),
    );
    settings.stripe_api_base = base.to_string();
    settings
}

/// A relay with accounts and billing, and its fake Stripe.
pub struct Connect {
    pub relay: TestRelay,
    pub stripe: FakeStripe,
    /// `created` of the next synthetic event: strictly increasing, from now.
    clock: AtomicU64,
    /// `created` of the newest delivered event of each subscription: the fake Stripe
    /// answers its object to a read, as Stripe would.
    stripe_state: Mutex<HashMap<String, u64>>,
}

/// An account device of a test.
pub struct Dev {
    pub key: DeviceKey,
    pub account: String,
    pub id: String,
    pub token: String,
}

pub fn start() -> Connect {
    start_with_config(|_| {})
}

/// A Connect relay; `edit` changes the configuration after billing is set.
pub fn start_with_config(edit: impl FnOnce(&mut RelayConfig)) -> Connect {
    let stripe = FakeStripe::start();
    let base = stripe.base().to_string();
    let relay = start_with(
        |cfg| {
            cfg.connect = ConnectConfig::accounts(Some(signing_key()));
            cfg.connect.billing = Some(billing_settings(&base));
            edit(cfg);
        },
        UpstreamOptions::default(),
    );
    // The tests run the billing pass themselves (`billing_store::maintain`).
    apassy_relay::server::billing_store::defer_background_pass(
        &relay.hub(),
        apassy_relay::now_unix(),
    );
    Connect {
        relay,
        stripe,
        clock: AtomicU64::new(apassy_relay::now_unix()),
        stripe_state: Mutex::new(HashMap::new()),
    }
}

pub fn now() -> u64 {
    apassy_relay::now_unix()
}

impl Connect {
    /// A handle of a relay started on its own (`relay::start_existing`) and the fake Stripe
    /// that its billing settings name.
    pub fn around(relay: TestRelay, stripe: FakeStripe) -> Self {
        Self {
            relay,
            stripe,
            clock: AtomicU64::new(apassy_relay::now_unix()),
        }
    }
}

impl Connect {
    pub fn origin(&self) -> &str {
        &self.relay.config.public_url
    }

    pub fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> (u16, Value) {
        call_url(
            &self.relay.url,
            Some(EDGE_SECRET),
            method,
            path,
            token,
            body,
        )
    }

    pub fn ok(&self, method: &str, path: &str, token: Option<&str>, body: Option<&Value>) -> Value {
        let (status, value) = self.call(method, path, token, body);
        assert_eq!(status, 200, "{method} {path}: {value}");
        value["result"].clone()
    }

    pub fn fails(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        status: u16,
        code: &str,
    ) {
        let (got, value) = self.call(method, path, token, body);
        assert_eq!(
            (got, value["error"]["code"].as_str()),
            (status, Some(code)),
            "{method} {path}: {value}"
        );
    }

    /// Rows of one text column of `relay.db`.
    pub fn rows(&self, sql: &str) -> Vec<String> {
        let conn = rusqlite::Connection::open(self.relay.config.directory_path()).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
            .unwrap();
        conn.busy_timeout(Duration::from_secs(10)).unwrap();
        let mut statement = conn.prepare(sql).unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Runs SQL on `relay.db` while the relay runs.
    pub fn edit_directory(&self, sql: &str) {
        let conn = rusqlite::Connection::open(self.relay.config.directory_path()).unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{VAULT_KEY}';"))
            .unwrap();
        conn.busy_timeout(Duration::from_secs(10)).unwrap();
        conn.execute_batch(sql).unwrap();
    }

    /// A new account with one Mac, signed in.
    pub fn account(&self, name: &str) -> Dev {
        let key = DeviceKey::generate().unwrap();
        let public_key = key.public_key_b64();
        let signature = key
            .sign(&device::account_message(self.origin(), &public_key))
            .unwrap();
        let made = self.ok(
            "POST",
            "/v1/account",
            None,
            Some(
                &json!({"name": name, "device_name": format!("{name}'s Mac"), "platform": "mac",
                         "public_key": public_key,
                         "recovery_hash": device::account_recovery_hash(&[9u8; 16]),
                         "signature": encode_b64(&signature)}),
            ),
        );
        let mut dev = Dev {
            key,
            account: made["account_id"].as_str().unwrap().to_string(),
            id: made["device_id"].as_str().unwrap().to_string(),
            token: String::new(),
        };
        dev.token = self.sign_in(&dev);
        dev
    }

    /// The account token of `dev`.
    pub fn sign_in(&self, dev: &Dev) -> String {
        let challenge = self.ok(
            "POST",
            "/v1/account/challenge",
            None,
            Some(&json!({"account_id": dev.account, "public_key": dev.key.public_key_b64()})),
        );
        let nonce = challenge["nonce"].as_str().unwrap();
        let message = device::account_sign_in_message(
            self.origin(),
            &dev.account,
            &dev.key.public_key_b64(),
            nonce,
        );
        let granted = self.ok(
            "POST",
            "/v1/account/token",
            None,
            Some(&json!({"account_id": dev.account, "public_key": dev.key.public_key_b64(),
                         "nonce": nonce, "signature": encode_b64(&dev.key.sign(&message).unwrap())})),
        );
        granted["token"].as_str().unwrap().to_string()
    }

    /// The next `created` time of a synthetic event. The fake Stripe's clock (its `Date`
    /// header) follows it, as Stripe's own clock is never behind its events.
    pub fn tick(&self) -> u64 {
        let created = self.clock.fetch_add(1, Ordering::Relaxed) + 1;
        self.stripe.set_date(Some(created));
        created
    }

    /// Delivers `event` as Stripe does: the exact bytes with a `Stripe-Signature` of now.
    /// A subscription event's object becomes the fake Stripe's state of it when it is the
    /// newest of that subscription.
    pub fn deliver(&self, event: &Value) -> (u16, Value) {
        if event["type"]
            .as_str()
            .is_some_and(|kind| kind.starts_with("customer.subscription."))
            && let Some(id) = event["data"]["object"]["id"].as_str()
        {
            let created = event["created"].as_u64().unwrap_or(0);
            let mut seen = self.stripe_state.lock().unwrap();
            if seen.get(id).is_none_or(|last| created >= *last) {
                seen.insert(id.to_string(), created);
                self.stripe
                    .put_subscription(event["data"]["object"].clone());
            }
        }
        let body = serde_json::to_vec(event).unwrap();
        self.deliver_bytes(
            &body,
            &signature_header(&SecretString::new(WEBHOOK_SECRET.to_string()), now(), &body),
        )
    }

    /// Delivers raw bytes with a given signature header.
    pub fn deliver_bytes(&self, body: &[u8], signature: &str) -> (u16, Value) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        let mut response = agent
            .post(format!("{}/v1/stripe/webhook", self.relay.url))
            .header("X-Apassy-Edge", EDGE_SECRET)
            .header("Stripe-Signature", signature)
            .header("Content-Type", "application/json")
            .send(body)
            .expect("webhook");
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().unwrap_or_default();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    /// Delivers `event` and expects it to be received once.
    pub fn deliver_ok(&self, event: &Value) {
        let (status, answer) = self.deliver(event);
        assert_eq!(status, 200, "{answer}");
        assert_eq!(answer["result"]["received"], true, "{answer}");
        assert_eq!(answer["result"]["duplicate"], false, "{answer}");
    }

    /// `checkout.session.completed` for `account` binding `customer` and `subscription`.
    pub fn checkout_completed(&self, account: &str, customer: &str, subscription: &str) -> Value {
        let created = self.tick();
        json!({"id": format!("evt_checkout{created}"), "object": "event",
               "api_version": "2025-03-31.basil", "created": created, "type": "checkout.session.completed",
               "data": {"object": {"id": format!("cs_test_{created}"), "object": "checkout.session",
                   "mode": "subscription", "client_reference_id": account,
                   "metadata": {"account_id": account}, "customer": customer,
                   "subscription": subscription,
                   "customer_details": {"email": "person@example.test"}}}})
    }

    /// `customer.subscription.<kind>` with one item.
    #[allow(clippy::too_many_arguments)]
    pub fn subscription_event(
        &self,
        kind: &str,
        account: &str,
        customer: &str,
        subscription: &str,
        lookup_key: &str,
        quantity: u32,
        status: &str,
    ) -> Value {
        let created = self.tick();
        json!({"id": format!("evt_sub{created}"), "object": "event",
               "api_version": "2025-03-31.basil", "created": created,
               "type": format!("customer.subscription.{kind}"),
               "data": {"object": {"id": subscription, "object": "subscription",
                   "customer": customer, "status": status, "cancel_at_period_end": false,
                   "ended_at": if status == "canceled" { json!(created) } else { Value::Null },
                   "metadata": {"account_id": account},
                   "items": {"object": "list", "data": [{"id": format!("si_{}", &subscription[4..]),
                       "object": "subscription_item", "quantity": quantity,
                       "current_period_end": created + 30 * 86_400,
                       "price": {"id": "price_Synth", "lookup_key": lookup_key}}]}}}})
    }

    /// The Stripe customer of `dev`: the one Connect made at its first checkout, else
    /// `cus_<account tail>`.
    pub fn customer_of(&self, dev: &Dev) -> String {
        self.rows(&format!(
            "SELECT customer_id FROM stripe_customer WHERE account_id = '{}'",
            dev.account
        ))
        .pop()
        .unwrap_or_else(|| format!("cus_{}", &dev.account[4..]))
    }

    /// A paid subscription: the checkout and the subscription's own `created` event.
    /// Answers the subscription id.
    pub fn subscribe(&self, dev: &Dev, lookup_key: &str, quantity: u32) -> String {
        let tail: String = dev.account[4..].to_string();
        let customer = self.customer_of(dev);
        let subscription = format!("sub_{tail}");
        self.deliver_ok(&self.checkout_completed(&dev.account, &customer, &subscription));
        self.deliver_ok(&self.subscription_event(
            "created",
            &dev.account,
            &customer,
            &subscription,
            lookup_key,
            quantity,
            "active",
        ));
        subscription
    }

    /// The subscription of `dev` (from `subscribe`) changes to `status` and `quantity`.
    pub fn update(&self, dev: &Dev, lookup_key: &str, quantity: u32, status: &str) {
        let tail: String = dev.account[4..].to_string();
        let kind = if status == "canceled" {
            "deleted"
        } else {
            "updated"
        };
        self.deliver_ok(&self.subscription_event(
            kind,
            &dev.account,
            &self.customer_of(dev),
            &format!("sub_{tail}"),
            lookup_key,
            quantity,
            status,
        ));
    }

    /// Moves the end of `subscription` to `ended_at`, in `relay.db` and in the fake
    /// Stripe's object (Stripe's `ended_at` wins when the relay reads the subscription).
    pub fn end_subscription_at(&self, subscription: &str, ended_at: u64) {
        self.edit_directory(&format!(
            "UPDATE stripe_subscription SET ended_at = {ended_at} WHERE subscription_id = '{subscription}'"
        ));
        if let Some(mut object) = self.stripe.subscription(subscription) {
            object["ended_at"] = json!(ended_at);
            self.stripe.put_subscription(object);
        }
    }

    /// `GET /v1/account/plan` of `dev`.
    pub fn plan(&self, dev: &Dev) -> Value {
        self.ok("GET", "/v1/account/plan", Some(&dev.token), None)
    }

    /// `owner` invites, `who` joins, `owner` confirms: `who` is an active member.
    pub fn add_member(&self, owner: &Dev, who: &Dev) -> Value {
        let invite = self.ok(
            "POST",
            "/v1/account/group/invites",
            Some(&owner.token),
            Some(&json!({"role": "member"})),
        );
        let code = invite_code(&invite);
        self.ok(
            "POST",
            "/v1/account/group/join",
            Some(&who.token),
            Some(&json!({"code": code})),
        );
        self.ok(
            "POST",
            &format!("/v1/account/group/members/{}/confirm", who.account),
            Some(&owner.token),
            Some(&json!({})),
        )
    }

    /// A raw request with extra headers.
    pub fn raw(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> (u16, String) {
        call_raw(
            &self.relay.url,
            Some(EDGE_SECRET),
            method,
            path,
            token,
            headers,
            body,
        )
    }
}

/// The code of an invite answer: the fragment of its URL.
pub fn invite_code(invite: &Value) -> String {
    invite["url"]
        .as_str()
        .unwrap()
        .split_once('#')
        .unwrap()
        .1
        .to_string()
}

// ---- Relay sync on a vault store (relay-sync-v1 with the account device key). ----

/// The answer of a relay-sync request.
pub struct Answer {
    pub status: u16,
    pub body: Value,
    pub bytes: Vec<u8>,
}

/// One relay-sync request with a team token.
pub fn send(
    base: &str,
    method: &str,
    path: &str,
    token: &str,
    headers: &[(&str, String)],
    body: Vec<u8>,
) -> Answer {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut builder = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{base}{path}"))
        .header("X-Apassy-Edge", EDGE_SECRET)
        .header("Authorization", format!("Bearer {token}"));
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    let mut response = agent.run(builder.body(body).unwrap()).unwrap();
    let status = response.status().as_u16();
    let bytes = response.body_mut().read_to_vec().unwrap_or_default();
    Answer {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        bytes,
    }
}

/// The pushes of one vault store: the chain of relay-sync-v1 sections 8 and 24.
pub struct Pusher {
    pub team: String,
    pub vault: String,
    pub version: u64,
    pub previous: String,
}

impl Pusher {
    pub fn new(team: &str, vault: &str) -> Self {
        Self {
            team: team.to_string(),
            vault: vault.to_string(),
            version: 0,
            previous: "0".repeat(64),
        }
    }

    pub fn head(&self, device: u64, body: &[u8]) -> String {
        use sha2::Digest;
        format!(
            "apassy-relay-sync-head-v1\n{} {} {} {}\n{} {}/{device} 1790000000",
            self.vault,
            self.version + 1,
            apassy_relay::sync_head::hex(&sha2::Sha256::digest(body)),
            body.len(),
            self.previous,
            self.team
        )
    }

    /// A push signed by `sign` (the device key, or the app's account signer).
    pub fn try_push_with(
        &self,
        base: &str,
        token: &str,
        device: u64,
        sign: &dyn Fn(&[u8]) -> Vec<u8>,
        body: &[u8],
    ) -> Answer {
        let text = self.head(device, body);
        send(
            base,
            "PUT",
            "/v1/sync/snapshot",
            token,
            &[
                ("If-Match", format!("\"{}\"", self.version)),
                ("Content-Type", "application/octet-stream".to_string()),
                ("X-Apassy-Sync-Head", encode_b64(text.as_bytes())),
                (
                    "X-Apassy-Sync-Signature",
                    encode_b64(&sign(text.as_bytes())),
                ),
            ],
            body.to_vec(),
        )
    }

    /// The next version moved on after a push that answered 200.
    pub fn pushed(&mut self, device: u64, body: &[u8]) {
        let text = self.head(device, body);
        self.version += 1;
        self.previous =
            apassy_relay::sync_head::hex(&apassy_relay::sync_head::head_hash(text.as_bytes()));
    }
}

impl Connect {
    /// A vault store of `dev` for `vault`: its id and `dev`'s store device id.
    pub fn store(&self, dev: &Dev, vault: &str) -> (String, u64) {
        let store = self.ok(
            "POST",
            "/v1/account/vaults",
            Some(&dev.token),
            Some(&json!({"vault_id": vault, "name": "Personal"})),
        );
        (
            store["team_id"].as_str().unwrap().to_string(),
            store["devices"][0]["store_device_id"].as_u64().unwrap(),
        )
    }

    /// The relay-sync team token of `dev` in the store `team`.
    pub fn store_token(&self, team: &str, dev: &Dev) -> String {
        let team = apassy_relay::ids::TeamId::parse(team).unwrap();
        self.relay.sign_in(&team, &dev.key)
    }

    /// A push of `body` by `dev` (store device `device`) with its key.
    pub fn try_push(
        &self,
        pusher: &Pusher,
        token: &str,
        device: u64,
        dev: &Dev,
        body: &[u8],
    ) -> Answer {
        pusher.try_push_with(
            &self.relay.url,
            token,
            device,
            &|message| dev.key.sign(message).unwrap(),
            body,
        )
    }

    /// `GET /v1/sync/head` (a pull) and `GET /v1/sync/snapshot?version=<version>` (a
    /// download) of a store.
    pub fn pull(&self, token: &str, version: u64) -> (u16, u16) {
        (
            send(
                &self.relay.url,
                "GET",
                "/v1/sync/head",
                token,
                &[],
                Vec::new(),
            )
            .status,
            send(
                &self.relay.url,
                "GET",
                &format!("/v1/sync/snapshot?version={version}"),
                token,
                &[],
                Vec::new(),
            )
            .status,
        )
    }
}

// ---- The tunnel (connect-tunnel-v1): WebSocket peers. ----

/// One end of a tunnel WebSocket: a node or a dialing device.
pub struct Peer {
    reader: apassy_relay::server::tunnel::ws::Reader<std::net::TcpStream>,
    writer: std::net::TcpStream,
}

impl Peer {
    pub fn send(&mut self, bytes: &[u8]) {
        use apassy_relay::server::tunnel::ws;
        ws::client::send(&mut self.writer, ws::OP_BINARY, bytes).unwrap();
    }

    /// The next message that is not a ping (pings are answered).
    pub fn next(&mut self) -> apassy_relay::server::tunnel::ws::Message {
        use apassy_relay::server::tunnel::ws::{self, Message};
        loop {
            match self.reader.read_message() {
                Ok(Message::Ping(payload)) => {
                    let _ = ws::client::send(&mut self.writer, ws::OP_PONG, &payload);
                }
                Ok(message) => return message,
                Err(error) => panic!("read: {error:?}"),
            }
        }
    }

    /// The next binary message.
    pub fn binary(&mut self) -> Vec<u8> {
        match self.next() {
            apassy_relay::server::tunnel::ws::Message::Binary(bytes) => bytes,
            other => panic!("expected bytes, got {other:?}"),
        }
    }

    /// Reads binary messages until `len` bytes came.
    pub fn read_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < len {
            out.extend(self.binary());
        }
        out
    }

    /// Waits for the close, skipping data; answers its code.
    pub fn closed(&mut self) -> Option<u16> {
        loop {
            match self.next() {
                apassy_relay::server::tunnel::ws::Message::Close(code) => return code,
                apassy_relay::server::tunnel::ws::Message::Binary(_) => {}
                other => panic!("expected a close, got {other:?}"),
            }
        }
    }
}

impl Connect {
    /// A WebSocket handshake to `path` with `token`; `Err` is the refusal's status and code.
    pub fn upgrade(&self, path: &str, token: &str) -> Result<Peer, (u16, String)> {
        use apassy_relay::server::tunnel::ws::client;
        use std::io::Write;
        let address = self.relay.url.trim_start_matches("http://");
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let key = client::new_key();
        let mut text =
            String::from_utf8(client::request("relay.test", path, &key, Some(token))).unwrap();
        text.truncate(text.len() - 2);
        text.push_str(&format!("X-Apassy-Edge: {EDGE_SECRET}\r\n\r\n"));
        stream.write_all(text.as_bytes()).unwrap();
        match client::finish(&mut stream, &key) {
            Ok(()) => {
                let writer = stream.try_clone().unwrap();
                Ok(Peer {
                    reader: apassy_relay::server::tunnel::ws::Reader::client(stream, 1 << 20),
                    writer,
                })
            }
            Err(client::HandshakeError::Refused(refused)) => {
                let body: Value = serde_json::from_slice(&refused.body).unwrap_or_default();
                Err((
                    refused.status,
                    body["error"]["code"].as_str().unwrap_or("").to_string(),
                ))
            }
            Err(other) => panic!("handshake: {other:?}"),
        }
    }

    /// Whether the node has an open WebSocket.
    pub fn online(&self, node_id: &str) -> bool {
        self.relay
            .hub()
            .tunnel()
            .is_some_and(|broker| broker.online(node_id))
    }
}
