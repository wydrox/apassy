//! Apassy Connect end to end on one relay (ADR 0037 stage 7, unit CW): the real Mac
//! client of `src/connect` (unit M1, unchanged) against a relay with the account routes,
//! billing against the fake Stripe server, groups, and the tunnel. The account's own
//! requests go through the client; the routes it has no call for yet (checkout, the group,
//! the tunnel: units M2 to M4) are made with the client's own token (`with_token`), and
//! the relay-sync pushes are signed by the client's account key. Stripe's events are
//! signed with the synthetic endpoint secret and delivered as Stripe does. Free loopback
//! ports and temporary directories only; synthetic values only.

#[path = "common/connect.rs"]
mod connect;
#[path = "common/fake_stripe.rs"]
mod fake_stripe;
#[path = "common/relay.rs"]
mod relay;

use apassy::connect::{ConnectAccount, ConnectClient};
use apassy_relay::config::EdgeMode;
use apassy_relay::hostkeys::encode_b64;
use apassy_relay::server::tunnel::frame::{self, Kind};
use apassy_relay::server::tunnel::ws::close;
use connect::{Connect, Pusher, send, start_with_config};
use serde_json::{Value, json};

const VAULT: &str = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
/// A node certificate pin: b64u of 32 bytes (synthetic).
const PIN: &str = "7a1oa64ozJdU3s56iDjUthpkQFsZwnCaD5CYEkabiDk";

/// An app device: its key store and its account file.
struct AppDevice {
    _dir: tempfile::TempDir,
    store: apassy::connect::MemoryKeyStore,
    path: std::path::PathBuf,
}

fn app_device() -> AppDevice {
    let dir = tempfile::tempdir().unwrap();
    let path = apassy::connect::account_file(dir.path());
    AppDevice {
        _dir: dir,
        store: apassy::connect::MemoryKeyStore::new(),
        path,
    }
}

/// One JSON request to Connect with the account token of `account` (as the Mac's next
/// units will make it): the result, or the status and the error code.
fn with_account(
    account: &mut ConnectAccount,
    base: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Value, (u16, String)> {
    let base = base.to_string();
    account
        .with_token(|_client, token| {
            let (status, value) = relay::call_url(&base, None, method, path, Some(token), body);
            Ok((status, value))
        })
        .map(|(status, value)| {
            if status == 200 {
                Ok(value["result"].clone())
            } else {
                Err((
                    status,
                    value["error"]["code"].as_str().unwrap_or("").to_string(),
                ))
            }
        })
        .expect("the account token")
}

/// The relay-sync team token of the app's account key in the store `team`.
fn store_token(c: &Connect, account: &ConnectAccount, team: &str) -> String {
    let signer = account.signer().unwrap();
    let challenge = c.ok(
        "POST",
        "/v1/auth/challenge",
        None,
        Some(&json!({"team_id": team, "public_key": signer.public_key_b64u()})),
    );
    let nonce = challenge["nonce"].as_str().unwrap();
    let signature = signer.sign_relay_sign_in(c.origin(), team, nonce).unwrap();
    let granted = c.ok(
        "POST",
        "/v1/auth/token",
        None,
        Some(
            &json!({"team_id": team, "public_key": signer.public_key_b64u(), "nonce": nonce,
                     "signature": encode_b64(&signature)}),
        ),
    );
    granted["token"].as_str().unwrap().to_string()
}

#[test]
fn connect_works_end_to_end_with_the_app_client() {
    let c = start_with_config(|cfg| cfg.edge = EdgeMode::Off);
    let base = c.relay.url.clone();
    let client = || ConnectClient::new(&base).unwrap();

    // 1. The Mac makes an account; the plans come from Stripe's prices.
    let mac = app_device();
    let (mut owner, _recovery) =
        ConnectAccount::create(client(), &mac.store, &mac.path, "Rafal", "MacBook Pro")
            .expect("create");
    let owner_id = owner.state().account_id.clone();
    let plans = client().plans().expect("plans");
    assert_eq!(plans.plans.len(), 3);
    assert_eq!(owner.view().unwrap().plan.status, "none");

    // 2. A Family checkout: the URL comes from Stripe; nothing changes until the webhook.
    let checkout = with_account(
        &mut owner,
        &base,
        "POST",
        "/v1/account/checkout",
        Some(&json!({"plan": "family", "interval": "month", "people": 4})),
    )
    .expect("checkout");
    assert!(
        checkout["url"]
            .as_str()
            .unwrap()
            .starts_with("https://checkout.stripe.com/")
    );
    let session = &c.stripe.calls_to("POST", "/v1/checkout/sessions")[0];
    assert_eq!(
        session.field("client_reference_id"),
        Some(owner_id.as_str())
    );
    assert_eq!(owner.view().unwrap().plan.status, "none");

    // 3. Stripe's signed webhooks: the plan becomes active in the app's view. The
    // customer is the one Connect made before the session and named in it.
    let tail = &owner_id[4..];
    let customer = session
        .field("customer")
        .expect("the session's customer")
        .to_string();
    assert!(customer.starts_with("cus_"));
    let subscription = format!("sub_{tail}");
    c.deliver_ok(&c.checkout_completed(&owner_id, &customer, &subscription));
    c.deliver_ok(&c.subscription_event(
        "created",
        &owner_id,
        &customer,
        &subscription,
        "connect_family_month",
        4,
        "active",
    ));
    let view = owner.view().unwrap();
    assert_eq!(
        (
            view.plan.status.as_str(),
            view.plan.entitled,
            view.plan.plan.as_deref()
        ),
        ("active", true, Some("family"))
    );
    assert_eq!(view.email.as_deref(), Some("person@example.test"));
    assert!(owner.entitlement().expect("entitlement").is_some());

    // 4. A vault store and a push signed with the app's account key.
    let store = owner.create_vault_store(VAULT, "Family").expect("store");
    let team = store.team_id.clone();
    let token = store_token(&c, &owner, &team);
    let signer = owner.signer().unwrap();
    let sign = |message: &[u8]| signer.sign(message).unwrap();
    let mut pusher = Pusher::new(&team, VAULT);
    let pushed = pusher.try_push_with(&base, &token, 1, &sign, b"ciphertext version one");
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    pusher.pushed(1, b"ciphertext version one");
    let pulled = send(
        &base,
        "GET",
        "/v1/sync/snapshot?version=1",
        &token,
        &[],
        Vec::new(),
    );
    assert_eq!(
        (pulled.status, pulled.bytes.as_slice()),
        (200, &b"ciphertext version one"[..])
    );

    // 5. A family member: the invite, the join from the member's own account, the
    // confirmation; the member's app sees the group and the family plan.
    let anna_mac = app_device();
    let (mut anna, _) = ConnectAccount::create(
        client(),
        &anna_mac.store,
        &anna_mac.path,
        "Anna",
        "Anna's Mac",
    )
    .expect("create Anna");
    let anna_id = anna.state().account_id.clone();
    let invite = with_account(
        &mut owner,
        &base,
        "POST",
        "/v1/account/group/invites",
        Some(&json!({"role": "member"})),
    )
    .expect("invite");
    let code = connect::invite_code(&invite);
    let joined = with_account(
        &mut anna,
        &base,
        "POST",
        "/v1/account/group/join",
        Some(&json!({"code": code})),
    )
    .expect("join");
    assert_eq!(joined["state"], "pending");
    assert!(!anna.view().unwrap().plan.entitled);
    with_account(
        &mut owner,
        &base,
        "POST",
        &format!("/v1/account/group/members/{anna_id}/confirm"),
        Some(&json!({})),
    )
    .expect("confirm");
    let anna_view = anna.view().unwrap();
    let group = anna_view.group.expect("group");
    assert_eq!(
        (group.role.as_str(), group.state.as_str()),
        ("member", "active")
    );
    assert!(anna_view.plan.entitled);
    // The member's Mac joins the shared store.
    let anna_device = anna.state().device_id.clone();
    let added = with_account(
        &mut owner,
        &base,
        "POST",
        &format!("/v1/account/vaults/{team}/devices"),
        Some(&json!({"device_id": anna_device})),
    )
    .expect("add Anna's Mac");
    assert_eq!(added["store_device_id"], 2);
    assert!(anna.vault_stores().unwrap()[0].shared);

    // 6. The tunnel: the owner's Mac registers its node and keeps its WebSocket; the
    // owner grants Anna's account, and Anna's Mac dials the node: bytes go through.
    let node = with_account(
        &mut owner,
        &base,
        "POST",
        "/v1/tunnel/nodes",
        Some(&json!({"name": "MacBook Pro", "pin": PIN})),
    )
    .expect("register the node");
    let node_id = node["node_id"].as_str().unwrap().to_string();
    let owner_token = owner.with_token(|_, token| Ok(token.to_string())).unwrap();
    let anna_token = anna.with_token(|_, token| Ok(token.to_string())).unwrap();
    let mut node_socket = c
        .upgrade("/v1/tunnel/node", &owner_token)
        .expect("node 101");
    let wait = std::time::Instant::now();
    while !c.online(&node_id) {
        assert!(
            wait.elapsed() < std::time::Duration::from_secs(10),
            "the node is online"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let dial_path = format!("/v1/tunnel/dial/{node_id}");
    assert_eq!(
        c.upgrade(&dial_path, &anna_token).err(),
        Some((403, "not_in_group".to_string()))
    );
    with_account(
        &mut owner,
        &base,
        "POST",
        "/v1/tunnel/grants",
        Some(&json!({"node_id": node_id, "account_id": anna_id})),
    )
    .expect("grant");
    let mut dial = c.upgrade(&dial_path, &anna_token).expect("dial 101");
    let open = frame::decode(&node_socket.binary()).unwrap();
    assert_eq!(
        (open.kind, open.is_open(), open.payload.len()),
        (Kind::Device, true, 0)
    );
    dial.send(b"a TLS ClientHello, in fact");
    let data = frame::decode(&node_socket.binary()).unwrap();
    assert_eq!(
        (data.stream, data.payload.as_slice()),
        (open.stream, &b"a TLS ClientHello, in fact"[..])
    );
    node_socket.send(&frame::encode(
        open.stream,
        Kind::Device,
        0,
        b"a ServerHello",
    ));
    assert_eq!(dial.read_bytes(13), b"a ServerHello");

    // 7. The owner cancels: the plan ends; the open dial closes (4003) and a new one is
    // refused; read-only refuses a push and allows a pull.
    c.deliver_ok(&c.subscription_event(
        "deleted",
        &owner_id,
        &customer,
        &subscription,
        "connect_family_month",
        4,
        "canceled",
    ));
    assert_eq!(dial.closed(), Some(close::REVOKED));
    assert_eq!(
        c.upgrade(&dial_path, &anna_token).err(),
        Some((403, "plan_required".to_string()))
    );
    let view = owner.view().unwrap();
    assert_eq!(
        (view.plan.status.as_str(), view.plan.entitled),
        ("read_only", false)
    );
    assert!(view.plan.read_only_until.is_some() && view.plan.delete_at.is_some());
    let refused = pusher.try_push_with(&base, &token, 1, &sign, b"ciphertext version two");
    assert_eq!(
        (refused.status, refused.body["error"]["code"].as_str()),
        (403, Some("plan_required"))
    );
    let head = send(&base, "GET", "/v1/sync/head", &token, &[], Vec::new());
    assert_eq!(head.status, 200, "{}", head.body);
    let pulled = send(
        &base,
        "GET",
        "/v1/sync/snapshot?version=1",
        &token,
        &[],
        Vec::new(),
    );
    assert_eq!(
        (pulled.status, pulled.bytes.as_slice()),
        (200, &b"ciphertext version one"[..])
    );
    // The relay signs no new entitlement token (the app keeps its cached one until `exp`,
    // as every service that checks it does: contract section 10).
    assert_eq!(
        with_account(&mut owner, &base, "GET", "/v1/account/entitlement", None),
        Err((403, "plan_required".to_string()))
    );
}
