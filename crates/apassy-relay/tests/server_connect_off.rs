//! A relay without `APASSY_RELAY_CONNECT_ACCOUNTS` behaves as before Apassy Connect (plan
//! s7, ADR 0037 stage 7): no route of the three Connect contracts answers (every one is
//! `404 not_found`, for every method, with or without a token), the settings make no
//! Connect state, and billing never starts even when its Stripe settings are given. The
//! rest of the suite runs on such relays and is the proof of "as before".

#[path = "common/connect.rs"]
mod connect;
#[path = "common/fake_stripe.rs"]
mod fake_stripe;
#[path = "common/relay.rs"]
mod relay;

use std::time::Duration;

use apassy_relay::config::{RelayConfig, UpstreamOptions};
use relay::{EDGE_SECRET, call_raw, start, start_with};

/// Every path of connect-account-v1, connect-billing-v1, and connect-tunnel-v1.
const PATHS: &[&str] = &[
    "/v1/account",
    "/v1/account/challenge",
    "/v1/account/token",
    "/v1/account/devices/link",
    "/v1/account/devices/pending",
    "/v1/account/devices/pending/1/confirm",
    "/v1/account/devices/pending/1/refuse",
    "/v1/account/devices/join",
    "/v1/account/devices/join/cancel",
    "/v1/account/devices/dev_aaaaaaaaaa",
    "/v1/account/vaults",
    "/v1/account/vaults/t_aaaaaaaaaa/devices",
    "/v1/account/vaults/t_aaaaaaaaaa",
    "/v1/account/recover",
    "/v1/account/entitlement",
    "/.well-known/apassy-connect.json",
    "/v1/plans",
    "/v1/account/checkout",
    "/v1/account/portal",
    "/v1/account/plan",
    "/v1/account/group",
    "/v1/account/group/invites",
    "/v1/account/group/join",
    "/v1/account/group/members/acc_aaaaaaaaaa/confirm",
    "/v1/account/group/members/acc_aaaaaaaaaa",
    "/v1/account/group/seats",
    "/v1/stripe/webhook",
    "/v1/tunnel/nodes",
    "/v1/tunnel/nodes/node_aaaaaaaaaa",
    "/v1/tunnel/node",
    "/v1/tunnel/dial/node_aaaaaaaaaa",
    "/v1/tunnel/grants",
    "/v1/tunnel/grants/tgr_aaaaaaaaaa",
];

fn assert_not_found(url: &str, token: Option<&str>) {
    for path in PATHS {
        for method in ["GET", "POST", "PUT", "DELETE"] {
            let body = (method == "POST" || method == "PUT").then(|| serde_json::json!({}));
            let (status, text) = call_raw(
                url,
                Some(EDGE_SECRET),
                method,
                path,
                token,
                &[],
                body.as_ref(),
            );
            let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
            assert_eq!(
                (status, value["error"]["code"].as_str()),
                (404, Some("not_found")),
                "{method} {path}: {text}"
            );
        }
    }
}

#[test]
fn no_connect_route_answers_without_the_account_setting() {
    let relay = start(UpstreamOptions::default());
    assert!(!relay.config.connect.accounts);
    assert_not_found(&relay.url, None);
    assert_not_found(&relay.url, Some(&relay.owner_token));
    assert_not_found(&relay.url, Some("apassy_act_acc_aaaaaaaaaa_00"));
    // The routes of before still answer.
    let (status, _) = call_raw(
        &relay.url,
        Some(EDGE_SECRET),
        "GET",
        "/v1/me",
        Some(&relay.owner_token),
        &[],
        None,
    );
    assert_eq!(status, 200);
}

#[test]
fn billing_settings_alone_start_nothing() {
    let stripe = fake_stripe::FakeStripe::start();
    let base = stripe.base().to_string();
    let relay = start_with(
        |cfg| cfg.connect.billing = Some(connect::billing_settings(&base)),
        UpstreamOptions::default(),
    );
    assert!(relay.hub().billing().is_none());
    assert_not_found(&relay.url, None);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        stripe.calls().is_empty(),
        "no Stripe call without the account routes"
    );
}

#[test]
fn the_environment_without_connect_settings_makes_no_connect_state() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data").to_string_lossy().into_owned();
    let pairs: Vec<(&str, String)> = vec![
        ("APASSY_RELAY_DATA", data),
        (
            "APASSY_RELAY_PUBLIC_URL",
            "https://relay.example.test".into(),
        ),
        ("APASSY_RELAY_EDGE_SECRET", EDGE_SECRET.into()),
        ("APASSY_RELAY_KEY", relay::VAULT_KEY.into()),
    ];
    let config = RelayConfig::from_lookup(move |name| {
        pairs
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
    })
    .unwrap();
    assert!(!config.connect.accounts);
    assert_eq!(config.connect.mode, apassy_relay::config::RelayMode::Relay);
    assert!(config.connect.signing_key.is_none());
    assert!(config.connect.billing.is_none());
    assert!(config.team_vaults);
}
