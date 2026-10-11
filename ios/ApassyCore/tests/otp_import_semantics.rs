//! Old imports can retain custom titles for explicit TOTP setup URIs.
use apassy_core::Core;
use serde_json::{Value, json};

fn call(core: &Core, request: Value) -> Value {
    let answer: Value = serde_json::from_str(&core.call(&request.to_string())).unwrap();
    assert_eq!(answer["ok"], true);
    answer["result"].clone()
}

#[test]
fn a_custom_title_keeps_totp_controls_without_releasing_the_setup_key() {
    let root = tempfile::tempdir().unwrap();
    let core = Core::new(
        &json!({
            "data_dir": root.path(), "device_name": "Synthetic phone", "role": "app"
        })
        .to_string(),
    )
    .unwrap();
    call(
        &core,
        json!({"op": "create_local_vault", "name": "Synthetic", "passphrase": "synthetic-test-passphrase"}),
    );
    let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    let uri = format!("otpauth://totp/Test?secret={seed}");
    let item = call(
        &core,
        json!({"op": "save", "item": {
            "title": "Imported login", "kind": "login", "fields": [
                {"name": "username", "value": "synthetic-user", "secret": false},
                {"name": "password", "value": "synthetic-password", "secret": true},
                {"label": "Authenticator", "value": uri, "secret": true},
                {"label": "Public URI", "value": uri, "secret": false},
                {"label": "Other hidden field", "value": "synthetic-hidden-value", "secret": true}
            ]
        }}),
    );
    let rows = call(&core, json!({"op": "items"}));
    assert_eq!(rows["items"][0]["has_totp"], true);
    assert!(!rows.to_string().contains(seed));
    let detail = call(&core, json!({"op": "item", "id": item["id"]}));
    let fields = detail["fields"].as_array().unwrap();
    let otp = fields
        .iter()
        .find(|field| field["label"] == "Authenticator")
        .unwrap();
    assert_eq!(otp["role"], "totp");
    assert!(otp["value"].is_null());
    assert_eq!(
        fields
            .iter()
            .find(|field| field["label"] == "Public URI")
            .unwrap()["role"],
        "other"
    );
    assert_eq!(
        fields
            .iter()
            .find(|field| field["label"] == "Other hidden field")
            .unwrap()["role"],
        "other"
    );
    let code = call(
        &core,
        json!({"op": "totp", "id": item["id"], "field": otp["name"]}),
    );
    assert_eq!(code["code"].as_str().unwrap().len(), 6);
    assert!(
        code["code"]
            .as_str()
            .unwrap()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    );
    assert!(!code.to_string().contains(seed));
}
