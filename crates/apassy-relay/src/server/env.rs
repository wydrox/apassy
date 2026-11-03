//! The environment of a session (docs/SPEC.md, "Session lifecycle and environment").
//!
//! One placeholder per item, one base URL variable per item, and the well-known
//! provider variables. The values are placeholders and URLs: never a real value.

use std::collections::BTreeMap;

use apassy::broker::proxy::HostRule;
use apassy::broker::proxy::base_env;

use crate::api::SessionView;
use crate::ids::{ItemId, SessionId};
use crate::proxy::base_url;
use crate::secret::SecretString;

/// Variable names that the relay sets itself. An item cannot use them. The table is
/// the core's (`apassy::broker::proxy::base_env`), shared with the run proxy.
pub use apassy::broker::proxy::base_env::RESERVED_BASE_NAMES as RESERVED_NAMES;
/// The name of the base URL variable of an item.
pub use apassy::broker::proxy::base_env::base_var;

/// The variable that holds the expiry of the session.
pub const EXPIRES_VAR: &str = "APASSY_RELAY_SESSION_EXPIRES";

/// One item of a run.
pub struct EnvItem {
    pub item_id: ItemId,
    pub env_name: String,
    pub value: SecretString,
    pub hosts: Vec<HostRule>,
}

/// The provider variables that an item with these hosts gets, without their values.
pub fn provider_vars(hosts: &[HostRule]) -> Vec<&'static str> {
    base_env::provider_vars(hosts)
        .into_iter()
        .map(|var| var.name)
        .collect()
}

/// Builds the view of a session. `placeholders[i]` is the placeholder of `items[i]`.
pub fn build(
    public_url: &str,
    key: &SecretString,
    session_id: SessionId,
    expires_at: u64,
    items: &[EnvItem],
    placeholders: &[SecretString],
) -> SessionView {
    let base = |host: &HostRule| base_url(public_url, key, host);
    let mut order: Vec<usize> = (0..items.len()).collect();
    // The item with the lower id wins a provider variable.
    order.sort_by_key(|&i| items[i].item_id);
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut base_urls: BTreeMap<String, String> = BTreeMap::new();
    let mut names = Vec::with_capacity(items.len());
    for &i in &order {
        let item = &items[i];
        env.insert(item.env_name.clone(), placeholders[i].expose().to_string());
        names.push(item.env_name.clone());
        if let Some(first) = item.hosts.first() {
            env.insert(base_var(&item.env_name), base(first));
        }
        for host in &item.hosts {
            base_urls.insert(host.to_string(), base(host));
        }
        for var in base_env::provider_vars(&item.hosts) {
            if let Ok(rule) = HostRule::parse(var.host) {
                env.entry(var.name.to_string())
                    .or_insert_with(|| format!("{}{}", base(&rule), var.suffix));
            }
        }
    }
    env.insert(EXPIRES_VAR.to_string(), expires_at.to_string());
    names.sort();
    SessionView {
        session_id,
        expires_at,
        env,
        placeholders: names,
        base_urls,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretString {
        SecretString::new(format!("apassy_ses_{}", "c".repeat(64)))
    }

    fn item(id: u64, env: &str, hosts: &[&str]) -> EnvItem {
        EnvItem {
            item_id: ItemId(id),
            env_name: env.into(),
            value: SecretString::new("v".into()),
            hosts: hosts.iter().map(|h| HostRule::parse(h).unwrap()).collect(),
        }
    }

    #[test]
    fn provider_variables_and_base_urls() {
        let items = vec![
            item(2, "OTHER_KEY", &["api.stripe.com", "api.example.com:8443"]),
            item(1, "STRIPE_API_KEY", &["api.stripe.com", "api.openai.com"]),
        ];
        let ph = vec![
            SecretString::new("p2".into()),
            SecretString::new("p1".into()),
        ];
        let view = build("https://r.test", &key(), SessionId(1), 99, &items, &ph);
        let prefix = format!("https://r.test/p/{}/", key().expose());
        assert_eq!(view.env["STRIPE_API_KEY"], "p1");
        assert_eq!(view.env["OTHER_KEY"], "p2");
        assert_eq!(
            view.env["STRIPE_API_BASE"],
            format!("{prefix}api.stripe.com")
        );
        assert_eq!(
            view.env["OPENAI_BASE_URL"],
            format!("{prefix}api.openai.com/v1")
        );
        assert_eq!(
            view.env["APASSY_BASE_OTHER_KEY"],
            format!("{prefix}api.stripe.com")
        );
        assert_eq!(view.env[EXPIRES_VAR], "99");
        assert!(!view.env.contains_key("ANTHROPIC_BASE_URL"));
        assert_eq!(
            view.base_urls["api.example.com:8443"],
            format!("{prefix}api.example.com:8443")
        );
        assert_eq!(view.placeholders, vec!["OTHER_KEY", "STRIPE_API_KEY"]);
    }
}
