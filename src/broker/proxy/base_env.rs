//! Base URL variables of a run: one table for local, linked, and cloud runs
//! (ADR 0011 stage 4, ADR 0037 §5).
//!
//! An item gets `APASSY_BASE_<ENV_NAME>`. An item for a well-known API host also
//! gets the provider variable that the tools of that provider read. The values are
//! URLs of a proxy, never a real value. The relay builds them for `/p/` today
//! (`crates/apassy-relay/src/server/env.rs`); a loopback base URL of the run proxy
//! uses the same table.

use super::HostRule;

/// A provider variable: the tools of a provider read it as the base URL of its API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderVar {
    /// The variable name, for example `OPENAI_BASE_URL`.
    pub name: &'static str,
    /// The API host that the variable points at.
    pub host: &'static str,
    /// What follows the base of the host in the value, for example `/v1`.
    pub suffix: &'static str,
}

/// The provider variables, in the order a run sets them.
pub const PROVIDER_VARS: [ProviderVar; 4] = [
    ProviderVar {
        name: "STRIPE_API_BASE",
        host: "api.stripe.com",
        suffix: "",
    },
    ProviderVar {
        name: "OPENAI_BASE_URL",
        host: "api.openai.com",
        suffix: "/v1",
    },
    ProviderVar {
        name: "ANTHROPIC_BASE_URL",
        host: "api.anthropic.com",
        suffix: "",
    },
    ProviderVar {
        name: "GITHUB_API_URL",
        host: "api.github.com",
        suffix: "",
    },
];

/// Variable names of the provider table. An item cannot use them.
pub const RESERVED_BASE_NAMES: [&str; 4] = [
    PROVIDER_VARS[0].name,
    PROVIDER_VARS[1].name,
    PROVIDER_VARS[2].name,
    PROVIDER_VARS[3].name,
];

/// The name of the base URL variable of an item.
pub fn base_var(env_name: &str) -> String {
    format!("APASSY_BASE_{env_name}")
}

/// The provider variables that an item with these hosts gets, in table order. A
/// variable counts when a host rule of the item covers its host on port 443.
pub fn provider_vars(hosts: &[HostRule]) -> Vec<&'static ProviderVar> {
    PROVIDER_VARS
        .iter()
        .filter(|var| hosts.iter().any(|rule| rule.covers(var.host, 443)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(hosts: &[&str]) -> Vec<HostRule> {
        hosts.iter().map(|h| HostRule::parse(h).unwrap()).collect()
    }

    #[test]
    fn provider_variables_follow_the_hosts_in_table_order() {
        let names = |hosts: &[&str]| -> Vec<&str> {
            provider_vars(&rules(hosts))
                .into_iter()
                .map(|var| var.name)
                .collect()
        };
        assert_eq!(
            names(&["api.github.com", "api.openai.com", "api.stripe.com"]),
            vec!["STRIPE_API_BASE", "OPENAI_BASE_URL", "GITHUB_API_URL"]
        );
        // A parent domain covers the API host; another port does not.
        assert_eq!(names(&["anthropic.com"]), vec!["ANTHROPIC_BASE_URL"]);
        assert!(names(&["api.openai.com:8443", "example.com"]).is_empty());
        let openai = provider_vars(&rules(&["api.openai.com"]))[0];
        assert_eq!(openai.suffix, "/v1");
        assert_eq!(base_var("OPENAI_API_KEY"), "APASSY_BASE_OPENAI_API_KEY");
        assert_eq!(
            RESERVED_BASE_NAMES,
            PROVIDER_VARS.map(|var| var.name),
            "the reserved names are the table"
        );
    }

    #[test]
    fn every_provider_host_is_a_valid_rule() {
        for var in PROVIDER_VARS {
            assert!(HostRule::parse(var.host).is_ok(), "{}", var.host);
        }
    }
}
