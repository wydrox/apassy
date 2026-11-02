//! Exact browser identities. Trust is device-local; it never grants owner fills.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceIdentity {
    pub bundle_id: String,
    pub team_id: String,
    /// Canonical browser-instance root, shared by all its profiles. Keep the
    /// original serialized key for protected storage and guard wire compatibility.
    #[serde(rename = "profile_dir")]
    pub user_data_root: String,
    /// Decimal TCP port, `pipe`, or `none` for extension-only unsafe switches.
    pub debugging: String,
    /// Names only: switch values can contain secrets and are never reported.
    pub unsafe_switches: Vec<String>,
}

impl InstanceIdentity {
    pub fn valid(&self) -> bool {
        let text = |s: &str, max| {
            !s.is_empty() && s.len() <= max && !s.chars().any(super::wire::hides_text)
        };
        text(&self.bundle_id, 128)
            && text(&self.team_id, 32)
            && text(&self.user_data_root, 700)
            && self.user_data_root.starts_with('/')
            && !self
                .user_data_root
                .split('/')
                .any(|s| s == "." || s == "..")
            && (matches!(self.debugging.as_str(), "pipe" | "none")
                || self
                    .debugging
                    .parse::<u16>()
                    .is_ok_and(|p| p > 0 && p.to_string() == self.debugging))
            && !self.unsafe_switches.is_empty()
            && self.unsafe_switches.len() <= 16
            && self.unsafe_switches.iter().all(|s| {
                text(s, 80)
                    && (s.starts_with("remote-debugging")
                        || matches!(s.as_str(), "load-extension" | "disable-extensions-except"))
            })
    }

    pub fn description(&self) -> String {
        let short = self
            .user_data_root
            .rsplit('/')
            .take(2)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("/");
        format!(
            "{} instance (data folder …/{short}, remote debugging on port {}) — all its profiles",
            self.bundle_id, self.debugging
        )
    }
}

#[cfg(any(all(feature = "vault", feature = "desktop"), test))]
fn insert(profiles: &mut Vec<InstanceIdentity>, identity: &InstanceIdentity) {
    if !profiles.contains(identity) {
        profiles.push(identity.clone());
    }
}
#[cfg(any(all(feature = "vault", feature = "desktop"), test))]
fn delete(profiles: &mut Vec<InstanceIdentity>, identity: &InstanceIdentity) {
    profiles.retain(|p| p != identity);
}

/// Reads only the protected helper's non-synchronizing device setting. Failure denies.
#[cfg(all(feature = "vault", feature = "desktop"))]
pub fn profiles() -> Result<Vec<InstanceIdentity>, String> {
    crate::native::NativeHelper::locate()
        .map_err(|e| e.to_string())?
        .browser_trust_read()
        .map_err(|e| e.to_string())
}

#[cfg(all(feature = "vault", feature = "desktop"))]
pub fn trusted_for_agent_fill(identity: &InstanceIdentity) -> bool {
    identity.valid() && profiles().is_ok_and(|profiles| profiles.contains(identity))
}

#[cfg(all(feature = "vault", feature = "desktop"))]
pub fn add(
    identity: &InstanceIdentity,
    proof: crate::broker::approvals::OwnerProof,
    epoch: [u8; 32],
) -> Result<(), String> {
    proof
        .check(
            &crate::broker::approvals::OwnerAction::BrowserDebugging {
                identity: identity.clone(),
                scope: None,
                binding: None,
            },
            &epoch,
        )
        .map_err(|_| "The owner check changed.".to_owned())?;
    if !identity.valid() {
        return Err("Invalid browser identity".into());
    }
    let helper = crate::native::NativeHelper::locate().map_err(|e| e.to_string())?;
    let mut profiles = helper.browser_trust_read().map_err(|e| e.to_string())?;
    insert(&mut profiles, identity);
    helper
        .browser_trust_write(&profiles)
        .map_err(|e| e.to_string())
}

#[cfg(all(feature = "vault", feature = "desktop"))]
pub fn remove(identity: &InstanceIdentity) -> Result<(), String> {
    let helper = crate::native::NativeHelper::locate().map_err(|e| e.to_string())?;
    let mut profiles = helper.browser_trust_read().map_err(|e| e.to_string())?;
    delete(&mut profiles, identity);
    helper
        .browser_trust_write(&profiles)
        .map_err(|e| e.to_string())
}

#[cfg(not(all(feature = "vault", feature = "desktop")))]
pub fn trusted_for_agent_fill(_identity: &InstanceIdentity) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn add_remove_and_exact_identity() {
        let id = InstanceIdentity {
            bundle_id: "net.imput.helium".into(),
            team_id: "S4Q33XPHB4".into(),
            user_data_root: "/tmp/owner".into(),
            debugging: "9223".into(),
            unsafe_switches: vec!["remote-debugging-port".into()],
        };
        assert!(id.valid());
        let mut profiles = Vec::new();
        insert(&mut profiles, &id);
        insert(&mut profiles, &id);
        assert_eq!(profiles.len(), 1);
        for other in [
            InstanceIdentity {
                debugging: "9222".into(),
                ..id.clone()
            },
            InstanceIdentity {
                user_data_root: "/tmp/other".into(),
                ..id.clone()
            },
            InstanceIdentity {
                team_id: "OTHER".into(),
                ..id.clone()
            },
        ] {
            assert!(!profiles.contains(&other));
            delete(&mut profiles, &other);
            assert_eq!(profiles.len(), 1);
        }
        delete(&mut profiles, &id);
        assert!(profiles.is_empty());
    }
}
