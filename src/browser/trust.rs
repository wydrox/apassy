//! Exact browser identities. Trust is device-local; it never grants owner fills.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileIdentity {
    pub bundle_id: String,
    pub team_id: String,
    pub profile_dir: String,
    /// Decimal TCP port, `pipe`, or `none` for extension-only unsafe switches.
    pub debugging: String,
    /// Names only: switch values can contain secrets and are never reported.
    pub unsafe_switches: Vec<String>,
}

impl ProfileIdentity {
    pub fn valid(&self) -> bool {
        let text = |s: &str, max| {
            !s.is_empty() && s.len() <= max && !s.chars().any(super::wire::hides_text)
        };
        text(&self.bundle_id, 128)
            && text(&self.team_id, 32)
            && text(&self.profile_dir, 700)
            && self.profile_dir.starts_with('/')
            && !self.profile_dir.split('/').any(|s| s == "." || s == "..")
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
            .profile_dir
            .rsplit('/')
            .take(2)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("/");
        format!(
            "{} (profile …/{short}, remote debugging on port {})",
            self.bundle_id, self.debugging
        )
    }
}

#[cfg(any(all(feature = "vault", feature = "desktop"), test))]
fn insert(profiles: &mut Vec<ProfileIdentity>, identity: &ProfileIdentity) {
    if !profiles.contains(identity) {
        profiles.push(identity.clone());
    }
}
#[cfg(any(all(feature = "vault", feature = "desktop"), test))]
fn delete(profiles: &mut Vec<ProfileIdentity>, identity: &ProfileIdentity) {
    profiles.retain(|p| p != identity);
}

/// Reads only the protected helper's non-synchronizing device setting. Failure denies.
#[cfg(all(feature = "vault", feature = "desktop"))]
pub fn profiles() -> Result<Vec<ProfileIdentity>, String> {
    crate::native::NativeHelper::locate()
        .map_err(|e| e.to_string())?
        .browser_trust_read()
        .map_err(|e| e.to_string())
}

#[cfg(all(feature = "vault", feature = "desktop"))]
pub fn trusted_for_agent_fill(identity: &ProfileIdentity) -> bool {
    identity.valid() && profiles().is_ok_and(|profiles| profiles.contains(identity))
}

#[cfg(all(feature = "vault", feature = "desktop"))]
pub fn add(
    identity: &ProfileIdentity,
    proof: crate::broker::approvals::OwnerProof,
    epoch: [u8; 32],
) -> Result<(), String> {
    proof
        .check(
            &crate::broker::approvals::OwnerAction::BrowserDebugging {
                identity: identity.clone(),
                scope: None,
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
pub fn remove(identity: &ProfileIdentity) -> Result<(), String> {
    let helper = crate::native::NativeHelper::locate().map_err(|e| e.to_string())?;
    let mut profiles = helper.browser_trust_read().map_err(|e| e.to_string())?;
    delete(&mut profiles, identity);
    helper
        .browser_trust_write(&profiles)
        .map_err(|e| e.to_string())
}

#[cfg(not(all(feature = "vault", feature = "desktop")))]
pub fn trusted_for_agent_fill(_identity: &ProfileIdentity) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn add_remove_and_exact_identity() {
        let id = ProfileIdentity {
            bundle_id: "net.imput.helium".into(),
            team_id: "S4Q33XPHB4".into(),
            profile_dir: "/tmp/owner".into(),
            debugging: "9223".into(),
            unsafe_switches: vec!["remote-debugging-port".into()],
        };
        assert!(id.valid());
        let mut profiles = Vec::new();
        insert(&mut profiles, &id);
        insert(&mut profiles, &id);
        assert_eq!(profiles.len(), 1);
        for other in [
            ProfileIdentity {
                debugging: "9222".into(),
                ..id.clone()
            },
            ProfileIdentity {
                profile_dir: "/tmp/other".into(),
                ..id.clone()
            },
            ProfileIdentity {
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
