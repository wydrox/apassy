//! Memory-only grants; the controller clears them at security lifecycle boundaries.
use super::trust::ProfileIdentity;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassScope {
    Once,
    FiveMinutes,
}

#[derive(Debug)]
pub enum Scope {
    Once,
    Until(Instant),
}

#[derive(Debug)]
pub struct RemoteDebuggingBypass {
    pub identity: ProfileIdentity,
    pub scope: Scope,
}

impl RemoteDebuggingBypass {
    pub fn approved(identity: ProfileIdentity, scope: BypassScope, now: Instant) -> Self {
        Self {
            identity,
            scope: match scope {
                BypassScope::Once => Scope::Once,
                BypassScope::FiveMinutes => Scope::Until(now + Duration::from_secs(300)),
            },
        }
    }
    pub fn remaining(&self, identity: &ProfileIdentity, now: Instant) -> Option<u64> {
        if &self.identity != identity {
            return None;
        }
        match self.scope {
            Scope::Once => Some(0),
            Scope::Until(end) if now < end => Some((end - now).as_millis().div_ceil(1000) as u64),
            _ => None,
        }
    }
}

pub fn consume(
    grant: &mut Option<RemoteDebuggingBypass>,
    identity: &ProfileIdentity,
    now: Instant,
) -> bool {
    let allowed = grant
        .as_ref()
        .is_some_and(|g| g.remaining(identity, now).is_some());
    if allowed
        && grant
            .as_ref()
            .is_some_and(|g| matches!(g.scope, Scope::Once))
    {
        *grant = None;
    }
    allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(port: &str) -> ProfileIdentity {
        ProfileIdentity {
            bundle_id: "net.imput.helium".into(),
            team_id: "S4Q33XPHB4".into(),
            profile_dir: "/tmp/owner".into(),
            debugging: port.into(),
            unsafe_switches: vec!["remote-debugging-port".into()],
        }
    }
    #[test]
    fn exact_once_and_expiry() {
        let now = Instant::now();
        let id = identity("9223");
        let mut grant = Some(RemoteDebuggingBypass::approved(
            id.clone(),
            BypassScope::Once,
            now,
        ));
        assert!(!consume(&mut grant, &identity("9222"), now));
        let mut other = id.clone();
        other.profile_dir = "/tmp/other".into();
        assert!(!consume(&mut grant, &other, now));
        assert!(consume(&mut grant, &id, now));
        assert!(!consume(&mut grant, &id, now));
        grant = Some(RemoteDebuggingBypass::approved(
            id.clone(),
            BypassScope::FiveMinutes,
            now,
        ));
        assert!(consume(&mut grant, &id, now + Duration::from_secs(299)));
        assert!(!consume(&mut grant, &id, now + Duration::from_secs(300)));
        grant = None;
        assert!(!consume(&mut grant, &id, now));
    }
}
