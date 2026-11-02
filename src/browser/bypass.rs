//! Memory-only grants; the controller clears them at security lifecycle boundaries.
use super::trust::InstanceIdentity;
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

/// A random extension request nonce, plus provenance inserted by its native host.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBinding {
    pub nonce: String,
    pub connection: String,
}

impl RequestBinding {
    pub fn valid(&self) -> bool {
        super::wire::is_request_id(&self.nonce)
            && !self.connection.is_empty()
            && self.connection.len() <= 100
            && self
                .connection
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-')
    }
}

/// Explicit allowlist: future guarded commands never inherit owner bypasses.
pub fn owner_operation(command: &super::wire::Command) -> bool {
    matches!(
        command,
        super::wire::Command::PasskeyGet(_)
            | super::wire::Command::PasskeyCreate(_)
            | super::wire::Command::FillCode { .. }
    )
}

/// Agent fills have no path to memory-only owner grants.
pub fn authorize_agent_fill(identity: &InstanceIdentity) -> bool {
    super::trust::trusted_for_agent_fill(identity)
}

#[derive(Debug)]
pub struct OwnerPasskeyCodeBypass {
    pub identity: InstanceIdentity,
    pub scope: Scope,
    pub binding: Option<RequestBinding>,
    expires: Instant,
}

impl OwnerPasskeyCodeBypass {
    pub fn approved(identity: InstanceIdentity, scope: BypassScope, now: Instant) -> Self {
        Self {
            identity,
            binding: None,
            expires: now + Duration::from_secs(300),
            scope: match scope {
                BypassScope::Once => Scope::Once,
                BypassScope::FiveMinutes => Scope::Until(now + Duration::from_secs(300)),
            },
        }
    }
    pub fn remaining(&self, identity: &InstanceIdentity, now: Instant) -> Option<u64> {
        if &self.identity != identity || now >= self.expires {
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
    grant: &mut Option<OwnerPasskeyCodeBypass>,
    identity: &InstanceIdentity,
    now: Instant,
    command: &super::wire::Command,
    binding: Option<&RequestBinding>,
) -> bool {
    if !owner_operation(command) {
        return false;
    }
    let allowed = grant.as_ref().is_some_and(|g| {
        g.remaining(identity, now).is_some()
            && (!matches!(g.scope, Scope::Once)
                || (binding.is_some() && g.binding.as_ref() == binding))
    });
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
    fn identity(port: &str) -> InstanceIdentity {
        InstanceIdentity {
            bundle_id: "net.imput.helium".into(),
            team_id: "S4Q33XPHB4".into(),
            user_data_root: "/tmp/owner".into(),
            debugging: port.into(),
            unsafe_switches: vec!["remote-debugging-port".into()],
        }
    }
    #[test]
    fn exact_once_and_expiry() {
        let now = Instant::now();
        let id = identity("9223");
        let command = super::super::wire::Command::FillCode {
            url: "https://example.com".into(),
            item: 1,
            field: None,
        };
        let binding = RequestBinding {
            nonce: "3b241101-e2bb-4255-8caf-4136c566a962".into(),
            connection: "123-456".into(),
        };
        let mut grant = Some(OwnerPasskeyCodeBypass::approved(
            id.clone(),
            BypassScope::Once,
            now,
        ));
        grant.as_mut().unwrap().binding = Some(binding.clone());
        let other_binding = RequestBinding {
            connection: "999-456".into(),
            ..binding.clone()
        };
        assert!(!consume(
            &mut grant,
            &id,
            now,
            &command,
            Some(&other_binding)
        ));
        let other_nonce = RequestBinding {
            nonce: "4b241101-e2bb-4255-8caf-4136c566a962".into(),
            ..binding.clone()
        };
        assert!(!consume(&mut grant, &id, now, &command, Some(&other_nonce)));
        for denied in [
            super::super::wire::Command::Status,
            super::super::wire::Command::Show,
            super::super::wire::Command::Fill {
                url: "https://example.com".into(),
                item: 1,
            },
            super::super::wire::Command::BypassEnd,
        ] {
            assert!(!consume(&mut grant, &id, now, &denied, Some(&binding)));
        }
        assert!(!consume(
            &mut grant,
            &identity("9222"),
            now,
            &command,
            Some(&binding)
        ));
        let mut other = id.clone();
        other.user_data_root = "/tmp/other".into();
        assert!(!consume(&mut grant, &other, now, &command, Some(&binding)));
        assert!(consume(&mut grant, &id, now, &command, Some(&binding)));
        assert!(!consume(&mut grant, &id, now, &command, Some(&binding)));
        grant = Some(OwnerPasskeyCodeBypass::approved(
            id.clone(),
            BypassScope::FiveMinutes,
            now,
        ));
        for denied in [
            super::super::wire::Command::Status,
            super::super::wire::Command::Show,
            super::super::wire::Command::Logins {
                url: "https://example.com".into(),
            },
            super::super::wire::Command::Fill {
                url: "https://example.com".into(),
                item: 1,
            },
            super::super::wire::Command::BypassStatus,
        ] {
            assert!(!consume(&mut grant, &id, now, &denied, Some(&binding)));
        }
        assert!(consume(
            &mut grant,
            &id,
            now + Duration::from_secs(299),
            &command,
            Some(&binding)
        ));
        assert!(!consume(
            &mut grant,
            &id,
            now + Duration::from_secs(300),
            &command,
            Some(&binding)
        ));
        grant = None;
        assert!(!consume(&mut grant, &id, now, &command, Some(&binding)));
    }
}
