//! Row ids of the team vault. Each is a positive `u64` and serializes as a plain number.

use serde::{Deserialize, Serialize};

macro_rules! row_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub u64);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = std::num::ParseIntError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                text.parse::<u64>().map(Self)
            }
        }
    };
}

row_id!(
    /// A member of the team: the owner, a manager, or a member.
    MemberId
);
row_id!(
    /// An agent of one member.
    AgentId
);
row_id!(
    /// A named set of items with one policy.
    CollectionId
);
row_id!(
    /// One credential in one collection.
    ItemId
);
row_id!(
    /// The use of one collection by one member.
    GrantId
);
row_id!(
    /// One run request of an agent. It is also the approval id.
    RunId
);
row_id!(
    /// One live proxy session of a released run.
    SessionId
);
row_id!(
    /// One one-time invite code.
    InviteId
);
row_id!(
    /// One audit row.
    AuditId
);
row_id!(
    /// One device (key pair) of one member. Local to its team.
    DeviceId
);

/// The public id of a team: `t_` and 10 characters of lowercase base32 (`a-z`, `2-7`).
/// It is in every credential of the team, so the relay finds the team before it opens
/// anything. It is not a secret.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TeamId(String);

/// The length of a team id, `t_` included.
pub const TEAM_ID_LEN: usize = 12;

impl TeamId {
    /// A team id if `text` has the form, else `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("t_")?;
        let ok = rest.len() == TEAM_ID_LEN - 2
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
        ok.then(|| Self(text.to_string()))
    }

    /// A new random team id.
    pub fn generate() -> Result<Self, getrandom::Error> {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut bytes = [0u8; TEAM_ID_LEN - 2];
        getrandom::fill(&mut bytes)?;
        let mut text = String::with_capacity(TEAM_ID_LEN);
        text.push_str("t_");
        for byte in bytes {
            text.push(char::from(ALPHABET[usize::from(byte & 31)]));
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TeamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TeamId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| serde::de::Error::custom("not a team id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_ids_have_one_form() {
        let id = TeamId::generate().unwrap();
        assert_eq!(id.as_str().len(), TEAM_ID_LEN);
        assert_eq!(TeamId::parse(id.as_str()), Some(id.clone()));
        assert_ne!(TeamId::generate().unwrap(), id);
        for bad in [
            "",
            "t_",
            "t_abcdefghi",
            "t_abcdefghijk",
            "t_ABCDEFGHIJ",
            "t_abcdefgh01",
            "x_abcdefghij",
        ] {
            assert_eq!(TeamId::parse(bad), None, "{bad}");
        }
        assert!(TeamId::parse("t_ab2cd7efgh").is_some());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<TeamId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<TeamId>("\"t_bad\"").is_err());
    }

    #[test]
    fn ids_are_plain_numbers_on_the_wire() {
        assert_eq!(serde_json::to_string(&RunId(7)).unwrap(), "7");
        let id: ItemId = serde_json::from_str("42").unwrap();
        assert_eq!(id, ItemId(42));
        assert_eq!("9".parse::<MemberId>().unwrap(), MemberId(9));
        assert_eq!(AgentId(3).to_string(), "3");
    }
}
