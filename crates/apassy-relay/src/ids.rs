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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_plain_numbers_on_the_wire() {
        assert_eq!(serde_json::to_string(&RunId(7)).unwrap(), "7");
        let id: ItemId = serde_json::from_str("42").unwrap();
        assert_eq!(id, ItemId(42));
        assert_eq!("9".parse::<MemberId>().unwrap(), MemberId(9));
        assert_eq!(AgentId(3).to_string(), "3");
    }
}
