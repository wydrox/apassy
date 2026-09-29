//! The edge secret and the bearer tokens (docs/SPEC.md, "Auth model").

use rusqlite::{Connection, OptionalExtension, params};

use crate::api::Role;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{AgentId, MemberId};
use crate::secret::{SecretString, TokenKind, same_bytes, token_hash};
use crate::server::store::{db, to_i, to_u};

/// A member, an owner, or a manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberAuth {
    pub id: MemberId,
    pub name: String,
    pub role: Role,
}

/// An agent and the member it acts for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAuth {
    pub id: AgentId,
    pub name: String,
    pub member: MemberAuth,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    Member(MemberAuth),
    Agent(AgentAuth),
}

/// The token in an `Authorization: Bearer <token>` header value.
pub fn bearer(header: Option<&str>) -> Option<&str> {
    let value = header?.trim();
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

/// True when the header holds the edge secret.
pub fn edge_ok(secret: &SecretString, header: Option<&str>) -> bool {
    header.is_some_and(|value| same_bytes(value.as_bytes(), secret.expose().as_bytes()))
}

/// Parses a stored role.
pub fn parse_role(text: &str) -> Role {
    match text {
        "owner" => Role::Owner,
        "manager" => Role::Manager,
        _ => Role::Member,
    }
}

pub fn role_text(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Manager => "manager",
        Role::Member => "member",
    }
}

/// Looks the token up by its hash. A missing, wrong-kind, unknown, or revoked token
/// is `unauthenticated`; an expired agent token is `token_expired`.
pub fn authenticate(conn: &Connection, token: &str, now: u64) -> RelayResult<Principal> {
    let hash = token_hash(token);
    match TokenKind::of(token) {
        Some(TokenKind::Member) => {
            let member = conn
                .query_row(
                    "SELECT id, name, role FROM member WHERE token_hash = ?1 AND revoked_at IS NULL",
                    params![hash.0.as_slice()],
                    |row| {
                        Ok(MemberAuth {
                            id: MemberId(to_u(row.get(0)?)),
                            name: row.get(1)?,
                            role: parse_role(&row.get::<_, String>(2)?),
                        })
                    },
                )
                .optional()
                .map_err(db)?
                .ok_or_else(RelayError::unauthenticated)?;
            Ok(Principal::Member(member))
        }
        Some(TokenKind::Agent) => {
            let agent = conn
                .query_row(
                    "SELECT a.id FROM agent a JOIN member m ON m.id = a.member_id \
                     WHERE a.token_hash = ?1 AND a.revoked_at IS NULL AND m.revoked_at IS NULL",
                    params![hash.0.as_slice()],
                    |row| Ok(AgentId(to_u(row.get(0)?))),
                )
                .optional()
                .map_err(db)?
                .ok_or_else(RelayError::unauthenticated)?;
            let agent = agent_by_id(conn, agent, now)?;
            Ok(Principal::Agent(agent))
        }
        _ => Err(RelayError::unauthenticated()),
    }
}

/// A live agent by id: not revoked, member not revoked, not expired.
pub fn agent_by_id(conn: &Connection, id: AgentId, now: u64) -> RelayResult<AgentAuth> {
    let row = conn
        .query_row(
            "SELECT a.name, a.expires_at, m.id, m.name, m.role FROM agent a \
             JOIN member m ON m.id = a.member_id \
             WHERE a.id = ?1 AND a.revoked_at IS NULL AND m.revoked_at IS NULL",
            params![to_i(id.0)],
            |row| {
                Ok(AgentAuth {
                    id,
                    name: row.get(0)?,
                    expires_at: to_u(row.get(1)?),
                    member: MemberAuth {
                        id: MemberId(to_u(row.get(2)?)),
                        name: row.get(3)?,
                        role: parse_role(&row.get::<_, String>(4)?),
                    },
                })
            },
        )
        .optional()
        .map_err(db)?
        .ok_or_else(RelayError::unauthenticated)?;
    if now >= row.expires_at {
        return Err(RelayError::new(
            codes::TOKEN_EXPIRED,
            "The agent token expired. Ask its member for a new one.",
        ));
    }
    Ok(row)
}

impl Principal {
    pub fn member(&self) -> &MemberAuth {
        match self {
            Self::Member(member) => member,
            Self::Agent(agent) => &agent.member,
        }
    }
}

/// What an endpoint needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// The edge secret only.
    Edge,
    /// A member token (any role).
    Member,
    /// A member token with role owner or manager.
    Approver,
    /// The owner token.
    Owner,
    /// An agent token.
    Agent,
    /// A member or an agent token.
    Any,
}

/// Checks a principal against a need.
pub fn allow(need: Need, principal: Option<&Principal>) -> RelayResult<()> {
    let wrong_kind = RelayError::unauthenticated;
    match (need, principal) {
        (Need::Edge, _) => Ok(()),
        (_, None) => Err(RelayError::unauthenticated()),
        (Need::Any, Some(_)) => Ok(()),
        (Need::Agent, Some(Principal::Agent(_))) => Ok(()),
        (Need::Agent, Some(Principal::Member(_))) => Err(wrong_kind()),
        (_, Some(Principal::Agent(_))) => Err(wrong_kind()),
        (Need::Member, Some(Principal::Member(_))) => Ok(()),
        (Need::Approver, Some(Principal::Member(m))) => {
            if m.role.is_approver() {
                Ok(())
            } else {
                Err(RelayError::forbidden(
                    "Only the owner or a manager can do this.",
                ))
            }
        }
        (Need::Owner, Some(Principal::Member(m))) => {
            if m.role == Role::Owner {
                Ok(())
            } else {
                Err(RelayError::forbidden("Only the owner can do this."))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parsing() {
        assert_eq!(bearer(Some("Bearer abc")), Some("abc"));
        assert_eq!(bearer(Some("bearer  abc ")), Some("abc"));
        assert_eq!(bearer(Some("Basic abc")), None);
        assert_eq!(bearer(Some("Bearer ")), None);
        assert_eq!(bearer(None), None);
    }

    #[test]
    fn edge_compare() {
        let secret = SecretString::new("x".repeat(40));
        assert!(edge_ok(&secret, Some(&"x".repeat(40))));
        assert!(!edge_ok(&secret, Some(&"x".repeat(39))));
        assert!(!edge_ok(&secret, None));
    }

    fn member(role: Role) -> Principal {
        Principal::Member(MemberAuth {
            id: MemberId(1),
            name: "a".into(),
            role,
        })
    }

    #[test]
    fn need_matrix() {
        assert!(allow(Need::Owner, Some(&member(Role::Owner))).is_ok());
        assert_eq!(
            allow(Need::Owner, Some(&member(Role::Manager)))
                .unwrap_err()
                .code,
            codes::FORBIDDEN
        );
        assert!(allow(Need::Approver, Some(&member(Role::Manager))).is_ok());
        assert_eq!(
            allow(Need::Approver, Some(&member(Role::Member)))
                .unwrap_err()
                .code,
            codes::FORBIDDEN
        );
        assert_eq!(
            allow(Need::Agent, Some(&member(Role::Owner)))
                .unwrap_err()
                .code,
            codes::UNAUTHENTICATED
        );
        assert_eq!(
            allow(Need::Member, None).unwrap_err().code,
            codes::UNAUTHENTICATED
        );
        assert!(allow(Need::Edge, None).is_ok());
        assert!(allow(Need::Any, Some(&member(Role::Member))).is_ok());
    }
}
