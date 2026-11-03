//! Who hosts and who trains the bouncer brain (ADR 0035, plan 0035 unit C2). The table
//! is in `schema29.rs`.
//!
//! The choice lives in the vault, not in `bouncer.json`: any process of the user can
//! write `bouncer.json`, so a remote address there would bypass the owner check. Each
//! role has at most one row. No row is "this Mac" (the default, as before). A row names
//! the owner's own server, with its bearer token, or Apassy Connect, whose device key
//! signs in (no bearer here).
//!
//! The vault checks only the form of a change. The proof of the fresh owner check is
//! checked by the caller in the broker (`crate::broker::brain_host::change`) just before
//! it calls [`Vault::set_bouncer_host`] with the vault held, as for a model promotion.
//! Each change goes to the activity log in the same transaction. The bearer never goes
//! to the activity log, to `Debug` output or to a pushed copy.

use rusqlite::{OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use super::Vault;
use super::agents::{
    ActivityDecision, MAX_ACTIVITY_REASON_BYTES, MAX_ACTIVITY_ROWS, from_sql_time, to_sql_time,
};
use super::types::{SecretValue, VaultErrorKind, VaultResult, err};

/// The version of the consent screen (ADR 0035 sections 1, 4 and 5) that this build
/// shows. A row records the version that the owner accepted.
pub const HOSTING_CONSENT_VERSION: u32 = 1;
/// The longest host address.
pub const MAX_HOST_URL_BYTES: usize = 200;
/// The shortest bearer token of an own server.
pub const MIN_BEARER_BYTES: usize = 16;
/// The longest bearer token of an own server.
pub const MAX_BEARER_BYTES: usize = 512;
/// The bytes of a bearer token that the app generates (shown once, then in the vault).
pub const GENERATED_BEARER_BYTES: usize = 32;
/// The image of the self-host server (plan 0035 unit E2), tagged with the shared
/// release version.
pub const BRAIN_IMAGE: &str = "ghcr.io/wydrox/apassy-brain";

/// The two choices of ADR 0035 section 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BouncerHostRole {
    /// Who answers the bouncer requests (inference).
    Hosting,
    /// Who runs the fine-tune of the decision heads.
    Training,
}

impl BouncerHostRole {
    pub const ALL: [Self; 2] = [Self::Hosting, Self::Training];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hosting => "hosting",
            Self::Training => "training",
        }
    }
}

/// Where the bouncer brain runs, or where it trains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum BouncerHostKind {
    /// This Mac: no row in the vault.
    #[default]
    ThisMac,
    /// A server of the owner, for example on the owner's tailnet, over `https://` with a
    /// bearer token.
    OwnServer,
    /// The bouncer brain service of Apassy Connect (paid).
    Connect,
}

impl BouncerHostKind {
    pub const ALL: [Self; 3] = [Self::ThisMac, Self::OwnServer, Self::Connect];

    /// The value of `bouncer_host.kind`. `None`: this Mac has no row.
    pub fn db_value(self) -> Option<&'static str> {
        match self {
            Self::ThisMac => None,
            Self::OwnServer => Some("own_server"),
            Self::Connect => Some("connect"),
        }
    }

    fn from_db(text: &str) -> VaultResult<Self> {
        match text {
            "own_server" => Ok(Self::OwnServer),
            "connect" => Ok(Self::Connect),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }

    /// The label in Settings.
    pub fn label(self) -> &'static str {
        match self {
            Self::ThisMac => "This Mac",
            Self::OwnServer => "My server",
            Self::Connect => "Apassy Connect",
        }
    }
}

/// One stored choice, without its bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BouncerHost {
    pub role: BouncerHostRole,
    /// [`BouncerHostKind::OwnServer`] or [`BouncerHostKind::Connect`].
    pub kind: BouncerHostKind,
    /// The `https://` origin of the server.
    pub url: String,
    /// The row has a bearer token ([`Vault::bouncer_host_bearer`]).
    pub has_bearer: bool,
    /// The consent screen that the owner accepted.
    pub consent_version: u32,
    pub consented_at: u64,
    pub updated_at: u64,
}

/// A change of one choice, as the owner confirmed it. `Debug` hides the bearer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BouncerHostChange {
    pub kind: BouncerHostKind,
    /// The `https://` origin. Empty for [`BouncerHostKind::ThisMac`].
    pub url: String,
    /// The bearer token of an own server. `None` for this Mac and for Connect.
    pub bearer: Option<SecretValue>,
    /// The consent screen that the owner accepted. 0 for this Mac.
    pub consent_version: u32,
}

impl BouncerHostChange {
    /// The return to this Mac.
    pub fn this_mac() -> Self {
        Self {
            kind: BouncerHostKind::ThisMac,
            url: String::new(),
            bearer: None,
            consent_version: 0,
        }
    }

    /// The address as the vault stores it: trimmed, without a trailing `/`.
    pub fn normalized_url(&self) -> String {
        normalize_url(&self.url)
    }
}

/// `url` trimmed, without a trailing `/`.
pub fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_owned()
}

/// A host address: `https://`, a host, an optional port and path, printable ASCII, no
/// user info, no query, no fragment, at most [`MAX_HOST_URL_BYTES`]. The client of the
/// broker checks the address again when it connects (`BouncerClient::remote`).
pub fn valid_host_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    let name = host.rsplit_once(':').map_or(host, |(name, _)| name);
    url.len() <= MAX_HOST_URL_BYTES
        && !name.is_empty()
        && url.bytes().all(|b| b.is_ascii_graphic())
        && !url.contains(['@', '?', '#', '\\'])
}

/// A bearer token of an own server: [`MIN_BEARER_BYTES`] to [`MAX_BEARER_BYTES`] of
/// printable ASCII without a space, so it fits an `Authorization` header as it is.
pub fn valid_bearer(bearer: &str) -> bool {
    (MIN_BEARER_BYTES..=MAX_BEARER_BYTES).contains(&bearer.len())
        && bearer.bytes().all(|b| b.is_ascii_graphic())
}

/// A new bearer token for an own server: [`GENERATED_BEARER_BYTES`] random bytes as
/// lowercase hex. The app shows it once with [`docker_run_line`]; then it is only in the
/// vault.
pub fn generate_bearer() -> VaultResult<SecretValue> {
    let mut bytes = Zeroizing::new([0u8; GENERATED_BEARER_BYTES]);
    getrandom::fill(&mut bytes[..]).map_err(|_| err(VaultErrorKind::Io))?;
    let mut text = String::with_capacity(GENERATED_BEARER_BYTES * 2);
    for byte in bytes.iter() {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    Ok(SecretValue::new(text))
}

/// The command that starts the self-host server with `bearer` (ADR 0035 section 2,
/// `docs/operations/bouncer-hosting.md`). It has the token, so it erases itself on drop.
pub fn docker_run_line(bearer: &SecretValue) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "docker run -d --name apassy-brain -p 8770:8770 -e LAYA_API_KEY={} {BRAIN_IMAGE}:{}",
        bearer.expose(),
        env!("CARGO_PKG_VERSION")
    ))
}

/// The check of a change, before any write.
fn check_change(change: &BouncerHostChange) -> VaultResult<()> {
    let url = change.normalized_url();
    let consent = (1..=HOSTING_CONSENT_VERSION).contains(&change.consent_version);
    let ok = match change.kind {
        BouncerHostKind::ThisMac => {
            url.is_empty() && change.bearer.is_none() && change.consent_version == 0
        }
        BouncerHostKind::OwnServer => {
            consent
                && valid_host_url(&url)
                && change
                    .bearer
                    .as_ref()
                    .is_some_and(|bearer| valid_bearer(bearer.expose()))
        }
        BouncerHostKind::Connect => consent && valid_host_url(&url) && change.bearer.is_none(),
    };
    if ok {
        Ok(())
    } else {
        Err(err(VaultErrorKind::InvalidInput))
    }
}

/// The words of the activity entry. No bearer.
fn activity_text(role: BouncerHostRole, change: &BouncerHostChange) -> (&'static str, String) {
    let operation = match role {
        BouncerHostRole::Hosting => "change bouncer brain host",
        BouncerHostRole::Training => "change bouncer brain trainer",
    };
    let reason = match change.kind {
        BouncerHostKind::ThisMac => "This Mac.".to_owned(),
        BouncerHostKind::OwnServer => format!("My server at {}.", change.normalized_url()),
        BouncerHostKind::Connect => format!("Apassy Connect at {}.", change.normalized_url()),
    };
    let mut reason = reason;
    if reason.len() > MAX_ACTIVITY_REASON_BYTES {
        let mut end = MAX_ACTIVITY_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
    }
    (operation, reason)
}

fn storage<E>(_: E) -> super::types::VaultError {
    err(VaultErrorKind::Storage)
}

impl Vault {
    /// The stored choice of `role`. `None`: this Mac.
    pub fn bouncer_host(&self, role: BouncerHostRole) -> VaultResult<Option<BouncerHost>> {
        let conn = self.conn_ref()?;
        let row: Option<(String, String, bool, i64, i64, i64)> = conn
            .query_row(
                "SELECT kind, url, bearer IS NOT NULL, consent_version, consented_at, updated_at
                 FROM bouncer_host WHERE role = ?1",
                [role.as_str()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        let Some((kind, url, has_bearer, consent, consented_at, updated_at)) = row else {
            return Ok(None);
        };
        Ok(Some(BouncerHost {
            role,
            kind: BouncerHostKind::from_db(&kind)?,
            url,
            has_bearer,
            consent_version: u32::try_from(consent).map_err(storage)?,
            consented_at: from_sql_time(consented_at)?,
            updated_at: from_sql_time(updated_at)?,
        }))
    }

    /// The bearer token of the own server of `role`. `None`: no row, or a row without a
    /// token (Connect). A stored token that is not valid text is `Storage`.
    pub fn bouncer_host_bearer(&self, role: BouncerHostRole) -> VaultResult<Option<SecretValue>> {
        let conn = self.conn_ref()?;
        let bytes: Option<Option<Vec<u8>>> = conn
            .query_row(
                "SELECT bearer FROM bouncer_host WHERE role = ?1",
                [role.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let Some(bytes) = bytes.flatten() else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        let text = std::str::from_utf8(&bytes).map_err(storage)?;
        Ok(Some(SecretValue::new(text.to_owned())))
    }

    /// Store the choice `change` for `role` at `now`, with its activity entry, in one
    /// transaction. [`BouncerHostKind::ThisMac`] removes the row. The caller has checked
    /// the fresh owner proof for exactly this change.
    ///
    /// `InvalidInput`: this Mac with an address, a bearer or a consent version; an own
    /// server without a valid `https://` address or bearer; Connect with a bearer or
    /// without a valid address; a consent version that this build does not know.
    pub fn set_bouncer_host(
        &mut self,
        role: BouncerHostRole,
        change: &BouncerHostChange,
        now: u64,
    ) -> VaultResult<()> {
        check_change(change)?;
        let at = to_sql_time(now)?;
        let url = change.normalized_url();
        let (operation, reason) = activity_text(role, change);
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        match change.kind.db_value() {
            None => {
                tx.execute("DELETE FROM bouncer_host WHERE role = ?1", [role.as_str()])
                    .map_err(storage)?;
            }
            Some(kind) => {
                let bearer: Option<Zeroizing<Vec<u8>>> = change
                    .bearer
                    .as_ref()
                    .map(|bearer| Zeroizing::new(bearer.expose().as_bytes().to_vec()));
                tx.execute(
                    "INSERT INTO bouncer_host
                         (role, kind, url, bearer, consent_version, consented_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                     ON CONFLICT(role) DO UPDATE SET kind = excluded.kind, url = excluded.url,
                         bearer = excluded.bearer, consent_version = excluded.consent_version,
                         consented_at = excluded.consented_at, updated_at = excluded.updated_at",
                    rusqlite::params![
                        role.as_str(),
                        kind,
                        url,
                        bearer.as_ref().map(|bytes| bytes.as_slice()),
                        i64::from(change.consent_version),
                        at,
                    ],
                )
                .map_err(storage)?;
            }
        }
        tx.execute(
            "INSERT INTO activity (at, agent_id, agent_name, item_id, operation, decision, reason)
             VALUES (?1, NULL, 'Owner', NULL, ?2, ?3, ?4)",
            rusqlite::params![at, operation, ActivityDecision::Allow.as_str(), reason],
        )
        .map_err(storage)?;
        tx.execute(
            "DELETE FROM activity WHERE id NOT IN
             (SELECT id FROM activity ORDER BY id DESC LIMIT ?1)",
            [i64::try_from(MAX_ACTIVITY_ROWS).map_err(storage)?],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "synthetic-bouncer-host-pass";
    const BEARER: &str = "SYNTH-bearer-host-0123456789abcdef";

    fn vault(dir: &tempfile::TempDir) -> Vault {
        let mut vault = Vault::create(&dir.path().join("v.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
    }

    fn own(url: &str, bearer: &str) -> BouncerHostChange {
        BouncerHostChange {
            kind: BouncerHostKind::OwnServer,
            url: url.to_owned(),
            bearer: Some(SecretValue::new(bearer.to_owned())),
            consent_version: HOSTING_CONSENT_VERSION,
        }
    }

    #[test]
    fn a_choice_is_stored_read_and_removed_for_each_role() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let change = own("https://brain.synthetic.ts.net/", BEARER);
        vault
            .set_bouncer_host(BouncerHostRole::Hosting, &change, 1_700_000_100)
            .unwrap();
        let host = vault
            .bouncer_host(BouncerHostRole::Hosting)
            .unwrap()
            .unwrap();
        assert_eq!(
            host,
            BouncerHost {
                role: BouncerHostRole::Hosting,
                kind: BouncerHostKind::OwnServer,
                url: "https://brain.synthetic.ts.net".to_owned(),
                has_bearer: true,
                consent_version: HOSTING_CONSENT_VERSION,
                consented_at: 1_700_000_100,
                updated_at: 1_700_000_100,
            }
        );
        assert_eq!(
            vault
                .bouncer_host_bearer(BouncerHostRole::Hosting)
                .unwrap()
                .unwrap()
                .expose(),
            BEARER
        );
        assert_eq!(vault.bouncer_host(BouncerHostRole::Training).unwrap(), None);

        let connect = BouncerHostChange {
            kind: BouncerHostKind::Connect,
            url: "https://brain.connect.example".to_owned(),
            bearer: None,
            consent_version: HOSTING_CONSENT_VERSION,
        };
        vault
            .set_bouncer_host(BouncerHostRole::Training, &connect, 1_700_000_200)
            .unwrap();
        let training = vault
            .bouncer_host(BouncerHostRole::Training)
            .unwrap()
            .unwrap();
        assert_eq!(training.kind, BouncerHostKind::Connect);
        assert!(!training.has_bearer);
        assert!(
            vault
                .bouncer_host_bearer(BouncerHostRole::Training)
                .unwrap()
                .is_none()
        );

        // A new choice replaces the row; this Mac removes it.
        vault
            .set_bouncer_host(
                BouncerHostRole::Hosting,
                &own("https://other.synthetic.ts.net:8443", BEARER),
                1_700_000_300,
            )
            .unwrap();
        assert_eq!(
            vault
                .bouncer_host(BouncerHostRole::Hosting)
                .unwrap()
                .unwrap()
                .url,
            "https://other.synthetic.ts.net:8443"
        );
        vault
            .set_bouncer_host(
                BouncerHostRole::Hosting,
                &BouncerHostChange::this_mac(),
                1_700_000_400,
            )
            .unwrap();
        assert_eq!(vault.bouncer_host(BouncerHostRole::Hosting).unwrap(), None);
        assert!(
            vault
                .bouncer_host_bearer(BouncerHostRole::Hosting)
                .unwrap()
                .is_none()
        );
        assert!(
            vault
                .bouncer_host(BouncerHostRole::Training)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_change_of_the_wrong_form_is_refused_and_changes_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        let mut no_consent = own("https://brain.synthetic.ts.net", BEARER);
        no_consent.consent_version = 0;
        let mut future_consent = own("https://brain.synthetic.ts.net", BEARER);
        future_consent.consent_version = HOSTING_CONSENT_VERSION + 1;
        let mut mac_with_url = BouncerHostChange::this_mac();
        mac_with_url.url = "https://brain.synthetic.ts.net".to_owned();
        let connect_with_bearer = BouncerHostChange {
            kind: BouncerHostKind::Connect,
            url: "https://brain.connect.example".to_owned(),
            bearer: Some(SecretValue::new(BEARER.to_owned())),
            consent_version: HOSTING_CONSENT_VERSION,
        };
        let own_without_bearer = BouncerHostChange {
            bearer: None,
            ..own("https://brain.synthetic.ts.net", BEARER)
        };
        for bad in [
            own("http://brain.synthetic.ts.net", BEARER),
            own("http://127.0.0.1:8770", BEARER),
            own("https://", BEARER),
            own("https://user@brain.synthetic.ts.net", BEARER),
            own("https://brain.synthetic.ts.net/?x=1", BEARER),
            own("https://brain synthetic.ts.net", BEARER),
            own(
                &format!("https://{}.ts.net", "a".repeat(MAX_HOST_URL_BYTES)),
                BEARER,
            ),
            own("https://brain.synthetic.ts.net", "short"),
            own("https://brain.synthetic.ts.net", "with a space 0123456789"),
            own(
                "https://brain.synthetic.ts.net",
                &"x".repeat(MAX_BEARER_BYTES + 1),
            ),
            own_without_bearer,
            no_consent,
            future_consent,
            mac_with_url,
            connect_with_bearer,
        ] {
            let text = format!("{bad:?}");
            assert!(!text.contains(BEARER), "Debug hides the bearer: {text}");
            assert_eq!(
                vault
                    .set_bouncer_host(BouncerHostRole::Hosting, &bad, 1)
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::InvalidInput,
                "{text}"
            );
        }
        assert_eq!(vault.bouncer_host(BouncerHostRole::Hosting).unwrap(), None);
    }

    #[test]
    fn each_change_is_in_the_activity_log_without_the_bearer() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        vault
            .set_bouncer_host(
                BouncerHostRole::Hosting,
                &own("https://brain.synthetic.ts.net", BEARER),
                1_700_000_100,
            )
            .unwrap();
        vault
            .set_bouncer_host(
                BouncerHostRole::Hosting,
                &BouncerHostChange::this_mac(),
                1_700_000_200,
            )
            .unwrap();
        let rows: Vec<(String, String)> = vault
            .conn_ref()
            .unwrap()
            .prepare(
                "SELECT operation, reason FROM activity
                 WHERE operation LIKE 'change bouncer brain%' ORDER BY id",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            [
                (
                    "change bouncer brain host".to_owned(),
                    "My server at https://brain.synthetic.ts.net.".to_owned()
                ),
                (
                    "change bouncer brain host".to_owned(),
                    "This Mac.".to_owned()
                ),
            ]
        );
        assert!(rows.iter().all(|(_, reason)| !reason.contains(BEARER)));
    }

    #[test]
    fn a_generated_bearer_is_new_hex_and_valid() {
        let one = generate_bearer().unwrap();
        let two = generate_bearer().unwrap();
        assert_ne!(one, two);
        assert_eq!(one.expose().len(), GENERATED_BEARER_BYTES * 2);
        assert!(one.expose().bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(valid_bearer(one.expose()));
        let line = docker_run_line(&one);
        assert!(line.contains(&format!("-e LAYA_API_KEY={} ", one.expose())));
        assert!(line.ends_with(&format!("{BRAIN_IMAGE}:{}", env!("CARGO_PKG_VERSION"))));
        assert!(!format!("{one:?}").contains(one.expose()));
    }

    #[test]
    fn a_locked_vault_reads_and_writes_no_choice() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = vault(&dir);
        vault.lock().unwrap();
        assert_eq!(
            vault
                .bouncer_host(BouncerHostRole::Hosting)
                .unwrap_err()
                .kind(),
            VaultErrorKind::Locked
        );
        assert_eq!(
            vault
                .set_bouncer_host(
                    BouncerHostRole::Hosting,
                    &own("https://brain.synthetic.ts.net", BEARER),
                    1
                )
                .unwrap_err()
                .kind(),
            VaultErrorKind::Locked
        );
    }
}
