//! The Apple Watch (ADR 0039; contract ios-core-v1 section 5.13). A child of questions,
//! so the contexts and the checks of the access requests stay shared.
//!
//! The watch answers access requests only. It holds one questions-only replica vault:
//! no item, the sync identity of the vault it answers for, its questions membership,
//! the question key, and the public `trusted_device` rows of the ADR 0032 handoff. It
//! never syncs, so the rows change only with a new connection.
//!
//! The watch connects with a Connect code of a Mac that the iPhone forwards: a handoff
//! link only (`&handoff=`). It joins the questions team with a new relay key, and sends
//! its answer key in the link name after the watch marker (`<name> ~W<key>`,
//! `apassy::questions::device_link`). After the owner confirms on the Mac, the Mac sends
//! the handoff. The watch then makes a new vault file with the passphrase of the app,
//! gives it the identity of the vault (`Vault::adopt_replica_identity`), adopts the
//! handoff, and opens it. Any failure removes the new file, and the device leaves the
//! team again.

use super::*;
use apassy::questions::QuestionsClient;
use apassy::questions::device_link::watch_link_device_name;
use apassy::relay::pairing::{Handoff, PairingChannel};
use apassy::sync::{DeviceKey, JoinedDevice};

use super::super::config::{VaultEntry, valid_id};
use super::super::{Closing, sidecar, truncate};

/// The name of the replica vault when the handoff names no Mac.
const DEFAULT_VAULT_NAME: &str = "Vault";

/// A connection of the watch that waits for the Mac. The passphrase of the new vault
/// stays only until the poll that makes it, and is erased on drop.
pub(super) struct Connecting {
    pending: PendingJoin,
    channel: PairingChannel,
    /// The answer key, X9.63 (65 bytes).
    answer_key: Vec<u8>,
    /// The relay device name, with the watch marker and the answer key.
    device_name: String,
    passphrase: Zeroizing<String>,
    words: Vec<String>,
    expires_at: u64,
}

impl Connecting {
    fn view(&self) -> Waiting {
        Waiting {
            state: "waiting",
            words: self.words.clone(),
            expires_at: self.expires_at,
        }
    }

    /// Give the join up on the relay, best effort.
    pub(super) fn cancel(self) {
        let _ = self.pending.cancel();
    }
}

#[derive(Serialize)]
struct Waiting {
    state: &'static str,
    words: Vec<String>,
    expires_at: u64,
}

#[derive(Serialize)]
struct VaultView {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct Attached {
    state: &'static str,
    vault: VaultView,
}

#[derive(Serialize)]
struct OwnView {
    /// The vault holds the row of this watch.
    found: bool,
    /// The row is of kind `watch`, holds an answer key other than its relay key, and,
    /// when the call named one, that answer key.
    answer_key_matches: bool,
}

#[derive(Serialize)]
struct StatusView {
    /// `unpaired`, `connecting`, `locked`, `ready`, or `removed`.
    state: &'static str,
    vault: Option<VaultView>,
    /// The names of the live Mac rows of the replica.
    macs: Vec<String>,
    /// Only while the replica is unlocked.
    own: Option<OwnView>,
}

impl StatusView {
    fn of(state: &'static str, vault: Option<VaultView>) -> Self {
        Self {
            state,
            vault,
            macs: Vec::new(),
            own: None,
        }
    }
}

fn plain_link() -> CoreError {
    CoreError::new(
        "link_invalid",
        "This code can't connect a watch. Make a new code on the Mac.",
    )
}

fn damaged_link() -> CoreError {
    CoreError::new(
        "link_invalid",
        "This pairing code is damaged. Make a new code on the Mac.",
    )
}

fn connected_already() -> CoreError {
    CoreError::new(
        "already_connected",
        "This watch is connected to a vault already. Forget it first.",
    )
}

fn mac_update_needed() -> CoreError {
    CoreError::new(
        "mac_update_needed",
        "Update Apassy on your Mac to connect this watch.",
    )
}

fn bad_answer_key() -> CoreError {
    CoreError::invalid("The answer key is not a P-256 public key.")
}

/// An answer key in b64u X9.63 form (65 bytes).
fn answer_key_of(text: &str) -> CoreResult<Vec<u8>> {
    decode_b64u(text)
        .filter(|key| key.len() == 65 && key[0] == 0x04)
        .ok_or_else(bad_answer_key)
}

/// The row of this watch in the handoff: the row with its relay key `sign_key`. A row
/// without an answer key is of a Mac that does not know the watch marker; a row of
/// another kind or with another answer key cannot answer here.
fn check_own_row(handoff: &Handoff, sign_key: &[u8], answer_key: &[u8]) -> CoreResult<()> {
    let own = handoff
        .devices
        .iter()
        .find(|device| device.sign_key == sign_key)
        .ok_or_else(mac_update_needed)?;
    match own.answer_key.as_deref() {
        None => Err(mac_update_needed()),
        Some(key) if key != answer_key || own.kind != TrustedDeviceKind::Watch => {
            Err(answer_key_changed_for(Role::Watch))
        }
        Some(_) => Ok(()),
    }
}

/// The name of the replica: the name of a live Mac row of the handoff, else "Vault".
fn vault_name(handoff: &Handoff) -> String {
    handoff
        .devices
        .iter()
        .filter(|device| device.kind == TrustedDeviceKind::Mac)
        .map(|device| truncate(device.name.trim(), SHOWN_NAME))
        .find(|name| !name.is_empty())
        .unwrap_or_else(|| DEFAULT_VAULT_NAME.to_owned())
}

impl Core {
    pub(crate) fn watch_call(&self, op: &str, request: &str) -> CoreResult<String> {
        match op {
            "watch_connect_start" => {
                #[derive(Deserialize)]
                struct Start {
                    link: Secret,
                    #[serde(default)]
                    name: Option<String>,
                    /// b64u, X9.63: the Secure Enclave answer key of this watch.
                    answer_key: String,
                    passphrase: Secret,
                }
                let Start {
                    link,
                    name,
                    answer_key,
                    passphrase,
                } = params(request)?;
                Ok(ok(&self.watch_connect_start(
                    link.expose(),
                    name.as_deref(),
                    &answer_key,
                    passphrase.into_inner(),
                )?))
            }
            "watch_connect_poll" => self.watch_connect_poll(),
            "watch_connect_cancel" => {
                let connecting = guard(&self.questions).watch_connect.take();
                if let Some(connecting) = connecting {
                    connecting.cancel();
                }
                Ok(ok(&Empty {}))
            }
            "watch_status" => {
                #[derive(Deserialize)]
                struct Status {
                    #[serde(default)]
                    answer_key: Option<String>,
                }
                let Status { answer_key } = params(request)?;
                Ok(ok(&self.watch_status(answer_key.as_deref())?))
            }
            "watch_forget" => self.watch_forget(),
            _ => Err(CoreError::invalid("This call is not known.")),
        }
    }

    /// `watch_connect_start`: register the link with a new relay key and the watch name.
    fn watch_connect_start(
        &self,
        link: &str,
        name: Option<&str>,
        answer_key: &str,
        passphrase: Zeroizing<String>,
    ) -> CoreResult<Waiting> {
        if !guard(&self.list).vaults.is_empty() {
            return Err(connected_already());
        }
        if passphrase.len() < apassy::vault::MIN_PASSPHRASE_BYTES {
            return Err(CoreError::invalid(format!(
                "The passphrase needs at least {} characters.",
                apassy::vault::MIN_PASSPHRASE_BYTES
            )));
        }
        let answer_key = answer_key_of(answer_key)?;
        let name = name
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(&self.device_name);
        let device_name = watch_link_device_name(name, &answer_key).ok_or_else(bad_answer_key)?;
        let channel = match PairingChannel::parse(link) {
            Some((_, channel)) => channel,
            None if link.contains("&handoff=") => return Err(damaged_link()),
            None => return Err(plain_link()),
        };
        let previous = guard(&self.questions).watch_connect.take();
        if let Some(previous) = previous {
            previous.cancel();
        }
        let pending =
            PendingJoin::request(link, DEFAULT_RELAY_URL, &device_name).map_err(join_link_error)?;
        let connecting = Connecting {
            words: pending
                .safety
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            expires_at: pending.expires_at,
            pending,
            channel,
            answer_key,
            device_name,
            passphrase,
        };
        let view = connecting.view();
        let replaced = guard(&self.questions).watch_connect.replace(connecting);
        if let Some(replaced) = replaced {
            replaced.cancel();
        }
        Ok(view)
    }

    /// Keep `connecting` for the next poll, unless a lock or a new connection came since
    /// the poll took it out (`drops`): then it is given up.
    fn watch_connect_keep(&self, connecting: Connecting, drops: u64) {
        let mut state = guard(&self.questions);
        if state.drops == drops && state.watch_connect.is_none() {
            state.watch_connect = Some(connecting);
        } else {
            drop(state);
            connecting.cancel();
        }
    }

    /// `watch_connect_poll`: `waiting`, or `attached` once the handoff came and the
    /// replica vault is open. The relay calls run with the connection taken out, as
    /// `join_attach_poll` does.
    fn watch_connect_poll(&self) -> CoreResult<String> {
        let (connecting, drops) = {
            let mut state = guard(&self.questions);
            let connecting = state.watch_connect.take().ok_or_else(|| {
                CoreError::invalid("No connection waits. Send the code from the iPhone again.")
            })?;
            (connecting, state.drops)
        };
        if connecting.expires_at <= now() {
            connecting.cancel();
            return Err(CoreError::new(
                "link_invalid",
                "This pairing code expired. Make a new code in Settings > Devices on the Mac.",
            ));
        }
        let joined = match connecting.pending.poll() {
            Ok(None) => {
                let view = connecting.view();
                self.watch_connect_keep(connecting, drops);
                return Ok(ok(&view));
            }
            Ok(Some(joined)) => joined,
            Err(error) => {
                let error = CoreError::from(error);
                if matches!(error.code, "join_refused" | "link_invalid") {
                    connecting.cancel();
                } else {
                    self.watch_connect_keep(connecting, drops);
                }
                return Err(error);
            }
        };
        let key_pkcs8 = joined
            .key_pkcs8()
            .ok_or_else(|| CoreError::internal("The device key is missing."))?;
        let received = connecting.channel.receive(
            &QuestionsClient::from_member(joined.member()),
            joined.member().team_id(),
            &DeviceKey::from_pkcs8(key_pkcs8)?,
            &connecting.device_name,
        );
        let handoff = match received {
            Ok(Some(handoff)) => handoff,
            Ok(None) => {
                let view = connecting.view();
                self.watch_connect_keep(connecting, drops);
                return Ok(ok(&view));
            }
            Err(_) => {
                self.watch_connect_keep(connecting, drops);
                return Err(CoreError::new(
                    "relay_unreachable",
                    "Waiting for the Mac to transfer the connection keys. Check the connection of this watch and keep the pairing screen open on the Mac.",
                ));
            }
        };
        match self.watch_adopt(&connecting, &joined, &handoff) {
            Ok(entry) => Ok(ok(&Attached {
                state: "attached",
                vault: VaultView {
                    id: entry.id,
                    name: entry.name,
                },
            })),
            Err(error) => {
                // The watch holds no key of the team: the device leaves it again.
                joined.cancel();
                Err(error)
            }
        }
    }

    /// Make the replica vault from `handoff`, register it, and open it with its context.
    /// On a failure no file and no list entry of it stays.
    fn watch_adopt(
        &self,
        connecting: &Connecting,
        joined: &JoinedDevice,
        handoff: &Handoff,
    ) -> CoreResult<VaultEntry> {
        let member = joined.member();
        check_own_row(handoff, member.public_key(), &connecting.answer_key)?;
        let id = handoff.vault_id.clone();
        if !valid_id(&id) {
            return Err(CoreError::invalid(
                "The Mac sent a vault ID that is not valid.",
            ));
        }
        if !guard(&self.list).vaults.is_empty() {
            return Err(connected_already());
        }
        let membership = RelayMembership {
            team_id: member.team_id().to_owned(),
            relay_url: member.relay_url().to_owned(),
            device_id: member
                .device_id()
                .ok_or_else(|| CoreError::internal("The relay gave no device number."))?,
            public_key: member.public_key().to_vec(),
            key_pkcs8: joined
                .key_pkcs8()
                .ok_or_else(|| CoreError::internal("The device key is missing."))?,
            purposes: BTreeSet::from([MembershipPurpose::Questions]),
            created_at: 0,
        };
        let passphrase = connecting.passphrase.as_str();
        let file = self.paths.vault_file(&id);
        let temp = self.paths.new_vault_file(&format!("watch-{}", now()));
        let made = (|| -> CoreResult<Keys> {
            if file.exists() {
                return Err(CoreError::new("io", "A file is in the way of the vault."));
            }
            let mut vault = Vault::create(&temp, passphrase)?;
            vault.unlock(passphrase)?;
            vault.adopt_replica_identity(&id)?;
            vault.adopt_question_handoff(handoff, &membership, &connecting.answer_key, None)?;
            let keys = read_keys(&vault)?
                .map(|(_, keys)| keys)
                .ok_or_else(|| CoreError::internal("The replica has no questions team."))?;
            let _ = vault.lock();
            drop(vault);
            std::fs::rename(&temp, &file).map_err(|_| CoreError::io())?;
            Ok(keys)
        })();
        let _ = std::fs::remove_file(&temp);
        let _ = std::fs::remove_file(sidecar(&temp));
        let keys = made?;
        let entry = VaultEntry {
            id: id.clone(),
            name: vault_name(handoff),
            sync_source: None,
            relay_url: None,
            team_id: None,
            device_id: None,
            added_at: now() as i64,
        };
        let registered = (|| -> CoreResult<()> {
            {
                let mut list = guard(&self.list);
                list.put(entry.clone());
                list.save(&self.paths.data_dir)?;
            }
            self.select_relay()?;
            // The joined device starts the context with its session; the unlock keeps it.
            guard(&self.questions).put(&id, Arc::new(member), keys);
            self.unlock(passphrase, false)
        })();
        if let Err(error) = registered {
            self.close(Closing::Lock);
            let _opening = guard(&self.opening);
            {
                let mut list = guard(&self.list);
                list.remove(&id);
                let _ = list.save(&self.paths.data_dir);
            }
            let _ = std::fs::remove_file(&file);
            let _ = std::fs::remove_file(sidecar(&file));
            self.questions_forget(&id);
            let _ = self.select_relay();
            return Err(error);
        }
        Ok(entry)
    }

    /// `watch_status`: the state of the watch and of its replica, without a relay call.
    /// `removed` also comes from the last relay call of the replica's team.
    fn watch_status(&self, answer_key: Option<&str>) -> CoreResult<StatusView> {
        let given = answer_key.map(answer_key_of).transpose()?;
        if guard(&self.questions).watch_connect.is_some() {
            return Ok(StatusView::of("connecting", None));
        }
        let selected = self.questions_refresh()?;
        let entry = guard(&self.list).selected_entry().cloned();
        let Some(entry) = entry else {
            return Ok(StatusView::of("unpaired", None));
        };
        let vault = Some(VaultView {
            id: entry.id.clone(),
            name: entry.name.clone(),
        });
        if !matches!(&selected, Selected::Unlocked(id) if *id == entry.id) {
            return Ok(StatusView::of("locked", vault));
        }
        let state = guard(&self.questions);
        let Some(context) = state.contexts.get(&entry.id) else {
            // An open replica without its questions team cannot answer.
            return Ok(StatusView::of("removed", vault));
        };
        let keys = &context.keys;
        let removed = keys.is_removed() || context.error == Some("removed");
        let macs = keys
            .devices
            .iter()
            .filter(|device| device.kind == TrustedDeviceKind::Mac)
            .map(|device| envelope::shown(&device.name, SHOWN_NAME))
            .collect();
        let own = keys.own.as_ref();
        let answer_key_matches = own.is_some_and(|own| {
            own.kind == TrustedDeviceKind::Watch
                && own.answer_key.as_deref().is_some_and(|key| {
                    key != own.sign_key.as_slice()
                        && given.as_deref().is_none_or(|given| given == key)
                })
        });
        Ok(StatusView {
            state: if removed { "removed" } else { "ready" },
            vault,
            macs,
            own: Some(OwnView {
                found: own.is_some(),
                answer_key_matches,
            }),
        })
    }

    /// `watch_forget`: leave the team (best effort, with the relay key of an open
    /// replica), then delete the replica, its list entry, its access guards, and its
    /// history. The watch is `unpaired` after it.
    fn watch_forget(&self) -> CoreResult<String> {
        let connecting = guard(&self.questions).watch_connect.take();
        if let Some(connecting) = connecting {
            connecting.cancel();
        }
        let ids: Vec<String> = guard(&self.list)
            .vaults
            .iter()
            .map(|entry| entry.id.clone())
            .collect();
        let _ = self.questions_refresh();
        let leaving: Vec<(Arc<RelayMember>, u64)> = guard(&self.questions)
            .contexts
            .iter()
            .filter(|(id, context)| ids.contains(id) && !context.keys.is_removed())
            .map(|(_, context)| (Arc::clone(&context.member), context.keys.device_id))
            .collect();
        for (member, device_id) in leaving {
            let path = format!("/v1/devices/{device_id}");
            let _ = member.call("DELETE", &path, None, Duration::ZERO);
        }
        self.close(Closing::Lock);
        let opening = guard(&self.opening);
        let guards_dir = self.paths.data_dir.join("request-history");
        for id in &ids {
            super::super::request_history::remove(&self.paths.data_dir, id)?;
            let guards = format!("access-guards-v1-{id}.json");
            let _ = std::fs::remove_file(guards_dir.join(format!(".{guards}.tmp")));
            let _ = std::fs::remove_file(guards_dir.join(guards));
            let file = self.paths.vault_file(id);
            let _ = std::fs::remove_file(&file);
            let _ = std::fs::remove_file(sidecar(&file));
        }
        {
            let mut list = guard(&self.list);
            for id in &ids {
                list.remove(id);
            }
            list.save(&self.paths.data_dir)?;
        }
        for id in &ids {
            self.questions_forget(id);
        }
        drop(opening);
        self.select_relay()?;
        Ok(ok(&StatusView::of("unpaired", None)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER_PUBLIC: &str =
        "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";

    fn row(kind: TrustedDeviceKind, sign_key: &[u8], answer_key: Option<Vec<u8>>) -> TrustedDevice {
        TrustedDevice {
            uuid: "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b".into(),
            name: "Synthetic device".into(),
            kind,
            relay_devices: BTreeMap::from([("t_7k2m5q4x3c".to_owned(), 2)]),
            sign_key: sign_key.to_vec(),
            answer_key,
            created_at: 1,
            updated_at: 1,
            updated_by: "synthetic".into(),
        }
    }

    fn keys(own: Option<TrustedDevice>) -> Keys {
        Keys {
            vault_identity: "d070dc14-a3ac-42c2-95aa-cc85d6d58900".into(),
            team_id: "t_7k2m5q4x3c".into(),
            device_id: 2,
            key: None,
            devices: own.iter().cloned().collect(),
            own,
            removed: false,
            questions_only: true,
        }
    }

    /// The own row of the watch core must be of kind `watch`, and that of the app of
    /// kind `iphone`: a row of the other kind is `answer_key_changed` (ADR 0039 §2).
    #[test]
    fn the_own_row_must_be_of_the_kind_of_the_device() {
        let sign = DeviceKey::generate().unwrap().public_key().to_vec();
        let answer = decode_b64u(ANSWER_PUBLIC).unwrap();
        for (role, right, wrong) in [
            (
                Role::Watch,
                TrustedDeviceKind::Watch,
                TrustedDeviceKind::Iphone,
            ),
            (
                Role::App,
                TrustedDeviceKind::Iphone,
                TrustedDeviceKind::Watch,
            ),
            (
                Role::Watch,
                TrustedDeviceKind::Watch,
                TrustedDeviceKind::Mac,
            ),
        ] {
            let good = keys(Some(row(right, &sign, Some(answer.clone()))));
            assert_eq!(good.own_row_as(role).unwrap().kind, right);
            let bad = keys(Some(row(wrong, &sign, Some(answer.clone()))));
            let error = bad.own_row_as(role).unwrap_err();
            assert_eq!(error.code, "answer_key_changed", "{role:?} {wrong:?}");
            if role == Role::Watch {
                assert!(error.message.contains("watch"), "{}", error.message);
            }
        }
        // No row is still `not_registered`, not a kind error.
        assert_eq!(
            keys(None).own_row_as(Role::Watch).unwrap_err().code,
            "not_registered"
        );
    }

    /// The handoff must hold a `watch` row with this watch's relay key and answer key.
    #[test]
    fn a_handoff_row_of_another_kind_or_key_is_refused() {
        let sign = DeviceKey::generate().unwrap().public_key().to_vec();
        let answer = decode_b64u(ANSWER_PUBLIC).unwrap();
        let other = DeviceKey::generate().unwrap().public_key().to_vec();
        let handoff = |devices: Vec<TrustedDevice>| Handoff {
            v: 1,
            vault_id: "d070dc14-a3ac-42c2-95aa-cc85d6d58900".into(),
            team_id: "t_7k2m5q4x3c".into(),
            recipient: sign.clone(),
            question_key: Zeroizing::new(vec![7; 32]),
            key_updated_at: 1,
            key_updated_by: "synthetic".into(),
            devices,
        };
        let code = |devices| {
            check_own_row(&handoff(devices), &sign, &answer)
                .err()
                .map(|error| error.code)
        };
        let watch = row(TrustedDeviceKind::Watch, &sign, Some(answer.clone()));
        assert_eq!(code(vec![watch]), None);
        let iphone = row(TrustedDeviceKind::Iphone, &sign, Some(answer.clone()));
        assert_eq!(code(vec![iphone]), Some("answer_key_changed"));
        let rekeyed = row(TrustedDeviceKind::Watch, &sign, Some(other.clone()));
        assert_eq!(code(vec![rekeyed]), Some("answer_key_changed"));
        let old_mac = row(TrustedDeviceKind::Watch, &sign, None);
        assert_eq!(code(vec![old_mac]), Some("mac_update_needed"));
        let someone_else = row(TrustedDeviceKind::Watch, &other, Some(answer.clone()));
        assert_eq!(code(vec![someone_else]), Some("mac_update_needed"));
        let mut mac = row(TrustedDeviceKind::Mac, &other, None);
        mac.name = "  MacBook Pro ".into();
        assert_eq!(vault_name(&handoff(vec![mac])), "MacBook Pro");
        assert_eq!(vault_name(&handoff(Vec::new())), DEFAULT_VAULT_NAME);
    }
}
