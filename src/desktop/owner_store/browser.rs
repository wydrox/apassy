//! The logins of a page, a fill in the browser (ADR 0021), one-time codes, and passkeys.
//!
//! A login may go to a page when it is a login with a password, it is not archived, and
//! one of its websites matches the page ([`crate::browser::site`]). The list and the
//! owner check dialog get the title and the username only. The password leaves the
//! vault in [`OwnerSession::fill_login`], after the owner check for that one fill.
//!
//! A one-time code may go to a page when its login is not archived and one of its
//! websites matches the page, with the same rule. The field is a hidden custom detail
//! with the label of a one-time password, or a hidden custom detail with an explicit
//! `otpauth://totp` link. The seed stays in [`OwnerSession::fill_code`]: only the code
//! leaves, after the owner check for that one code.
//!
//! A passkey signs or is made only in [`OwnerSession::sign_passkey`] and
//! [`OwnerSession::create_passkey`], with a proof for exactly that request. The values
//! that sign are the values of the proof. The list of passkeys has no key.

use std::fmt;

use zeroize::Zeroizing;

use super::{OtpCode, OwnerSession, SecretForm, fail, map_err, unix_now};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::browser::site::{Page, Website, is_website_field};
use crate::browser::wire::MAX_LOGINS;
use crate::contracts::CredentialKind;
use crate::desktop::model::{ItemDraft, ModelError, ModelResult};
use crate::owner::wire::SecretText;
use crate::vault::{
    ItemDetails, PasskeyAssertion, PasskeyCreate, PasskeyCreated, PasskeyError, PasskeyInfo, Vault,
    VaultErrorKind, custom_detail_label,
};

/// One login that may go to a page. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageLogin {
    pub id: u64,
    pub title: String,
    pub username: String,
    /// The login has a one-time password. Its seed and its code stay in the vault.
    pub has_totp: bool,
}

/// The passkey of one login, for the credential page. It has no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyItem {
    pub info: PasskeyInfo,
    /// The login has a password that is not empty. Without one, removing the passkey
    /// deletes the login.
    pub has_password: bool,
}

/// The origin that the history of a login names for a fill of macOS AutoFill.
pub const SYSTEM_FILL_ORIGIN: &str = "macOS AutoFill";

/// A login for macOS AutoFill, without a secret value: its metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemLogin {
    pub id: u64,
    pub title: String,
    pub username: String,
    /// The website values of the login, as stored.
    pub websites: Vec<String>,
    pub revision: u64,
    /// The password is not empty. Only such a login fills a password.
    pub has_password: bool,
    pub has_passkey: bool,
    /// The stored name of the first one-time password field, when the login has one.
    pub code_field: Option<String>,
}

/// The one-time password of a login that may go to a page. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCode {
    pub id: u64,
    pub title: String,
    /// The stored name of the field of the seed.
    pub field: String,
}

/// The values of one fill. Debug output hides the password.
pub struct FillValues {
    pub username: String,
    pub password: Zeroizing<String>,
}

impl fmt::Debug for FillValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FillValues")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

fn no_match() -> ModelError {
    fail(
        "no_match",
        "This login is not for this page. Nothing was filled.",
    )
}

fn gone() -> ModelError {
    fail(
        "not_found",
        "This login is not in Apassy any more, or it has no password. Nothing was filled.",
    )
}

fn no_code() -> ModelError {
    fail(
        "no_code",
        "This login has no one-time password for this field. Nothing was filled.",
    )
}

/// The owner text of a passkey failure. It never quotes a key or an input.
fn passkey_err(err: PasskeyError) -> ModelError {
    match err {
        PasskeyError::Vault(err) if err.kind() == VaultErrorKind::NotFound => fail(
            "not_found",
            "The passkey is not in Apassy any more, or it is for another site. Nothing was signed.",
        ),
        PasskeyError::Vault(err) => map_err(err),
        PasskeyError::Excluded => fail(
            "excluded",
            "Apassy has a passkey for this account on this site already. Nothing was saved.",
        ),
        PasskeyError::NoSupportedAlgorithm => fail(
            "unsupported",
            "The site asks for a passkey type that Apassy does not make. Nothing was saved.",
        ),
        PasskeyError::Exists => fail(
            "exists",
            "The login has a passkey already. Nothing was saved.",
        ),
        PasskeyError::BadKey => fail(
            "refused",
            "The passkey in Apassy is damaged. Nothing was signed.",
        ),
    }
}

impl OwnerSession {
    /// The logins that may go to `page`, by title, at most [`MAX_LOGINS`].
    pub fn logins_for_page(&self, page: &Page) -> ModelResult<Vec<PageLogin>> {
        let mut found = self.all_logins_for_page(page)?;
        found.truncate(MAX_LOGINS);
        Ok(found)
    }

    /// A login for `page` with `username`, without regard to case.
    pub fn login_with_username(
        &self,
        page: &Page,
        username: &str,
    ) -> ModelResult<Option<PageLogin>> {
        let wanted = username.trim().to_lowercase();
        Ok(self
            .all_logins_for_page(page)?
            .into_iter()
            .find(|login| login.username.trim().to_lowercase() == wanted))
    }

    /// Add the login that the owner typed on `page`, after the owner check (ADR 0021).
    /// The website of the new login is the origin of the page. A login with the same
    /// username for the page gets `exists`.
    pub fn save_login(
        &mut self,
        title: &str,
        username: &str,
        password: SecretText,
        page: &Page,
        proof: OwnerProof,
    ) -> ModelResult<u64> {
        drop(self.unlocked_for(
            proof,
            &OwnerAction::SaveLogin {
                title: title.to_owned(),
                username: username.to_owned(),
                origin: page.origin(),
            },
        )?);
        let mut secrets = SecretForm::default();
        secrets.password.push_str(password.expose());
        drop(password);
        self.add_page_login(title, username, page, &secrets)
    }

    /// Add a login with a new password for `page`, after the owner check (ADR 0021).
    /// The app makes the password ([`crate::browser::password`]). The values go to the
    /// browser.
    pub fn create_login(
        &mut self,
        title: &str,
        username: &str,
        page: &Page,
        length: u32,
        symbols: bool,
        proof: OwnerProof,
    ) -> ModelResult<(u64, FillValues)> {
        drop(self.unlocked_for(
            proof,
            &OwnerAction::CreateLogin {
                title: title.to_owned(),
                username: username.to_owned(),
                origin: page.origin(),
                length,
                symbols,
            },
        )?);
        let password = crate::browser::password::generate(length, symbols).map_err(|_| {
            fail(
                "refused",
                "Apassy could not make a password. Nothing was saved.",
            )
        })?;
        let mut secrets = SecretForm::default();
        secrets.password.push_str(&password);
        let id = self.add_page_login(title, username, page, &secrets)?;
        Ok((
            id,
            FillValues {
                username: username.to_owned(),
                password,
            },
        ))
    }

    fn add_page_login(
        &mut self,
        title: &str,
        username: &str,
        page: &Page,
        secrets: &SecretForm,
    ) -> ModelResult<u64> {
        if let Some(existing) = self.login_with_username(page, username)? {
            return Err(fail(
                "exists",
                format!(
                    "\"{}\" is in Apassy for this page with the username {}. Nothing was saved.",
                    existing.title, existing.username
                ),
            ));
        }
        let draft = ItemDraft {
            name: title.to_owned(),
            kind: CredentialKind::Login,
            username: username.to_owned(),
            website: page.origin(),
            ..ItemDraft::default()
        };
        Ok(self.add(&draft, secrets)?.id)
    }

    /// Every login that may go to `page`, by title.
    fn all_logins_for_page(&self, page: &Page) -> ModelResult<Vec<PageLogin>> {
        let vault = self.unlocked()?;
        let mut found = Vec::new();
        for summary in vault.search("").map_err(map_err)? {
            if summary.kind != CredentialKind::Login {
                continue;
            }
            if let Some(username) = fillable(&vault, summary.id, page)? {
                let details = vault.details(summary.id).map_err(map_err)?;
                found.push(PageLogin {
                    id: summary.id,
                    title: summary.title,
                    username,
                    has_totp: !code_fields(&vault, &details)?.is_empty(),
                });
            }
        }
        found.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        Ok(found)
    }

    /// Login `id` when it may go to `page`. `no_match` for another item.
    pub fn page_login(&self, id: u64, page: &Page) -> ModelResult<PageLogin> {
        let vault = self.unlocked()?;
        let username = fillable(&vault, id, page)?.ok_or_else(no_match)?;
        let details = vault.details(id).map_err(map_err)?;
        Ok(PageLogin {
            id,
            has_totp: !code_fields(&vault, &details)?.is_empty(),
            title: details.summary.title,
            username,
        })
    }

    /// The username and the password of login `id` for `page`, after the owner check for
    /// this fill (goal item A4). The proof names the login by its title now: a login with
    /// another title is refused. The match is checked again.
    pub fn fill_login(
        &mut self,
        id: u64,
        page: &Page,
        proof: OwnerProof,
    ) -> ModelResult<FillValues> {
        let title = match self.unlocked()?.details(id) {
            Ok(details) => details.summary.title,
            Err(err) if err.kind() == VaultErrorKind::NotFound => {
                drop(proof);
                return Err(no_match());
            }
            Err(err) => return Err(map_err(err)),
        };
        let vault = self.unlocked_for(
            proof,
            &OwnerAction::FillLogin {
                item_id: id,
                login: title,
                origin: page.origin(),
            },
        )?;
        let username = fillable(&vault, id, page)?.ok_or_else(no_match)?;
        // Move the value into the erasing buffer without a copy (key-memory review F10).
        let password = vault
            .reveal(id, "password")
            .map_err(map_err)?
            .into_zeroizing();
        Ok(FillValues { username, password })
    }

    /// The one-time password of login `id` for `page`, before the owner check. `field`
    /// names the field by its label (as the extension knows it) or by its stored name;
    /// `None` takes the first one-time password of the login. `no_match`
    /// when the login is not for the page, `no_code` when the field holds no one-time
    /// password. Nothing secret leaves.
    pub fn page_code(&self, id: u64, page: &Page, field: Option<&str>) -> ModelResult<PageCode> {
        let vault = self.unlocked()?;
        let (details, fields) = code_login(&vault, id, page)?.ok_or_else(no_match)?;
        let field = match field {
            Some(field) => fields
                .into_iter()
                .find(|name| {
                    name == field || custom_detail_label(name).is_some_and(|label| label == field)
                })
                .ok_or_else(no_code)?,
            None => fields.into_iter().next().ok_or_else(no_code)?,
        };
        Ok(PageCode {
            id,
            title: details.summary.title,
            field,
        })
    }

    /// The current code of the one-time password in `field` of login `id` for `page`,
    /// after the owner check for this one code: [`OwnerAction::FillCode`] names the item,
    /// the field, and the origin of the page. The match and the field are checked again.
    /// The seed stays in this call and is erased before it returns. The proof is used up,
    /// also on a failure.
    pub fn fill_code(
        &mut self,
        id: u64,
        field: &str,
        page: &Page,
        proof: OwnerProof,
    ) -> ModelResult<OtpCode> {
        self.fill_code_at(id, field, page, proof, unix_now())
    }

    /// [`Self::fill_code`] at `unix` seconds.
    pub(crate) fn fill_code_at(
        &mut self,
        id: u64,
        field: &str,
        page: &Page,
        proof: OwnerProof,
        unix: u64,
    ) -> ModelResult<OtpCode> {
        let seed = {
            let vault = self.unlocked_for(
                proof,
                &OwnerAction::FillCode {
                    item_id: id,
                    field: field.to_owned(),
                    origin: page.origin(),
                },
            )?;
            let (_, fields) = code_login(&vault, id, page)?.ok_or_else(no_match)?;
            if !fields.iter().any(|name| name == field) {
                return Err(no_code());
            }
            vault.reveal(id, field).map_err(map_err)?.into_zeroizing()
        };
        let totp = crate::otp::Totp::parse(&seed).map_err(|_| {
            fail(
                "invalid_input",
                "The one-time password of this login is not a valid setup key. Nothing was filled.",
            )
        })?;
        drop(seed);
        let (digits, left) = totp.code_at(unix);
        Ok(OtpCode {
            digits: Zeroizing::new(digits),
            left,
        })
    }

    /// The canonical passkeys of `rp_id`, without keys. A non-empty `allowed` keeps only
    /// those credential IDs. No owner check: the list has no secret value.
    pub fn passkeys_for(&self, rp_id: &str, allowed: &[Vec<u8>]) -> ModelResult<Vec<PasskeyInfo>> {
        self.unlocked()?
            .passkeys(rp_id, allowed)
            .map_err(passkey_err)
    }

    /// Every canonical passkey, without keys, for the identities of macOS AutoFill.
    pub fn all_passkeys(&self) -> ModelResult<Vec<PasskeyInfo>> {
        self.unlocked()?.all_passkeys().map_err(passkey_err)
    }

    /// The canonical passkey of item `id`, when it is for `rp_id` and has `credential_id`.
    pub fn passkey_of(
        &self,
        id: u64,
        rp_id: &str,
        credential_id: &[u8],
    ) -> ModelResult<Option<PasskeyInfo>> {
        Ok(self
            .passkeys_for(rp_id, &[credential_id.to_vec()])?
            .into_iter()
            .find(|info| info.item_id == id))
    }

    /// Sign the assertion that `action` names ([`OwnerAction::SignPasskey`]) with `proof`
    /// for that action. The values that sign come from the action, so they are the values
    /// that the owner confirmed. The vault checks the item, the relying party, and the
    /// credential again. User presence and verification are set only here, after the
    /// proof. The proof is used up, also on a failure.
    pub fn sign_passkey(
        &mut self,
        action: &OwnerAction,
        proof: OwnerProof,
    ) -> ModelResult<PasskeyAssertion> {
        let OwnerAction::SignPasskey {
            rp_id,
            item_id,
            credential_id,
            client_data_hash,
            ..
        } = action
        else {
            drop(proof);
            return Err(fail(
                "owner_check_required",
                "The owner check was for another action. Nothing was signed.",
            ));
        };
        let vault = self.unlocked_for(proof, action)?;
        vault
            .sign_passkey(*item_id, rp_id, credential_id, client_data_hash)
            .map_err(passkey_err)
    }

    /// Make the passkey that `action` names ([`OwnerAction::CreatePasskey`]) with `proof`
    /// for that action. As [`Self::sign_passkey`]: the values come from the action. An
    /// excluded credential answers `excluded` after the check, so a page cannot learn
    /// without the owner that a passkey is in Apassy.
    pub fn create_passkey(
        &mut self,
        action: &OwnerAction,
        proof: OwnerProof,
    ) -> ModelResult<PasskeyCreated> {
        let OwnerAction::CreatePasskey {
            rp_id,
            client_data_hash,
            user_handle,
            user_name,
            user_display_name,
            algorithms,
            excluded,
            target,
            ..
        } = action
        else {
            drop(proof);
            return Err(fail(
                "owner_check_required",
                "The owner check was for another action. Nothing was saved.",
            ));
        };
        let mut vault = self.unlocked_for(proof, action)?;
        vault
            .create_passkey(PasskeyCreate {
                rp_id,
                user_handle,
                user_name,
                user_display_name,
                client_data_hash,
                algorithms,
                exclude: excluded,
                target: target.clone(),
            })
            .map_err(passkey_err)
    }

    /// The active logins for macOS AutoFill, in vault order, without secret values. An
    /// archived login is not in the list.
    pub fn system_logins(&self) -> ModelResult<Vec<SystemLogin>> {
        let vault = self.unlocked()?;
        let mut logins = Vec::new();
        for summary in vault.search("").map_err(map_err)? {
            if summary.kind != CredentialKind::Login {
                continue;
            }
            if let Some(login) = system_login(&vault, summary.id)? {
                logins.push(login);
            }
        }
        Ok(logins)
    }

    /// Login `id` for macOS AutoFill, without secret values. `None` for a missing or
    /// archived item, or an item that is not a login.
    pub fn system_login(&self, id: u64) -> ModelResult<Option<SystemLogin>> {
        system_login(&*self.unlocked()?, id)
    }

    /// The username and the password of login `id` for one request `rid` of macOS
    /// AutoFill, after the owner check for [`OwnerAction::FillSystemLogin`] of this
    /// request, this login, and its title as the owner saw it. A login without a password
    /// (a passkey only) never fills. The proof is used up, also on a failure.
    pub fn system_fill(
        &mut self,
        rid: &str,
        id: u64,
        title: &str,
        proof: OwnerProof,
    ) -> ModelResult<FillValues> {
        let vault = self.unlocked_for(
            proof,
            &OwnerAction::FillSystemLogin {
                rid: rid.to_owned(),
                item_id: id,
                login: title.to_owned(),
            },
        )?;
        let login = system_login(&vault, id)?.ok_or_else(gone)?;
        if !login.has_password || login.title != title {
            return Err(gone());
        }
        let password = vault
            .reveal(id, "password")
            .map_err(map_err)?
            .into_zeroizing();
        Ok(FillValues {
            username: login.username,
            password,
        })
    }

    /// The current code of the one-time password in `field` of login `id` for one
    /// request `rid` of macOS AutoFill, after the owner check for
    /// [`OwnerAction::FillSystemCode`]. The seed stays in this call. The proof is used
    /// up, also on a failure.
    pub fn system_code(
        &mut self,
        rid: &str,
        id: u64,
        field: &str,
        proof: OwnerProof,
    ) -> ModelResult<OtpCode> {
        let seed = {
            let vault = self.unlocked_for(
                proof,
                &OwnerAction::FillSystemCode {
                    rid: rid.to_owned(),
                    item_id: id,
                    field: field.to_owned(),
                },
            )?;
            let Some(details) = active_login(&vault, id)? else {
                return Err(gone());
            };
            if !code_fields(&vault, &details)?
                .iter()
                .any(|name| name == field)
            {
                return Err(no_code());
            }
            vault.reveal(id, field).map_err(map_err)?.into_zeroizing()
        };
        let totp = crate::otp::Totp::parse(&seed).map_err(|_| {
            fail(
                "invalid_input",
                "The one-time password of this login is not a valid setup key. Nothing was filled.",
            )
        })?;
        drop(seed);
        let (digits, left) = totp.code_at(unix_now());
        Ok(OtpCode {
            digits: Zeroizing::new(digits),
            left,
        })
    }

    /// The passkey of login `id`, without its key. `None` when the item has none.
    pub fn passkey_item(&self, id: u64) -> ModelResult<Option<PasskeyItem>> {
        let vault = self.unlocked()?;
        let info = match vault.passkey_info(id) {
            Ok(info) => info,
            Err(PasskeyError::Vault(err)) if err.kind() == VaultErrorKind::NotFound => {
                return Ok(None);
            }
            Err(err) => return Err(passkey_err(err)),
        };
        // The password is read only to see that it is not empty, and is erased at once.
        let has_password = match vault.reveal(id, "password") {
            Ok(value) => !value.expose().is_empty(),
            Err(err) if err.kind() == VaultErrorKind::NotFound => false,
            Err(err) => return Err(map_err(err)),
        };
        Ok(Some(PasskeyItem { info, has_password }))
    }

    /// Remove the passkey of login `id` at `revision`, after the owner check for
    /// [`OwnerAction::RemovePasskey`] of this item and revision. A login with a password
    /// keeps it and gets a new revision. A login without a password is deleted, like a
    /// delete: with its notes, codes, and every field, also on the synced devices. The
    /// revealed values and the opened seeds of the item are erased. The proof is used up,
    /// also on a failure.
    pub fn remove_passkey(&mut self, id: u64, revision: u64, proof: OwnerProof) -> ModelResult<()> {
        self.unlocked_for(
            proof,
            &OwnerAction::RemovePasskey {
                item_id: id,
                revision,
            },
        )?
        .remove_passkey(id, revision)
        .map_err(|err| match err {
            PasskeyError::Vault(err) if err.kind() == VaultErrorKind::NotFound => fail(
                "not_found",
                "This login has no passkey any more. Nothing was removed.",
            ),
            other => passkey_err(other),
        })?;
        self.forget_item_reveals(id);
        Ok(())
    }

    /// A login for `page` with `username` that has no passkey yet, at its revision: a new
    /// passkey for this account can go into it.
    pub fn passkey_attach_target(
        &self,
        page: &Page,
        username: &str,
    ) -> ModelResult<Option<(PageLogin, u64)>> {
        let Some(login) = self.login_with_username(page, username)? else {
            return Ok(None);
        };
        let vault = self.unlocked()?;
        match vault.passkey_info(login.id) {
            Ok(_) => return Ok(None),
            Err(PasskeyError::Vault(err)) if err.kind() == VaultErrorKind::NotFound => {}
            Err(err) => return Err(passkey_err(err)),
        }
        let revision = vault.details(login.id).map_err(map_err)?.summary.revision;
        Ok(Some((login, revision)))
    }

    /// Record a fill in the history of login `id`, after the browser got the values.
    pub fn record_fill(&mut self, id: u64, origin: &str) -> ModelResult<()> {
        self.unlocked()?.record_fill(id, origin).map_err(map_err)
    }
}

/// The username of item `id` when it may go to `page`: a login with a password, not
/// archived, with a website that matches. `None` otherwise, also for a missing item.
fn fillable(vault: &Vault, id: u64, page: &Page) -> ModelResult<Option<String>> {
    let Some(details) = page_item(vault, id, page)? else {
        return Ok(None);
    };
    // A login with a passkey only has no password to fill.
    if !details
        .fields
        .iter()
        .any(|field| field.name == "password" && field.secret)
    {
        return Ok(None);
    }
    match vault.reveal(id, "username") {
        Ok(value) => Ok(Some(value.expose().to_owned())),
        Err(err) if err.kind() == VaultErrorKind::NotFound => Ok(Some(String::new())),
        Err(err) => Err(map_err(err)),
    }
}

/// The details of item `id` when it is a login that is not archived, with a website that
/// matches `page`. `None` otherwise, also for a missing item.
fn page_item(vault: &Vault, id: u64, page: &Page) -> ModelResult<Option<ItemDetails>> {
    let details = match vault.details(id) {
        Ok(details) => details,
        Err(err) if err.kind() == VaultErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(map_err(err)),
    };
    if details.summary.kind != CredentialKind::Login || vault.is_archived(id).map_err(map_err)? {
        return Ok(None);
    }
    for field in details.fields.iter().filter(|field| !field.secret) {
        let label = custom_detail_label(&field.name);
        if !is_website_field(&field.name, label.as_deref()) {
            continue;
        }
        let value = vault.reveal(id, &field.name).map_err(map_err)?;
        if Website::parse(value.expose()).is_some_and(|website| website.matches(page)) {
            return Ok(Some(details));
        }
    }
    Ok(None)
}

/// The details of login `id` for `page` and the names of its one-time password fields,
/// when it has at least one. `None` when the login is not for the page.
fn code_login(
    vault: &Vault,
    id: u64,
    page: &Page,
) -> ModelResult<Option<(ItemDetails, Vec<String>)>> {
    let Some(details) = page_item(vault, id, page)? else {
        return Ok(None);
    };
    let fields = code_fields(vault, &details)?;
    Ok(Some((details, fields)))
}

/// The stored names of the fields of an item that hold a one-time password, in stored
/// order: a custom detail with the label of a one-time password, or with an explicit
/// `otpauth://totp` link ([`super::is_setup_key`]). The same recognizers as the
/// credential page and the iPhone core. The password and the built-in fields are never
/// a one-time password.
fn code_fields(vault: &Vault, details: &ItemDetails) -> ModelResult<Vec<String>> {
    let mut names = Vec::new();
    for field in &details.fields {
        if super::is_code_field(vault, details.summary.id, field)? {
            names.push(field.name.clone());
        }
    }
    Ok(names)
}

/// The details of item `id` when it is a login that is not archived.
fn active_login(vault: &Vault, id: u64) -> ModelResult<Option<ItemDetails>> {
    let details = match vault.details(id) {
        Ok(details) => details,
        Err(err) if err.kind() == VaultErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(map_err(err)),
    };
    if details.summary.kind != CredentialKind::Login || vault.is_archived(id).map_err(map_err)? {
        return Ok(None);
    }
    Ok(Some(details))
}

/// Login `id` for macOS AutoFill: its metadata, and which secrets it has. The password
/// and the seeds are read only to see that they are there, and are erased at once.
fn system_login(vault: &Vault, id: u64) -> ModelResult<Option<SystemLogin>> {
    let Some(details) = active_login(vault, id)? else {
        return Ok(None);
    };
    let mut websites = Vec::new();
    for field in details.fields.iter().filter(|field| !field.secret) {
        let label = custom_detail_label(&field.name);
        if !is_website_field(&field.name, label.as_deref()) {
            continue;
        }
        let value = vault.reveal(id, &field.name).map_err(map_err)?;
        let value = value.expose().trim();
        if !value.is_empty() {
            websites.push(value.to_owned());
        }
    }
    let username = match vault.reveal(id, "username") {
        Ok(value) => value.expose().to_owned(),
        Err(err) if err.kind() == VaultErrorKind::NotFound => String::new(),
        Err(err) => return Err(map_err(err)),
    };
    let has_password = match vault.reveal(id, "password") {
        Ok(value) => !value.expose().is_empty(),
        Err(err) if err.kind() == VaultErrorKind::NotFound => false,
        Err(err) => return Err(map_err(err)),
    };
    let has_passkey = match vault.passkey_info(id) {
        Ok(_) => true,
        Err(PasskeyError::Vault(err)) if err.kind() == VaultErrorKind::NotFound => false,
        Err(err) => return Err(passkey_err(err)),
    };
    let code_field = code_fields(vault, &details)?.into_iter().next();
    Ok(Some(SystemLogin {
        id,
        title: details.summary.title,
        username,
        websites,
        revision: details.summary.revision,
        has_password,
        has_passkey,
        code_field,
    }))
}
