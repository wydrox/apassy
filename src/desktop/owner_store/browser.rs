//! The logins of a page, and a fill in the browser (ADR 0021).
//!
//! A login may go to a page when it is a login with a password, it is not archived, and
//! one of its websites matches the page ([`crate::browser::site`]). The list and the
//! owner check dialog get the title and the username only. The password leaves the
//! vault in [`OwnerSession::fill_login`], after the owner check for that one fill.

use std::fmt;

use zeroize::Zeroizing;

use super::{OwnerSession, SecretForm, fail, map_err};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::browser::site::{Page, Website, is_website_field};
use crate::browser::wire::MAX_LOGINS;
use crate::contracts::CredentialKind;
use crate::desktop::model::{ItemDraft, ModelError, ModelResult};
use crate::owner::wire::SecretText;
use crate::vault::{Vault, VaultErrorKind, custom_detail_label};

/// One login that may go to a page. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageLogin {
    pub id: u64,
    pub title: String,
    pub username: String,
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
                found.push(PageLogin {
                    id: summary.id,
                    title: summary.title,
                    username,
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
        let title = vault.details(id).map_err(map_err)?.summary.title;
        Ok(PageLogin {
            id,
            title,
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

    /// Record a fill in the history of login `id`, after the browser got the values.
    pub fn record_fill(&mut self, id: u64, origin: &str) -> ModelResult<()> {
        self.unlocked()?.record_fill(id, origin).map_err(map_err)
    }
}

/// The username of item `id` when it may go to `page`: a login with a password, not
/// archived, with a website that matches. `None` otherwise, also for a missing item.
fn fillable(vault: &Vault, id: u64, page: &Page) -> ModelResult<Option<String>> {
    let details = match vault.details(id) {
        Ok(details) => details,
        Err(err) if err.kind() == VaultErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(map_err(err)),
    };
    if details.summary.kind != CredentialKind::Login
        || !details
            .fields
            .iter()
            .any(|field| field.name == "password" && field.secret)
        || vault.is_archived(id).map_err(map_err)?
    {
        return Ok(None);
    }
    let mut matched = false;
    for field in details.fields.iter().filter(|field| !field.secret) {
        let label = custom_detail_label(&field.name);
        if !is_website_field(&field.name, label.as_deref()) {
            continue;
        }
        let value = vault.reveal(id, &field.name).map_err(map_err)?;
        if Website::parse(value.expose()).is_some_and(|website| website.matches(page)) {
            matched = true;
            break;
        }
    }
    if !matched {
        return Ok(None);
    }
    match vault.reveal(id, "username") {
        Ok(value) => Ok(Some(value.expose().to_owned())),
        Err(err) if err.kind() == VaultErrorKind::NotFound => Ok(Some(String::new())),
        Err(err) => Err(map_err(err)),
    }
}
