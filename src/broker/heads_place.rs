//! Head set placement (ADR 0035, plan 0035 unit G): a head set trained on this Mac
//! answers where the bouncer brain runs.
//!
//! - [`place`] uploads the head file of one candidate to the bouncer brain of a client
//!   (`PUT /v1/heads/<sha256>`, [`BouncerClient::put_heads`]): the owner's server, or
//!   the server on this Mac with the key of this start of Apassy (plan 0035 unit C2).
//!   Only after the upload does the vault name the host (`model_candidate.uploaded_to`).
//!   Until then the candidate gives `NoAnswer` in shadow mode and cannot be promoted
//!   ([`shadow::placement_refusal`](super::shadow::placement_refusal)). The active model
//!   never waits for it.
//! - A full server (409 `heads_full`) loses the oldest replaced candidate of this owner
//!   on that host (`DELETE /v1/heads/<sha256>`), and the upload is tried once more.
//! - [`place_all`] puts the active and the shadow head sets on a host: before a change
//!   of the hosting choice completes, and when the owner asks for it on the Learning
//!   card. Every upload succeeds before any row changes, so a failed upload keeps the
//!   old host.
//!
//! What goes up: the head file and its `manifest.json` (names, hashes, counts and
//! training numbers; no example and no request data). A manifest over 12 KiB, one that
//! names another head file, or one that names the folder of the head file or the home
//! folder of this Mac is refused before any connection.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::SharedVault;
use super::bouncer::{BouncerClient, HeadsCallFailure};
use super::decide::lock;
use super::http::{HttpFailure, HttpResponse, TransferFailure};
use super::shadow::host_key;
use crate::vault::{
    CandidateRecord, CandidateState, MAX_CANDIDATES, THIS_MAC_HOST, Vault, VaultError,
};

/// The manifest of a head set, next to its head file (`tools/finetune/local_train.py`).
pub const MANIFEST_FILE: &str = "manifest.json";
/// The largest manifest that goes up: its compact JSON must fit the 16 KiB
/// `Apassy-Manifest` header of any host (contract bouncer-brain-v2 section 4.4).
pub const MAX_MANIFEST_BYTES: usize = 12 * 1024;

/// Why a bouncer brain on this Mac takes no head set (plan 0035 unit G): it runs
/// outside Apassy, and Apassy has no key for it.
pub const NO_KEY_THIS_MAC: &str = concat!(
    "The bouncer brain on this ",
    crate::computer!(),
    " runs outside Apassy without APASSY_BOUNCER_KEY, so it takes no head set from Apassy. Set APASSY_BOUNCER_KEY to its LAYA_API_KEY, or let Apassy start the bouncer brain (Settings > Bouncer brain)."
);

/// The host of a host key ([`host_key`]) in a sentence.
pub fn host_label(host: &str) -> String {
    if host == THIS_MAC_HOST {
        concat!("the bouncer brain on this ", crate::computer!()).to_owned()
    } else {
        format!("the bouncer brain server {host}")
    }
}

/// Why one head set did not go up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaceFailure {
    /// The vault is locked, or another vault is open now.
    Locked,
    /// The vault has no such candidate.
    NoCandidate,
    /// The vault did not read or store a row.
    Vault,
    /// The head file or its manifest on this Mac is missing or not valid. Nothing was
    /// sent.
    Files(&'static str),
    /// No key for a route that writes. Nothing was sent.
    NoKey,
    /// The server answered with another status; `code` is the contract error code.
    Refused { status: u16, code: Option<String> },
    /// The server did not answer, or the connection ended during the upload.
    Unreachable,
    /// The head file is over the upload limit (160 MiB).
    TooLarge,
}

/// A failed placement on the host `host` (a key of [`host_key`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceError {
    pub host: String,
    pub failure: PlaceFailure,
}

impl PlaceError {
    fn new(host: &str, failure: PlaceFailure) -> Self {
        Self {
            host: host.to_owned(),
            failure,
        }
    }

    /// Text for the owner. It names the host, never the bearer.
    pub fn message(&self) -> String {
        let place = host_label(&self.host);
        let this_mac = self.host == THIS_MAC_HOST;
        let code = |code: &Option<String>| code.as_deref().unwrap_or_default().to_owned();
        match &self.failure {
            PlaceFailure::Locked => {
                "The vault is locked, so Apassy did not upload the head set.".to_owned()
            }
            PlaceFailure::NoCandidate => "The vault has no such head set.".to_owned(),
            PlaceFailure::Vault => "The vault did not store the upload of the head set.".to_owned(),
            PlaceFailure::Files(text) => {
                format!(
                    concat!(
                        "The head set on this ",
                        crate::computer!(),
                        " cannot go up: {text}."
                    ),
                    text = text
                )
            }
            PlaceFailure::NoKey if this_mac => NO_KEY_THIS_MAC.to_owned(),
            PlaceFailure::NoKey => {
                format!("Apassy has no token for {place}. Choose the server again.")
            }
            PlaceFailure::Refused { status: 401, .. } if this_mac => NO_KEY_THIS_MAC.to_owned(),
            PlaceFailure::Refused { status: 401, .. } => format!(
                "{} refused the token (401). Choose the server again with its LAYA_API_KEY.",
                capital(&place)
            ),
            PlaceFailure::Refused {
                status: 403,
                code: c,
            } if code(c) == "no_token" => {
                if this_mac {
                    NO_KEY_THIS_MAC.to_owned()
                } else {
                    format!(
                        "{} has no LAYA_API_KEY, so it takes no head set. Start it with LAYA_API_KEY.",
                        capital(&place)
                    )
                }
            }
            PlaceFailure::Refused {
                status: 409,
                code: c,
            } if code(c) == "heads_full" => format!(
                "{} stores no more head sets (heads_full), and none of your replaced head sets was there to delete. Delete a head set there first.",
                capital(&place)
            ),
            PlaceFailure::Refused { status: 400, .. } => format!(
                "{} refused the head set (bad_heads): the head file or its manifest does not match the base model of that server.",
                capital(&place)
            ),
            PlaceFailure::Refused { status, .. } => format!(
                "{} refused the head set (status {status}).",
                capital(&place)
            ),
            PlaceFailure::Unreachable => format!(
                "{} did not take the head set: no answer, or the connection ended. Try again.",
                capital(&place)
            ),
            PlaceFailure::TooLarge => {
                "The head set is larger than the upload limit of 160 MiB.".to_owned()
            }
        }
    }
}

fn capital(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// One head set on a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    pub candidate_id: u64,
    /// The host key ([`host_key`]).
    pub host: String,
    /// The SHA-256 of the head file.
    pub heads: String,
    /// The host stored it now (201). `false`: it was there already.
    pub created: bool,
    /// The replaced candidates whose head sets were deleted to make room.
    pub freed: Vec<u64>,
}

/// Upload the head set of candidate `candidate_id` to the bouncer brain of `client`,
/// then mark it in the vault. A head set that the vault already names on that host is
/// not sent again. The caller must not hold the vault lock: the upload runs without it.
pub fn place(
    vault: &SharedVault,
    candidate_id: u64,
    client: &BouncerClient,
) -> Result<Placed, PlaceError> {
    let host = host_key(client);
    let error = |failure| PlaceError::new(&host, failure);
    let file = open_file(vault).map_err(error)?;
    let record = with_vault(vault, &file, |vault| vault.candidate(candidate_id))
        .map_err(error)?
        .ok_or_else(|| error(PlaceFailure::NoCandidate))?;
    let placed = send(vault, &file, &host, &record, client, &[]).map_err(error)?;
    mark(vault, &file, &host, std::slice::from_ref(&placed)).map_err(error)?;
    Ok(placed)
}

/// Put the active head set (a promoted model) and the shadow candidate on the bouncer
/// brain of `client`. Every upload succeeds before the vault changes, so a failure
/// keeps every row on its old host. A default bouncer and no candidate send nothing.
pub fn place_all(vault: &SharedVault, client: &BouncerClient) -> Result<Vec<Placed>, PlaceError> {
    let host = host_key(client);
    let error = |failure| PlaceError::new(&host, failure);
    let file = open_file(vault).map_err(error)?;
    let records = with_vault(vault, &file, |vault| current_records(vault)).map_err(error)?;
    let batch: Vec<String> = records
        .iter()
        .map(|record| record.heads_sha256().to_owned())
        .collect();
    let mut placed = Vec::new();
    for record in &records {
        placed.push(send(vault, &file, &host, record, client, &batch).map_err(error)?);
    }
    mark(vault, &file, &host, &placed).map_err(error)?;
    Ok(placed)
}

/// The active head set and the shadow candidate whose head files are not on the host
/// `host` (a key of [`host_key`] or `shadow::hosting_key`). Empty: nothing to upload.
pub fn missing_on(vault: &Vault, host: &str) -> Result<Vec<CandidateRecord>, VaultError> {
    Ok(current_records(vault)?
        .into_iter()
        .filter(|record| !record.is_on_host(host))
        .collect())
}

/// The candidate rows of the active head set and of the shadow candidate.
fn current_records(vault: &Vault) -> Result<Vec<CandidateRecord>, VaultError> {
    let mut out: Vec<CandidateRecord> = Vec::new();
    if let Some(heads) = active_heads(vault)? {
        let record = vault
            .candidates(MAX_CANDIDATES)?
            .into_iter()
            .find(|record| record.heads_sha256() == heads);
        out.extend(record);
    }
    if let Some(shadow) = vault.shadow_candidate()?
        && !out
            .iter()
            .any(|record| record.heads_sha256() == shadow.heads_sha256())
    {
        out.push(shadow);
    }
    Ok(out)
}

fn active_heads(vault: &Vault) -> Result<Option<String>, VaultError> {
    match vault.active_model()? {
        Some(activation) => vault.activation_heads(&activation),
        None => Ok(None),
    }
}

/// The file of the open vault: the rows change only in this vault.
fn open_file(vault: &SharedVault) -> Result<PathBuf, PlaceFailure> {
    let guard = lock(vault);
    guard
        .as_ref()
        .filter(|vault| !vault.is_locked())
        .map(|vault| vault.path().to_path_buf())
        .ok_or(PlaceFailure::Locked)
}

fn with_vault<T>(
    vault: &SharedVault,
    file: &Path,
    f: impl FnOnce(&mut Vault) -> Result<T, VaultError>,
) -> Result<T, PlaceFailure> {
    let mut guard = lock(vault);
    let vault = guard
        .as_mut()
        .filter(|vault| !vault.is_locked() && vault.path() == file)
        .ok_or(PlaceFailure::Locked)?;
    f(vault).map_err(|_| PlaceFailure::Vault)
}

/// Mark each head set of `placed` on `host`, in one hold of the vault.
fn mark(
    vault: &SharedVault,
    file: &Path,
    host: &str,
    placed: &[Placed],
) -> Result<(), PlaceFailure> {
    with_vault(vault, file, |vault| {
        for one in placed {
            vault.mark_candidate_uploaded(one.candidate_id, Some(host))?;
        }
        Ok(())
    })
}

/// The bytes that go up for one head set.
struct Upload {
    heads: String,
    checkpoint: PathBuf,
    manifest: Vec<u8>,
}

/// Read the head file path and the manifest of `record`, and check the manifest.
fn upload_of(record: &CandidateRecord) -> Result<Upload, PlaceFailure> {
    let checkpoint = PathBuf::from(&record.checkpoint);
    if !checkpoint.is_file() {
        return Err(PlaceFailure::Files(concat!(
            "the head file is not on this ",
            crate::computer!()
        )));
    }
    let mut manifest = Vec::new();
    fs::File::open(checkpoint.with_file_name(MANIFEST_FILE))
        .map_err(|_| {
            PlaceFailure::Files(concat!(
                "its manifest.json is not on this ",
                crate::computer!()
            ))
        })?
        .take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut manifest)
        .map_err(|_| PlaceFailure::Files("its manifest.json cannot be read"))?;
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(PlaceFailure::Files(
            "its manifest.json is larger than 12 KiB",
        ));
    }
    let value: Value = serde_json::from_slice(&manifest)
        .map_err(|_| PlaceFailure::Files("its manifest.json is not JSON"))?;
    if !value.is_object() {
        return Err(PlaceFailure::Files(
            "its manifest.json is not a JSON object",
        ));
    }
    if value["checkpoint"]["sha256"].as_str() != Some(record.heads_sha256()) {
        return Err(PlaceFailure::Files(
            "its manifest.json names another head file",
        ));
    }
    // A manifest names no path of this Mac (ADR 0007 state only): not the folder of
    // the head file, and not the home folder. The vault keeps the canonical path
    // (`/private/var/...`); a trainer may write the same folder as `/var/...`.
    let text = String::from_utf8_lossy(&manifest);
    let folder = checkpoint
        .parent()
        .and_then(Path::to_str)
        .unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();
    let named = [
        folder,
        folder.strip_prefix("/private").unwrap_or_default(),
        &home,
    ]
    .into_iter()
    .filter(|path| path.len() > 1)
    .any(|path| text.contains(path));
    if named {
        return Err(PlaceFailure::Files(concat!(
            "its manifest.json names a folder on this ",
            crate::computer!()
        )));
    }
    Ok(Upload {
        heads: record.heads_sha256().to_owned(),
        checkpoint,
        manifest,
    })
}

/// What the server did with one upload.
enum Answer {
    Stored { created: bool },
    Full,
}

fn code(response: &HttpResponse) -> Option<String> {
    serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|body| body["detail"]["code"].as_str().map(str::to_owned))
}

fn call_failure(failure: HeadsCallFailure) -> PlaceFailure {
    match failure {
        HeadsCallFailure::NoKey => PlaceFailure::NoKey,
        HeadsCallFailure::BadHash => PlaceFailure::Files("the head hash is not valid"),
        HeadsCallFailure::Transfer(TransferFailure::Http(HttpFailure::TooLarge)) => {
            PlaceFailure::TooLarge
        }
        HeadsCallFailure::Transfer(TransferFailure::File) => {
            PlaceFailure::Files("the head file cannot be read")
        }
        HeadsCallFailure::Transfer(_) => PlaceFailure::Unreachable,
    }
}

fn put(client: &BouncerClient, upload: &Upload) -> Result<Answer, PlaceFailure> {
    let response = client
        .put_heads(&upload.heads, &upload.checkpoint, &upload.manifest)
        .map_err(call_failure)?;
    match response.status {
        200 | 201 => {
            let named = serde_json::from_slice::<Value>(&response.body)
                .ok()
                .and_then(|body| body["heads"].as_str().map(str::to_owned));
            if named.as_deref() != Some(upload.heads.as_str()) {
                return Err(PlaceFailure::Refused {
                    status: response.status,
                    code: Some("wrong_heads".to_owned()),
                });
            }
            Ok(Answer::Stored {
                created: response.status == 201,
            })
        }
        409 if code(&response).as_deref() == Some("heads_full") => Ok(Answer::Full),
        status => Err(PlaceFailure::Refused {
            status,
            code: code(&response),
        }),
    }
}

/// Upload one head set; on `heads_full`, free room once and try once more. The vault
/// is not marked here.
fn send(
    vault: &SharedVault,
    file: &Path,
    host: &str,
    record: &CandidateRecord,
    client: &BouncerClient,
    batch: &[String],
) -> Result<Placed, PlaceFailure> {
    let placed = |created, freed| Placed {
        candidate_id: record.id,
        host: host.to_owned(),
        heads: record.heads_sha256().to_owned(),
        created,
        freed,
    };
    if record.is_on_host(host) {
        return Ok(placed(false, Vec::new()));
    }
    let upload = upload_of(record)?;
    let full = || PlaceFailure::Refused {
        status: 409,
        code: Some("heads_full".to_owned()),
    };
    match put(client, &upload)? {
        Answer::Stored { created } => Ok(placed(created, Vec::new())),
        Answer::Full => {
            let freed = free_room(vault, file, host, client, &upload.heads, batch)?;
            if freed.is_empty() {
                return Err(full());
            }
            match put(client, &upload)? {
                Answer::Stored { created } => Ok(placed(created, freed)),
                Answer::Full => Err(full()),
            }
        }
    }
}

/// Delete the head set of the oldest replaced candidate on `host` that no current
/// head set shares (the active one, the shadow one, `heads`, and `batch`). A head set
/// that the server no longer has (404) is unmarked, and the next one is tried. Returns
/// the candidates whose rows lost the host; empty when nothing was freed.
fn free_room(
    vault: &SharedVault,
    file: &Path,
    host: &str,
    client: &BouncerClient,
    heads: &str,
    batch: &[String],
) -> Result<Vec<u64>, PlaceFailure> {
    let (mut victims, keep) = with_vault(vault, file, |vault| {
        let mut keep: Vec<String> = batch.to_vec();
        keep.push(heads.to_owned());
        keep.extend(active_heads(vault)?);
        if let Some(shadow) = vault.shadow_candidate()? {
            keep.push(shadow.heads_sha256().to_owned());
        }
        Ok((vault.candidates(MAX_CANDIDATES)?, keep))
    })?;
    // Oldest first.
    victims.reverse();
    let mut freed = Vec::new();
    let mut tried: Vec<String> = Vec::new();
    for victim in &victims {
        let sha = victim.heads_sha256();
        if victim.state != CandidateState::Replaced
            || !victim.is_on_host(host)
            || keep.iter().any(|kept| kept == sha)
            || tried.iter().any(|done| done == sha)
        {
            continue;
        }
        tried.push(sha.to_owned());
        let response = client.delete_heads(sha).map_err(call_failure)?;
        let deleted = match response.status {
            200 | 204 => true,
            404 => false,
            status => {
                return Err(PlaceFailure::Refused {
                    status,
                    code: code(&response),
                });
            }
        };
        // Every row with this head file on this host loses the host.
        let same: Vec<u64> = victims
            .iter()
            .filter(|row| row.heads_sha256() == sha && row.is_on_host(host))
            .map(|row| row.id)
            .collect();
        with_vault(vault, file, |vault| {
            for id in &same {
                vault.mark_candidate_uploaded(*id, None)?;
            }
            Ok(())
        })?;
        freed.extend(same);
        if deleted {
            return Ok(freed);
        }
    }
    // Only head sets that were gone already: nothing made room.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_messages_name_the_host_and_the_no_key_case() {
        let mac = PlaceError::new(THIS_MAC_HOST, PlaceFailure::NoKey);
        assert_eq!(mac.message(), NO_KEY_THIS_MAC);
        let mac = PlaceError::new(
            THIS_MAC_HOST,
            PlaceFailure::Refused {
                status: 403,
                code: Some("no_token".to_owned()),
            },
        );
        assert_eq!(mac.message(), NO_KEY_THIS_MAC);
        let server = PlaceError::new(
            "https://brain.synthetic.ts.net",
            PlaceFailure::Refused {
                status: 409,
                code: Some("heads_full".to_owned()),
            },
        );
        let text = server.message();
        assert!(
            text.starts_with(
                "The bouncer brain server https://brain.synthetic.ts.net stores no more"
            ),
            "{text}"
        );
        assert!(
            PlaceError::new("https://brain.synthetic.ts.net", PlaceFailure::Unreachable)
                .message()
                .contains("Try again")
        );
    }
}
