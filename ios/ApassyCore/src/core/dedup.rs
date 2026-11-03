//! Duplicate cleanup (contract section 5.3a): the duplicate groups of the vault, and
//! the merge of a group into one item. The rules are the vault's
//! (`src/vault/dedup.rs`), the same as on the Mac. No answer holds a value: the
//! differences and the reasons are labels.

use apassy::vault::{DuplicateGroup, MergeRefusal, Vault, VaultErrorKind};
use serde::{Deserialize, Serialize};

use super::errors::{CoreError, CoreResult};
use super::items::kind_str;

#[derive(Debug, Serialize)]
pub struct Member {
    pub id: u64,
    pub title: String,
    pub kind: &'static str,
    pub revision: u64,
    pub has_passkey: bool,
    pub changed_at: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct Group {
    pub items: Vec<Member>,
    pub keep: u64,
    pub differences: Vec<String>,
    pub identical: bool,
    pub mergeable: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Groups {
    pub groups: Vec<Group>,
}

#[derive(Deserialize)]
pub struct OtherIn {
    pub id: u64,
    pub revision: u64,
}

#[derive(Deserialize)]
pub struct MergeIn {
    pub keep: u64,
    pub keep_revision: u64,
    pub others: Vec<OtherIn>,
}

#[derive(Debug, Serialize)]
pub struct Merged {
    pub id: u64,
    pub revision: u64,
    pub archived: Vec<u64>,
}

fn group(group: DuplicateGroup) -> Group {
    Group {
        items: group
            .items
            .into_iter()
            .map(|member| Member {
                id: member.id,
                title: member.title,
                kind: kind_str(member.kind),
                revision: member.revision,
                has_passkey: member.has_passkey,
                changed_at: member.changed_at,
            })
            .collect(),
        keep: group.keep,
        differences: group.differences,
        identical: group.identical,
        mergeable: group.mergeable,
        reason: group.reason,
    }
}

/// `duplicates`: every duplicate group of the active items.
pub fn groups(vault: &Vault) -> CoreResult<Groups> {
    Ok(Groups {
        groups: vault.duplicate_groups()?.into_iter().map(group).collect(),
    })
}

/// The error of a refused merge: `too_large` for a limit, else `invalid_input` with the
/// reason.
fn refusal(refusal: MergeRefusal) -> CoreError {
    match refusal {
        MergeRefusal::TooManyFields => CoreError::new(
            "too_large",
            "The merged item would be over the limits of an item. Merge fewer items, or remove details first.",
        ),
        MergeRefusal::TwoPasskeys => {
            CoreError::invalid("These items hold two different passkeys. Apassy cannot merge them.")
        }
        MergeRefusal::KeepPasskey => {
            CoreError::invalid("Keep the item with the passkey. Choose it, then merge.")
        }
        MergeRefusal::PasskeyElsewhere => CoreError::invalid(
            "The passkey of these items is on another item. Apassy cannot merge them.",
        ),
        MergeRefusal::UsedByAgents => CoreError::invalid(
            "Agents use these items in a way that cannot move. Change the agent settings on the Mac first.",
        ),
    }
}

/// `duplicates_merge`: keep one item of a group and archive the others.
pub fn merge(vault: &mut Vault, request: MergeIn) -> CoreResult<Merged> {
    if request.others.is_empty() {
        return Err(CoreError::invalid(
            "Choose at least one other item to merge.",
        ));
    }
    let others: Vec<(u64, u64)> = request
        .others
        .iter()
        .map(|other| (other.id, other.revision))
        .collect();
    match vault.merge_duplicates((request.keep, request.keep_revision), &others) {
        Ok(outcome) => Ok(Merged {
            id: outcome.id,
            revision: outcome.revision,
            archived: outcome.archived,
        }),
        Err(error) if error.kind() == VaultErrorKind::InvalidInput => {
            let ids: Vec<u64> = others.iter().map(|(id, _)| *id).collect();
            match vault.merge_refusal(request.keep, &ids) {
                Ok(Some(reason)) => Err(refusal(reason)),
                Err(error) if error.kind() != VaultErrorKind::InvalidInput => Err(error.into()),
                _ => Err(CoreError::invalid(
                    "These items are not duplicates of each other now. Look for duplicates again.",
                )),
            }
        }
        Err(error) => Err(error.into()),
    }
}
