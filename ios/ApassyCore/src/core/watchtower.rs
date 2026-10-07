//! Watchtower (contract section 9): weak, reused, and old passwords, and conflict
//! copies. Each password is read in memory, hashed, and erased; the answer has item
//! IDs only.

use std::collections::BTreeMap;

use ring::digest;
use serde::Serialize;

use apassy::vault::Vault;

use super::errors::CoreResult;
use super::generate::strength;
use super::items::{self, Archived};

const OLD_AFTER: u64 = 365 * 86_400;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Report {
    pub weak: Vec<u64>,
    pub reused: Vec<Vec<u64>>,
    pub old: Vec<u64>,
    pub conflicts: Vec<u64>,
    pub checked: usize,
}

pub fn report(vault: &Vault, now: u64) -> CoreResult<Report> {
    let rows = items::rows(vault, Archived::No)?;
    let mut weak = Vec::new();
    let mut old = Vec::new();
    let mut conflicts = Vec::new();
    let mut groups: BTreeMap<Vec<u8>, Vec<u64>> = BTreeMap::new();
    let mut checked = 0;
    for row in &rows {
        if row.conflict_of.is_some() {
            conflicts.push(row.id);
        }
        let details = vault.details(row.id)?;
        let Some(field) = details
            .fields
            .iter()
            .find(|field| field.secret && items::field_role(&field.name, true) == "password")
        else {
            continue;
        };
        let password = vault.reveal(row.id, &field.name)?;
        checked += 1;
        if strength(password.expose()).score < 2 {
            weak.push(row.id);
        }
        let hash = digest::digest(&digest::SHA256, password.expose().as_bytes());
        groups
            .entry(hash.as_ref().to_vec())
            .or_default()
            .push(row.id);
        if row
            .changed_at
            .is_some_and(|changed| changed + OLD_AFTER < now)
        {
            old.push(row.id);
        }
    }
    let mut reused: Vec<Vec<u64>> = groups.into_values().filter(|ids| ids.len() > 1).collect();
    for ids in &mut reused {
        ids.sort_unstable();
    }
    reused.sort();
    weak.sort_unstable();
    old.sort_unstable();
    conflicts.sort_unstable();
    Ok(Report {
        weak,
        reused,
        old,
        conflicts,
        checked,
    })
}
