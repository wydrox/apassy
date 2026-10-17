//! Owner library search. Identity values are inspected only in the unlocked vault;
//! no plaintext index or query history is stored.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use super::types::{MAX_SEARCH_RESULTS, VaultErrorKind, VaultResult, err};
use super::{ItemSummary, Vault, kind_from_str, search_metadata, to_public_id, to_public_revision};

impl Vault {
    /// Search metadata and the visible identity fields `username`, `website`, and
    /// `host`, using the same literal Unicode lowercase matching as [`Vault::search`].
    /// Secret fields, custom fields, passkeys and setup keys never participate. Results
    /// contain only item metadata and are ordered by ID. Requires an unlocked vault.
    pub fn search_identities(&self, query: &str) -> VaultResult<Vec<ItemSummary>> {
        let conn = self.conn_ref()?;
        let mut found: BTreeMap<_, _> = search_metadata(conn, query)?
            .into_iter()
            .map(|item| (item.id, item))
            .collect();
        // All metadata already matches an empty query. Do not read any identities.
        if query.is_empty() {
            return Ok(found.into_values().collect());
        }
        let storage = |_| err(VaultErrorKind::Storage);
        let needle = Zeroizing::new(query.to_lowercase());
        let mut stmt = conn
            .prepare(
                "SELECT i.id, i.title, i.kind, i.revision, f.name, f.value
                 FROM item i JOIN item_field f ON f.item_id = i.id
                 WHERE f.secret = 0 AND f.name IN ('username', 'website', 'host')
                 ORDER BY i.id, f.position",
            )
            .map_err(storage)?;
        let mut rows = stmt.query([]).map_err(storage)?;
        while let Some(row) = rows.next().map_err(storage)? {
            let id = to_public_id(row.get(0).map_err(storage)?)?;
            if found.contains_key(&id) {
                continue;
            }
            let name: String = row.get(4).map_err(storage)?;
            let value = Zeroizing::new(row.get::<_, String>(5).map_err(storage)?);
            if super::is_setup_key_field(&name, &value) {
                continue;
            }
            let normalized = Zeroizing::new(value.to_lowercase());
            if !normalized.contains(needle.as_str()) {
                continue;
            }
            if found.len() >= MAX_SEARCH_RESULTS {
                return Err(err(VaultErrorKind::InvalidInput));
            }
            found.insert(
                id,
                ItemSummary {
                    id,
                    title: row.get(1).map_err(storage)?,
                    kind: kind_from_str(&row.get::<_, String>(2).map_err(storage)?)?,
                    revision: to_public_revision(row.get(3).map_err(storage)?)?,
                },
            );
        }
        Ok(found.into_values().collect())
    }
}
