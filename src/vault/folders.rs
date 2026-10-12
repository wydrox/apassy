//! Folders of the vault (schema 18, ADR 0026 §5).
//!
//! A folder has a random UUID, a name, an optional parent, and a position among its
//! siblings. A credential is in at most one folder (`item_folder`, a child row of the
//! credential); a credential without a folder is at the top level. Folders nest to
//! [`MAX_FOLDER_DEPTH`] levels.
//!
//! Folder rows sync one by one: the later `(updated_at, updated_by)` wins
//! (`merge::merge_lww`). `created_at` and `deleted_at` are Unix seconds; `updated_at` is
//! Unix milliseconds, the version of the row. A deleted folder keeps its row with
//! `deleted_at`, so the delete reaches the other Macs.
//!
//! Two Macs can make a state that this API refuses: a credential or a folder in a folder
//! that the other Mac deleted, or a cycle of two moves. The reads resolve it: a parent
//! that is gone counts as the top level, and a cycle is cut at the folder with the
//! smallest UUID. Moving a credential changes nothing else; deleting a folder never
//! deletes a credential.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::history::{self, ItemEventKind};
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, agents, to_hex, to_public_id, to_sql_id};

/// A folder name has at most this many bytes.
pub const MAX_FOLDER_NAME_BYTES: usize = 64;
/// Folders nest at most this many levels: a folder at the top level is level 1.
pub const MAX_FOLDER_DEPTH: usize = 4;

/// The separator of a folder path in the detail of a "moved" event.
const PATH_SEPARATOR: &str = " / ";

/// A folder that is not deleted. `parent` is `None` at the top level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub uuid: String,
    pub parent: Option<String>,
    pub name: String,
    pub position: i64,
}

/// The folders that are not deleted, with each parent resolved (see the module
/// documentation).
struct Tree {
    folders: BTreeMap<String, Folder>,
}

impl Tree {
    fn load(conn: &Connection) -> VaultResult<Self> {
        let storage = |_| err(VaultErrorKind::Storage);
        let mut stmt = conn
            .prepare(
                "SELECT uuid, parent_uuid, name, position FROM folder
                 WHERE deleted_at IS NULL",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(Folder {
                    uuid: row.get(0)?,
                    parent: row.get(1)?,
                    name: row.get(2)?,
                    position: row.get(3)?,
                })
            })
            .map_err(storage)?;
        let mut folders = BTreeMap::new();
        for row in rows {
            let folder = row.map_err(storage)?;
            folders.insert(folder.uuid.clone(), folder);
        }
        // A parent that is gone counts as the top level.
        let live: BTreeSet<String> = folders.keys().cloned().collect();
        for folder in folders.values_mut() {
            if folder
                .parent
                .as_ref()
                .is_some_and(|parent| !live.contains(parent) || *parent == folder.uuid)
            {
                folder.parent = None;
            }
        }
        let mut tree = Self { folders };
        tree.cut_cycles();
        Ok(tree)
    }

    /// Cut each cycle at the folder with the smallest UUID: it goes to the top level.
    fn cut_cycles(&mut self) {
        let uuids: Vec<String> = self.folders.keys().cloned().collect();
        for start in uuids {
            loop {
                let mut path: Vec<String> = Vec::new();
                let mut at = Some(start.clone());
                let mut cycle = None;
                while let Some(uuid) = at {
                    if let Some(index) = path.iter().position(|seen| *seen == uuid) {
                        cycle = path[index..].iter().min().cloned();
                        break;
                    }
                    at = self.folders.get(&uuid).and_then(|f| f.parent.clone());
                    path.push(uuid);
                }
                match cycle.and_then(|cut| self.folders.get_mut(&cut)) {
                    Some(folder) => folder.parent = None,
                    None => break,
                }
            }
        }
    }

    fn get(&self, uuid: &str) -> VaultResult<&Folder> {
        self.folders
            .get(uuid)
            .ok_or_else(|| err(VaultErrorKind::NotFound))
    }

    /// The level of `uuid`: 1 at the top level.
    fn depth(&self, uuid: &str) -> usize {
        let mut depth = 0;
        let mut at = Some(uuid);
        while let Some(uuid) = at {
            depth += 1;
            at = self.folders.get(uuid).and_then(|f| f.parent.as_deref());
        }
        depth
    }

    /// The levels of `uuid` and the folders below it: 1 without subfolders.
    fn height(&self, uuid: &str) -> usize {
        1 + self
            .children(Some(uuid))
            .iter()
            .map(|child| self.height(&child.uuid))
            .max()
            .unwrap_or(0)
    }

    /// The subfolders of `parent` (`None`: the top level), by position, name, and UUID.
    fn children(&self, parent: Option<&str>) -> Vec<&Folder> {
        let mut children: Vec<&Folder> = self
            .folders
            .values()
            .filter(|folder| folder.parent.as_deref() == parent)
            .collect();
        children
            .sort_by(|a, b| (a.position, &a.name, &a.uuid).cmp(&(b.position, &b.name, &b.uuid)));
        children
    }

    /// `uuid` and every folder below it.
    fn subtree(&self, uuid: &str) -> BTreeSet<String> {
        let mut all = BTreeSet::from([uuid.to_owned()]);
        for child in self.children(Some(uuid)) {
            all.extend(self.subtree(&child.uuid));
        }
        all
    }

    /// The names from the top level to `uuid`.
    fn path(&self, uuid: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut at = self.folders.get(uuid);
        while let Some(folder) = at {
            names.push(folder.name.clone());
            at = folder.parent.as_deref().and_then(|p| self.folders.get(p));
        }
        names.reverse();
        names
    }

    /// Every folder, depth first, each level in the order of [`Tree::children`].
    fn ordered(&self) -> Vec<Folder> {
        fn walk(tree: &Tree, parent: Option<&str>, out: &mut Vec<Folder>) {
            for child in tree.children(parent) {
                out.push(child.clone());
                walk(tree, Some(&child.uuid), out);
            }
        }
        let mut out = Vec::new();
        walk(self, None, &mut out);
        out
    }

    /// A sibling of `parent` other than `except` has `name` (case-insensitive).
    fn name_taken(&self, parent: Option<&str>, name: &str, except: Option<&str>) -> bool {
        let lower = name.to_lowercase();
        self.children(parent).iter().any(|folder| {
            Some(folder.uuid.as_str()) != except && folder.name.to_lowercase() == lower
        })
    }

    /// The position after the last subfolder of `parent`.
    fn next_position(&self, parent: Option<&str>) -> i64 {
        self.children(parent)
            .iter()
            .map(|folder| folder.position)
            .max()
            .map_or(0, |last| last.saturating_add(1))
    }

    /// The folder of a credential from its stored folder UUID: `None` when that folder
    /// is gone.
    fn resolve(&self, stored: Option<String>) -> Option<String> {
        stored.filter(|uuid| self.folders.contains_key(uuid))
    }
}

/// A folder name: trimmed, not empty, at most [`MAX_FOLDER_NAME_BYTES`], no control
/// characters.
fn clean_name(name: &str) -> VaultResult<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_FOLDER_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    Ok(name.to_owned())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// The version of a change by this device: now in Unix milliseconds and the device ID.
fn version(conn: &Connection) -> VaultResult<(i64, String)> {
    let device: Option<String> = conn
        .query_row(
            "SELECT device_id FROM sync_device WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok((now_ms(), device.unwrap_or_default()))
}

fn new_uuid() -> VaultResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| err(VaultErrorKind::Io))?;
    Ok(to_hex(&bytes))
}

/// The stored folder UUID of an item, as it is (it can name a folder that is gone).
fn stored_folder(conn: &Connection, item: i64) -> VaultResult<Option<String>> {
    conn.query_row(
        "SELECT folder_uuid FROM item_folder WHERE item_id = ?1",
        [item],
        |row| row.get(0),
    )
    .optional()
    .map_err(|_| err(VaultErrorKind::Storage))
}

/// Put the item in `folder` (`None`: the top level) and record a "moved" event with the
/// folder path. The caller checked the item and the folder.
fn move_item(
    tx: &rusqlite::Transaction<'_>,
    tree: &Tree,
    item: i64,
    folder: Option<&str>,
) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    match folder {
        Some(folder) => tx
            .execute(
                "INSERT INTO item_folder (item_id, folder_uuid) VALUES (?1, ?2)
                 ON CONFLICT(item_id) DO UPDATE SET folder_uuid = excluded.folder_uuid",
                (item, folder),
            )
            .map_err(storage)?,
        None => tx
            .execute("DELETE FROM item_folder WHERE item_id = ?1", [item])
            .map_err(storage)?,
    };
    let path = folder.map(|uuid| tree.path(uuid)).unwrap_or_default();
    history::record(tx, item, ItemEventKind::Moved, &path.join(PATH_SEPARATOR))
}

impl Vault {
    /// The folders that are not deleted, depth first; each level by position, name, and
    /// UUID.
    pub fn folders(&self) -> VaultResult<Vec<Folder>> {
        Ok(Tree::load(self.conn_ref()?)?.ordered())
    }

    /// Make a folder in `parent` (`None`: the top level), after its last subfolder.
    ///
    /// - `InvalidInput`: the name is empty, longer than [`MAX_FOLDER_NAME_BYTES`], or has
    ///   a control character, or the folder would be below [`MAX_FOLDER_DEPTH`].
    /// - `NotFound`: the parent is not a folder.
    /// - `AlreadyExists`: a sibling has the same name (case-insensitive).
    pub fn create_folder(&mut self, parent: Option<&str>, name: &str) -> VaultResult<Folder> {
        let name = clean_name(name)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let tree = Tree::load(&tx)?;
        let depth = match parent {
            Some(parent) => tree.get(parent).map(|_| tree.depth(parent))?,
            None => 0,
        };
        if depth + 1 > MAX_FOLDER_DEPTH {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if tree.name_taken(parent, &name, None) {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        let folder = Folder {
            uuid: new_uuid()?,
            parent: parent.map(str::to_owned),
            name,
            position: tree.next_position(parent),
        };
        let (at, by) = version(&tx)?;
        tx.execute(
            "INSERT INTO folder (uuid, parent_uuid, name, position, created_at, updated_at,
                 updated_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                &folder.uuid,
                &folder.parent,
                &folder.name,
                folder.position,
                at / 1000,
                at,
                &by,
            ),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(folder)
    }

    /// Rename a folder. The same name changes nothing. The errors are those of
    /// [`Vault::create_folder`].
    pub fn rename_folder(&mut self, uuid: &str, name: &str) -> VaultResult<()> {
        let name = clean_name(name)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let tree = Tree::load(&tx)?;
        let folder = tree.get(uuid)?;
        if folder.name == name {
            return Ok(());
        }
        if tree.name_taken(folder.parent.as_deref(), &name, Some(uuid)) {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        let (at, by) = version(&tx)?;
        tx.execute(
            "UPDATE folder SET name = ?1, updated_at = ?2, updated_by = ?3 WHERE uuid = ?4",
            (&name, at, &by, uuid),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Move a folder with its subfolders and credentials into `parent` (`None`: the top
    /// level), after its last subfolder. The same parent changes nothing.
    ///
    /// - `InvalidInput`: `parent` is the folder or one of its subfolders (a cycle), or the
    ///   deepest subfolder would be below [`MAX_FOLDER_DEPTH`].
    /// - `NotFound`: the folder or the parent is not a folder.
    /// - `AlreadyExists`: a folder in `parent` has the same name.
    pub fn move_folder(&mut self, uuid: &str, parent: Option<&str>) -> VaultResult<()> {
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let tree = Tree::load(&tx)?;
        let folder = tree.get(uuid)?;
        let depth = match parent {
            Some(parent) => {
                tree.get(parent)?;
                if tree.subtree(uuid).contains(parent) {
                    return Err(err(VaultErrorKind::InvalidInput));
                }
                tree.depth(parent)
            }
            None => 0,
        };
        if depth + tree.height(uuid) > MAX_FOLDER_DEPTH {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if folder.parent.as_deref() == parent {
            return Ok(());
        }
        if tree.name_taken(parent, &folder.name, Some(uuid)) {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        let (at, by) = version(&tx)?;
        tx.execute(
            "UPDATE folder SET parent_uuid = ?1, position = ?2, updated_at = ?3,
                 updated_by = ?4 WHERE uuid = ?5",
            (parent, tree.next_position(parent), at, &by, uuid),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Delete a folder. Its credentials and subfolders go to its parent (the top level
    /// when it has none); no credential is deleted. Each credential gets a "moved" event.
    /// Returns the count of credentials that moved. `NotFound`: not a folder.
    pub fn delete_folder(&mut self, uuid: &str) -> VaultResult<usize> {
        let storage = |_| err(VaultErrorKind::Storage);
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let tree = Tree::load(&tx)?;
        let parent = tree.get(uuid)?.parent.clone();
        let items: Vec<i64> = {
            let mut stmt = tx
                .prepare("SELECT item_id FROM item_folder WHERE folder_uuid = ?1 ORDER BY item_id")
                .map_err(storage)?;
            stmt.query_map([uuid], |row| row.get(0))
                .map_err(storage)?
                .collect::<Result<_, _>>()
                .map_err(storage)?
        };
        for item in &items {
            move_item(&tx, &tree, *item, parent.as_deref())?;
        }
        let (at, by) = version(&tx)?;
        let children: Vec<String> = tree
            .children(Some(uuid))
            .iter()
            .map(|child| child.uuid.clone())
            .collect();
        let mut position = tree.next_position(parent.as_deref());
        for child in children {
            tx.execute(
                "UPDATE folder SET parent_uuid = ?1, position = ?2, updated_at = ?3,
                     updated_by = ?4 WHERE uuid = ?5",
                (&parent, position, at, &by, &child),
            )
            .map_err(storage)?;
            position = position.saturating_add(1);
        }
        tx.execute(
            "UPDATE folder SET deleted_at = ?1, updated_at = ?2, updated_by = ?3 WHERE uuid = ?4",
            (at / 1000, at, &by, uuid),
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(items.len())
    }

    /// The folder of a credential. `None`: the top level, also when its folder is gone.
    /// `NotFound`: no such credential.
    pub fn item_folder(&self, item_id: u64) -> VaultResult<Option<String>> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_ref()?;
        let found: Option<Option<String>> = conn
            .query_row(
                "SELECT f.uuid FROM item i
                 LEFT JOIN item_folder p ON p.item_id = i.id
                 LEFT JOIN folder f ON f.uuid = p.folder_uuid AND f.deleted_at IS NULL
                 WHERE i.id = ?1",
                [item],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let stored = found.ok_or_else(|| err(VaultErrorKind::NotFound))?;
        // A folder in a cycle is still a folder, so the stored UUID is the answer.
        Ok(stored)
    }

    /// Put a credential in `folder` (`None`: the top level), with a "moved" event that
    /// syncs. The same folder changes nothing. `NotFound`: no such credential or folder.
    pub fn set_item_folder(&mut self, item_id: u64, folder: Option<&str>) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        agents::require_item(&tx, item)?;
        let tree = Tree::load(&tx)?;
        if let Some(folder) = folder {
            tree.get(folder)?;
        }
        if tree.resolve(stored_folder(&tx, item)?).as_deref() == folder {
            return Ok(());
        }
        move_item(&tx, &tree, item, folder)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// The names from the top level to `folder`; empty for `None`. `NotFound`: not a
    /// folder.
    pub fn folder_path(&self, folder: Option<&str>) -> VaultResult<Vec<String>> {
        let Some(folder) = folder else {
            return Ok(Vec::new());
        };
        let tree = Tree::load(self.conn_ref()?)?;
        tree.get(folder)?;
        Ok(tree.path(folder))
    }

    /// The credentials in `folder` by ID. `None` is the top level: the credentials
    /// without a folder or with a folder that is gone. `recursive` adds the credentials of
    /// the subfolders; with `None` that is every credential. Archived credentials count.
    /// `NotFound`: not a folder.
    pub fn items_in_folder(&self, folder: Option<&str>, recursive: bool) -> VaultResult<Vec<u64>> {
        let storage = |_| err(VaultErrorKind::Storage);
        let conn = self.conn_ref()?;
        let tree = Tree::load(conn)?;
        let wanted: Option<BTreeSet<String>> = match folder {
            Some(folder) => {
                tree.get(folder)?;
                Some(if recursive {
                    tree.subtree(folder)
                } else {
                    BTreeSet::from([folder.to_owned()])
                })
            }
            None => None,
        };
        let mut stmt = conn
            .prepare(
                "SELECT i.id, p.folder_uuid FROM item i
                 LEFT JOIN item_folder p ON p.item_id = i.id ORDER BY i.id",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .map_err(storage)?;
        let mut items = Vec::new();
        for row in rows {
            let (id, stored) = row.map_err(storage)?;
            let at = tree.resolve(stored);
            let inside = match (&wanted, at) {
                (Some(wanted), Some(at)) => wanted.contains(&at),
                (Some(_), None) => false,
                (None, at) => recursive || at.is_none(),
            };
            if inside {
                items.push(to_public_id(id)?);
            }
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, ItemEventKind, MAX_ITEM_EVENTS, SecretValue};

    const PASS: &str = "synthetic-folder-pass";

    fn vault(dir: &tempfile::TempDir) -> Vault {
        let mut vault = Vault::create(&dir.path().join("folders.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
    }

    fn add(vault: &mut Vault, title: &str) -> u64 {
        vault
            .add(ItemDraft {
                title: title.to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("SYNTH-folder-token".to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id
    }

    fn names(vault: &Vault) -> Vec<(String, Option<String>)> {
        let folders = vault.folders().unwrap();
        let name_of = |uuid: &str| {
            folders
                .iter()
                .find(|folder| folder.uuid == uuid)
                .unwrap()
                .name
                .clone()
        };
        folders
            .iter()
            .map(|folder| (folder.name.clone(), folder.parent.as_deref().map(name_of)))
            .collect()
    }

    #[test]
    fn create_rename_and_list_in_tree_order() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let work = v.create_folder(None, "  Work ").unwrap();
        assert_eq!(work.name, "Work");
        assert_eq!(work.position, 0);
        assert_eq!(work.uuid.len(), 32);
        let acme = v.create_folder(Some(&work.uuid), "Acme").unwrap();
        let home = v.create_folder(None, "Home").unwrap();
        assert_eq!(home.position, 1);
        assert_eq!(
            names(&v),
            [
                ("Work".to_owned(), None),
                ("Acme".to_owned(), Some("Work".to_owned())),
                ("Home".to_owned(), None),
            ]
        );
        v.rename_folder(&acme.uuid, "Acme billing").unwrap();
        assert_eq!(
            v.folder_path(Some(&acme.uuid)).unwrap(),
            ["Work", "Acme billing"]
        );
        assert!(v.folder_path(None).unwrap().is_empty());

        // Names: empty, too long, control characters, a sibling with the same name.
        for bad in ["", "   ", "a\nb", &"x".repeat(MAX_FOLDER_NAME_BYTES + 1)] {
            assert_eq!(
                v.create_folder(None, bad).unwrap_err().kind(),
                VaultErrorKind::InvalidInput,
                "{bad:?}"
            );
            assert_eq!(
                v.rename_folder(&work.uuid, bad).unwrap_err().kind(),
                VaultErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
        assert!(
            v.create_folder(None, &"ż".repeat(MAX_FOLDER_NAME_BYTES / 2))
                .is_ok()
        );
        assert_eq!(
            v.create_folder(None, "work").unwrap_err().kind(),
            VaultErrorKind::AlreadyExists
        );
        assert_eq!(
            v.rename_folder(&home.uuid, "WORK").unwrap_err().kind(),
            VaultErrorKind::AlreadyExists
        );
        // The same name in another folder is fine; a missing parent is not.
        v.create_folder(Some(&work.uuid), "Home").unwrap();
        assert_eq!(
            v.create_folder(Some("0123"), "Lost").unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            v.rename_folder("0123", "Lost").unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn depth_and_cycles_are_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let mut chain = Vec::new();
        let mut parent: Option<String> = None;
        for level in 1..=MAX_FOLDER_DEPTH {
            let folder = v
                .create_folder(parent.as_deref(), &format!("Level {level}"))
                .unwrap();
            parent = Some(folder.uuid.clone());
            chain.push(folder.uuid);
        }
        assert_eq!(
            v.create_folder(parent.as_deref(), "Too deep")
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        // A cycle: a folder into itself or below itself.
        for target in &chain {
            assert_eq!(
                v.move_folder(&chain[0], Some(target)).unwrap_err().kind(),
                VaultErrorKind::InvalidInput
            );
        }
        // Depth: level 2 with its two levels below goes under another top folder: 1 + 3.
        let other = v.create_folder(None, "Other").unwrap();
        v.move_folder(&chain[1], Some(&other.uuid)).unwrap();
        assert_eq!(
            v.folder_path(Some(&chain[3])).unwrap(),
            ["Other", "Level 2", "Level 3", "Level 4"]
        );
        // One level more is refused, and the tree stays.
        let deeper = v.create_folder(Some(&other.uuid), "Deeper").unwrap();
        assert_eq!(
            v.move_folder(&chain[1], Some(&deeper.uuid))
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        assert_eq!(
            v.folder_path(Some(&chain[3])).unwrap(),
            ["Other", "Level 2", "Level 3", "Level 4"]
        );
        // To the top level, and missing folders.
        v.move_folder(&chain[1], None).unwrap();
        assert_eq!(v.folder_path(Some(&chain[1])).unwrap(), ["Level 2"]);
        assert_eq!(
            v.move_folder("0123", None).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            v.move_folder(&chain[1], Some("0123")).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn items_move_with_a_synced_event_and_delete_moves_them_to_the_parent() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let b = add(&mut v, "Beta");
        let c = add(&mut v, "Gamma");
        let work = v.create_folder(None, "Work").unwrap();
        let acme = v.create_folder(Some(&work.uuid), "Acme").unwrap();
        let sub = v.create_folder(Some(&acme.uuid), "Sub").unwrap();
        v.set_item_folder(a, Some(&acme.uuid)).unwrap();
        v.set_item_folder(b, Some(&work.uuid)).unwrap();
        v.set_item_folder(c, Some(&sub.uuid)).unwrap();
        assert_eq!(
            v.item_folder(a).unwrap().as_deref(),
            Some(acme.uuid.as_str())
        );
        let moved = v.item_events(a, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(moved[0].kind, ItemEventKind::Moved);
        assert_eq!(moved[0].detail, "Work / Acme");
        assert!(super::super::merge::SYNCED_EVENT_KINDS.contains(&"moved"));
        // The same folder again records nothing.
        v.set_item_folder(a, Some(&acme.uuid)).unwrap();
        assert_eq!(
            v.item_events(a, MAX_ITEM_EVENTS).unwrap().len(),
            moved.len()
        );
        assert_eq!(v.items_in_folder(Some(&acme.uuid), false).unwrap(), [a]);
        assert_eq!(
            v.items_in_folder(Some(&work.uuid), true).unwrap(),
            [a, b, c]
        );
        assert!(v.items_in_folder(None, false).unwrap().is_empty());
        assert_eq!(v.items_in_folder(None, true).unwrap(), [a, b, c]);
        assert_eq!(
            v.set_item_folder(a, Some("0123")).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            v.set_item_folder(999, None).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        assert_eq!(
            v.item_folder(999).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );

        // Delete "Acme": its item and its subfolder go to "Work".
        assert_eq!(v.delete_folder(&acme.uuid).unwrap(), 1);
        assert_eq!(
            v.item_folder(a).unwrap().as_deref(),
            Some(work.uuid.as_str())
        );
        let events = v.item_events(a, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(events[0].kind, ItemEventKind::Moved);
        assert_eq!(events[0].detail, "Work");
        assert_eq!(v.folder_path(Some(&sub.uuid)).unwrap(), ["Work", "Sub"]);
        assert_eq!(
            v.item_folder(c).unwrap().as_deref(),
            Some(sub.uuid.as_str())
        );
        assert_eq!(
            v.folder_path(Some(&acme.uuid)).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
        // Delete "Work": everything goes to the top level; no credential is deleted.
        assert_eq!(v.delete_folder(&work.uuid).unwrap(), 2);
        assert_eq!(v.item_folder(a).unwrap(), None);
        assert_eq!(v.item_folder(b).unwrap(), None);
        assert_eq!(v.folder_path(Some(&sub.uuid)).unwrap(), ["Sub"]);
        assert_eq!(v.search("").unwrap().len(), 3);
        assert_eq!(v.items_in_folder(None, false).unwrap(), [a, b]);
        let events = v.item_events(b, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(
            (events[0].kind, events[0].detail.as_str()),
            (ItemEventKind::Moved, "")
        );
        // The deleted rows stay for sync.
        let rows: i64 = v
            .conn_ref()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM folder WHERE deleted_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 2);
        assert_eq!(
            v.delete_folder(&work.uuid).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }

    #[test]
    fn a_folder_that_is_gone_or_a_cycle_reads_as_the_top_level() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let x = v.create_folder(None, "X").unwrap();
        let y = v.create_folder(None, "Y").unwrap();
        // As after a merge: the item names a folder that only the other Mac knows, and
        // two concurrent moves made a cycle.
        let conn = v.conn_ref().unwrap();
        conn.execute(
            "INSERT INTO item_folder (item_id, folder_uuid) VALUES (?1, 'ffff')",
            [a as i64],
        )
        .unwrap();
        conn.execute(
            "UPDATE folder SET parent_uuid = ?1 WHERE uuid = ?2",
            (&y.uuid, &x.uuid),
        )
        .unwrap();
        conn.execute(
            "UPDATE folder SET parent_uuid = ?1 WHERE uuid = ?2",
            (&x.uuid, &y.uuid),
        )
        .unwrap();
        assert_eq!(v.item_folder(a).unwrap(), None);
        assert_eq!(v.items_in_folder(None, false).unwrap(), [a]);
        let cut = x.uuid.clone().min(y.uuid.clone());
        let folders = v.folders().unwrap();
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].uuid, cut);
        assert_eq!(folders[0].parent, None);
        assert_eq!(folders[1].parent.as_deref(), Some(cut.as_str()));
        // Each still works.
        v.set_item_folder(a, Some(&x.uuid)).unwrap();
        assert_eq!(v.item_folder(a).unwrap().as_deref(), Some(x.uuid.as_str()));
        v.set_item_folder(a, None).unwrap();
        assert_eq!(v.item_folder(a).unwrap(), None);
    }

    #[test]
    fn deleting_an_item_removes_its_folder_row() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut v = vault(&dir);
        let a = add(&mut v, "Alpha");
        let work = v.create_folder(None, "Work").unwrap();
        v.set_item_folder(a, Some(&work.uuid)).unwrap();
        let revision = v.details(a).unwrap().summary.revision;
        v.delete(a, revision).unwrap();
        assert!(
            v.items_in_folder(Some(&work.uuid), true)
                .unwrap()
                .is_empty()
        );
        let rows: i64 = v
            .conn_ref()
            .unwrap()
            .query_row("SELECT count(*) FROM item_folder", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0);
    }
}
