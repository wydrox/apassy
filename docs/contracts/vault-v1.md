# Experimental passphrase vault API

Date: 2026-09-16.
Status: experimental backend contract. See [local verification](../operations/vault-verification.md) for measured results and limits.
Schema version 2 (2026-09-25) adds agent, grant, destination, and activity tables. See section 9 of the [broker contract](broker-v0.md). The item API in this document did not change. Item delete also removes the grants and the destination of the item. Restore also revokes all agents.
The owner selected SQLCipher with a master passphrase after the synthetic storage probe passed.
This contract does not permit real-secret use or claim complete P2 acceptance.

## Scope and boundary

The `vault` feature provides an encrypted local backend in `apassy::vault`.
These APIs are trusted-process internals. They are not agent endpoints or an authenticated owner transport.
With `desktop` and `vault` both enabled, the owner vault and item views call this API. Rules, agents, and activity stay in-memory fixtures. A desktop build without `vault` stays the in-memory demo.
No CLI secret output, clipboard operation, network call, or Keychain operation is added.

The backend uses one SQLCipher database for items and metadata. It does not add a plaintext search index.
SQLCipher uses its existing KDF and HMAC settings. No custom cipher, password hash, or weakened KDF is permitted.
The master passphrase is also needed to restore an encrypted backup. Lost passphrases have no bypass or reset path in this phase.
No separate recovery key or automatic Keychain unlock is included.

## Frozen Rust API

All types below are in `apassy::vault`. Use `CredentialKind` from `apassy::contracts`.

```rust
pub struct SecretValue; // private String; new(String), expose(&self) -> &str
// SecretValue: Clone, PartialEq, Eq; Debug is redacted; no public Serialize.
pub struct Field {
    pub name: String,
    pub value: SecretValue,
    pub secret: bool,
}
pub struct ItemDraft {
    pub title: String,
    pub kind: CredentialKind,
    pub notes: String,
    pub tags: Vec<String>,
    pub fields: Vec<Field>,
}
// Field and ItemDraft: Clone and redacted Debug, no public Serialize.
pub struct ItemSummary {
    pub id: u64,
    pub title: String,
    pub kind: CredentialKind,
    pub revision: u64,
}
pub struct FieldSummary { pub name: String, pub secret: bool }
pub struct ItemDetails {
    pub summary: ItemSummary,
    pub notes: String,
    pub tags: Vec<String>,
    pub fields: Vec<FieldSummary>,
}
// Summary and detail types: Debug, Clone, PartialEq, Eq. No field values.
// ItemDetails Debug redacts notes. The notes field remains explicit metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultErrorKind {
    Locked, AlreadyExists, NotFound, Conflict, InvalidInput,
    WrongKeyOrCorrupt, UnsupportedSchema, Busy, Io, Storage,
}
pub struct VaultError; // Debug + Display + std::error::Error; kind(&self) -> VaultErrorKind
pub type VaultResult<T> = Result<T, VaultError>;
pub struct Vault; // private connection and path; redacted Debug; not Clone or Serialize
impl Vault {
    pub fn create(path: &std::path::Path, passphrase: &str) -> VaultResult<Self>;
    pub fn open(path: &std::path::Path) -> VaultResult<Self>;
    pub fn unlock(&mut self, passphrase: &str) -> VaultResult<()>;
    pub fn lock(&mut self) -> VaultResult<()>;
    pub fn is_locked(&self) -> bool;
    pub fn epoch(&self) -> [u8; 32];
    pub fn add(&mut self, draft: ItemDraft) -> VaultResult<ItemSummary>;
    pub fn update(&mut self, id: u64, expected_revision: u64, draft: ItemDraft) -> VaultResult<ItemSummary>;
    pub fn delete(&mut self, id: u64, expected_revision: u64) -> VaultResult<()>;
    pub fn search(&self, query: &str) -> VaultResult<Vec<ItemSummary>>;
    pub fn details(&self, id: u64) -> VaultResult<ItemDetails>;
    pub fn reveal(&self, id: u64, field_name: &str) -> VaultResult<SecretValue>;
    pub fn backup(&mut self, destination: &std::path::Path) -> VaultResult<()>;
    pub fn restore(backup: &std::path::Path, destination: &std::path::Path, passphrase: &str) -> VaultResult<Self>;
}
```

## Data checks

Creation requires a passphrase of 12 to 1024 UTF-8 bytes. Empty or oversized input is refused.
Creation, unlock, and restore refuse NUL bytes and the reserved leading `x'` or `X'` syntax with `InvalidInput`.
SQLCipher can interpret that syntax as a raw key and bypass password derivation. Other quotes and Unicode text remain permitted.
Draft title: 1 to 128 bytes after trim. Notes: at most 8192 bytes.
At most 32 tags, each 1 to 64 bytes. At most 64 uniquely named fields.
Field names: 1 to 64 bytes, ASCII letters, digits, and underscores. Field values: at most 65536 bytes.
A stored payload must not exceed 1048576 bytes. Reject excessive input, do not truncate it.

Required fields are case-sensitive:

| Kind | Required fields | Fields that must be marked secret |
| --- | --- | --- |
| ApiKey | `token` | `token` |
| Login | `username`, `password` | `password` |
| SshKey | `private_key` | `private_key`, and `passphrase` when present |
| Database | `host`, `database`, `username`, `password` | `password` |
| Custom | At least one named field | Owner-specified flags |

Required values must not be empty. Extra fields are permitted within the same bounds.
Search is a literal search over title, notes, and tags only. It must not match field values.
Case-insensitive comparison uses Rust Unicode lowercase mapping, not locale-aware comparison or full case folding.
Search returns at most 1000 summaries. If the matching result exceeds that limit, return `InvalidInput`, not a silent partial list.
Invalid draft changes leave the previous item intact. Update and delete require the current revision.
An update cannot change the item category. A different category returns `InvalidInput` without a stored change.
IDs are positive and are not reused after deletion. Revisions increase on item edits, not reveals or searches.

## Storage and lifecycle

Create refuses every existing target. Open does not create a missing file. Both start locked.
Unlock verifies an actual encrypted schema read and the supported schema version before any data API is available.
Missing or wrong keys and damaged encrypted schema return a sanitized error and leave the backend locked.
Repeated unlock must not preserve a connection after a failed passphrase attempt.
Every constructor, lock, and unlock attempt requests a fresh 32-byte epoch from `getrandom::fill`.
Unlock closes the previous connection and changes the epoch before it checks the passphrase. A refused or wrong passphrase ends the previous epoch.
If entropy is unavailable, the operation fails with the connection closed. A new epoch cannot be guaranteed on that error.
Epochs are invalidation data, not authentication tokens. No agent sessions or approvals exist in this backend yet.

Create and backup use exclusive file creation with Unix mode 0600. Refuse symlink targets.
Hold a nonblocking `std::fs::File::try_lock` on a persistent adjacent `<canonical-db-path>.lock` file for the vault lifetime, including locked state.
New lock files use mode 0600. Do not truncate or remove an existing lock file.
Other instances of this backend must return `Busy` for the same file.
Refuse hard-linked database and lock files to prevent alternate names from bypassing this lock.
Use absolute canonical database paths and disable SQLite URI handling. Relative paths and special SQLite names must identify actual filesystem files.
Database and backup names cannot end in `.lock`, `-journal`, `-wal`, or `-shm`, without regard to ASCII case.
These suffixes belong to lock and SQLite companion files. New targets with existing SQLite companions return `AlreadyExists` before any database write.
Restore accepts only a closed single-file source. Existing source journal, WAL, or SHM files cause `InvalidInput`, without changes to those files.
Backup also refuses remaining source companions after it closes the connection. It checks them before it creates a destination sidecar.
Vault and backup parent directories must permit lock-file creation when the sidecar is absent.
The separate lock file replaces a direct database lock. A local probe showed that the direct lock blocks SQLite writes on this host.
This advisory lock does not isolate an unrestricted same-user process or an arbitrary SQLite client.
Do not claim resistance to hostile parent-directory replacement or all filesystem races.

Use parameterized SQL, immediate write transactions, `temp_store=MEMORY`, and DELETE journal mode.
Set `secure_delete=ON` and verify the value for writable sessions. This does not erase old backups, memory, or filesystem snapshots.
Do not enable extension loading or the plaintext SQLite backup API.
Backup requires an unlocked vault, closes its connection before the encrypted copy, and leaves the source locked, even on copy failure.
Keep the source file lock while copying. Refuse an existing destination and sync the new file.
Restore holds the source lock through validation and copy. An in-use source returns `Busy`.
Restore validates the encrypted source with the supplied passphrase before creating a new destination.
It reserves the destination sidecar before key validation and retains that lock without an unlocked gap.
A refused restore can leave an empty persistent destination sidecar, but it does not create the destination database.
It must not overwrite either source or destination. The restored instance starts locked with a fresh epoch.
Unlock and restore check the encrypted schema, supported `user_version`, expected columns, and database integrity before they succeed.

## Remaining limits

Passphrases and decrypted data exist in process memory. SQLCipher key setup also makes a temporary SQL string.
Redacted Debug is not memory erasure or a defense against memory inspection, swap, or crash dumps.
A completed file copy is not proof of crash-safe directory-entry persistence or a complete recovery product.
Schema migration, rekey, authenticated reveal, durable agent authority, product isolation, and native-code review remain separate gates.
Tests use temporary synthetic data only. No real credential or passphrase belongs in repository fixtures or logs.
