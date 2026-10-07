# Import from 1Password

Date: 2026-09-28.
Scope: the import of a 1Password export into the vault (0.3.0). Code: `src/import/` (the readers and the mapping) and `src/desktop/ui/import.rs` (the sheet).
Use only synthetic values for tests.

## 1. Export from 1Password

1. Open 1Password 8 and unlock it.
2. Choose File > Export, then the account.
3. Choose the format 1PUX. Type the account password. 1Password saves a file such as `1PasswordExport-….1pux`.

1PUX has every item with all its fields. CSV works too, but it has only the title, the website, the username, the password, the one-time password, the tags, and the notes. A CSV export has no API credentials, SSH keys, databases, or servers. Apassy does not read the 1PIF format of 1Password 7.

The export file is not encrypted. Anyone who can read it has your secrets. Section 5 says what to do with it.

## 2. Import

1. Unlock the vault.
2. Open Settings > General > Import > "Import from 1Password…".
3. Type the path of the export file, or drop the file on the window. `~/` is your home folder. Click "Read".
4. Apassy shows each item: the title, the 1Password vault, the 1Password category, the Apassy kind, and warnings. Nothing is in the vault yet.
5. Check the selection. Click "Import N credentials".
6. Apassy adds each selected item. A failed item does not stop the import. The result lists it with the reason.
7. Click "Delete the export file" (section 5).

Apassy is for the credentials that agents use. So the first selection has API credentials, SSH keys, databases, and servers. Logins, passwords, secure notes, other categories, and CSV rows are not selected. "Select all" and "Select none" change the whole list.

An item with the same title (case is ignored) and the same kind as a credential in the vault is not selected. The preview marks it "Already in the vault".

No agent gets access. An imported credential has no grant, no environment variable, and no declaration. An agent that sees all credentials sees the name, the kind, and the visible details of an imported credential, as for any other credential.

## 3. What maps to what

| 1Password category | Apassy kind | Fields | Selected first |
| --- | --- | --- | --- |
| API Credential | API key | "credential" is the token. The other fields are details. | Yes |
| SSH Key | SSH key | The private key in the OpenSSH form, and the public key. The fingerprint and the key type are visible details. | Yes |
| Database | Database | Server (host), database, username, and password. Type, port, SID, alias, and options are details. Without all four: a custom secret. | Yes |
| Server | Login | Username and password. The URL and the admin console fields are details. Without a username: a custom secret. | Yes |
| Login | Login | The username and the password of the login form. The websites and the one-time password are details. Without a username: a custom secret. | No |
| Password | Custom | The password is the field `secret`. | No |
| Secure Note | Custom | The note text is the hidden field `note`. The notes of the credential stay empty. | No |
| Email Account, Software License, Wireless Router, and other categories | Custom | The password, or the first hidden value, is the field `secret`. The preview has a warning. | No |
| Credit Card, Identity, Document, Bank Account, Driver License, Outdoor License, Membership, Passport, Reward Program, Social Security Number, Medical Record, Crypto Wallet | Not imported | The preview shows the item with the reason. | Cannot be selected |
| CSV row | Login, or Custom | Username and password make a login. A password alone makes a custom secret. Another column with a value is a hidden detail. | No |

The fields of an item:

- A concealed field is a hidden detail. A one-time password (TOTP) is a hidden detail "One-time password".
- A text field is a visible detail only when its name is a known plain name: username, host, server, port, database, URL, type, and a few more. Any other text field is a hidden detail, because a text field can hold a secret. You can make a detail visible later in the item form.
- A URL, an email address, a phone number, a menu choice, a date (`YYYY-MM-DD`), and a month (`YYYY-MM`) are visible details.
- The websites of an item are visible details "Website", "Website 2", and so on.
- The notes of the 1Password item are the notes of the credential. Notes are searchable. They are at most 8 KB. Longer notes are shortened, with a warning.
- The tags are the 1Password tags and `1password`. They are searchable. An edit of the credential keeps them.
- The title is at most 128 bytes. A longer title is shortened, with a warning.
- A secret never goes into the title, the notes, or the tags.
- An item has at most 10 details. A detail label has at most 31 bytes, and two labels differ (Apassy adds " 2", " 3"). When an item has more values, Apassy leaves out visible details first, from the end, then hidden ones. The preview has a warning for each value that it leaves out. The warning names the label, never the value.
- An item that is archived in 1Password is not selected. When you import it, Apassy archives it too.

## 4. What is not imported

- Items in the 1Password trash.
- The categories in the table above that Apassy does not import.
- Attachments and documents. Apassy does not read the `files/` folder of the 1PUX archive.
- Links to other items, addresses, and other field types that Apassy does not know. The preview has a warning.
- The password history, favorites, icons, and the vault structure. The preview shows the 1Password vault name. The credential does not keep it.
- Web form fields of a login other than the username, the password, and password fields.

## 5. The export file afterwards

The export file holds your secrets in plain text. After the import:

1. Click "Delete the export file" in the result, or delete the file in Finder.
2. Empty the Trash if the file is in it.
3. A Time Machine backup, a cloud folder, or another copy of the file holds the secrets too. Delete those copies.

On an SSD, a deletion is not a secure wipe. The data can stay on the disk until the disk reuses the space. With FileVault on, that data is encrypted. Turn on FileVault on the Mac that runs Apassy.

## 6. Limits

- 1PUX: the archive is at most 2 GB, `export.data` is at most 64 MB uncompressed, and it expands at most 250 times. The archive has at most 20000 files. Apassy refuses an encrypted entry, a zip64 archive, an archive in parts, two `export.data` files, and a method other than stored and deflate. Apassy checks the size and the CRC-32 checksum of `export.data`. It never writes a file of the archive to disk.
- CSV: at most 32 MB, 50000 rows, and 64 columns. The file is UTF-8, with or without a byte-order mark. Columns match by the header name, in any order and case. Fields follow RFC 4180: quotes, commas, and line breaks in a quoted field.
- The duplicate check uses the vault search. With more than 1000 credentials, Apassy searches for each title of the export.
- The import runs in the window. A large export can take some seconds.
- Memory: the file bytes, the uncompressed `export.data`, and each parsed value are in erasing buffers, and the debug output of the preview is redacted. The app drops the preview on "Cancel", "Back", a lock, and quit, and after the import. This is best effort, as in the [key-memory review](../reviews/key-memory.md): `serde_json` keeps a scratch copy of a string with escape characters, the deflate window is not erased, and the allocator does not erase freed memory.

## 7. Tests

Run the tests from the repository root:

```
cargo test --locked --features vault --test onepassword_import
cargo test --locked --features desktop,vault --lib import
```

| Test | What it shows |
| --- | --- |
| `every_category_maps_to_its_kind` (`tests/onepassword_import.rs`) | Each 1Password category, the fields, the details, the fallbacks, archived and trashed items, and the first selection. |
| `secrets_never_reach_title_notes_tags_or_debug_output` | No synthetic secret is in a title, notes, tags, a warning, or the debug output. Each secret is a secret field. |
| `every_ready_item_validates_in_a_vault` | The vault accepts each item. A secret is not searchable. The tags are. |
| `too_many_fields_leave_out_visible_details_first` | At most 10 details, visible ones left out first, a warning for each. |
| `csv_rows_map_with_quoting_line_breaks_and_unknown_columns`, `csv_columns_match_by_name_in_any_order_and_case`, `csv_errors_name_the_row_and_no_value` | The CSV reader and mapping. |
| `malformed_and_truncated_archives_are_refused`, `encryption_zip64_and_other_methods_are_refused`, `limits_stop_zip_bombs_and_oversized_archives` | The zip reader and its limits. |
| `the_sheet_reads_a_file_shows_the_preview_and_imports_the_selection` (`src/desktop/ui/import.rs`) | Settings, the sheet, the preview, the duplicate mark, the import of the selection, no parsed data after the import, and the deletion of the file. |
| `cancel_back_and_lock_drop_the_parsed_export` | Cancel, Back, and each lock drop the preview. |
| `a_failed_item_does_not_stop_the_import` | An item that the vault refuses is listed under "Problems". The next item goes in. |
| `imported_items_can_be_edited_in_the_desktop_forms` | An edit in the item form keeps the fields, the hidden values, and the tags. |
