//! Import of `.env` files and of CSV exports from 1Password and Bitwarden.
//!
//! The parsers run in the command line. Each entry becomes one [`ItemInput`] that the
//! app adds like an item from the add sheet. The command line never prints a value.

use zeroize::Zeroize;

use crate::contracts::CredentialKind;
use crate::owner::wire::{DetailInput, ItemInput, SecretText};

/// The vault limits of custom details (`src/desktop/owner_store.rs`).
const MAX_DETAILS: usize = 10;
const MAX_DETAIL_LABEL_BYTES: usize = 31;
/// The vault limit of a title.
const MAX_NAME_CHARS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Env,
    OnePassword,
    Bitwarden,
    /// A CSV file with a name column and a password column.
    Csv,
}

impl Format {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "env" | "dotenv" => Some(Self::Env),
            "1password" | "op" => Some(Self::OnePassword),
            "bitwarden" | "bw" => Some(Self::Bitwarden),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Env => ".env",
            Self::OnePassword => "1Password CSV",
            Self::Bitwarden => "Bitwarden CSV",
            Self::Csv => "CSV",
        }
    }
}

/// One entry of the file. `line` names its place for messages.
#[derive(Debug)]
pub struct Entry {
    pub line: usize,
    pub item: ItemInput,
}

/// An entry that the import leaves out, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub line: usize,
    pub reason: String,
}

/// Guess the format from the file name and the first line.
pub fn detect(path: &str, text: &str) -> Option<Format> {
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
        .to_lowercase();
    if name.starts_with(".env") || name.ends_with(".env") {
        return Some(Format::Env);
    }
    let header = text.lines().next().unwrap_or_default().to_lowercase();
    if header.contains("login_password") || header.contains("login_username") {
        return Some(Format::Bitwarden);
    }
    if header.contains("title") && header.contains("password") {
        return Some(Format::OnePassword);
    }
    if header.contains("name") && header.contains("password") {
        return Some(Format::Csv);
    }
    if text.lines().any(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with('#') && env_key(line).is_some()
    }) {
        return Some(Format::Env);
    }
    None
}

/// Options of an import.
#[derive(Debug, Default, Clone)]
pub struct Options {
    /// The kind for `.env` entries. The default is an API key.
    pub env_kind: Option<CredentialKind>,
    pub project: Option<String>,
    pub service: Option<String>,
}

/// Parse a file into entries.
pub fn parse(format: Format, text: &str, options: &Options) -> (Vec<Entry>, Vec<Skipped>) {
    let (mut entries, skipped) = match format {
        Format::Env => parse_env(text, options),
        Format::OnePassword | Format::Bitwarden | Format::Csv => parse_csv_items(text),
    };
    for entry in &mut entries {
        if let Some(project) = &options.project {
            entry.item.project = Some(project.clone());
        }
        if let Some(service) = &options.service {
            entry.item.service = Some(service.clone());
        }
    }
    (entries, skipped)
}

// ---- .env ----

/// The key of a `KEY=value` line, with an optional `export`.
fn env_key(line: &str) -> Option<(&str, &str)> {
    let line = line.strip_prefix("export ").map_or(line, str::trim_start);
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    let valid = !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !key.as_bytes()[0].is_ascii_digit();
    valid.then_some((key, value))
}

fn parse_env(text: &str, options: &Options) -> (Vec<Entry>, Vec<Skipped>) {
    let kind = options.env_kind.unwrap_or(CredentialKind::ApiKey);
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0;
    while index < lines.len() {
        let number = index + 1;
        let line = lines[index].trim_start();
        index += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = env_key(line) else {
            skipped.push(Skipped {
                line: number,
                reason: "not a KEY=value line".to_owned(),
            });
            continue;
        };
        let raw = raw.trim_start();
        let mut value = match raw.chars().next() {
            Some(quote @ ('"' | '\'')) => {
                // A quoted value can span lines, for example a private key.
                let mut body = raw[1..].to_owned();
                loop {
                    if let Some(end) = closing_quote(&body, quote) {
                        body.truncate(end);
                        break;
                    }
                    if index >= lines.len() {
                        body.zeroize();
                        skipped.push(Skipped {
                            line: number,
                            reason: format!("{key}: the quote does not close"),
                        });
                        body = String::new();
                        break;
                    }
                    body.push('\n');
                    body.push_str(lines[index]);
                    index += 1;
                }
                if quote == '"' {
                    unescape_double(&body)
                } else {
                    body
                }
            }
            _ => {
                // An unquoted value ends at " #".
                let end = raw.find(" #").unwrap_or(raw.len());
                raw[..end].trim().to_owned()
            }
        };
        if value.is_empty() {
            if !skipped.iter().any(|s| s.line == number) {
                skipped.push(Skipped {
                    line: number,
                    reason: format!("{key}: the value is empty"),
                });
            }
            continue;
        }
        let mut item = ItemInput {
            name: Some(key.to_owned()),
            kind: Some(kind),
            ..ItemInput::default()
        };
        match kind {
            CredentialKind::Custom => item.field_name = Some(custom_field(key)),
            CredentialKind::Login => {
                // A login needs a username. The key stands in for it.
                item.username = Some(key.to_owned());
            }
            _ => {}
        }
        item.secret = Some(SecretText::new(std::mem::take(&mut value)));
        entries.push(Entry { line: number, item });
    }
    (entries, skipped)
}

/// The position of the closing quote. In double quotes, `\"` does not close.
fn closing_quote(body: &str, quote: char) -> Option<usize> {
    let mut escaped = false;
    for (at, c) in body.char_indices() {
        if quote == '"' && c == '\\' && !escaped {
            escaped = true;
            continue;
        }
        if c == quote && !escaped {
            return Some(at);
        }
        escaped = false;
    }
    None
}

fn unescape_double(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// A custom field name from a variable name: lowercase letters, digits, and `_`. A
/// built-in name gets a `value_` prefix.
fn custom_field(key: &str) -> String {
    let name = key.to_lowercase();
    match name.as_str() {
        "service" | "project" | "token" | "password" | "private_key" | "passphrase"
        | "username" | "host" | "database" | "public_key" => format!("value_{name}"),
        _ if name.starts_with("x_") => format!("value_{name}"),
        _ => name,
    }
}

// ---- CSV ----

/// RFC 4180 records: quoted fields can hold commas, quotes (`""`), and newlines.
/// Returns each record with the line where it starts.
pub fn parse_csv(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut line = 1;
    let mut start = 1;
    let mut chars = text.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = false,
                '\n' => {
                    line += 1;
                    field.push('\n');
                }
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => {
                quoted = true;
                any = true;
            }
            ',' => {
                record.push(std::mem::take(&mut field));
                any = true;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                if any || !field.is_empty() {
                    record.push(std::mem::take(&mut field));
                    records.push((start, std::mem::take(&mut record)));
                }
                any = false;
                line += 1;
                start = line;
            }
            _ => {
                field.push(c);
                any = true;
            }
        }
    }
    if any || !field.is_empty() {
        record.push(field);
        records.push((start, record));
    }
    records
}

/// The column of the first header name that matches.
fn column(header: &[String], names: &[&str]) -> Option<usize> {
    names.iter().find_map(|name| {
        header.iter().position(|cell| {
            cell.trim()
                .trim_start_matches('\u{feff}')
                .eq_ignore_ascii_case(name)
        })
    })
}

fn parse_csv_items(text: &str) -> (Vec<Entry>, Vec<Skipped>) {
    let mut records = parse_csv(text).into_iter();
    let Some((_, header)) = records.next() else {
        return (Vec::new(), Vec::new());
    };
    let name_col = column(&header, &["title", "name"]);
    let url_col = column(&header, &["url", "website", "login_uri", "urls"]);
    let user_col = column(&header, &["username", "login_username", "user", "email"]);
    let pass_col = column(&header, &["password", "login_password"]);
    let otp_col = column(
        &header,
        &["otpauth", "login_totp", "totp", "one-time password"],
    );
    let notes_col = column(&header, &["notes", "notesplain", "note"]);
    let type_col = column(&header, &["type"]);
    let fields_col = column(&header, &["fields"]);
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    for (line, mut record) in records {
        let cell = |record: &[String], col: Option<usize>| -> String {
            col.and_then(|col| record.get(col))
                .map(|value| value.trim().to_owned())
                .unwrap_or_default()
        };
        let name = cell(&record, name_col);
        let url = cell(&record, url_col);
        let username = cell(&record, user_col);
        let notes = cell(&record, notes_col);
        let kind_text = cell(&record, type_col).to_lowercase();
        let password = pass_col
            .and_then(|col| record.get_mut(col))
            .map(std::mem::take)
            .unwrap_or_default();
        let otp = otp_col
            .and_then(|col| record.get_mut(col))
            .map(std::mem::take)
            .unwrap_or_default();
        let fields = fields_col
            .and_then(|col| record.get_mut(col))
            .map(std::mem::take)
            .unwrap_or_default();
        for value in &mut record {
            value.zeroize();
        }
        let name: String = if name.is_empty() {
            service_of(&url)
        } else {
            name
        };
        let name: String = name.chars().take(MAX_NAME_CHARS).collect();
        if name.trim().is_empty() {
            skipped.push(Skipped {
                line,
                reason: "no name".to_owned(),
            });
            continue;
        }
        let mut item = ItemInput {
            name: Some(name.clone()),
            service: Some(service_of(&url)).filter(|service| !service.is_empty()),
            ..ItemInput::default()
        };
        let password = password.trim_end_matches(['\r', '\n']).to_owned();
        if !password.is_empty() && !username.is_empty() {
            item.kind = Some(CredentialKind::Login);
            item.username = Some(username);
            item.secret = Some(SecretText::new(password));
            item.notes = Some(notes).filter(|notes| !notes.is_empty());
        } else if !password.is_empty() {
            item.kind = Some(CredentialKind::ApiKey);
            item.secret = Some(SecretText::new(password));
            item.notes = Some(notes).filter(|notes| !notes.is_empty());
        } else if !notes.is_empty() && (kind_text == "note" || kind_text.is_empty()) {
            // A secure note: the note is the secret.
            item.kind = Some(CredentialKind::Custom);
            item.field_name = Some("note".to_owned());
            item.secret = Some(SecretText::new(notes));
        } else {
            skipped.push(Skipped {
                line,
                reason: format!("{name}: no password and no note"),
            });
            continue;
        }
        let otp = otp.trim().to_owned();
        if !otp.is_empty() {
            item.details.push(DetailInput {
                label: "One-time code".to_owned(),
                value: SecretText::new(otp),
                hidden: true,
            });
        }
        for (label, value) in custom_fields(&fields) {
            if item.details.len() >= MAX_DETAILS {
                skipped.push(Skipped {
                    line,
                    reason: format!(
                        "{name}: more than {MAX_DETAILS} custom fields; the rest are left out"
                    ),
                });
                break;
            }
            if item
                .details
                .iter()
                .any(|detail| detail.label.eq_ignore_ascii_case(&label))
            {
                continue;
            }
            item.details.push(DetailInput {
                label,
                value,
                hidden: true,
            });
        }
        entries.push(Entry { line, item });
    }
    (entries, skipped)
}

/// Bitwarden custom fields: one `name: value` per line. Every value is hidden.
fn custom_fields(text: &str) -> Vec<(String, SecretText)> {
    text.lines()
        .filter_map(|line| {
            let (label, value) = line.split_once(": ").or_else(|| line.split_once(':'))?;
            let label = detail_label(label);
            let value = value.trim();
            (!label.is_empty() && !value.is_empty())
                .then(|| (label, SecretText::new(value.to_owned())))
        })
        .collect()
}

/// A detail label of at most 31 bytes.
fn detail_label(text: &str) -> String {
    let text = text.trim();
    let mut end = text.len().min(MAX_DETAIL_LABEL_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].trim().to_owned()
}

/// The host of a URL, without `www.`: `https://www.example.com/login` is `example.com`.
fn service_of(url: &str) -> String {
    let url = url.lines().next().unwrap_or_default().trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
    let host = host.split(':').next().unwrap_or_default();
    host.trim_start_matches("www.").to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(entry: &Entry) -> &str {
        entry.item.secret.as_ref().expect("secret").expose()
    }

    #[test]
    fn env_files_keep_quotes_comments_exports_and_multiline_values() {
        let text = "# comment\nexport STRIPE_KEY=sk_test_env-canary # live? no\nEMPTY=\nQUOTED=\"a b\\n c\"\nSINGLE='x\\ny'\nPEM=\"-----BEGIN KEY-----\nabc\n-----END KEY-----\"\n9BAD=1\nnot a line\n";
        let (entries, skipped) = parse(Format::Env, text, &Options::default());
        let names: Vec<_> = entries
            .iter()
            .map(|entry| entry.item.name.clone().unwrap_or_default())
            .collect();
        assert_eq!(names, ["STRIPE_KEY", "QUOTED", "SINGLE", "PEM"]);
        assert_eq!(secret(&entries[0]), "sk_test_env-canary");
        assert_eq!(secret(&entries[1]), "a b\n c");
        assert_eq!(secret(&entries[2]), "x\\ny");
        assert_eq!(
            secret(&entries[3]),
            "-----BEGIN KEY-----\nabc\n-----END KEY-----"
        );
        assert_eq!(entries[3].line, 6);
        assert!(
            entries
                .iter()
                .all(|entry| entry.item.kind == Some(CredentialKind::ApiKey))
        );
        let lines: Vec<usize> = skipped.iter().map(|skip| skip.line).collect();
        assert_eq!(lines, [3, 9, 10]);
        let debug = format!("{entries:?}");
        assert!(!debug.contains("canary"), "{debug}");
    }

    #[test]
    fn env_custom_kind_uses_a_safe_field_name() {
        let options = Options {
            env_kind: Some(CredentialKind::Custom),
            project: Some("billing".to_owned()),
            ..Options::default()
        };
        let (entries, _) = parse(Format::Env, "TOKEN=abc\nAPI_KEY=def\n", &options);
        assert_eq!(entries[0].item.field_name.as_deref(), Some("value_token"));
        assert_eq!(entries[1].item.field_name.as_deref(), Some("api_key"));
        assert_eq!(entries[1].item.project.as_deref(), Some("billing"));
    }

    #[test]
    fn csv_records_handle_quotes_commas_and_newlines() {
        let text = "a,b,c\r\n\"x, y\",\"say \"\"hi\"\"\",\"line1\nline2\"\n\n1,2,3";
        let records = parse_csv(text);
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].1, ["x, y", "say \"hi\"", "line1\nline2"]);
        assert_eq!(records[2].0, 5);
        assert_eq!(records[2].1, ["1", "2", "3"]);
    }

    #[test]
    fn one_password_csv_becomes_logins_keys_and_notes() {
        let text = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
GitHub,https://github.com/login,octo,gh-pass-canary,otpauth://totp/x?secret=ABC,false,false,,\n\
Stripe,https://dashboard.stripe.com,,sk_test_canary,,false,false,,test key\n\
Wifi,,,,,false,false,,\"network: home\"\n\
Empty,,,,,false,false,,\n";
        assert_eq!(detect("export.csv", text), Some(Format::OnePassword));
        let (entries, skipped) = parse(Format::OnePassword, text, &Options::default());
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].item.kind, Some(CredentialKind::Login));
        assert_eq!(entries[0].item.service.as_deref(), Some("github.com"));
        assert_eq!(entries[0].item.details[0].label, "One-time code");
        assert!(entries[0].item.details[0].hidden);
        assert_eq!(entries[1].item.kind, Some(CredentialKind::ApiKey));
        assert_eq!(entries[1].item.notes.as_deref(), Some("test key"));
        assert_eq!(entries[2].item.kind, Some(CredentialKind::Custom));
        assert_eq!(secret(&entries[2]), "network: home");
        assert_eq!(skipped.len(), 1);
        assert!(!format!("{entries:?}").contains("canary"));
    }

    #[test]
    fn bitwarden_csv_maps_custom_fields_to_hidden_details() {
        let text = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
,,login,AWS,,\"Access key: AKIA-canary\nRegion: eu-west-1\",0,https://console.aws.amazon.com,admin,aws-pass,\n\
,,note,Recovery codes,\"1111 2222\",,0,,,,\n";
        assert_eq!(
            detect("bitwarden_export.csv", text),
            Some(Format::Bitwarden)
        );
        let (entries, skipped) = parse(Format::Bitwarden, text, &Options::default());
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(entries[0].item.username.as_deref(), Some("admin"));
        assert_eq!(
            entries[0].item.service.as_deref(),
            Some("console.aws.amazon.com")
        );
        let labels: Vec<_> = entries[0]
            .item
            .details
            .iter()
            .map(|d| d.label.as_str())
            .collect();
        assert_eq!(labels, ["Access key", "Region"]);
        assert_eq!(entries[1].item.kind, Some(CredentialKind::Custom));
        assert_eq!(secret(&entries[1]), "1111 2222");
    }

    #[test]
    fn detection_uses_the_name_then_the_header() {
        assert_eq!(detect("/x/.env.local", ""), Some(Format::Env));
        assert_eq!(detect("prod.env", ""), Some(Format::Env));
        assert_eq!(detect("secrets.txt", "A=1\n"), Some(Format::Env));
        assert_eq!(detect("x.csv", "name,url,password\n"), Some(Format::Csv));
        assert_eq!(detect("x.csv", "a,b\n"), None);
    }
}
