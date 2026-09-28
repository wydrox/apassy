//! An RFC 4180 CSV reader for the 1Password CSV export.
//!
//! Fields are separated by commas and records by a line break (`\r\n`, `\n`, or `\r`).
//! A quoted field can hold commas, line breaks, and quotes (written as `""`). Each field
//! is one allocation of its final size in an erasing buffer, so no partial copy of a
//! value stays behind when a buffer grows.

use std::fmt;

use zeroize::Zeroizing;

/// The most records in one file, with the header.
pub const MAX_RECORDS: usize = 50_000;
/// The most fields in one record.
pub const MAX_FIELDS: usize = 64;

/// One record: its fields. Each field erases itself on drop.
pub type Record = Vec<Zeroizing<String>>;

/// Why a CSV file cannot be read. The text names a record number, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsvError {
    /// A quoted field has no closing quote.
    UnclosedQuote {
        record: usize,
    },
    /// Text follows the closing quote of a field.
    TextAfterQuote {
        record: usize,
    },
    TooManyRecords,
    TooManyFields {
        record: usize,
    },
}

impl fmt::Display for CsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnclosedQuote { record } => write!(
                f,
                "Row {record} of the CSV file has a quoted field without a closing quote."
            ),
            Self::TextAfterQuote { record } => write!(
                f,
                "Row {record} of the CSV file has text after a closing quote."
            ),
            Self::TooManyRecords => {
                write!(f, "The CSV file has more than {} rows.", MAX_RECORDS - 1)
            }
            Self::TooManyFields { record } => write!(
                f,
                "Row {record} of the CSV file has more than {MAX_FIELDS} columns."
            ),
        }
    }
}

impl std::error::Error for CsvError {}

/// Split `text` into records. A byte-order mark at the start is skipped. Empty lines
/// are skipped. Record numbers in errors start at 1 and count the header.
pub fn parse(text: &str) -> Result<Vec<Record>, CsvError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let bytes = text.as_bytes();
    let mut records = Vec::new();
    let mut record: Record = Vec::new();
    let mut pos = 0;
    loop {
        let number = records.len() + 1;
        let (field, next) = if bytes.get(pos) == Some(&b'"') {
            quoted_field(text, pos, number)?
        } else {
            plain_field(text, pos)
        };
        if record.len() >= MAX_FIELDS {
            return Err(CsvError::TooManyFields { record: number });
        }
        record.push(field);
        pos = next;
        match bytes.get(pos) {
            Some(b',') => {
                pos += 1;
            }
            Some(b'\r') | Some(b'\n') => {
                if bytes[pos] == b'\r' && bytes.get(pos + 1) == Some(&b'\n') {
                    pos += 1;
                }
                pos += 1;
                finish(&mut records, std::mem::take(&mut record))?;
                if pos >= bytes.len() {
                    break;
                }
            }
            None => {
                finish(&mut records, std::mem::take(&mut record))?;
                break;
            }
            Some(_) => return Err(CsvError::TextAfterQuote { record: number }),
        }
    }
    Ok(records)
}

fn finish(records: &mut Vec<Record>, record: Record) -> Result<(), CsvError> {
    if record.len() == 1 && record[0].is_empty() {
        return Ok(());
    }
    if records.len() >= MAX_RECORDS {
        return Err(CsvError::TooManyRecords);
    }
    records.push(record);
    Ok(())
}

/// An unquoted field: the text up to the next comma or line break. A quote inside it
/// is kept as text.
fn plain_field(text: &str, start: usize) -> (Zeroizing<String>, usize) {
    let end = text[start..]
        .find([',', '\r', '\n'])
        .map_or(text.len(), |offset| start + offset);
    (Zeroizing::new(text[start..end].to_owned()), end)
}

/// A quoted field that starts at `start` (the opening quote). Returns the field and
/// the position after the closing quote.
fn quoted_field(
    text: &str,
    start: usize,
    record: usize,
) -> Result<(Zeroizing<String>, usize), CsvError> {
    let bytes = text.as_bytes();
    // Find the closing quote first, so the field gets one allocation of the right size.
    let mut end = start + 1;
    loop {
        match bytes.get(end) {
            None => return Err(CsvError::UnclosedQuote { record }),
            Some(b'"') if bytes.get(end + 1) == Some(&b'"') => end += 2,
            Some(b'"') => break,
            Some(_) => end += 1,
        }
    }
    let raw = &text[start + 1..end];
    let mut field = Zeroizing::new(String::with_capacity(raw.len()));
    let mut rest = raw;
    while let Some(quote) = rest.find("\"\"") {
        field.push_str(&rest[..=quote]);
        rest = &rest[quote + 2..];
    }
    field.push_str(rest);
    Ok((field, end + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(text: &str) -> Vec<Vec<String>> {
        parse(text)
            .unwrap()
            .into_iter()
            .map(|record| record.iter().map(|field| field.to_string()).collect())
            .collect()
    }

    #[test]
    fn quotes_commas_and_line_breaks() {
        let text = "a,b,c\r\n\"x, y\",\"say \"\"hi\"\"\",\"line 1\nline 2\"\n,,\n";
        assert_eq!(
            rows(text),
            vec![
                vec!["a", "b", "c"],
                vec!["x, y", "say \"hi\"", "line 1\nline 2"],
                vec!["", "", ""],
            ]
        );
    }

    #[test]
    fn a_byte_order_mark_and_empty_lines_are_skipped() {
        assert_eq!(
            rows("\u{feff}a,b\n\nc,d"),
            vec![vec!["a", "b"], vec!["c", "d"]]
        );
        assert!(rows("\"\"\n").is_empty());
    }

    #[test]
    fn malformed_quotes_are_errors() {
        assert_eq!(
            parse("a\n\"open,b\n").unwrap_err(),
            CsvError::UnclosedQuote { record: 2 }
        );
        assert_eq!(
            parse("\"a\"b,c").unwrap_err(),
            CsvError::TextAfterQuote { record: 1 }
        );
    }
}
