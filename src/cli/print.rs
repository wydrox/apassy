//! Text output of the command line: tables, key-value blocks, and times.

use std::fmt::Write as _;

/// A table with a header. Columns are as wide as their widest cell, up to a limit.
pub struct Table {
    header: Vec<&'static str>,
    rows: Vec<Vec<String>>,
}

/// A long cell is cut to this many characters, with "…".
const MAX_CELL_CHARS: usize = 60;

impl Table {
    pub fn new(header: &[&'static str]) -> Self {
        Self {
            header: header.to_vec(),
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn render(&self) -> String {
        let cells: Vec<Vec<String>> = self
            .rows
            .iter()
            .map(|row| row.iter().map(|cell| cut(&clean(cell))).collect())
            .collect();
        let mut widths: Vec<usize> = self.header.iter().map(|h| h.chars().count()).collect();
        for row in &cells {
            for (index, cell) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(index) {
                    *width = (*width).max(cell.chars().count());
                }
            }
        }
        let mut out = String::new();
        let line = |out: &mut String, cells: &[String]| {
            let last = cells.len().saturating_sub(1);
            for (index, cell) in cells.iter().enumerate() {
                if index == last {
                    out.push_str(cell);
                } else {
                    let pad = widths[index].saturating_sub(cell.chars().count());
                    out.push_str(cell);
                    out.push_str(&" ".repeat(pad + 2));
                }
            }
            out.push('\n');
        };
        let header: Vec<String> = self.header.iter().map(|h| (*h).to_owned()).collect();
        line(&mut out, &header);
        for row in &cells {
            line(&mut out, row);
        }
        out
    }
}

/// Text without control characters, so a stored name cannot move the cursor.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn cut(text: &str) -> String {
    if text.chars().count() <= MAX_CELL_CHARS {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(MAX_CELL_CHARS - 1).collect();
    out.push('…');
    out
}

/// Aligned "label: value" lines. Empty values are left out.
pub struct Block {
    lines: Vec<(String, String)>,
}

impl Block {
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }

    pub fn line(&mut self, label: &str, value: impl Into<String>) {
        let value = value.into();
        if !value.trim().is_empty() {
            self.lines.push((label.to_owned(), value));
        }
    }

    pub fn render(&self) -> String {
        let width = self
            .lines
            .iter()
            .map(|(label, _)| label.chars().count())
            .max()
            .unwrap_or(0);
        let mut out = String::new();
        for (label, value) in &self.lines {
            let pad = width - label.chars().count();
            let mut value_lines = value.lines();
            let first = value_lines.next().unwrap_or_default();
            let _ = writeln!(out, "{label}:{} {}", " ".repeat(pad), clean(first));
            for more in value_lines {
                let _ = writeln!(out, "{} {}", " ".repeat(width + 1), clean(more));
            }
        }
        out
    }
}

impl Default for Block {
    fn default() -> Self {
        Self::new()
    }
}

/// A Unix time as `2026-10-01 14:03 UTC`. Zero is "never".
pub fn time(unix: u64) -> String {
    if unix == 0 {
        return "never".to_owned();
    }
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// Days since 1970-01-01 to a date (Howard Hinnant, `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Seconds as "45 s", "3 min", or "2 h 5 min".
pub fn duration(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs} s"),
        60..3600 => format!("{} min", secs / 60),
        _ => format!("{} h {} min", secs / 3600, (secs % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_utc_dates() {
        assert_eq!(time(0), "never");
        assert_eq!(time(1), "1970-01-01 00:00 UTC");
        assert_eq!(time(1_790_000_000), "2026-09-21 14:13 UTC");
        assert_eq!(time(951_782_400), "2000-02-29 00:00 UTC");
    }

    #[test]
    fn tables_align_and_clean_cells() {
        let mut table = Table::new(&["ID", "NAME"]);
        table.row(vec!["7".to_owned(), "Stripe\x1b[2J".to_owned()]);
        table.row(vec!["12".to_owned(), "GitHub".to_owned()]);
        assert_eq!(table.render(), "ID  NAME\n7   Stripe [2J\n12  GitHub\n");
    }
}
