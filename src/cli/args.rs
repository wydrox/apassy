//! A small argument parser. Each command takes the options that it knows, then
//! [`Args::finish`] refuses the rest.

use std::fmt;

/// A usage error. The command line prints it with a hint to `--help`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage(pub String);

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn usage(text: impl Into<String>) -> Usage {
    Usage(text.into())
}

/// The words after the command name. Taken words become `None`.
#[derive(Debug)]
pub struct Args {
    words: Vec<Option<String>>,
}

impl Args {
    /// Split `--name=value` into two words. A word after `--` is never an option.
    pub fn new(words: impl IntoIterator<Item = String>) -> Self {
        let mut out = Vec::new();
        let mut rest = false;
        for word in words {
            if rest {
                out.push(Some(word));
                continue;
            }
            if word == "--" {
                rest = true;
                out.push(Some(word));
                continue;
            }
            match word.split_once('=') {
                Some((name, value)) if name.starts_with("--") && name.len() > 2 => {
                    out.push(Some(name.to_owned()));
                    out.push(Some(value.to_owned()));
                }
                _ => out.push(Some(word)),
            }
        }
        Self { words: out }
    }

    /// The index of `--`, or the end.
    fn end_of_options(&self) -> usize {
        self.words
            .iter()
            .position(|word| word.as_deref() == Some("--"))
            .unwrap_or(self.words.len())
    }

    fn position_of(&self, names: &[&str]) -> Option<usize> {
        let end = self.end_of_options();
        self.words[..end]
            .iter()
            .position(|word| word.as_deref().is_some_and(|word| names.contains(&word)))
    }

    /// True when one of `names` is present. Takes every copy.
    pub fn flag(&mut self, names: &[&str]) -> bool {
        let mut found = false;
        while let Some(index) = self.position_of(names) {
            self.words[index] = None;
            found = true;
        }
        found
    }

    /// The value of the last copy of an option.
    pub fn value(&mut self, names: &[&str]) -> Result<Option<String>, Usage> {
        Ok(self.values(names)?.pop())
    }

    /// The values of every copy of an option, in order.
    pub fn values(&mut self, names: &[&str]) -> Result<Vec<String>, Usage> {
        let mut values = Vec::new();
        while let Some(index) = self.position_of(names) {
            let name = self.words[index].take().unwrap_or_default();
            let value = self
                .words
                .get_mut(index + 1)
                .and_then(Option::take)
                .filter(|value| value != "--")
                .ok_or_else(|| usage(format!("{name} needs a value.")))?;
            values.push(value);
        }
        Ok(values)
    }

    /// A number option.
    pub fn number<T: std::str::FromStr>(&mut self, names: &[&str]) -> Result<Option<T>, Usage> {
        match self.value(names)? {
            None => Ok(None),
            Some(text) => text
                .trim()
                .parse()
                .map(Some)
                .map_err(|_| usage(format!("{} needs a whole number.", names[0]))),
        }
    }

    /// The next word that is not an option.
    pub fn positional(&mut self) -> Option<String> {
        let end = self.end_of_options();
        let index = self.words[..end].iter().position(|word| {
            word.as_deref()
                .is_some_and(|word| !word.starts_with('-') || word == "-")
        })?;
        self.words[index].take()
    }

    /// The next positional word, or a usage error that names it.
    pub fn required(&mut self, what: &str) -> Result<String, Usage> {
        self.positional()
            .ok_or_else(|| usage(format!("Name the {what}.")))
    }

    /// Every word that is not an option, and every word after `--`.
    pub fn rest(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(word) = self.positional() {
            out.push(word);
        }
        if let Some(index) = self
            .words
            .iter()
            .position(|word| word.as_deref() == Some("--"))
        {
            self.words[index] = None;
            out.extend(self.words[index + 1..].iter_mut().filter_map(Option::take));
        }
        out
    }

    /// Refuse every word that the command did not take.
    pub fn finish(self) -> Result<(), Usage> {
        match self.words.into_iter().flatten().next() {
            None => Ok(()),
            Some(word) if word.starts_with('-') && word != "-" => {
                Err(usage(format!("Unknown option {word}.")))
            }
            Some(word) => Err(usage(format!("Unexpected word \"{word}\"."))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Args {
        Args::new(words.iter().map(|word| (*word).to_owned()))
    }

    #[test]
    fn options_and_positionals_mix_in_any_order() {
        let mut a = args(&[
            "Stripe",
            "--kind=api_key",
            "--json",
            "--detail",
            "a=b",
            "--detail",
            "c=d",
        ]);
        assert!(a.flag(&["--json"]));
        assert_eq!(a.value(&["--kind"]).unwrap().as_deref(), Some("api_key"));
        assert_eq!(a.values(&["--detail"]).unwrap(), vec!["a=b", "c=d"]);
        assert_eq!(a.positional().as_deref(), Some("Stripe"));
        a.finish().unwrap();
    }

    #[test]
    fn unknown_options_and_missing_values_are_usage_errors() {
        let a = args(&["--nope"]);
        assert_eq!(a.finish().unwrap_err().0, "Unknown option --nope.");
        let mut a = args(&["--kind"]);
        assert!(a.value(&["--kind"]).is_err());
        let mut a = args(&["x", "--limit", "many"]);
        assert!(a.number::<u32>(&["--limit"]).is_err());
    }

    #[test]
    fn words_after_the_separator_are_not_options() {
        let mut a = args(&["claude", "--", "--json", "x"]);
        assert!(!a.flag(&["--json"]));
        assert_eq!(a.rest(), vec!["claude", "--json", "x"]);
        a.finish().unwrap();
    }
}
