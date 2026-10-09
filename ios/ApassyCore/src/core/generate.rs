//! The password generator and the strength estimate (contract sections 5.4 and 9).
//! Random choices come from the system generator (`getrandom`) with rejection
//! sampling, so each character or word is uniform.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::errors::{CoreError, CoreResult};

/// The EFF large word list (7776 words, CC BY 3.0 US; licenses/eff-wordlist).
const WORDS: &str = include_str!("../../data/eff_large_wordlist.txt");

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Symbols that sign-up forms usually take.
const SYMBOLS: &str = "!#$%&*+-.:=?@^_~";
const SEPARATORS: [&str; 5] = ["-", ".", "_", " ", ","];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Style {
    Random,
    Memorable,
    Pin,
}

#[derive(Debug, Deserialize)]
pub struct Options {
    pub style: Style,
    pub length: Option<u32>,
    pub digits: Option<bool>,
    pub symbols: Option<bool>,
    pub words: Option<u32>,
    pub separator: Option<String>,
    pub capitalize: Option<bool>,
}

/// A generated value and its entropy. The value is erased when the answer is written.
#[derive(Serialize)]
pub struct Generated {
    #[serde(serialize_with = "super::wire::zeroizing")]
    pub value: Zeroizing<String>,
    pub bits: f64,
}

fn words() -> Vec<&'static str> {
    WORDS.lines().filter(|word| !word.is_empty()).collect()
}

/// A uniform index below `n`.
fn index(n: usize) -> CoreResult<usize> {
    let n =
        u32::try_from(n).map_err(|_| CoreError::internal("The generator range is too large."))?;
    let limit = u32::MAX - u32::MAX % n;
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes)
            .map_err(|_| CoreError::internal("The system random generator failed."))?;
        let value = u32::from_le_bytes(bytes);
        if value < limit {
            return Ok((value % n) as usize);
        }
    }
}

fn pick(alphabet: &[char]) -> CoreResult<char> {
    Ok(alphabet[index(alphabet.len())?])
}

pub fn generate(options: &Options) -> CoreResult<Generated> {
    match options.style {
        Style::Pin => {
            let length = options.length.unwrap_or(6);
            if !(4..=12).contains(&length) {
                return Err(CoreError::invalid("A PIN has 4 to 12 digits."));
            }
            let digits: Vec<char> = DIGITS.chars().collect();
            let mut value = Zeroizing::new(String::new());
            for _ in 0..length {
                value.push(pick(&digits)?);
            }
            Ok(Generated {
                value,
                bits: f64::from(length) * 10f64.log2(),
            })
        }
        Style::Memorable => {
            let count = options.words.unwrap_or(5);
            if !(3..=10).contains(&count) {
                return Err(CoreError::invalid(
                    "A memorable password has 3 to 10 words.",
                ));
            }
            let separator = options.separator.as_deref().unwrap_or("-");
            if !SEPARATORS.contains(&separator) {
                return Err(CoreError::invalid(
                    "This separator is not one of the choices.",
                ));
            }
            let list = words();
            let capitalize = options.capitalize.unwrap_or(true);
            let mut value = Zeroizing::new(String::new());
            for n in 0..count {
                if n > 0 {
                    value.push_str(separator);
                }
                let word = list[index(list.len())?];
                let mut chars = word.chars();
                if capitalize && let Some(first) = chars.next() {
                    value.extend(first.to_uppercase());
                    value.push_str(chars.as_str());
                } else {
                    value.push_str(word);
                }
            }
            Ok(Generated {
                value,
                bits: f64::from(count) * (list.len() as f64).log2(),
            })
        }
        Style::Random => {
            let length = options.length.unwrap_or(24);
            if !(8..=64).contains(&length) {
                return Err(CoreError::invalid(
                    "A random password has 8 to 64 characters.",
                ));
            }
            let mut classes: Vec<Vec<char>> =
                vec![LOWER.chars().collect(), UPPER.chars().collect()];
            if options.digits.unwrap_or(true) {
                classes.push(DIGITS.chars().collect());
            }
            if options.symbols.unwrap_or(true) {
                classes.push(SYMBOLS.chars().collect());
            }
            let alphabet: Vec<char> = classes.iter().flatten().copied().collect();
            // Draw again until each chosen class is in the value: forms often ask for
            // one of each. The loss of entropy is small at these lengths.
            loop {
                let mut value = Zeroizing::new(String::new());
                for _ in 0..length {
                    value.push(pick(&alphabet)?);
                }
                if classes
                    .iter()
                    .all(|class| value.chars().any(|ch| class.contains(&ch)))
                {
                    return Ok(Generated {
                        value,
                        bits: f64::from(length) * (alphabet.len() as f64).log2(),
                    });
                }
            }
        }
    }
}

/// The estimate of a value that the owner typed (contract section 9).
#[derive(Debug, Serialize, PartialEq)]
pub struct StrengthOut {
    pub bits: f64,
    pub score: u8,
}

pub fn score(bits: f64) -> u8 {
    match bits {
        b if b < 28.0 => 0,
        b if b < 36.0 => 1,
        b if b < 60.0 => 2,
        b if b < 80.0 => 3,
        _ => 4,
    }
}

/// Length times log2 of the size of the character classes it uses, less half a
/// character for each repeat or step of a sequence ("aaa", "abc", "321"). A value of
/// fewer than 8 characters scores 0.
pub fn strength(value: &str) -> StrengthOut {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return StrengthOut {
            bits: 0.0,
            score: 0,
        };
    }
    let mut pool = 0u32;
    if chars.iter().any(char::is_ascii_lowercase) {
        pool += 26;
    }
    if chars.iter().any(char::is_ascii_uppercase) {
        pool += 26;
    }
    if chars.iter().any(char::is_ascii_digit) {
        pool += 10;
    }
    if chars.iter().any(char::is_ascii_punctuation) || chars.contains(&' ') {
        pool += 33;
    }
    if chars.iter().any(|ch| !ch.is_ascii()) {
        pool += 100;
    }
    let mut weak = 0.0;
    for pair in chars.windows(2) {
        let (a, b) = (pair[0] as i64, pair[1] as i64);
        if a == b || (a - b).abs() == 1 {
            weak += 0.5;
        }
    }
    let length = (chars.len() as f64 - weak).max(1.0);
    let bits = (length * f64::from(pool.max(1)).log2() * 10.0).round() / 10.0;
    // A short value falls to a guess list whatever its characters are.
    let score = if chars.len() < 8 { 0 } else { score(bits) };
    StrengthOut { bits, score }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(style: Style) -> Options {
        Options {
            style,
            length: None,
            digits: None,
            symbols: None,
            words: None,
            separator: None,
            capitalize: None,
        }
    }

    #[test]
    fn the_word_list_is_the_eff_list() {
        let list = words();
        assert_eq!(list.len(), 7776);
        assert_eq!(list[0], "abacus");
        assert_eq!(list[7775], "zoom");
    }

    #[test]
    fn random_has_each_class_and_the_length() {
        for _ in 0..50 {
            let out = generate(&options(Style::Random)).unwrap();
            assert_eq!(out.value.chars().count(), 24);
            assert!(out.value.chars().any(|c| c.is_ascii_digit()));
            assert!(out.value.chars().any(|c| SYMBOLS.contains(c)));
            assert!(out.bits > 140.0);
        }
        let mut plain = options(Style::Random);
        plain.length = Some(12);
        plain.digits = Some(false);
        plain.symbols = Some(false);
        let out = generate(&plain).unwrap();
        assert!(out.value.chars().all(|c| c.is_ascii_alphabetic()));
        plain.length = Some(7);
        assert!(generate(&plain).is_err());
    }

    #[test]
    fn memorable_and_pin() {
        let mut memorable = options(Style::Memorable);
        memorable.separator = Some(".".into());
        let out = generate(&memorable).unwrap();
        assert_eq!(out.value.split('.').count(), 5);
        assert!(
            out.value
                .split('.')
                .all(|w| w.chars().next().unwrap().is_uppercase())
        );
        assert!((out.bits - 64.6).abs() < 0.1);
        memorable.separator = Some("/".into());
        assert!(generate(&memorable).is_err());
        let out = generate(&options(Style::Pin)).unwrap();
        assert_eq!(out.value.len(), 6);
        assert!(out.value.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn strength_scores() {
        assert_eq!(strength("").score, 0);
        assert_eq!(strength("short1").score, 0);
        assert_eq!(strength("aaaaaaaaaaaa").score, 1);
        assert!(strength("correct-horse-battery").score >= 3);
        assert_eq!(strength("Tr0ub4dour&3xQ9!kL2#mZ").score, 4);
        assert!(strength("abcdefgh").bits < strength("aqzmwkxj").bits);
    }
}
