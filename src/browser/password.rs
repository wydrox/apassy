//! New passwords for the browser (ADR 0021, contract section 8).
//!
//! The app makes the password, so it is in the vault before the page gets it. The bytes
//! come from the random generator of the system (`getrandom`). A byte maps to a
//! character by rejection, so each character of the alphabet is equally likely. A
//! password has at least one character of each class; a password without one is made
//! again.

use zeroize::Zeroizing;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
/// Symbols that most sites take. No quote, no backslash, no space.
pub const SYMBOLS: &[u8] = b"!#$%&*+-.:;=?@^_~";

/// Why no password was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    /// The length is outside 12 to 64.
    Length,
    /// The random generator of the system failed.
    Random,
}

/// A new password of `length` characters: letters and digits, and symbols when
/// `symbols` is true.
pub fn generate(length: u32, symbols: bool) -> Result<Zeroizing<String>, PasswordError> {
    use super::wire::{MAX_NEW_PASSWORD, MIN_NEW_PASSWORD};
    if !(MIN_NEW_PASSWORD..=MAX_NEW_PASSWORD).contains(&length) {
        return Err(PasswordError::Length);
    }
    let mut classes: Vec<&[u8]> = vec![LOWER, UPPER, DIGITS];
    if symbols {
        classes.push(SYMBOLS);
    }
    let alphabet: Vec<u8> = classes.concat();
    // The largest multiple of the alphabet size that fits in a byte. A larger byte
    // would make the first characters more likely, so it is skipped.
    let limit = 256 - (256 % alphabet.len());
    let length = length as usize;
    loop {
        let mut out = Zeroizing::new(Vec::with_capacity(length));
        let mut random = Zeroizing::new([0u8; 128]);
        while out.len() < length {
            getrandom::fill(&mut *random).map_err(|_| PasswordError::Random)?;
            for byte in random.iter().copied() {
                if usize::from(byte) < limit && out.len() < length {
                    out.push(alphabet[usize::from(byte) % alphabet.len()]);
                }
            }
        }
        if classes
            .iter()
            .all(|class| out.iter().any(|byte| class.contains(byte)))
        {
            // Each byte is ASCII.
            let text: String = out.iter().map(|byte| char::from(*byte)).collect();
            return Ok(Zeroizing::new(text));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_has_the_length_and_each_class() {
        for length in [12, 20, 64] {
            for symbols in [true, false] {
                let password = generate(length, symbols).unwrap();
                assert_eq!(password.chars().count(), length as usize);
                assert!(password.bytes().any(|b| LOWER.contains(&b)));
                assert!(password.bytes().any(|b| UPPER.contains(&b)));
                assert!(password.bytes().any(|b| DIGITS.contains(&b)));
                assert_eq!(
                    password.bytes().any(|b| SYMBOLS.contains(&b)),
                    symbols,
                    "{symbols}"
                );
                assert!(password.bytes().all(|b| b.is_ascii_graphic()));
            }
        }
    }

    #[test]
    fn lengths_outside_the_range_are_refused() {
        assert_eq!(generate(11, true).unwrap_err(), PasswordError::Length);
        assert_eq!(generate(65, true).unwrap_err(), PasswordError::Length);
    }

    #[test]
    fn passwords_differ_and_use_the_whole_alphabet() {
        let a = generate(20, true).unwrap();
        let b = generate(20, true).unwrap();
        assert_ne!(*a, *b);
        // 200 passwords of 64 characters: each of the 79 characters shows up.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            seen.extend(generate(64, true).unwrap().bytes());
        }
        assert_eq!(
            seen.len(),
            LOWER.len() + UPPER.len() + DIGITS.len() + SYMBOLS.len()
        );
    }
}
