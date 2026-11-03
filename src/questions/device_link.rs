//! The answer key of an iPhone in its device link (contract relay-questions-v1 section
//! 5.2, contract ios-core-v1 `join_attach`).
//!
//! An iPhone does not write its own `trusted_device` row. The Mac that confirms its link
//! writes it during the owner check of the confirmation, from the keys that the iPhone
//! sent with the link: the relay device key (`public_key` of the link, bound by the
//! safety words) and the answer key. The link of the relay has no field for a second key
//! (`POST /v1/devices/link` takes `code`, `device_name`, and `public_key`, and refuses
//! any other field), so the iPhone sends its answer key at the end of `device_name`, as a
//! compressed P-256 point in b64u: `<name> ~<44 characters>`. The name with the key fits
//! the 64 bytes of a relay device name. The proof of the confirmation names the whole
//! `device_name`, so the owner check covers the answer key too.
//!
//! An Apple Watch (ADR 0039 §2) sends its answer key the same way after the marker
//! ` ~W`: `<name> ~W<44 characters>`, so its name before the marker is at most 17 bytes.
//! The marker carries the kind: the Mac that confirms the link writes a `watch` row. The
//! functions for an iPhone ([`link_device_name`], [`split_link_device_name`]) never take
//! a watch key; [`split_linked_device_name`] tells the two kinds apart.
//!
//! The relay can change a name, as it can change any field that the safety words do not
//! cover. A changed answer key gives the relay nothing: an answer still needs the question
//! key of the vault, which the relay never has. The iPhone checks that its row holds its
//! own answer key once the row reaches it, and says so when it does not.
//!
//! The point arithmetic is the square root of P-256 (`p ≡ 3 mod 4`) on four 64-bit limbs.
//! It handles public keys only: no secret goes through it.

use crate::sync::{decode_b64u, encode_b64u};

/// The bytes of a relay device name (relay `MAX_NAME_BYTES`).
pub const MAX_LINK_NAME_BYTES: usize = 64;
/// Between the name and the key.
const KEY_MARK: &str = " ~";
/// A compressed P-256 point in b64u: 33 bytes.
const KEY_CHARS: usize = 44;
/// The longest name before the key.
const MAX_SHOWN_NAME_BYTES: usize = MAX_LINK_NAME_BYTES - KEY_MARK.len() - KEY_CHARS;
/// Between the key mark and the key of a watch: the kind (ADR 0039 §2).
const WATCH_KIND: char = 'W';
/// The longest name of a watch before its key: 17 bytes.
const MAX_SHOWN_WATCH_NAME_BYTES: usize = MAX_SHOWN_NAME_BYTES - WATCH_KIND.len_utf8();

type U256 = [u64; 4];

/// The prime of P-256, little-endian limbs.
const P: U256 = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];
/// The coefficient `b` of P-256.
const B: U256 = [
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
];

fn from_be(bytes: &[u8]) -> U256 {
    let mut out = [0u64; 4];
    for (limb, chunk) in out.iter_mut().rev().zip(bytes.chunks_exact(8)) {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        *limb = u64::from_be_bytes(word);
    }
    out
}

fn to_be(value: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(value.iter().rev()) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn at_least(a: &U256, b: &U256) -> bool {
    for at in (0..4).rev() {
        if a[at] != b[at] {
            return a[at] > b[at];
        }
    }
    true
}

fn wrapping_sub(a: &U256, b: &U256) -> U256 {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for at in 0..4 {
        let (step, first) = a[at].overflowing_sub(b[at]);
        let (step, second) = step.overflowing_sub(u64::from(borrow));
        out[at] = step;
        borrow = first || second;
    }
    out
}

/// `a + b` and the carry out of 256 bits.
fn add_carry(a: &U256, b: &U256) -> (U256, bool) {
    let mut out = [0u64; 4];
    let mut carry = false;
    for at in 0..4 {
        let (step, first) = a[at].overflowing_add(b[at]);
        let (step, second) = step.overflowing_add(u64::from(carry));
        out[at] = step;
        carry = first || second;
    }
    (out, carry)
}

/// `a + b mod p` for `a, b < p`.
fn add_mod(a: &U256, b: &U256) -> U256 {
    let (sum, carry) = add_carry(a, b);
    if carry || at_least(&sum, &P) {
        wrapping_sub(&sum, &P)
    } else {
        sum
    }
}

/// `a - b mod p` for `a, b < p`.
fn sub_mod(a: &U256, b: &U256) -> U256 {
    if at_least(a, b) {
        wrapping_sub(a, b)
    } else {
        // a - b + 2^256, then + p, wraps to a - b + p.
        add_carry(&wrapping_sub(a, b), &P).0
    }
}

/// `a · b mod p` for `a, b < p`: the 512-bit product, reduced one bit at a time.
fn mul_mod(a: &U256, b: &U256) -> U256 {
    let mut product = [0u64; 8];
    for (i, &x) in a.iter().enumerate() {
        let mut carry = 0u128;
        for (j, &y) in b.iter().enumerate() {
            let step = u128::from(x) * u128::from(y) + u128::from(product[i + j]) + carry;
            product[i + j] = step as u64;
            carry = step >> 64;
        }
        product[i + 4] = carry as u64;
    }
    let mut rest = [0u64; 4];
    for bit in (0..512).rev() {
        let top = rest[3] >> 63;
        for at in (1..4).rev() {
            rest[at] = (rest[at] << 1) | (rest[at - 1] >> 63);
        }
        rest[0] = (rest[0] << 1) | ((product[bit / 64] >> (bit % 64)) & 1);
        if top == 1 || at_least(&rest, &P) {
            rest = wrapping_sub(&rest, &P);
        }
    }
    rest
}

fn pow_mod(base: &U256, exponent: &U256) -> U256 {
    let mut out: U256 = [1, 0, 0, 0];
    for bit in (0..256).rev() {
        out = mul_mod(&out, &out);
        if (exponent[bit / 64] >> (bit % 64)) & 1 == 1 {
            out = mul_mod(&out, base);
        }
    }
    out
}

/// A P-256 point in X9.63 form (65 bytes from `0x04`), compressed: 33 bytes from `0x02`
/// or `0x03`. `None` for another form.
pub fn compress_point(point: &[u8]) -> Option<[u8; 33]> {
    if point.len() != 65 || point[0] != 0x04 {
        return None;
    }
    let mut out = [0u8; 33];
    out[0] = 0x02 | (point[64] & 1);
    out[1..].copy_from_slice(&point[1..33]);
    Some(out)
}

/// A compressed P-256 point in X9.63 form, or `None` when it is not on the curve.
pub fn decompress_point(compressed: &[u8]) -> Option<Vec<u8>> {
    if compressed.len() != 33 || !matches!(compressed[0], 0x02 | 0x03) {
        return None;
    }
    let x = from_be(&compressed[1..]);
    if at_least(&x, &P) {
        return None;
    }
    // y² = x³ - 3x + b.
    let x3 = mul_mod(&mul_mod(&x, &x), &x);
    let three_x = add_mod(&add_mod(&x, &x), &x);
    let rhs = add_mod(&sub_mod(&x3, &three_x), &B);
    // p ≡ 3 mod 4: a square root is rhs^((p + 1) / 4).
    let (plus_one, _) = add_carry(&P, &[1, 0, 0, 0]);
    let exponent = [
        (plus_one[0] >> 2) | (plus_one[1] << 62),
        (plus_one[1] >> 2) | (plus_one[2] << 62),
        (plus_one[2] >> 2) | (plus_one[3] << 62),
        plus_one[3] >> 2,
    ];
    let mut y = pow_mod(&rhs, &exponent);
    if mul_mod(&y, &y) != rhs {
        return None;
    }
    if (y[0] & 1) != u64::from(compressed[0] & 1) {
        if y == [0; 4] {
            return None;
        }
        y = wrapping_sub(&P, &y);
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&to_be(&x));
    point.extend_from_slice(&to_be(&y));
    Some(point)
}

/// The kind of device that a link name with an answer key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkedDeviceKind {
    /// `<name> ~<44 characters>`.
    Iphone,
    /// `<name> ~W<44 characters>` (ADR 0039 §2).
    Watch,
}

/// `name` without control characters, trimmed, and cut on a character to at most `max`
/// bytes; `fallback` when nothing is left.
fn cut_name(name: &str, max: usize, fallback: &str) -> String {
    let mut shown = String::new();
    for ch in name.trim().chars().filter(|ch| !ch.is_control()) {
        if shown.len() + ch.len_utf8() > max {
            break;
        }
        shown.push(ch);
    }
    let shown = shown.trim();
    if shown.is_empty() {
        fallback.to_owned()
    } else {
        shown.to_owned()
    }
}

/// The `device_name` of the link of an iPhone: its name, cut to fit, then the answer key
/// (`answer_key`, a P-256 point in X9.63 form). `None` for a key of another form.
pub fn link_device_name(name: &str, answer_key: &[u8]) -> Option<String> {
    let key = encode_b64u(&compress_point(answer_key)?);
    let shown = cut_name(name, MAX_SHOWN_NAME_BYTES, "iPhone");
    Some(format!("{shown}{KEY_MARK}{key}"))
}

/// The `device_name` of the link of an Apple Watch: `<name> ~W<44 characters: b64u of
/// the compressed point>`, at most 64 bytes. The name is cut on a character to at most
/// 17 bytes. `answer_key` is a P-256 point in X9.63 form (65 bytes), as for
/// [`link_device_name`]; `None` for a key of another form.
pub fn watch_link_device_name(name: &str, answer_key: &[u8]) -> Option<String> {
    let key = encode_b64u(&compress_point(answer_key)?);
    let shown = cut_name(name, MAX_SHOWN_WATCH_NAME_BYTES, "Apple Watch");
    Some(format!("{shown}{KEY_MARK}{WATCH_KIND}{key}"))
}

/// The name before the last key mark and the answer key after it, when the text after
/// the mark is the key of a device of `kind`: for a watch the kind letter first, then
/// 44 b64u characters of a point on the curve.
fn key_after_mark(text: &str, kind: LinkedDeviceKind) -> Option<(String, Vec<u8>)> {
    let (name, rest) = text.rsplit_once(KEY_MARK)?;
    let key = match kind {
        LinkedDeviceKind::Iphone => rest,
        LinkedDeviceKind::Watch => rest.strip_prefix(WATCH_KIND)?,
    };
    if key.len() != KEY_CHARS || name.trim().is_empty() {
        return None;
    }
    let point = decompress_point(&decode_b64u(key)?)?;
    Some((name.trim().to_owned(), point))
}

/// The name and the answer key in the `device_name` of the link of an iPhone. A name
/// without a key (a Mac, or an older iPhone) is the name as it is, with `None`. So is the
/// name of a watch: its key is never taken as the key of an iPhone.
pub fn split_link_device_name(text: &str) -> (String, Option<Vec<u8>>) {
    match key_after_mark(text, LinkedDeviceKind::Iphone) {
        Some((name, point)) => (name, Some(point)),
        None => (text.trim().to_owned(), None),
    }
}

/// The shown name of a link and, when the name ends in a valid marker and key, the kind
/// of the device and its answer key in X9.63 form. A name without a valid key is the
/// whole name, trimmed, with `None`.
pub fn split_linked_device_name(text: &str) -> (String, Option<(LinkedDeviceKind, Vec<u8>)>) {
    for kind in [LinkedDeviceKind::Iphone, LinkedDeviceKind::Watch] {
        if let Some((name, point)) = key_after_mark(text, kind) {
            return (name, Some((kind, point)));
        }
    }
    (text.trim().to_owned(), None)
}

/// The name of a link for the screen: the name without an answer key of an iPhone or a
/// watch.
pub fn shown_link_name(text: &str) -> String {
    split_linked_device_name(text).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::DeviceKey;

    const ANSWER_PUBLIC: &str =
        "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts";

    #[test]
    fn points_compress_and_come_back() {
        let mut keys = vec![decode_b64u(ANSWER_PUBLIC).unwrap()];
        for _ in 0..24 {
            keys.push(DeviceKey::generate().unwrap().public_key().to_vec());
        }
        let mut parities = [0usize; 2];
        for key in keys {
            let compressed = compress_point(&key).unwrap();
            parities[usize::from(compressed[0] & 1)] += 1;
            assert_eq!(decompress_point(&compressed).as_deref(), Some(&key[..]));
        }
        assert!(parities[0] > 0 && parities[1] > 0, "{parities:?}");
    }

    #[test]
    fn points_of_another_form_or_off_the_curve_are_refused() {
        let key = decode_b64u(ANSWER_PUBLIC).unwrap();
        let compressed = compress_point(&key).unwrap();
        assert_eq!(compress_point(&key[..64]), None);
        assert_eq!(compress_point(&compressed), None);
        let mut prefix = compressed;
        prefix[0] = 0x04;
        assert_eq!(decompress_point(&prefix), None);
        assert_eq!(decompress_point(&compressed[..32]), None);
        // x = p is not a coordinate; about half of the x values are on no point.
        let mut too_big = [0xffu8; 33];
        too_big[0] = 0x02;
        assert_eq!(decompress_point(&too_big), None);
        let off = (1u8..=40)
            .filter(|fill| {
                let mut candidate = [*fill; 33];
                candidate[0] = 0x02;
                decompress_point(&candidate).is_none()
            })
            .count();
        assert!(off > 5 && off < 35, "{off}");
    }

    #[test]
    fn a_link_name_carries_the_answer_key_within_64_bytes() {
        let key = decode_b64u(ANSWER_PUBLIC).unwrap();
        let name = link_device_name("Test iPhone", &key).unwrap();
        assert!(name.starts_with("Test iPhone ~"), "{name}");
        assert!(name.len() <= MAX_LINK_NAME_BYTES);
        assert_eq!(
            split_link_device_name(&name),
            ("Test iPhone".to_owned(), Some(key.clone()))
        );
        assert_eq!(shown_link_name(&name), "Test iPhone");
        // A long name is cut at a character; an empty one is "iPhone".
        let long = link_device_name("Rafał's very long iPhone name", &key).unwrap();
        assert!(long.len() <= MAX_LINK_NAME_BYTES, "{long}");
        assert_eq!(split_link_device_name(&long).1, Some(key.clone()));
        assert!(
            link_device_name(" \t", &key)
                .unwrap()
                .starts_with("iPhone ~")
        );
        // A Mac's name, and a name with a broken key, carry no key.
        assert_eq!(
            split_link_device_name("Mac mini"),
            ("Mac mini".to_owned(), None)
        );
        let broken = format!("Test iPhone ~{}", "A".repeat(44));
        assert_eq!(split_link_device_name(&broken), (broken.clone(), None));
        assert_eq!(link_device_name("Test iPhone", &key[..33]), None);
    }

    #[test]
    fn both_kinds_round_trip_and_never_mix() {
        let key = decode_b64u(ANSWER_PUBLIC).unwrap();
        let phone = link_device_name("Test iPhone", &key).unwrap();
        let watch = watch_link_device_name("Test Watch", &key).unwrap();
        assert!(watch.starts_with("Test Watch ~W"), "{watch}");
        assert_eq!(watch.len(), "Test Watch".len() + 3 + 44);
        assert_eq!(
            split_linked_device_name(&phone),
            (
                "Test iPhone".to_owned(),
                Some((LinkedDeviceKind::Iphone, key.clone()))
            )
        );
        assert_eq!(
            split_linked_device_name(&watch),
            (
                "Test Watch".to_owned(),
                Some((LinkedDeviceKind::Watch, key.clone()))
            )
        );
        assert_eq!(shown_link_name(&watch), "Test Watch");
        assert_eq!(shown_link_name(&phone), "Test iPhone");
        // The iPhone path takes no watch key: a 45-character rest is not an iPhone key.
        assert_eq!(split_link_device_name(&watch), (watch.clone(), None));
        assert_eq!(watch_link_device_name("Test Watch", &key[..33]), None);
    }

    #[test]
    fn a_broken_watch_key_keeps_the_whole_name() {
        let key = decode_b64u(ANSWER_PUBLIC).unwrap();
        let watch = watch_link_device_name("Test Watch", &key).unwrap();
        // x = p is on no point; a key of 43 or 45 characters is no key.
        let mut off = [0xffu8; 33];
        off[0] = 0x02;
        let short = &watch[..watch.len() - 1];
        let long = format!("{watch}A");
        for text in [
            format!("Test Watch ~W{}", encode_b64u(&off)),
            short.to_owned(),
            long,
            format!(" ~W{}", &watch[watch.len() - 44..]),
        ] {
            assert_eq!(
                split_linked_device_name(&text),
                (text.trim().to_owned(), None),
                "{text}"
            );
            assert_eq!(shown_link_name(&text), text.trim());
        }
        // ` ~X` is not a kind.
        let other = watch.replacen(" ~W", " ~X", 1);
        assert_eq!(split_linked_device_name(&other), (other.clone(), None));
    }

    #[test]
    fn a_watch_name_is_cut_on_a_character_to_17_bytes() {
        let key = decode_b64u(ANSWER_PUBLIC).unwrap();
        for name in [
            "Zegarek Rafała ąęśćż",
            "ŻŻŻŻŻŻŻŻŻŻ",
            "⌚⌚⌚⌚⌚⌚⌚",
            "Apple Watch of a very long name",
        ] {
            let link = watch_link_device_name(name, &key).unwrap();
            assert!(link.len() <= MAX_LINK_NAME_BYTES, "{link}");
            let (shown, found) = split_linked_device_name(&link);
            assert!(shown.len() <= 17, "{shown:?}");
            assert!(name.starts_with(&shown), "{shown:?}");
            assert_eq!(found, Some((LinkedDeviceKind::Watch, key.clone())));
        }
        // 2-byte characters: eight fit in 17 bytes, the ninth does not.
        let (shown, _) =
            split_linked_device_name(&watch_link_device_name("ŻŻŻŻŻŻŻŻŻŻ", &key).unwrap());
        assert_eq!(shown, "ŻŻŻŻŻŻŻŻ");
        assert!(
            watch_link_device_name(" \t", &key)
                .unwrap()
                .starts_with("Apple Watch ~W")
        );
        // An iPhone name of the longest size still parses the same.
        let phone = link_device_name("Rafał's very long iPhone name", &key).unwrap();
        assert_eq!(
            split_link_device_name(&phone).0,
            split_linked_device_name(&phone).0
        );
    }

    #[test]
    fn old_iphone_names_parse_as_before() {
        let key = decode_b64u(ANSWER_PUBLIC).unwrap();
        let compressed = encode_b64u(&compress_point(&key).unwrap());
        for text in [
            format!("Test iPhone ~{compressed}"),
            format!("  Test iPhone ~{compressed}  "),
            format!("A ~ B ~{compressed}"),
            "Mac mini".to_owned(),
            format!("Test iPhone ~{}", "A".repeat(44)),
            format!(" ~{compressed}"),
            "".to_owned(),
        ] {
            let (name, found) = split_link_device_name(&text);
            let (linked_name, linked) = split_linked_device_name(&text);
            assert_eq!(name, linked_name, "{text:?}");
            assert_eq!(
                found,
                linked.map(|(kind, point)| {
                    assert_eq!(kind, LinkedDeviceKind::Iphone);
                    point
                }),
                "{text:?}"
            );
        }
    }
}
