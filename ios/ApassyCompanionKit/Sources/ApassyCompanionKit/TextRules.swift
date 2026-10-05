// The character rules of the contract (section 2, "Characters"), in one place.
//
// A length counts Unicode scalar values. A control character is a scalar of general category Cc
// (Rust `char::is_control`). A space at the start or the end is any Unicode `White_Space` scalar
// (Rust `char::is_whitespace`). Foundation's `String.count` counts grapheme clusters and its
// `CharacterSet` names differ, so the code that follows the contract uses these functions.

import Foundation

public enum TextRules {
    /// The longest name of this iPhone, of a Mac in the pairing link, and in a prompt, in scalars.
    public static let maxNameScalars = 40

    /// A scalar of general category Cc.
    public static func isControl(_ scalar: Unicode.Scalar) -> Bool {
        scalar.properties.generalCategory == .control
    }

    /// A scalar with the Unicode `White_Space` property.
    public static func isSpace(_ scalar: Unicode.Scalar) -> Bool {
        scalar.properties.isWhitespace
    }

    /// The number of Unicode scalar values.
    public static func length(_ text: String) -> Int {
        text.unicodeScalars.count
    }

    /// Whether the text has a scalar of category Cc.
    public static func hasControl(_ text: String) -> Bool {
        text.unicodeScalars.contains(where: isControl)
    }

    /// Whether the text is empty or only `White_Space`.
    public static func isBlank(_ text: String) -> Bool {
        text.unicodeScalars.allSatisfy(isSpace)
    }

    /// The text without `White_Space` scalars at the start and at the end.
    public static func trimmed(_ text: String) -> String {
        let scalars = text.unicodeScalars
        guard let start = scalars.firstIndex(where: { !isSpace($0) }),
            let end = scalars.lastIndex(where: { !isSpace($0) })
        else {
            return ""
        }
        return String(scalars[start...end])
    }

    /// The first `count` scalars of the text.
    public static func prefix(_ text: String, scalars count: Int) -> String {
        String(String.UnicodeScalarView(text.unicodeScalars.prefix(count)))
    }

    /// The text without its control characters.
    public static func removingControl(_ text: String) -> String {
        String(String.UnicodeScalarView(text.unicodeScalars.filter { !isControl($0) }))
    }

    /// A name that the Mac accepts for this iPhone: no control character, at most 40 scalars, no
    /// space at the start or the end. `fallback` when nothing is left.
    public static func deviceName(from raw: String, fallback: String) -> String {
        let cleaned = trimmed(prefix(removingControl(raw), scalars: maxNameScalars))
        return cleaned.isEmpty ? fallback : cleaned
    }
}
