import ApassyVaultKit
import Foundation

/// Text rules of the vault screens that need no UI: how a value is grouped and colored, how a
/// label reads inside a sentence, and how a website opens.
enum VaultText {
    /// The kind of a character in a secret, for its color: digits and symbols stand out from
    /// letters, so the owner can tell `0` from `O` and `l` from `1`.
    enum CharacterClass: Equatable, Sendable {
        case letter
        case digit
        case symbol
        case space
    }

    static func characterClass(_ character: Character) -> CharacterClass {
        if character.isWhitespace { return .space }
        if character.isASCII, character.isNumber { return .digit }
        if character.isLetter { return .letter }
        return .symbol
    }

    /// A one-time code in groups of three: "123456" is "123 456", "12345678" is "12 345 678".
    static func groupedCode(_ code: String) -> String {
        var groups: [String] = []
        var rest = Substring(code)
        while !rest.isEmpty {
            let size = rest.count % 3 == 0 ? 3 : rest.count % 3
            groups.append(String(rest.prefix(size)))
            rest = rest.dropFirst(size)
        }
        return groups.joined(separator: " ")
    }

    /// The digits of a code one by one, so VoiceOver does not read it as one number.
    static func spokenCode(_ code: String) -> String {
        code.filter(\.isNumber).map(String.init).joined(separator: ", ")
    }

    /// A label inside a sentence: "Password" reads "password", "API key" stays as it is.
    static func phrase(_ label: String) -> String {
        let characters = Array(label)
        guard let first = characters.first, first.isUppercase else { return label }
        if characters.count > 1, characters[1].isUppercase { return label }
        return first.lowercased() + String(characters.dropFirst())
    }

    /// The URL to open for a website value; `https://` when it has no scheme. Only http and https.
    static func websiteURL(_ value: String) -> URL? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let text = trimmed.contains("://") ? trimmed : "https://\(trimmed)"
        guard let url = URL(string: text), let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
            url.host() != nil
        else { return nil }
        return url
    }

    /// The host of a website for a row: "github.com".
    static func host(_ value: String) -> String {
        guard let host = websiteURL(value)?.host() else { return value }
        return host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
    }

    /// Whether `text` is a device link of the relay: the link `<relay>/link#apassy_lnk_…`, or the
    /// bare token. Returns the trimmed link, or nil.
    static func joinLink(from text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains(where: \.isNewline) else { return nil }
        if trimmed.hasPrefix("apassy_lnk_") || trimmed.contains("/link#apassy_lnk_") { return trimmed }
        return nil
    }

    /// Whether `text` is a one-time password setup code: an `otpauth://totp/` URI.
    static func otpURI(from text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.lowercased().hasPrefix("otpauth://totp/") ? trimmed : nil
    }

    /// The date of a time of the core (Unix seconds).
    static func date(_ seconds: Int64?) -> Date? {
        seconds.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }

    /// The start of a passkey ID in hex, in groups of four, to tell two passkeys apart.
    static func shortID(_ id: Data) -> String {
        let hex = id.prefix(6).map { String(format: "%02x", $0) }.joined()
        var groups: [String] = []
        var rest = Substring(hex)
        while !rest.isEmpty {
            groups.append(String(rest.prefix(4)))
            rest = rest.dropFirst(4)
        }
        return groups.joined(separator: " ") + (id.count > 6 ? "…" : "")
    }
}
