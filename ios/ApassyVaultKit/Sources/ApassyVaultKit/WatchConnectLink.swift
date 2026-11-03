import ApassyCompanionKit
import Foundation

/// The Connect code that the iPhone scans on the Mac and hands to the watch (ADR 0032, ADR 0039
/// section 6): a device link of the relay (`apassy_lnk_<team>_<hex>`) with a handoff
/// (`&handoff=`). A plain device link cannot connect a watch.
public enum WatchConnectLink {
    /// The longest name of the watch before the link marker, in UTF-8 bytes (ADR 0039 section 2).
    public static let maxNameBytes = 17
    /// The name when the watch has no usable name of its own.
    public static let fallbackName = "Apple Watch"

    /// Whether `text` is a Connect code that can connect a watch.
    public static func isConnectLink(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.contains("&handoff=") && team(of: trimmed) != nil
    }

    /// The questions team of a device link (`t_` and ten base32 letters), or nil.
    public static func team(of text: String) -> String? {
        guard let start = text.range(of: "apassy_lnk_") else { return nil }
        let code = text[start.upperBound...].prefix { $0 != "&" && !$0.isWhitespace }
        let team = code.prefix(12)
        let base32 = Set("abcdefghijklmnopqrstuvwxyz234567")
        let hex = Set("0123456789abcdef")
        guard team.count == 12, team.hasPrefix("t_"), team.dropFirst(2).allSatisfy(base32.contains),
            code.dropFirst(12).first == "_", code.count > 13, code.dropFirst(13).allSatisfy(hex.contains)
        else { return nil }
        return String(team)
    }

    /// The name that the watch sends with the link: the name of the device as the Mac accepts it
    /// (`TextRules.deviceName`), cut to 17 UTF-8 bytes at a character boundary, else "Apple Watch".
    public static func defaultName(deviceName: String) -> String {
        let cleaned = TextRules.deviceName(from: deviceName, fallback: "")
        var name = ""
        for character in cleaned {
            guard name.utf8.count + String(character).utf8.count <= maxNameBytes else { break }
            name.append(character)
        }
        let trimmed = TextRules.trimmed(name)
        return trimmed.isEmpty ? fallbackName : trimmed
    }
}
