// The code of "Add a device" on the Mac (contract relay-connect-v1, section 7), and the pairing
// link of the local network (contract companion-v1, section 5.1).
//
//     https://<relay>/link#apassy_lnk_<team>_<64 hex>&r=sync|connect&n=<Mac name>&e=<expires>&p=<b64u of apassy://pair…>
//     apassy_lnk_<team>_<64 hex>
//     apassy://pair?v=1&h=…
//
// The QR code and the pasted text are the same string; the app registers no URL scheme. The
// parameters are hints for the screens: the trust comes only from the safety words that the Mac
// and this iPhone both show, and from the owner check on the Mac.

import Foundation

/// What a device does with a relay link (`r`).
public enum ConnectRoute: String, Sendable, Equatable {
    /// Join relay sync: the copy of the vault comes from the relay (a paid plan).
    case sync
    /// Join the Connect team for the questions only: the vault comes from iCloud Drive (Free).
    case connect
}

/// A text that the Mac shows under "Add a device", parsed.
public enum ConnectLink: Sendable, Equatable {
    /// A link of the relay.
    case relay(RelayConnectLink)
    /// A pairing link of the local network, as it was scanned.
    case pairing(String)

    /// A link is at most this many bytes, as on the Mac.
    public static let maxBytes = 2048
    /// The pairing link in `p` is at most this many bytes.
    static let maxPairingBytes = 1024
    /// The Mac name is cut to this many bytes, as on the Mac.
    static let maxNameBytes = 64

    /// Parse a scanned or pasted text (contract relay-connect-v1, section 7.2).
    public static func parse(_ text: String) throws(ConnectLinkError) -> ConnectLink {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.utf8.count <= maxBytes, !trimmed.contains(where: \.isNewline) else {
            throw .notALink
        }
        if trimmed.hasPrefix("apassy://pair?") { return .pairing(trimmed) }

        let relay: String?
        let fragment: Substring
        if let range = trimmed.range(of: "/link#") {
            relay = String(trimmed[..<range.lowerBound])
            fragment = trimmed[range.upperBound...]
        } else {
            relay = nil
            fragment = Substring(trimmed)
        }
        let code: Substring
        let params: Substring
        if let amp = fragment.firstIndex(of: "&") {
            code = fragment[..<amp]
            params = fragment[fragment.index(after: amp)...]
        } else {
            code = fragment
            params = ""
        }
        guard let team = linkCodeTeam(code) else { throw .notALink }
        if let relay, !isRelayOrigin(relay) { throw .notALink }

        var route: ConnectRoute?
        var macName: String?
        var expiresAt: Int64?
        var pairing: String?
        var seen = Set<Substring>()
        for pair in params.split(separator: "&", omittingEmptySubsequences: true) {
            guard let equals = pair.firstIndex(of: "=") else { continue }
            let key = pair[..<equals]
            let value = String(pair[pair.index(after: equals)...])
            // The first value of a key counts.
            guard seen.insert(key).inserted else { continue }
            switch key {
            case "r":
                guard let known = ConnectRoute(rawValue: value) else { throw .needsNewerVersion }
                route = known
            case "n": macName = parseName(value)
            case "e": expiresAt = parseExpiry(value)
            case "p": pairing = parsePairing(value)
            default: break
            }
        }
        return .relay(
            RelayConnectLink(
                text: trimmed, relay: relay, code: String(code), team: team, route: route ?? .sync,
                macName: macName, expiresAt: expiresAt, pairingLink: pairing))
    }

    /// `apassy_lnk_<t_ and 10 of a-z, 2-7>_<64 lowercase hex>`: the team id, or nil.
    static func linkCodeTeam(_ code: Substring) -> String? {
        guard code.hasPrefix("apassy_lnk_") else { return nil }
        let rest = code.utf8.dropFirst("apassy_lnk_".utf8.count)
        guard rest.count == 12 + 1 + 64 else { return nil }
        let team = Array(rest.prefix(12))
        let separator = rest.dropFirst(12).first
        let secret = rest.dropFirst(13)
        let teamValid =
            team.starts(with: Array("t_".utf8))
            && team.dropFirst(2).allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x32 && $0 <= 0x37) }
        let secretValid = secret.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
        guard teamValid, separator == 0x5F, secretValid else { return nil }
        return String(decoding: team, as: UTF8.self)
    }

    /// The part before `/link#`: `https://host[:port]`, or `http://` for a relay on this computer.
    /// The core checks it again.
    private static func isRelayOrigin(_ text: String) -> Bool {
        guard let components = URLComponents(string: text), let scheme = components.scheme?.lowercased(),
            scheme == "https" || scheme == "http", let host = components.host, !host.isEmpty,
            components.path.isEmpty, components.query == nil, components.user == nil
        else { return false }
        return true
    }

    /// `n`: percent-decoded UTF-8, no control character, at most 64 bytes. A bad escape drops it.
    private static func parseName(_ value: String) -> String? {
        guard let decoded = percentDecode(value) else { return nil }
        // As `clean_name` on the Mac: trim, drop control characters, cut at a scalar, trim.
        var name = String.UnicodeScalarView()
        var bytes = 0
        for scalar in TextRules.trimmed(decoded).unicodeScalars where !TextRules.isControl(scalar) {
            let size = String(scalar).utf8.count
            if bytes + size > maxNameBytes { break }
            name.append(scalar)
            bytes += size
        }
        let cleaned = TextRules.trimmed(String(name))
        return cleaned.isEmpty ? nil : cleaned
    }

    /// `e`: a decimal number with no leading zero. A bad value drops it.
    private static func parseExpiry(_ value: String) -> Int64? {
        guard !value.isEmpty, value.utf8.count <= 18, !value.hasPrefix("0"),
            value.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 })
        else { return nil }
        return Int64(value)
    }

    /// `p`: b64u of an `apassy://pair?` link of printable ASCII. A bad value drops it.
    private static func parsePairing(_ value: String) -> String? {
        guard value.utf8.count <= (maxPairingBytes + 2) / 3 * 4, let data = B64U.decode(value),
            data.count <= maxPairingBytes, data.allSatisfy({ $0 > 0x20 && $0 < 0x7F }),
            let text = String(data: data, encoding: .ascii), text.hasPrefix("apassy://pair?")
        else { return nil }
        return text
    }

    /// Decode `%XX` escapes. Nil for a broken escape or bytes that are not UTF-8. A `+` stays.
    private static func percentDecode(_ text: String) -> String? {
        var out: [UInt8] = []
        var bytes = text.utf8.makeIterator()
        while let byte = bytes.next() {
            guard byte == 0x25 else {
                out.append(byte)
                continue
            }
            guard let high = bytes.next(), let low = bytes.next(),
                let value = UInt8(String(decoding: [high, low], as: UTF8.self), radix: 16)
            else { return nil }
            out.append(value)
        }
        return String(validating: out, as: UTF8.self)
    }
}

/// A link of the relay, with the hints of its parameters.
public struct RelayConnectLink: Sendable, Equatable {
    /// The trimmed text, as it goes to the vault core. The core reads the code before the first
    /// `&`, and the relay address before `/link#`.
    public let text: String
    /// The relay address before `/link#`; nil for a bare code (the default relay then).
    public let relay: String?
    /// `apassy_lnk_<team>_<64 hex>`.
    public let code: String
    /// The team id, `t_…`.
    public let team: String
    /// What the join does. A link with no `r` is `sync`, as every link before relay-connect-v1.
    public let route: ConnectRoute
    /// The name of the Mac that made the link, for the screens only.
    public let macName: String?
    /// When the code expires, Unix seconds. The relay decides; this is for the screens.
    public let expiresAt: Int64?
    /// The pairing link of the local network (`apassy://pair?…`), for "Only on this Wi-Fi".
    public let pairingLink: String?
}

/// Why a text is not a code of "Add a device". Each message is for the owner.
public enum ConnectLinkError: Error, Equatable, LocalizedError {
    case notALink
    /// `r` names a route that this version does not know: a newer Mac made the link.
    case needsNewerVersion

    public var errorDescription: String? {
        switch self {
        case .notALink:
            "This is not a code of Apassy. On your Mac, open Apassy > Settings > Devices > Add a device."
        case .needsNewerVersion:
            "This code needs a newer version of Apassy. Update Apassy on this iPhone, then try again."
        }
    }
}
