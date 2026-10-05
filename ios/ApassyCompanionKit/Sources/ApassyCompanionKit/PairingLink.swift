// The pairing link from the QR code (contract 5.1).
//
//     apassy://pair?v=1&h=Mac-mini.local,192.168.1.20&p=48620&c=<pin>&s=<secret>&n=Mac%20mini&e=1790000300
//
// The link is the payload of the QR code. The app scans it itself; it registers no URL scheme.

import Foundation

/// Where the Mac listens and which certificate the phone trusts.
public struct CompanionEndpoint: Sendable, Equatable {
    /// The hosts to try, in order.
    public let hosts: [String]
    public let port: UInt16
    /// SHA-256 of the certificate DER, 32 bytes.
    public let pin: Data

    public init(hosts: [String], port: UInt16, pin: Data) {
        self.hosts = hosts
        self.port = port
        self.pin = pin
    }
}

/// A pairing link is refused. Each message is for the owner.
public enum PairingLinkError: Error, Equatable, LocalizedError {
    /// The text is not a pairing link.
    case notAPairingLink
    /// The link has another contract version.
    case unsupportedVersion(String)
    /// A parameter is missing or empty.
    case missingParameter(String)
    /// A parameter has a value out of its format or range.
    case badParameter(String)
    /// More than 4 hosts.
    case tooManyHosts
    /// The pin or the secret is not 32 bytes of base64url.
    case badPinOrSecret
    /// The window is over.
    case expired

    public var errorDescription: String? {
        switch self {
        case .notAPairingLink:
            return "This is not an Apassy pairing code. Select \"Pair an iPhone\" in Settings > iPhone companion on your Mac."
        case .unsupportedVersion:
            return "This pairing code is from another version of Apassy. Update Apassy on the Mac and on the iPhone."
        case .missingParameter, .badParameter, .tooManyHosts, .badPinOrSecret:
            return "This pairing code is not valid. Select \"Pair an iPhone\" on your Mac to make a new one."
        case .expired:
            return "This pairing code has expired. Select \"Pair an iPhone\" on your Mac to make a new one."
        }
    }
}

/// A parsed pairing link.
public struct PairingLink: Sendable, Equatable {
    public static let supportedVersion = "1"
    public static let maxHosts = 4
    public static let maxMacNameCharacters = 40

    public let hosts: [String]
    public let port: UInt16
    /// The pin of the Mac certificate, 32 bytes.
    public let pin: Data
    /// The one-time pairing secret, 32 bytes.
    public let secret: Data
    /// The Mac name for the screen, without control characters, at most 40 characters.
    public let macName: String
    /// The end of the pairing window, Unix seconds.
    public let expiresAt: Int64

    /// The endpoint that the link names.
    public var endpoint: CompanionEndpoint {
        CompanionEndpoint(hosts: hosts, port: port, pin: pin)
    }

    /// Whether the window is over at `now`.
    public func isExpired(at now: Date) -> Bool {
        Int64(now.timeIntervalSince1970.rounded(.down)) >= expiresAt
    }

    /// Parse the QR payload. `now` is the clock for the expiry check.
    public static func parse(_ text: String, now: Date = Date()) throws -> PairingLink {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        // The payload is ASCII: a non-ASCII byte belongs to no link that a Mac makes.
        guard trimmed.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }),
            let components = URLComponents(string: trimmed),
            components.scheme == "apassy",
            components.host == "pair",
            components.path.isEmpty,
            components.user == nil,
            components.port == nil
        else {
            throw PairingLinkError.notAPairingLink
        }

        var values: [String: String] = [:]
        for item in components.queryItems ?? [] {
            guard values[item.name] == nil else { throw PairingLinkError.badParameter(item.name) }
            values[item.name] = item.value ?? ""
        }

        guard let version = values["v"], !version.isEmpty else { throw PairingLinkError.missingParameter("v") }
        guard version == supportedVersion else { throw PairingLinkError.unsupportedVersion(version) }

        func required(_ name: String) throws -> String {
            guard let value = values[name], !value.isEmpty else { throw PairingLinkError.missingParameter(name) }
            return value
        }
        let hostText = try required("h")
        let portText = try required("p")
        let pinText = try required("c")
        let secretText = try required("s")
        let nameText = try required("n")
        let expiryText = try required("e")

        let hosts = try parseHosts(hostText)
        let port = try parsePort(portText)
        guard let pin = B64U.decode(pinText), pin.count == 32,
            let secret = B64U.decode(secretText), secret.count == 32
        else {
            throw PairingLinkError.badPinOrSecret
        }
        guard expiryText.utf8.count <= 12, expiryText.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
            let expiresAt = Int64(expiryText)
        else {
            throw PairingLinkError.badParameter("e")
        }
        let link = PairingLink(
            hosts: hosts,
            port: port,
            pin: pin,
            secret: secret,
            macName: cleanMacName(nameText),
            expiresAt: expiresAt
        )
        if link.isExpired(at: now) {
            throw PairingLinkError.expired
        }
        return link
    }

    private static func parseHosts(_ text: String) throws -> [String] {
        let hosts = text.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard hosts.count <= maxHosts else { throw PairingLinkError.tooManyHosts }
        for host in hosts {
            // A `.local` name or an IPv4 address: letters, digits, dots, and hyphens.
            let valid =
                !host.isEmpty && host.utf8.count <= 253
                && host.utf8.allSatisfy { byte in
                    (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A)
                        || (byte >= 0x61 && byte <= 0x7A) || byte == 0x2E || byte == 0x2D
                }
            guard valid else { throw PairingLinkError.badParameter("h") }
        }
        return hosts
    }

    private static func parsePort(_ text: String) throws -> UInt16 {
        guard text.utf8.count <= 5, text.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
            let number = UInt16(text), number >= 1
        else {
            throw PairingLinkError.badParameter("p")
        }
        return number
    }

    /// Remove control characters and cut the name to 40 characters.
    private static func cleanMacName(_ text: String) -> String {
        var name = TextRules.prefix(TextRules.removingControl(text), scalars: maxMacNameCharacters)
        if TextRules.isBlank(name) {
            name = "your Mac"
        }
        return name
    }
}
