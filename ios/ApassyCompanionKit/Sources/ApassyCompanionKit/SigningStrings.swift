// The signing strings of the wire (contract sections 5.3, 6, and 7), and the pairing code.
//
// A signing string is lines joined with a line feed, with no trailing line feed. A field with a
// control character is refused before a string is built.

import Foundation

/// A signing string cannot be built.
public enum SigningError: Error, Equatable, LocalizedError {
    /// A field has a control character.
    case controlCharacter(field: String)

    public var errorDescription: String? {
        switch self {
        case .controlCharacter(let field):
            return "The field \"\(field)\" has a control character. Nothing was sent."
        }
    }
}

/// The action of an approval string.
public enum ApprovalAction: String, Sendable, Equatable {
    case approve
    case approveAndRemember = "approve_and_remember"
}

/// Builds the strings that the keys sign, and the pairing proof and code.
public enum SigningStrings {
    static let pairTag = "apassy-companion-pair-v1"
    static let codeTag = "apassy-companion-code-v1"
    static let requestTag = "apassy-companion-request-v1"
    static let approveTag = "apassy-companion-approve-v1"

    /// The pair string (contract 5.3).
    public static func pair(deviceID: String, deviceName: String, requestKey: Data, approvalKey: Data) throws -> String {
        try join([
            pairTag,
            checked(deviceID, "device_id"),
            checked(deviceName, "device_name"),
            B64U.encode(requestKey),
            B64U.encode(approvalKey),
        ])
    }

    /// The code string (contract 5.3). The code is derived from it.
    public static func code(secret: Data, requestKey: Data, approvalKey: Data) -> String {
        [codeTag, B64U.encode(secret), B64U.encode(requestKey), B64U.encode(approvalKey)]
            .joined(separator: "\n")
    }

    /// The request string (contract section 6). The body hash is over `body`, the exact bytes sent.
    public static func request(
        method: String,
        path: String,
        deviceID: String,
        time: Int64,
        nonce: String,
        body: Data
    ) throws -> String {
        try join([
            requestTag,
            checked(method, "method"),
            checked(path, "path"),
            checked(deviceID, "device_id"),
            String(time),
            checked(nonce, "nonce"),
            Hashing.sha256Hex(body),
        ])
    }

    /// The approval string (contract section 7).
    public static func approve(
        deviceID: String,
        action: ApprovalAction,
        runID: String,
        digest: String,
        time: Int64
    ) throws -> String {
        try join([
            approveTag,
            checked(deviceID, "device_id"),
            action.rawValue,
            checked(runID, "run_id"),
            checked(digest, "digest"),
            String(time),
        ])
    }

    /// The proof of the pairing secret: `HMAC-SHA256(key: secret, message: pair string)`.
    public static func pairProof(secret: Data, pairString: String) -> Data {
        Hashing.hmacSHA256(key: secret, message: Data(pairString.utf8))
    }

    /// Whether the text has a control character (Unicode category Cc, which includes line feed).
    static func hasControlCharacter(_ text: String) -> Bool {
        TextRules.hasControl(text)
    }

    private static func checked(_ field: String, _ name: String) throws -> String {
        if hasControlCharacter(field) {
            throw SigningError.controlCharacter(field: name)
        }
        return field
    }

    private static func join(_ lines: [String]) -> String {
        lines.joined(separator: "\n")
    }
}

/// The 6-digit code that only the phone shows (contract 5.3).
public enum PairingCode {
    /// SHA-256 of the code string.
    public static func hash(secret: Data, requestKey: Data, approvalKey: Data) -> Data {
        Hashing.sha256(Data(SigningStrings.code(secret: secret, requestKey: requestKey, approvalKey: approvalKey).utf8))
    }

    /// The code as 6 digits with leading zeros, for example `348942`.
    public static func digits(secret: Data, requestKey: Data, approvalKey: Data) -> String {
        let h = hash(secret: secret, requestKey: requestKey, approvalKey: approvalKey)
        let number = h.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let text = String(number % 1_000_000)
        return String(repeating: "0", count: 6 - text.count) + text
    }

    /// The code as the phone shows it: `348 942`.
    public static func display(secret: Data, requestKey: Data, approvalKey: Data) -> String {
        let text = digits(secret: secret, requestKey: requestKey, approvalKey: approvalKey)
        return "\(text.prefix(3)) \(text.suffix(3))"
    }
}
