import CryptoKit
import Foundation

// Passkeys (contract: a Login with one passkey, the calls passkey_*). Bytes go over the wire as
// standard base64, which is how `JSONEncoder` and `JSONDecoder` write and read `Data`. No type
// here holds a passkey key except `PasskeyImportAccount` and `ExportedPasskey`, which live only
// for one hand-off and are never logged or written to a file.

/// The algorithms of Apassy passkeys.
public enum PasskeyAlgorithm {
    /// ES256: ECDSA on P-256 with SHA-256 (COSE -7). The only one that Apassy has.
    public static let es256 = -7
}

/// The passkey of a login, without its key (contract: `Detail.passkey`).
public struct PasskeySummary: Codable, Sendable, Hashable {
    public var rpID: String
    public var userName: String
    public var userDisplayName: String
    public var credentialID: Data
    public var userHandle: Data

    public init(rpID: String, userName: String, userDisplayName: String, credentialID: Data, userHandle: Data) {
        self.rpID = rpID
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.credentialID = credentialID
        self.userHandle = userHandle
    }

    enum CodingKeys: String, CodingKey {
        case rpID = "rp_id"
        case userName = "user_name"
        case userDisplayName = "user_display_name"
        case credentialID = "credential_id"
        case userHandle = "user_handle"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        rpID = try container.decode(String.self, forKey: .rpID)
        userName = try container.decodeIfPresent(String.self, forKey: .userName) ?? ""
        userDisplayName = try container.decodeIfPresent(String.self, forKey: .userDisplayName) ?? ""
        credentialID = try container.decode(Data.self, forKey: .credentialID)
        userHandle = try container.decodeIfPresent(Data.self, forKey: .userHandle) ?? Data()
    }

    /// The account the passkey signs in to, as the owner reads it.
    public var accountName: String {
        if !userName.isEmpty { return userName }
        return userDisplayName
    }
}

/// A passkey that AutoFill can offer (`passkey_list`).
public struct PasskeyCandidate: Codable, Sendable, Hashable, Identifiable {
    /// The item.
    public var id: UInt64
    public var title: String
    public var rpID: String
    public var userName: String
    public var userDisplayName: String
    public var credentialID: Data
    public var userHandle: Data

    public init(
        id: UInt64, title: String, rpID: String, userName: String, userDisplayName: String, credentialID: Data,
        userHandle: Data
    ) {
        self.id = id
        self.title = title
        self.rpID = rpID
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.credentialID = credentialID
        self.userHandle = userHandle
    }

    enum CodingKeys: String, CodingKey {
        case id, title
        case rpID = "rp_id"
        case userName = "user_name"
        case userDisplayName = "user_display_name"
        case credentialID = "credential_id"
        case userHandle = "user_handle"
    }
}

/// A sign-in with a passkey (`passkey_assert`).
public struct PasskeyAssertionRequest: Sendable, Hashable {
    public var id: UInt64
    public var rpID: String
    public var credentialID: Data
    /// SHA-256 of the client data that the browser or the app made: 32 bytes.
    public var clientDataHash: Data

    public init(id: UInt64, rpID: String, credentialID: Data, clientDataHash: Data) {
        self.id = id
        self.rpID = rpID
        self.credentialID = credentialID
        self.clientDataHash = clientDataHash
    }
}

/// The answer of `passkey_assert`.
public struct PasskeyAssertion: Codable, Sendable, Hashable {
    public var credentialID: Data
    public var userHandle: Data
    public var authenticatorData: Data
    public var signature: Data

    public init(credentialID: Data, userHandle: Data, authenticatorData: Data, signature: Data) {
        self.credentialID = credentialID
        self.userHandle = userHandle
        self.authenticatorData = authenticatorData
        self.signature = signature
    }

    enum CodingKeys: String, CodingKey {
        case credentialID = "credential_id"
        case userHandle = "user_handle"
        case authenticatorData = "authenticator_data"
        case signature
    }
}

/// A new passkey (`passkey_register`).
public struct PasskeyRegistration: Sendable, Hashable {
    /// A login to add the passkey to, with the revision that the owner saw.
    public struct Attach: Sendable, Hashable {
        public var id: UInt64
        public var revision: UInt64

        public init(id: UInt64, revision: UInt64) {
            self.id = id
            self.revision = revision
        }
    }

    public var rpID: String
    public var userName: String
    public var userDisplayName: String
    public var userHandle: Data
    public var clientDataHash: Data
    /// The COSE algorithms that the relying party accepts, in its order.
    public var algorithms: [Int]
    /// The credential IDs that the relying party has for this account already.
    public var excluded: [Data]
    /// nil: a new login named `title`.
    public var attach: Attach?
    public var title: String

    public init(
        rpID: String, userName: String, userDisplayName: String, userHandle: Data, clientDataHash: Data,
        algorithms: [Int], excluded: [Data], attach: Attach?, title: String
    ) {
        self.rpID = rpID
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.userHandle = userHandle
        self.clientDataHash = clientDataHash
        self.algorithms = algorithms
        self.excluded = excluded
        self.attach = attach
        self.title = title
    }
}

/// The answer of `passkey_register`.
public struct PasskeyCreated: Codable, Sendable, Hashable {
    public var id: UInt64
    public var credentialID: Data
    public var attestationObject: Data

    public init(id: UInt64, credentialID: Data, attestationObject: Data) {
        self.id = id
        self.credentialID = credentialID
        self.attestationObject = attestationObject
    }

    enum CodingKeys: String, CodingKey {
        case id
        case credentialID = "credential_id"
        case attestationObject = "attestation_object"
    }
}

/// A passkey from another app, for `passkey_import`. `key` is a normalized DER PKCS#8 P-256 key.
public struct PasskeyImportAccount: Sendable, Hashable, CustomStringConvertible {
    public var rpID: String
    public var credentialID: Data
    public var userHandle: Data
    public var userName: String
    public var userDisplayName: String
    public var key: Data
    public var title: String

    public init(
        rpID: String, credentialID: Data, userHandle: Data, userName: String, userDisplayName: String, key: Data,
        title: String
    ) {
        self.rpID = rpID
        self.credentialID = credentialID
        self.userHandle = userHandle
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.key = key
        self.title = title
    }

    /// No key, no names: what a stray print shows.
    public var description: String { "PasskeyImportAccount([redacted])" }
}

/// The answer of `passkey_import`: counts only.
public struct PasskeyImportResult: Codable, Sendable, Equatable {
    public var imported: Int
    public var skippedExisting: Int
    public var failed: Int

    public init(imported: Int, skippedExisting: Int, failed: Int) {
        self.imported = imported
        self.skippedExisting = skippedExisting
        self.failed = failed
    }

    enum CodingKeys: String, CodingKey {
        case imported
        case skippedExisting = "skipped_existing"
        case failed
    }
}

/// A passkey for the QuickType bar and the passkey sheet of iOS: no key.
public struct PasskeyIdentity: Codable, Sendable, Hashable {
    /// The item.
    public var id: UInt64
    public var rpID: String
    public var userName: String
    public var credentialID: Data
    public var userHandle: Data

    public init(id: UInt64, rpID: String, userName: String, credentialID: Data, userHandle: Data) {
        self.id = id
        self.rpID = rpID
        self.userName = userName
        self.credentialID = credentialID
        self.userHandle = userHandle
    }

    enum CodingKeys: String, CodingKey {
        case id
        case rpID = "rp_id"
        case userName = "user_name"
        case credentialID = "credential_id"
        case userHandle = "user_handle"
    }
}

/// A login with a one-time password for the QuickType bar: no code, no seed.
public struct CodeIdentity: Codable, Sendable, Hashable {
    public var id: UInt64
    public var title: String
    public var username: String
    public var host: String

    public init(id: UInt64, title: String, username: String, host: String) {
        self.id = id
        self.title = title
        self.username = username
        self.host = host
    }

    /// What iOS shows for the code: the username, or the title of a login without one.
    public var label: String { username.isEmpty ? title : username }
}

/// What iOS gets for its AutoFill suggestions (`credential_identities`).
public struct IdentitySet: Codable, Sendable, Equatable {
    /// Logins with a password.
    public var passwords: [CredentialIdentity]
    public var passkeys: [PasskeyIdentity]
    /// Logins with a one-time password.
    public var codes: [CodeIdentity]

    public init(passwords: [CredentialIdentity], passkeys: [PasskeyIdentity], codes: [CodeIdentity] = []) {
        self.passwords = passwords
        self.passkeys = passkeys
        self.codes = codes
    }

    enum CodingKeys: String, CodingKey {
        case passwords = "identities"
        case passkeys
        case codes = "totp"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        passwords = try container.decode([CredentialIdentity].self, forKey: .passwords)
        passkeys = try container.decodeIfPresent([PasskeyIdentity].self, forKey: .passkeys) ?? []
        codes = try container.decodeIfPresent([CodeIdentity].self, forKey: .codes) ?? []
    }
}

// MARK: - Export

/// The answer of `credential_export`: the logins as Apple's credential exchange takes them.
/// It holds passwords and passkey keys: hand it to the system and drop it.
public struct CredentialExport: Decodable, Sendable, CustomStringConvertible {
    public var items: [ExportedItem]
    /// Items that the export leaves out (other kinds, nothing to export).
    public var skipped: Int

    public init(items: [ExportedItem], skipped: Int) {
        self.items = items
        self.skipped = skipped
    }

    public var description: String { "CredentialExport(\(items.count) items, [redacted])" }
}

public struct ExportedItem: Decodable, Sendable {
    public var id: UInt64
    public var title: String
    public var notes: String
    public var tags: [String]
    public var createdAt: Int64?
    public var changedAt: Int64?
    public var username: String?
    public var password: String?
    public var websites: [String]
    public var totp: ExportedTotp?
    public var passkey: ExportedPasskey?

    public init(
        id: UInt64, title: String, notes: String = "", tags: [String] = [], createdAt: Int64? = nil,
        changedAt: Int64? = nil, username: String? = nil, password: String? = nil, websites: [String] = [],
        totp: ExportedTotp? = nil, passkey: ExportedPasskey? = nil
    ) {
        self.id = id
        self.title = title
        self.notes = notes
        self.tags = tags
        self.createdAt = createdAt
        self.changedAt = changedAt
        self.username = username
        self.password = password
        self.websites = websites
        self.totp = totp
        self.passkey = passkey
    }

    enum CodingKeys: String, CodingKey {
        case id, title, notes, tags, username, password, websites, totp, passkey
        case createdAt = "created_at"
        case changedAt = "changed_at"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UInt64.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        notes = try container.decodeIfPresent(String.self, forKey: .notes) ?? ""
        tags = try container.decodeIfPresent([String].self, forKey: .tags) ?? []
        createdAt = try container.decodeIfPresent(Int64.self, forKey: .createdAt)
        changedAt = try container.decodeIfPresent(Int64.self, forKey: .changedAt)
        username = try container.decodeIfPresent(String.self, forKey: .username)
        password = try container.decodeIfPresent(String.self, forKey: .password)
        websites = try container.decodeIfPresent([String].self, forKey: .websites) ?? []
        totp = try container.decodeIfPresent(ExportedTotp.self, forKey: .totp)
        passkey = try container.decodeIfPresent(ExportedPasskey.self, forKey: .passkey)
    }
}

public struct ExportedTotp: Decodable, Sendable, Hashable {
    /// The raw key bytes (not base32).
    public var secret: Data
    public var period: Int
    public var digits: Int
    /// `sha1`, `sha256`, or `sha512`.
    public var algorithm: String
    public var issuer: String?
    public var user: String?

    public init(secret: Data, period: Int, digits: Int, algorithm: String, issuer: String?, user: String?) {
        self.secret = secret
        self.period = period
        self.digits = digits
        self.algorithm = algorithm
        self.issuer = issuer
        self.user = user
    }
}

public struct ExportedPasskey: Decodable, Sendable, Hashable {
    public var rpID: String
    public var credentialID: Data
    public var userHandle: Data
    public var userName: String
    public var userDisplayName: String
    /// DER PKCS#8.
    public var key: Data

    public init(rpID: String, credentialID: Data, userHandle: Data, userName: String, userDisplayName: String, key: Data) {
        self.rpID = rpID
        self.credentialID = credentialID
        self.userHandle = userHandle
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.key = key
    }

    enum CodingKeys: String, CodingKey {
        case rpID = "rp_id"
        case credentialID = "credential_id"
        case userHandle = "user_handle"
        case userName = "user_name"
        case userDisplayName = "user_display_name"
        case key
    }
}

// MARK: - The checks of a request

/// Why Apassy refuses a passkey request before it touches the vault. Each case has an error of
/// AuthenticationServices; `message` is plain English for the owner and holds no value.
public enum PasskeyRequestError: Error, Sendable, Equatable {
    /// The client data hash is not 32 bytes.
    case badClientDataHash
    case badRelyingParty
    /// The user handle is empty or longer than 64 bytes (WebAuthn `user.id`).
    case badUserHandle
    case badCredentialID
    /// The relying party accepts no algorithm that Apassy has.
    case unsupportedAlgorithm
    /// The request needs a WebAuthn extension that Apassy does not have.
    case unsupportedExtension(String)

    public var message: String {
        switch self {
        case .badClientDataHash: "The request of the website is not valid."
        case .badRelyingParty: "The request does not name a website."
        case .badUserHandle: "The account of the request is not valid."
        case .badCredentialID: "The passkey of the request is not valid."
        case .unsupportedAlgorithm: "The website asks for a kind of passkey that Apassy cannot make. Apassy makes ES256 passkeys."
        case .unsupportedExtension(let name): "The website needs \(name), which Apassy passkeys do not have."
        }
    }
}

/// What a request asks of a WebAuthn extension, as AutoFill reads it from iOS.
public struct PasskeyExtensionRequest: Sendable, Equatable {
    public enum LargeBlob: Sendable, Equatable {
        case none
        /// Registration: `support: "preferred"`.
        case preferred
        /// Registration: `support: "required"`.
        case required
        /// Assertion: read the blob.
        case read
        /// Assertion: write a blob.
        case write
    }

    public var largeBlob: LargeBlob
    /// The request has PRF input.
    public var prf: Bool

    public init(largeBlob: LargeBlob = .none, prf: Bool = false) {
        self.largeBlob = largeBlob
        self.prf = prf
    }

    /// What Apassy answers: only "not supported" outputs, never a made-up value.
    public struct Answer: Sendable, Equatable {
        /// Registration: report `largeBlob.supported = false`.
        public var largeBlobUnsupported = false
        /// Assertion: report a read without a blob.
        public var largeBlobReadEmpty = false
        /// Assertion: report a failed write.
        public var largeBlobWriteFailed = false
        /// Registration: report `prf.enabled = false`.
        public var prfUnsupported = false

        public init() {}

        public var isEmpty: Bool { self == Answer() }
    }
}

/// The checks of a passkey request: pure, so they run in `swift test`.
public enum PasskeyRequestCheck {
    static let maxCredentialID = 1023
    static let maxUserHandle = 64

    public static func clientDataHash(_ hash: Data) throws(PasskeyRequestError) {
        guard hash.count == SHA256.byteCount else { throw .badClientDataHash }
    }

    public static func relyingParty(_ rpID: String) throws(PasskeyRequestError) {
        let trimmed = rpID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed == rpID, !rpID.contains("/"), !rpID.contains(":"), rpID.utf8.count <= 253
        else { throw .badRelyingParty }
    }

    /// A registration. `algorithms` empty means the WebAuthn default list, which has ES256.
    public static func registration(
        rpID: String, userHandle: Data, clientDataHash hash: Data, algorithms: [Int], extensions: PasskeyExtensionRequest
    ) throws(PasskeyRequestError) -> PasskeyExtensionRequest.Answer {
        try clientDataHash(hash)
        try relyingParty(rpID)
        guard !userHandle.isEmpty, userHandle.count <= maxUserHandle else { throw .badUserHandle }
        guard algorithms.isEmpty || algorithms.contains(PasskeyAlgorithm.es256) else { throw .unsupportedAlgorithm }
        var answer = PasskeyExtensionRequest.Answer()
        switch extensions.largeBlob {
        case .required: throw .unsupportedExtension("large blob storage")
        case .preferred: answer.largeBlobUnsupported = true
        case .none, .read, .write: break
        }
        answer.prfUnsupported = extensions.prf
        return answer
    }

    /// A sign-in. A PRF request gets no PRF output, as WebAuthn says for an authenticator
    /// without it; a large blob request gets an empty read or a failed write.
    public static func assertion(rpID: String, credentialID: Data?, clientDataHash hash: Data, extensions: PasskeyExtensionRequest)
        throws(PasskeyRequestError) -> PasskeyExtensionRequest.Answer
    {
        try clientDataHash(hash)
        try relyingParty(rpID)
        if let credentialID, credentialID.isEmpty || credentialID.count > maxCredentialID { throw .badCredentialID }
        var answer = PasskeyExtensionRequest.Answer()
        switch extensions.largeBlob {
        case .read: answer.largeBlobReadEmpty = true
        case .write: answer.largeBlobWriteFailed = true
        case .none, .preferred, .required: break
        }
        return answer
    }

    /// A passkey key from another app, normalized to the DER PKCS#8 that CryptoKit writes (with
    /// the public point), which the core takes. Throws when it is not a P-256 key.
    public static func normalizedKey(_ key: Data) throws -> Data {
        do {
            return try P256.Signing.PrivateKey(derRepresentation: key).derRepresentation
        } catch {
            throw VaultError(.badKey, "The passkey key is not an ES256 key.")
        }
    }

    /// A passkey from another app, checked before it goes to the core.
    public static func importable(rpID: String, credentialID: Data, userHandle: Data) -> Bool {
        (try? relyingParty(rpID)) != nil && !credentialID.isEmpty && credentialID.count <= maxCredentialID
            && !userHandle.isEmpty && userHandle.count <= maxUserHandle
    }
}

// MARK: - TOTP URIs

/// The `otpauth://` URI of a one-time password, as the core reads it.
public enum OTPAuthURI {
    /// RFC 4648 base32 without padding.
    public static func base32(_ data: Data) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = ""
        var buffer = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                out.append(alphabet[(buffer >> (bits - 5)) & 31])
                bits -= 5
            }
            buffer &= (1 << bits) - 1
        }
        if bits > 0 { out.append(alphabet[(buffer << (5 - bits)) & 31]) }
        return out
    }

    /// RFC 4648 base32, case and padding ignored. nil on a character outside the alphabet.
    public static func decodeBase32(_ text: String) -> Data? {
        var buffer = 0
        var bits = 0
        var out = Data()
        for character in text.uppercased() where character != "=" && character != " " {
            guard let ascii = character.asciiValue else { return nil }
            let value: Int
            switch ascii {
            case 65...90: value = Int(ascii) - 65
            case 50...55: value = Int(ascii) - 24
            default: return nil
            }
            buffer = (buffer << 5) | value
            bits += 5
            if bits >= 8 {
                out.append(UInt8((buffer >> (bits - 8)) & 0xff))
                bits -= 8
            }
            buffer &= (1 << bits) - 1
        }
        return out
    }

    public static func make(
        secret: Data, issuer: String?, account: String?, algorithm: String = "sha1", digits: Int = 6, period: Int = 30
    ) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: ":/?#[]@!$&'()*+,;=")
        let issuer = issuer?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        let account = account?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        let label = [issuer, account].compactMap { $0?.addingPercentEncoding(withAllowedCharacters: allowed) }
            .joined(separator: ":")
        var query = ["secret=\(base32(secret))"]
        if let issuer, let encoded = issuer.addingPercentEncoding(withAllowedCharacters: allowed) {
            query.append("issuer=\(encoded)")
        }
        query.append("algorithm=\(algorithm.uppercased())")
        query.append("digits=\(digits)")
        query.append("period=\(period)")
        return "otpauth://totp/\(label.isEmpty ? "Apassy" : label)?\(query.joined(separator: "&"))"
    }
}

extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
