import CryptoKit
import Foundation
import Security

/// The sealed summary of a push (contract push-gateway-v1 section 12): what a Notification
/// Service Extension opens so the notification can say more while the gateway, the node, and
/// Apple see 720 characters of ciphertext only.
///
/// The summary key of a questions team is HKDF-SHA256 of the vault's question key (empty salt,
/// info `apassy-push-summary-v1`, 32 bytes). The app gets it from the core (`push_summary_keys`)
/// and keeps it in a Keychain group shared with its extension. The extension makes no network
/// request, opens no vault, and logs nothing.
public enum PushSummary {
    public static let info = "apassy-push-summary-v1"
    /// b64u of a 12-byte nonce and 512 + 16 bytes of ChaCha20-Poly1305.
    public static let textLength = 720
    public static let sealedLength = 540
    public static let paddedLength = 512
    public static let maxJSONLength = 510
    /// The most keys an extension tries.
    public static let maxKeys = 16

    public enum Kind: String, Sendable, Equatable {
        case run
        case access
    }

    /// An opened summary.
    public struct Content: Sendable, Equatable {
        public let team: String
        public let qid: String
        public let expiresAt: Int64
        public let kind: Kind
        public let title: String
        public let body: String
    }

    /// The summary key of one questions team.
    public struct Key: Sendable {
        public let teamID: String
        let key: SymmetricKey

        /// `key`: b64u of 32 bytes, as the core gives it.
        public init?(teamID: String, key: String) {
            guard !teamID.isEmpty, let bytes = Base64URL.decode(key), bytes.count == 32 else { return nil }
            self.teamID = teamID
            self.key = SymmetricKey(data: bytes)
        }

        init(teamID: String, symmetric: SymmetricKey) {
            self.teamID = teamID
            self.key = symmetric
        }
    }

    /// The summary key of a question key (32 bytes). The app takes it from the core; this is the
    /// same derivation, for the tests.
    public static func key(teamID: String, questionKey: Data) -> Key? {
        guard questionKey.count == 32 else { return nil }
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: questionKey), salt: Data(), info: Data(info.utf8),
            outputByteCount: 32)
        return Key(teamID: teamID, symmetric: derived)
    }

    /// The b64u text of a key, for the tests.
    public static func text(of key: Key) -> String {
        key.key.withUnsafeBytes { Base64URL.encode(Data($0)) }
    }

    /// Open `text` with the first of `keys` (at most 16) that opens it, and check it: `v` 1, the
    /// team of that key, `expires_at` after `now`, and the text rules. nil on any failure.
    public static func open(_ text: String, keys: [Key], now: Date) -> Content? {
        guard text.utf8.count == textLength, let sealed = Base64URL.decode(text), sealed.count == sealedLength,
            let box = try? ChaChaPoly.SealedBox(combined: sealed)
        else { return nil }
        let aad = Data(info.utf8)
        for key in keys.prefix(maxKeys) {
            guard let padded = try? ChaChaPoly.open(box, using: key.key, authenticating: aad) else { continue }
            return content(padded: padded, team: key.teamID, now: now)
        }
        return nil
    }

    private static func content(padded: Data, team: String, now: Date) -> Content? {
        let bytes = [UInt8](padded)
        guard bytes.count == paddedLength else { return nil }
        let length = Int(bytes[0]) << 8 | Int(bytes[1])
        guard (1...maxJSONLength).contains(length), bytes[(2 + length)...].allSatisfy({ $0 == 0 }) else {
            return nil
        }
        let json = Data(bytes[2..<(2 + length)])
        guard let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
            Set(object.keys) == ["v", "team", "qid", "expires_at", "kind", "title", "body"],
            (object["v"] as? NSNumber)?.intValue == 1, (object["v"] as? NSNumber).map(isInteger) == true,
            let summaryTeam = object["team"] as? String, summaryTeam == team,
            let qid = object["qid"] as? String, Base64URL.decode(qid)?.count == 16,
            let expiresNumber = object["expires_at"] as? NSNumber, isInteger(expiresNumber),
            let kindText = object["kind"] as? String, let kind = Kind(rawValue: kindText),
            let title = object["title"] as? String, validText(title, maxBytes: 64),
            let body = object["body"] as? String, validText(body, maxBytes: 160)
        else { return nil }
        let expiresAt = expiresNumber.int64Value
        guard expiresAt > Int64(now.timeIntervalSince1970) else { return nil }
        return Content(team: summaryTeam, qid: qid, expiresAt: expiresAt, kind: kind, title: title, body: body)
    }

    private static func isInteger(_ number: NSNumber) -> Bool {
        // A Bool is an NSNumber too: `true` is no integer here.
        CFGetTypeID(number) != CFBooleanGetTypeID() && number.doubleValue == Double(number.int64Value)
            && number.int64Value >= 0
    }

    /// 1 to `maxBytes` bytes of UTF-8 with no control or format character.
    static func validText(_ text: String, maxBytes: Int) -> Bool {
        (1...maxBytes).contains(text.utf8.count)
            && !text.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
}

/// What a notification shows from its sealed summary (push-gateway-v1 sections 11 and 12).
public enum PushSummaryNotification {
    public enum Device: Sendable {
        case iphone
        /// The watch answers access requests only: a run question says where to answer it.
        case watch
    }

    /// The key of the sealed summary in the APNs payload.
    public static let payloadKey = "s"
    public static let watchRunBody = "Answer on your iPhone or Mac"

    /// The title and body of a notification whose payload carries a summary that one of `keys`
    /// opens; nil keeps the fixed text ("A question is waiting").
    public static func texts(
        userInfo: [AnyHashable: Any], keys: [PushSummary.Key], now: Date, device: Device
    ) -> (title: String, body: String)? {
        guard let text = userInfo[payloadKey] as? String,
            let content = PushSummary.open(text, keys: keys, now: now)
        else { return nil }
        switch (device, content.kind) {
        case (.watch, .run): return (content.title, watchRunBody)
        default: return (content.title, content.body)
        }
    }
}

/// A summary key as the core gives it (`push_summary_keys`).
public struct PushSummaryKey: Sendable, Equatable, Decodable {
    public let teamID: String
    /// b64u of 32 bytes.
    public let key: String

    public init(teamID: String, key: String) {
        self.teamID = teamID
        self.key = key
    }

    private enum CodingKeys: String, CodingKey {
        case teamID = "team_id"
        case key
    }
}

/// The answer of `push_summary_keys`.
public struct PushSummaryKeys: Sendable, Decodable {
    public let keys: [PushSummaryKey]

    public init(keys: [PushSummaryKey]) { self.keys = keys }
}

/// Where the app keeps the summary keys for its Notification Service Extension.
public protocol PushSummaryKeyStore: Sendable {
    /// Keep `keys` (one per team), replacing the key of the same team.
    func save(_ keys: [PushSummaryKey])
    /// Delete the keys of these teams.
    func remove(teamIDs: Set<String>)
    func removeAll()
    /// The teams that have a key.
    func teamIDs() -> Set<String>
    /// Every key, at most 16 (the extension).
    func loadAll() -> [PushSummary.Key]
}

extension PushSummaryKeyStore {
    /// Keep the keys of `keys` and delete those of teams outside `known` and `keys`: a team that
    /// was left loses its key.
    public func sync(_ keys: [PushSummaryKey], known: Set<String>) {
        save(keys)
        let keep = known.union(keys.map(\.teamID))
        let gone = teamIDs().subtracting(keep)
        if !gone.isEmpty { remove(teamIDs: gone) }
    }
}

/// `PushSummaryKeyStore` in a Keychain access group shared with the extension: generic password
/// items of the service `com.wydrox.apassy.push-summary`, one per team, readable after the first
/// unlock, on this device only.
public struct KeychainPushSummaryKeyStore: PushSummaryKeyStore {
    public static let service = "com.wydrox.apassy.push-summary"
    /// The group of the iPhone app and its extension, without the team prefix.
    public static let iphoneGroupSuffix = "com.wydrox.apassy.push"
    /// The group of the watch app and its extension, without the team prefix.
    public static let watchGroupSuffix = "com.wydrox.apassy.watch.push"

    private let service: String
    private let accessGroup: String?

    public init(service: String = KeychainPushSummaryKeyStore.service, accessGroup: String?) {
        self.service = service
        self.accessGroup = accessGroup
    }

    /// The store of this build's iPhone app or watch app (the group with the team prefix of the
    /// Info.plist key `ApassyAppIdentifierPrefix`). nil in `swift test`.
    public static func forThisApp(watch: Bool) -> KeychainPushSummaryKeyStore? {
        guard let prefix = Bundle.main.object(forInfoDictionaryKey: "ApassyAppIdentifierPrefix") as? String,
            !prefix.isEmpty, !prefix.hasPrefix("$(")
        else { return nil }
        return KeychainPushSummaryKeyStore(accessGroup: prefix + (watch ? watchGroupSuffix : iphoneGroupSuffix))
    }

    private func base() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    public func save(_ keys: [PushSummaryKey]) {
        for entry in keys.prefix(PushSummary.maxKeys) {
            guard let bytes = Base64URL.decode(entry.key), bytes.count == 32 else { continue }
            var query = base()
            query[kSecAttrAccount as String] = entry.teamID
            let update: [String: Any] = [kSecValueData as String: bytes]
            if SecItemUpdate(query as CFDictionary, update as CFDictionary) == errSecItemNotFound {
                query[kSecValueData as String] = bytes
                query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                query[kSecAttrSynchronizable as String] = false
                SecItemAdd(query as CFDictionary, nil)
            }
        }
    }

    public func remove(teamIDs: Set<String>) {
        for team in teamIDs {
            var query = base()
            query[kSecAttrAccount as String] = team
            SecItemDelete(query as CFDictionary)
        }
    }

    public func removeAll() {
        SecItemDelete(base() as CFDictionary)
    }

    public func teamIDs() -> Set<String> {
        var query = base()
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
            let items = result as? [[String: Any]]
        else { return [] }
        return Set(items.compactMap { $0[kSecAttrAccount as String] as? String })
    }

    public func loadAll() -> [PushSummary.Key] {
        var query = base()
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = true
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
            let items = result as? [[String: Any]]
        else { return [] }
        return items.prefix(PushSummary.maxKeys).compactMap { item in
            guard let team = item[kSecAttrAccount as String] as? String,
                let data = item[kSecValueData as String] as? Data
            else { return nil }
            return PushSummary.Key(teamID: team, key: Base64URL.encode(data))
        }
    }
}

/// `PushSummaryKeyStore` in memory, for previews and tests.
public final class MemoryPushSummaryKeyStore: PushSummaryKeyStore, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: String] = [:]

    public init() {}

    public func save(_ entries: [PushSummaryKey]) {
        lock.withLock { for entry in entries.prefix(PushSummary.maxKeys) { keys[entry.teamID] = entry.key } }
    }

    public func remove(teamIDs: Set<String>) {
        lock.withLock { for team in teamIDs { keys[team] = nil } }
    }

    public func removeAll() { lock.withLock { keys = [:] } }

    public func teamIDs() -> Set<String> { lock.withLock { Set(keys.keys) } }

    public func loadAll() -> [PushSummary.Key] {
        lock.withLock {
            keys.sorted { $0.key < $1.key }.prefix(PushSummary.maxKeys)
                .compactMap { PushSummary.Key(teamID: $0.key, key: $0.value) }
        }
    }
}
