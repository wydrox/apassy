import Foundation
import Security

/// The secret of the replica vault of the watch (ADR 0039 section 4): its passphrase, 32 random
/// bytes in b64u that the watch makes, and the questions team that the watch answers for.
public struct WatchReplicaSecret: Equatable, Sendable {
    public let passphrase: String
    public let team: String

    public init(passphrase: String, team: String) {
        self.passphrase = passphrase
        self.team = team
    }
}

/// Where the watch keeps the secret of its replica vault.
public protocol WatchReplicaStore: Sendable {
    /// A new passphrase for `team`; an older secret is replaced.
    func create(team: String) throws -> WatchReplicaSecret
    func load() throws -> WatchReplicaSecret?
    func delete()
}

extension WatchReplicaStore {
    /// 32 random bytes in b64u.
    public static func newPassphrase() throws -> String {
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, base)
        }
        guard status == errSecSuccess else {
            throw VaultError(.storage, "This watch could not make a passphrase (error \(status)).")
        }
        return Base64URL.encode(bytes)
    }
}

/// The secret in the keychain of the watch: this device only, never synchronized, and only while
/// a passcode is set (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`). The Simulator has no
/// passcode, so a Simulator build keeps it while unlocked instead.
public struct KeychainWatchReplicaStore: WatchReplicaStore {
    static let service = "com.wydrox.apassy.watch.replica"
    static let passphraseAccount = "passphrase"
    static let teamAccount = "team"

    public init() {}

    public func create(team: String) throws -> WatchReplicaSecret {
        let secret = WatchReplicaSecret(passphrase: try Self.newPassphrase(), team: team)
        try WatchKeychain.save(Data(secret.passphrase.utf8), service: Self.service, account: Self.passphraseAccount)
        try WatchKeychain.save(Data(team.utf8), service: Self.service, account: Self.teamAccount)
        return secret
    }

    public func load() throws -> WatchReplicaSecret? {
        guard let passphrase = try WatchKeychain.load(service: Self.service, account: Self.passphraseAccount),
            let team = try WatchKeychain.load(service: Self.service, account: Self.teamAccount)
        else { return nil }
        return WatchReplicaSecret(
            passphrase: String(decoding: passphrase, as: UTF8.self), team: String(decoding: team, as: UTF8.self))
    }

    public func delete() {
        WatchKeychain.delete(service: Self.service, account: Self.passphraseAccount)
        WatchKeychain.delete(service: Self.service, account: Self.teamAccount)
    }
}

/// The secret in memory, for previews and tests.
public final class MemoryWatchReplicaStore: WatchReplicaStore, @unchecked Sendable {
    private let lock = NSLock()
    private var secret: WatchReplicaSecret?

    public init(_ secret: WatchReplicaSecret? = nil) { self.secret = secret }

    public func create(team: String) throws -> WatchReplicaSecret {
        let made = WatchReplicaSecret(passphrase: try Self.newPassphrase(), team: team)
        lock.withLock { secret = made }
        return made
    }

    public func load() throws -> WatchReplicaSecret? { lock.withLock { secret } }

    public func delete() { lock.withLock { secret = nil } }
}

/// Generic passwords of the watch: this device only, never synchronized, in the data protection
/// keychain, in the first keychain access group of the app.
public enum WatchKeychain {
    /// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`; in the Simulator, which has no passcode,
    /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
    public static var protection: CFString {
        #if targetEnvironment(simulator)
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        #else
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        #endif
    }

    public static func save(_ data: Data, service: String, account: String) throws {
        delete(service: service, account: account)
        var item = query(service: service, account: account)
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = protection
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultError(.storage, "This watch could not keep its keys (keychain error \(status)). Set a passcode on this watch.")
        }
    }

    public static func load(service: String, account: String) throws -> Data? {
        var request = query(service: service, account: account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw VaultError(.storage, "The keychain of this watch did not answer (error \(status)).")
        }
        return data
    }

    public static func delete(service: String, account: String) {
        _ = SecItemDelete(query(service: service, account: account) as CFDictionary)
    }

    private static func query(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }
}
