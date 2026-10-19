import Foundation
import Security

/// A local journal key independent of the vault's rotating question key.
/// There is deliberately no update or delete operation: unreadable keys must not
/// silently replace the key that protects an existing journal.
public final class KeychainHistoryKeyStore: Sendable {
    public enum ReadResult: Equatable, Sendable {
        case value(Data)
        case missing
        case unavailable
    }

    public enum AddResult: Equatable, Sendable {
        case added
        case duplicate
        case unavailable
    }

    public enum KeyResult: Equatable, Sendable {
        case key(Data)
        case missing
        case unavailable
    }

    /// All operations must be thread-safe. Tests inject an in-memory backend;
    /// constructing a store does not read or write Keychain.
    public struct Backend: Sendable {
        public let read: @Sendable (String) -> ReadResult
        public let add: @Sendable (String, Data) -> AddResult
        public let randomKey: @Sendable () -> Data?

        public init(read: @escaping @Sendable (String) -> ReadResult,
                    add: @escaping @Sendable (String, Data) -> AddResult,
                    randomKey: @escaping @Sendable () -> Data?) {
            self.read = read
            self.add = add
            self.randomKey = randomKey
        }
    }

    private let backend: Backend

    public init(backend: Backend? = nil) {
        self.backend = backend ?? Self.keychainBackend
    }

    public static func isValidVaultID(_ vaultID: String) -> Bool {
        (16...64).contains(vaultID.utf8.count) && vaultID.utf8.allSatisfy {
            $0 == 45 || (48...57).contains($0) || (97...102).contains($0)
        }
    }

    public func key(vaultID: String, mayCreate: Bool) -> KeyResult {
        guard Self.isValidVaultID(vaultID) else { return .unavailable }
        switch backend.read(vaultID) {
        case .value(let key):
            return key.count == 32 ? .key(key) : .unavailable
        case .unavailable:
            return .unavailable
        case .missing:
            guard mayCreate else { return .missing }
        }

        guard let candidate = backend.randomKey(), candidate.count == 32 else { return .unavailable }
        switch backend.add(vaultID, candidate) {
        case .added:
            return .key(candidate)
        case .unavailable:
            return .unavailable
        case .duplicate:
            // A concurrent caller won. Only its persisted key can encrypt data.
            guard case .value(let existing) = backend.read(vaultID), existing.count == 32 else {
                return .unavailable
            }
            return .key(existing)
        }
    }

    private static func query(vaultID: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.wydrox.apassy.request-history-key",
            kSecAttrAccount as String: vaultID,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private static var keychainBackend: Backend {
        Backend(read: { vaultID in
            var request = query(vaultID: vaultID)
            request[kSecReturnData as String] = true
            request[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            switch SecItemCopyMatching(request as CFDictionary, &result) {
            case errSecSuccess:
                guard let data = result as? Data else { return .unavailable }
                return .value(data)
            case errSecItemNotFound:
                return .missing
            default:
                return .unavailable
            }
        }, add: { vaultID, key in
            var request = query(vaultID: vaultID)
            request[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            request[kSecValueData as String] = key
            switch SecItemAdd(request as CFDictionary, nil) {
            case errSecSuccess: return .added
            case errSecDuplicateItem: return .duplicate
            default: return .unavailable
            }
        }, randomKey: {
            var key = Data(count: 32)
            let status = key.withUnsafeMutableBytes { bytes in
                guard let base = bytes.baseAddress else { return errSecParam }
                return SecRandomCopyBytes(kSecRandomDefault, bytes.count, base)
            }
            return status == errSecSuccess ? key : nil
        })
    }
}
