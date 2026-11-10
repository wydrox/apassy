import Foundation
import Security

/// The Apassy Connect account device key of this iPhone (contract ios-core-v1 section 5.14,
/// connect-account-v1 section 5): one P-256 key, made by the core, outside every vault. The item
/// is a generic password of the app in the data-protection Keychain, this device only
/// (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) and not synchronizable, so it never reaches
/// iCloud Keychain or a backup on another device. The core reads it only to sign one of the seven
/// messages of section 5 and drops it with `lock` and `suspend`; this type never logs it.
public final class KeychainAccountKeyStore: Sendable {
    public enum ReadResult: Equatable, Sendable {
        case value(Data)
        case missing
        case unavailable
    }

    /// Thread-safe operations. Tests inject an in-memory backend; making a store touches no
    /// Keychain.
    public struct Backend: Sendable {
        public let read: @Sendable () -> ReadResult
        /// Store the key, replacing an earlier one. False: unavailable.
        public let write: @Sendable (Data) -> Bool
        /// True: deleted; false: no key; nil: unavailable.
        public let delete: @Sendable () -> Bool?

        public init(
            read: @escaping @Sendable () -> ReadResult, write: @escaping @Sendable (Data) -> Bool,
            delete: @escaping @Sendable () -> Bool?
        ) {
            self.read = read
            self.write = write
            self.delete = delete
        }
    }

    /// The service of the Keychain item.
    public static let service = "com.wydrox.apassy.connect-account-key"
    /// The largest document the core reads (a P-256 PKCS#8 key is 138 bytes).
    public static let capacity = 1024

    private let backend: Backend

    public init(backend: Backend? = nil) {
        self.backend = backend ?? Self.keychainBackend
    }

    public func read() -> ReadResult {
        switch backend.read() {
        case .value(let key) where (1...Self.capacity).contains(key.count): .value(key)
        case .value: .unavailable
        case let other: other
        }
    }

    public func write(_ key: Data) -> Bool {
        guard (1...Self.capacity).contains(key.count) else { return false }
        return backend.write(key)
    }

    public func delete() -> Bool? { backend.delete() }

    private static var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "device",
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private static var keychainBackend: Backend {
        Backend(
            read: {
                var request = query
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
            },
            write: { key in
                let deleted = SecItemDelete(query as CFDictionary)
                guard deleted == errSecSuccess || deleted == errSecItemNotFound else { return false }
                var request = query
                request[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                request[kSecValueData as String] = key
                return SecItemAdd(request as CFDictionary, nil) == errSecSuccess
            },
            delete: {
                switch SecItemDelete(query as CFDictionary) {
                case errSecSuccess: true
                case errSecItemNotFound: false
                default: nil
                }
            })
    }
}
