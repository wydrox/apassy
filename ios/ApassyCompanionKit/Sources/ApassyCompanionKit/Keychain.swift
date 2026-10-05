// The keychain items of the companion: generic passwords, this device only, never synchronized.

import Foundation
import Security

/// The keychain refused a request.
public struct CompanionStorageError: Error, Equatable, LocalizedError {
    public let status: Int32

    public var errorDescription: String? {
        "The keychain refused the request (code \(status))."
    }
}

/// The keychain names of the companion.
public enum CompanionKeychain {
    /// The service name of every keychain item of the companion.
    public static let service = "com.wydrox.apassy.companion"
}

enum KeychainItems {
    static func save(_ data: Data, service: String, account: String, accessible: CFString) throws {
        let query = baseQuery(service: service, account: account)
        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = accessible
        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let update: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrAccessible as String: accessible,
            ]
            let updated = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            guard updated == errSecSuccess else { throw CompanionStorageError(status: updated) }
        } else if status != errSecSuccess {
            throw CompanionStorageError(status: status)
        }
    }

    static func load(service: String, account: String) throws -> Data? {
        var query = baseQuery(service: service, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw CompanionStorageError(status: status)
        }
        return data
    }

    static func delete(service: String, account: String) throws {
        let status = SecItemDelete(baseQuery(service: service, account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CompanionStorageError(status: status)
        }
    }

    private static func baseQuery(service: String, account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
        #if os(iOS)
            query[kSecUseDataProtectionKeychain as String] = true
        #endif
        return query
    }
}
