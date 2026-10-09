import Foundation
import LocalAuthentication
import Security

/// `PassphraseStore` in the keychain. Each read makes a new `LAContext`, so a Face ID
/// match is never reused for a second read.
public struct KeychainPassphraseStore: PassphraseStore {
    private let service: String
    private let accessGroup: String?

    /// - Parameters:
    ///   - service: the keychain service; tests pass their own.
    ///   - accessGroup: the shared group of the app and the extension
    ///     (`SharedContainer.keychainGroup`); nil uses the default group.
    public init(service: String = "com.wydrox.apassy.vault-passphrase", accessGroup: String? = SharedContainer.keychainGroup) {
        self.service = service
        self.accessGroup = accessGroup
    }

    private func query(_ vaultID: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: vaultID,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    public func hasPassphrase(vaultID: String) -> Bool {
        var query = query(vaultID)
        // Asks the item without its data: no Face ID prompt.
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = context
        query[kSecReturnAttributes as String] = true
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    public func save(_ passphrase: String, vaultID: String) throws {
        remove(vaultID: vaultID)
        var error: Unmanaged<CFError>?
        guard
            let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &error)
        else {
            throw VaultError(.storage, "This iPhone cannot keep the passphrase behind Face ID. Set a passcode first.")
        }
        var item = query(vaultID)
        item[kSecAttrAccessControl as String] = access
        item[kSecValueData as String] = Data(passphrase.utf8)
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultError(.storage, "This iPhone did not keep the passphrase (keychain error \(status)).")
        }
    }

    public func read(vaultID: String, reason: String) async throws -> String {
        let store = self
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var request = store.query(vaultID)
                let context = LAContext()
                context.localizedReason = reason
                context.localizedFallbackTitle = "Enter Passphrase"
                request[kSecUseAuthenticationContext as String] = context
                request[kSecReturnData as String] = true
                request[kSecMatchLimit as String] = kSecMatchLimitOne
                var result: CFTypeRef?
                let status = SecItemCopyMatching(request as CFDictionary, &result)
                switch status {
                case errSecSuccess:
                    if let data = result as? Data, let text = String(data: data, encoding: .utf8) {
                        continuation.resume(returning: text)
                    } else {
                        continuation.resume(throwing: VaultError(.storage, "The stored passphrase is damaged."))
                    }
                case errSecUserCanceled, errSecAuthFailed:
                    continuation.resume(throwing: VaultError(.cancelled, "Face ID did not unlock the vault."))
                case errSecItemNotFound:
                    continuation.resume(
                        throwing: VaultError(
                            .locked, "Face ID changed on this iPhone, so Apassy forgot the passphrase. Type it once."))
                default:
                    continuation.resume(
                        throwing: VaultError(.storage, "The keychain did not answer (error \(status))."))
                }
            }
        }
    }

    public func remove(vaultID: String) {
        SecItemDelete(query(vaultID) as CFDictionary)
    }
}

/// `OwnerCheck` with LocalAuthentication: biometry only (no device passcode), a new
/// context for each check.
public struct BiometricOwnerCheck: OwnerCheck {
    public init() {}

    public var biometry: Biometry {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return .none }
        switch context.biometryType {
        case .faceID: return .faceID
        case .touchID: return .touchID
        case .opticID: return .opticID
        default: return .none
        }
    }

    public func confirm(reason: String) async -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = "Enter Passphrase"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return false }
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch {
            return false
        }
    }
}
