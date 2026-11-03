// The passphrase behind Face ID and the biometric owner check. watchOS has no biometry: the
// Apple Watch keeps its replica passphrase in WatchReplicaStore (ADR 0039).
#if !os(watchOS)
import Foundation
import LocalAuthentication
import Security
import ApassyCompanionKit

/// `PassphraseStore` in the keychain. Default (including AutoFill): fresh contexts.
/// The app explicitly supplies its shared window.
public struct KeychainPassphraseStore: PassphraseStore {
    private let service: String
    private let accessGroup: String?
    private let window: FaceIDWindow?
    var usesAppWindow: Bool { window != nil }

    /// - Parameters:
    ///   - service: the keychain service; tests pass their own.
    ///   - accessGroup: the shared group of the app and the extension
    ///     (`SharedContainer.keychainGroup`); nil uses the default group.
    public init(service: String = "com.wydrox.apassy.vault-passphrase", accessGroup: String? = SharedContainer.keychainGroup, window: FaceIDWindow? = nil) {
        self.service = service
        self.accessGroup = accessGroup
        self.window = window
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
        if let window {
            let lease = try await authenticate(window, reason: reason)
            do {
                let result = try await copy(vaultID, context: Context(lease.context))
                guard lease.isValid else { throw VaultError(.locked, "The Face ID window ended.") }
                lease.end()
                return result
            } catch { lease.end(failed: true); throw error }
        }
        let context = LAContext()
        context.localizedReason = reason
        context.localizedFallbackTitle = "Enter Passphrase"
        return try await copy(vaultID, context: Context(context))
    }

    /// A context that one read hands to a keychain thread; nothing else uses it meanwhile.
    fileprivate struct Context: @unchecked Sendable {
        let context: LAContext
        init(_ context: LAContext) { self.context = context }
    }

    /// Read the passphrase of `vaultID` with `context` on a keychain thread.
    fileprivate func copy(_ vaultID: String, context: Context) async throws -> String {
        let store = self
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var request = store.query(vaultID)
                request[kSecUseAuthenticationContext as String] = context.context
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
                case errSecInteractionNotAllowed:
                    continuation.resume(throwing: VaultError(.locked, "Face ID did not unlock the vault."))
                default:
                    continuation.resume(
                        throwing: VaultError(.storage, "The keychain did not answer (error \(status))."))
                }
            }
        }
    }

    public func readSession(reason: String) async throws -> any PassphraseReads {
        if let window {
            let lease = try await authenticate(window, reason: reason)
            return KeychainReads(store: self, context: Context(lease.context), lease: lease)
        }
        let context = LAContext()
        // No passphrase fallback: a vault that Face ID does not open shows its Unlock row.
        context.localizedFallbackTitle = ""
        do {
            guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            else { throw VaultError(.cancelled, "Face ID did not unlock the vaults.") }
        } catch let error as VaultError {
            throw error
        } catch {
            throw VaultError(.cancelled, "Face ID did not unlock the vaults.")
        }
        // The match counts for every read of this session, and no read may ask again.
        context.interactionNotAllowed = true
        return KeychainReads(store: self, context: Context(context))
    }

    public func remove(vaultID: String) {
        SecItemDelete(query(vaultID) as CFDictionary)
    }

    private func authenticate(_ window: FaceIDWindow, reason: String) async throws -> FaceIDLease {
        do { return try await window.authenticate(reason: reason) }
        catch { throw VaultError(.cancelled, "Face ID did not unlock the vault.") }
    }
}

/// The reads of one evaluated `LAContext` (`KeychainPassphraseStore.readSession`).
private final class KeychainReads: PassphraseReads, @unchecked Sendable {
    private let store: KeychainPassphraseStore
    private let lock = NSLock()
    private var context: KeychainPassphraseStore.Context?
    private let lease: FaceIDLease?

    init(store: KeychainPassphraseStore, context: KeychainPassphraseStore.Context, lease: FaceIDLease? = nil) {
        self.store = store
        self.context = context
        self.lease = lease
    }

    deinit { end() }

    func read(vaultID: String) async throws -> String {
        guard let context = lock.withLock({ self.context }) else {
            throw VaultError(.locked, "Face ID did not unlock the vault.")
        }
        do {
            if let lease, !lease.isValid { throw VaultError(.locked, "The Face ID window ended.") }
            let value = try await store.copy(vaultID, context: context)
            if let lease, !lease.isValid { throw VaultError(.locked, "The Face ID window ended.") }
            return value
        }
        catch { lease?.end(failed: true); throw error }
    }

    func end() {
        let context = lock.withLock {
            defer { self.context = nil }
            return self.context
        }
        if let lease { lease.end() } else { context?.context.invalidate() }
    }
}

/// Biometry only. Defaults to a fresh context; the app opts into its window.
public struct BiometricOwnerCheck: OwnerCheck {
    private let window: FaceIDWindow?
    var usesAppWindow: Bool { window != nil }
    public init(window: FaceIDWindow? = nil) { self.window = window }

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
        if let window {
            do {
                let lease = try await window.authenticate(reason: reason)
                let valid = lease.isValid
                lease.end()
                return valid
            } catch { return false }
        }
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
#endif
