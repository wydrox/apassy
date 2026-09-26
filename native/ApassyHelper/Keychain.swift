// The Touch ID unlock key in the data protection keychain.
//
// The item is a generic password with:
// - kSecUseDataProtectionKeychain = true,
// - SecAccessControl .biometryCurrentSet with
//   kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
// - the Apassy keychain access group from the helper entitlements.
//
// The data protection keychain needs the `keychain-access-groups`
// entitlement. On macOS that entitlement needs a provisioning profile. When
// the helper has no access group, each keychain command returns
// `keychain_unavailable`.
//
// kSecAttrGeneric holds the biometric state hash at store time. It is not a
// secret. A different hash at read time means that the owner changed the
// fingerprints, and the helper returns `biometry_changed` without a prompt.

import Foundation
import LocalAuthentication
import Security

let keychainService = "com.wydrox.apassy.vault-unlock"
let maxSecretBytes = 4096

/// The first keychain access group in the signed entitlements of this
/// process, or nil.
func keychainAccessGroup() -> String? {
    guard let task = SecTaskCreateFromSelf(nil),
          let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil)
    else {
        return nil
    }
    return (value as? [String])?.first
}

func requireAccessGroup() throws -> String {
    guard let group = keychainAccessGroup() else {
        throw HelperError(
            .keychainUnavailable,
            "The helper has no keychain access group. Build the app with a provisioning profile. Touch ID can confirm actions but cannot unlock the vault."
        )
    }
    return group
}

func baseQuery(group: String, account: String) -> Fields {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: account,
        kSecAttrAccessGroup as String: group,
        kSecUseDataProtectionKeychain as String: true,
    ]
}

/// Map a keychain status that is not success.
func keychainError(_ status: OSStatus, _ action: String) -> HelperError {
    switch status {
    case errSecMissingEntitlement:
        return HelperError(.keychainUnavailable, "The keychain refused the \(action): missing entitlement (\(status)). Touch ID can confirm actions but cannot unlock the vault.")
    case errSecItemNotFound:
        return HelperError(.notFound, "No Apassy unlock key is in the keychain.")
    case errSecUserCanceled:
        return HelperError(.cancelled, "The owner or the system cancelled Touch ID.")
    case errSecAuthFailed:
        return HelperError(.failed, "Touch ID did not confirm the owner.")
    case errSecInteractionNotAllowed:
        return HelperError(.failed, "The keychain cannot show the Touch ID prompt now (\(status)).")
    case errSecNotAvailable:
        return HelperError(.keychainUnavailable, "The keychain is not available (\(status)).")
    default:
        let text = (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown"
        return HelperError(.failed, "The keychain \(action) failed with status \(status): \(text).")
    }
}

/// Item attributes without the value. This never shows a prompt.
func findAttributes(group: String, account: String) throws -> Fields? {
    var query = baseQuery(group: group, account: account)
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecSuccess:
        return (result as? Fields) ?? [:]
    case errSecItemNotFound:
        return nil
    case errSecInteractionNotAllowed:
        // The item exists, but the attribute read wants authentication.
        return [:]
    default:
        throw keychainError(status, "lookup")
    }
}

/// True when the stored biometric state differs from the current state.
/// False when either state is unknown, for example when the Touch ID
/// keyboard is not connected. A read then reports the Touch ID state.
func biometryChanged(attributes: Fields) -> Bool {
    guard let current = currentBiometryStateHash(),
          let stored = attributes[kSecAttrGeneric as String] as? Data, !stored.isEmpty
    else {
        return false
    }
    return stored != current
}

/// `keychain_store {account, secret_b64}`: replace the unlock key.
func handleKeychainStore(_ request: Request) throws -> Fields {
    let account = try request.identifier("account")
    let encoded = try request.string("secret_b64")
    guard var secret = Data(base64Encoded: encoded), (1...maxSecretBytes).contains(secret.count) else {
        throw HelperError(.invalidRequest, "The field \"secret_b64\" must be standard base64 of 1 to \(maxSecretBytes) bytes.")
    }
    defer { secret.resetBytes(in: 0..<secret.count) }
    let group = try requireAccessGroup()
    // The item is only useful when Touch ID works now.
    let context = try biometricContext()
    let stateHash = context.domainState.biometry.stateHash ?? Data()

    var acError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        .biometryCurrentSet,
        &acError
    ) else {
        let detail = acError.map { String(describing: $0.takeRetainedValue()) } ?? "unknown"
        throw HelperError(.internalError, "The helper could not create the access control: \(detail).")
    }

    let query = baseQuery(group: group, account: account)
    let deleteStatus = SecItemDelete(query as CFDictionary)
    if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
        throw keychainError(deleteStatus, "delete before store")
    }

    var add = query
    add[kSecAttrAccessControl as String] = access
    add[kSecAttrLabel as String] = "Apassy vault unlock key"
    add[kSecAttrDescription as String] = "Apassy Touch ID unlock"
    add[kSecAttrGeneric as String] = stateHash
    add[kSecValueData as String] = secret
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw keychainError(status, "store")
    }
    return ["ok": true, "access_group": group]
}

/// `keychain_read {account, reason}`: show the Touch ID prompt and return
/// the unlock key.
func handleKeychainRead(_ request: Request) throws -> Fields {
    let account = try request.identifier("account")
    let reason = try request.text("reason", min: 1, max: 200)
    let group = try requireAccessGroup()
    guard let attributes = try findAttributes(group: group, account: account) else {
        throw HelperError(.notFound, "No Apassy unlock key is in the keychain.")
    }
    // Map an unusable Touch ID state before the keychain prompt.
    _ = try biometricContext()
    if biometryChanged(attributes: attributes) {
        throw HelperError(.biometryChanged, "The Touch ID fingerprints changed after setup. Unlock with the passphrase and set up Touch ID again.")
    }

    let context = LAContext()
    context.localizedReason = reason
    context.localizedFallbackTitle = ""
    var query = baseQuery(group: group, account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound, (try? findAttributes(group: group, account: account)) != nil {
        // The item is present but its access control no longer matches.
        throw HelperError(.biometryChanged, "The keychain item is no longer valid for the current fingerprints. Unlock with the passphrase and set up Touch ID again.")
    }
    guard status == errSecSuccess, var secret = result as? Data else {
        throw keychainError(status == errSecSuccess ? errSecDecode : status, "read")
    }
    defer { secret.resetBytes(in: 0..<secret.count) }
    return ["ok": true, "secret_b64": secret.base64EncodedString()]
}

/// `keychain_delete {account}`.
func handleKeychainDelete(_ request: Request) throws -> Fields {
    let account = try request.identifier("account")
    let group = try requireAccessGroup()
    let status = SecItemDelete(baseQuery(group: group, account: account) as CFDictionary)
    switch status {
    case errSecSuccess:
        return ["ok": true, "deleted": true]
    case errSecItemNotFound:
        return ["ok": true, "deleted": false]
    default:
        throw keychainError(status, "delete")
    }
}

/// `keychain_exists {account}`: never shows a prompt.
func handleKeychainExists(_ request: Request) throws -> Fields {
    let account = try request.identifier("account")
    let group = try requireAccessGroup()
    guard let attributes = try findAttributes(group: group, account: account) else {
        return ["ok": true, "exists": false, "biometry_changed": false]
    }
    return ["ok": true, "exists": true, "biometry_changed": biometryChanged(attributes: attributes)]
}
