// ADR 0030: non-synchronizing device policy. Caller.swift protects every command.
import Foundation
import Security
import LocalAuthentication

let ownerPolicyValues = ["every_time", "1m", "5m", "15m", "1h", "until_lock"]
// Protected device setting: same caller, access group and accessibility as owner policy.
func browserTrustQuery() throws -> Fields {
    var query = try ownerPolicyQuery()
    query[kSecAttrService as String] = "com.wydrox.apassy.browser-trust"
    query[kSecAttrAccount as String] = "profiles-v1"
    return query
}
func handleBrowserTrustRead() throws -> Fields {
    var query = try browserTrustQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let context = LAContext(); context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return ["profiles": "[]"] }
    guard status == errSecSuccess else { throw keychainError(status, "read browser trust") }
    guard let data = result as? Data, data.count <= 32768, let json = String(data: data, encoding: .utf8),
          let list = try? JSONSerialization.jsonObject(with: data) as? [Fields], list.count <= 32
    else { throw HelperError(.failed, "The browser trust setting cannot be verified.") }
    return ["profiles": json]
}
func handleBrowserTrustWrite(_ request: Request) throws -> Fields {
    let json = try request.string("profiles")
    let data = Data(json.utf8)
    guard data.count <= 32768, let list = try? JSONSerialization.jsonObject(with: data) as? [Fields], list.count <= 32 else { throw HelperError(.invalidRequest, "Invalid browser trust list.") }
    let query = try browserTrustQuery()
    let attrs: Fields = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    var status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
    if status == errSecItemNotFound { var item = query; attrs.forEach { item[$0.key] = $0.value }; status = SecItemAdd(item as CFDictionary, nil) }
    guard status == errSecSuccess else { throw keychainError(status, "save browser trust") }
    return try handleBrowserTrustRead()
}
func ownerPolicyQuery() throws -> Fields {
    [kSecClass as String: kSecClassGenericPassword,
     kSecAttrService as String: "com.wydrox.apassy.owner-policy",
     kSecAttrAccount as String: "frequency-v1",
     kSecAttrAccessGroup as String: try requireAccessGroup(),
     kSecUseDataProtectionKeychain as String: true,
     kSecAttrSynchronizable as String: false]
}
func handleOwnerPolicyRead() throws -> Fields {
    var query = try ownerPolicyQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return ["policy": "every_time"] }
    guard status == errSecSuccess else { throw keychainError(status, "read owner policy") }
    guard let data = result as? Data,
          let object = try? JSONSerialization.jsonObject(with: data) as? Fields,
          (object["version"] as? Int) == 1,
          let policy = object["policy"] as? String, ownerPolicyValues.contains(policy)
    else { throw HelperError(.failed, "The owner-check setting cannot be verified.") }
    return ["policy": policy]
}
func handleOwnerPolicyWrite(_ request: Request) throws -> Fields {
    let policy = try request.string("policy")
    guard ownerPolicyValues.contains(policy) else { throw HelperError(.invalidRequest, "Unknown owner-check frequency.") }
    let data = try JSONSerialization.data(withJSONObject: ["version": 1, "policy": policy])
    let query = try ownerPolicyQuery()
    let attrs: Fields = [kSecValueData as String: data,
                        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    var status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
    if status == errSecItemNotFound {
        var item = query
        attrs.forEach { item[$0.key] = $0.value }
        status = SecItemAdd(item as CFDictionary, nil)
    }
    guard status == errSecSuccess else { throw keychainError(status, "save owner policy") }
    return try handleOwnerPolicyRead()
}

let autoLockPolicyValues = ["never", "15m", "1h", "4h", "session"]
func autoLockPolicyQuery() throws -> Fields {
    [kSecClass as String: kSecClassGenericPassword,
     kSecAttrService as String: "com.wydrox.apassy.auto-lock",
     kSecAttrAccount as String: "inactivity-v1",
     kSecAttrAccessGroup as String: try requireAccessGroup(),
     kSecUseDataProtectionKeychain as String: true,
     kSecAttrSynchronizable as String: false]
}
func handleAutoLockPolicyRead() throws -> Fields {
    var query = try autoLockPolicyQuery()
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let context = LAContext()
    context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return ["policy": "never"] }
    guard status == errSecSuccess else { throw keychainError(status, "read owner policy") }
    guard let data = result as? Data,
          let object = try? JSONSerialization.jsonObject(with: data) as? Fields,
          (object["version"] as? Int) == 1,
          let policy = object["policy"] as? String, autoLockPolicyValues.contains(policy)
    else { throw HelperError(.failed, "The auto-lock setting cannot be verified.") }
    return ["policy": policy]
}
func handleAutoLockPolicyWrite(_ request: Request) throws -> Fields {
    let policy = try request.string("policy")
    guard autoLockPolicyValues.contains(policy) else { throw HelperError(.invalidRequest, "Unknown auto-lock frequency.") }
    let data = try JSONSerialization.data(withJSONObject: ["version": 1, "policy": policy])
    let query = try autoLockPolicyQuery()
    let attrs: Fields = [kSecValueData as String: data,
                        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
    var status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
    if status == errSecItemNotFound {
        var item = query
        attrs.forEach { item[$0.key] = $0.value }
        status = SecItemAdd(item as CFDictionary, nil)
    }
    guard status == errSecSuccess else { throw keychainError(status, "save owner policy") }
    return try handleAutoLockPolicyRead()
}
