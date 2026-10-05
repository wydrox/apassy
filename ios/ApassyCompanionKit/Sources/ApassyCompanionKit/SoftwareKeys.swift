// Software keys, for the iOS Simulator and for tests. The Secure Enclave keys are in
// SecureEnclaveKeys.swift.

import CryptoKit
import Foundation

/// P-256 keys in memory, or in the keychain.
///
/// The private keys are not in the Secure Enclave, and an approval asks for no Face ID. A build
/// with these keys says so on the pairing screen (`isSecureEnclave` is false). They are for
/// development only.
public struct SoftwareKeys: CompanionKeys {
    static let requestAccount = "software-request-key"
    static let approvalAccount = "software-approval-key"

    private let requestKey: P256.Signing.PrivateKey
    private let approvalKey: P256.Signing.PrivateKey

    public var requestPublicKey: Data { requestKey.publicKey.x963Representation }
    public var approvalPublicKey: Data { approvalKey.publicKey.x963Representation }
    public var isSecureEnclave: Bool { false }

    /// New random keys, in memory only.
    public init() {
        requestKey = P256.Signing.PrivateKey()
        approvalKey = P256.Signing.PrivateKey()
    }

    /// Keys from two raw 32-byte private scalars.
    public init(requestPrivateKey: Data, approvalPrivateKey: Data) throws {
        do {
            requestKey = try P256.Signing.PrivateKey(rawRepresentation: requestPrivateKey)
            approvalKey = try P256.Signing.PrivateKey(rawRepresentation: approvalPrivateKey)
        } catch {
            throw CompanionKeyError.invalidKey
        }
    }

    public func signRequest(_ message: Data) throws -> Data {
        try requestKey.signature(for: message).derRepresentation
    }

    public func signApproval(_ message: Data, reason: String) async throws -> Data {
        try approvalKey.signature(for: message).derRepresentation
    }

    /// New random keys, saved in the keychain. Older software keys are replaced.
    public static func create(service: String = CompanionKeychain.service) throws -> SoftwareKeys {
        let keys = SoftwareKeys()
        try KeychainItems.save(
            keys.requestKey.rawRepresentation, service: service, account: requestAccount,
            accessible: CompanionKeyPolicy.requestProtection)
        try KeychainItems.save(
            keys.approvalKey.rawRepresentation, service: service, account: approvalAccount,
            accessible: CompanionKeyPolicy.approvalProtection)
        return keys
    }

    /// The keys from the keychain, or nil when there are none.
    public static func load(service: String = CompanionKeychain.service) throws -> SoftwareKeys? {
        guard let request = try KeychainItems.load(service: service, account: requestAccount),
            let approval = try KeychainItems.load(service: service, account: approvalAccount)
        else {
            return nil
        }
        return try SoftwareKeys(requestPrivateKey: request, approvalPrivateKey: approval)
    }

    /// Remove the keys from the keychain.
    public static func delete(service: String = CompanionKeychain.service) throws {
        try KeychainItems.delete(service: service, account: requestAccount)
        try KeychainItems.delete(service: service, account: approvalAccount)
    }
}
