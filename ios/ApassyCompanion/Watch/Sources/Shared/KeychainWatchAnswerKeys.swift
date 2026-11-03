import ApassyVaultKit
import CryptoKit
import Foundation
import LocalAuthentication

/// The answer keys of this watch (ADR 0039 section 3): one P-256 key per questions team in the
/// Secure Enclave, with the access control of `WatchAnswerKeyPolicy`. The keychain holds only the
/// `dataRepresentation` of each key, a blob that only this Secure Enclave can use.
///
/// The Simulator has no Secure Enclave and no passcode: a Simulator build keeps a software key in
/// the keychain instead, for development only.
struct KeychainWatchAnswerKeys: WatchAnswerKeys {
    static let account = "answer-key"

    var canSign: Bool {
        #if targetEnvironment(simulator)
            return true
        #else
            // A passcode is set. The wrist is checked at each signature.
            let context = LAContext()
            defer { context.invalidate() }
            return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
        #endif
    }

    func create(team: String) throws -> Data {
        let service = WatchAnswerKeyPolicy.service(team: team)
        #if targetEnvironment(simulator)
            let key = P256.Signing.PrivateKey()
            try WatchKeychain.save(key.rawRepresentation, service: service, account: Self.account)
            return key.publicKey.x963Representation
        #else
            guard SecureEnclave.isAvailable else { throw WatchKeyError.failed(code: Int(errSecUnimplemented)) }
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: WatchAnswerKeyPolicy.accessControl())
            try WatchKeychain.save(key.dataRepresentation, service: service, account: Self.account)
            return key.publicKey.x963Representation
        #endif
    }

    func publicKey(team: String) -> Data? {
        guard let blob = try? WatchKeychain.load(service: WatchAnswerKeyPolicy.service(team: team), account: Self.account)
        else { return nil }
        #if targetEnvironment(simulator)
            return (try? P256.Signing.PrivateKey(rawRepresentation: blob))?.publicKey.x963Representation
        #else
            // No context: reading the public key needs no authentication.
            return (try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob))?.publicKey.x963Representation
        #endif
    }

    func delete(team: String) {
        WatchKeychain.delete(service: WatchAnswerKeyPolicy.service(team: team), account: Self.account)
    }

    func attempt(team: String) -> any WatchSigningAttempt {
        WristSigningAttempt(service: WatchAnswerKeyPolicy.service(team: team), account: Self.account)
    }
}
