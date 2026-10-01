// Secure Enclave keys (contract 5.2). The code compiles where a Secure Enclave can exist. The
// iOS Simulator has none, so it uses SoftwareKeys.

#if !targetEnvironment(simulator)

    import CryptoKit
    import Foundation
    import LocalAuthentication
    import Security

    /// P-256 keys in the Secure Enclave.
    ///
    /// The request key needs no biometry. The approval key is bound to the current biometric set,
    /// with no passcode fallback: each signature asks for Face ID or Touch ID, in a new
    /// authentication context, with no reuse.
    ///
    /// The keychain holds only each key's `dataRepresentation`, an encrypted blob that only this
    /// Secure Enclave can use.
    public struct SecureEnclaveKeys: CompanionKeys {
        static let requestAccount = "se-request-key"
        static let approvalAccount = "se-approval-key"
        /// The biometric enrollment (`LAContext.domainState.biometry.stateHash`) when the keys were made. It is
        /// not a secret. The keys compare it with the current one after a failed approval, to tell
        /// a face that was not recognised from a changed enrollment.
        static let enrollmentAccount = "se-enrollment-state"

        private let service: String
        private let requestBlob: Data
        private let approvalBlob: Data

        public let requestPublicKey: Data
        public let approvalPublicKey: Data
        public var isSecureEnclave: Bool { true }

        /// Whether this device has a Secure Enclave.
        public static var isAvailable: Bool { SecureEnclave.isAvailable }

        private init(service: String, requestBlob: Data, approvalBlob: Data) throws {
            do {
                requestPublicKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: requestBlob)
                    .publicKey.x963Representation
                // No context: reading the public key needs no biometry.
                approvalPublicKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: approvalBlob)
                    .publicKey.x963Representation
            } catch {
                throw CompanionKeyError.invalidKey
            }
            self.service = service
            self.requestBlob = requestBlob
            self.approvalBlob = approvalBlob
        }

        /// Make both keys and save them in the keychain. Older keys are replaced.
        ///
        /// - Throws: `noSecureEnclave` or `notEnrolled` when this device cannot pair.
        public static func create(service: String = CompanionKeychain.service) throws -> SecureEnclaveKeys {
            guard SecureEnclave.isAvailable else { throw CompanionKeyError.noSecureEnclave }
            try requireBiometry()
            do {
                let request = try SecureEnclave.P256.Signing.PrivateKey(
                    accessControl: accessControl(CompanionKeyPolicy.requestProtection, CompanionKeyPolicy.requestFlags))
                let approval = try SecureEnclave.P256.Signing.PrivateKey(
                    accessControl: accessControl(CompanionKeyPolicy.approvalProtection, CompanionKeyPolicy.approvalFlags))
                try KeychainItems.save(
                    request.dataRepresentation, service: service, account: requestAccount,
                    accessible: CompanionKeyPolicy.requestProtection)
                try KeychainItems.save(
                    approval.dataRepresentation, service: service, account: approvalAccount,
                    accessible: CompanionKeyPolicy.approvalProtection)
                if let state = enrollmentState() {
                    try KeychainItems.save(
                        state, service: service, account: enrollmentAccount,
                        accessible: CompanionKeyPolicy.approvalProtection)
                }
                return try SecureEnclaveKeys(
                    service: service, requestBlob: request.dataRepresentation,
                    approvalBlob: approval.dataRepresentation)
            } catch {
                try? delete(service: service)
                throw CompanionKeyError.map(error)
            }
        }

        /// The keys from the keychain, or nil when there are none.
        public static func load(service: String = CompanionKeychain.service) throws -> SecureEnclaveKeys? {
            guard let request = try KeychainItems.load(service: service, account: requestAccount),
                let approval = try KeychainItems.load(service: service, account: approvalAccount)
            else {
                return nil
            }
            return try SecureEnclaveKeys(service: service, requestBlob: request, approvalBlob: approval)
        }

        /// Remove both keys from the keychain.
        public static func delete(service: String = CompanionKeychain.service) throws {
            try KeychainItems.delete(service: service, account: requestAccount)
            try KeychainItems.delete(service: service, account: approvalAccount)
            try KeychainItems.delete(service: service, account: enrollmentAccount)
        }

        public func signRequest(_ message: Data) throws -> Data {
            do {
                let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: requestBlob)
                return try key.signature(for: message).derRepresentation
            } catch {
                throw CompanionKeyError.map(error)
            }
        }

        public func signApproval(_ message: Data, reason: String) async throws -> Data {
            let blob = approvalBlob
            let service = service
            // The signature waits for the owner, so it runs off the cooperative thread pool.
            return try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async {
                    do {
                        let context = LAContext()
                        context.touchIDAuthenticationAllowableReuseDuration = 0
                        context.localizedReason = reason
                        context.localizedFallbackTitle = ""
                        let key = try SecureEnclave.P256.Signing.PrivateKey(
                            dataRepresentation: blob, authenticationContext: context)
                        continuation.resume(returning: try key.signature(for: message).derRepresentation)
                    } catch {
                        // A failed match and a key that a changed enrollment made unusable can give the
                        // same status (`CompanionKeyError.map(status:)`), so the enrollment decides.
                        let stored = try? KeychainItems.load(service: service, account: Self.enrollmentAccount)
                        continuation.resume(
                            throwing: CompanionKeyError.classifyAuthFailure(
                                CompanionKeyError.map(error), enrolledState: stored, currentState: Self.enrollmentState()))
                    }
                }
            }
        }

        /// The state of the biometric enrollment now, or nil when it cannot be read.
        private static func enrollmentState() -> Data? {
            let context = LAContext()
            var error: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return nil }
            return context.domainState.biometry.stateHash
        }

        private static func accessControl(_ protection: CFString, _ flags: SecAccessControlCreateFlags) throws
            -> SecAccessControl
        {
            var error: Unmanaged<CFError>?
            guard let control = SecAccessControlCreateWithFlags(nil, protection, flags, &error) else {
                throw error?.takeRetainedValue() ?? CompanionKeyError.failed(code: 0)
            }
            return control
        }

        /// The approval key needs enrolled biometry.
        private static func requireBiometry() throws {
            let context = LAContext()
            var error: NSError?
            if !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
                throw error.map { CompanionKeyError.map($0) } ?? CompanionKeyError.biometryUnavailable
            }
        }
    }

#endif
