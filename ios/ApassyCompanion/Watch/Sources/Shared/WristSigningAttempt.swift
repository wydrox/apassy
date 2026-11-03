import ApassyVaultKit
import CryptoKit
import Foundation
import LocalAuthentication

/// One Allow once signature (ADR 0039 section 3): a new `LAContext`, evaluated with
/// `.deviceOwnerAuthenticationWithWristDetection` (it fails when the watch is locked or off the
/// wrist), passed to the Secure Enclave key, and invalidated after the signature, a failure, or
/// `cancel` (the scene went to the background, the request changed, the prepared bytes expired).
final class WristSigningAttempt: WatchSigningAttempt, @unchecked Sendable {
    private let service: String
    private let account: String
    private let context = LAContext()
    private let lock = NSLock()
    private var ended = false

    init(service: String, account: String) {
        self.service = service
        self.account = account
    }

    private var isEnded: Bool { lock.withLock { ended } }

    func cancel() {
        lock.withLock { ended = true }
        context.invalidate()
    }

    func sign(_ message: Data) async throws -> Data {
        defer { cancel() }
        guard !isEnded else { throw WatchKeyError.cancelled }
        guard let blob = try? WatchKeychain.load(service: service, account: account) else {
            throw WatchKeyError.noKey
        }
        #if targetEnvironment(simulator)
            // No wrist and no Secure Enclave in the Simulator: a pause stands in for the check.
            try? await Task.sleep(for: .seconds(1))
            guard !isEnded else { throw WatchKeyError.cancelled }
            guard let key = try? P256.Signing.PrivateKey(rawRepresentation: blob) else { throw WatchKeyError.noKey }
            return try key.signature(for: message).derRepresentation
        #else
            do {
                // The reason is not shown on watchOS, but it may not be empty.
                guard try await context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithWristDetection, localizedReason: "Allow one scoped use attempt")
                else { throw WatchKeyError.notOnWrist }
            } catch let error as WatchKeyError {
                throw error
            } catch {
                throw isEnded ? WatchKeyError.cancelled : WatchKeyError.notOnWrist
            }
            guard !isEnded else { throw WatchKeyError.cancelled }
            // The check passed: the signature uses it and never shows a prompt of its own from the
            // thread below. A context that no longer counts fails at once instead.
            context.interactionNotAllowed = true
            // The signature can wait on the Secure Enclave, so it runs off the cooperative pool.
            return try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .userInitiated).async { [self] in
                    do {
                        let key = try SecureEnclave.P256.Signing.PrivateKey(
                            dataRepresentation: blob, authenticationContext: context)
                        let signature = try key.signature(for: message).derRepresentation
                        guard !isEnded else { throw WatchKeyError.cancelled }
                        continuation.resume(returning: signature)
                    } catch let error as WatchKeyError {
                        continuation.resume(throwing: error)
                    } catch {
                        continuation.resume(throwing: isEnded ? WatchKeyError.cancelled : WatchKeyError.notOnWrist)
                    }
                }
            }
        #endif
    }
}
