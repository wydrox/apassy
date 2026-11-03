import Foundation
import Security

/// The answer keys of the watch (ADR 0039 section 3): one P-256 key per questions team, in the
/// Secure Enclave on a watch. Allow once signs with it while the watch is unlocked on the wrist;
/// Deny signs with the relay key in the core and needs no key here.
public protocol WatchAnswerKeys: Sendable {
    /// A new key for `team`; an older key of the team is replaced. The public key, X9.63.
    func create(team: String) throws -> Data
    /// The public key of `team` (X9.63), or nil when this watch has none.
    func publicKey(team: String) -> Data?
    func delete(team: String)
    /// Whether this watch can sign at all: a passcode is set. Being on the wrist is checked at
    /// each signature.
    var canSign: Bool { get }
    /// One signature, with its own authentication context.
    func attempt(team: String) -> any WatchSigningAttempt
}

/// One Allow once signature. The context is new for the attempt and is invalidated after the
/// signature, a failure, or `cancel` (the owner left, the scene went to the background).
public protocol WatchSigningAttempt: AnyObject, Sendable {
    /// Check that the watch is unlocked on the wrist, then sign `message`. The signature is DER.
    func sign(_ message: Data) async throws -> Data
    /// End the attempt: a running check fails, and a later `sign` fails at once.
    func cancel()
}

/// A failed Allow once signature. Nothing was sent.
public enum WatchKeyError: Error, Equatable, LocalizedError {
    /// The watch is locked, off the wrist, or has no passcode.
    case notOnWrist
    /// The attempt was cancelled.
    case cancelled
    /// This watch has no answer key for the team.
    case noKey
    /// Anything else, with the system code.
    case failed(code: Int)

    public var errorDescription: String? {
        switch self {
        case .notOnWrist: "Allow once needs this watch unlocked on your wrist. Nothing was sent."
        case .cancelled: "The check was cancelled. Nothing was sent."
        case .noKey: "This watch has no answer key. Connect this watch again."
        case .failed(let code): "The key could not sign (code \(code)). Nothing was sent."
        }
    }
}

/// The access control of the answer key of the watch, in one place (ADR 0039 section 3). A physical
/// watch may need `.devicePasscode` in place of `.userPresence`; change it only here.
public enum WatchAnswerKeyPolicy {
    /// Removing the passcode destroys the key; it never leaves this watch.
    public static var protection: CFString { kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly }
    public static var flags: SecAccessControlCreateFlags { [.privateKeyUsage, .userPresence] }

    /// The keychain service of the key of `team`.
    public static func service(team: String) -> String { "com.wydrox.apassy.watch.answer-key.\(team)" }

    public static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(nil, protection, flags, &error) else {
            throw error?.takeRetainedValue() ?? WatchKeyError.failed(code: 0)
        }
        return control
    }
}
