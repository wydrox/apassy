// The two device keys (contract 5.2): the request key and the approval key.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The two P-256 keys of the phone.
///
/// The request key signs each request and needs no biometry. The approval key signs the pair
/// string once, then only approvals, and each signature needs Face ID or Touch ID.
public protocol CompanionKeys: Sendable {
    /// The request public key, X9.63 uncompressed, 65 bytes.
    var requestPublicKey: Data { get }
    /// The approval public key, X9.63 uncompressed, 65 bytes.
    var approvalPublicKey: Data { get }
    /// True when the private keys are in the Secure Enclave. The pairing screen shows false.
    var isSecureEnclave: Bool { get }
    /// Sign a message with the request key. The signature is DER.
    func signRequest(_ message: Data) throws -> Data
    /// Sign a message with the approval key. The owner sees `reason` in the Face ID prompt.
    /// The signature is DER.
    func signApproval(_ message: Data, reason: String) async throws -> Data
}

/// A key operation failed. Each message is for the owner.
public enum CompanionKeyError: Error, Equatable, LocalizedError {
    /// The device has no Secure Enclave, so it cannot pair.
    case noSecureEnclave
    /// No biometry is enrolled, so it cannot pair.
    case notEnrolled
    /// Face ID or Touch ID is not available now.
    case biometryUnavailable
    /// Face ID or Touch ID is locked after too many failed attempts.
    case lockedOut
    /// The owner or the system cancelled the prompt. Nothing was signed.
    case cancelled
    /// The Face ID or Touch ID match did not succeed, for example a face that was not recognised.
    /// The key is fine: the owner can try again. Nothing was signed.
    case authenticationFailed
    /// The approval key cannot be used: the biometric enrollment changed, or the key is gone.
    /// Pair again.
    case biometryChanged
    /// The private key bytes are not a valid P-256 key.
    case invalidKey
    /// Anything else, with the system code.
    case failed(code: Int)

    public var errorDescription: String? {
        switch self {
        case .noSecureEnclave:
            return "This iPhone has no Secure Enclave, so it cannot pair with Apassy."
        case .notEnrolled:
            return "Set up Face ID or Touch ID in Settings, then pair again."
        case .biometryUnavailable:
            return "Face ID or Touch ID is not available now. Nothing was approved."
        case .lockedOut:
            return "Face ID or Touch ID is locked. Unlock the iPhone with its passcode, then try again. Nothing was approved."
        case .cancelled:
            return "The check was cancelled. Nothing was approved."
        case .authenticationFailed:
            return "Face ID or Touch ID did not recognise you. Nothing was approved. Try again."
        case .biometryChanged:
            return "Face ID or Touch ID changed on this iPhone, so the approval key no longer works. Pair this iPhone again."
        case .invalidKey:
            return "The stored key is not valid. Pair this iPhone again."
        case .failed(let code):
            return "The key could not sign (code \(code)). Nothing was approved."
        }
    }

    /// Map an error from LocalAuthentication, Security, or CryptoKit.
    static func map(_ error: Error) -> CompanionKeyError {
        if let known = error as? CompanionKeyError { return known }
        if case CryptoKitError.underlyingCoreCryptoError(let status) = error {
            return map(status: OSStatus(status))
        }
        let ns = error as NSError
        if ns.domain == LAError.errorDomain {
            switch LAError.Code(rawValue: ns.code) {
            case .userCancel, .systemCancel, .appCancel, .userFallback: return .cancelled
            case .biometryNotEnrolled: return .notEnrolled
            case .biometryLockout: return .lockedOut
            case .biometryNotAvailable, .biometryNotPaired, .biometryDisconnected, .passcodeNotSet, .notInteractive:
                return .biometryUnavailable
            // A failed match (face not recognised): the key is fine, the owner can try again.
            case .authenticationFailed: return .authenticationFailed
            // Any other code, `invalidContext` too, says nothing about the key: the context is new
            // for each signature. The owner sees the code and nothing is signed.
            default: return .failed(code: ns.code)
            }
        }
        if ns.domain == NSOSStatusErrorDomain {
            return map(status: OSStatus(ns.code))
        }
        return .failed(code: ns.code)
    }

    /// Map a Security status code.
    ///
    /// - `errSecUserCanceled` (-128): the owner or the system closed the prompt. Retryable.
    /// - `errSecAuthFailed` (-25293): the generic authentication failure. The Secure Enclave gives
    ///   it when the Face ID or Touch ID match fails (face not recognised, too many attempts),
    ///   and it can also come with a key whose `.biometryCurrentSet` no longer holds. The code
    ///   alone cannot tell the two apart, so it is a retryable `authenticationFailed`; the
    ///   Secure Enclave keys then compare the biometric enrollment (`classifyAuthFailure`) and
    ///   report `biometryChanged` only when it changed.
    /// - `errSecItemNotFound` (-25300): the key is gone, so pairing again is the only way.
    /// - `errSecInteractionNotAllowed` (-25308): no prompt can show now (the iPhone is locked).
    static func map(status: OSStatus) -> CompanionKeyError {
        switch status {
        case errSecUserCanceled: return .cancelled
        case errSecAuthFailed: return .authenticationFailed
        case errSecItemNotFound: return .biometryChanged
        case errSecInteractionNotAllowed: return .biometryUnavailable
        default: return .failed(code: Int(status))
        }
    }

    /// What a failed approval means, given the biometric enrollment when the keys were made and now
    /// (`LAContext.domainState.biometry.stateHash`). A changed enrollment makes the approval key
    /// unusable, so it is `biometryChanged`. When nothing changed, or when either state is not
    /// known, the failure stays as it is: a plain failed match that the owner can retry.
    static func classifyAuthFailure(
        _ error: CompanionKeyError, enrolledState: Data?, currentState: Data?
    ) -> CompanionKeyError {
        guard error == .authenticationFailed, let enrolledState, let currentState, enrolledState != currentState
        else {
            return error
        }
        return .biometryChanged
    }

    /// Whether this error means that the approval key cannot be used again, so the app unpairs and
    /// goes back to the pairing flow.
    public var keyIsUnusable: Bool {
        self == .biometryChanged || self == .invalidKey
    }
}

/// The access control of each key, as contract 5.2 says.
///
/// The Secure Enclave code uses these values. They are here so a test can read them on macOS.
public enum CompanionKeyPolicy {
    /// The request key: after first unlock, this device only, with no biometry.
    public static var requestProtection: CFString { kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly }
    public static var requestFlags: SecAccessControlCreateFlags { [.privateKeyUsage] }

    /// The approval key: unlocked, this device only, the current biometric set, and no passcode.
    public static var approvalProtection: CFString { kSecAttrAccessibleWhenUnlockedThisDeviceOnly }
    public static var approvalFlags: SecAccessControlCreateFlags { [.privateKeyUsage, .biometryCurrentSet] }
}

/// The text of the Face ID prompt (contract 5.2).
public enum ApprovalPrompt {
    /// The longest agent or Mac name in a prompt, in characters.
    public static let maxNameCharacters = 40

    /// The name as the Mac cleans it: control characters and `"` removed, at most 40 characters,
    /// and `unknown` when nothing is left.
    public static func shortName(_ name: String) -> String {
        let scalars = name.unicodeScalars
            .filter { !TextRules.isControl($0) && $0 != "\"" }
            .prefix(maxNameCharacters)
        let cleaned = String(String.UnicodeScalarView(scalars))
        return TextRules.isBlank(cleaned) ? "unknown" : cleaned
    }

    /// The reason for the approval of a run of an agent: `approve a run of agent "NAME"`.
    public static func approveReason(agent: String) -> String {
        "approve a run of agent \"\(shortName(agent))\""
    }

    /// The reason for the pair string: `pair with Apassy on "MAC NAME"`.
    public static func pairReason(macName: String) -> String {
        "pair with Apassy on \"\(shortName(macName))\""
    }
}
