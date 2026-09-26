// Touch ID checks with LocalAuthentication.
//
// The policy is `.deviceOwnerAuthenticationWithBiometrics`: Touch ID only.
// The macOS login password is not a fallback. When the owner selects the
// fallback button, the helper returns `fallback`, and the app asks for the
// Apassy passphrase.

import Foundation
import LocalAuthentication

let biometricPolicy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
let fallbackTitle = "Use Apassy Passphrase"

/// Map an LAError to a helper error code.
func mapLAError(_ error: Error?) -> HelperError {
    guard let error = error as NSError?, error.domain == LAError.errorDomain else {
        return HelperError(.failed, "Touch ID did not confirm the owner.")
    }
    switch LAError.Code(rawValue: error.code) {
    case .userCancel, .systemCancel, .appCancel:
        return HelperError(.cancelled, "The owner or the system cancelled Touch ID.")
    case .userFallback:
        return HelperError(.fallback, "The owner selected the Apassy passphrase.")
    case .biometryNotEnrolled:
        return HelperError(.notEnrolled, "No fingerprint is enrolled for Touch ID.")
    case .biometryLockout:
        return HelperError(.lockedOut, "Touch ID is locked after too many failed attempts. Unlock the Mac with its password to reset it.")
    case .biometryDisconnected, .biometryNotPaired:
        return HelperError(.notAvailable, "The Touch ID keyboard is not connected or not paired.")
    case .biometryNotAvailable, .passcodeNotSet:
        return HelperError(.notAvailable, "Touch ID is not available on this Mac.")
    case .authenticationFailed:
        return HelperError(.failed, "Touch ID did not recognize the fingerprint.")
    case .notInteractive:
        return HelperError(.failed, "The system cannot show the Touch ID prompt now.")
    default:
        return HelperError(.failed, "Touch ID failed with LAError \(error.code).")
    }
}

/// Check that Touch ID can run now. Returns the context for later use.
func biometricContext() throws -> LAContext {
    let context = LAContext()
    context.localizedFallbackTitle = fallbackTitle
    var error: NSError?
    guard context.canEvaluatePolicy(biometricPolicy, error: &error) else {
        throw mapLAError(error)
    }
    return context
}

/// The current biometric state hash. It changes when the owner adds or
/// removes a fingerprint. Nil when Touch ID is not available.
func currentBiometryStateHash() -> Data? {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(biometricPolicy, error: &error) else {
        return nil
    }
    return context.domainState.biometry.stateHash
}

func biometryStatus() -> String {
    let context = LAContext()
    var error: NSError?
    if context.canEvaluatePolicy(biometricPolicy, error: &error) {
        return "available"
    }
    return mapLAError(error).code.rawValue
}

/// `authenticate {reason}`: show the Touch ID prompt and wait.
func handleAuthenticate(_ request: Request) throws -> Fields {
    let reason = try request.text("reason", min: 1, max: 200)
    let context = try biometricContext()
    let done = DispatchSemaphore(value: 0)
    let box = ResultBox<(Bool, Error?)>()
    context.evaluatePolicy(biometricPolicy, localizedReason: reason) { success, error in
        box.set((success, error))
        done.signal()
    }
    done.wait()
    guard let (success, error) = box.get() else {
        throw HelperError(.internalError, "Touch ID returned no result.")
    }
    if !success {
        throw mapLAError(error)
    }
    return ["ok": true]
}
