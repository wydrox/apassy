import CryptoKit
import Foundation
import LocalAuthentication
import Security
import Testing

@testable import ApassyCompanionKit

@Suite("Keys")
struct KeysTests {
    @Test("software keys sign for their public keys, and not for each other")
    func softwareKeys() async throws {
        let keys = SoftwareKeys()
        #expect(keys.requestPublicKey.count == 65)
        #expect(keys.approvalPublicKey.count == 65)
        #expect(keys.requestPublicKey != keys.approvalPublicKey)
        let message = Data("hello".utf8)
        let request = try keys.signRequest(message)
        let approval = try await keys.signApproval(message, reason: "test")
        #expect(Vectors.verifies(signature: request, of: "hello", publicKey: keys.requestPublicKey))
        #expect(!Vectors.verifies(signature: request, of: "hello", publicKey: keys.approvalPublicKey))
        #expect(Vectors.verifies(signature: approval, of: "hello", publicKey: keys.approvalPublicKey))
        #expect(!Vectors.verifies(signature: approval, of: "hello", publicKey: keys.requestPublicKey))
        #expect(!keys.isSecureEnclave)
    }

    @Test("raw private keys of the wrong size are refused")
    func badPrivateKey() {
        #expect(throws: CompanionKeyError.invalidKey) {
            try SoftwareKeys(requestPrivateKey: Data(count: 31), approvalPrivateKey: Data(count: 32))
        }
        #expect(throws: CompanionKeyError.invalidKey) {
            try SoftwareKeys(requestPrivateKey: Data(count: 32), approvalPrivateKey: Data(count: 32))
        }
    }

    @Test("the request key has no biometry, and the approval key has the current biometric set and no passcode")
    func accessControl() {
        let request = CompanionKeyPolicy.requestFlags
        #expect(request == [.privateKeyUsage])
        #expect(CompanionKeyPolicy.requestProtection == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)

        let approval = CompanionKeyPolicy.approvalFlags
        #expect(approval.contains(.privateKeyUsage))
        #expect(approval.contains(.biometryCurrentSet))
        #expect(!approval.contains(.devicePasscode))
        #expect(!approval.contains(.userPresence))
        #expect(!approval.contains(.biometryAny))
        #expect(CompanionKeyPolicy.approvalProtection == kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    }

    @Test("the prompt name loses control characters and quotes, is cut to 40 characters, and falls back to unknown")
    func shortName() {
        #expect(ApprovalPrompt.shortName("claude-code") == "claude-code")
        #expect(ApprovalPrompt.shortName("a\"b\nc\td\u{7F}e") == "abcde")
        #expect(ApprovalPrompt.shortName(String(repeating: "x", count: 100)).count == 40)
        #expect(ApprovalPrompt.shortName("\"\"") == "unknown")
        #expect(ApprovalPrompt.shortName("") == "unknown")
        #expect(ApprovalPrompt.shortName("  \n ") == "unknown")
        // The cut comes after the removal, as on the Mac.
        #expect(ApprovalPrompt.shortName(String(repeating: "\"", count: 50) + "abc") == "abc")
        #expect(ApprovalPrompt.shortName("Zażółć") == "Zażółć")
    }

    @Test("the reasons of the prompts")
    func reasons() {
        #expect(ApprovalPrompt.approveReason(agent: "codex") == "approve a run of agent \"codex\"")
        #expect(ApprovalPrompt.approveReason(agent: "co\"dex\n") == "approve a run of agent \"codex\"")
        #expect(ApprovalPrompt.approveReason(agent: "") == "approve a run of agent \"unknown\"")
        #expect(ApprovalPrompt.pairReason(macName: "Mac mini") == "pair with Apassy on \"Mac mini\"")
    }

    @Test("LocalAuthentication errors map to owner errors")
    func mapLocalAuthentication() {
        func map(_ code: LAError.Code) -> CompanionKeyError {
            CompanionKeyError.map(NSError(domain: LAError.errorDomain, code: code.rawValue))
        }
        #expect(map(.userCancel) == .cancelled)
        #expect(map(.systemCancel) == .cancelled)
        #expect(map(.appCancel) == .cancelled)
        #expect(map(.biometryNotEnrolled) == .notEnrolled)
        #expect(map(.biometryLockout) == .lockedOut)
        #expect(map(.biometryNotAvailable) == .biometryUnavailable)
        // A context problem says nothing about the key, so it does not ask to pair again.
        #expect(map(.invalidContext) == .failed(code: LAError.Code.invalidContext.rawValue))
        #expect(map(.authenticationFailed) == .authenticationFailed)
    }

    @Test("Security status codes map to owner errors")
    func mapSecurity() {
        #expect(CompanionKeyError.map(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecUserCanceled))) == .cancelled)
        #expect(CompanionKeyError.map(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecAuthFailed))) == .authenticationFailed)
        #expect(CompanionKeyError.map(NSError(domain: NSOSStatusErrorDomain, code: Int(errSecItemNotFound))) == .biometryChanged)
        #expect(CompanionKeyError.map(CryptoKitError.underlyingCoreCryptoError(error: errSecAuthFailed)) == .authenticationFailed)
        #expect(CompanionKeyError.map(NSError(domain: "other", code: 7)) == .failed(code: 7))
        #expect(CompanionKeyError.map(CompanionKeyError.noSecureEnclave) == .noSecureEnclave)
    }

    @Test("a failed match is retryable, and only a changed enrollment asks to pair again")
    func authFailureNeedsChangedEnrollment() {
        let enrolled = Data([1, 2, 3])
        let failed = CompanionKeyError.authenticationFailed
        // The same enrollment, or an enrollment that is not known: a plain failed match.
        #expect(CompanionKeyError.classifyAuthFailure(failed, enrolledState: enrolled, currentState: enrolled) == failed)
        #expect(CompanionKeyError.classifyAuthFailure(failed, enrolledState: nil, currentState: enrolled) == failed)
        #expect(CompanionKeyError.classifyAuthFailure(failed, enrolledState: enrolled, currentState: nil) == failed)
        // A changed enrollment makes the key unusable.
        #expect(
            CompanionKeyError.classifyAuthFailure(failed, enrolledState: enrolled, currentState: Data([9]))
                == .biometryChanged)
        // Another error is left as it is, whatever the enrollment says.
        #expect(
            CompanionKeyError.classifyAuthFailure(.cancelled, enrolledState: enrolled, currentState: Data([9]))
                == .cancelled)
        #expect(!failed.keyIsUnusable)
        #expect(!CompanionKeyError.cancelled.keyIsUnusable)
        #expect(CompanionKeyError.biometryChanged.keyIsUnusable)
        #expect(CompanionKeyError.invalidKey.keyIsUnusable)
        #expect(failed.errorDescription?.contains("Try again") == true)
        #expect(failed.errorDescription?.contains("Pair") == false)
    }

    @Test("a changed biometric set says to pair again")
    func biometryChangedMessage() {
        #expect(CompanionKeyError.biometryChanged.errorDescription?.contains("Pair this iPhone again") == true)
        #expect(CompanionKeyError.cancelled.errorDescription?.hasSuffix("Nothing was approved.") == true)
        #expect(CompanionKeyError.noSecureEnclave.errorDescription?.contains("no Secure Enclave") == true)
        #expect(CompanionKeyError.notEnrolled.errorDescription?.contains("Face ID") == true)
    }

    @Test("this build reports where the keys live")
    func usesSecureEnclave() {
        #if targetEnvironment(simulator)
            #expect(!CompanionKeyStore.usesSecureEnclave)
        #else
            #expect(CompanionKeyStore.usesSecureEnclave)
        #endif
    }
}
