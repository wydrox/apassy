// The calls of the extension and the checks of their answers. Foundation and CryptoKit
// only, so the bridge tests compile this file too.
//
// The calls are the iOS core wire (contract.txt): standard base64 bytes, answers
// {"ok":true,"result":{…}} or {"ok":false,"error":{"code","message"}}. The extension
// never holds a key. It keeps an answer only until it hands it to macOS.

import CryptoKit
import Foundation

// MARK: - Failures

/// Why a call did not give an answer. The message of `failed` is for the owner and never
/// holds a value of a credential.
enum ProviderFailure: Error, Equatable, Sendable {
    /// No bridge listens: Apassy is not running, or it has no vault open.
    case notRunning
    /// The vault is locked.
    case locked
    /// The owner cancelled, or the owner check failed.
    case cancelled
    /// A passkey of the exclude list is in Apassy (after the owner check).
    case excluded
    /// The login or passkey is not in the vault any more.
    case notFound
    /// The website asks for an algorithm or an extension that Apassy does not support.
    case unsupported
    case timeout
    /// The program at the other end of the socket is not the bridge of this Apassy app.
    case bridgeRefused
    case failed(String)
}

/// Map an error code of the app or the bridge.
func providerFailure(code: String, message: String) -> ProviderFailure {
    // The iOS core codes and the codes of src/desktop/passkey_socket.rs.
    switch code {
    case "locked", "no_vault", "vault_locked", "none_open": .locked
    case "not_running": .notRunning
    case "cancelled", "owner_cancelled", "owner_check_failed", "denied": .cancelled
    case "excluded": .excluded
    case "not_found", "no_match": .notFound
    case "unsupported_algorithm", "unsupported", "unsupported_extension": .unsupported
    case "timeout": .timeout
    default: .failed(visibleText(message, max: 240).isEmpty ? "Apassy could not do this." : visibleText(message, max: 240))
    }
}

// MARK: - Calls

struct PasskeyListCall: Encodable {
    let op = "passkey_list"
    let rpId: String
    let allowed: [String]
}

struct PasskeyAssertCall: Encodable {
    let op = "passkey_assert"
    let id: UInt64
    let rpId: String
    let credentialId: String
    let clientDataHash: String
}

struct PasskeyRegisterCall: Encodable {
    let op = "passkey_register"
    let rpId: String
    let userName: String
    let userDisplayName: String
    let userHandle: String
    let clientDataHash: String
    let algorithms: [Int]
    let excluded: [String]
    let attachId: UInt64?
    let attachRevision: UInt64?
    let title: String
}

struct AutofillListCall: Encodable {
    let op = "autofill_list"
    let domains: [String]
}

/// `autofill_credential` or `autofill_code` for one login.
struct ItemCall: Encodable {
    let op: String
    let id: UInt64
}

struct IdentitiesCall: Encodable {
    let op = "credential_identities"
}

// MARK: - Answers

struct WireErrorBody: Decodable {
    let code: String
    let message: String
}

struct WireAnswer<Result: Decodable>: Decodable {
    let ok: Bool
    let result: Result?
    let error: WireErrorBody?
}

struct PasskeyEntry: Decodable, Equatable {
    let id: UInt64
    let title: String
    let rpId: String
    let userName: String
    let userDisplayName: String
    let credentialId: String
    let userHandle: String
}

struct PasskeyListAnswer: Decodable {
    let passkeys: [PasskeyEntry]
}

struct PasskeyAssertAnswer: Decodable {
    let credentialId: String
    let userHandle: String
    let authenticatorData: String
    let signature: String
}

struct PasskeyRegisterAnswer: Decodable {
    let id: UInt64
    let credentialId: String
    let attestationObject: String
}

struct FillEntry: Decodable, Equatable {
    let id: UInt64
    let title: String
    let username: String
    let website: String?
    let hasTotp: Bool
    /// Mac addition (mac-native-api.txt): the revision, so a passkey can join this login.
    let revision: UInt64?
    let hasPasskey: Bool?
}

struct FillListAnswer: Decodable {
    let matches: [FillEntry]
    let others: [FillEntry]
}

/// The username and the password of one login. Handed to macOS at once, never kept.
struct LoginSecretAnswer: Decodable {
    let username: String
    let password: String
}

struct OneTimeCodeAnswer: Decodable {
    let code: String
}

struct LoginIdentity: Decodable {
    let id: UInt64
    let username: String
    let host: String
}

struct CodeIdentity: Decodable {
    let id: UInt64
    let title: String
    let username: String
    let host: String
}

struct IdentitiesAnswer: Decodable {
    let identities: [LoginIdentity]
    let passkeys: [PasskeyEntry]
    let totp: [CodeIdentity]
}

// MARK: - Coding

func encodeCall(_ call: some Encodable) throws -> Data {
    let encoder = JSONEncoder()
    encoder.keyEncodingStrategy = .convertToSnakeCase
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(call)
    guard data.count <= BridgeConstants.maxRequestBytes else {
        throw ProviderFailure.failed("The request is too large for Apassy.")
    }
    return data
}

/// The result of an answer, or the failure it names.
func decodeAnswer<Result: Decodable>(_ data: Data, as type: Result.Type) throws -> Result {
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    guard let answer = try? decoder.decode(WireAnswer<Result>.self, from: data) else {
        throw ProviderFailure.failed("Apassy sent an answer that AutoFill cannot read.")
    }
    if answer.ok, let result = answer.result {
        return result
    }
    if !answer.ok, let error = answer.error {
        throw providerFailure(code: error.code, message: error.message)
    }
    throw ProviderFailure.failed("Apassy sent an answer that AutoFill cannot read.")
}

private struct AnyResult: Decodable {}

/// The failure an answer names, or nil for a successful or unreadable answer.
func answerFailure(_ data: Data) -> ProviderFailure? {
    guard let answer = try? JSONDecoder().decode(WireAnswer<AnyResult>.self, from: data), !answer.ok,
          let error = answer.error
    else {
        return nil
    }
    return providerFailure(code: error.code, message: error.message)
}

/// Canonical standard base64 with padding, at most `max` bytes, at least one byte.
func wireBytes(_ text: String, max: Int) -> Data? {
    guard !text.isEmpty, text.utf8.count % 4 == 0, text.utf8.count / 4 * 3 <= max + 2,
          let bytes = Data(base64Encoded: text), !bytes.isEmpty, bytes.count <= max,
          bytes.base64EncodedString() == text
    else {
        return nil
    }
    return bytes
}

// MARK: - Checks of the answers

/// The parts of an assertion for ASPasskeyAssertionCredential.
struct CheckedAssertion: Equatable {
    let credentialID: Data
    let userHandle: Data
    let authenticatorData: Data
    let signature: Data
}

/// Authenticator data flags (WebAuthn): user present, user verified.
let flagUserPresent: UInt8 = 0x01
let flagUserVerified: UInt8 = 0x04

/// Check an assertion before it goes to macOS: the same credential, the hash of the
/// relying party, user presence and verification (the owner check of the app), and
/// sane sizes. A wrong answer is never handed on.
func checkAssertion(_ answer: PasskeyAssertAnswer, rpID: String, credentialID: Data) throws -> CheckedAssertion {
    guard let credential = wireBytes(answer.credentialId, max: 1023), credential == credentialID,
          let handle = wireBytes(answer.userHandle, max: 64),
          let data = wireBytes(answer.authenticatorData, max: 1024), data.count >= 37,
          let signature = wireBytes(answer.signature, max: 128), signature.count >= 8
    else {
        throw ProviderFailure.failed("Apassy sent a passkey answer that AutoFill cannot use.")
    }
    let rpHash = Data(SHA256.hash(data: Data(rpID.utf8)))
    let flags = data[data.startIndex + 32]
    guard data.prefix(32) == rpHash, flags & flagUserPresent != 0, flags & flagUserVerified != 0 else {
        throw ProviderFailure.failed("Apassy sent a passkey answer for another website or without the owner check.")
    }
    return CheckedAssertion(credentialID: credential, userHandle: handle, authenticatorData: data, signature: signature)
}

struct CheckedRegistration: Equatable {
    let credentialID: Data
    let attestationObject: Data
}

/// Check a new passkey: sizes, and the attestation holds the hash of the relying party.
func checkRegistration(_ answer: PasskeyRegisterAnswer, rpID: String) throws -> CheckedRegistration {
    guard let credential = wireBytes(answer.credentialId, max: 1023),
          let attestation = wireBytes(answer.attestationObject, max: 64 * 1024)
    else {
        throw ProviderFailure.failed("Apassy sent a new passkey that AutoFill cannot use.")
    }
    let rpHash = Data(SHA256.hash(data: Data(rpID.utf8)))
    guard attestation.range(of: rpHash) != nil, attestation.range(of: credential) != nil else {
        throw ProviderFailure.failed("Apassy sent a new passkey for another website.")
    }
    return CheckedRegistration(credentialID: credential, attestationObject: attestation)
}

/// A one-time code: 4 to 10 ASCII letters or digits.
func checkCode(_ answer: OneTimeCodeAnswer) throws -> String {
    let code = answer.code
    guard (4...10).contains(code.utf8.count),
          code.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) })
    else {
        throw ProviderFailure.failed("Apassy sent a code that AutoFill cannot use.")
    }
    return code
}

/// A passkey of a list: it must be for the website, and in the allow list if there is one.
func usablePasskey(_ entry: PasskeyEntry, rpID: String, allowed: [Data]) -> Data? {
    guard entry.rpId == rpID, let credential = wireBytes(entry.credentialId, max: 1023),
          wireBytes(entry.userHandle, max: 64) != nil
    else {
        return nil
    }
    return allowed.isEmpty || allowed.contains(credential) ? credential : nil
}

// MARK: - Text for the owner

/// Text from a website or a vault, for display: no control, bidi, or zero-width
/// characters, at most `max` characters.
func visibleText(_ text: String, max: Int) -> String {
    let scalars = text.unicodeScalars.filter { scalar in
        !(CharacterSet.controlCharacters.contains(scalar)
            || (0x200B...0x200F).contains(scalar.value) || (0x202A...0x202E).contains(scalar.value)
            || (0x2066...0x2069).contains(scalar.value) || scalar.value == 0xFEFF)
    }
    let clean = String(String.UnicodeScalarView(scalars)).trimmingCharacters(in: .whitespaces)
    return clean.count > max ? String(clean.prefix(max - 1)) + "…" : clean
}
