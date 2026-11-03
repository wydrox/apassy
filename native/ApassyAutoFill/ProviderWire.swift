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
    /// The PRF inputs for the chosen credential. Absent when the website asks for none.
    var prf: PrfCallInput? = nil
    /// Absent when the website asks for no large blob operation.
    var largeBlob: LargeBlobCallInput? = nil
}

/// {"first", "second"?, "hashed"}: standard base64 inputs of the WebAuthn prf extension.
/// `hashed` says whether they are already the hmac-secret salts
/// (SHA-256("WebAuthn PRF" || 0x00 || input)), or the raw inputs that the app hashes.
struct PrfCallInput: Encodable, Equatable {
    let first: String
    let second: String?
    let hashed: Bool
}

/// {"read": true} or {"write": bytes}.
enum LargeBlobCallInput: Encodable, Equatable {
    case read
    case write(String)

    private enum Key: String, CodingKey {
        case read
        case write
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: Key.self)
        switch self {
        case .read: try container.encode(true, forKey: .read)
        case .write(let blob): try container.encode(blob, forKey: .write)
        }
    }
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
    /// The COSE algorithm of the signature. An app before the extension outputs sends
    /// none, and signs ES256 (-7) only.
    var algorithm: Int? = nil
    var prf: PrfAnswer? = nil
    var largeBlob: LargeBlobAnswer? = nil
}

/// The PRF outputs: {"first", "second"?}, 32 bytes each.
struct PrfAnswer: Decodable, Equatable {
    let first: String
    var second: String? = nil
}

/// {"data": bytes} (absent or null: no blob) after a read, {"written": bool} after a write.
struct LargeBlobAnswer: Decodable, Equatable {
    var data: String? = nil
    var written: Bool? = nil
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

// MARK: - Extensions of a sign-in

/// PRF inputs as macOS gives them (ASAuthorizationPublicKeyCredentialPRFAssertionInput).
struct PrfValues: Equatable {
    let first: Data
    let second: Data?
}

/// The prf extension of a sign-in: the inputs for every credential (WebAuthn `eval`) and
/// those for single credentials (`evalByCredential`).
struct PrfRequest: Equatable {
    let all: PrfValues?
    let byCredential: [Data: PrfValues]
}

enum LargeBlobRequest: Equatable {
    case read
    case write(Data)
}

/// The extension inputs of a sign-in request of macOS.
struct AssertionExtensionRequest: Equatable {
    var prf: PrfRequest?
    var largeBlob: LargeBlobRequest?
}

enum ExtensionLimits {
    static let minPrfInputBytes = 1
    static let maxPrfInputBytes = 1024
    static let maxPrfCredentials = 256
    static let prfOutputBytes = 32
    static let maxLargeBlobBytes = 64 * 1024
}

/// Whether macOS gives the provider hmac-secret salts or the raw WebAuthn PRF inputs.
///
/// Evidence (MacOSX.sdk, AuthenticationServices): the provider reads the same type,
/// ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues
/// (`saltInput1`, `saltInput2`), that an app gives to
/// ASAuthorizationPlatformPublicKeyCredentialAssertionRequest.prf, where the values are
/// the WebAuthn `eval` inputs. Neither the headers nor the swiftinterface say that the
/// system hashes them before ASPasskeyCredentialRequestParameters.extensionInput or
/// ASPasskeyCredentialRequest.extensionInput. With no evidence of hashing, the
/// extension sends them as raw inputs (`hashed: false`), and the app hashes them with
/// "WebAuthn PRF" || 0x00. Unverified on a device: check with a known PRF test vector.
let prfInputsAreHashed = false

/// What the call of one credential carries. `skippedWrite`: macOS asked to write an empty
/// blob, which the wire does not carry; the answer to macOS is "not written".
struct AssertionCallExtensions: Equatable {
    var prf: PrfCallInput?
    var largeBlob: LargeBlobCallInput?
    var skippedWrite = false
}

/// The extension inputs for the call of `credentialID`: the inputs of this credential if
/// the website names it in evalByCredential, else the inputs for every credential. A
/// value outside the limits fails with `unsupported`, before anything goes to Apassy.
func assertionCallExtensions(_ request: AssertionExtensionRequest, credentialID: Data) throws -> AssertionCallExtensions {
    var call = AssertionCallExtensions()
    if let prf = request.prf {
        guard prf.byCredential.count <= ExtensionLimits.maxPrfCredentials else {
            throw ProviderFailure.unsupported
        }
        let range = ExtensionLimits.minPrfInputBytes...ExtensionLimits.maxPrfInputBytes
        for values in Array(prf.byCredential.values) + (prf.all.map { [$0] } ?? []) {
            guard range.contains(values.first.count), values.second.map({ range.contains($0.count) }) ?? true else {
                throw ProviderFailure.unsupported
            }
        }
        if let values = prf.byCredential[credentialID] ?? prf.all {
            call.prf = PrfCallInput(
                first: values.first.base64EncodedString(), second: values.second?.base64EncodedString(),
                hashed: prfInputsAreHashed)
        }
    }
    switch request.largeBlob {
    case .read?:
        call.largeBlob = .read
    case .write(let blob)?:
        guard blob.count <= ExtensionLimits.maxLargeBlobBytes else {
            throw ProviderFailure.unsupported
        }
        if blob.isEmpty {
            call.skippedWrite = true
        } else {
            call.largeBlob = .write(blob.base64EncodedString())
        }
    case nil:
        break
    }
    return call
}

// MARK: - Checks of the answers

struct CheckedPrf: Equatable {
    let first: Data
    let second: Data?
}

enum CheckedLargeBlob: Equatable {
    /// Nil: the passkey has no blob.
    case read(Data?)
    case written(Bool)
}

/// The parts of an assertion for ASPasskeyAssertionCredential.
struct CheckedAssertion: Equatable {
    let credentialID: Data
    let userHandle: Data
    let authenticatorData: Data
    let signature: Data
    /// The COSE algorithm of the signature.
    var algorithm: Int = coseES256
    var prf: CheckedPrf? = nil
    var largeBlob: CheckedLargeBlob? = nil
}

let coseES256 = -7
let coseEdDSA = -8
let coseES384 = -35
let coseRS256 = -257

/// Whether a signature has the size of its COSE algorithm. ES256 and ES384 are DER
/// ECDSA signatures (at most 72 and 104 bytes), EdDSA is Ed25519 (64 bytes), RS256 is
/// RSA PKCS#1 v1.5 with a modulus of 1024 to 4096 bits. Any other algorithm fails.
func signatureFits(_ signature: Data, algorithm: Int) -> Bool {
    switch algorithm {
    case coseES256: (8...72).contains(signature.count)
    case coseES384: (8...104).contains(signature.count)
    case coseEdDSA: signature.count == 64
    case coseRS256: (128...512).contains(signature.count)
    default: false
    }
}

/// Authenticator data flags (WebAuthn).
let flagUserPresent: UInt8 = 0x01
let flagUserVerified: UInt8 = 0x04
let flagBackupEligible: UInt8 = 0x08
let flagBackupState: UInt8 = 0x10
let flagAttestedData: UInt8 = 0x40
/// The flags of each assertion: user presence and verification (the owner check of the
/// app), and backup eligibility and state, which the credential provider API requires
/// (macOS refuses a new passkey without BS: "AuthData is missing a required flag").
let assertionFlags: UInt8 = flagUserPresent | flagUserVerified | flagBackupEligible | flagBackupState
/// The flags of each registration: the assertion flags and attested credential data.
let registrationFlags: UInt8 = assertionFlags | flagAttestedData

/// Check an assertion before it goes to macOS: the same credential, the hash of the
/// relying party, exactly the assertion flags, no extension data in the authenticator
/// data, a signature of the size of its algorithm, and extension outputs only for the
/// extensions of the call. A wrong answer is never handed on.
func checkAssertion(
    _ answer: PasskeyAssertAnswer, rpID: String, credentialID: Data, requested: AssertionCallExtensions = AssertionCallExtensions()
) throws -> CheckedAssertion {
    let algorithm = answer.algorithm ?? coseES256
    guard let credential = wireBytes(answer.credentialId, max: 1023), credential == credentialID,
          let handle = wireBytes(answer.userHandle, max: 64),
          let data = wireBytes(answer.authenticatorData, max: 1024), data.count >= 37,
          let signature = wireBytes(answer.signature, max: 512), signatureFits(signature, algorithm: algorithm)
    else {
        throw ProviderFailure.failed("Apassy sent a passkey answer that AutoFill cannot use.")
    }
    let rpHash = Data(SHA256.hash(data: Data(rpID.utf8)))
    let flags = data[data.startIndex + 32]
    guard data.prefix(32) == rpHash, flags & flagUserPresent != 0, flags & flagUserVerified != 0 else {
        throw ProviderFailure.failed("Apassy sent a passkey answer for another website or without the owner check.")
    }
    guard flags == assertionFlags, data.count == 37 else {
        throw ProviderFailure.failed("Apassy sent a passkey answer that macOS would refuse.")
    }
    return CheckedAssertion(
        credentialID: credential, userHandle: handle, authenticatorData: data, signature: signature, algorithm: algorithm,
        prf: try checkPrfOutput(answer.prf, requested: requested.prf),
        largeBlob: try checkLargeBlobOutput(answer.largeBlob, requested: requested))
}

/// PRF outputs: only when the call carried inputs, 32 bytes each, a second output only
/// for a second input. No outputs: the passkey has no PRF, and macOS gets none.
func checkPrfOutput(_ answer: PrfAnswer?, requested: PrfCallInput?) throws -> CheckedPrf? {
    guard let answer else { return nil }
    let size = ExtensionLimits.prfOutputBytes
    guard let requested, let first = wireBytes(answer.first, max: size), first.count == size else {
        throw ProviderFailure.failed("Apassy sent a passkey answer that AutoFill cannot use.")
    }
    guard let text = answer.second else {
        return CheckedPrf(first: first, second: nil)
    }
    guard requested.second != nil, let second = wireBytes(text, max: size), second.count == size else {
        throw ProviderFailure.failed("Apassy sent a passkey answer that AutoFill cannot use.")
    }
    return CheckedPrf(first: first, second: second)
}

/// The large blob output must match the operation of the call: data (or none) after a
/// read, "written" after a write. An empty write that the call skipped is "not written".
func checkLargeBlobOutput(_ answer: LargeBlobAnswer?, requested: AssertionCallExtensions) throws -> CheckedLargeBlob? {
    if requested.skippedWrite {
        guard answer == nil else {
            throw ProviderFailure.failed("Apassy sent a passkey answer that AutoFill cannot use.")
        }
        return .written(false)
    }
    guard let answer else { return nil }
    switch requested.largeBlob {
    case .read?:
        guard answer.written == nil else { break }
        guard let text = answer.data, !text.isEmpty else { return .read(nil) }
        guard let blob = wireBytes(text, max: ExtensionLimits.maxLargeBlobBytes) else { break }
        return .read(blob)
    case .write?:
        guard answer.data == nil, let written = answer.written else { break }
        return .written(written)
    case nil:
        break
    }
    throw ProviderFailure.failed("Apassy sent a passkey answer that AutoFill cannot use.")
}

struct CheckedRegistration: Equatable {
    let credentialID: Data
    let attestationObject: Data
}

/// Definite-length CBOR, enough for the attestation object of the app. Each read fails
/// on an indefinite length, a reserved value, a longer head than needed, or a length past
/// the end.
struct CBORReader {
    let bytes: [UInt8]
    private(set) var at = 0

    init(_ data: Data) {
        bytes = [UInt8](data)
    }

    var atEnd: Bool { at == bytes.count }

    /// The major type and the argument of the next item.
    mutating func head() -> (major: UInt8, argument: UInt64)? {
        guard at < bytes.count else { return nil }
        let initial = bytes[at]
        at += 1
        let info = initial & 0x1F
        let size: Int
        switch info {
        case 0..<24: return (initial >> 5, UInt64(info))
        case 24: size = 1
        case 25: size = 2
        case 26: size = 4
        case 27: size = 8
        default: return nil
        }
        guard bytes.count - at >= size else { return nil }
        let argument = bytes[at..<at + size].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        guard argument >= (size == 1 ? 24 : UInt64(1) << (size * 4)) else { return nil }
        at += size
        return (initial >> 5, argument)
    }

    /// The next head is exactly this major type and argument.
    mutating func head(_ major: UInt8, _ argument: UInt64) -> Bool {
        guard let next = head() else { return false }
        return next.major == major && next.argument == argument
    }

    /// The content of a byte string (major 2) or a text string (major 3).
    mutating func string(major: UInt8) -> [UInt8]? {
        guard let next = head(), next.major == major, next.argument <= UInt64(bytes.count - at) else { return nil }
        let start = at
        at += Int(next.argument)
        return Array(bytes[start..<at])
    }

    mutating func text(_ expected: String) -> Bool {
        string(major: 3) == Array(expected.utf8)
    }

    /// Skip one item: integers, strings, arrays, and maps only, at most `depth` deep.
    mutating func skip(depth: Int = 4) -> Bool {
        guard depth > 0, let next = head() else { return false }
        switch next.major {
        case 0, 1:
            return true
        case 2, 3:
            guard next.argument <= UInt64(bytes.count - at) else { return false }
            at += Int(next.argument)
            return true
        case 4, 5:
            // Each item takes at least one byte.
            guard next.argument <= UInt64(bytes.count - at) else { return false }
            var items = next.major == 5 ? next.argument * 2 : next.argument
            while items > 0 {
                guard skip(depth: depth - 1) else { return false }
                items -= 1
            }
            return true
        default:
            return false
        }
    }
}

/// Check a new passkey before it goes to macOS. The attestation object must be exactly
/// {"fmt": "none", "attStmt": {}, "authData": bytes} with nothing after it. Its
/// authenticator data must have the hash of the relying party, exactly the registration
/// flags, and the attested credential data of this credential ID with one COSE key that
/// ends the data.
func checkRegistration(_ answer: PasskeyRegisterAnswer, rpID: String) throws -> CheckedRegistration {
    guard let credential = wireBytes(answer.credentialId, max: 1023),
          let attestation = wireBytes(answer.attestationObject, max: 64 * 1024)
    else {
        throw ProviderFailure.failed("Apassy sent a new passkey that AutoFill cannot use.")
    }
    var object = CBORReader(attestation)
    guard object.head(5, 3), object.text("fmt"), object.text("none"), object.text("attStmt"), object.head(5, 0),
          object.text("authData"), let auth = object.string(major: 2), object.atEnd, auth.count >= 55
    else {
        throw ProviderFailure.failed("Apassy sent a new passkey that AutoFill cannot use.")
    }
    let rpHash = [UInt8](SHA256.hash(data: Data(rpID.utf8)))
    let length = Int(auth[53]) << 8 | Int(auth[54])
    guard Array(auth[0..<32]) == rpHash, auth.count >= 55 + length,
          Array(auth[55..<55 + length]) == [UInt8](credential)
    else {
        throw ProviderFailure.failed("Apassy sent a new passkey for another website.")
    }
    var key = CBORReader(Data(auth[(55 + length)...]))
    guard auth[32] == registrationFlags, key.bytes.first.map({ $0 >> 5 }) == 5, key.skip(), key.atEnd else {
        throw ProviderFailure.failed("Apassy sent a new passkey that macOS would refuse.")
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
