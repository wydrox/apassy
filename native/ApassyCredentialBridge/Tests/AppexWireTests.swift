// Tests of native/ApassyAutoFill/ProviderWire.swift: the calls of the extension and the
// checks before an answer goes to macOS.

import CryptoKit
import Foundation

func authenticatorData(rpID: String, flags: UInt8) -> Data {
    var data = Data(SHA256.hash(data: Data(rpID.utf8)))
    data.append(flags)
    data.append(contentsOf: [0, 0, 0, 0])
    return data
}

/// An attestation object in the form of src/vault/passkey.rs: "none" attestation in CTAP2
/// canonical order, a zero AAGUID, and an ES256 COSE key of the public point `point`
/// (x and y). `statement` is the CBOR of attStmt; `extra` follows the COSE key.
func attestationObject(
    rpID: String, flags: UInt8, credentialID: Data, point: Data, fmt: String = "none",
    statement: Data = Data([0xA0]), extra: Data = Data()
) -> Data {
    var auth = authenticatorData(rpID: rpID, flags: flags)
    auth.append(Data(count: 16))
    auth.append(contentsOf: [UInt8(credentialID.count >> 8), UInt8(credentialID.count & 0xFF)])
    auth.append(credentialID)
    auth.append(contentsOf: [0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])
    auth.append(point.prefix(32))
    auth.append(contentsOf: [0x22, 0x58, 0x20])
    auth.append(point.suffix(32))
    auth.append(extra)
    var object = Data([0xA3, 0x63]) + Data("fmt".utf8) + Data([0x60 | UInt8(fmt.utf8.count)]) + Data(fmt.utf8)
    object += Data([0x67]) + Data("attStmt".utf8) + statement + Data([0x68]) + Data("authData".utf8)
    object += auth.count < 256 ? Data([0x58, UInt8(auth.count)]) : Data([0x59, UInt8(auth.count >> 8), UInt8(auth.count & 0xFF)])
    return object + auth
}

func appexWireTests() {
    // Failure codes of the app.
    expect(providerFailure(code: "locked", message: "") == .locked, "locked maps to locked")
    expect(providerFailure(code: "no_vault", message: "") == .locked, "no_vault maps to locked")
    expect(providerFailure(code: "owner_cancelled", message: "") == .cancelled, "an owner cancel maps to cancelled")
    expect(providerFailure(code: "excluded", message: "") == .excluded, "excluded maps to excluded")
    expect(providerFailure(code: "unsupported_algorithm", message: "") == .unsupported, "an unsupported algorithm maps to unsupported")
    expect(providerFailure(code: "storage", message: "Bad\u{202E}text") == .failed("Badtext"), "a message loses its bidi characters")
    // The codes of the Rust desktop (src/desktop/passkey_socket.rs).
    expect(providerFailure(code: "vault_locked", message: "") == .locked, "vault_locked maps to locked")
    expect(providerFailure(code: "none_open", message: "") == .locked, "none_open maps to locked")
    expect(providerFailure(code: "no_match", message: "") == .notFound, "no_match maps to not found")
    expect(providerFailure(code: "caller_not_allowed", message: "Refused.") == .failed("Refused."), "caller_not_allowed is a failure")
    expect(answerFailure(json(["ok": false, "error": ["code": "vault_locked", "message": "x"]])) == .locked, "an answer names its failure")
    expect(answerFailure(json(["ok": true, "result": ["passkeys": []]])) == nil, "a successful answer names no failure")
    expect((try? decodeAnswer(json(["ok": true, "result": ["code": "123456", "remaining": 12]]), as: OneTimeCodeAnswer.self))?.code == "123456",
           "a code answer with extra fields decodes")

    // Calls: snake case, standard base64, no attach fields for a new login.
    let register = PasskeyRegisterCall(
        rpId: "example.com", userName: "ann", userDisplayName: "ann", userHandle: "AQ==", clientDataHash: hash32,
        algorithms: [-7], excluded: [], attachId: nil, attachRevision: nil, title: "Example")
    let encoded = (try? encodeCall(register)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    expect(encoded?["op"] as? String == "passkey_register" && encoded?["rp_id"] as? String == "example.com"
           && encoded?["client_data_hash"] as? String == hash32, "a registration call uses the core names")
    expect(encoded?["attach_id"] == nil && encoded?["attach_revision"] == nil, "a new login sends no attach fields")
    // The bridge accepts what the extension sends.
    expect((try? encodeCall(register)).flatMap { try? checkRequest($0) } != nil, "the bridge accepts a registration of the extension")
    let assertCall = PasskeyAssertCall(id: 3, rpId: "example.com", credentialId: credential, clientDataHash: hash32)
    expect((try? encodeCall(assertCall)).flatMap { try? checkRequest($0) }?.op == .passkeyAssert, "the bridge accepts an assertion of the extension")
    expect((try? encodeCall(IdentitiesCall())).flatMap { try? checkRequest($0) }?.op == .credentialIdentities, "the bridge accepts the identity call")
    expect((try? encodeCall(ItemCall(op: "autofill_code", id: 9))).flatMap { try? checkRequest($0) }?.op == .autofillCode, "the bridge accepts a code call")

    // Answers.
    let listed = json(["ok": true, "result": ["passkeys": [[
        "id": 1, "title": "Example", "rp_id": "example.com", "user_name": "ann", "user_display_name": "Ann",
        "credential_id": credential, "user_handle": "AQ==",
    ]]]])
    expect((try? decodeAnswer(listed, as: PasskeyListAnswer.self))?.passkeys.first?.rpId == "example.com", "a passkey list decodes")
    do {
        _ = try decodeAnswer(json(["ok": false, "error": ["code": "locked", "message": "The vault is locked."]]), as: PasskeyListAnswer.self)
        expect(false, "an error answer throws")
    } catch {
        expect(error as? ProviderFailure == .locked, "an error answer throws its failure")
    }
    expectThrows("an answer without ok fails") { _ = try decodeAnswer(json(["result": [:]]), as: PasskeyListAnswer.self) }
    let fill = json(["ok": true, "result": ["matches": [["id": 2, "title": "A", "username": "ann", "website": "https://a.com", "has_totp": true]], "others": []]])
    let fillList = try? decodeAnswer(fill, as: FillListAnswer.self)
    expect(fillList?.matches.first?.hasTotp == true && fillList?.matches.first?.revision == nil, "a fill list without the Mac fields decodes")

    // Assertion checks. The flags are UP, UV, BE, BS (0x1d), as src/vault/passkey.rs signs.
    let credentialID = Data([1, 2, 3, 4, 5])
    func assertion(rp: String = "example.com", flags: UInt8 = 0x1D, id: String = credential, extra: Data = Data()) -> PasskeyAssertAnswer {
        PasskeyAssertAnswer(
            credentialId: id, userHandle: "AQ==", authenticatorData: (authenticatorData(rpID: rp, flags: flags) + extra).base64EncodedString(),
            signature: Data(repeating: 0x30, count: 70).base64EncodedString())
    }
    expect(assertionFlags == 0x1D && registrationFlags == 0x5D, "the provider flags are UP, UV, BE, BS (and AT)")
    expect((try? checkAssertion(assertion(), rpID: "example.com", credentialID: credentialID)) != nil, "a good assertion passes")
    expectThrows("an assertion for another website fails") { _ = try checkAssertion(assertion(rp: "evil.com"), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion without user verification fails") { _ = try checkAssertion(assertion(flags: 0x19), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion without user presence fails") { _ = try checkAssertion(assertion(flags: 0x1C), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion without BS fails (the earlier 0x0d)") { _ = try checkAssertion(assertion(flags: 0x0D), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion without BE fails") { _ = try checkAssertion(assertion(flags: 0x15), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion with only UP and UV fails") { _ = try checkAssertion(assertion(flags: 0x05), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion with AT fails") { _ = try checkAssertion(assertion(flags: 0x5D), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion with extension data fails") {
        _ = try checkAssertion(assertion(flags: 0x9D, extra: Data([0xA0])), rpID: "example.com", credentialID: credentialID)
    }
    expectThrows("an assertion with bytes after the flags and counter fails") {
        _ = try checkAssertion(assertion(extra: Data([0])), rpID: "example.com", credentialID: credentialID)
    }
    expectThrows("an assertion of another credential fails") { _ = try checkAssertion(assertion(id: "AQ=="), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion in base64url fails") {
        var bad = assertion()
        bad = PasskeyAssertAnswer(credentialId: bad.credentialId, userHandle: "AQ", authenticatorData: bad.authenticatorData, signature: bad.signature)
        _ = try checkAssertion(bad, rpID: "example.com", credentialID: credentialID)
    }
    // The checked bytes are the signed bytes: a signature over them verifies.
    let key = P256.Signing.PrivateKey()
    let clientDataHash = Data(repeating: 7, count: 32)
    let signedData = authenticatorData(rpID: "example.com", flags: 0x1D)
    let signed = PasskeyAssertAnswer(
        credentialId: credential, userHandle: "AQ==", authenticatorData: signedData.base64EncodedString(),
        signature: ((try? key.signature(for: signedData + clientDataHash).derRepresentation) ?? Data()).base64EncodedString())
    let checkedSigned = try? checkAssertion(signed, rpID: "example.com", credentialID: credentialID)
    expect(checkedSigned.flatMap { checked in
        (try? P256.Signing.ECDSASignature(derRepresentation: checked.signature)).map {
            key.publicKey.isValidSignature($0, for: checked.authenticatorData + clientDataHash)
        }
    } == true, "a checked assertion keeps a valid signature")

    // Registration checks. A 32-byte credential ID, as the vault makes.
    let newID = Data((0..<32).map { UInt8($0) })
    let newCredential = newID.base64EncodedString()
    let point = key.publicKey.rawRepresentation
    func registration(_ object: Data, id: String = newCredential) -> PasskeyRegisterAnswer {
        PasskeyRegisterAnswer(id: 4, credentialId: id, attestationObject: object.base64EncodedString())
    }
    func good(flags: UInt8 = 0x5D) -> Data {
        attestationObject(rpID: "example.com", flags: flags, credentialID: newID, point: point)
    }
    // The same bytes as the canonical prefix that tests/passkeys.rs checks on the vault.
    var canonical = Data([0xA3, 0x63])
    canonical.append(contentsOf: Array("fmt".utf8) + [0x64] + Array("none".utf8))
    canonical.append(contentsOf: [0x67] + Array("attStmt".utf8) + [0xA0, 0x68])
    canonical.append(contentsOf: Array("authData".utf8) + [0x58, 0xA4])
    expect(good().prefix(30) == canonical, "the registration fixture has the canonical prefix of the vault")
    let checkedNew = try? checkRegistration(registration(good()), rpID: "example.com")
    expect(checkedNew?.credentialID == newID && checkedNew?.attestationObject == good(), "a good registration passes unchanged")
    expectThrows("a registration for another website fails") { _ = try checkRegistration(registration(good()), rpID: "evil.com") }
    expectThrows("a registration of another credential ID fails") { _ = try checkRegistration(registration(good(), id: credential), rpID: "example.com") }
    // The two Helium attempts: macOS refused 0x4d, "AuthData is missing a required flag".
    expectThrows("a registration without BS fails (the earlier 0x4d)") { _ = try checkRegistration(registration(good(flags: 0x4D)), rpID: "example.com") }
    expectThrows("a registration without BE fails") { _ = try checkRegistration(registration(good(flags: 0x55)), rpID: "example.com") }
    expectThrows("a registration without UV fails") { _ = try checkRegistration(registration(good(flags: 0x59)), rpID: "example.com") }
    expectThrows("a registration without UP fails") { _ = try checkRegistration(registration(good(flags: 0x5C)), rpID: "example.com") }
    expectThrows("a registration without AT fails") { _ = try checkRegistration(registration(good(flags: 0x1D)), rpID: "example.com") }
    expectThrows("a registration with extension data fails") {
        let object = attestationObject(rpID: "example.com", flags: 0xDD, credentialID: newID, point: point, extra: Data([0xA0]))
        _ = try checkRegistration(registration(object), rpID: "example.com")
    }
    expectThrows("a registration with a byte after the COSE key fails") {
        let object = attestationObject(rpID: "example.com", flags: 0x5D, credentialID: newID, point: point, extra: Data([0]))
        _ = try checkRegistration(registration(object), rpID: "example.com")
    }
    expectThrows("a registration with another format fails") {
        let object = attestationObject(rpID: "example.com", flags: 0x5D, credentialID: newID, point: point, fmt: "packed")
        _ = try checkRegistration(registration(object), rpID: "example.com")
    }
    expectThrows("a registration with an attestation statement fails") {
        let statement = Data([0xA1, 0x63]) + Data("alg".utf8) + Data([0x26])
        let object = attestationObject(rpID: "example.com", flags: 0x5D, credentialID: newID, point: point, statement: statement)
        _ = try checkRegistration(registration(object), rpID: "example.com")
    }
    expectThrows("a registration with a byte after the attestation object fails") {
        _ = try checkRegistration(registration(good() + Data([0])), rpID: "example.com")
    }
    expectThrows("a cut registration fails") { _ = try checkRegistration(registration(good().dropLast()), rpID: "example.com") }
    expectThrows("an indefinite-length attestation map fails") {
        var object = good()
        object[0] = 0xBF
        _ = try checkRegistration(registration(object), rpID: "example.com")
    }
    expectThrows("a longer head than needed fails") {
        var object = good()
        object.replaceSubrange(28..<30, with: [0x59, 0x00, 0xA4])
        _ = try checkRegistration(registration(object), rpID: "example.com")
    }
    expectThrows("a credential length past the end fails") {
        var object = good()
        object[30 + 53] = 0xFF
        _ = try checkRegistration(registration(object), rpID: "example.com")
    }
    expectThrows("the earlier fixture (flags and IDs without CBOR) fails") {
        var loose = Data([0xA3])
        loose.append(authenticatorData(rpID: "example.com", flags: 0x5D))
        loose.append(newID)
        _ = try checkRegistration(registration(loose), rpID: "example.com")
    }

    // Codes, lists, text.
    expect((try? checkCode(OneTimeCodeAnswer(code: "123456"))) == "123456", "a six-digit code passes")
    expectThrows("a code with a space fails") { _ = try checkCode(OneTimeCodeAnswer(code: "123 456")) }
    let entry = PasskeyEntry(id: 1, title: "", rpId: "example.com", userName: "", userDisplayName: "", credentialId: credential, userHandle: "AQ==")
    expect(usablePasskey(entry, rpID: "example.com", allowed: []) == credentialID, "a passkey of the website is usable")
    expect(usablePasskey(entry, rpID: "example.com", allowed: [Data([9])]) == nil, "a passkey outside the allow list is not usable")
    expect(usablePasskey(entry, rpID: "other.com", allowed: []) == nil, "a passkey of another website is not usable")
    expect(visibleText("ann\u{202E}moc\u{200B}", max: 80) == "annmoc", "visible text drops bidi and zero-width characters")
    expect(visibleText(String(repeating: "a", count: 100), max: 10).count == 10, "visible text is cut to its limit")
}
