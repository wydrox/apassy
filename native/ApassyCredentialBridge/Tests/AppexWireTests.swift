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

    // Assertion checks.
    let credentialID = Data([1, 2, 3, 4, 5])
    func assertion(rp: String = "example.com", flags: UInt8 = 0x05, id: String = credential) -> PasskeyAssertAnswer {
        PasskeyAssertAnswer(
            credentialId: id, userHandle: "AQ==", authenticatorData: authenticatorData(rpID: rp, flags: flags).base64EncodedString(),
            signature: Data(repeating: 0x30, count: 70).base64EncodedString())
    }
    expect((try? checkAssertion(assertion(), rpID: "example.com", credentialID: credentialID)) != nil, "a good assertion passes")
    expectThrows("an assertion for another website fails") { _ = try checkAssertion(assertion(rp: "evil.com"), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion without user verification fails") { _ = try checkAssertion(assertion(flags: 0x01), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion of another credential fails") { _ = try checkAssertion(assertion(id: "AQ=="), rpID: "example.com", credentialID: credentialID) }
    expectThrows("an assertion in base64url fails") {
        var bad = assertion()
        bad = PasskeyAssertAnswer(credentialId: bad.credentialId, userHandle: "AQ", authenticatorData: bad.authenticatorData, signature: bad.signature)
        _ = try checkAssertion(bad, rpID: "example.com", credentialID: credentialID)
    }

    // Registration checks.
    var attestation = Data([0xA3])
    attestation.append(authenticatorData(rpID: "example.com", flags: 0x45))
    attestation.append(credentialID)
    let created = PasskeyRegisterAnswer(id: 4, credentialId: credential, attestationObject: attestation.base64EncodedString())
    expect((try? checkRegistration(created, rpID: "example.com")) != nil, "a good registration passes")
    expectThrows("a registration for another website fails") { _ = try checkRegistration(created, rpID: "evil.com") }

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
