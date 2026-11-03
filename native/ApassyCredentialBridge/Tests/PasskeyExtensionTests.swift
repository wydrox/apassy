// Tests of the prf and largeBlob extensions of a sign-in and of the signature
// algorithms of an assertion: the bridge checks (BridgeWire.swift), the calls and the
// answer checks of the extension (ProviderWire.swift), and the outputs for macOS
// (ProviderModel.swift). Synthetic values only.

import AuthenticationServices
import CryptoKit
import Foundation

private func base64(_ count: Int, _ byte: UInt8 = 5) -> String {
    Data(repeating: byte, count: count).base64EncodedString()
}

private func object(_ data: Data?) -> [String: Any]? {
    data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
}

private func bridgeExtensionTests() {
    func check(_ extra: [String: Any]) throws -> CheckedRequest {
        var request: [String: Any] = [
            "op": "passkey_assert", "id": 12, "rp_id": "example.com", "credential_id": credential, "client_data_hash": hash32,
        ]
        request.merge(extra) { $1 }
        return try checkRequest(json(request))
    }

    let prf = try? check(["prf": ["first": base64(32), "second": base64(1024), "hashed": false]])
    let prfPayload = prf?.payload["prf"] as? [String: Any]
    expect(prfPayload?["first"] as? String == base64(32) && prfPayload?["second"] as? String == base64(1024)
           && prfPayload?["hashed"] as? Bool == false, "B: PRF inputs of 32 and 1024 bytes pass unchanged")
    expect(prf.map { Set($0.payload.keys) } == ["op", "id", "rp_id", "credential_id", "client_data_hash", "prf"],
           "B: the payload holds the checked PRF inputs and nothing else")
    expect(((try? check(["prf": ["first": base64(1), "hashed": false]]))?.payload["prf"] as? [String: Any])?["second"] == nil,
           "B: one PRF input of 1 byte passes without a second")
    expectThrows("B: an empty PRF input is refused") { _ = try check(["prf": ["first": "", "hashed": false]]) }
    expectThrows("B: a PRF input of 1025 bytes is refused") { _ = try check(["prf": ["first": base64(1025), "hashed": false]]) }
    expectThrows("B: a second PRF input of 1025 bytes is refused") {
        _ = try check(["prf": ["first": base64(1), "second": base64(1025), "hashed": false]])
    }
    expectThrows("B: PRF inputs without hashed are refused") { _ = try check(["prf": ["first": base64(32)]]) }
    expectThrows("B: hashed as a number is refused") { _ = try check(["prf": ["first": base64(32), "hashed": 0]]) }
    expectThrows("B: a PRF field that the call does not take is refused") {
        _ = try check(["prf": ["first": base64(32), "hashed": false, "eval_by_credential": [:]]])
    }
    expectThrows("B: PRF inputs in base64url are refused") { _ = try check(["prf": ["first": "-_8=", "hashed": false]]) }
    expectThrows("B: PRF inputs as a string are refused") { _ = try check(["prf": base64(32)]) }
    expect((try? check(["prf": ["first": base64(32), "second": base64(32), "hashed": true]])) != nil, "B: hashed salts of 32 bytes pass")
    expectThrows("B: a hashed salt of 31 bytes is refused") { _ = try check(["prf": ["first": base64(31), "hashed": true]]) }
    expectThrows("B: a hashed salt of 33 bytes is refused") { _ = try check(["prf": ["first": base64(33), "hashed": true]]) }

    let read = try? check(["large_blob": ["read": true]])
    expect((read?.payload["large_blob"] as? [String: Any])?["read"] as? Bool == true, "B: a large blob read passes")
    let write = try? check(["large_blob": ["write": base64(ExtensionLimits.maxLargeBlobBytes)]])
    expect((write?.payload["large_blob"] as? [String: Any])?["write"] as? String == base64(ExtensionLimits.maxLargeBlobBytes),
           "B: a large blob write of 64 KiB passes")
    expectThrows("B: a large blob write above 64 KiB is refused") {
        _ = try check(["large_blob": ["write": base64(ExtensionLimits.maxLargeBlobBytes + 1)]])
    }
    expectThrows("B: an empty large blob write is refused") { _ = try check(["large_blob": ["write": ""]]) }
    expectThrows("B: a read of false is refused") { _ = try check(["large_blob": ["read": false]]) }
    expectThrows("B: a read of 1 is refused") { _ = try check(["large_blob": ["read": 1]]) }
    expectThrows("B: a read and a write together are refused") { _ = try check(["large_blob": ["read": true, "write": base64(4)]]) }
    expectThrows("B: a large blob field that the call does not take is refused") {
        _ = try check(["large_blob": ["read": true, "support": "required"]])
    }
    expectThrows("B: an empty large blob object is refused") { _ = try check(["large_blob": [String: Any]()]) }
    expectThrows("B: a registration takes no PRF") {
        _ = try checkRequest(json([
            "op": "passkey_register", "rp_id": "example.com", "user_name": "ann", "user_handle": "AQ==",
            "client_data_hash": hash32, "prf": ["first": base64(32), "hashed": false],
        ]))
    }
    expectThrows("B: a request above 128 KiB is refused") {
        _ = try checkRequest(json(["op": "autofill_list", "domains": [String(repeating: "a", count: 140_000)]]))
    }
}

private func callExtensionTests() {
    let chosen = Data([1, 2, 3, 4, 5])
    let other = Data([9, 9])
    let all = PrfValues(first: Data(repeating: 1, count: 32), second: nil)
    let mine = PrfValues(first: Data(repeating: 2, count: 32), second: Data(repeating: 3, count: 7))

    let byCredential = try? assertionCallExtensions(
        AssertionExtensionRequest(prf: PrfRequest(all: all, byCredential: [chosen: mine, other: all])), credentialID: chosen)
    expect(byCredential?.prf == PrfCallInput(
        first: mine.first.base64EncodedString(), second: mine.second?.base64EncodedString(), hashed: false),
           "X: the PRF inputs of the chosen credential win over the inputs for all")
    let fallback = try? assertionCallExtensions(
        AssertionExtensionRequest(prf: PrfRequest(all: all, byCredential: [other: mine])), credentialID: chosen)
    expect(fallback?.prf == PrfCallInput(first: all.first.base64EncodedString(), second: nil, hashed: false),
           "X: without inputs of its own, the chosen credential gets the inputs for all")
    let noInputs = try? assertionCallExtensions(
        AssertionExtensionRequest(prf: PrfRequest(all: nil, byCredential: [other: mine])), credentialID: chosen)
    expect(noInputs != nil && noInputs?.prf == nil, "X: no inputs for the chosen credential send no PRF")
    expect(prfInputsAreHashed == false, "X: the inputs of macOS go to Apassy as raw WebAuthn inputs")
    expectThrows("X: an empty PRF input fails before the call") {
        _ = try assertionCallExtensions(
            AssertionExtensionRequest(prf: PrfRequest(all: PrfValues(first: Data(), second: nil), byCredential: [:])), credentialID: chosen)
    }
    expectThrows("X: a PRF input of 1025 bytes of another credential fails before the call") {
        let large = PrfValues(first: Data(repeating: 1, count: 1025), second: nil)
        _ = try assertionCallExtensions(AssertionExtensionRequest(prf: PrfRequest(all: all, byCredential: [other: large])), credentialID: chosen)
    }
    expectThrows("X: more than 256 credentials with PRF inputs fail before the call") {
        var many: [Data: PrfValues] = [:]
        for index in 0...256 { many[Data([UInt8(index & 0xFF), UInt8(index >> 8)])] = all }
        _ = try assertionCallExtensions(AssertionExtensionRequest(prf: PrfRequest(all: nil, byCredential: many)), credentialID: chosen)
    }
    expect((try? assertionCallExtensions(AssertionExtensionRequest(largeBlob: .read), credentialID: chosen))?.largeBlob == .read,
           "X: a large blob read goes to the call")
    let blob = Data(repeating: 4, count: ExtensionLimits.maxLargeBlobBytes)
    expect((try? assertionCallExtensions(AssertionExtensionRequest(largeBlob: .write(blob)), credentialID: chosen))?.largeBlob
           == .write(blob.base64EncodedString()), "X: a large blob write of 64 KiB goes to the call")
    expectThrows("X: a large blob write above 64 KiB fails before the call") {
        _ = try assertionCallExtensions(AssertionExtensionRequest(largeBlob: .write(blob + Data([0]))), credentialID: chosen)
    }
    let empty = try? assertionCallExtensions(AssertionExtensionRequest(largeBlob: .write(Data())), credentialID: chosen)
    expect(empty?.largeBlob == nil && empty?.skippedWrite == true, "X: an empty large blob write is not sent")

    // The call as the bridge reads it.
    let call = PasskeyAssertCall(
        id: 3, rpId: "example.com", credentialId: credential, clientDataHash: hash32,
        prf: PrfCallInput(first: base64(32), second: base64(32), hashed: false), largeBlob: .write(blob.base64EncodedString()))
    let encoded = try? encodeCall(call)
    let fields = object(encoded)
    expect((fields?["prf"] as? [String: Any])?["hashed"] as? Bool == false
           && (fields?["large_blob"] as? [String: Any])?["write"] as? String == blob.base64EncodedString(),
           "X: the call names prf and large_blob in snake case")
    expect(encoded.flatMap { try? checkRequest($0) }?.payload["large_blob"] != nil, "X: the bridge accepts a sign-in that writes 64 KiB")
    let readCall = try? encodeCall(PasskeyAssertCall(id: 3, rpId: "example.com", credentialId: credential, clientDataHash: hash32, largeBlob: .read))
    expect((object(readCall)?["large_blob"] as? [String: Any])?["read"] as? Bool == true && object(readCall)?["prf"] == nil,
           "X: a read call is {\"read\": true} and has no prf")
    expect(readCall.flatMap { try? checkRequest($0) } != nil, "X: the bridge accepts a read call")
    let plain = object(try? encodeCall(PasskeyAssertCall(id: 3, rpId: "example.com", credentialId: credential, clientDataHash: hash32)))
    expect(plain?["prf"] == nil && plain?["large_blob"] == nil, "X: a sign-in without extensions sends neither field")
}

private func answerExtensionTests() {
    let credentialID = Data([1, 2, 3, 4, 5])
    let data = authenticatorData(rpID: "example.com", flags: 0x1D).base64EncodedString()
    func answer(signature: Data = Data(repeating: 0x30, count: 70), algorithm: Int? = nil, prf: PrfAnswer? = nil, largeBlob: LargeBlobAnswer? = nil)
        -> PasskeyAssertAnswer
    {
        PasskeyAssertAnswer(
            credentialId: credential, userHandle: "AQ==", authenticatorData: data, signature: signature.base64EncodedString(),
            algorithm: algorithm, prf: prf, largeBlob: largeBlob)
    }
    func check(_ answer: PasskeyAssertAnswer, _ requested: AssertionCallExtensions = AssertionCallExtensions()) throws -> CheckedAssertion {
        try checkAssertion(answer, rpID: "example.com", credentialID: credentialID, requested: requested)
    }

    // Algorithms.
    expect((try? check(answer()))?.algorithm == coseES256, "A: an answer without an algorithm is ES256")
    expectThrows("A: an ES256 signature of 73 bytes fails") { _ = try check(answer(signature: Data(repeating: 0x30, count: 73))) }
    expect((try? check(answer(signature: Data(repeating: 1, count: 64), algorithm: coseEdDSA)))?.algorithm == coseEdDSA,
           "A: an EdDSA signature of 64 bytes passes")
    expectThrows("A: an EdDSA signature of 63 bytes fails") { _ = try check(answer(signature: Data(repeating: 1, count: 63), algorithm: coseEdDSA)) }
    expect((try? check(answer(signature: Data(repeating: 1, count: 256), algorithm: coseRS256))) != nil, "A: an RS256 signature of 256 bytes passes")
    expect((try? check(answer(signature: Data(repeating: 1, count: 512), algorithm: coseRS256))) != nil, "A: an RS256 signature of 512 bytes passes")
    expectThrows("A: an RS256 signature of 513 bytes fails") { _ = try check(answer(signature: Data(repeating: 1, count: 513), algorithm: coseRS256)) }
    expectThrows("A: an RS256 signature of 64 bytes fails") { _ = try check(answer(signature: Data(repeating: 1, count: 64), algorithm: coseRS256)) }
    expect((try? check(answer(signature: Data(repeating: 0x30, count: 103), algorithm: coseES384))) != nil, "A: an ES384 signature of 103 bytes passes")
    expectThrows("A: an unknown algorithm fails") { _ = try check(answer(signature: Data(repeating: 1, count: 64), algorithm: -9)) }
    // A real Ed25519 signature stays valid through the check.
    let edKey = Curve25519.Signing.PrivateKey()
    let clientDataHash = Data(repeating: 7, count: 32)
    let signedData = authenticatorData(rpID: "example.com", flags: 0x1D)
    let edSignature = (try? edKey.signature(for: signedData + clientDataHash)) ?? Data()
    let edChecked = try? check(answer(signature: edSignature, algorithm: coseEdDSA))
    expect(edChecked.map { edKey.publicKey.isValidSignature($0.signature, for: $0.authenticatorData + clientDataHash) } == true,
           "A: a checked EdDSA assertion keeps a valid signature")

    // PRF outputs.
    let prfCall = AssertionCallExtensions(prf: PrfCallInput(first: base64(32), second: base64(32), hashed: false))
    let firstOnly = AssertionCallExtensions(prf: PrfCallInput(first: base64(32), second: nil, hashed: false))
    let outputs = try? check(answer(prf: PrfAnswer(first: base64(32, 1), second: base64(32, 2))), prfCall)
    expect(outputs?.prf == CheckedPrf(first: Data(repeating: 1, count: 32), second: Data(repeating: 2, count: 32)), "A: two PRF outputs pass")
    expect((try? check(answer(), prfCall))?.prf == nil, "A: an answer without PRF outputs passes without them")
    expectThrows("A: a PRF output of 31 bytes fails") { _ = try check(answer(prf: PrfAnswer(first: base64(31))), prfCall) }
    expectThrows("A: a PRF output of 64 bytes fails") { _ = try check(answer(prf: PrfAnswer(first: base64(64))), prfCall) }
    expectThrows("A: a PRF output without PRF inputs fails") { _ = try check(answer(prf: PrfAnswer(first: base64(32)))) }
    expectThrows("A: a second PRF output without a second input fails") {
        _ = try check(answer(prf: PrfAnswer(first: base64(32), second: base64(32))), firstOnly)
    }

    // Large blob outputs.
    let readCall = AssertionCallExtensions(largeBlob: .read)
    let writeCall = AssertionCallExtensions(largeBlob: .write(base64(4)))
    expect((try? check(answer(largeBlob: LargeBlobAnswer(data: base64(5))), readCall))?.largeBlob == .read(Data(repeating: 5, count: 5)),
           "A: a read gives the blob")
    expect((try? check(answer(largeBlob: LargeBlobAnswer()), readCall))?.largeBlob == .read(nil), "A: a read without data gives no blob")
    expect((try? check(answer(largeBlob: LargeBlobAnswer(written: true)), writeCall))?.largeBlob == .written(true), "A: a write gives written")
    expect((try? check(answer(largeBlob: LargeBlobAnswer(written: false)), writeCall))?.largeBlob == .written(false), "A: a refused write gives not written")
    expect((try? check(answer(), writeCall))?.largeBlob == nil, "A: an answer without a large blob output passes without it")
    expectThrows("A: written after a read fails") { _ = try check(answer(largeBlob: LargeBlobAnswer(written: true)), readCall) }
    expectThrows("A: data after a write fails") { _ = try check(answer(largeBlob: LargeBlobAnswer(data: base64(5))), writeCall) }
    expectThrows("A: a large blob output without an operation fails") { _ = try check(answer(largeBlob: LargeBlobAnswer(data: base64(5)))) }
    expectThrows("A: a blob above 64 KiB fails") {
        _ = try check(answer(largeBlob: LargeBlobAnswer(data: base64(ExtensionLimits.maxLargeBlobBytes + 1))), readCall)
    }
    expect((try? check(answer(), AssertionCallExtensions(skippedWrite: true)))?.largeBlob == .written(false),
           "A: an empty write that was not sent gives not written")

    // The answer of the app, decoded.
    let decoded = try? decodeAnswer(json(["ok": true, "result": [
        "credential_id": credential, "user_handle": "AQ==", "authenticator_data": data,
        "signature": Data(repeating: 1, count: 64).base64EncodedString(), "algorithm": -8,
        "prf": ["first": base64(32, 1)], "large_blob": ["data": NSNull()],
    ]]), as: PasskeyAssertAnswer.self)
    expect(decoded?.algorithm == -8 && decoded?.prf == PrfAnswer(first: base64(32, 1)) && decoded?.largeBlob == LargeBlobAnswer(),
           "A: an answer with the algorithm and the extension outputs decodes")
    let older = try? decodeAnswer(json(["ok": true, "result": [
        "credential_id": credential, "user_handle": "AQ==", "authenticator_data": data, "signature": base64(70, 0x30),
    ]]), as: PasskeyAssertAnswer.self)
    expect(older != nil && older?.algorithm == nil && older?.prf == nil && older?.largeBlob == nil,
           "A: an answer without the new members decodes")

    // The outputs for macOS.
    let output = outputs.flatMap(assertionExtensionOutput)
    expect(output?.prf.map { $0.first.withUnsafeBytes { Data($0) } } == Data(repeating: 1, count: 32)
           && output?.prf?.second.map { $0.withUnsafeBytes { Data($0) } } == Data(repeating: 2, count: 32),
           "A: macOS gets both PRF outputs")
    expect(output?.largeBlob == nil, "A: macOS gets no large blob output without an operation")
    expect((try? check(answer())).flatMap(assertionExtensionOutput) == nil, "A: a sign-in without extensions has no extension output")
    let readOutput = (try? check(answer(largeBlob: LargeBlobAnswer(data: base64(5))), readCall)).flatMap(assertionExtensionOutput)
    if case .read(data: let blob)? = readOutput?.largeBlob?.result {
        expect(blob == Data(repeating: 5, count: 5), "A: macOS gets the blob of a read")
    } else {
        expect(false, "A: macOS gets the blob of a read")
    }
    let writeOutput = (try? check(answer(largeBlob: LargeBlobAnswer(written: true)), writeCall)).flatMap(assertionExtensionOutput)
    if case .write(success: let success)? = writeOutput?.largeBlob?.result {
        expect(success, "A: macOS hears that the blob was written")
    } else {
        expect(false, "A: macOS hears that the blob was written")
    }
}

func passkeyExtensionTests() {
    bridgeExtensionTests()
    callExtensionTests()
    answerExtensionTests()
}
