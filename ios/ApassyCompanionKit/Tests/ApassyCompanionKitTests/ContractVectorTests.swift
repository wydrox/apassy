// Every vector of contract section 9.

import CryptoKit
import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Contract vectors")
struct ContractVectorTests {
    @Test("the pair string is the one of the contract")
    func pairString() throws {
        let string = try SigningStrings.pair(
            deviceID: Vectors.deviceID, deviceName: Vectors.deviceName,
            requestKey: Vectors.requestPublicKey, approvalKey: Vectors.approvalPublicKey)
        #expect(string == Vectors.pairString)
    }

    @Test("the pair proof is recomputed")
    func pairProof() {
        let proof = SigningStrings.pairProof(secret: Vectors.secretBytes, pairString: Vectors.pairString)
        #expect(B64U.encode(proof) == Vectors.proof)
    }

    @Test("a changed pair string or secret gives another proof")
    func pairProofChanges() {
        let changed = Vectors.changed(Vectors.pairString, at: 30)
        #expect(B64U.encode(SigningStrings.pairProof(secret: Vectors.secretBytes, pairString: changed)) != Vectors.proof)
        var secret = Vectors.secretBytes
        secret[0] ^= 1
        #expect(B64U.encode(SigningStrings.pairProof(secret: secret, pairString: Vectors.pairString)) != Vectors.proof)
    }

    @Test("the code hash, the digits, and the display form")
    func code() {
        let hash = PairingCode.hash(
            secret: Vectors.secretBytes, requestKey: Vectors.requestPublicKey, approvalKey: Vectors.approvalPublicKey)
        #expect(Hex.encode(hash) == Vectors.codeHash)
        #expect(
            PairingCode.digits(
                secret: Vectors.secretBytes, requestKey: Vectors.requestPublicKey,
                approvalKey: Vectors.approvalPublicKey) == "348942")
        #expect(
            PairingCode.display(
                secret: Vectors.secretBytes, requestKey: Vectors.requestPublicKey,
                approvalKey: Vectors.approvalPublicKey) == Vectors.code)
    }

    @Test("the code has leading zeros")
    func codeLeadingZeros() {
        // Find a secret whose code starts with zero, so the padding is shown to work.
        var found = false
        for counter in 0..<5000 {
            let secret = Hashing.sha256(Data("zero-\(counter)".utf8))
            let digits = PairingCode.digits(
                secret: secret, requestKey: Vectors.requestPublicKey, approvalKey: Vectors.approvalPublicKey)
            #expect(digits.count == 6)
            if digits.hasPrefix("00") {
                let display = PairingCode.display(
                    secret: secret, requestKey: Vectors.requestPublicKey, approvalKey: Vectors.approvalPublicKey)
                #expect(display == "\(digits.prefix(3)) \(digits.suffix(3))")
                found = true
                break
            }
        }
        #expect(found)
    }

    @Test("a different key gives a different code")
    func codeDependsOnKeys() {
        let other = SoftwareKeys()
        let code = PairingCode.hash(
            secret: Vectors.secretBytes, requestKey: other.requestPublicKey, approvalKey: Vectors.approvalPublicKey)
        #expect(Hex.encode(code) != Vectors.codeHash)
    }

    @Test("body hashes")
    func bodyHashes() {
        #expect(Hashing.sha256Hex(Data(#"{"remember":false}"#.utf8)) == Vectors.remember0Hash)
        #expect(Hashing.sha256Hex(Data()) == Vectors.emptyHash)
    }

    @Test("the pin of the DER bytes 30 00")
    func pin() {
        #expect(PinnedTLS.pinText(ofCertificate: Data([0x30, 0x00])) == Vectors.pinOf3000)
    }

    @Test("the request string is the one of the contract")
    func requestString() throws {
        let string = try SigningStrings.request(
            method: "GET", path: "/v1/inbox", deviceID: Vectors.deviceID, time: Vectors.time,
            nonce: Vectors.nonce, body: Data())
        #expect(string == Vectors.requestString)
    }

    @Test("the approval string is the one of the contract")
    func approvalString() throws {
        let string = try SigningStrings.approve(
            deviceID: Vectors.deviceID, action: .approve, runID: "123456789012345",
            digest: Vectors.approvalDigest, time: Vectors.time)
        #expect(string == Vectors.approvalString)
    }

    @Test("approve_and_remember is the action name")
    func approveAndRemember() throws {
        let string = try SigningStrings.approve(
            deviceID: Vectors.deviceID, action: .approveAndRemember, runID: "1",
            digest: Vectors.approvalDigest, time: 5)
        #expect(string.split(separator: "\n")[2] == "approve_and_remember")
    }

    @Test("the four given signatures verify with the right key")
    func givenSignaturesVerify() {
        #expect(
            Vectors.verifies(
                signature: Vectors.bytes(Vectors.pairSignatureRequestKey), of: Vectors.pairString,
                publicKey: Vectors.requestPublicKey))
        #expect(
            Vectors.verifies(
                signature: Vectors.bytes(Vectors.pairSignatureApprovalKey), of: Vectors.pairString,
                publicKey: Vectors.approvalPublicKey))
        #expect(
            Vectors.verifies(
                signature: Vectors.bytes(Vectors.requestSignature), of: Vectors.requestString,
                publicKey: Vectors.requestPublicKey))
        #expect(
            Vectors.verifies(
                signature: Vectors.bytes(Vectors.approvalSignature), of: Vectors.approvalString,
                publicKey: Vectors.approvalPublicKey))
    }

    @Test("each given signature fails after one changed character of its string")
    func givenSignaturesFailWhenChanged() {
        let cases: [(String, String, Data)] = [
            (Vectors.pairSignatureRequestKey, Vectors.pairString, Vectors.requestPublicKey),
            (Vectors.pairSignatureApprovalKey, Vectors.pairString, Vectors.approvalPublicKey),
            (Vectors.requestSignature, Vectors.requestString, Vectors.requestPublicKey),
            (Vectors.approvalSignature, Vectors.approvalString, Vectors.approvalPublicKey),
        ]
        for (signature, string, key) in cases {
            let der = Vectors.bytes(signature)
            #expect(Vectors.verifies(signature: der, of: string, publicKey: key))
            // Change each character in turn: no single change may verify.
            for index in 0..<string.count {
                #expect(
                    !Vectors.verifies(signature: der, of: Vectors.changed(string, at: index), publicKey: key),
                    "a change at \(index) verified")
            }
        }
    }

    @Test("each given signature fails with the other key")
    func givenSignaturesFailWithOtherKey() {
        #expect(
            !Vectors.verifies(
                signature: Vectors.bytes(Vectors.pairSignatureRequestKey), of: Vectors.pairString,
                publicKey: Vectors.approvalPublicKey))
        #expect(
            !Vectors.verifies(
                signature: Vectors.bytes(Vectors.pairSignatureApprovalKey), of: Vectors.pairString,
                publicKey: Vectors.requestPublicKey))
        #expect(
            !Vectors.verifies(
                signature: Vectors.bytes(Vectors.requestSignature), of: Vectors.requestString,
                publicKey: Vectors.approvalPublicKey))
        #expect(
            !Vectors.verifies(
                signature: Vectors.bytes(Vectors.approvalSignature), of: Vectors.approvalString,
                publicKey: Vectors.requestPublicKey))
    }

    @Test("the raw private keys give the public keys of the contract")
    func privateKeysGivePublicKeys() throws {
        let keys = try Vectors.makeKeys()
        #expect(keys.requestPublicKey == Vectors.requestPublicKey)
        #expect(keys.approvalPublicKey == Vectors.approvalPublicKey)
        #expect(!keys.isSecureEnclave)
    }

    @Test("signatures of the vector keys verify, differ each time, and fail when changed or with the other key")
    func newSignaturesVerify() async throws {
        let keys = try Vectors.makeKeys()

        let requestA = try keys.signRequest(Data(Vectors.requestString.utf8))
        let requestB = try keys.signRequest(Data(Vectors.requestString.utf8))
        #expect(requestA != requestB)
        for signature in [requestA, requestB] {
            #expect(Vectors.verifies(signature: signature, of: Vectors.requestString, publicKey: Vectors.requestPublicKey))
            #expect(!Vectors.verifies(signature: signature, of: Vectors.requestString, publicKey: Vectors.approvalPublicKey))
            #expect(
                !Vectors.verifies(
                    signature: signature, of: Vectors.changed(Vectors.requestString, at: 40),
                    publicKey: Vectors.requestPublicKey))
        }

        let approvalA = try await keys.signApproval(Data(Vectors.approvalString.utf8), reason: "test")
        let approvalB = try await keys.signApproval(Data(Vectors.approvalString.utf8), reason: "test")
        #expect(approvalA != approvalB)
        for signature in [approvalA, approvalB] {
            #expect(
                Vectors.verifies(signature: signature, of: Vectors.approvalString, publicKey: Vectors.approvalPublicKey))
            #expect(
                !Vectors.verifies(signature: signature, of: Vectors.approvalString, publicKey: Vectors.requestPublicKey))
            #expect(
                !Vectors.verifies(
                    signature: signature, of: Vectors.changed(Vectors.approvalString, at: 40),
                    publicKey: Vectors.approvalPublicKey))
        }
    }

    @Test("the vector pair signatures are the DER of a P-256 signature")
    func signaturesAreDER() {
        for text in [
            Vectors.pairSignatureRequestKey, Vectors.pairSignatureApprovalKey, Vectors.requestSignature,
            Vectors.approvalSignature,
        ] {
            let der = Vectors.bytes(text)
            #expect(der.first == 0x30)
            #expect((try? P256.Signing.ECDSASignature(derRepresentation: der)) != nil)
        }
    }
}
