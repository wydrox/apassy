import CryptoKit
import Foundation

/// The passkey arithmetic of `PreviewVaultService`, as the contract has it for the core: ES256,
/// "none" attestation, a zero AAGUID, and a sign count of 0. Only for synthetic data in previews
/// and tests; the vault core does this for real vaults.
struct PreviewAuthenticator {
    /// User present and user verified: AutoFill unlocked the vault for this request.
    static let flagsUPUV: UInt8 = 0x05
    /// And attested credential data.
    static let flagAT: UInt8 = 0x40

    let rpID: String
    let key: P256.Signing.PrivateKey

    var rpIDHash: Data { Data(SHA256.hash(data: Data(rpID.utf8))) }

    func assertionData() -> Data {
        rpIDHash + [Self.flagsUPUV, 0, 0, 0, 0]
    }

    func sign(_ authenticatorData: Data, clientDataHash: Data) throws -> Data {
        try key.signature(for: authenticatorData + clientDataHash).derRepresentation
    }

    /// The authenticator data of a registration, with the credential and its COSE key.
    func registrationData(credentialID: Data) -> Data {
        var data = rpIDHash
        data.append(Self.flagsUPUV | Self.flagAT)
        data += [0, 0, 0, 0]
        data += Data(count: 16)
        data += [UInt8(credentialID.count >> 8), UInt8(credentialID.count & 0xff)]
        data += credentialID
        data += coseKey()
        return data
    }

    /// `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
    func coseKey() -> Data {
        let raw = key.publicKey.rawRepresentation
        var cbor = CBOR()
        cbor.map(5)
        cbor.int(1); cbor.int(2)
        cbor.int(3); cbor.int(-7)
        cbor.int(-1); cbor.int(1)
        cbor.int(-2); cbor.bytes(raw.prefix(32))
        cbor.int(-3); cbor.bytes(raw.suffix(32))
        return cbor.data
    }

    /// `{"fmt": "none", "attStmt": {}, "authData": …}`.
    func attestationObject(credentialID: Data) -> Data {
        var cbor = CBOR()
        cbor.map(3)
        cbor.text("fmt"); cbor.text("none")
        cbor.text("attStmt"); cbor.map(0)
        cbor.text("authData"); cbor.bytes(registrationData(credentialID: credentialID))
        return cbor.data
    }
}

/// A CBOR writer for the few shapes above.
struct CBOR {
    private(set) var data = Data()

    private mutating func head(_ major: UInt8, _ value: UInt64) {
        let type = major << 5
        switch value {
        case ..<24: data.append(type | UInt8(value))
        case ..<0x100: data += [type | 24, UInt8(value)]
        case ..<0x10000: data += [type | 25, UInt8(value >> 8), UInt8(value & 0xff)]
        default:
            data.append(type | 26)
            for shift in stride(from: 24, through: 0, by: -8) { data.append(UInt8((value >> UInt64(shift)) & 0xff)) }
        }
    }

    mutating func int(_ value: Int) {
        if value >= 0 { head(0, UInt64(value)) } else { head(1, UInt64(-1 - value)) }
    }

    mutating func bytes(_ value: Data) {
        head(2, UInt64(value.count))
        data += value
    }

    mutating func text(_ value: String) {
        head(3, UInt64(value.utf8.count))
        data += Data(value.utf8)
    }

    mutating func map(_ count: Int) { head(5, UInt64(count)) }
}
