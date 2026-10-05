// The test vectors of contract section 9, and helpers that the suites share. All values are synthetic.

import CryptoKit
import Foundation

@testable import ApassyCompanionKit

enum Vectors {
    static let requestPrivateHex = "71c2b0317a434582145879f70d13e172c602ea37c2c4fada95a83679867a2676"
    static let approvalPrivateHex = "bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b"
    static let requestPublic =
        "BIcY3rZ6TdzHFNUttUCSdryZE3YayizgQ0KT5D1LKMdwv4E2AxLTggQEYU3HYfQzwIm-fdsPZYt5aEYV6-EJskE"
    static let approvalPublic =
        "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts"
    static let secret = "s9IIzFKuwMPGM-IW92PJK8U5dG0y14hgHYP9lX4UI0g"
    static let deviceID = "d4c0ffee00000000000000000000beef"
    static let deviceName = "Test iPhone"
    static let proof = "KGSWHAv-NdQat1HFN0hqCLYCiGJnuQaxbQ3kogGaqFE"
    static let pairSignatureRequestKey =
        "MEYCIQCDKleQt7-bz06sJBuMu2Mgxo4-sOmKfR8ZnRk3WX-xPgIhAMidi2mo3Lbz1aK4ROOSYNlvsoWqc-RI7Zbi5oLDHujf"
    static let pairSignatureApprovalKey =
        "MEUCIQC-Lswfys1i6xzmUbXHou1gX-N5cpBnnrH6wkqo4LU46gIgIqEtSlpfzZhyiJuHgALfdyQ0Uu6XlIC3w_dL60VmQUQ"
    static let codeHash = "7050e20eb0016a113bfb886cf0ca8e4eefc9bccd1861d2d9f292aa637ca28555"
    static let code = "348 942"
    static let nonce = "AAECAwQFBgcICQoLDA0ODw"
    static let time: Int64 = 1_790_000_000
    static let remember0Hash = "c21638494d6f31b1eb753c01dc27df1491cafaa42e908bf82eaede49134884c3"
    static let emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    static let pinOf3000 = "5PYNCqbX89O2pklLHIYbmfZJxvnsUauvIBsg8pcyfJU"
    static let requestSignature =
        "MEQCICGLPWDhC0B33p0zHBaApsO593Vzug0WuvtkmZ5F6Wx3AiB5QXmACxIlrPnUhtpTMplEC2h1h6fqwvAyUIOA2PFipw"
    static let approvalDigest = String(repeating: "ab", count: 32)
    static let approvalSignature =
        "MEUCIEdCbu0iVNdaKys-5EkPMdAn4R79c0p0wtlE9Jnk5QtfAiEAtyrTuQWKWoTxZRvziO4_A-NK1QD5B-gXMiuV5Pvs9wo"

    static let pairString = """
        apassy-companion-pair-v1
        d4c0ffee00000000000000000000beef
        Test iPhone
        BIcY3rZ6TdzHFNUttUCSdryZE3YayizgQ0KT5D1LKMdwv4E2AxLTggQEYU3HYfQzwIm-fdsPZYt5aEYV6-EJskE
        BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts
        """

    static let requestString = """
        apassy-companion-request-v1
        GET
        /v1/inbox
        d4c0ffee00000000000000000000beef
        1790000000
        AAECAwQFBgcICQoLDA0ODw
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """

    static let approvalString = """
        apassy-companion-approve-v1
        d4c0ffee00000000000000000000beef
        approve
        123456789012345
        abababababababababababababababababababababababababababababababab
        1790000000
        """

    // MARK: Decoded values

    static func bytes(_ text: String) -> Data { B64U.decode(text)! }

    static var requestPublicKey: Data { bytes(requestPublic) }
    static var approvalPublicKey: Data { bytes(approvalPublic) }
    static var secretBytes: Data { bytes(secret) }

    static func makeKeys() throws -> SoftwareKeys {
        try SoftwareKeys(
            requestPrivateKey: Hex.decode(requestPrivateHex)!,
            approvalPrivateKey: Hex.decode(approvalPrivateHex)!)
    }

    /// Whether a DER signature over the UTF-8 bytes of a string verifies with a public key.
    static func verifies(signature: Data, of text: String, publicKey: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
            let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature)
        else {
            return false
        }
        return key.isValidSignature(sig, for: Data(text.utf8))
    }

    /// The text with the character at `index` changed to another one.
    static func changed(_ text: String, at index: Int) -> String {
        var characters = Array(text)
        characters[index] = characters[index] == "x" ? "y" : "x"
        return String(characters)
    }

    /// A pairing link for the vector secret and keys, valid until 1790000300.
    static func link(
        hosts: [String] = ["Mac-mini.local", "192.168.1.20"], pin: Data = Data(repeating: 7, count: 32)
    ) -> PairingLink {
        PairingLink(
            hosts: hosts, port: 48620, pin: pin, secret: secretBytes, macName: "Mac mini", expiresAt: 1_790_000_300)
    }

    static let clockNow = Date(timeIntervalSince1970: 1_790_000_000)
}

/// A throwaway self-signed ECDSA P-256 certificate and key for the local TLS tests, as PKCS#12 with
/// the password "test". It secures nothing: the common name is `apassy-test.invalid`.
enum TLSFixture {
    static let pkcs12Base64 =
        "MIIDZwIBAzCCAy0GCSqGSIb3DQEHAaCCAx4EggMaMIIDFjCCAe8GCSqGSIb3DQEHBqCCAeAwggHcAgEAMIIB1QYJ" +
        "KoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIb1+0jdjoWw4CAggAgIIBqD2Bk/qoT8Io+BY4Oua2hXxtET0IkJ95" +
        "bd6bqCp7H0GHULq37ZlNTlVhiiRIH4L8ApEWBdERkfY8rQFJy8lRRNwWyIO9dHljZ3jqxBuCCx8dyalqFCgUPuwM" +
        "4873bZrL0ORaX3/lR8SK4kftFJYk7bviyZkEq5TerXS/mWwMpkinus7QyDLrV0Iy6u/xjwvFLUkME15HHFALuOKT" +
        "exJsLvDyoTSPH4eqZa0Vq4/s7i3SVpOlqT0t5FQNSrSc0Lhnb6267rjF7WGjcpJkzfBsWh0oAas2mQVlBub8a5QR" +
        "1UY/NEw8JLtYAtRC/edlA0eZ/RQpo/QIODUwivMy6txG5LpzCky/U6LpmNyAPUpz7twpXui2TPstxvtuxiO9yvKL" +
        "hGTxmNeJigH8WglamFGz0fep/eYpci0QeM4AQI6+p6vyU0Xg7p+sEdFq/jrQB/YrOTWI4BoxrqEyH7qRwQos64b6" +
        "v4eLbChNBa7LiPADgkxL4btR4VsqlOxV8ksts1PXaZc0axwixwup8u9JlcZZQdzhgbo5yKQ+LJxAFHD8sZYfQcmB" +
        "kNq7yFIwggEfBgkqhkiG9w0BBwGgggEQBIIBDDCCAQgwggEEBgsqhkiG9w0BDAoBAqCBtDCBsTAcBgoqhkiG9w0B" +
        "DAEDMA4ECBQ74KYg/QWlAgIIAASBkLwzg5mbMAIExj191mE1lBUJ17nO55iioKZ07/kfzBH6twaAgDLOSdrDGd+6" +
        "GhNcWgKXLt2Jg9cf5rFmSSbWqTNLZaPilXAy1a5ReFQjSr+mj/Hm8OoJdW65RFmb6iOh49w6J4/jftCHn2/wKDb3" +
        "iljC+P8Wv4p1o0rx2nFRv2Zf3twOqkbybgWOJpd9xlclhTE+MBcGCSqGSIb3DQEJFDEKHggAdABlAHMAdDAjBgkq" +
        "hkiG9w0BCRUxFgQUWfpH+v/hrUnP2ap8VleDGfhtAzwwMTAhMAkGBSsOAwIaBQAEFF9XWxKxZTxtZI0cXBZ2tDLL" +
        "YEvTBAhnu2gRnhheJwICCAA="
    static let password = "test"
    /// The pin of its certificate, computed with openssl when the fixture was made.
    static let pin = "75r2QEN0o4P_I3ifA2mcoAJhP8Px4o3d7i4cSDeXO-4"
}
