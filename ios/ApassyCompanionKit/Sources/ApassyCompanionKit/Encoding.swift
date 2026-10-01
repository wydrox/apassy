// Encodings of the wire: base64url, hex, and the hashes (contract section 2).

import CryptoKit
import Foundation

/// Base64url without padding (RFC 4648 section 5).
///
/// Every binary value on the wire uses it: keys, signatures, nonces, the pairing secret, the pin.
public enum B64U {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

    /// Encode bytes. The text has no `=` padding.
    public static func encode(_ data: Data) -> String {
        var out = [UInt8]()
        out.reserveCapacity((data.count * 4 + 2) / 3)
        var buffer: UInt32 = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 6 {
                bits -= 6
                out.append(alphabet[Int((buffer >> UInt32(bits)) & 0x3F)])
            }
            buffer &= (1 << UInt32(bits)) - 1
        }
        if bits > 0 {
            out.append(alphabet[Int((buffer << UInt32(6 - bits)) & 0x3F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decode text, or return nil.
    ///
    /// The decoder is strict: only the base64url alphabet, no padding, no white space, and no
    /// spare bits that are not zero. So each value has one text form.
    public static func decode(_ text: String) -> Data? {
        let input = Array(text.utf8)
        if input.count % 4 == 1 { return nil }
        var out = [UInt8]()
        out.reserveCapacity(input.count * 3 / 4)
        var buffer: UInt32 = 0
        var bits = 0
        for byte in input {
            guard let value = sextet(byte) else { return nil }
            buffer = (buffer << 6) | UInt32(value)
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> UInt32(bits)) & 0xFF))
                buffer &= (1 << UInt32(bits)) - 1
            }
        }
        if buffer != 0 { return nil }
        return Data(out)
    }

    private static func sextet(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): return byte - UInt8(ascii: "A")
        case UInt8(ascii: "a")...UInt8(ascii: "z"): return byte - UInt8(ascii: "a") + 26
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0") + 52
        case UInt8(ascii: "-"): return 62
        case UInt8(ascii: "_"): return 63
        default: return nil
        }
    }
}

/// Lowercase hexadecimal.
public enum Hex {
    private static let digits = Array("0123456789abcdef".utf8)

    /// Encode bytes as lowercase hex.
    public static func encode(_ data: Data) -> String {
        var out = [UInt8]()
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decode lowercase hex, or return nil for any other text.
    public static func decode(_ text: String) -> Data? {
        let input = Array(text.utf8)
        guard input.count % 2 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(input.count / 2)
        var index = 0
        while index < input.count {
            guard let high = nibble(input[index]), let low = nibble(input[index + 1]) else { return nil }
            out.append(high << 4 | low)
            index += 2
        }
        return Data(out)
    }

    private static func nibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
        default: return nil
        }
    }
}

/// Hashes and comparisons that the wire needs.
public enum Hashing {
    /// SHA-256 of the bytes.
    public static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// SHA-256 of the bytes, as lowercase hex.
    public static func sha256Hex(_ data: Data) -> String {
        Hex.encode(sha256(data))
    }

    /// HMAC-SHA256 of a message with a key.
    public static func hmacSHA256(key: Data, message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    /// Compare two byte strings without stopping at the first difference.
    ///
    /// The lengths are not secret, so a different length returns false at once.
    public static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for (x, y) in zip(a, b) {
            difference |= x ^ y
        }
        return difference == 0
    }
}

/// The device ID: 16 random bytes as 32 lowercase hex characters, chosen by the phone.
public enum DeviceID {
    /// A new random device ID.
    public static func random() -> String {
        Hex.encode(RandomBytes.make(16))
    }

    /// Whether the text has the format of a device ID.
    public static func isValid(_ text: String) -> Bool {
        text.utf8.count == 32 && Hex.decode(text) != nil
    }
}

/// Random bytes from the system generator, which is cryptographically secure on Apple platforms.
public enum RandomBytes {
    /// `count` random bytes.
    public static func make(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
}
