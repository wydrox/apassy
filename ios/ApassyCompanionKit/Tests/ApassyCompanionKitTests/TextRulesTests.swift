import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Text rules of the contract")
struct TextRulesTests {
    @Test("a length counts scalars, not characters")
    func scalars() throws {
        // One character on the screen, several scalars: a family emoji, a flag, and a letter with a mark.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}"
        #expect(family.count == 1)
        #expect(TextRules.length(family) == 5)
        let flag = "\u{1F1F5}\u{1F1F1}"
        #expect(flag.count == 1)
        #expect(TextRules.length(flag) == 2)
        let decomposed = "e\u{0301}"
        #expect(decomposed.count == 1)
        #expect(TextRules.length(decomposed) == 2)

        // 40 scalars pass, 41 do not, whatever the number of characters.
        try CompanionClient.checkDeviceName(String(repeating: "a", count: 40))
        try CompanionClient.checkDeviceName(String(repeating: "\u{1F600}", count: 40))
        #expect(throws: CompanionError.self) { try CompanionClient.checkDeviceName(String(repeating: "a", count: 41)) }
        #expect(throws: CompanionError.self) { try CompanionClient.checkDeviceName(String(repeating: "e\u{0301}", count: 21)) }
        // Twenty families are 20 characters but 100 scalars.
        #expect(throws: CompanionError.self) { try CompanionClient.checkDeviceName(String(repeating: family, count: 20)) }
        // Eight families are 40 scalars.
        try CompanionClient.checkDeviceName(String(repeating: family, count: 8))
        #expect(throws: CompanionError.self) { try CompanionClient.checkDeviceName("") }
    }

    @Test("a control character is a scalar of category Cc")
    func control() {
        for value in [0x00, 0x09, 0x0A, 0x0D, 0x1B, 0x7F, 0x80, 0x85, 0x9F] as [UInt32] {
            let text = "a" + String(Unicode.Scalar(value)!) + "b"
            #expect(TextRules.hasControl(text), "U+\(String(value, radix: 16))")
            #expect(throws: CompanionError.self) { try CompanionClient.checkDeviceName(text) }
        }
        // Format, separator, and private use scalars are not Cc: the Mac accepts them.
        for value in [0x00AD, 0x200B, 0x200E, 0x2028, 0x2029, 0xE000, 0xFEFF] as [UInt32] {
            let text = "a" + String(Unicode.Scalar(value)!) + "b"
            #expect(!TextRules.hasControl(text), "U+\(String(value, radix: 16))")
            #expect((try? CompanionClient.checkDeviceName(text)) != nil, "U+\(String(value, radix: 16))")
        }
    }

    @Test("a space at the start or the end is any White_Space scalar")
    func whiteSpace() {
        // The White_Space scalars that are not Cc: U+0020, U+00A0, U+1680, U+2000 to U+200A, U+2028,
        // U+2029, U+202F, U+205F, U+3000. (U+0009 to U+000D and U+0085 are Cc too.)
        let spaces: [UInt32] =
            [0x20, 0xA0, 0x1680] + Array(0x2000...0x200A) + [0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
        for value in spaces {
            let space = String(Unicode.Scalar(value)!)
            #expect(TextRules.isSpace(Unicode.Scalar(value)!), "U+\(String(value, radix: 16))")
            #expect(throws: CompanionError.self) { try CompanionClient.checkDeviceName(space + "Phone") }
            #expect(throws: CompanionError.self) { try CompanionClient.checkDeviceName("Phone" + space) }
            // Inside the name, a space is fine.
            #expect((try? CompanionClient.checkDeviceName("My" + space + "Phone")) != nil)
            #expect(TextRules.trimmed(space + "Phone" + space) == "Phone")
        }
        // Zero width space, the mark of the Mongolian vowel separator, and the word joiner are not
        // White_Space, so they stay at the edge.
        for value in [0x200B, 0x180E, 0x2060, 0xFEFF] as [UInt32] {
            let text = String(Unicode.Scalar(value)!) + "Phone"
            #expect(!TextRules.isSpace(Unicode.Scalar(value)!), "U+\(String(value, radix: 16))")
            #expect(TextRules.trimmed(text) == text)
            #expect((try? CompanionClient.checkDeviceName(text)) != nil)
        }
        #expect(TextRules.trimmed("   ") == "")
        #expect(TextRules.trimmed("") == "")
        #expect(TextRules.isBlank("\u{3000}\u{00A0} "))
        #expect(!TextRules.isBlank("\u{200B}"))
    }

    @Test("the first name of this iPhone is cleaned to what the Mac accepts")
    func firstName() throws {
        #expect(TextRules.deviceName(from: "Rafal's iPhone", fallback: "iPhone") == "Rafal's iPhone")
        #expect(TextRules.deviceName(from: "  \u{3000}Test\niPhone\u{00A0} ", fallback: "iPhone") == "TestiPhone")
        #expect(TextRules.deviceName(from: "\u{0}\u{1}\u{3000}", fallback: "iPhone") == "iPhone")
        #expect(TextRules.deviceName(from: "", fallback: "iPhone") == "iPhone")
        // A cut in the middle of a name leaves no space at the end.
        let cut = TextRules.deviceName(from: String(repeating: "a", count: 39) + " b", fallback: "iPhone")
        #expect(cut == String(repeating: "a", count: 39))
        for raw in [
            String(repeating: "\u{1F600}", count: 90), String(repeating: "x y ", count: 30),
            "\u{2003}" + String(repeating: "n", count: 60),
        ] {
            let name = TextRules.deviceName(from: raw, fallback: "iPhone")
            try CompanionClient.checkDeviceName(name)
            #expect(TextRules.length(name) <= 40)
        }
    }

    @Test("the Mac name and the prompt name follow the same rules")
    func macNameAndPrompt() {
        // Control characters go, the cut is at 40 scalars, and a blank name is replaced.
        #expect(ApprovalPrompt.shortName("a\u{7}b") == "ab")
        #expect(ApprovalPrompt.shortName("\u{3000}\u{00A0}") == "unknown")
        #expect(ApprovalPrompt.shortName(String(repeating: "\u{1F600}", count: 50)).unicodeScalars.count == 40)
    }
}
