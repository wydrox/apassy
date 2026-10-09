import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@Suite("VaultText")
struct VaultTextTests {
    @Test("a code is grouped from the right in threes")
    func groupedCode() {
        #expect(VaultText.groupedCode("123456") == "123 456")
        #expect(VaultText.groupedCode("12345678") == "12 345 678")
        #expect(VaultText.groupedCode("1234567") == "1 234 567")
        #expect(VaultText.groupedCode("") == "")
    }

    @Test("a code is spoken digit by digit")
    func spokenCode() {
        #expect(VaultText.spokenCode("123 456") == "1, 2, 3, 4, 5, 6")
    }

    @Test("a label inside a sentence loses its first capital, unless it starts an acronym")
    func phrase() {
        #expect(VaultText.phrase("Password") == "password")
        #expect(VaultText.phrase("API key") == "API key")
        #expect(VaultText.phrase("wifi_password") == "wifi_password")
        #expect(VaultText.phrase("") == "")
    }

    @Test("a website opens with https when it has no scheme, and only as http or https")
    func websiteURL() {
        #expect(VaultText.websiteURL("github.com") == URL(string: "https://github.com"))
        #expect(VaultText.websiteURL("http://x.org") == URL(string: "http://x.org"))
        #expect(VaultText.websiteURL("  github.com \n") == URL(string: "https://github.com"))
        #expect(VaultText.websiteURL("javascript:alert(1)") == nil)
        #expect(VaultText.websiteURL("ftp://x.org") == nil)
        #expect(VaultText.websiteURL("") == nil)
    }

    @Test("the host of a website has no www")
    func host() {
        #expect(VaultText.host("https://www.github.com/x") == "github.com")
        #expect(VaultText.host("netflix.com") == "netflix.com")
    }

    @Test("a device link is the relay link or the bare token, trimmed")
    func joinLink() {
        let link = "https://apassy-relay.example/link#apassy_lnk_abc123"
        #expect(VaultText.joinLink(from: link) == link)
        #expect(VaultText.joinLink(from: "apassy_lnk_abc") == "apassy_lnk_abc")
        #expect(VaultText.joinLink(from: "  apassy_lnk_abc \n") == "apassy_lnk_abc")
        #expect(VaultText.joinLink(from: "https://example.com") == nil)
        #expect(VaultText.joinLink(from: "apassy_lnk_a\napassy_lnk_b") == nil)
        #expect(VaultText.joinLink(from: "  ") == nil)
    }

    @Test("a one-time password setup code is an otpauth totp URI")
    func otpURI() {
        let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP"
        #expect(VaultText.otpURI(from: uri) == uri)
        #expect(VaultText.otpURI(from: "  \(uri)\n") == uri)
        #expect(VaultText.otpURI(from: "OTPAUTH://TOTP/x") == "OTPAUTH://TOTP/x")
        #expect(VaultText.otpURI(from: "otpauth://hotp/x") == nil)
        #expect(VaultText.otpURI(from: "JBSWY3DPEHPK3PXP") == nil)
    }

    @Test("a character is a letter, a digit, a symbol, or a space")
    func characterClass() {
        #expect(VaultText.characterClass("a") == .letter)
        #expect(VaultText.characterClass("Z") == .letter)
        #expect(VaultText.characterClass("7") == .digit)
        #expect(VaultText.characterClass("!") == .symbol)
        #expect(VaultText.characterClass(" ") == .space)
    }

    @Test("a time of the core is a date")
    func date() {
        #expect(VaultText.date(nil) == nil)
        #expect(VaultText.date(60) == Date(timeIntervalSince1970: 60))
    }
}
