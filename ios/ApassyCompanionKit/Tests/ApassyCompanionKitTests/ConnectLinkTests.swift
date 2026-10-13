import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Connect link")
struct ConnectLinkTests {
    static let relay = "https://apassy-relay.wyderka.cc"
    static let code = "apassy_lnk_t_7k2m5q4x3c_" + String(repeating: "0123456789abcdef", count: 4)
    static let pairing =
        "apassy://pair?v=1&h=192.0.2.10&p=48620&c=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&s=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA&n=Mac%20mini&e=1790000300"

    static func relayLink(_ text: String) throws -> RelayConnectLink {
        guard case .relay(let link) = try ConnectLink.parse(text) else {
            Issue.record("not a relay link: \(text)")
            throw ConnectLinkError.notALink
        }
        return link
    }

    // MARK: The vectors of relay-connect-v1, section 7.3

    @Test("vector 1: the old form, with no parameters")
    func vector1() throws {
        let text = "\(Self.relay)/link#\(Self.code)"
        let link = try Self.relayLink(text)
        #expect(link.text == text)
        #expect(link.relay == Self.relay)
        #expect(link.code == Self.code)
        #expect(link.team == "t_7k2m5q4x3c")
        #expect(link.route == .sync)
        #expect(link.macName == nil)
        #expect(link.expiresAt == nil)
        #expect(link.pairingLink == nil)
    }

    @Test("vector 2: the new form with r=connect")
    func vector2() throws {
        let text =
            "\(Self.relay)/link#\(Self.code)&r=connect&n=Mac%20mini&e=1790000600&p=YXBhc3N5Oi8vcGFpcj92PTEmaD0xOTIuMC4yLjEwJnA9NDg2MjAmYz1BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBJnM9QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQSZuPU1hYyUyMG1pbmkmZT0xNzkwMDAwMzAw"
        let link = try Self.relayLink(text)
        #expect(link.relay == Self.relay)
        #expect(link.code == Self.code)
        #expect(link.team == "t_7k2m5q4x3c")
        #expect(link.route == .connect)
        #expect(link.macName == "Mac mini")
        #expect(link.expiresAt == 1_790_000_600)
        #expect(link.pairingLink == Self.pairing)
        // The core gets the whole text; it reads the code before the first `&`.
        #expect(link.text == text)
    }

    @Test("vector 3: a bare code uses the default relay")
    func vector3() throws {
        let link = try Self.relayLink(Self.code)
        #expect(link.relay == nil)
        #expect(link.code == Self.code)
        #expect(link.team == "t_7k2m5q4x3c")
        #expect(link.route == .sync)
        #expect(link.macName == nil && link.expiresAt == nil && link.pairingLink == nil)
    }

    // MARK: Old forms and the pairing link

    @Test("old forms still parse: white space around, and a bare code with parameters")
    func oldForms() throws {
        let link = try Self.relayLink("  \(Self.relay)/link#\(Self.code) \n")
        #expect(link.text == "\(Self.relay)/link#\(Self.code)")
        #expect(link.route == .sync)
        let bare = try Self.relayLink("\(Self.code)&r=connect&n=Mac")
        #expect(bare.relay == nil)
        #expect(bare.route == .connect)
        #expect(bare.macName == "Mac")
    }

    @Test("a pairing link of the local network is a pairing")
    func pairingLink() throws {
        #expect(try ConnectLink.parse("  \(Self.pairing)\n") == .pairing(Self.pairing))
    }

    // MARK: The parse rules

    @Test("text that is not a link is refused")
    func notALink() {
        for text in [
            "", "   ", "https://example.com", "apassy_lnk_abc123", "\(Self.relay)/link#apassy_lnk_abc",
            // Upper case hex, a short secret, a bad team id, a missing separator.
            "apassy_lnk_t_7k2m5q4x3c_" + String(repeating: "0123456789ABCDEF", count: 4),
            "apassy_lnk_t_7k2m5q4x3c_" + String(repeating: "0", count: 63),
            "apassy_lnk_t_7k2m5q4x31_" + String(repeating: "0", count: 64),
            "apassy_lnk_t_7k2m5q4x3c" + String(repeating: "0", count: 65),
            // Two lines, a relay that is not a web address, and a text too long.
            "\(Self.code)\n\(Self.code)", "ftp://relay/link#\(Self.code)", "relay/link#\(Self.code)",
            "\(Self.code)&n=" + String(repeating: "a", count: 2048),
        ] {
            #expect(throws: ConnectLinkError.notALink, "\(text.prefix(60))") { try ConnectLink.parse(text) }
        }
    }

    @Test("a missing route is sync; an unknown route needs a newer version")
    func route() throws {
        #expect(try Self.relayLink("\(Self.code)&n=Mac").route == .sync)
        #expect(try Self.relayLink("\(Self.code)&r=sync").route == .sync)
        // The first value of a key counts.
        #expect(try Self.relayLink("\(Self.code)&r=connect&r=sync").route == .connect)
        for value in ["share", "", "SYNC"] {
            #expect(throws: ConnectLinkError.needsNewerVersion, "\(value)") {
                try ConnectLink.parse("\(Self.relay)/link#\(Self.code)&r=\(value)")
            }
        }
        #expect(ConnectLinkError.needsNewerVersion.errorDescription?.contains("newer version of Apassy") == true)
    }

    @Test("a bad name, expiry, or pairing link is dropped, and the rest stays")
    func badHints() throws {
        for name in ["Mac%2", "Mac%zz", "%FF%FE", "%00%01", "%20%20"] {
            let link = try Self.relayLink("\(Self.code)&r=connect&n=\(name)&e=1790000600")
            #expect(link.macName == nil, "\(name)")
            #expect(link.route == .connect && link.expiresAt == 1_790_000_600)
        }
        for expiry in ["", "0", "01790000600", "17900006OO", "-1", "1" + String(repeating: "0", count: 30)] {
            #expect(try Self.relayLink("\(Self.code)&e=\(expiry)").expiresAt == nil, "\(expiry)")
        }
        let notPairing = B64U.encode(Data("https://example.com".utf8))
        let withSpace = B64U.encode(Data("apassy://pair?v=1 x".utf8))
        for pairing in ["!!", notPairing, withSpace, B64U.encode(Data(Self.pairing.utf8)) + "="] {
            #expect(try Self.relayLink("\(Self.code)&p=\(pairing)").pairingLink == nil, "\(pairing)")
        }
        // Unknown keys and a parameter without `=` are ignored.
        let link = try Self.relayLink("\(Self.code)&x=1&n&n=Mac%20mini&&")
        #expect(link.macName == "Mac mini")
    }

    @Test("the Mac name is cleaned as on the Mac: no control character, at most 64 bytes")
    func name() throws {
        #expect(try Self.relayLink("\(Self.code)&n=%20Rafa%C5%82%27s%09Mac%20").macName == "Rafał'sMac")
        let long = String(repeating: "%C5%82", count: 40)
        let cut = try #require(try Self.relayLink("\(Self.code)&n=\(long)").macName)
        #expect(cut == String(repeating: "ł", count: 32))
        #expect(cut.utf8.count == 64)
        // A `+` is not a space.
        #expect(try Self.relayLink("\(Self.code)&n=Mac+mini").macName == "Mac+mini")
    }
}
