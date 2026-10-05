import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Pairing link")
struct PairingLinkTests {
    static let pin = B64U.encode(Data(repeating: 0x11, count: 32))
    static let secret = Vectors.secret
    static let now = Date(timeIntervalSince1970: 1_790_000_000)

    /// A valid link with one parameter replaced, added, or removed.
    static func link(
        v: String? = "1",
        h: String? = "Mac-mini.local,192.168.1.20",
        p: String? = "48620",
        c: String? = pin,
        s: String? = secret,
        n: String? = "Mac%20mini",
        e: String? = "1790000300"
    ) -> String {
        let items = [("v", v), ("h", h), ("p", p), ("c", c), ("s", s), ("n", n), ("e", e)]
            .compactMap { name, value in value.map { "\(name)=\($0)" } }
        return "apassy://pair?" + items.joined(separator: "&")
    }

    @Test("a valid link parses")
    func valid() throws {
        let link = try PairingLink.parse(Self.link(), now: Self.now)
        #expect(link.hosts == ["Mac-mini.local", "192.168.1.20"])
        #expect(link.port == 48620)
        #expect(link.pin == Data(repeating: 0x11, count: 32))
        #expect(link.secret == Vectors.secretBytes)
        #expect(link.macName == "Mac mini")
        #expect(link.expiresAt == 1_790_000_300)
        #expect(link.endpoint == CompanionEndpoint(hosts: link.hosts, port: 48620, pin: link.pin))
        #expect(!link.isExpired(at: Self.now))
    }

    @Test("the contract example shape parses, with surrounding white space")
    func contractShape() throws {
        let text = "  \(Self.link())\n"
        #expect(try PairingLink.parse(text, now: Self.now).hosts.count == 2)
    }

    @Test("the order of the parameters does not matter")
    func order() throws {
        let text = "apassy://pair?e=1790000300&n=Mac&s=\(Self.secret)&c=\(Self.pin)&p=1&h=a.local&v=1"
        let link = try PairingLink.parse(text, now: Self.now)
        #expect(link.hosts == ["a.local"])
        #expect(link.port == 1)
    }

    @Test("a link with 4 hosts parses and one with 5 is refused")
    func hostCount() throws {
        #expect(try PairingLink.parse(Self.link(h: "a.local,10.0.0.1,10.0.0.2,10.0.0.3"), now: Self.now).hosts.count == 4)
        #expect(throws: PairingLinkError.tooManyHosts) {
            try PairingLink.parse(Self.link(h: "a.local,10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4"), now: Self.now)
        }
    }

    @Test("text that is not a pairing link is refused", arguments: [
        "",
        "hello",
        "https://pair?v=1",
        "apassy://other?v=1",
        "apassy://pair/extra?v=1",
        "apassy://user@pair?v=1",
        "apassy://pair?v=1&n=Zażółć",
        "apassy://pair?v=1&n=a b",
        "apassy://pair:80?v=1",
    ])
    func notALink(text: String) {
        #expect(throws: PairingLinkError.notAPairingLink) { try PairingLink.parse(text, now: Self.now) }
    }

    @Test("another version is refused, and a missing version too")
    func version() {
        #expect(throws: PairingLinkError.unsupportedVersion("2")) { try PairingLink.parse(Self.link(v: "2"), now: Self.now) }
        #expect(throws: PairingLinkError.unsupportedVersion("01")) { try PairingLink.parse(Self.link(v: "01"), now: Self.now) }
        #expect(throws: PairingLinkError.missingParameter("v")) { try PairingLink.parse(Self.link(v: nil), now: Self.now) }
    }

    @Test("each missing or empty parameter is refused", arguments: ["h", "p", "c", "s", "n", "e"])
    func missing(name: String) {
        func make(_ value: String?) -> String {
            Self.link(
                h: name == "h" ? value : "a.local", p: name == "p" ? value : "48620",
                c: name == "c" ? value : Self.pin, s: name == "s" ? value : Self.secret,
                n: name == "n" ? value : "Mac", e: name == "e" ? value : "1790000300")
        }
        #expect(throws: PairingLinkError.missingParameter(name)) { try PairingLink.parse(make(nil), now: Self.now) }
        #expect(throws: PairingLinkError.missingParameter(name)) { try PairingLink.parse(make(""), now: Self.now) }
    }

    @Test("a pin or a secret that is not 32 bytes of b64u is refused")
    func pinAndSecret() {
        let short = B64U.encode(Data(repeating: 1, count: 31))
        let long = B64U.encode(Data(repeating: 1, count: 33))
        for bad in [short, long, "not%20base64!", Self.pin + "=", Self.pin + "A"] {
            #expect(throws: PairingLinkError.badPinOrSecret) { try PairingLink.parse(Self.link(c: bad), now: Self.now) }
            #expect(throws: PairingLinkError.badPinOrSecret) { try PairingLink.parse(Self.link(s: bad), now: Self.now) }
        }
    }

    @Test("an expiry in the past is refused, with the injected clock")
    func expiry() throws {
        let link = Self.link(e: "1790000300")
        #expect(throws: PairingLinkError.expired) {
            try PairingLink.parse(link, now: Date(timeIntervalSince1970: 1_790_000_300))
        }
        #expect(throws: PairingLinkError.expired) {
            try PairingLink.parse(link, now: Date(timeIntervalSince1970: 1_790_009_000))
        }
        #expect(try PairingLink.parse(link, now: Date(timeIntervalSince1970: 1_790_000_299.9)).expiresAt == 1_790_000_300)
        #expect(throws: PairingLinkError.expired) { try PairingLink.parse(Self.link(e: "1"), now: Self.now) }
    }

    @Test("a bad expiry is refused", arguments: ["abc", "-5", "1.5", "17900003000000", "+5", "1%202"])
    func badExpiry(value: String) {
        #expect(throws: PairingLinkError.badParameter("e")) { try PairingLink.parse(Self.link(e: value), now: Self.now) }
    }

    @Test("a port out of range is refused", arguments: ["0", "65536", "99999", "-1", "abc", "48620x", "123456", "4%208"])
    func badPort(value: String) {
        #expect(throws: PairingLinkError.badParameter("p")) { try PairingLink.parse(Self.link(p: value), now: Self.now) }
    }

    @Test("the edges of the port range are accepted")
    func portEdges() throws {
        #expect(try PairingLink.parse(Self.link(p: "1"), now: Self.now).port == 1)
        #expect(try PairingLink.parse(Self.link(p: "65535"), now: Self.now).port == 65535)
    }

    @Test("a bad host is refused", arguments: [",", "a.local,", ",a.local", "a%20b", "a/b", "host:80", "[::1]", "a.local,,b.local", "%C3%A9.local"])
    func badHost(value: String) {
        #expect(throws: PairingLinkError.badParameter("h")) { try PairingLink.parse(Self.link(h: value), now: Self.now) }
    }

    @Test("a repeated parameter is refused")
    func duplicate() {
        let text = Self.link() + "&p=1"
        #expect(throws: PairingLinkError.badParameter("p")) { try PairingLink.parse(text, now: Self.now) }
    }

    @Test("a Mac name loses control characters and is cut to 40 characters")
    func macName() throws {
        let noisy = try PairingLink.parse(Self.link(n: "Ma%0Ac%09%1Bmini"), now: Self.now)
        #expect(noisy.macName == "Macmini")
        let long = try PairingLink.parse(Self.link(n: String(repeating: "x", count: 60)), now: Self.now)
        #expect(long.macName.count == 40)
        let blank = try PairingLink.parse(Self.link(n: "%0A%0A"), now: Self.now)
        #expect(blank.macName == "your Mac")
        let unicode = try PairingLink.parse(Self.link(n: "Za%C5%BC%C3%B3%C5%82%C4%87%20Mac"), now: Self.now)
        #expect(unicode.macName == "Zażółć Mac")
    }

    @Test("each error has a message for the owner")
    func messages() {
        let errors: [PairingLinkError] = [
            .notAPairingLink, .unsupportedVersion("2"), .missingParameter("h"), .badParameter("p"),
            .tooManyHosts, .badPinOrSecret, .expired,
        ]
        for error in errors {
            let text = error.errorDescription ?? ""
            #expect(text.hasSuffix("."))
            #expect(!text.contains("PairingLinkError"))
        }
    }
}
