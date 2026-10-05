import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Client: pairing")
struct ClientPairTests {
    static func pairClient(
        transport: any CompanionTransport, keys: any CompanionKeys, link: PairingLink = Vectors.link(),
        clock: TestClock = TestClock()
    ) -> CompanionClient {
        CompanionClient(
            link: link, deviceID: Vectors.deviceID, keys: keys, transport: transport, now: clock.source,
            nonce: Support.nonces())
    }

    @Test("pairing sends the contract body and returns the code of the vectors")
    func pair() async throws {
        let keys = try RecordingKeys()
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"expires_at":1790000300}"#) }
        let client = Self.pairClient(transport: transport, keys: keys)
        let start = try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        #expect(start.code == Vectors.code)
        #expect(start.expiresAt == 1_790_000_300)

        let request = try #require(transport.requests.first)
        #expect(transport.requests.count == 1)
        #expect(request.method == "POST")
        #expect(request.path == "/v1/pair")
        #expect(request.host == "Mac-mini.local")
        #expect(request.port == 48620)
        // A pair request has no request signature.
        #expect(request.headers.keys.filter { $0.hasPrefix("X-Apassy") }.isEmpty)

        let object = try #require(JSONSerialization.jsonObject(with: request.body) as? [String: Any])
        #expect(
            Set(object.keys) == [
                "v", "device_id", "device_name", "request_key", "approval_key", "request_key_signature",
                "approval_key_signature", "proof",
            ])
        #expect(object["v"] as? Int == 1)
        #expect(object["device_id"] as? String == Vectors.deviceID)
        #expect(object["device_name"] as? String == "Test iPhone")
        #expect(object["request_key"] as? String == Vectors.requestPublic)
        #expect(object["approval_key"] as? String == Vectors.approvalPublic)
        #expect(object["proof"] as? String == Vectors.proof)

        let requestSignature = try Support.field(object["request_key_signature"] as? String)
        let approvalSignature = try Support.field(object["approval_key_signature"] as? String)
        #expect(Vectors.verifies(signature: requestSignature, of: Vectors.pairString, publicKey: Vectors.requestPublicKey))
        #expect(Vectors.verifies(signature: approvalSignature, of: Vectors.pairString, publicKey: Vectors.approvalPublicKey))
        #expect(!Vectors.verifies(signature: requestSignature, of: Vectors.pairString, publicKey: Vectors.approvalPublicKey))
        #expect(!Vectors.verifies(signature: approvalSignature, of: Vectors.pairString, publicKey: Vectors.requestPublicKey))

        // One Face ID prompt, for the pair string, with the reason of the contract.
        #expect(keys.approvalMessages == [Vectors.pairString])
        #expect(keys.approvalReasons == ["pair with Apassy on \"Mac mini\""])
    }

    @Test("the pair request goes to the next host after a connection error")
    func pairFallback() async throws {
        let transport = ScriptedTransport { _, index in
            index == 0 ? .failure(.connection) : Support.ok(#"{"expires_at":1790000300}"#)
        }
        let client = Self.pairClient(transport: transport, keys: try RecordingKeys())
        _ = try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        #expect(transport.requests.map(\.host) == ["Mac-mini.local", "192.168.1.20"])
        #expect(transport.requests[0].body == transport.requests[1].body)
    }

    @Test("a 401 says that the link does not work, and no code is made")
    func rejected() async throws {
        let transport = ScriptedTransport { _, _ in Support.error(401, "unauthorized") }
        let client = Self.pairClient(transport: transport, keys: try RecordingKeys())
        await #expect(throws: CompanionError.linkRejected) {
            try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        }
        await #expect(throws: CompanionError.self) { try await client.pairStatus() }
        #expect(transport.requests.count == 1)
    }

    @Test("other pair errors keep the message of the Mac")
    func alreadyPaired() async throws {
        let transport = ScriptedTransport { _, _ in Support.error(409, "already_paired", "This device is paired.") }
        let client = Self.pairClient(transport: transport, keys: try RecordingKeys())
        await #expect(throws: CompanionError.server(status: 409, code: "already_paired", message: "This device is paired.")) {
            try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        }
    }

    @Test("an expired link sends nothing")
    func expired() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"expires_at":1}"#) }
        let clock = TestClock(1_790_000_300)
        let keys = try RecordingKeys()
        let client = Self.pairClient(transport: transport, keys: keys, clock: clock)
        await #expect(throws: CompanionError.linkExpired) {
            try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        }
        #expect(transport.requests.isEmpty)
        #expect(keys.approvalMessages.isEmpty)
    }

    @Test("a bad device name is refused before a signature or a request", arguments: [
        "", " Test", "Test ", "a\nb", "a\tb", String(repeating: "x", count: 41), "\u{7F}",
    ])
    func badName(name: String) async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"expires_at":1790000300}"#) }
        let keys = try RecordingKeys()
        let client = Self.pairClient(transport: transport, keys: keys)
        await #expect(throws: CompanionError.self) { try await client.pair(link: Vectors.link(), deviceName: name) }
        #expect(transport.requests.isEmpty)
        #expect(keys.approvalMessages.isEmpty)
    }

    @Test("a name of 40 characters, with inner spaces and non-ASCII text, is accepted")
    func goodName() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"expires_at":1790000300}"#) }
        let client = Self.pairClient(transport: transport, keys: try RecordingKeys())
        let name = "Zażółć gęślą jaźń " + String(repeating: "x", count: 22)
        #expect(name.unicodeScalars.count == 40)
        _ = try await client.pair(link: Vectors.link(), deviceName: name)
        let object = try Support.json(try #require(transport.requests.first).body)
        #expect(object["device_name"] as? String == name)
    }

    @Test("a cancelled Face ID sends nothing")
    func cancelled() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"expires_at":1790000300}"#) }
        let client = Self.pairClient(transport: transport, keys: RefusingKeys())
        await #expect(throws: CompanionKeyError.cancelled) {
            try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        }
        #expect(transport.requests.isEmpty)
    }

    @Test("a link for another Mac than the client is refused")
    func otherLink() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"expires_at":1790000300}"#) }
        let client = Self.pairClient(transport: transport, keys: try RecordingKeys())
        let other = Vectors.link(pin: Data(repeating: 1, count: 32))
        await #expect(throws: CompanionError.self) { try await client.pair(link: other, deviceName: "Test iPhone") }
        #expect(transport.requests.isEmpty)
    }

    @Test("pair status asks with the proof and no request signature, and reads each state")
    func pairStatus() async throws {
        let answers = [
            #"{"state":"waiting"}"#, #"{"state":"paired","mac_name":"Mac mini"}"#, #"{"state":"denied"}"#,
            #"{"state":"expired"}"#,
        ]
        let transport = ScriptedTransport { request, index in
            if request.path == "/v1/pair" { return Support.ok(#"{"expires_at":1790000300}"#) }
            return Support.ok(answers[index - 1])
        }
        let client = Self.pairClient(transport: transport, keys: try RecordingKeys())
        _ = try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        #expect(try await client.pairStatus() == .waiting)
        #expect(try await client.pairStatus() == .paired(macName: "Mac mini"))
        #expect(try await client.pairStatus() == .denied)
        #expect(try await client.pairStatus() == .expired)

        let poll = transport.requests[1]
        #expect(poll.method == "GET")
        #expect(poll.path == "/v1/pair/\(Vectors.deviceID)")
        #expect(poll.headers["X-Apassy-Pair-Proof"] == Vectors.proof)
        #expect(poll.headers.keys.filter { $0.hasPrefix("X-Apassy") } == ["X-Apassy-Pair-Proof"])
        #expect(poll.body.isEmpty)
    }

    @Test("an unknown state is an invalid response")
    func unknownState() async throws {
        let transport = ScriptedTransport { request, _ in
            request.path == "/v1/pair" ? Support.ok(#"{"expires_at":1790000300}"#) : Support.ok(#"{"state":"later"}"#)
        }
        let client = Self.pairClient(transport: transport, keys: try RecordingKeys())
        _ = try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        await #expect(throws: CompanionError.invalidResponse) { try await client.pairStatus() }
    }

    @Test("when the Mac dropped the answer, a signed status decides")
    func missedAnswer() async throws {
        let paired = ScriptedTransport { request, _ in
            switch request.path {
            case "/v1/pair": return Support.ok(#"{"expires_at":1790000300}"#)
            case "/v1/status":
                return Support.ok(#"{"v":1,"mac_name":"Mac mini","app_version":"0.2.1","approval_timeout_seconds":120,"device":{"id":"d4c0ffee00000000000000000000beef","name":"Test iPhone","paired_at":1790000000}}"#)
            default: return Support.error(404, "not_found")
            }
        }
        let client = Self.pairClient(transport: paired, keys: try RecordingKeys())
        _ = try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        #expect(try await client.pairStatus() == .paired(macName: "Mac mini"))
        let status = try #require(paired.requests.last)
        #expect(status.path == "/v1/status")
        Support.verifySigned(status, publicKey: Vectors.requestPublicKey)

        let notPaired = ScriptedTransport { request, _ in
            switch request.path {
            case "/v1/pair": return Support.ok(#"{"expires_at":1790000300}"#)
            case "/v1/status": return Support.error(401, "unpaired")
            default: return Support.error(404, "not_found")
            }
        }
        let second = Self.pairClient(transport: notPaired, keys: try RecordingKeys())
        _ = try await second.pair(link: Vectors.link(), deviceName: "Test iPhone")
        #expect(try await second.pairStatus() == .expired)
    }

    @Test("after pairing the client makes the record to save")
    func record() async throws {
        let transport = ScriptedTransport { request, _ in
            request.path == "/v1/pair" ? Support.ok(#"{"expires_at":1790000300}"#) : Support.ok(#"{"state":"paired","mac_name":"Mac mini"}"#)
        }
        let client = Self.pairClient(transport: transport, keys: try RecordingKeys())
        _ = try await client.pair(link: Vectors.link(), deviceName: "Test iPhone")
        #expect(try await client.pairStatus() == .paired(macName: "Mac mini"))
        let record = await client.pairingRecord(macName: "Mac mini")
        #expect(record.deviceID == Vectors.deviceID)
        #expect(record.hosts == ["Mac-mini.local", "192.168.1.20"])
        #expect(record.port == 48620)
        #expect(record.pin == Data(repeating: 7, count: 32))
        #expect(record.lastGoodHost == "Mac-mini.local")
        #expect(record.pairedAt == 1_790_000_000)
    }
}
