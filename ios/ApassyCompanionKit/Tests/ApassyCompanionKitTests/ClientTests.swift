import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Client: signed requests")
struct ClientRequestTests {
    @Test("a request has the four headers, and with the vector clock and nonce it signs the contract string")
    func fourHeaders() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(WireModelTests.inboxJSON) }
        let client = try Support.client(transport: transport)
        let nonces: NonceSource = { Data(0...15) }
        let vectorClient = CompanionClient(
            deviceID: Vectors.deviceID, endpoint: Support.endpoint, keys: try Vectors.makeKeys(),
            transport: transport, now: TestClock().source, nonce: nonces)
        _ = try await client.inbox()
        _ = try await vectorClient.inbox()

        let request = try #require(transport.requests.last)
        #expect(request.method == "GET")
        #expect(request.path == "/v1/inbox")
        #expect(request.body.isEmpty)
        #expect(request.headers["X-Apassy-Device"] == Vectors.deviceID)
        #expect(request.headers["X-Apassy-Time"] == "1790000000")
        #expect(request.headers["X-Apassy-Nonce"] == Vectors.nonce)
        let signatureText = try #require(request.headers["X-Apassy-Signature"])
        let signature = try #require(B64U.decode(signatureText))
        #expect(Vectors.verifies(signature: signature, of: Vectors.requestString, publicKey: Vectors.requestPublicKey))
        Support.verifySigned(transport.requests[0], publicKey: Vectors.requestPublicKey)
        Support.verifySigned(request, publicKey: Vectors.requestPublicKey)
    }

    @Test("each request has a new nonce, and the time follows the clock")
    func newNonce() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(WireModelTests.inboxJSON) }
        let clock = TestClock()
        let client = try Support.client(transport: transport, clock: clock)
        _ = try await client.inbox()
        clock.advance(2)
        _ = try await client.inbox()
        let a = transport.requests[0].headers
        let b = transport.requests[1].headers
        #expect(a["X-Apassy-Nonce"] != b["X-Apassy-Nonce"])
        #expect(a["X-Apassy-Time"] == "1790000000")
        #expect(b["X-Apassy-Time"] == "1790000002")
        #expect(a["X-Apassy-Signature"] != b["X-Apassy-Signature"])
    }

    @Test("a body request signs the hash of the exact bytes it sends")
    func bodyHash() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"outcome":"denied"}"#) }
        let client = try Support.client(transport: transport)
        try await client.deny(run: Support.run())
        let request = try #require(transport.requests.first)
        #expect(request.method == "POST")
        #expect(request.path == "/v1/runs/123456789012345/deny")
        #expect(String(decoding: request.body, as: UTF8.self) == "{}")
        #expect(request.headers["Content-Type"] == "application/json")
        Support.verifySigned(request, publicKey: Vectors.requestPublicKey)

        // A signature over another body does not verify with these headers.
        var altered = request
        altered.body = Data(#"{"a":1}"#.utf8)
        let timeText = try #require(altered.headers["X-Apassy-Time"])
        let nonceText = try #require(altered.headers["X-Apassy-Nonce"])
        let signatureText = try #require(altered.headers["X-Apassy-Signature"])
        let string = try SigningStrings.request(
            method: altered.method, path: altered.path, deviceID: Vectors.deviceID,
            time: Int64(timeText) ?? 0, nonce: nonceText, body: altered.body)
        let signature = try #require(B64U.decode(signatureText))
        #expect(!Vectors.verifies(signature: signature, of: string, publicKey: Vectors.requestPublicKey))
    }

    @Test("the endpoints use the paths and methods of the contract")
    func paths() async throws {
        let transport = ScriptedTransport { request, _ in
            switch request.path {
            case "/v1/status":
                return Support.ok(#"{"v":1,"mac_name":"Mac mini","app_version":"0.2.1","approval_timeout_seconds":120,"device":{"id":"d4c0ffee00000000000000000000beef","name":"Test iPhone","paired_at":1790000000}}"#)
            case "/v1/inbox": return Support.ok(WireModelTests.inboxJSON)
            case "/v1/device": return Support.ok(#"{"outcome":"unpaired"}"#)
            default: return Support.ok(#"{"outcome":"denied"}"#)
            }
        }
        let client = try Support.client(transport: transport)
        #expect(try await client.status().macName == "Mac mini")
        #expect(try await client.inbox().runs.count == 1)
        try await client.deny(run: Support.run())
        try await client.denyAccessRequest(id: "42")
        try await client.unpair()
        let seen = transport.requests.map { "\($0.method) \($0.path)" }
        #expect(
            seen == [
                "GET /v1/status", "GET /v1/inbox", "POST /v1/runs/123456789012345/deny",
                "POST /v1/access-requests/42/deny", "DELETE /v1/device",
            ])
        for request in transport.requests {
            Support.verifySigned(request, publicKey: Vectors.requestPublicKey)
            #expect(request.port == 48620)
        }
        #expect(transport.requests.last?.body.isEmpty == true)
    }

    @Test("an ID that is not a decimal number is refused before anything is sent")
    func idInjection() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"outcome":"denied"}"#) }
        let client = try Support.client(transport: transport)
        for id in ["", "1/../device", "12a", "1 2", "1\n2", String(repeating: "1", count: 21)] {
            await #expect(throws: CompanionError.self) { try await client.denyAccessRequest(id: id) }
            var run = Support.run()
            run = PendingRun(
                id: id, agent: run.agent, command: run.command, cwd: run.cwd, envNames: run.envNames,
                purpose: run.purpose, risk: run.risk, userRequest: run.userRequest, requestSource: run.requestSource,
                agentRequest: run.agentRequest, remember: run.remember, digest: run.digest, waitingSeconds: nil)
            await #expect(throws: CompanionError.self) { try await client.deny(run: run) }
        }
        #expect(transport.requests.isEmpty)
    }

    @Test("an answer that is not the contract gives invalidResponse")
    func invalidResponse() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok("<html>") }
        let client = try Support.client(transport: transport)
        await #expect(throws: CompanionError.invalidResponse) { try await client.inbox() }
    }

    @Test("an unpaired answer and a clock skew answer become their errors")
    func serverErrors() async throws {
        let unpaired = ScriptedTransport { _, _ in Support.error(401, "unpaired") }
        await #expect(throws: CompanionError.unpaired) { try await Support.client(transport: unpaired).inbox() }

        let skew = ScriptedTransport { _, _ in Support.error(401, "clock_skew", "The clocks differ by 93 s.") }
        await #expect(throws: CompanionError.clockSkew(message: "The clocks differ by 93 s.")) {
            try await Support.client(transport: skew).inbox()
        }

        let other = ScriptedTransport { _, _ in Support.error(429, "too_many_requests", "Slow down.") }
        await #expect(throws: CompanionError.server(status: 429, code: "too_many_requests", message: "Slow down.")) {
            try await Support.client(transport: other).inbox()
        }
    }

    @Test("unpair counts a Mac that no longer knows the device as done")
    func unpairAlreadyGone() async throws {
        let transport = ScriptedTransport { _, _ in Support.error(401, "unpaired") }
        try await Support.client(transport: transport).unpair()
        let broken = ScriptedTransport { _, _ in Support.error(500, "internal") }
        await #expect(throws: CompanionError.self) { try await Support.client(transport: broken).unpair() }
    }
}

@Suite("Client: hosts")
struct ClientHostTests {
    static let endpoint = CompanionEndpoint(
        hosts: ["a.local", "10.0.0.2", "10.0.0.3"], port: 48620, pin: Data(repeating: 7, count: 32))

    @Test("the next host follows a connection error, a TLS error, and a pin mismatch, in order")
    func fallbackOrder() async throws {
        let transport = ScriptedTransport { request, _ in
            switch request.host {
            case "a.local": return .failure(.connection)
            case "10.0.0.2": return .failure(.tls)
            default: return Support.ok(WireModelTests.inboxJSON)
            }
        }
        let client = try Support.client(transport: transport, endpoint: Self.endpoint)
        _ = try await client.inbox()
        #expect(transport.requests.map(\.host) == ["a.local", "10.0.0.2", "10.0.0.3"])
        #expect(await client.lastGoodHost == "10.0.0.3")

        let mismatch = ScriptedTransport { request, _ in
            request.host == "a.local" ? .failure(.pinMismatch) : Support.ok(WireModelTests.inboxJSON)
        }
        let second = try Support.client(transport: mismatch, endpoint: Self.endpoint)
        _ = try await second.inbox()
        #expect(mismatch.requests.map(\.host) == ["a.local", "10.0.0.2"])
        #expect(await second.lastGoodHost == "10.0.0.2")
    }

    @Test("the last good host goes first, and the others follow in order")
    func lastGoodFirst() async throws {
        let transport = ScriptedTransport { request, _ in
            request.host == "10.0.0.3" ? Support.ok(WireModelTests.inboxJSON) : .failure(.connection)
        }
        let client = try Support.client(transport: transport, endpoint: Self.endpoint)
        _ = try await client.inbox()
        _ = try await client.inbox()
        #expect(transport.requests.map(\.host) == ["a.local", "10.0.0.2", "10.0.0.3", "10.0.0.3"])
    }

    @Test("when the last good host stops answering, the others are tried in the order of the link")
    func lastGoodFails() async throws {
        let transport = ScriptedTransport { request, _ in
            request.host == "10.0.0.2" ? Support.ok(WireModelTests.inboxJSON) : .failure(.connection)
        }
        let client = try Support.client(transport: transport, endpoint: Self.endpoint, lastGoodHost: "10.0.0.3")
        _ = try await client.inbox()
        #expect(transport.requests.map(\.host) == ["10.0.0.3", "a.local", "10.0.0.2"])
        #expect(await client.lastGoodHost == "10.0.0.2")
    }

    @Test("a last good host that is not in the link is ignored")
    func unknownLastGood() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(WireModelTests.inboxJSON) }
        let client = try Support.client(transport: transport, endpoint: Self.endpoint, lastGoodHost: "evil.example")
        _ = try await client.inbox()
        #expect(transport.requests.map(\.host) == ["a.local"])
    }

    @Test("an answer with an error status does not move to the next host")
    func errorStatusStays() async throws {
        let transport = ScriptedTransport { _, _ in Support.error(401, "unauthorized") }
        let client = try Support.client(transport: transport, endpoint: Self.endpoint)
        await #expect(throws: CompanionError.self) { try await client.inbox() }
        #expect(transport.requests.count == 1)
        #expect(await client.lastGoodHost == "a.local")
    }

    @Test("each host gets a request signed for it, with its own nonce")
    func signedAgainPerHost() async throws {
        let transport = ScriptedTransport { request, _ in
            request.host == "10.0.0.3" ? Support.ok(WireModelTests.inboxJSON) : .failure(.connection)
        }
        let client = try Support.client(transport: transport, endpoint: Self.endpoint)
        _ = try await client.inbox()
        let nonces = Set(transport.requests.compactMap { $0.headers["X-Apassy-Nonce"] })
        #expect(nonces.count == 3)
        for request in transport.requests { Support.verifySigned(request, publicKey: Vectors.requestPublicKey) }
    }

    @Test("every host with a pin mismatch gives pinMismatchOnAllHosts")
    func allPinMismatch() async throws {
        let transport = ScriptedTransport { _, _ in .failure(.pinMismatch) }
        let client = try Support.client(transport: transport, endpoint: Self.endpoint)
        await #expect(throws: CompanionError.pinMismatchOnAllHosts) { try await client.inbox() }
        #expect(transport.requests.count == 3)
        #expect(await client.lastGoodHost == nil)
    }

    @Test("a pin mismatch on one host and no connection on another gives notReachable")
    func mixedFailure() async throws {
        let transport = ScriptedTransport { request, _ in
            request.host == "a.local" ? .failure(.connection) : .failure(.pinMismatch)
        }
        let client = try Support.client(transport: transport, endpoint: Self.endpoint)
        await #expect(throws: CompanionError.notReachable) { try await client.inbox() }
    }

    @Test("no connection at all gives notReachable, and a local network refusal gives localNetworkDenied")
    func notReachableAndDenied() async throws {
        let down = ScriptedTransport { _, _ in .failure(.connection) }
        await #expect(throws: CompanionError.notReachable) {
            try await Support.client(transport: down, endpoint: Self.endpoint).inbox()
        }
        let denied = ScriptedTransport { _, _ in .failure(.localNetworkDenied) }
        await #expect(throws: CompanionError.localNetworkDenied) {
            try await Support.client(transport: denied, endpoint: Self.endpoint).inbox()
        }
    }

    @Test("a cancelled task stops the loop and throws a cancellation")
    func cancelled() async throws {
        let transport = ScriptedTransport { _, _ in .failure(.cancelled) }
        let client = try Support.client(transport: transport, endpoint: Self.endpoint)
        await #expect(throws: CancellationError.self) { try await client.inbox() }
        #expect(transport.requests.count == 1)
    }

    @Test("a client made from a record starts with its last good host")
    func fromRecord() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(WireModelTests.inboxJSON) }
        let record = PairingRecord(
            deviceID: Vectors.deviceID, macName: "Mac", hosts: Self.endpoint.hosts, port: 48620,
            pin: Self.endpoint.pin, pairedAt: 1, lastGoodHost: "10.0.0.2")
        let client = CompanionClient(record: record, keys: try Vectors.makeKeys(), transport: transport, now: TestClock().source)
        _ = try await client.inbox()
        #expect(transport.requests.map(\.host) == ["10.0.0.2"])
        let saved = await client.pairingRecord(macName: "Mac")
        #expect(saved.lastGoodHost == "10.0.0.2")
        #expect(saved.deviceID == Vectors.deviceID)
        #expect(saved.endpoint == record.endpoint)
        #expect(saved.pairedAt == Vectors.time)
    }
}
