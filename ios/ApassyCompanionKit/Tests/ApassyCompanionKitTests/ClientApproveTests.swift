import Foundation
import Synchronization
import Testing

@testable import ApassyCompanionKit

@Suite("Client: approval")
struct ClientApproveTests {
    static let oneHost = CompanionEndpoint(hosts: ["mac.local"], port: 48620, pin: Data(repeating: 7, count: 32))

    static func body(_ request: TransportRequest) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: request.body) as? [String: Any])
    }

    @Test("an approval signs the contract approval string, with the reason for the agent of the run")
    func approve() async throws {
        let keys = try RecordingKeys()
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"outcome":"approved"}"#) }
        let client = try Support.client(transport: transport, keys: keys)
        let outcome = try await client.approve(run: Support.run(), remember: false)
        #expect(outcome == .approved)

        // The run, the digest, and the time are those of the vector, so the string is the contract one.
        #expect(keys.approvalMessages == [Vectors.approvalString])
        #expect(keys.approvalReasons == ["approve a run of agent \"claude-code\""])

        let request = try #require(transport.requests.first)
        #expect(transport.requests.count == 1)
        #expect(request.method == "POST")
        #expect(request.path == "/v1/runs/123456789012345/approve")
        Support.verifySigned(request, publicKey: Vectors.requestPublicKey)

        let object = try Self.body(request)
        #expect(Set(object.keys) == ["digest", "remember", "time", "approval_signature"])
        #expect(object["digest"] as? String == Vectors.approvalDigest)
        #expect(object["remember"] as? Bool == false)
        #expect(object["time"] as? Int == 1_790_000_000)
        let signature = try Support.field(object["approval_signature"] as? String)
        #expect(Vectors.verifies(signature: signature, of: Vectors.approvalString, publicKey: Vectors.approvalPublicKey))
        // The approval signature is by the approval key, not the request key.
        #expect(!Vectors.verifies(signature: signature, of: Vectors.approvalString, publicKey: Vectors.requestPublicKey))
    }

    @Test("approve and remember signs the other action and reports the other outcome")
    func approveAndRemember() async throws {
        let keys = try RecordingKeys()
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"outcome":"approved_and_remembered"}"#) }
        let client = try Support.client(transport: transport, keys: keys)
        let outcome = try await client.approve(run: Support.run(), remember: true)
        #expect(outcome == .approvedAndRemembered)
        let message = try #require(keys.approvalMessages.first)
        #expect(message.split(separator: "\n")[2] == "approve_and_remember")
        let object = try Self.body(try #require(transport.requests.first))
        #expect(object["remember"] as? Bool == true)
        let signature = try Support.field(object["approval_signature"] as? String)
        #expect(Vectors.verifies(signature: signature, of: message, publicKey: Vectors.approvalPublicKey))
        #expect(!Vectors.verifies(signature: signature, of: Vectors.approvalString, publicKey: Vectors.approvalPublicKey))
    }

    @Test("the reason cleans the agent name as the Mac does")
    func reasonCleaning() async throws {
        let keys = try RecordingKeys()
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"outcome":"approved"}"#) }
        let client = try Support.client(transport: transport, keys: keys)
        var run = Support.run()
        run = PendingRun(
            id: run.id, agent: "ev\"il\nagent" + String(repeating: "z", count: 60), command: run.command, cwd: run.cwd,
            envNames: run.envNames, purpose: run.purpose, risk: run.risk, userRequest: run.userRequest,
            requestSource: run.requestSource, agentRequest: run.agentRequest, remember: run.remember,
            digest: run.digest, waitingSeconds: nil)
        _ = try await client.approve(run: run, remember: false)
        let reason = try #require(keys.approvalReasons.first)
        #expect(reason == "approve a run of agent \"\(ApprovalPrompt.shortName(run.agent))\"")
        let name = reason.dropFirst("approve a run of agent \"".count).dropLast()
        #expect(!name.contains("\""))
        #expect(!name.contains("\n"))
        #expect(reason.count <= "approve a run of agent \"\"".count + 40)
    }

    @Test("remember without an offer is refused before Face ID")
    func noOffer() async throws {
        let keys = try RecordingKeys()
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"outcome":"approved"}"#) }
        let client = try Support.client(transport: transport, keys: keys)
        await #expect(throws: CompanionError.self) { try await client.approve(run: Support.run(remember: false), remember: true) }
        #expect(keys.approvalMessages.isEmpty)
        #expect(transport.requests.isEmpty)
    }

    @Test("a digest that is not 64 hex characters is refused before Face ID")
    func badDigest() async throws {
        let keys = try RecordingKeys()
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"outcome":"approved"}"#) }
        let client = try Support.client(transport: transport, keys: keys)
        let run = Support.run()
        for digest in ["", "ab", String(repeating: "AB", count: 32), String(repeating: "g", count: 64), run.digest + "\n"] {
            let bad = PendingRun(
                id: run.id, agent: run.agent, command: run.command, cwd: run.cwd, envNames: run.envNames,
                purpose: run.purpose, risk: run.risk, userRequest: run.userRequest, requestSource: run.requestSource,
                agentRequest: run.agentRequest, remember: run.remember, digest: digest, waitingSeconds: nil)
            await #expect(throws: CompanionError.self) { try await client.approve(run: bad, remember: false) }
        }
        #expect(keys.approvalMessages.isEmpty)
        #expect(transport.requests.isEmpty)
    }

    @Test("a cancelled Face ID sends nothing")
    func cancelled() async throws {
        let transport = ScriptedTransport { _, _ in Support.ok(#"{"outcome":"approved"}"#) }
        let client = try Support.client(transport: transport, keys: RefusingKeys())
        await #expect(throws: CompanionKeyError.cancelled) { try await client.approve(run: Support.run(), remember: false) }
        #expect(transport.requests.isEmpty)
    }

    @Test("a network error is followed by one retry with the same approval signature and a new nonce")
    func retryAfterNetworkError() async throws {
        let keys = try RecordingKeys()
        let clock = TestClock()
        let transport = ScriptedTransport { _, index in
            if index == 0 {
                clock.advance(10)
                return .failure(.connection)
            }
            return Support.ok(#"{"outcome":"approved"}"#)
        }
        let client = try Support.client(transport: transport, keys: keys, endpoint: Self.oneHost, clock: clock)
        #expect(try await client.approve(run: Support.run(), remember: false) == .approved)
        #expect(transport.requests.count == 2)
        // The owner saw one Face ID prompt.
        #expect(keys.approvalMessages.count == 1)
        let first = try #require(transport.requests.first)
        let second = try #require(transport.requests.last)
        #expect(first.body == second.body)
        #expect(first.headers["X-Apassy-Nonce"] != second.headers["X-Apassy-Nonce"])
        #expect(first.headers["X-Apassy-Time"] == "1790000000")
        #expect(second.headers["X-Apassy-Time"] == "1790000010")
        Support.verifySigned(first, publicKey: Vectors.requestPublicKey)
        Support.verifySigned(second, publicKey: Vectors.requestPublicKey)
    }

    @Test("a 423 and a 500 are each followed by one retry", arguments: [(423, "vault_locked"), (500, "internal")])
    func retryAfterServerError(status: Int, code: String) async throws {
        let keys = try RecordingKeys()
        let transport = ScriptedTransport { _, index in
            index == 0 ? Support.error(status, code) : Support.ok(#"{"outcome":"approved"}"#)
        }
        let client = try Support.client(transport: transport, keys: keys, endpoint: Self.oneHost)
        #expect(try await client.approve(run: Support.run(), remember: false) == .approved)
        #expect(transport.requests.count == 2)
        #expect(keys.approvalMessages.count == 1)
        #expect(transport.requests[0].body == transport.requests[1].body)
    }

    @Test("there is only one retry")
    func onlyOneRetry() async throws {
        let transport = ScriptedTransport { _, _ in Support.error(423, "vault_locked", "The vault is locked.") }
        let client = try Support.client(transport: transport, endpoint: Self.oneHost)
        await #expect(throws: CompanionError.server(status: 423, code: "vault_locked", message: "The vault is locked.")) {
            try await client.approve(run: Support.run(), remember: false)
        }
        #expect(transport.requests.count == 2)

        // A first attempt after a network error may have reached the Mac, so two failures without
        // an answer do not say that nothing happened.
        let down = ScriptedTransport { _, _ in .failure(.connection) }
        await #expect(throws: CompanionError.approvalUnconfirmed) {
            try await Support.client(transport: down, endpoint: Self.oneHost).approve(run: Support.run(), remember: false)
        }
        #expect(down.requests.count == 2)

        let broken = ScriptedTransport { _, _ in Support.error(500, "internal") }
        await #expect(throws: CompanionError.approvalUnconfirmed) {
            try await Support.client(transport: broken, endpoint: Self.oneHost).approve(run: Support.run(), remember: false)
        }
        #expect(broken.requests.count == 2)
    }

    @Test("after a 423 the first attempt did not arrive, so a second failure keeps its own error")
    func lockedThenDown() async throws {
        let transport = ScriptedTransport { _, index in
            index == 0 ? Support.error(423, "vault_locked", "The vault is locked.") : .failure(.connection)
        }
        await #expect(throws: CompanionError.notReachable) {
            try await Support.client(transport: transport, endpoint: Self.oneHost).approve(run: Support.run(), remember: false)
        }
        #expect(transport.requests.count == 2)
    }

    @Test("the text of an unconfirmed approval is the one of the contract")
    func unconfirmedText() {
        #expect(CompanionError.approvalUnconfirmed.errorDescription == "The Mac may have approved this run. Check Activity.")
    }

    @Test("other errors are not retried", arguments: [
        (403, "owner_check_failed"), (403, "stale"), (404, "not_waiting"), (409, "changed"),
        (409, "nothing_to_remember"), (401, "unauthorized"), (429, "too_many_requests"),
    ])
    func noRetry(status: Int, code: String) async throws {
        let transport = ScriptedTransport { _, _ in Support.error(status, code) }
        let client = try Support.client(transport: transport, endpoint: Self.oneHost)
        await #expect(throws: CompanionError.server(status: status, code: code, message: "Message.")) {
            try await client.approve(run: Support.run(), remember: false)
        }
        #expect(transport.requests.count == 1)
    }

    @Test("a pin mismatch and a local network refusal are not retried")
    func noRetryForTrust() async throws {
        let pin = ScriptedTransport { _, _ in .failure(.pinMismatch) }
        await #expect(throws: CompanionError.pinMismatchOnAllHosts) {
            try await Support.client(transport: pin, endpoint: Self.oneHost).approve(run: Support.run(), remember: false)
        }
        #expect(pin.requests.count == 1)
        let denied = ScriptedTransport { _, _ in .failure(.localNetworkDenied) }
        await #expect(throws: CompanionError.localNetworkDenied) {
            try await Support.client(transport: denied, endpoint: Self.oneHost).approve(run: Support.run(), remember: false)
        }
        #expect(denied.requests.count == 1)
    }

    @Test("no retry once the approval is older than the window")
    func retryWindow() async throws {
        let clock = TestClock()
        let transport = ScriptedTransport { _, _ in
            clock.advance(60)
            return .failure(.connection)
        }
        let client = try Support.client(transport: transport, endpoint: Self.oneHost, clock: clock)
        // The first attempt may have arrived, and it is too old to send again.
        await #expect(throws: CompanionError.approvalUnconfirmed) { try await client.approve(run: Support.run(), remember: false) }
        #expect(transport.requests.count == 1)

        let lateLock = TestClock()
        let locked = ScriptedTransport { _, _ in
            lateLock.advance(60)
            return Support.error(423, "vault_locked", "The vault is locked.")
        }
        let third = try Support.client(transport: locked, endpoint: Self.oneHost, clock: lateLock)
        // A 423 says that nothing was approved, so its own message stands.
        await #expect(throws: CompanionError.server(status: 423, code: "vault_locked", message: "The vault is locked.")) {
            try await third.approve(run: Support.run(), remember: false)
        }
        #expect(locked.requests.count == 1)

        let quick = TestClock()
        let inTime = ScriptedTransport { _, index in
            quick.advance(20)
            return index == 0 ? .failure(.connection) : Support.ok(#"{"outcome":"approved"}"#)
        }
        let second = try Support.client(transport: inTime, endpoint: Self.oneHost, clock: quick)
        #expect(try await second.approve(run: Support.run(), remember: false) == .approved)
        #expect(inTime.requests.count == 2)
    }

    @Test("the window is 55 s from the time of the approval, and a slow Face ID uses part of it")
    func windowBoundary() async throws {
        // The first attempt ends 54 s after the time in the approval: a retry is allowed.
        let justInside = TestClock()
        let inside = ScriptedTransport { _, index in
            if index == 0 { justInside.advance(54) }
            return index == 0 ? .failure(.connection) : Support.ok(#"{"outcome":"approved"}"#)
        }
        let a = try Support.client(transport: inside, endpoint: Self.oneHost, clock: justInside)
        #expect(try await a.approve(run: Support.run(), remember: false) == .approved)
        #expect(inside.requests.count == 2)

        // At 55 s it is not.
        let atEdge = TestClock()
        let edge = ScriptedTransport { _, _ in
            atEdge.advance(55)
            return .failure(.connection)
        }
        let b = try Support.client(transport: edge, endpoint: Self.oneHost, clock: atEdge)
        await #expect(throws: CompanionError.approvalUnconfirmed) { try await b.approve(run: Support.run(), remember: false) }
        #expect(edge.requests.count == 1)

        // The time is fixed before the prompt: a Face ID of 50 s leaves 5 s, so a first attempt that
        // takes 5 s is the last one.
        let slow = TestClock()
        let keys = SlowKeys(clock: slow, seconds: 50)
        let late = ScriptedTransport { _, _ in
            slow.advance(5)
            return .failure(.connection)
        }
        let c = try Support.client(transport: late, keys: keys, endpoint: Self.oneHost, clock: slow)
        await #expect(throws: CompanionError.approvalUnconfirmed) { try await c.approve(run: Support.run(), remember: false) }
        #expect(late.requests.count == 1)
        // The request went out with the time from before the prompt.
        let object = try Self.body(try #require(late.requests.first))
        #expect(object["time"] as? Int == 1_790_000_000)
    }

    @Test("a retry that finds no waiting run after a network error or a 500 is unconfirmed, not a denial")
    func unconfirmed() async throws {
        let afterNetwork = ScriptedTransport { _, index in
            index == 0 ? .failure(.connection) : Support.error(404, "not_waiting", "The run no longer waits. Nothing was approved.")
        }
        await #expect(throws: CompanionError.approvalUnconfirmed) {
            try await Support.client(transport: afterNetwork, endpoint: Self.oneHost).approve(run: Support.run(), remember: false)
        }
        let afterServer = ScriptedTransport { _, index in
            index == 0 ? Support.error(500, "internal") : Support.error(404, "not_waiting")
        }
        await #expect(throws: CompanionError.approvalUnconfirmed) {
            try await Support.client(transport: afterServer, endpoint: Self.oneHost).approve(run: Support.run(), remember: false)
        }
        // After a 423 nothing was approved, so the server message stands.
        let afterLocked = ScriptedTransport { _, index in
            index == 0 ? Support.error(423, "vault_locked") : Support.error(404, "not_waiting")
        }
        await #expect(throws: CompanionError.server(status: 404, code: "not_waiting", message: "Message.")) {
            try await Support.client(transport: afterLocked, endpoint: Self.oneHost).approve(run: Support.run(), remember: false)
        }
    }
}
