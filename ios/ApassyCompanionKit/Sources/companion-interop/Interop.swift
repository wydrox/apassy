// The driver of the interop check (scripts/companion-interop.sh).
//
// It is the phone side of one full session with the development server of the Mac
// (`examples/companion_dev.rs`), over the real wire: TLS with the pin check, the signed
// requests, the Face ID approval strings (software keys here), and the pairing. It uses the
// real `CompanionClient` and `PinnedURLSessionTransport`, and mocks nothing. The keys are
// software keys in memory, the pairing store is in memory, and every value is synthetic.
//
//     companion-interop <pairing link>
//
// It prints `CODE <6 digits>` for the harness to send to the server, and one `OK <step>` line
// per passed step. On the first failure it prints `FAIL <step>: <reason>` and exits with 1.

import ApassyCompanionKit
import Foundation

/// A step failed.
struct StepFailure: Error {
    let reason: String
}

/// Write one line to stdout at once, so that a harness that reads a pipe sees it now.
func say(_ line: String) {
    FileHandle.standardOutput.write(Data((line + "\n").utf8))
}

/// Run one step. It prints `OK <step>` (with `detail` when there is one), or `FAIL <step>` and
/// ends the program.
func step(_ name: String, _ body: () async throws -> String?) async {
    do {
        let detail = try await body()
        say(detail.map { "OK \(name) \($0)" } ?? "OK \(name)")
    } catch let failure as StepFailure {
        fail(name, failure.reason)
    } catch {
        fail(name, error.localizedDescription)
    }
}

func fail(_ name: String, _ reason: String) -> Never {
    let one = reason.map { $0.isNewline ? " " : $0 }
    say("FAIL \(name): \(String(one))")
    exit(1)
}

func expect(_ condition: Bool, _ reason: @autoclosure () -> String) throws {
    if !condition { throw StepFailure(reason: reason()) }
}

/// Call `body` every 100 ms until it gives a value, for at most `seconds`.
func wait<T>(seconds: Double, _ what: String, _ body: () async throws -> T?) async throws -> T {
    let end = Date().addingTimeInterval(seconds)
    while Date() < end {
        if let value = try await body() { return value }
        try await Task.sleep(for: .milliseconds(100))
    }
    throw StepFailure(reason: "gave up waiting for \(what) after \(Int(seconds)) s")
}

/// A request built by hand: the same headers as the client, with the signature that the caller
/// gives.
func handmadeRequest(
    link: PairingLink, deviceID: String, method: String, path: String,
    sign: (Data) throws -> Data
) throws -> TransportRequest {
    let time = Int64(Date().timeIntervalSince1970.rounded(.down))
    let nonce = B64U.encode(RandomBytes.make(16))
    let string = try SigningStrings.request(
        method: method, path: path, deviceID: deviceID, time: time, nonce: nonce, body: Data())
    let signature = try sign(Data(string.utf8))
    return TransportRequest(
        host: link.hosts[0], port: link.port, method: method, path: path,
        headers: [
            "X-Apassy-Device": deviceID,
            "X-Apassy-Time": String(time),
            "X-Apassy-Nonce": nonce,
            "X-Apassy-Signature": B64U.encode(signature),
        ],
        body: Data())
}

/// The code of the error body of the contract, or nil.
func errorCode(_ response: TransportResponse) -> String? {
    guard let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
        let error = object["error"] as? [String: Any]
    else { return nil }
    return error["code"] as? String
}

@main
enum Interop {
    static func main() async {
        let arguments = CommandLine.arguments
        guard arguments.count == 2 else {
            say("FAIL usage: companion-interop <pairing link>")
            exit(2)
        }
        await run(linkText: arguments[1])
    }

    static func run(linkText: String) async {
        let deviceName = "Interop iPhone"
        let keys = SoftwareKeys()
        let deviceID = DeviceID.random()
        let store = InMemoryPairingStore()
        var link: PairingLink!
        var client: CompanionClient!

        await step("link") {
            link = try PairingLink.parse(linkText)
            try expect(link.hosts == ["127.0.0.1"], "the link has the hosts \(link.hosts)")
            return "host=\(link.hosts[0]) port=\(link.port)"
        }

        await step("pair") {
            client = CompanionClient(link: link, deviceID: deviceID, keys: keys)
            let start = try await client.pair(link: link, deviceName: deviceName)
            let digits = PairingCode.digits(
                secret: link.secret, requestKey: keys.requestPublicKey, approvalKey: keys.approvalPublicKey)
            try expect(digits.count == 6 && digits.allSatisfy(\.isNumber), "the code is not 6 digits: \(digits)")
            try expect(
                start.code.replacingOccurrences(of: " ", with: "") == digits,
                "the code shown, \(start.code), is not the code computed, \(digits)")
            // The harness sends this line to the server, as the owner types the code on the Mac.
            say("CODE \(digits)")
            return nil
        }

        await step("pair-status") {
            let macName = try await wait(seconds: 30, "the Mac to say paired") { () -> String? in
                switch try await client.pairStatus() {
                case .waiting: return nil
                case .paired(let macName): return macName
                case .denied: throw StepFailure(reason: "the Mac denied the pairing")
                case .expired: throw StepFailure(reason: "the pairing window expired")
                }
            }
            try expect(macName == "Dev Mac", "the Mac name is \(macName)")
            try store.save(await client.pairingRecord(macName: macName))
            // From here on the client comes from the saved record, as after a restart of the app.
            guard let record = try store.load() else { throw StepFailure(reason: "the record was not saved") }
            try expect(record.hosts == link.hosts && record.pin == link.pin, "the record differs from the link")
            client = CompanionClient(record: record, keys: keys)
            return "mac=\(macName)"
        }

        await step("status") {
            let status = try await client.status()
            try expect(status.v == 1, "the status has v=\(status.v)")
            try expect(status.macName == "Dev Mac", "the Mac name is \(status.macName)")
            try expect(!status.appVersion.isEmpty, "the app version is empty")
            try expect(status.approvalTimeoutSeconds > 0, "the approval timeout is \(status.approvalTimeoutSeconds)")
            try expect(status.device.id == deviceID, "the Mac knows this device as \(status.device.id)")
            try expect(status.device.name == deviceName, "the Mac knows this device as \(status.device.name)")
            return nil
        }

        var runs: [PendingRun] = []
        var accessRequest: AccessRequest!
        await step("inbox") {
            let inbox = try await wait(seconds: 15, "3 runs and 1 access request") { () -> Inbox? in
                let inbox = try await client.inbox()
                return inbox.runs.count >= 3 && !inbox.accessRequests.isEmpty ? inbox : nil
            }
            try expect(inbox.runs.count == 3, "the inbox has \(inbox.runs.count) runs, not 3")
            try expect(inbox.accessRequests.count == 1, "the inbox has \(inbox.accessRequests.count) access requests")
            runs = inbox.runs
            accessRequest = inbox.accessRequests[0]
            // Oldest first: a run with an offer to remember, a run without, a run to deny.
            let offer = try unwrap(runs[0].remember, "the first run has no offer to remember")
            try expect(
                offer.pattern == "npm run migrate" && offer.approvals == 1 && offer.needed == 3,
                "the offer is \(offer)")
            try expect(runs[1].remember == nil && runs[2].remember == nil, "the runs 2 and 3 have an offer")
            try expect(runs[0].command == ["npm", "run", "migrate"], "the first command is \(runs[0].command)")
            try expect(runs[1].command == ["cargo", "test"], "the second command is \(runs[1].command)")
            try expect(runs[2].command == ["rm", "-rf", "build"], "the third command is \(runs[2].command)")
            for run in runs {
                try expect(run.agent == "Synthetic agent", "the agent is \(run.agent)")
                try expect(run.cwd == "/tmp/synthetic-shop", "the cwd is \(String(describing: run.cwd))")
                try expect(run.envNames == ["SYNTHETIC_API_KEY"], "the env names are \(run.envNames)")
                try expect(run.digest.utf8.count == 64 && Hex.decode(run.digest) != nil, "the digest is not 64 hex")
                try expect(run.agentRequest.isEmpty, "the agent request is \(run.agentRequest)")
                try expect(run.userRequest == "Run the synthetic task.", "the user request is \(run.userRequest)")
                try expect(
                    run.requestSource == "from the host hook", "the request source is \(run.requestSource)")
            }
            try expect(Set(runs.map(\.id)).count == 3, "the run IDs are not distinct")
            try expect(accessRequest.agent == "Synthetic agent", "the agent is \(accessRequest.agent)")
            try expect(accessRequest.itemName == "Synthetic API key", "the item is \(accessRequest.itemName)")
            try expect(
                accessRequest.reason == "The user asked me to run the synthetic task.",
                "the reason is \(accessRequest.reason)")
            try expect(accessRequest.cwd == "/tmp/synthetic-shop", "the cwd is \(String(describing: accessRequest.cwd))")
            return "runs=\(runs.map(\.id).joined(separator: ",")) access_request=\(accessRequest.id)"
        }

        await step("approve") {
            let outcome = try await client.approve(run: runs[1], remember: false)
            try expect(outcome == .approved, "the outcome is \(outcome)")
            return "run=\(runs[1].id)"
        }

        await step("approve-and-remember") {
            let outcome = try await client.approve(run: runs[0], remember: true)
            try expect(outcome == .approvedAndRemembered, "the outcome is \(outcome)")
            return "run=\(runs[0].id)"
        }

        await step("deny") {
            try await client.deny(run: runs[2])
            return "run=\(runs[2].id)"
        }

        await step("deny-access-request") {
            try await client.denyAccessRequest(id: accessRequest.id)
            return "access_request=\(accessRequest.id)"
        }

        await step("inbox-empty") {
            let inbox = try await wait(seconds: 10, "an empty inbox") { () -> Inbox? in
                let inbox = try await client.inbox()
                return inbox.runs.isEmpty && inbox.accessRequests.isEmpty ? inbox : nil
            }
            try expect(inbox.runs.isEmpty && inbox.accessRequests.isEmpty, "the inbox is not empty")
            return nil
        }

        await step("tampered-signature") {
            let transport = PinnedURLSessionTransport(pin: link.pin)
            let good = try handmadeRequest(
                link: link, deviceID: deviceID, method: "GET", path: "/v1/status", sign: keys.signRequest)
            let control = try await transport.send(good)
            try expect(control.status == 200, "the control request got \(control.status)")

            // A signature of other keys: valid DER, wrong key.
            let stranger = SoftwareKeys()
            let wrongKey = try handmadeRequest(
                link: link, deviceID: deviceID, method: "GET", path: "/v1/status", sign: stranger.signRequest)
            let first = try await transport.send(wrongKey)
            try expect(
                first.status == 401 && errorCode(first) == "unauthorized",
                "a signature of another key got \(first.status) \(errorCode(first) ?? "no code")")

            // The right key, with one bit of the signature changed.
            let flipped = try handmadeRequest(
                link: link, deviceID: deviceID, method: "GET", path: "/v1/status",
                sign: { message in
                    var signature = try keys.signRequest(message)
                    signature[signature.count - 1] ^= 0x01
                    return signature
                })
            let second = try await transport.send(flipped)
            try expect(
                second.status == 401 && errorCode(second) == "unauthorized",
                "a changed signature got \(second.status) \(errorCode(second) ?? "no code")")

            // The signature of the right request, sent with another path.
            var moved = try handmadeRequest(
                link: link, deviceID: deviceID, method: "GET", path: "/v1/status", sign: keys.signRequest)
            moved.path = "/v1/inbox"
            let third = try await transport.send(moved)
            try expect(
                third.status == 401 && errorCode(third) == "unauthorized",
                "a signature for another path got \(third.status) \(errorCode(third) ?? "no code")")
            return nil
        }

        await step("wrong-pin") {
            var wrong = link.pin
            wrong[0] ^= 0xFF
            let record = try unwrap(try store.load(), "the record is gone")
            let other = PairingRecord(
                deviceID: record.deviceID, macName: record.macName, hosts: record.hosts, port: record.port,
                pin: wrong, pairedAt: record.pairedAt)
            let stranger = CompanionClient(record: other, keys: keys)
            do {
                _ = try await stranger.status()
            } catch CompanionError.pinMismatchOnAllHosts {
                return nil
            }
            throw StepFailure(reason: "a client with a wrong pin did not fail with the pin mismatch error")
        }

        await step("unpair") {
            try await client.unpair()
            return nil
        }

        await step("unpaired-request") {
            let response = try await PinnedURLSessionTransport(pin: link.pin).send(
                handmadeRequest(
                    link: link, deviceID: deviceID, method: "GET", path: "/v1/status", sign: keys.signRequest))
            try expect(
                response.status == 401 && errorCode(response) == "unpaired",
                "a request after the unpair got \(response.status) \(errorCode(response) ?? "no code")")
            do {
                _ = try await client.status()
            } catch CompanionError.unpaired {
                return nil
            }
            throw StepFailure(reason: "the client did not throw unpaired after the unpair")
        }
    }
}

func unwrap<T>(_ value: T?, _ reason: String) throws -> T {
    guard let value else { throw StepFailure(reason: reason) }
    return value
}
