import ApassyCompanionKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("PairingModel")
struct PairingModelTests {
    @MainActor
    final class Fixture {
        let mac: ScriptedPairingMac
        let store = InMemoryPairingStore()
        var paired: [PairingRecord] = []
        var model: PairingModel!

        init(polls: [ScriptedPairingMac.Poll], deviceName: String = "Test iPhone", notice: String? = nil) {
            mac = ScriptedPairingMac(polls: polls)
            model = PairingModel(
                store: store, notice: notice, deviceName: deviceName, pollInterval: .milliseconds(20),
                makeKeys: { SoftwareKeys() },
                makeClient: { [mac] link, keys in
                    CompanionClient(link: link, deviceID: DeviceID.random(), keys: keys, transport: mac)
                },
                onPaired: { [unowned self] record, _ in paired.append(record) })
        }

        /// Scan a good link and wait for the code screen.
        func scanToCode() async -> Bool {
            model.startScanning()
            model.handleScan(pairingLinkText(expiresIn: 300))
            return await waitUntil {
                if case .code = model.step { return true }
                return false
            }
        }
    }

    @Test("a name with no character or 41 characters blocks the scan")
    func nameRules() {
        let empty = Fixture(polls: [], deviceName: "   ")
        empty.model.startScanning()
        #expect(empty.model.step == .welcome)
        #expect(empty.model.deviceNameProblem != nil)
        let long = Fixture(polls: [], deviceName: String(repeating: "x", count: 41))
        #expect(long.model.deviceNameProblem != nil)
        let edge = Fixture(polls: [], deviceName: String(repeating: "x", count: 40))
        #expect(edge.model.deviceNameProblem == nil)
    }

    @Test("a name is sent without the spaces around it")
    func trimmedName() {
        let f = Fixture(polls: [], deviceName: "  Test iPhone \n")
        #expect(f.model.trimmedDeviceName == "Test iPhone")
        #expect(f.model.deviceNameProblem == nil)
    }

    @Test("scanning clears the notice, and a code that is no pairing link only sets a note")
    func scanNotes() async {
        let f = Fixture(polls: [], notice: "This iPhone is no longer paired with the Mac. Pair it again.")
        #expect(f.model.notice != nil)
        f.model.startScanning()
        #expect(f.model.notice == nil)
        #expect(f.model.step == .scan)
        f.model.handleScan("https://example.test/not-a-link")
        #expect(f.model.step == .scan)
        #expect(f.model.scanNote != nil)
        f.model.handleScan(pairingLinkText(expiresIn: -10))
        #expect(f.model.step == .scan)
        #expect(f.model.scanNote == PairingLinkError.expired.errorDescription)
        #expect(f.mac.requests.isEmpty)
    }

    @Test("a good link shows the code, the Mac says paired, and Continue hands over the record")
    func happyPath() async throws {
        let f = Fixture(polls: [.waiting, .paired])
        #expect(await f.scanToCode())
        guard case .code(let macName, let code, _) = f.model.step else { return }
        #expect(macName == "Mac mini")
        #expect(code.count == 7 && code[code.index(code.startIndex, offsetBy: 3)] == " ")
        #expect(await waitUntil { f.model.step == .paired(macName: "Mac mini") })
        let saved = try #require(try f.store.load())
        #expect(saved.macName == "Mac mini")
        #expect(saved.hosts == ["Mac-mini.local"])
        #expect(saved.port == 48620)
        #expect(saved.pin == Data(repeating: 0x11, count: 32))
        #expect(DeviceID.isValid(saved.deviceID))
        #expect(f.paired.isEmpty)
        f.model.finish()
        #expect(f.paired == [saved])
        f.model.finish()
        #expect(f.paired.count == 1)
        let requests = f.mac.requests
        #expect(requests.first == "POST /v1/pair")
        #expect(requests.dropFirst().allSatisfy { $0 == "GET /v1/pair/\(saved.deviceID)" })
    }

    @Test("the Mac closing the pairing ends with nothing stored, and start again scans")
    func denied() async {
        let f = Fixture(polls: [.denied])
        f.model.startScanning()
        f.model.handleScan(pairingLinkText(expiresIn: 300))
        #expect(await waitUntil { f.model.step == .denied })
        #expect((try? f.store.load()) == nil)
        f.model.startAgain()
        #expect(f.model.step == .scan)
    }

    @Test("an expired window ends with nothing stored")
    func expired() async {
        let f = Fixture(polls: [.expired])
        f.model.startScanning()
        f.model.handleScan(pairingLinkText(expiresIn: 300))
        #expect(await waitUntil { f.model.step == .expired })
        #expect((try? f.store.load()) == nil)
    }

    @Test("a dropped connection sets a note and polling goes on until the Mac answers")
    func dropped() async {
        let f = Fixture(polls: [.dropped, .waiting, .paired])
        #expect(await f.scanToCode())
        #expect(await waitUntil { f.model.waitNote != nil })
        #expect(await waitUntil { f.model.step == .paired(macName: "Mac mini") })
        #expect(f.model.waitNote == nil)
    }

    @Test("cancelling on the code screen stops the polling")
    func cancel() async {
        let f = Fixture(polls: [])
        #expect(await f.scanToCode())
        f.model.backToWelcome()
        #expect(f.model.step == .welcome)
        try? await Task.sleep(for: .milliseconds(60))
        let count = f.mac.requests.count
        try? await Task.sleep(for: .milliseconds(200))
        #expect(f.mac.requests.count == count)
    }

    @Test("a device without a Secure Enclave fails with the message, before any request")
    func noSecureEnclave() async {
        let mac = ScriptedPairingMac(polls: [])
        let model = PairingModel(
            store: InMemoryPairingStore(), notice: nil, deviceName: "Test iPhone",
            makeKeys: { throw CompanionKeyError.noSecureEnclave },
            makeClient: { link, keys in
                CompanionClient(link: link, deviceID: DeviceID.random(), keys: keys, transport: mac)
            },
            onPaired: { _, _ in })
        model.startScanning()
        model.handleScan(pairingLinkText(expiresIn: 300))
        #expect(
            await waitUntil {
                if case .failed = model.step { return true }
                return false
            })
        #expect(
            model.step
                == .failed(
                    title: "This iPhone cannot pair", message: CompanionKeyError.noSecureEnclave.errorDescription ?? ""))
        #expect(mac.requests.isEmpty)
    }

    @Test("a name counts scalars, and every White_Space scalar around it is trimmed")
    func nameScalars() {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}"
        // Eight families are 8 characters and 40 scalars.
        #expect(Fixture(polls: [], deviceName: String(repeating: family, count: 8)).model.deviceNameProblem == nil)
        // Nine are 9 characters and 45 scalars.
        #expect(Fixture(polls: [], deviceName: String(repeating: family, count: 9)).model.deviceNameProblem != nil)
        #expect(Fixture(polls: [], deviceName: String(repeating: "\u{1F600}", count: 40)).model.deviceNameProblem == nil)
        #expect(Fixture(polls: [], deviceName: String(repeating: "\u{1F600}", count: 41)).model.deviceNameProblem != nil)
        // A control character inside the name is refused, a Cf scalar is not.
        #expect(Fixture(polls: [], deviceName: "Test\u{7}iPhone").model.deviceNameProblem != nil)
        #expect(Fixture(polls: [], deviceName: "Test\u{200B}iPhone").model.deviceNameProblem == nil)
        // The no-break space and the ideographic space are trimmed, as the Mac counts them as spaces.
        let padded = Fixture(polls: [], deviceName: "\u{00A0}\u{3000}Test iPhone\u{2003}")
        #expect(padded.model.trimmedDeviceName == "Test iPhone")
        #expect(padded.model.deviceNameProblem == nil)
    }

    @Test("a cancel that lands after the Mac answered shows no code and starts no polling")
    func cancelAfterAnswer() async {
        let box = ModelBox()
        let mac = ScriptedPairingMac(polls: [.paired]) {
            await MainActor.run { box.model?.backToWelcome() }
        }
        let store = InMemoryPairingStore()
        let model = PairingModel(
            store: store, notice: nil, deviceName: "Test iPhone", pollInterval: .milliseconds(20),
            makeKeys: { SoftwareKeys() },
            makeClient: { link, keys in CompanionClient(link: link, deviceID: DeviceID.random(), keys: keys, transport: mac) },
            onPaired: { _, _ in })
        box.model = model
        model.startScanning()
        model.handleScan(pairingLinkText(expiresIn: 300))
        #expect(await waitUntil { mac.requests.count == 1 })
        try? await Task.sleep(for: .milliseconds(300))
        #expect(model.step == .welcome)
        #expect(mac.requests == ["POST /v1/pair"])
        #expect((try? store.load()) == nil)
    }

    @Test("a cancelled Face ID while pairing says that nothing is paired, not that nothing was approved")
    func cancelledFaceID() async {
        let mac = ScriptedPairingMac(polls: [])
        let model = PairingModel(
            store: InMemoryPairingStore(), notice: nil, deviceName: "Test iPhone",
            makeKeys: { FailingApprovalKeys(error: .cancelled) },
            makeClient: { link, keys in CompanionClient(link: link, deviceID: DeviceID.random(), keys: keys, transport: mac) },
            onPaired: { _, _ in })
        model.startScanning()
        model.handleScan(pairingLinkText(expiresIn: 300))
        #expect(
            await waitUntil {
                if case .failed = model.step { return true }
                return false
            })
        guard case .failed(let title, let message) = model.step else { return }
        #expect(title == "Could not pair")
        #expect(message == "The Face ID check was cancelled. Nothing is paired.")
        #expect(!message.contains("approved"))
        // The prompt came before any request.
        #expect(mac.requests.isEmpty)
    }

    @Test("every key error of the pairing avoids the word approved", arguments: [
        CompanionKeyError.cancelled, .authenticationFailed, .biometryUnavailable, .lockedOut, .failed(code: -1),
    ])
    func pairingMessages(error: CompanionKeyError) {
        let message = PairingModel.message(for: error)
        #expect(!message.contains("approved"))
        #expect(message.contains("Nothing is paired"))
        // Other errors keep their own text.
        #expect(PairingModel.message(for: CompanionKeyError.noSecureEnclave) == CompanionKeyError.noSecureEnclave.errorDescription)
        #expect(PairingModel.message(for: CompanionError.notReachable) == CompanionError.notReachable.errorDescription)
    }

    @Test("a refused link has its own title, so the title does not repeat the message")
    func linkRefused() async {
        let mac = RefusingPairTransport()
        let model = PairingModel(
            store: InMemoryPairingStore(), notice: nil, deviceName: "Test iPhone",
            makeKeys: { SoftwareKeys() },
            makeClient: { link, keys in CompanionClient(link: link, deviceID: DeviceID.random(), keys: keys, transport: mac) },
            onPaired: { _, _ in })
        model.startScanning()
        model.handleScan(pairingLinkText(expiresIn: 300))
        #expect(
            await waitUntil {
                if case .failed = model.step { return true }
                return false
            })
        guard case .failed(let title, let message) = model.step else { return }
        #expect(title == "The Mac refused the link")
        #expect(message == CompanionError.linkRejected.errorDescription)
        #expect(!message.hasPrefix(title))
    }
}

/// A Mac that answers the pair request with 401, as for a used link.
struct RefusingPairTransport: CompanionTransport {
    func send(_ request: TransportRequest) async throws(TransportFailure) -> TransportResponse {
        TransportResponse(status: 401, body: Data(#"{"error":{"code":"unauthorized","message":"No."}}"#.utf8))
    }
}
