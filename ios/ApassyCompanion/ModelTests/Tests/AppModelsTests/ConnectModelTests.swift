import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("ConnectModel")
struct ConnectModelTests {
    static let code = "apassy_lnk_t_7k2m5q4x3c_" + String(repeating: "0123456789abcdef", count: 4)
    static let relay = "https://apassy-relay.example"

    /// A link of "Add a device" with these parameters.
    static func link(_ params: String = "") -> String { "\(relay)/link#\(code)\(params)" }

    @MainActor
    final class Fixture {
        let service: PreviewVaultService
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let signer = ScriptedSigner()
        let questions: QuestionsModel
        let pairingStore = InMemoryPairingStore()
        let mac = ScriptedPairingMac(polls: [.waiting])
        var pairing: PairingModel?
        var finished: [VaultEntry?] = []
        var cancelled = 0
        var model: ConnectModel!

        init(
            start: ConnectModel.Start = .scan, attaches: Bool = false, empty: Bool = true, paired: Bool = false,
            biometry: Biometry = .faceID
        ) {
            service = PreviewVaultService(empty: empty)
            questions = QuestionsModel(
                service: service, signer: signer, push: nil, deviceName: "Test iPhone",
                defaults: makeDefaults(), retryInterval: .milliseconds(10))
            if !paired {
                pairing = PairingModel(
                    store: pairingStore, notice: nil, deviceName: "Test iPhone", pollInterval: .milliseconds(20),
                    makeKeys: { SoftwareKeys() },
                    makeClient: { [mac] link, keys in
                        CompanionClient(link: link, deviceID: DeviceID.random(), keys: keys, transport: mac)
                    },
                    onPaired: { _, _ in })
            }
            model = ConnectModel(
                start: start, attachesSelectedVault: attaches, service: service, passphraseStore: store,
                settings: settings, biometry: biometry, deviceName: "Test iPhone", questions: questions,
                answerKey: { Data([4] + [UInt8](repeating: 1, count: 64)) },
                pairing: { [unowned self] in pairing.map { .ready($0) } ?? .paired }, pollInterval: .milliseconds(10),
                onFinished: { [unowned self] vault in finished.append(vault) },
                onCancel: { [unowned self] in cancelled += 1 })
        }

        var stepID: String { model.step.id }

        /// From a scanned `r=connect` code to the name step, through the iCloud file.
        func openVault() async -> VaultEntry? {
            model.handle(ConnectModelTests.link("&r=connect&n=Mac%20mini"))
            guard case .openVault = model.step else { return nil }
            model.openFile(URL(fileURLWithPath: "/tmp/Personal.apassy"))
            guard case .iCloud(let iCloud) = model.step else { return nil }
            await iCloud.open(passphrase: PreviewVaultService.passphrase)
            iCloud.turnOnFaceID()
            return model.openedVault
        }
    }

    // MARK: Routing by the code

    @Test("a paid Mac's code and an old code go to the relay join, at its name step")
    func syncRoute() {
        for text in [Self.link("&r=sync&n=Mac%20mini"), Self.link(), "  \(Self.code)\n"] {
            let fixture = Fixture()
            fixture.model.handle(text)
            guard case .join(let join) = fixture.model.step else {
                Issue.record("no join for \(text)")
                continue
            }
            #expect(join.step == .name(link: text.trimmingCharacters(in: .whitespacesAndNewlines)))
            #expect(fixture.model.note == nil)
        }
    }

    @Test("a Free Mac's code asks for the vault from iCloud Drive first")
    func connectRoute() {
        let fixture = Fixture()
        fixture.model.handle(Self.link("&r=connect&n=Mac%20mini&e=1790000600"))
        #expect(fixture.stepID == "openVault")
        #expect(fixture.model.macName == "Mac mini")
        #expect(fixture.model.link?.route == .connect)
    }

    @Test("a text that is no code, and a code of a newer Mac, only set a note")
    func notes() {
        let fixture = Fixture()
        fixture.model.handle("https://example.com")
        #expect(fixture.stepID == "scan")
        #expect(fixture.model.note?.contains("Settings > Devices > Add a device") == true)
        fixture.model.showPaste()
        fixture.model.handle(Self.link("&r=share"))
        #expect(fixture.stepID == "paste")
        #expect(fixture.model.note?.contains("newer version of Apassy") == true)
    }

    @Test("a pairing code of the local network starts the pairing")
    func pairingCode() async {
        let fixture = Fixture()
        fixture.model.handle(pairingLinkText(expiresIn: 300))
        guard case .pairing(let pairing) = fixture.model.step else {
            Issue.record("no pairing")
            return
        }
        #expect(pairing.step == .connecting(macName: "Mac mini"))
        pairing.backToWelcome()
        fixture.model.pairingLeft()
        #expect(fixture.stepID == "scan")
    }

    // MARK: Free: the vault, then the words

    @Test("Free: the iCloud file, the passphrase, Face ID, the name, the words, then connected")
    func freeFlow() async {
        let fixture = Fixture()
        let vault = await fixture.openVault()
        #expect(vault?.isICloud == true)
        // Face ID went on to the name at once, without the screen that says the vault is here.
        #expect(fixture.stepID == "name")
        #expect(fixture.store.stored(vaultID: vault?.id ?? "") == PreviewVaultService.passphrase)
        fixture.model.deviceName = "  Rafał's iPhone "
        await fixture.model.connect()
        #expect(fixture.model.step.id == "connected")
        // The words name no Mac: the name in the code shows only as "Code from …".
        if case .connected(let vaultName) = fixture.model.step { #expect(vaultName == vault?.name) }
        #expect(fixture.model.codeFrom == "Code from “Mac mini”")
        #expect(fixture.settings.deviceName == "Rafał's iPhone")
        #expect(fixture.questions.phase == .ready)
        #expect(fixture.questions.attach == nil)
        #expect(fixture.finished.isEmpty)
        fixture.model.complete()
        #expect(fixture.finished.count == 1)
        #expect(fixture.finished.first??.id == vault?.id)
    }

    @Test("Cancel while the words show keeps the vault that the flow opened")
    func cancelAtWords() async {
        let fixture = Fixture()
        _ = await fixture.openVault()
        fixture.model.deviceName = "Test iPhone"
        let connecting = Task { await fixture.model.connect() }
        #expect(await waitUntil { if case .waiting? = fixture.model.attach { return true }; return false })
        await fixture.model.cancel()
        await connecting.value
        #expect(fixture.cancelled == 0)
        #expect(fixture.finished.count == 1)
        #expect(fixture.finished.first??.isICloud == true)
        #expect(fixture.questions.attach == nil)
    }

    @Test("Cancel in the iCloud steps removes the local copy and goes back to the choice")
    func cancelInICloud() async throws {
        let fixture = Fixture()
        fixture.model.handle(Self.link("&r=connect"))
        fixture.model.openFile(URL(fileURLWithPath: "/tmp/Personal.apassy"))
        guard case .iCloud(let iCloud) = fixture.model.step else {
            Issue.record("no iCloud step")
            return
        }
        await iCloud.open(passphrase: PreviewVaultService.passphrase)
        await iCloud.cancel()
        #expect(fixture.stepID == "openVault")
        #expect(fixture.model.openedVault == nil)
        #expect(try await fixture.service.info().vaults.isEmpty)
        #expect(fixture.cancelled == 0)
    }

    @Test("without a code, the vault from iCloud Drive ends on its own screen, then the flow ends")
    func openVaultOnly() async {
        let fixture = Fixture(start: .openVault)
        #expect(fixture.stepID == "openVault")
        fixture.model.openFile(URL(fileURLWithPath: "/tmp/Personal.apassy"))
        guard case .iCloud(let iCloud) = fixture.model.step else {
            Issue.record("no iCloud step")
            return
        }
        await iCloud.open(passphrase: PreviewVaultService.passphrase)
        iCloud.notNow()
        guard case .done = iCloud.step else {
            Issue.record("the done screen did not show")
            return
        }
        iCloud.complete()
        #expect(fixture.finished.count == 1)
    }

    // MARK: Only on this Wi-Fi

    @Test("Only on this Wi-Fi pairs with the pairing link of the code")
    func wifiWithPairingLink() {
        let fixture = Fixture()
        let pairing = B64U.encode(Data(pairingLinkText(expiresIn: 300).utf8))
        fixture.model.handle(Self.link("&r=connect&n=Mac%20mini&p=\(pairing)"))
        fixture.model.onlyOnThisWiFi()
        guard case .pairing(let model) = fixture.model.step else {
            Issue.record("no pairing")
            return
        }
        #expect(model.step == .connecting(macName: "Mac mini"))
        #expect(model.deviceName == "Test iPhone")
        model.backToWelcome()
        fixture.model.pairingLeft()
        #expect(fixture.stepID == "openVault")
    }

    @Test("Only on this Wi-Fi without a pairing link says how to pair, then scans")
    func wifiWithoutPairingLink() {
        let fixture = Fixture()
        fixture.model.handle(Self.link("&r=connect"))
        fixture.model.onlyOnThisWiFi()
        #expect(fixture.stepID == "pairHelp")
        fixture.model.backToChoice()
        #expect(fixture.stepID == "openVault")
        fixture.model.onlyOnThisWiFi()
        fixture.model.scanPairingCode()
        guard case .pairing(let model) = fixture.model.step else {
            Issue.record("no pairing")
            return
        }
        #expect(model.step == .scan)
        fixture.model.pairingFinished()
        #expect(fixture.finished.count == 1)
        #expect(fixture.finished.first == .some(nil))
    }

    @Test("an iPhone that is paired already says so")
    func pairedAlready() {
        let fixture = Fixture(paired: true)
        fixture.model.handle(pairingLinkText(expiresIn: 300))
        guard case .failed(let title, _) = fixture.model.step else {
            Issue.record("no failure")
            return
        }
        #expect(title == "This iPhone is paired already")
        fixture.model.scanAgain()
        #expect(fixture.stepID == "scan")
    }

    @Test("a pairing that the keychain cannot read says why")
    func pairingUnavailable() {
        let service = PreviewVaultService(empty: true)
        var finished = 0
        let model = ConnectModel(
            service: service, passphraseStore: MemoryPassphraseStore(), settings: makeSettings(), biometry: .faceID,
            deviceName: "Test iPhone", questions: nil, pairing: { .unavailable("The keychain is locked.") },
            onFinished: { _ in finished += 1 }, onCancel: {})
        model.handle(pairingLinkText(expiresIn: 300))
        guard case .failed(let title, let message) = model.step else {
            Issue.record("no failure")
            return
        }
        #expect(title == "This iPhone cannot pair")
        #expect(message == "The keychain is locked.")
        #expect(finished == 0)
    }

    // MARK: The vault on this iPhone

    @Test("with a vault open, any relay code joins its notifications team")
    func attachSelectedVault() async {
        for text in [Self.link("&r=connect&n=Mac%20mini"), Self.link()] {
            let fixture = Fixture(attaches: true, empty: false)
            fixture.model.handle(text)
            #expect(fixture.stepID == "name")
            await fixture.model.connect()
            #expect(fixture.stepID == "connected")
            fixture.model.complete()
            #expect(fixture.finished == [nil])
        }
    }

    @Test("a refused connection fails, and Scan a new code starts again")
    func attachRefused() async {
        let fixture = Fixture(attaches: true, empty: false)
        // The vault gets questions already: the core refuses a second team.
        await fixture.service.setQuestions(enabled: true)
        fixture.model.handle(Self.link("&r=connect"))
        await fixture.model.connect()
        guard case .failed(_, let message) = fixture.model.step else {
            Issue.record("no failure")
            return
        }
        #expect(message.contains("already"))
        fixture.model.scanAgain()
        #expect(fixture.stepID == "scan")
        #expect(fixture.model.link == nil)
    }

    @Test("a name that the core cannot take does not start the connection")
    func nameRules() async {
        let fixture = Fixture(attaches: true, empty: false)
        fixture.model.handle(Self.link("&r=connect"))
        fixture.model.deviceName = "   "
        #expect(fixture.model.deviceNameProblem != nil)
        await fixture.model.connect()
        #expect(fixture.stepID == "name")
        fixture.model.deviceName = String(repeating: "ł", count: 33)
        #expect(fixture.model.deviceNameProblem == "Use a shorter name.")
    }

    @Test("Cancel before anything opened leaves the flow")
    func cancelEarly() async {
        let fixture = Fixture()
        await fixture.model.cancel()
        #expect(fixture.cancelled == 1)
        // A second cancel does nothing.
        await fixture.model.cancel()
        #expect(fixture.cancelled == 1)
    }
}
