import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("JoinModel")
struct JoinModelTests {
    private let link = "https://apassy-relay.example/link#apassy_lnk_abc123"

    @MainActor
    final class Fixture {
        let service = PreviewVaultService(empty: true)
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        var finished: [VaultEntry] = []
        var cancelled = 0
        var model: JoinModel!

        init(biometry: Biometry = .faceID, deviceName: String = "Test iPhone") {
            model = JoinModel(
                service: service, passphraseStore: store, settings: settings, biometry: biometry,
                deviceName: deviceName, pollInterval: .milliseconds(20),
                onFinished: { [unowned self] vault in finished.append(vault) },
                onCancel: { [unowned self] in cancelled += 1 })
        }

        /// Scan the link, send it, and wait for the passphrase screen.
        func toPassphrase(link: String) async -> Bool {
            model.handleCode(link)
            await model.start()
            return await waitUntil { model.step == .passphrase(team: "Personal") }
        }
    }

    @Test("text that is not a device link only sets a note")
    func notALink() {
        let fixture = Fixture()
        fixture.model.showScanner()
        fixture.model.handleCode("https://example.com")
        #expect(fixture.model.scanNote != nil)
        #expect(fixture.model.step == .scan)
    }

    @Test("a device link goes to the name step")
    func linkToNameStep() {
        let fixture = Fixture()
        fixture.model.handleCode("https://example.com")
        fixture.model.handleCode("  \(link) \n")
        #expect(fixture.model.step == .name(link: link))
        #expect(fixture.model.scanNote == nil)
    }

    @Test("a name needs a character and at most 64 bytes")
    func deviceNameProblem() {
        let fixture = Fixture()
        fixture.model.deviceName = ""
        #expect(fixture.model.deviceNameProblem != nil)
        fixture.model.deviceName = String(repeating: "a", count: 65)
        #expect(fixture.model.deviceNameProblem != nil)
        fixture.model.deviceName = String(repeating: "a", count: 64)
        #expect(fixture.model.deviceNameProblem == nil)
        fixture.model.deviceName = "Test iPhone"
        #expect(fixture.model.deviceNameProblem == nil)
    }

    @Test("start shows the safety words, then the passphrase when the Mac confirmed")
    func waitsForTheMac() async throws {
        let fixture = Fixture()
        fixture.model.handleCode(link)
        await fixture.model.start()
        guard case .waiting(let join) = fixture.model.step else {
            Issue.record("expected the waiting step, got \(fixture.model.step)")
            return
        }
        #expect(join.words == ["amber", "marble"])
        #expect(fixture.settings.deviceName == "Test iPhone")
        #expect(await waitUntil { fixture.model.step == .passphrase(team: "Personal") })
    }

    @Test("an error of the relay while waiting ends in a failure")
    func pollFails() async {
        let fixture = Fixture()
        // Cancel the join on the service, so that the next poll answers with an error.
        fixture.model.handleCode(link)
        await fixture.model.start()
        try? await fixture.service.joinCancel()
        #expect(
            await waitUntil {
                if case .failed = fixture.model.step { return true }
                return false
            })
    }

    @Test("a wrong passphrase keeps the step with a message")
    func wrongPassphrase() async {
        let fixture = Fixture()
        #expect(await fixture.toPassphrase(link: link))
        await fixture.model.finish(passphrase: "wrong")
        #expect(fixture.model.passphraseMessage == "The passphrase does not open this vault.")
        #expect(fixture.model.step == .passphrase(team: "Personal"))
        await fixture.model.finish(passphrase: "")
        #expect(fixture.model.passphraseMessage == "Type the passphrase.")
    }

    @Test("the right passphrase offers Face ID, and turning it on stores the passphrase")
    func faceIDOn() async {
        let fixture = Fixture()
        #expect(await fixture.toPassphrase(link: link))
        await fixture.model.finish(passphrase: PreviewVaultService.passphrase)
        guard case .faceID(let vault) = fixture.model.step else {
            Issue.record("expected the Face ID step, got \(fixture.model.step)")
            return
        }
        fixture.model.turnOnFaceID()
        #expect(fixture.store.stored(vaultID: vault.id) == PreviewVaultService.passphrase)
        #expect(fixture.settings.faceIDUnlock(vaultID: vault.id))
        #expect(fixture.model.step == .done(vault))

        fixture.model.complete()
        #expect(fixture.finished == [vault])
    }

    @Test("not now keeps the passphrase out of the store")
    func faceIDOff() async {
        let fixture = Fixture()
        #expect(await fixture.toPassphrase(link: link))
        await fixture.model.finish(passphrase: PreviewVaultService.passphrase)
        guard case .faceID(let vault) = fixture.model.step else {
            Issue.record("expected the Face ID step, got \(fixture.model.step)")
            return
        }
        fixture.model.notNow()
        #expect(!fixture.store.hasPassphrase(vaultID: vault.id))
        #expect(!fixture.settings.faceIDUnlock(vaultID: vault.id))
        #expect(fixture.model.step == .done(vault))
    }

    @Test("without biometry the right passphrase ends the flow")
    func noBiometry() async {
        let fixture = Fixture(biometry: .none)
        #expect(await fixture.toPassphrase(link: link))
        await fixture.model.finish(passphrase: PreviewVaultService.passphrase)
        guard case .done = fixture.model.step else {
            Issue.record("expected the done step, got \(fixture.model.step)")
            return
        }
        fixture.model.complete()
        #expect(fixture.finished.count == 1)
    }

    @Test("cancel while waiting cancels the join on the relay")
    func cancelWaiting() async throws {
        let fixture = Fixture()
        fixture.model.handleCode(link)
        await fixture.model.start()
        #expect(try await fixture.service.info().join != nil)
        await fixture.model.cancel()
        #expect(fixture.cancelled == 1)
        #expect(try await fixture.service.info().join == nil)
    }
}
