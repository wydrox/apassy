import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("ICloudVaultModel")
struct ICloudVaultModelTests {
    @MainActor
    final class Fixture {
        let service = SpyVaultService(inner: PreviewVaultService(empty: true))
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let url = URL(fileURLWithPath: "/iCloud/Apassy/Personal.apassy")
        var finished: [VaultEntry] = []
        var cancelled = 0
        var away = false
        var model: ICloudVaultModel!

        init(biometry: Biometry = .faceID) {
            model = ICloudVaultModel(service: service, passphraseStore: store, settings: settings,
                biometry: biometry, isAway: { [unowned self] in away },
                onFinished: { [unowned self] in finished.append($0) },
                onCancel: { [unowned self] in cancelled += 1 })
            model.selectFile(url)
        }
    }

    @Test("the filename gives the name and Face ID needs the owner choice")
    func validOpen() async throws {
        let f = Fixture()
        await f.model.open(passphrase: "passphrase")
        guard case .faceID(let entry) = f.model.step else { Issue.record("No Face ID offer"); return }
        #expect(entry.name == "Personal")
        #expect(entry.isICloud)
        #expect(f.store.stored(vaultID: entry.id) == nil)
        f.model.turnOnFaceID()
        #expect(f.store.stored(vaultID: entry.id) == "passphrase")
        #expect(f.settings.faceIDUnlock(vaultID: entry.id))
        f.model.complete()
        f.model.complete()
        #expect(f.finished.count == 1)
        #expect(f.service.iCloudOpenCount == 1)
    }

    @Test("a wrong passphrase stays at the selected file and can be corrected")
    func wrongPassphrase() async {
        let f = Fixture(biometry: .none)
        await f.model.open(passphrase: "wrong")
        #expect(f.model.step == .passphrase(f.url))
        #expect(f.model.message != nil)
        await f.model.open(passphrase: "passphrase")
        guard case .done = f.model.step else { Issue.record("Did not open"); return }
    }

    @Test("two open actions make one import")
    func doubleTap() async {
        let f = Fixture()
        f.service.iCloudOpenDelay = .milliseconds(80)
        let first = Task { await f.model.open(passphrase: "passphrase") }
        #expect(await waitUntil { f.model.isWorking })
        await f.model.open(passphrase: "passphrase")
        await first.value
        #expect(f.service.iCloudOpenCount == 1)
    }

    @Test("cancel during open waits for the result and closes the vault")
    func cancelDuringOpen() async throws {
        let f = Fixture()
        f.service.iCloudOpenDelay = .milliseconds(80)
        let first = Task { await f.model.open(passphrase: "passphrase") }
        #expect(await waitUntil { f.model.isWorking })
        await f.model.cancel()
        await first.value
        #expect(f.model.step == .cancelled)
        #expect(try await !f.service.coreUnlocked())
        #expect(f.cancelled == 1)
        #expect(try await f.service.info().vaults.isEmpty)
        #expect(f.finished.isEmpty)
        await f.model.cancel()
        #expect(f.cancelled == 1)
    }

    @Test("background during open closes the vault even after a quick return")
    func backgroundDuringOpen() async throws {
        let f = Fixture()
        f.service.iCloudOpenDelay = .milliseconds(80)
        let first = Task { await f.model.open(passphrase: "passphrase") }
        #expect(await waitUntil { f.model.isWorking })
        f.model.enterBackground()
        f.model.enterForeground()
        await first.value
        guard case .done(let entry) = f.model.step else { Issue.record("No closed completion"); return }
        #expect(try await !f.service.coreUnlocked())
        #expect(f.store.stored(vaultID: entry.id) == nil)
        f.model.turnOnFaceID()
        #expect(f.store.stored(vaultID: entry.id) == nil)
    }

    @Test("cancel at the Face ID offer closes the vault and saves no passphrase")
    func cancelFaceID() async throws {
        let f = Fixture()
        await f.model.open(passphrase: "passphrase")
        guard case .faceID(let entry) = f.model.step else { Issue.record("No offer"); return }
        await f.model.cancel()
        #expect(try await !f.service.coreUnlocked())
        f.model.turnOnFaceID()
        #expect(f.store.stored(vaultID: entry.id) == nil)
        #expect(try await f.service.info().vaults.isEmpty)
    }

    @Test("cancel restores the previous vault after it removes the new local entry")
    func cancelWithPreviousVault() async throws {
        let f = Fixture()
        let previous = try await f.service.createLocalVault(name: "Previous", passphrase: "a long fixture passphrase")
        await f.model.open(passphrase: "passphrase")
        await f.model.cancel()
        // The root restores selection after the flow's rollback.
        try await f.service.select(vaultID: previous.id)
        let info = try await f.service.info()
        #expect(info.selected == previous.id)
        #expect(info.vaults.map(\.id) == [previous.id])
        #expect(!info.unlocked)
    }

    @Test("background at the Face ID offer drops its passphrase and closes the vault")
    func backgroundFaceID() async throws {
        let f = Fixture()
        await f.model.open(passphrase: "passphrase")
        guard case .faceID(let entry) = f.model.step else { Issue.record("No offer"); return }
        f.model.enterBackground()
        for _ in 0..<50 {
            if try await !f.service.coreUnlocked() { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(try await !f.service.coreUnlocked())
        #expect(f.model.step == .done(entry))
        f.model.enterForeground()
        f.model.turnOnFaceID()
        #expect(f.store.stored(vaultID: entry.id) == nil)
    }

    @Test("a failed cancel cleanup stays closed and lets the owner try Cancel again")
    func failedCancelCleanup() async throws {
        let f = Fixture()
        await f.model.open(passphrase: "passphrase")
        f.service.removeError = VaultError(.io, "The local file could not be removed.")
        await f.model.cancel()
        #expect(try await !f.service.coreUnlocked())
        #expect(f.cancelled == 0)
        #expect(f.model.message != nil)
        guard case .done = f.model.step else { Issue.record("No cleanup error screen"); return }
        f.service.removeError = nil
        await f.model.cancel()
        #expect(f.cancelled == 1)
        #expect(try await f.service.info().vaults.isEmpty)
    }

    @Test("the service rejects a wrong provider without completion")
    func invalidProvider() async {
        let f = Fixture()
        f.service.iCloudError = VaultError(.invalidInput, "Select a file in iCloud Drive.")
        await f.model.open(passphrase: "passphrase")
        #expect(f.model.step == .passphrase(f.url))
        #expect(f.model.message?.contains("iCloud Drive") == true)
        #expect(f.finished.isEmpty)
    }

    @Test("reselection connects the existing vault and reports a failed selection")
    func reconnect() async {
        let f = Fixture()
        let model = ICloudReconnectModel(service: f.service, vaultID: "existing-vault")
        f.service.iCloudError = VaultError(.conflict, "This is a different vault.")
        #expect(await !model.reconnect(f.url))
        #expect(model.message != nil)
        #expect(f.service.reconnects.isEmpty)
        f.service.iCloudError = nil
        #expect(await model.reconnect(f.url))
        #expect(model.message == nil)
        #expect(f.service.reconnects.count == 1)
        #expect(f.service.reconnects.first?.1 == "existing-vault")
        #expect(f.service.iCloudOpenCount == 0)
    }
}
