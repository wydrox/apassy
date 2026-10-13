import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// The vault syncs on its own, without "Sync now" (the preview vault is an iCloud vault): at a
/// return to the app, and soon after each kind of local change. How the sync loop sees a change
/// of the iCloud file is tested in ApassyVaultKit (`ICloudChangeCheckTests`).
@MainActor
@Suite("Automatic sync")
struct AutomaticSyncTests {
    @Test("a return to the app syncs at once and runs the loop again")
    func returnSyncs() async {
        let settings = makeSettings()
        settings.lockAfter = .fiveMinutes
        let spy = SpyVaultService(inner: PreviewVaultService(empty: false, unlocked: false))
        let (vault, _) = makeVault(service: spy, settings: settings)
        await vault.start()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        defer { vault.stopSync() }
        #expect(vault.vault?.isICloud == true)
        #expect(await waitUntil { spy.syncCount >= 1 })

        await vault.didEnterBackground()
        #expect(!vault.isSyncLoopRunning)
        let before = spy.syncCount
        await vault.didBecomeActive()
        #expect(vault.isSyncLoopRunning)
        #expect(await waitUntil(seconds: 1) { spy.syncCount > before })
    }

    @Test("the options of a credential and a paste each push soon after")
    func optionsAndPasteSync() async throws {
        let spy = SpyVaultService(organize: true)
        let (vault, _) = makeVault(service: spy)
        await vault.start()
        #expect(await waitUntil { spy.syncCount >= 1 })
        vault.stopSync()

        var before = spy.syncCount
        #expect(await vault.setItemOptions(id: 102, alwaysAsk: true))
        #expect(await waitUntil(seconds: 1) { spy.syncCount > before })

        before = spy.syncCount
        let paste = NewCredentialModel(service: spy, folder: nil, debounce: .milliseconds(10))
        paste.text = "sk_test_EXAMPLE00000000000000000000"
        await paste.detectNow()
        let added = try #require(await paste.add(in: vault))
        #expect(added.count == 1)
        #expect(await waitUntil(seconds: 1) { spy.syncCount > before })
    }
}
