import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("VaultModel")
struct VaultModelTests {
    private let wrongMessage = "The passphrase does not open this vault."

    /// A model on an unlocked preview vault, started.
    private func startedVault(
        service: (any VaultService)? = nil, check: ScriptedOwnerCheck = ScriptedOwnerCheck(),
        store: MemoryPassphraseStore = MemoryPassphraseStore(), settings: VaultSettings = makeSettings()
    ) async -> (VaultModel, VaultRecorder) {
        let (vault, recorder) = makeVault(
            service: service ?? PreviewVaultService(empty: false, unlocked: true), check: check, store: store,
            settings: settings)
        await vault.start()
        return (vault, recorder)
    }

    /// The field of an item as the detail screen gets it.
    private func field(_ id: UInt64, _ name: String) async throws -> FieldView {
        let detail = try await PreviewVaultService(unlocked: true).item(id: id)
        return try #require(detail.fields.first { $0.name == name })
    }

    // MARK: Start and the lock

    @Test("start finds the vault and leaves it locked")
    func startLocked() async {
        let (vault, _) = makeVault()
        await vault.start()
        #expect(vault.hasVault)
        #expect(!vault.isUnlocked)
        #expect(vault.vault?.name == "Personal")
        #expect(vault.items.isEmpty)
    }

    @Test("a wrong passphrase leaves the vault locked with a message")
    func wrongUnlock() async {
        let (vault, _) = makeVault()
        await vault.start()
        await vault.unlock(passphrase: "wrong")
        #expect(vault.unlockMessage == wrongMessage)
        #expect(!vault.isUnlocked)
    }

    @Test("an empty passphrase asks for one")
    func emptyUnlock() async {
        let (vault, _) = makeVault()
        await vault.start()
        await vault.unlock(passphrase: "")
        #expect(vault.unlockMessage == "Type the passphrase.")
    }

    @Test("the right passphrase unlocks and reads the items and Watchtower")
    func rightUnlock() async {
        let (vault, _) = makeVault()
        await vault.start()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        defer { vault.stopSync() }
        #expect(vault.isUnlocked)
        #expect(vault.unlockMessage == nil)
        #expect(vault.items.count == 9)
        #expect(vault.activeItems.count == 8)
        #expect(vault.watchtower != nil)
    }

    @Test("unlocking gives iOS the logins for the QuickType bar once")
    func unlockPublishesIdentities() async {
        let (vault, recorder) = makeVault()
        await vault.start()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        defer { vault.stopSync() }
        #expect(recorder.replacedIdentities == [previewVaultID])
    }

    @Test("lock drops the items and the revealed values")
    func lock() async {
        let (vault, _) = await startedVault()
        defer { vault.stopSync() }
        #expect(vault.isUnlocked)
        let epoch = vault.revealEpoch
        await vault.lock()
        #expect(vault.items.isEmpty)
        #expect(!vault.isUnlocked)
        #expect(vault.watchtower == nil)
        #expect(vault.revealEpoch > epoch)
        #expect(!vault.isSyncLoopRunning)
    }

    @Test("going to the background locks at once with Immediately")
    func backgroundImmediately() async {
        let (vault, _) = await startedVault()
        await vault.didEnterBackground()
        #expect(!vault.isUnlocked)
        #expect(vault.items.isEmpty)
    }

    @Test("with 5 minutes the vault stays for 60 seconds and locks after 301")
    func backgroundFiveMinutes() async {
        let settings = makeSettings()
        settings.lockAfter = .fiveMinutes
        let (vault, recorder) = makeVault(settings: settings)
        await vault.start()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        defer { vault.stopSync() }
        #expect(vault.isUnlocked)

        let start = recorder.now
        await vault.didEnterBackground()
        recorder.now = start + .seconds(60)
        await vault.didBecomeActive()
        #expect(vault.isUnlocked)

        await vault.didEnterBackground()
        recorder.now = start + .seconds(60 + 301)
        await vault.didBecomeActive()
        #expect(!vault.isUnlocked)
    }

    // MARK: Copying

    @Test("a plain field is copied without an owner check")
    func copyPlain() async throws {
        let check = ScriptedOwnerCheck()
        let (vault, recorder) = await startedVault(check: check)
        defer { vault.stopSync() }
        await vault.copy(try await field(100, "username"), of: "GitHub", itemID: 100)
        #expect(recorder.copies == [.init(value: "octocat", secret: false)])
        #expect(check.calls == 0)
    }

    @Test("a secret field is copied after the owner check, marked secret")
    func copySecret() async throws {
        let check = ScriptedOwnerCheck(answer: true)
        let (vault, recorder) = await startedVault(check: check)
        defer { vault.stopSync() }
        await vault.copy(try await field(100, "password"), of: "GitHub", itemID: 100)
        #expect(recorder.copies == [.init(value: "synthetic-Pw-7Hq2!kLm9x", secret: true)])
        #expect(check.reasons == ["Copy the password of “GitHub”"])
    }

    @Test("a cancelled passphrase prompt copies nothing")
    func copyCancelled() async throws {
        let check = ScriptedOwnerCheck(answer: false)
        let (vault, recorder) = await startedVault(check: check)
        defer { vault.stopSync() }
        let password = try await field(100, "password")
        let task = Task { await vault.copy(password, of: "GitHub", itemID: 100) }
        #expect(await waitUntil { vault.gate.prompt != nil })
        vault.gate.cancel()
        await task.value
        #expect(recorder.copies.isEmpty)
    }

    @Test("the main secret of a row is copied: the token of an API key")
    func copyMainSecret() async throws {
        let (vault, recorder) = await startedVault()
        defer { vault.stopSync() }
        let row = try #require(vault.item(101))
        await vault.copyMainSecret(row)
        #expect(recorder.copies == [.init(value: "sk_synthetic_4eC39HqLyjWDarjtT1zdp7dc", secret: true)])
    }

    @Test("the username of a row is copied plain")
    func copyUsername() async throws {
        let (vault, recorder) = await startedVault()
        defer { vault.stopSync() }
        vault.copyUsername(try #require(vault.item(100)))
        #expect(recorder.copies == [.init(value: "octocat", secret: false)])
    }

    // MARK: Items

    @Test("saving a new login adds it, publishes the logins, and syncs soon after")
    func saveNewItem() async throws {
        let spy = SpyVaultService()
        let (vault, recorder) = await startedVault(service: spy)
        defer { vault.stopSync() }
        #expect(await waitUntil { spy.syncCount >= 1 })
        vault.stopSync()
        let before = spy.syncCount

        let draft = ItemDraft(
            title: "New login", kind: .login, notes: "", tags: [],
            fields: [.named("username", "me", secret: false), .named("password", "pw-1", secret: true)])
        let saved = try await vault.save(id: nil, revision: nil, draft: draft)
        #expect(saved.id == 109)
        #expect(vault.activeItems.count == 9)
        #expect(recorder.replacedIdentities.last == previewVaultID)
        #expect(await waitUntil(seconds: 1) { spy.syncCount > before })
    }

    @Test("deleting an item removes it and its favorite")
    func deleteItem() async throws {
        let (vault, _) = await startedVault()
        defer { vault.stopSync() }
        vault.toggleFavorite(102)
        #expect(vault.isFavorite(102))
        let row = try #require(vault.item(102))
        #expect(await vault.delete(row))
        #expect(vault.item(102) == nil)
        #expect(!vault.isFavorite(102))
    }

    @Test("a favorite is toggled on and off")
    func favorite() async {
        let (vault, _) = await startedVault()
        defer { vault.stopSync() }
        vault.toggleFavorite(100)
        #expect(vault.isFavorite(100))
        #expect(vault.favoriteIDs == [100])
        vault.toggleFavorite(100)
        #expect(!vault.isFavorite(100))
    }

    // MARK: Face ID

    @Test("Face ID unlock checks the passphrase before it stores it")
    func enableFaceID() async throws {
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let (vault, _) = makeVault(store: store, settings: settings)
        await vault.start()

        await #expect(throws: VaultError(.wrongPassphrase, wrongMessage)) {
            try await vault.enableFaceIDUnlock(passphrase: "wrong")
        }
        #expect(!store.hasPassphrase(vaultID: previewVaultID))
        #expect(!settings.faceIDUnlock(vaultID: previewVaultID))

        try await vault.enableFaceIDUnlock(passphrase: PreviewVaultService.passphrase)
        #expect(store.stored(vaultID: previewVaultID) == PreviewVaultService.passphrase)
        #expect(settings.faceIDUnlock(vaultID: previewVaultID))
        #expect(vault.faceIDUnlockOn)
        #expect(vault.hasStoredPassphrase)
    }

    @Test("turning Face ID unlock off removes the passphrase and the choice")
    func disableFaceID() async throws {
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let (vault, _) = makeVault(store: store, settings: settings)
        await vault.start()
        try await vault.enableFaceIDUnlock(passphrase: PreviewVaultService.passphrase)
        vault.disableFaceIDUnlock()
        #expect(!store.hasPassphrase(vaultID: previewVaultID))
        #expect(!settings.faceIDUnlock(vaultID: previewVaultID))
    }

    @Test("Face ID unlock reads the stored passphrase and unlocks")
    func unlockWithFaceID() async throws {
        let store = MemoryPassphraseStore()
        try store.save(PreviewVaultService.passphrase, vaultID: previewVaultID)
        let (vault, _) = makeVault(store: store)
        await vault.start()
        await vault.unlockWithFaceID()
        defer { vault.stopSync() }
        #expect(vault.isUnlocked)
    }

    @Test("a stored passphrase that iOS dropped is stored again at the next unlock")
    func faceIDRepair() async {
        let store = MemoryPassphraseStore()
        store.readError = VaultError(.locked, "x")
        let settings = makeSettings()
        settings.setFaceIDUnlock(true, vaultID: previewVaultID)
        let (vault, _) = makeVault(store: store, settings: settings)
        await vault.start()

        await vault.unlockWithFaceID()
        #expect(vault.faceIDNeedsRepair)
        #expect(vault.unlockMessage == "x")
        #expect(!vault.isUnlocked)
        #expect(!store.hasPassphrase(vaultID: previewVaultID))

        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        defer { vault.stopSync() }
        #expect(vault.isUnlocked)
        #expect(!vault.faceIDNeedsRepair)
        #expect(store.stored(vaultID: previewVaultID) == PreviewVaultService.passphrase)
    }

    @Test("a cancelled Face ID prompt leaves the lock screen as it is")
    func faceIDCancelled() async throws {
        let store = MemoryPassphraseStore()
        store.readError = VaultError(.cancelled, "Cancelled.")
        let (vault, _) = makeVault(store: store)
        await vault.start()
        await vault.unlockWithFaceID()
        #expect(!vault.isUnlocked)
        #expect(!vault.faceIDNeedsRepair)
        #expect(vault.unlockMessage == nil)
    }

    // MARK: Face ID first

    /// A started, locked model whose vault opens with Face ID.
    private func faceIDVault(
        service: any VaultService = PreviewVaultService(empty: false, unlocked: false),
        store: MemoryPassphraseStore = MemoryPassphraseStore()
    ) async throws -> (VaultModel, VaultRecorder) {
        let settings = makeSettings()
        settings.setFaceIDUnlock(true, vaultID: previewVaultID)
        try store.save(PreviewVaultService.passphrase, vaultID: previewVaultID)
        let (vault, recorder) = makeVault(service: service, store: store, settings: settings)
        await vault.start()
        return (vault, recorder)
    }

    @Test("the lock screen opens with Face ID first, without the passphrase field")
    func faceIDFirstOpens() async throws {
        let store = MemoryPassphraseStore()
        let (vault, _) = try await faceIDVault(store: store)
        #expect(!vault.showsPassphraseField)
        #expect(vault.waitsForFaceIDTry)

        await vault.unlockWithFaceIDFirst()
        defer { vault.stopSync() }
        #expect(vault.isUnlocked)
        #expect(store.prompts.count == 1)
    }

    @Test("a cancelled first Face ID shows the field once; a return to the app tries again")
    func faceIDFirstCancelled() async throws {
        let store = MemoryPassphraseStore()
        let (vault, _) = try await faceIDVault(store: store)
        store.readError = VaultError(.cancelled, "Cancelled.")

        await vault.unlockWithFaceIDFirst()
        #expect(!vault.isUnlocked)
        #expect(vault.showsPassphraseField)
        #expect(!vault.waitsForFaceIDTry)
        await vault.unlockWithFaceIDFirst()
        #expect(store.prompts.count == 1)

        await vault.didEnterBackground()
        #expect(!vault.showsPassphraseField)
        await vault.unlockWithFaceIDFirst()
        #expect(store.prompts.count == 1)

        store.readError = nil
        await vault.didBecomeActive()
        await vault.unlockWithFaceIDFirst()
        defer { vault.stopSync() }
        #expect(vault.isUnlocked)
        #expect(store.prompts.count == 2)
    }

    @Test("a first Face ID that ends after the app left keeps the field hidden")
    func faceIDFirstLeft() async throws {
        let store = MemoryPassphraseStore()
        let (vault, _) = try await faceIDVault(store: store)
        store.readError = VaultError(.cancelled, "Cancelled by the system.")
        store.readDelay = .milliseconds(200)

        let attempt = Task { await vault.unlockWithFaceIDFirst() }
        #expect(await waitUntil { store.prompts.count == 1 })
        await vault.didEnterBackground()
        await attempt.value
        #expect(!vault.showsPassphraseField)
        #expect(vault.waitsForFaceIDTry)
    }

    @Test("a return while the first Face ID still ends tries again by itself")
    func faceIDFirstReturnedDuringTry() async throws {
        let store = MemoryPassphraseStore()
        let (vault, _) = try await faceIDVault(store: store)
        store.readError = VaultError(.cancelled, "Cancelled by the system.")
        store.readDelay = .milliseconds(200)

        let attempt = Task { await vault.unlockWithFaceIDFirst() }
        #expect(await waitUntil { store.prompts.count == 1 })
        await vault.didEnterBackground()
        await vault.didBecomeActive()
        // The lock screen asks on the return; the first try still runs.
        await vault.unlockWithFaceIDFirst()
        await attempt.value
        #expect(store.prompts.count == 2)
        #expect(vault.showsPassphraseField)
    }

    @Test("a wrong stored passphrase shows the field with the message")
    func faceIDFirstWrongPassphrase() async throws {
        let store = MemoryPassphraseStore()
        let (vault, _) = try await faceIDVault(store: store)
        try store.save("not the passphrase", vaultID: previewVaultID)

        await vault.unlockWithFaceIDFirst()
        #expect(!vault.isUnlocked)
        #expect(vault.showsPassphraseField)
        #expect(vault.unlockMessage == wrongMessage)
    }

    @Test("without Face ID unlock the field shows at once, and nothing prompts")
    func faceIDFirstOff() async {
        let store = MemoryPassphraseStore()
        let (vault, _) = makeVault(store: store)
        await vault.start()
        #expect(vault.showsPassphraseField)

        await vault.unlockWithFaceIDFirst()
        #expect(!vault.isUnlocked)
        #expect(store.prompts.isEmpty)
    }

    @Test("after an unlock, the next lock screen tries Face ID first again")
    func faceIDFirstAfterUnlock() async throws {
        let store = MemoryPassphraseStore()
        let (vault, _) = try await faceIDVault(store: store)
        store.readError = VaultError(.cancelled, "Cancelled.")
        await vault.unlockWithFaceIDFirst()
        #expect(vault.showsPassphraseField)

        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        vault.stopSync()
        await vault.lock()
        #expect(!vault.showsPassphraseField)
        #expect(vault.waitsForFaceIDTry)
    }

    @Test("another vault tries its own Face ID first once it is selected")
    func faceIDFirstOtherVault() async throws {
        let spy = SpyVaultService()
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let second = try await spy.createLocalVault(name: "Second", passphrase: "a long fixture passphrase")
        try await spy.select(vaultID: previewVaultID)
        settings.setFaceIDUnlock(true, vaultID: previewVaultID)
        settings.setFaceIDUnlock(true, vaultID: second.id)
        try store.save(PreviewVaultService.passphrase, vaultID: previewVaultID)
        // The preview service opens every vault with its own passphrase.
        try store.save(PreviewVaultService.passphrase, vaultID: second.id)
        let (vault, _) = makeVault(service: spy, store: store, settings: settings)
        await vault.start()
        store.readError = VaultError(.cancelled, "Cancelled.")
        await vault.unlockWithFaceIDFirst()
        #expect(vault.showsPassphraseField)

        store.readError = nil
        await vault.select(vaultID: second.id)
        #expect(vault.vault?.id == second.id)
        #expect(vault.waitsForFaceIDTry)
        #expect(!vault.showsPassphraseField)
        await vault.unlockWithFaceIDFirst()
        defer { vault.stopSync() }
        #expect(vault.isUnlocked)
        #expect(store.prompts.last == "Unlock “Second”")
    }

    // MARK: Removing the vault

    @Test("removing the vault forgets its passphrase, settings, and QuickType logins")
    func removeVault() async throws {
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let (vault, recorder) = makeVault(store: store, settings: settings)
        await vault.start()
        try await vault.enableFaceIDUnlock(passphrase: PreviewVaultService.passphrase)
        vault.toggleFavorite(100)

        try await vault.removeVault(force: false)
        #expect(!vault.hasVault)
        #expect(!store.hasPassphrase(vaultID: previewVaultID))
        #expect(!settings.faceIDUnlock(vaultID: previewVaultID))
        #expect(settings.favorites(vaultID: previewVaultID).isEmpty)
        #expect(recorder.removedAllIdentities == 1)
    }

    // MARK: Sync

    private var rekeyStatus: SyncStatus {
        SyncStatus(enabled: true, state: .error, message: "iCloud publication failed after rekey.",
            version: 900, lastSyncAt: nil, pushed: false, merged: nil)
    }

    @Test("a delayed rekey stores the passphrase for its original vault after selection changes")
    func rekeyAfterSelectionChange() async throws {
        let spy = SpyVaultService()
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let second = try await spy.createLocalVault(name: "Second", passphrase: "a long fixture passphrase")
        try await spy.select(vaultID: previewVaultID)
        let (vault, recorder) = makeVault(service: spy, store: store, settings: settings)
        await vault.start()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        vault.stopSync()
        settings.setFaceIDUnlock(true, vaultID: previewVaultID)
        settings.setFaceIDUnlock(true, vaultID: second.id)
        try store.save("first-old", vaultID: previewVaultID)
        try store.save("second-stored", vaultID: second.id)
        spy.passphraseChangeDelay = .milliseconds(600)
        spy.passphraseChangeResult = PassphraseChange(status: rekeyStatus, rekeyed: true)
        let rekey = Task { try await vault.takeNewPassphrase("first-new") }
        #expect(await waitUntil { spy.passphraseChangeCount == 1 })
        await vault.select(vaultID: second.id)
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        let secondStatus = vault.syncStatus
        let publications = recorder.replacedIdentities
        try await rekey.value
        #expect(vault.vault?.id == second.id)
        #expect(store.stored(vaultID: second.id) == "second-stored")
        #expect(store.stored(vaultID: previewVaultID) == "first-new")
        #expect(vault.syncStatus == secondStatus)
        #expect(recorder.replacedIdentities == publications)
        #expect(!vault.isSyncLoopRunning)
    }

    @Test("a delayed rekey does not recreate credentials after the original vault is removed")
    func rekeyAfterRemoval() async throws {
        let spy = SpyVaultService()
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let (vault, _) = await startedVault(service: spy, store: store, settings: settings)
        vault.stopSync()
        settings.setFaceIDUnlock(true, vaultID: previewVaultID)
        try store.save("old-passphrase", vaultID: previewVaultID)
        spy.passphraseChangeDelay = .milliseconds(100)
        spy.passphraseChangeResult = PassphraseChange(status: rekeyStatus, rekeyed: true)
        let rekey = Task { try await vault.takeNewPassphrase("new-passphrase") }
        #expect(await waitUntil { spy.passphraseChangeCount == 1 })
        try await vault.removeVault(force: true)
        try await rekey.value
        #expect(!store.hasPassphrase(vaultID: previewVaultID))
        #expect(!vault.hasVault)
        #expect(!vault.isSyncLoopRunning)
    }

    @Test("a passphrase that did not rekey does not replace the stored passphrase")
    func openedCopyWithoutRekey() async throws {
        let spy = SpyVaultService()
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let (vault, _) = await startedVault(service: spy, store: store, settings: settings)
        vault.stopSync()
        defer { vault.stopSync() }
        settings.setFaceIDUnlock(true, vaultID: previewVaultID)
        try store.save("old-passphrase", vaultID: previewVaultID)
        spy.passphraseChangeResult = PassphraseChange(status: rekeyStatus, rekeyed: false)
        try await vault.takeNewPassphrase("copy-passphrase")
        #expect(store.stored(vaultID: previewVaultID) == "old-passphrase")
    }

    @Test("an iCloud publication error reloads a committed local merge and AutoFill identities")
    func syncPublicationErrorReloadsLocalMerge() async throws {
        let spy = SpyVaultService()
        let (vault, recorder) = await startedVault(service: spy)
        #expect(await waitUntil { spy.syncCount >= 1 })
        vault.stopSync()
        let publications = recorder.replacedIdentities.count
        spy.syncMutationTitle = "Merged from iCloud"
        spy.syncDelay = .milliseconds(40)
        spy.syncError = VaultError(.io, "The iCloud provider could not publish the file.")
        await vault.syncNow()
        vault.stopSync()
        #expect(vault.items.contains { $0.title == "Merged from iCloud" })
        #expect(recorder.replacedIdentities.count > publications)
        #expect(recorder.replacedIdentities.last == previewVaultID)
    }

    @Test("a delayed iCloud publication error cannot replace the next vault status or identities")
    func syncPublicationErrorAfterSelectionChange() async throws {
        let spy = SpyVaultService()
        let second = try await spy.createLocalVault(name: "Second", passphrase: "a long fixture passphrase")
        try await spy.select(vaultID: previewVaultID)
        let (vault, recorder) = makeVault(service: spy)
        await vault.start()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        #expect(await waitUntil { spy.syncCount >= 1 })
        vault.stopSync()
        let before = spy.syncCount
        spy.syncMutationTitle = "Merged before publication"
        spy.syncDelay = .milliseconds(600)
        spy.syncError = VaultError(.io, "The iCloud provider could not publish the file.")
        let sync = Task { await vault.syncNow() }
        #expect(await waitUntil { spy.syncCount > before })
        await vault.select(vaultID: second.id)
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        let secondStatus = vault.syncStatus
        let publications = recorder.replacedIdentities
        let itemsVersion = vault.itemsVersion
        spy.syncStatusOverride = rekeyStatus
        await sync.value
        #expect(vault.vault?.id == second.id)
        #expect(vault.syncStatus == secondStatus)
        #expect(recorder.replacedIdentities == publications)
        #expect(vault.itemsVersion == itemsVersion)
        #expect(!vault.isSyncLoopRunning)
    }

    @Test("the sync loop syncs, waits, and syncs again when the relay has news, and stops on request")
    func syncLoop() async {
        let spy = SpyVaultService(syncWaits: [true, false])
        let (vault, _) = await startedVault(service: spy)
        #expect(vault.isSyncLoopRunning)
        #expect(await waitUntil { spy.syncCount >= 2 })
        vault.stopSync()
        #expect(!vault.isSyncLoopRunning)
    }

    @Test("the sync loop tries again after an error")
    func syncRetries() async {
        let spy = SpyVaultService(syncError: VaultError(.relayUnreachable, "x"))
        let (vault, _) = await startedVault(service: spy)
        #expect(await waitUntil(seconds: 1) { spy.syncCount >= 3 })
        vault.stopSync()
    }

    @Test("a local vault does not sync")
    func localVaultNoSync() async throws {
        let service = PreviewVaultService(empty: true)
        _ = try await service.createLocalVault(name: "Local", passphrase: "a long enough passphrase")
        let (vault, _) = await startedVault(service: service)
        #expect(vault.isUnlocked)
        #expect(!vault.isSyncLoopRunning)
    }

    @Test("a sync merged something when the merge exists and the version or the merge moved")
    func merged() {
        func status(version: UInt64, merged: SyncStatus.Merged?) -> SyncStatus {
            SyncStatus(
                enabled: true, state: .ok, message: "", version: version, lastSyncAt: nil, pushed: false, merged: merged)
        }
        let one = SyncStatus.Merged(inserted: 1, updated: 0, deleted: 0, conflicts: 0)
        let two = SyncStatus.Merged(inserted: 2, updated: 0, deleted: 0, conflicts: 0)
        #expect(!VaultModel.merged(status(version: 5, merged: nil), since: nil))
        #expect(!VaultModel.merged(status(version: 5, merged: nil), since: status(version: 4, merged: one)))
        #expect(VaultModel.merged(status(version: 5, merged: one), since: nil))
        #expect(!VaultModel.merged(status(version: 5, merged: one), since: status(version: 5, merged: one)))
        #expect(VaultModel.merged(status(version: 6, merged: one), since: status(version: 5, merged: one)))
        #expect(VaultModel.merged(status(version: 5, merged: two), since: status(version: 5, merged: one)))
    }

    @Test("states that the owner must solve stop the sync loop")
    func waitsForOwner() {
        #expect(VaultModel.waitsForOwner(.needsPassphrase))
        #expect(VaultModel.waitsForOwner(.forkedCopy))
        #expect(!VaultModel.waitsForOwner(.ok))
        #expect(!VaultModel.waitsForOwner(.offline))
        // Another device of the account syncs, and then this iPhone goes on: the loop waits on.
        #expect(!VaultModel.waitsForOwner(.waitsForDevice))
    }

    @Test("a sync that waits for another device of the account is a plain line, not a problem")
    func waitsForDeviceIsPlain() {
        #expect(SyncStatusLook.of(.waitsForDevice) == .plain)
        #expect(!SyncStatusLook.of(.waitsForDevice).isProblem)
        #expect(SyncStatusLook.of(nil) == .plain)
        #expect(SyncStatusLook.of(.ok) == .ok)
        #expect(SyncStatusLook.of(.busy) == .busy && !SyncStatusLook.of(.busy).isProblem)
        #expect(SyncStatusLook.of(.needsPassphrase) == .attention && SyncStatusLook.of(.needsPassphrase).isProblem)
        #expect(SyncStatusLook.of(.offline) == .attention && SyncStatusLook.of(.offline).isProblem)
        for state: SyncStatus.State in [.removed, .damaged, .staleCopy, .forkedCopy, .error] {
            #expect(SyncStatusLook.of(state) == .critical && SyncStatusLook.of(state).isProblem, "\(state)")
        }
        for state: SyncStatus.State in [.off, .never, .pending] {
            #expect(SyncStatusLook.of(state) == .plain, "\(state)")
        }
    }
}
