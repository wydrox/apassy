import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// The vault closes in the background also while it is being opened (an unlock, a resume, a
/// join), and secrets that arrive after a drop are not kept.
@MainActor
@Suite("Vault lifecycle")
struct VaultLifecycleTests {
    private func lockedSpy() -> SpyVaultService {
        SpyVaultService(inner: PreviewVaultService(empty: false, unlocked: false))
    }

    // MARK: 1a: a resume that the background overtakes

    @Test("a resume that returns after the app went away again closes the vault at once")
    func resumeOvertaken() async throws {
        let settings = makeSettings()
        settings.lockAfter = .fiveMinutes
        let spy = lockedSpy()
        let (vault, _) = makeVault(service: spy, settings: settings)
        await vault.start()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        defer { vault.stopSync() }
        await vault.didEnterBackground()
        #expect(vault.isSuspended)
        #expect(try await !spy.coreUnlocked())

        spy.resumeDelay = .milliseconds(200)
        vault.enterForeground()
        try await Task.sleep(for: .milliseconds(50))
        vault.enterBackground()
        await vault.settle()
        #expect(try await !spy.coreUnlocked())
        #expect(vault.isUnlocked)
        #expect(vault.isSuspended)
        #expect(!vault.isSyncLoopRunning)

        // The next return resumes as after any time away.
        spy.resumeDelay = nil
        await vault.didBecomeActive()
        #expect(vault.isUnlocked)
        #expect(!vault.isSuspended)
        #expect(try await spy.coreUnlocked())
    }

    @Test("a return waits for the background transition before it resumes")
    func returnWaitsForClose() async throws {
        let settings = makeSettings()
        settings.lockAfter = .fiveMinutes
        let spy = lockedSpy()
        let (vault, _) = makeVault(service: spy, settings: settings)
        await vault.start()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        defer { vault.stopSync() }
        vault.enterBackground()
        vault.enterForeground()
        await vault.settle()
        #expect(vault.isUnlocked)
        #expect(!vault.isSuspended)
        #expect(try await spy.coreUnlocked())
    }

    // MARK: 1b: an unlock that the background overtakes

    @Test("an unlock that ends after the app went away locks again with Immediately")
    func unlockOvertakenImmediately() async throws {
        let spy = lockedSpy()
        let (vault, _) = makeVault(service: spy)
        await vault.start()
        // The preview takes 300 ms to unlock, like a key derivation.
        let unlocking = Task { await vault.unlock(passphrase: PreviewVaultService.passphrase) }
        try await Task.sleep(for: .milliseconds(50))
        vault.enterBackground()
        await unlocking.value
        await vault.settle()
        #expect(!vault.isUnlocked)
        #expect(vault.unlockMessage == nil)
        #expect(try await !spy.coreUnlocked())
        #expect(!vault.isSyncLoopRunning)
    }

    @Test("an unlock that ends after the app went away is closed with 5 minutes too")
    func unlockOvertakenFiveMinutes() async throws {
        let settings = makeSettings()
        settings.lockAfter = .fiveMinutes
        let spy = lockedSpy()
        let (vault, _) = makeVault(service: spy, settings: settings)
        await vault.start()
        let unlocking = Task { await vault.unlock(passphrase: PreviewVaultService.passphrase) }
        try await Task.sleep(for: .milliseconds(50))
        vault.enterBackground()
        await unlocking.value
        await vault.settle()
        #expect(try await !spy.coreUnlocked())
        #expect(!vault.isSyncLoopRunning)
    }

    @Test("a core that refuses an overtaken unlock with locked leaves the lock screen without a message")
    func unlockRefusedAsLocked() async throws {
        let spy = SpyVaultService(inner: PreviewVaultService(empty: false, unlocked: false))
        let (vault, _) = makeVault(service: spy)
        await vault.start()
        spy.unlockError = VaultError(.locked, "The vault is locked.")
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        #expect(!vault.isUnlocked)
        #expect(vault.unlockMessage == nil)
        #expect(vault.alert == nil)
    }

    // MARK: 1c: a vault that the core opened behind the screens (a join)

    @Test("going to the background closes a vault that the screens do not show as unlocked")
    func backgroundClosesJoinedVault() async throws {
        let spy = lockedSpy()
        let (vault, _) = makeVault(service: spy)
        await vault.start()
        // `join_finish` selects and unlocks the vault; the model is not unlocked yet.
        try await spy.unlock(passphrase: PreviewVaultService.passphrase, keep: false)
        #expect(!vault.isUnlocked)
        #expect(try await spy.coreUnlocked())
        await vault.didEnterBackground()
        #expect(try await !spy.coreUnlocked())
    }

    // MARK: 2: one-time codes

    private func makeDetail(check: ScriptedOwnerCheck = ScriptedOwnerCheck(), lifetime: Duration = .milliseconds(150))
        async -> (ItemDetailModel, VaultModel)
    {
        let (vault, _) = makeVault(service: PreviewVaultService(empty: false, unlocked: true), check: check)
        await vault.start()
        vault.stopSync()
        let detail = ItemDetailModel(id: 100, vault: vault, revealLifetime: lifetime)
        await detail.load()
        return (detail, vault)
    }

    @Test("a one-time code goes after its lifetime, as a revealed value")
    func codeExpires() async throws {
        let (detail, _) = await makeDetail()
        let field = try #require(detail.detail?.field(.totp))
        await detail.showCode(field)
        #expect(detail.codes[field.name] != nil)
        #expect(await waitUntil(seconds: 2) { detail.codes[field.name] == nil })
    }

    @Test("the refresh of a code stops and drops it when the secrets are dropped")
    func codeStopsOnEpoch() async throws {
        let (detail, vault) = await makeDetail(lifetime: .seconds(30))
        let field = try #require(detail.detail?.field(.totp))
        await detail.showCode(field)
        let running = Task { await detail.runCode(field) }
        // Let the refresh start before the drop.
        try await Task.sleep(for: .milliseconds(100))
        let clock = ContinuousClock()
        let dropped = clock.now
        vault.dropRevealed()
        await running.value
        #expect(detail.codes[field.name] == nil)
        // It stops within its one-second check, not at the end of the code's lifetime.
        #expect(clock.now - dropped < .seconds(2))
    }

    // MARK: 7: a value that arrives after a drop

    @Test("a secret that arrives after the secrets were dropped is not kept")
    func revealAfterDrop() async throws {
        let check = ScriptedOwnerCheck(answer: false)
        let (detail, vault) = await makeDetail(check: check, lifetime: .seconds(30))
        let field = try #require(detail.detail?.fields.first { $0.name == "password" })
        let revealing = Task { await detail.reveal(field) }
        #expect(await waitUntil { vault.gate.prompt != nil })
        vault.dropRevealed()
        await vault.gate.submit(PreviewVaultService.passphrase)
        await revealing.value
        #expect(detail.revealed.isEmpty)
    }

    @Test("a code that arrives after the screen dropped its secrets is not kept")
    func codeAfterDrop() async throws {
        let check = ScriptedOwnerCheck(answer: false)
        let (detail, vault) = await makeDetail(check: check, lifetime: .seconds(30))
        let field = try #require(detail.detail?.field(.totp))
        let showing = Task { await detail.showCode(field) }
        #expect(await waitUntil { vault.gate.prompt != nil })
        detail.dropSecrets()
        await vault.gate.submit(PreviewVaultService.passphrase)
        await showing.value
        #expect(detail.codes.isEmpty)
    }

    // MARK: 4: the clock

    @Test("the auto-lock measures the time away on the continuous clock")
    func continuousClock() async {
        let settings = makeSettings()
        settings.lockAfter = .oneMinute
        let (vault, recorder) = makeVault(settings: settings)
        await vault.start()
        await vault.unlock(passphrase: PreviewVaultService.passphrase)
        defer { vault.stopSync() }
        let start = recorder.now
        await vault.didEnterBackground()
        recorder.now = start + .seconds(59)
        await vault.didBecomeActive()
        #expect(vault.isUnlocked)
        await vault.didEnterBackground()
        recorder.now = start + .seconds(59) + .seconds(60)
        await vault.didBecomeActive()
        #expect(!vault.isUnlocked)
    }
}
