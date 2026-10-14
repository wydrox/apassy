import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// The questions of the vaults that are not selected (contract ios-core-v1 section 5.10, "Several
/// vaults"): the core drops every questions context on a lock and a suspend, and after a resume
/// holds the selected vault only. The app opens the others again with `questions_unlock`: with one
/// Face ID for those whose passphrase is stored, else with the passphrase sheet of their row.
@MainActor
@Suite("Questions of the other vaults")
struct OtherVaultsQuestionsTests {
    static let personal = previewVaultID
    static let work = (id: "8e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b", name: "Work", team: "t_wq3k7m2p5x")
    static let family = (id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", name: "Family", team: "t_fffffffff2")

    @MainActor
    final class Fixture {
        let service = PreviewVaultService(empty: false, unlocked: false)
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let defaults: UserDefaults
        let vault: VaultModel
        let questions: QuestionsModel
        let personalQuestion: RemoteQuestion
        let workQuestion: RemoteQuestion
        let familyQuestion: RemoteQuestion

        /// Personal is selected and locked; Work and Family are on this iPhone, each with its
        /// questions team, and no context yet. Family has the newest question.
        init(now: Date = Date()) async throws {
            let suite = "questions-other-vaults-\(UUID().uuidString)"
            defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            settings.lockAfter = .fiveMinutes
            let signers = TeamAnswerSigners(store: ScriptedKeyStore())
            personalQuestion = PreviewVaultService.sampleQuestion(
                qid: "cGVyc29uYWwtcXVlc3Rpb24tMQ", now: now.addingTimeInterval(-90))
            workQuestion = PreviewVaultService.sampleQuestion(
                qid: "d29yay1xdWVzdGlvbi0wMDAwMQ", now: now.addingTimeInterval(-60))
            familyQuestion = PreviewVaultService.sampleQuestion(qid: "ZmFtaWx5LXF1ZXN0aW9uLTAwMQ", now: now)
            await service.setQuestions(
                enabled: true, questions: [personalQuestion], answerKey: try signers.joinKey(team: "t_7k2m5q4x3c"))
            await service.addQuestionsVault(
                id: OtherVaultsQuestionsTests.work.id, name: OtherVaultsQuestionsTests.work.name,
                team: OtherVaultsQuestionsTests.work.team, questions: [workQuestion],
                answerKey: try signers.joinKey(team: OtherVaultsQuestionsTests.work.team), onPhone: true, open: false)
            await service.addQuestionsVault(
                id: OtherVaultsQuestionsTests.family.id, name: OtherVaultsQuestionsTests.family.name,
                team: OtherVaultsQuestionsTests.family.team, questions: [familyQuestion],
                answerKey: try signers.joinKey(team: OtherVaultsQuestionsTests.family.team), onPhone: true,
                open: false)
            (vault, _) = makeVault(service: service, store: store, settings: settings)
            questions = QuestionsModel(
                service: service, signers: signers, push: nil, deviceName: "Test iPhone", defaults: defaults,
                retryInterval: .milliseconds(10))
            questions.follow(vault)
            await vault.start()
        }

        /// "Unlock with Face ID" on for `vaultID`, with `passphrase` stored behind it.
        func storeFaceID(_ vaultID: String, passphrase: String = PreviewVaultService.passphrase) throws {
            try store.save(passphrase, vaultID: vaultID)
            settings.setFaceIDUnlock(true, vaultID: vaultID)
        }

        /// Unlock Personal with its typed passphrase, and wait for the other vaults.
        func unlock() async {
            await vault.unlock(passphrase: PreviewVaultService.passphrase)
            await questions.reopenFinished()
        }

        func contexts() async -> [String: Bool] {
            [
                work.id: await service.hasQuestionsContext(vaultID: work.id),
                family.id: await service.hasQuestionsContext(vaultID: family.id),
            ]
        }

        var work: (id: String, name: String, team: String) { OtherVaultsQuestionsTests.work }
        var family: (id: String, name: String, team: String) { OtherVaultsQuestionsTests.family }

        func locked(_ id: String) -> LockedVault? { questions.lockedVaults.first { $0.id == id } }
    }

    @Test("an unlock opens the questions of the other vaults with one Face ID, in the background")
    func unlockOpensOthers() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.work.id)
        try fixture.storeFaceID(Self.family.id)

        await fixture.unlock()

        #expect(fixture.store.prompts == ["Read the questions of 2 other vaults"])
        #expect(Set(fixture.store.sessionReads) == [Self.work.id, Self.family.id])
        #expect(fixture.store.openSessions == 0)
        #expect(Set(await fixture.service.questionsUnlocks()) == [Self.work.id, Self.family.id])
        #expect(await fixture.contexts() == [Self.work.id: true, Self.family.id: true])
        #expect(fixture.questions.lockedVaults.isEmpty)
        #expect(fixture.questions.phase == .ready)
        #expect(fixture.questions.questions.count == 3)
        // The selected vault did not change.
        #expect(fixture.vault.vault?.id == Self.personal)
    }

    @Test("resume opens the questions of the other vaults again with one Face ID")
    func resumeReopensWithOneFaceID() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.work.id)
        try fixture.storeFaceID(Self.family.id)
        await fixture.unlock()
        #expect(fixture.store.prompts.count == 1)

        // The suspend drops every context.
        await fixture.vault.didEnterBackground()
        #expect(fixture.vault.isSuspended)
        #expect(await fixture.contexts() == [Self.work.id: false, Self.family.id: false])

        await fixture.vault.didBecomeActive()
        await fixture.questions.reopenFinished()
        #expect(fixture.vault.isUnlocked && !fixture.vault.isSuspended)
        // One more Face ID for both vaults, and both contexts again.
        #expect(fixture.store.prompts.count == 2)
        #expect(fixture.store.openSessions == 0)
        #expect(await fixture.service.questionsUnlocks().count == 4)
        #expect(await fixture.contexts() == [Self.work.id: true, Self.family.id: true])
        #expect(fixture.questions.lockedVaults.isEmpty)
        #expect(
            Set(fixture.questions.questions.map(\.vaultID))
                == [Self.personal, Self.work.id, Self.family.id])
    }

    @Test("a Face ID unlock reads the passphrases of the selected and the other vaults with one prompt")
    func faceIDUnlockIsOnePrompt() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.personal)
        try fixture.storeFaceID(Self.work.id)
        try fixture.storeFaceID(Self.family.id)

        await fixture.vault.unlockWithFaceID()
        await fixture.questions.reopenFinished()

        #expect(fixture.vault.isUnlocked)
        #expect(fixture.store.prompts == ["Unlock “Personal” and read the questions of 2 other vaults"])
        #expect(fixture.store.sessionReads.first == Self.personal)
        #expect(Set(fixture.store.sessionReads) == [Self.personal, Self.work.id, Self.family.id])
        #expect(fixture.store.openSessions == 0)
        #expect(await fixture.contexts() == [Self.work.id: true, Self.family.id: true])
        #expect(fixture.questions.lockedVaults.isEmpty)
    }

    @Test("a vault without a stored passphrase shows one Unlock row, and its sheet opens its questions only")
    func unlockRowWithoutStoredPassphrase() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.work.id)
        await fixture.unlock()

        let family = try #require(fixture.locked(Self.family.id))
        #expect(fixture.questions.lockedVaults == [family])
        #expect(family.text == "Family is locked. Unlock to see its questions.")
        #expect(!fixture.questions.questions.contains { $0.vaultID == Self.family.id })

        // Unlock asks for the passphrase: no Face ID, nothing is stored for Family.
        await fixture.questions.unlockTapped(family)
        #expect(fixture.questions.unlockPrompt == family)
        #expect(fixture.store.prompts.count == 1)

        let wrong = await fixture.questions.unlockQuestions(family, passphrase: "not the passphrase")
        #expect(wrong == "The passphrase does not open this vault.")
        #expect(fixture.questions.unlockPrompt == family)

        let opened = await fixture.questions.unlockQuestions(family, passphrase: PreviewVaultService.passphrase)
        #expect(opened == nil)
        #expect(fixture.questions.unlockPrompt == nil)
        #expect(fixture.questions.lockedVaults.isEmpty)
        #expect(fixture.questions.questions.contains { $0.vaultID == Self.family.id })
        // questions_unlock, not a vault switch: Personal stays selected and open.
        #expect(fixture.vault.vault?.id == Self.personal)
        #expect(fixture.vault.isUnlocked)
        #expect(await fixture.service.questionsUnlocks().last == Self.family.id)
        #expect(fixture.store.stored(vaultID: Self.family.id) == nil)
    }

    @Test("a stored passphrase that does not open the vault keeps it locked, and Unlock asks for the passphrase")
    func wrongStoredPassphrase() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.work.id, passphrase: "an old passphrase")
        try fixture.storeFaceID(Self.family.id)
        await fixture.unlock()

        let work = try #require(fixture.locked(Self.work.id))
        #expect(fixture.questions.lockedVaults == [work])
        await fixture.questions.unlockTapped(work)
        #expect(fixture.questions.unlockPrompt == work)
        #expect(fixture.store.prompts.count == 1, "no second Face ID for a passphrase that failed")

        // The typed passphrase opens it and replaces the stored one for the next Face ID.
        #expect(await fixture.questions.unlockQuestions(work, passphrase: PreviewVaultService.passphrase) == nil)
        #expect(fixture.store.stored(vaultID: Self.work.id) == PreviewVaultService.passphrase)
    }

    @Test("a cancelled Face ID leaves the other vaults locked, each with Unlock")
    func cancelledFaceID() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.work.id)
        try fixture.storeFaceID(Self.family.id)
        fixture.store.cancelsSession = true
        await fixture.unlock()

        #expect(fixture.vault.isUnlocked)
        #expect(Set(fixture.questions.lockedVaults.map(\.id)) == [Self.work.id, Self.family.id])
        #expect(await fixture.service.questionsUnlocks().isEmpty)

        // Unlock in a row asks Face ID again for that vault only.
        fixture.store.cancelsSession = false
        await fixture.questions.unlockTapped(try #require(fixture.locked(Self.work.id)))
        #expect(fixture.store.prompts == ["Read the questions of 2 other vaults", "Read the questions of “Work”"])
        #expect(fixture.questions.lockedVaults.map(\.id) == [Self.family.id])
        #expect(fixture.questions.unlockPrompt == nil)
    }

    @Test("a notification for a closed vault asks to unlock it, then opens its question")
    func notificationAsksToUnlock() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.work.id)
        await fixture.unlock()
        let family = try #require(fixture.locked(Self.family.id))

        fixture.questions.notificationOpened()
        let before = fixture.questions.focusRequests
        #expect(await fixture.questions.takeFocus(stillFree: { true }) == nil)
        #expect(fixture.questions.unlockPrompt == family)

        #expect(await fixture.questions.unlockQuestions(family, passphrase: PreviewVaultService.passphrase) == nil)
        // The sheet closes (its onDismiss), and the round goes on.
        fixture.questions.unlockPromptClosed()
        #expect(fixture.questions.focusRequests == before + 1)
        let qid = await fixture.questions.takeFocus(stillFree: { true })
        #expect(qid == fixture.familyQuestion.qid)
        #expect(fixture.questions.questions.first { $0.qid == qid }?.vaultID == Self.family.id)
    }

    @Test("a notification opens a closed vault with Face ID when its passphrase is stored, then its question")
    func notificationUsesFaceID() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.work.id)
        try fixture.storeFaceID(Self.family.id)
        fixture.store.cancelsSession = true
        await fixture.unlock()
        #expect(fixture.questions.lockedVaults.count == 2)

        fixture.store.cancelsSession = false
        fixture.questions.notificationOpened()
        let qid = await fixture.questions.takeFocus(stillFree: { true })
        #expect(qid == fixture.familyQuestion.qid)
        #expect(fixture.store.prompts.count == 2)
        #expect(fixture.questions.unlockPrompt == nil)
        #expect(fixture.questions.lockedVaults.isEmpty)
    }

    @Test("a cancelled sheet of a notification still opens the newest question of the open vaults")
    func notificationSheetCancelled() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.work.id)
        await fixture.unlock()

        fixture.questions.notificationOpened()
        #expect(await fixture.questions.takeFocus(stillFree: { true }) == nil)
        #expect(fixture.questions.unlockPrompt?.id == Self.family.id)
        fixture.questions.unlockPromptClosed()
        #expect(await fixture.questions.takeFocus(stillFree: { true }) == fixture.workQuestion.qid)
        #expect(fixture.questions.unlockPrompt == nil)
    }

    @Test("a lock shows every vault as locked, and drops every question")
    func lockShowsEveryVaultLocked() async throws {
        let fixture = try await Fixture()
        try fixture.storeFaceID(Self.work.id)
        try fixture.storeFaceID(Self.family.id)
        await fixture.unlock()
        #expect(fixture.questions.lockedVaults.isEmpty)

        await fixture.vault.lock()
        #expect(fixture.questions.phase == .locked)
        #expect(fixture.questions.questions.isEmpty)
        #expect(fixture.questions.vaults.isEmpty)
        #expect(Set(fixture.questions.lockedVaults.map(\.id)) == [Self.personal, Self.work.id, Self.family.id])
        #expect(await fixture.contexts() == [Self.work.id: false, Self.family.id: false])

        // The list read again says the same.
        await fixture.questions.refresh()
        #expect(fixture.questions.phase == .locked)
        #expect(fixture.questions.lockedVaults.count == 3)
    }

    @Test("the passphrase sheet closes when the app leaves the screen, and the work stops")
    func backgroundClosesTheSheet() async throws {
        let fixture = try await Fixture()
        await fixture.unlock()
        let work = try #require(fixture.locked(Self.work.id))
        await fixture.questions.unlockTapped(work)
        #expect(fixture.questions.unlockPrompt == work)

        fixture.vault.enterBackground()
        #expect(fixture.questions.unlockPrompt == nil)
        await fixture.vault.settle()
    }
}
