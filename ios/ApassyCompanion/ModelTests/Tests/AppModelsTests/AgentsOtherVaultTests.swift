import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// "Remove" on the agents of a vault that is not selected (contract ios-core-v1 section 5.12,
/// `can_act`): the core cannot act on a feed that came after the keys of that vault were last read.
/// With its passphrase behind Face ID, the tap reads the keys again first (`questions_unlock`, one
/// Face ID that names the vault), then the list; the confirmation shows only when the core can act
/// on it now. Nothing is prepared or signed before. No value is real.
@MainActor
@Suite("Agents of a vault that is not selected")
struct AgentsOtherVaultTests {
    static let work = (id: PreviewVaultService.workFeedVaultID, name: "Work", team: "t_wq3k7m2p5x")

    @MainActor
    final class Fixture {
        let service = PreviewVaultService(empty: false, unlocked: false)
        let store = MemoryPassphraseStore()
        let settings = makeSettings()
        let vault: VaultModel
        let questions: QuestionsModel
        let agents: AgentsModel

        /// Personal is selected and unlocked; Work is on this iPhone with its questions open, and its
        /// Mac sent a feed after that (`can_act: false`). With `stored`, Work's passphrase is behind
        /// Face ID.
        init(stored: Bool) async throws {
            let suite = "agents-other-vault-\(UUID().uuidString)"
            let defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            let keys = ScriptedKeyStore()
            keys.add(service: TeamAnswerSigners.service(team: AgentsModelTests.personalTeam))
            keys.add(service: TeamAnswerSigners.service(team: AgentsOtherVaultTests.work.team))
            let signers = TeamAnswerSigners(store: keys)
            await service.setQuestions(enabled: true, answerKey: try signers.joinKey(team: AgentsModelTests.personalTeam))
            await service.addQuestionsVault(
                id: AgentsOtherVaultTests.work.id, name: AgentsOtherVaultTests.work.name,
                team: AgentsOtherVaultTests.work.team,
                answerKey: try signers.joinKey(team: AgentsOtherVaultTests.work.team), onPhone: true, open: false)
            (vault, _) = makeVault(service: service, store: store, settings: settings)
            questions = QuestionsModel(
                service: service, signers: signers, push: ScriptedPush(allows: true), deviceName: "Test iPhone",
                defaults: defaults, retryInterval: .milliseconds(10))
            questions.follow(vault)
            agents = AgentsModel(
                service: service, signers: signers, keys: questions.agentKeys, retryInterval: .milliseconds(10),
                actionWait: 0)
            await vault.start()
            await vault.unlock(passphrase: PreviewVaultService.passphrase)
            await questions.reopenFinished()
            // Work's questions open with its typed passphrase, so no Face ID was asked yet.
            #expect(await questions.unlockQuestions(LockedVault(id: work.id, name: work.name),
                passphrase: PreviewVaultService.passphrase) == nil)
            if stored {
                try store.save(PreviewVaultService.passphrase, vaultID: work.id)
                settings.setFaceIDUnlock(true, vaultID: work.id)
            }
            // Then Work's Mac sent a feed: the core cannot act on it.
            var feed = PreviewVaultService.sampleFeed()
            for mac in feed[1].macs.indices { feed[1].macs[mac].canAct = false }
            await service.setFeed(feed)
            await agents.refresh()
        }

        var work: (id: String, name: String, team: String) { AgentsOtherVaultTests.work }

        func entry() throws -> AgentEntry {
            try #require(
                agents.sections.first { $0.vaultName == "Work" }?.agents.first { $0.agent.name == "Claude Code" })
        }

        func only() throws -> FeedException {
            try #require(try entry().agent.exceptions.first { $0.kind == .only })
        }

        func unlocks() async -> Int { await service.questionsUnlocks().filter { $0 == work.id }.count }
    }

    @Test("a stored passphrase: Remove reads the keys again with Face ID, then asks, then sends")
    func storedPassphraseReadsTheKeysFirst() async throws {
        let fixture = try await Fixture(stored: true)
        let entry = try fixture.entry()
        let only = try fixture.only()
        #expect(!entry.mac.canAct)
        #expect(fixture.agents.removalBlock(of: only, in: entry) == nil, "Remove shows")
        let before = await fixture.unlocks()

        // Nothing is prepared before the keys are read again.
        await fixture.agents.remove(only, in: entry)
        #expect(await fixture.service.preparedFeedActions().isEmpty)

        let asks = await fixture.agents.removeTapped(only, in: entry)

        #expect(asks, "the confirmation shows")
        #expect(fixture.store.prompts == ["Unlock the questions of Work to remove this exception"])
        #expect(await fixture.unlocks() == before + 1)
        #expect(await fixture.service.preparedFeedActions().isEmpty, "nothing prepared before the confirmation")
        #expect(fixture.agents.removals.isEmpty)
        let fresh = try fixture.entry()
        #expect(fresh.mac.canAct)

        // The owner confirms: the usual removal.
        await fixture.agents.remove(only, in: fresh)
        let sent = try #require(await fixture.service.sentFeedActions().first)
        #expect(sent.removal.vaultID == fixture.work.id)
        let removal = try #require(fixture.agents.removal(of: only, in: fresh))
        #expect(fixture.agents.removals[removal] == .removed("Removed on MacBook Pro."))
        // The selected vault did not change.
        #expect(fixture.vault.vault?.id == previewVaultID)
    }

    @Test("no stored passphrase: Remove does not show, and the note says to select the vault")
    func noPassphraseKeepsTheNote() async throws {
        let fixture = try await Fixture(stored: false)
        let entry = try fixture.entry()
        let only = try fixture.only()
        #expect(
            fixture.agents.removalBlock(of: only, in: entry)
                == "Select Work on this iPhone to remove exceptions of its agents.")
        let before = await fixture.unlocks()
        #expect(await fixture.agents.removeTapped(only, in: entry) == false)
        await fixture.agents.remove(only, in: entry)
        #expect(fixture.store.prompts.isEmpty)
        #expect(await fixture.unlocks() == before)
        #expect(await fixture.service.preparedFeedActions().isEmpty)
        #expect(await fixture.service.sentFeedActions().isEmpty)
    }

    @Test("a cancelled Face ID does nothing")
    func cancelledFaceIDDoesNothing() async throws {
        let fixture = try await Fixture(stored: true)
        fixture.store.cancelsSession = true
        let entry = try fixture.entry()
        let only = try fixture.only()
        let before = await fixture.unlocks()
        let lists = await fixture.service.feedListCalls()

        #expect(await fixture.agents.removeTapped(only, in: entry) == false)

        #expect(fixture.store.prompts == ["Unlock the questions of Work to remove this exception"])
        #expect(await fixture.unlocks() == before)
        #expect(await fixture.service.feedListCalls() == lists, "not even the list")
        #expect(fixture.agents.removals.isEmpty, "no line")
        #expect(await fixture.service.preparedFeedActions().isEmpty)
        #expect(try !fixture.entry().mac.canAct)
        // Remove still shows: the passphrase did not fail.
        #expect(fixture.agents.removalBlock(of: only, in: entry) == nil)
    }

    @Test("still stale after the keys were read again: the list changed")
    func stillStaleSaysTheListChanged() async throws {
        let fixture = try await Fixture(stored: true)
        await fixture.service.scriptFeedCanActAfterUnlock(false)
        let entry = try fixture.entry()
        let only = try fixture.only()
        let before = await fixture.unlocks()

        #expect(await fixture.agents.removeTapped(only, in: entry) == false)

        #expect(await fixture.unlocks() == before + 1)
        let removal = try #require(fixture.agents.removal(of: only, in: entry))
        #expect(fixture.agents.removals[removal] == .failed("The list on MacBook Pro changed. Look at it again."))
        #expect(await fixture.service.preparedFeedActions().isEmpty)
        #expect(await fixture.service.sentFeedActions().isEmpty)
    }

    @Test("a stored passphrase that does not open the vault: the note to select it")
    func wrongStoredPassphraseFails() async throws {
        let fixture = try await Fixture(stored: true)
        try fixture.store.save("not the passphrase", vaultID: fixture.work.id)
        let entry = try fixture.entry()
        let only = try fixture.only()

        #expect(await fixture.agents.removeTapped(only, in: entry) == false)

        let removal = try #require(fixture.agents.removal(of: only, in: entry))
        #expect(
            fixture.agents.removals[removal]
                == .failed("Face ID did not open Work. Select Work on this iPhone to remove exceptions of its agents."))
        #expect(await fixture.service.preparedFeedActions().isEmpty)
        // Face ID is not offered again for it: Remove gives way to the note.
        #expect(
            fixture.agents.removalBlock(of: only, in: entry)
                == "Select Work on this iPhone to remove exceptions of its agents.")
    }
}
