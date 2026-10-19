import Foundation
import Testing
@testable import ApassyVaultKit

@Suite struct RequestHistoryTests {
    private let vaultID = "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c"

    @Test func acceptedDeliveryNeverDecodesAsApproval() throws {
        let data = Data("""
            {"vaults":[{"vault_id":"vault","vault_name":"Synthetic","availability":"available","entries":[
            {"id":"relay:vault:qid","vault_id":"vault","qid":"qid","source":"relay","title":"API token",
            "agent":"test-agent","project":"test","action":"deploy","production":true,"device_name":"Test Mac",
            "first_seen_at":1800000000,"last_seen_at":1800000001,"expires_at":1800000010,
            "selected_kind":"approve_once","sent_at":1800000001,"outcome":null}]}],
            "retention_days":30,"max_entries_per_vault":1000}
            """.utf8)
        let snapshot = try JSONDecoder().decode(RequestHistorySnapshot.self, from: data)
        #expect(snapshot.vaults[0].entries[0].sentAt != nil)
        #expect(snapshot.vaults[0].entries[0].outcome == nil)
        #expect(snapshot.vaults[0].entries[0].confirmedAt == nil)
        #expect(snapshot.retentionDays == 30)
    }

    @Test func lockedScopeDiscardsRowsEvenFromAnIncorrectHost() throws {
        let data = Data("""
            {"vault_id":"vault","vault_name":"Synthetic","availability":"locked","entries":[{"private":"do not decode"}]}
            """.utf8)
        let vault = try JSONDecoder().decode(RequestHistoryVault.self, from: data)
        #expect(vault.entries.isEmpty)
        #expect(vault.availability == .locked)
    }

    @Test func previewLockHidesSavedFixtureAndUnlockRestoresItThenClearDeletes() async throws {
        let service = PreviewVaultService()
        let entry = RequestHistoryEntry(id: "relay:\(vaultID):qid", vaultID: vaultID, qid: "qid",
                                        title: "Synthetic API token", agent: "agent", action: "deploy", production: true,
                                        deviceName: "Test Mac", firstSeenAt: 1_800_000_000,
                                        lastSeenAt: 1_800_000_000, expiresAt: 1_800_000_300)
        await service.setRequestHistory([RequestHistoryVault(vaultID: vaultID, vaultName: "Personal",
                                                            availability: .available, entries: [entry])])
        #expect(try await service.requestHistory().vaults[0].entries.count == 1)
        try await service.lock()
        #expect(try await service.requestHistory().vaults[0].availability == .locked)
        #expect(try await service.requestHistory().vaults[0].entries.isEmpty)
        try await service.unlock(passphrase: PreviewVaultService.passphrase, keep: false)
        #expect(try await service.requestHistory().vaults[0].entries.count == 1)
        try await service.clearRequestHistory(vaultID: vaultID)
        #expect(try await service.requestHistory().vaults[0].entries.isEmpty)
    }

    @Test func previewCanReportOwnVaultScopeWithoutAnotherVault() async throws {
        let service = PreviewVaultService()
        await service.setQuestions(enabled: true, questions: [PreviewVaultService.sampleQuestion()])
        let legacy = try await service.questionsList()
        #expect(legacy.vaults == nil)
        #expect(legacy.questions[0].vaultID == nil)
        await service.setQuestionsReportVaultScope(true)
        let scoped = try await service.questionsList()
        #expect(scoped.vaults?.count == 1)
        #expect(scoped.vaults?.first?.vaultID == vaultID)
        #expect(scoped.vaults?.first?.vaultName == "Personal")
        #expect(scoped.questions[0].vaultID == vaultID)
        #expect(scoped.questions[0].vaultName == "Personal")
    }

    @Test func questionVaultKeepsRefreshFailure() throws {
        let data = Data("""
            {"vault_id":"vault","vault_name":"Synthetic","status":{"enabled":true,"has_key":true},"error":"relay_unreachable"}
            """.utf8)
        let vault = try JSONDecoder().decode(QuestionsVault.self, from: data)
        #expect(vault.error == "relay_unreachable")
    }
}
