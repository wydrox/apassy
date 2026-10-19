import ApassyVaultKit
import Foundation
import Testing

@testable import ApassyVaultCore

/// The question calls over the real core (macOS slice). The relay flows are in the core's own
/// tests (`ios/ApassyCore/tests/questions_flow.rs`); here the wire of the Swift side.
@Suite struct CoreQuestionsTests {
    @Test func aVaultWithoutATeamHasNoQuestions() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app,
            historyKeyStore: CoreTestHistoryKeys().store)
        let vault = try await core.createLocalVault(name: "Personal", passphrase: "synthetic-swift-pass")

        // A core that keeps the questions of every vault lists none: no vault has a context.
        let list = try await core.questionsList()
        #expect(list.status == .off)
        #expect(list.questions.isEmpty)
        #expect(list.vaults ?? [] == [])
        #expect(try await core.questionsWait(timeout: 1) == false)
        let key = Data([4] + [UInt8](repeating: 7, count: 64))
        do {
            _ = try await core.answerKeyRegister(publicKey: key)
            Issue.record("a vault without a team registered an answer key")
        } catch let error as VaultError {
            #expect(error.code == .noQuestions)
        }
        do {
            _ = try await core.questionAnswer(
                qid: "oKGio6SlpqeoqaqrrK2urw", answer: RemoteAnswer(kind: .deny),
                time: Int64(Date().timeIntervalSince1970), signature: nil)
            Issue.record("an answer went without a team")
        } catch let error as VaultError {
            #expect(error.code == .noQuestions)
        }
        // The vault of the question goes as `vault_id`: this vault has no team, and a vault
        // that is not on this iPhone is `no_vault`.
        do {
            _ = try await core.questionAnswerString(
                qid: "oKGio6SlpqeoqaqrrK2urw", answer: RemoteAnswer(kind: .deny), vaultID: vault.id)
            Issue.record("an answer string was made without a team")
        } catch let error as VaultError {
            #expect(error.code == .noQuestions, "\(error)")
        }
        do {
            _ = try await core.questionAnswerString(
                qid: "oKGio6SlpqeoqaqrrK2urw", answer: RemoteAnswer(kind: .deny),
                vaultID: "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c")
            Issue.record("an answer string was made for a vault that is not on this iPhone")
        } catch let error as VaultError {
            #expect(error.code == .noVault, "\(error)")
        }
        do {
            _ = try await core.joinAttach(link: "not a link", deviceName: "Test iPhone", answerKey: key)
            Issue.record("a text that is not a link started a connection")
        } catch let error as VaultError {
            #expect(error.code == .linkInvalid)
        }

        try await core.lock()
        do {
            _ = try await core.questionsList()
            Issue.record("a locked vault listed questions")
        } catch let error as VaultError {
            #expect(error.code == .locked)
        }
    }

    @Test func theAutoFillExtensionCannotAnswer() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "apassy-core-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let historyKeys = CoreTestHistoryKeys()
        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .autofill,
            historyKeyStore: historyKeys.store)
        do {
            _ = try await core.questionsList()
            Issue.record("AutoFill listed questions")
        } catch let error as VaultError {
            #expect(error.code == .notAllowed)
        }
        do {
            _ = try await core.requestHistory()
            Issue.record("AutoFill read request history")
        } catch let error as VaultError {
            #expect(error.code == .notAllowed)
        }
        #expect(historyKeys.snapshot.readVaultIDs.isEmpty)
        #expect(historyKeys.snapshot.generationCount == 0)
    }
}
