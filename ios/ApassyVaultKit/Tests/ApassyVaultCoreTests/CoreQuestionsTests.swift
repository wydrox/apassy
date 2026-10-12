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
        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .app)
        _ = try await core.createLocalVault(name: "Personal", passphrase: "synthetic-swift-pass")

        let list = try await core.questionsList()
        #expect(list == .off)
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
        do {
            _ = try await core.joinAttach(link: "not a link", deviceName: "Test iPhone")
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
        let core = try CoreVaultService(dataDirectory: dir, deviceName: "Test iPhone", role: .autofill)
        do {
            _ = try await core.questionsList()
            Issue.record("AutoFill listed questions")
        } catch let error as VaultError {
            #expect(error.code == .notAllowed)
        }
    }
}
