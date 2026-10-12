import Foundation
import Testing

@testable import ApassyVaultKit

/// The models of questions through the relay (ios-core-v1 section 5.10). Synthetic values of the
/// contract's test vectors.
@Suite struct QuestionModelTests {
    @Test func aListOfTheCoreDecodes() throws {
        let json = """
            {"status": {"enabled": true, "team_id": "t_7k2m5q4x3c", "relay_device_id": 2,
              "device_uuid": "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
              "answer_key": "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts",
              "has_key": true},
             "questions": [
              {"qid": "oKGio6SlpqeoqaqrrK2urw", "state": "open", "asker_name": "MacBook Pro",
               "created_at": 1790000001, "expires_at": 1790000300, "problem": null, "settle": null,
               "answered": "deny",
               "card": {"asker_device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", "created_at": 1790000000,
                 "digest": "f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d",
                 "run": {"id": "123456789012345", "agent": "claude-code", "command": ["npm", "run", "migrate"],
                   "cwd": "/tmp/synthetic-shop", "env_names": ["DATABASE_URL"], "purpose": "p", "risk": "r",
                   "user_request": "u", "request_source": "s", "agent_request": "a",
                   "remember": {"pattern": "npm run migrate", "approvals": 1, "needed": 3}},
                 "question": {"items": [{"item_id": "9", "name": "API token", "production": false,
                     "unconfirmed": true, "always_ask": false}],
                   "project": {"key": "/tmp/synthetic-shop/.git", "label": "synthetic-shop"},
                   "action": "deploy", "production": true, "why": "w",
                   "valid_answers": ["once", "production:deploy", "correct_environment"]}}},
              {"qid": "AAAAAAAAAAAAAAAAAAAAAA", "state": "settled", "asker_name": "MacBook Pro",
               "created_at": 1790000001, "expires_at": 1790000300,
               "problem": "Sync this vault to read this question.", "card": null, "answered": null,
               "settle": {"outcome": "approved", "device_name": "Test iPhone", "device_kind": "iphone",
                 "kind": "allow_production", "at": 1790000031, "replaced_by": null}}]}
            """
        let list = try JSONDecoder().decode(QuestionsList.self, from: Data(json.utf8))
        #expect(list.status.enabled)
        #expect(list.status.relayDeviceID == 2)
        #expect(list.status.answerKey?.count == 65)
        let open = list.questions[0]
        #expect(open.state == .open)
        #expect(open.answered == .deny)
        #expect(open.card?.run.remember?.needed == 3)
        #expect(open.card?.question.action == .deploy)
        #expect(open.card?.question.items[0].unconfirmed == true)
        let settled = list.questions[1]
        #expect(settled.card == nil)
        #expect(settled.problem == "Sync this vault to read this question.")
        #expect(settled.settle?.deviceName == "Test iPhone")
    }

    @Test func theCoreAnswersOfAnAnswerDecode() throws {
        let prepared = try JSONDecoder().decode(
            PreparedAnswer.self,
            from: Data(#"{"time": 1790000030, "answer_string": "apassy-question-answer-v1\nx", "needs_face_id": true}"#.utf8))
        #expect(prepared.needsFaceID)
        #expect(prepared.answerString.hasPrefix("apassy-question-answer-v1\n"))
        let sent = try JSONDecoder().decode(
            SentAnswer.self, from: Data(#"{"id": 7, "at": 1790000032, "kind": "allow_production"}"#.utf8))
        #expect(sent.kind == .allowProduction)
        let attach = try JSONDecoder().decode(
            AttachInfo.self,
            from: Data(#"{"state": "attached", "team": "Notifications", "words": ["a", "b"], "expires_at": 1}"#.utf8))
        #expect(attach.state == .attached)
    }

    /// Contract section 5.3: Face ID for the answers that give authority, none for the others.
    @Test func onlyTheAnswersThatGiveAuthorityNeedFaceID() {
        #expect(RemoteAnswer(kind: .approveOnce).needsFaceID)
        #expect(RemoteAnswer(kind: .approveInProject).needsFaceID)
        #expect(RemoteAnswer(kind: .allowProduction).needsFaceID)
        #expect(RemoteAnswer(kind: .correctEnvironment, itemID: "9", environment: .development).needsFaceID)
        #expect(!RemoteAnswer(kind: .correctEnvironment, itemID: "9", environment: .production).needsFaceID)
        for kind in [AnswerKind.deny, .neverForAgent, .alwaysAskForAgent, .disconnect] {
            #expect(!RemoteAnswer(kind: kind).needsFaceID)
        }
        let params = RemoteAnswer(kind: .correctEnvironment, itemID: "9", environment: .development).parameters
        #expect(params["kind"] as? String == "correct_environment")
        #expect(params["item_id"] as? String == "9")
        #expect(params["environment"] as? String == "development")
        #expect(RemoteAnswer(kind: .deny).parameters.count == 1)
    }

    @Test func base64URLRoundTripsWithoutPadding() {
        let key = "BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts"
        let data = Base64URL.decode(key)
        #expect(data?.count == 65)
        #expect(data.map(Base64URL.encode) == key)
        #expect(Base64URL.decode("AA==") == nil)
        #expect(Base64URL.decode("a+b/") == nil)
    }

    @Test func thePreviewServiceTakesAnAnswerOnlyWithItsSignature() async throws {
        let service = PreviewVaultService()
        #expect(try await service.questionsList() == .off)
        await #expect(throws: VaultError.self) {
            try await service.answerKeyRegister(publicKey: Data([4] + [UInt8](repeating: 1, count: 64)))
        }
        let question = PreviewVaultService.sampleQuestion()
        await service.setQuestions(enabled: true, questions: [question])
        _ = try await service.answerKeyRegister(publicKey: Data([4] + [UInt8](repeating: 1, count: 64)))
        let prepared = try await service.questionAnswerString(
            qid: question.qid, answer: RemoteAnswer(kind: .allowProduction))
        #expect(prepared.needsFaceID)
        #expect(prepared.answerString.contains("\nallow_production:deploy:/tmp/synthetic-shop/.git\n"))
        await #expect(throws: VaultError.self) {
            try await service.questionAnswer(
                qid: question.qid, answer: RemoteAnswer(kind: .allowProduction), time: prepared.time, signature: nil)
        }
        let sent = try await service.questionAnswer(
            qid: question.qid, answer: RemoteAnswer(kind: .deny), time: prepared.time, signature: nil)
        #expect(sent.kind == .deny)
        await service.settleQuestion(qid: question.qid, by: "Test iPhone")
        do {
            _ = try await service.questionAnswer(
                qid: question.qid, answer: RemoteAnswer(kind: .deny), time: prepared.time, signature: nil)
            Issue.record("a settled question took an answer")
        } catch let error as VaultError {
            #expect(error.code == .alreadyAnswered)
        }
    }
}
