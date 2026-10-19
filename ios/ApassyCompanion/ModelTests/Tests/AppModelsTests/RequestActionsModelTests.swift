import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@Suite("Request list actions")
struct RequestActionsModelTests {
    private func routine() -> RemoteQuestion {
        var question = PreviewVaultService.sampleQuestion()
        question.vaultID = "synthetic-vault"
        question.vaultName = "Synthetic Vault"
        question.card?.question.action = .read
        question.card?.question.production = false
        question.card?.question.items = [
            QuestionInfo.Item(itemID: "synthetic-item", name: "SYNTHETIC_TOKEN", production: false,
                unconfirmed: false, alwaysAsk: true)
        ]
        question.card?.question.project = QuestionInfo.Project(key: "synthetic", label: "Synthetic")
        question.card?.question.validAnswers = ["once"]
        question.card?.run.command = ["git", "status"]
        question.card?.run.risk = ""
        return question
    }

    @Test("only an explicit fully readable routine Read gets Allow Once")
    func eligibleRead() {
        let actions = RequestListActions.make(for: routine(), current: true)
        #expect(actions.canDeny)
        #expect(actions.canAllowOnce)
        #expect(!actions.reviewOnly)
        #expect(!RequestListActions.make(for: routine(), current: false).canDeny)
    }

    @Test("production, unconfirmed, destructive, unknown and missing scope require Review")
    func conservativeEligibility() {
        let sample = routine()
        var variants: [RemoteQuestion] = []
        var value = sample
        value.vaultID = nil
        variants.append(value)
        value = sample
        value.vaultName = nil
        variants.append(value)
        value = sample
        value.vaultName = "  "
        variants.append(value)
        value = sample
        value.vaultID = "  "
        variants.append(value)
        value = sample
        value.card?.question.production = true
        variants.append(value)
        value = sample
        value.card?.question.items[0].unconfirmed = true
        variants.append(value)
        value = sample
        value.card?.question.items[0].production = true
        variants.append(value)
        value = sample
        value.card?.question.action = .delete
        variants.append(value)
        value = sample
        value.card?.run.command = ["rm", "-rf", "synthetic"]
        variants.append(value)
        value = sample
        value.card?.run.command = ["unknown-program", "read"]
        variants.append(value)
        value = sample
        value.card?.run.command = ["git", "status", "--output=synthetic"]
        variants.append(value)
        value = sample
        value.card?.question.project = nil
        variants.append(value)
        value = sample
        value.card?.question.items = []
        variants.append(value)
        value = sample
        value.card?.question.validAnswers = ["in_project:read"]
        variants.append(value)
        value = sample
        value.card?.run.risk = "Unknown risk"
        variants.append(value)
        for variant in variants {
            let actions = RequestListActions.make(for: variant, current: true)
            #expect(actions.canDeny)
            #expect(!actions.canAllowOnce)
        }
        value = sample
        value.problem = "Unreadable"
        #expect(!RequestListActions.make(for: value, current: true).canAllowOnce)
    }

    @Test("source identities cannot collide through delimiters or equal qids")
    func identities() {
        var a = routine()
        a.vaultID = "a:b"
        a.qid = "c"
        var b = a
        b.vaultID = "a"
        b.qid = "b:c"
        #expect(a.requestIdentity != b.requestIdentity)
        b.qid = a.qid
        #expect(a.requestIdentity != b.requestIdentity)
    }
}
