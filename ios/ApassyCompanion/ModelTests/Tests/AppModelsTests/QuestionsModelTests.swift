import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Synchronization
import Testing

@testable import AppModels

/// An answer key in memory: it counts the signatures and their reasons, and fails as told.
final class ScriptedSigner: AnswerSigner {
    private struct State {
        var key = Data([4] + [UInt8](repeating: 1, count: 64))
        var reasons: [String] = []
        var failure: CompanionKeyError?
        var renewals = 0
    }

    private let state = Mutex(State())

    var reasons: [String] { state.withLock { $0.reasons } }
    var renewals: Int { state.withLock { $0.renewals } }
    var key: Data { state.withLock { $0.key } }

    func fail(with error: CompanionKeyError?) { state.withLock { $0.failure = error } }

    func publicKey() throws -> Data { state.withLock { $0.key } }

    func sign(_ message: Data, reason: String) async throws -> Data {
        try state.withLock { state in
            state.reasons.append(reason)
            if let failure = state.failure { throw failure }
            return Data("signature".utf8)
        }
    }

    func renew() throws -> Data {
        state.withLock { state in
            state.renewals += 1
            state.key = Data([4] + [UInt8](repeating: 2, count: 64))
            state.failure = nil
            return state.key
        }
    }
}

@MainActor
final class ScriptedPush: PushPermission {
    var allows: Bool
    private(set) var asked = 0
    private(set) var registrations = 0
    let environment = PushEnvironment.development

    init(allows: Bool) { self.allows = allows }

    func requestAuthorization() async -> Bool {
        asked += 1
        return allows
    }

    func registerForPushes() { registrations += 1 }
}

@MainActor
@Suite("QuestionsModel")
struct QuestionsModelTests {
    @MainActor
    final class Fixture {
        let service = PreviewVaultService()
        let signer = ScriptedSigner()
        let push: ScriptedPush
        let defaults: UserDefaults
        let model: QuestionsModel

        init(allows: Bool = true) {
            push = ScriptedPush(allows: allows)
            let suite = "questions-\(UUID().uuidString)"
            defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            model = QuestionsModel(
                service: service, signer: signer, push: push, deviceName: "Test iPhone", defaults: defaults,
                retryInterval: .milliseconds(10))
        }

        func withQuestion() async -> RemoteQuestion {
            let question = PreviewVaultService.sampleQuestion()
            await service.setQuestions(enabled: true, questions: [question])
            await model.refresh()
            return question
        }
    }

    private static func card(validAnswers: [String], project: Bool = true, unconfirmed: Bool = true) -> QuestionCard {
        var card = PreviewVaultService.sampleQuestion().card!
        card.question.validAnswers = validAnswers
        if !project { card.question.project = nil }
        if !unconfirmed { card.question.items = card.question.items.map { var item = $0; item.unconfirmed = false; return item } }
        return card
    }

    // MARK: The answer bar (ADR 0026)

    @Test("the bar of a production question: Allow production first, the rest in the menu")
    func productionBar() {
        let bar = AnswerBar.make(for: PreviewVaultService.sampleQuestion().card!)
        #expect(bar.primary?.label == "Allow production: Deploy in synthetic-shop")
        #expect(bar.primary?.answer == RemoteAnswer(kind: .allowProduction))
        #expect(bar.allowOnce?.answer.kind == .approveOnce)
        #expect(bar.deny.answer.kind == .deny)
        #expect(bar.menu.map(\.label) == [
            "Development", "Production", "Not for this agent", "Always ask for this agent", "Disconnect",
        ])
        #expect(bar.menu[0].answer == RemoteAnswer(kind: .correctEnvironment, itemID: "9", environment: .development))
        #expect(bar.menu.last?.destructive == true)
    }

    @Test("a project answer, a correction, and a question without a project")
    func otherBars() {
        let project = AnswerBar.make(for: Self.card(validAnswers: ["once", "in_project:deploy"]))
        #expect(project.primary?.label == "Allow Deploy in synthetic-shop")
        #expect(project.menu.isEmpty)
        let correction = AnswerBar.make(for: Self.card(validAnswers: ["correct_environment"]))
        #expect(correction.primary?.label == "Development")
        #expect(correction.allowOnce == nil)
        #expect(correction.menu.map(\.label) == ["Production"])
        let noProject = AnswerBar.make(for: Self.card(validAnswers: ["once", "in_project:deploy"], project: false))
        #expect(noProject.primary == nil)
        let confirmed = AnswerBar.make(for: Self.card(validAnswers: ["correct_environment"], unconfirmed: false))
        #expect(confirmed.primary == nil)
        #expect(confirmed.menu.isEmpty)
    }

    @Test("the Face ID reason names the agent without control characters or quotes, and the answer")
    func faceIDReason() {
        #expect(
            QuestionsModel.faceIDReason(agent: "claude-code", answer: "Allow Once")
                == "answer a question of agent \"claude-code\": Allow Once")
        let long = QuestionsModel.faceIDReason(agent: "a\"b\nc" + String(repeating: "x", count: 60), answer: "Deny")
        #expect(long == "answer a question of agent \"abc\(String(repeating: "x", count: 37))\": Deny")
    }

    // MARK: States

    @Test("off without a team; ready with one, and the answer key is registered once")
    func registersTheAnswerKeyOnce() async {
        let fixture = Fixture()
        await fixture.model.refresh()
        #expect(fixture.model.phase == .off)
        #expect(await fixture.service.answerKeyRegistrations() == 0)
        _ = await fixture.withQuestion()
        #expect(fixture.model.phase == .ready)
        #expect(fixture.model.waitingCount == 1)
        #expect(await fixture.service.registeredAnswerKey() == fixture.signer.key)
        await fixture.model.refresh()
        #expect(await fixture.service.answerKeyRegistrations() == 1)
    }

    @Test("an answer that gives authority asks for Face ID and sends the signature")
    func approvingNeedsFaceID() async throws {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        let bar = AnswerBar.make(for: question.card!)
        await fixture.model.send(bar.primary!, for: fixture.model.questions[0])
        #expect(fixture.signer.reasons == [
            "answer a question of agent \"claude-code\": Allow production: Deploy in synthetic-shop"
        ])
        let sent = await fixture.service.sentAnswers()
        #expect(sent.map(\.answer.kind) == [.allowProduction])
        #expect(sent[0].signature == Data("signature".utf8))
        #expect(fixture.model.deliveries[question.qid] == .sent(.allowProduction))
        #expect(fixture.model.deliveryText(for: fixture.model.questions[0]) == "Sent. Waiting for MacBook Pro…")
    }

    @Test("Deny and the stricter answers go without Face ID")
    func stricterAnswersNeedNoFaceID() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        let bar = AnswerBar.make(for: question.card!)
        await fixture.model.send(bar.deny, for: fixture.model.questions[0])
        let disconnect = bar.menu.first { $0.answer.kind == .disconnect }!
        await fixture.model.send(disconnect, for: fixture.model.questions[0])
        let production = bar.menu.first { $0.answer.environment == .production }!
        await fixture.model.send(production, for: fixture.model.questions[0])
        #expect(fixture.signer.reasons.isEmpty)
        let sent = await fixture.service.sentAnswers()
        #expect(sent.map(\.answer.kind) == [.deny, .disconnect, .correctEnvironment])
        #expect(sent.allSatisfy { $0.signature == nil })
    }

    @Test("a cancelled Face ID sends nothing")
    func cancelledFaceID() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        fixture.signer.fail(with: .cancelled)
        await fixture.model.send(AnswerBar.make(for: question.card!).allowOnce!, for: fixture.model.questions[0])
        #expect(await fixture.service.sentAnswers().isEmpty)
        #expect(fixture.model.deliveries[question.qid] == nil)
    }

    @Test("a new Face ID enrollment makes a new answer key and registers it")
    func biometryChanged() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        fixture.signer.fail(with: .biometryChanged)
        await fixture.model.send(AnswerBar.make(for: question.card!).allowOnce!, for: fixture.model.questions[0])
        #expect(await fixture.service.sentAnswers().isEmpty)
        #expect(fixture.signer.renewals == 1)
        #expect(await fixture.service.registeredAnswerKey() == fixture.signer.key)
        guard case .failed(let message) = fixture.model.deliveries[question.qid] else {
            Issue.record("no failure shown")
            return
        }
        #expect(message.contains("Face ID changed"))
    }

    @Test("a network failure sends the same answer again; a settled question says so")
    func retriesAndLateAnswers() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        await fixture.service.failNextAnswer(VaultError(.relayUnreachable, "The relay is not reachable."))
        await fixture.model.send(AnswerBar.make(for: question.card!).deny, for: fixture.model.questions[0])
        #expect(await fixture.service.sentAnswers().count == 1)
        #expect(fixture.model.deliveries[question.qid] == .sent(.deny))

        await fixture.service.failNextAnswer(VaultError(.alreadyAnswered, "Already answered on another device."))
        await fixture.model.send(AnswerBar.make(for: question.card!).deny, for: fixture.model.questions[0])
        #expect(fixture.model.deliveries[question.qid] == .failed("Already answered."))

        await fixture.service.settleQuestion(qid: question.qid, by: "Test iPhone")
        await fixture.model.refresh()
        #expect(fixture.model.waitingCount == 0)
        #expect(fixture.model.deliveryText(for: fixture.model.questions[0]) == "Answered on Test iPhone")
    }

    // MARK: Notifications

    @Test("notifications ask for permission when turned on, and the token goes to the relay")
    func notifications() async {
        let refused = Fixture(allows: false)
        _ = await refused.withQuestion()
        await refused.model.setNotifications(true)
        #expect(refused.push.asked == 1)
        #expect(!refused.model.notificationsOn)
        #expect(refused.push.registrations == 0)
        #expect(refused.model.notice?.contains("Notifications are off") == true)

        let fixture = Fixture()
        _ = await fixture.withQuestion()
        #expect(fixture.push.asked == 0)
        await fixture.model.setNotifications(true)
        #expect(fixture.model.notificationsOn)
        #expect(fixture.defaults.bool(forKey: QuestionsModel.notificationsKey))
        #expect(fixture.push.registrations == 1)
        await fixture.model.receivePushToken(Data([1, 2, 3]))
        #expect(await fixture.service.currentPushToken() == Data([1, 2, 3]))
        await fixture.model.setNotifications(false)
        #expect(await fixture.service.currentPushToken() == nil)
        await fixture.model.receivePushToken(Data([4]))
        #expect(await fixture.service.currentPushToken() == nil)
    }

    // MARK: Connecting a vault from iCloud Drive

    @Test("a device link connects the vault after the Mac confirms")
    func attach() async {
        let fixture = Fixture()
        await fixture.model.refresh()
        #expect(fixture.model.phase == .off)
        await fixture.model.startAttach(link: "not a link")
        guard case .failed = fixture.model.attach else {
            Issue.record("a text that is not a link started")
            return
        }
        await fixture.model.startAttach(
            link: "https://apassy-relay.example/link#apassy_lnk_t_7k2m5q4x3c_00", pollInterval: .milliseconds(10))
        guard case .waiting(let info) = fixture.model.attach else {
            Issue.record("no words shown")
            return
        }
        #expect(info.words == ["amber", "marble"])
        await fixture.model.attachFinished()
        #expect(fixture.model.attach == .attached)
        #expect(fixture.model.phase == .ready)
        #expect(await fixture.service.registeredAnswerKey() == fixture.signer.key)
    }
}
