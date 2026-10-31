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
        var beforeSignature: (@Sendable () async -> Void)?
        var renewals = 0
        let renewedKey = Data([4] + [UInt8](repeating: 2, count: 64))
    }

    private let state = Mutex(State())

    var reasons: [String] { state.withLock { $0.reasons } }
    var renewals: Int { state.withLock { $0.renewals } }
    var key: Data { state.withLock { $0.key } }

    func fail(with error: CompanionKeyError?) { state.withLock { $0.failure = error } }

    func beforeSigning(_ action: @escaping @Sendable () async -> Void) {
        state.withLock { $0.beforeSignature = action }
    }

    func publicKey() throws -> Data { state.withLock { $0.key } }

    func sign(_ message: Data, reason: String) async throws -> Data {
        let result = try state.withLock { state in
            state.reasons.append(reason)
            if let failure = state.failure { throw failure }
            return Data("signature".utf8)
        }
        let action = state.withLock { $0.beforeSignature }
        await action?()
        return result
    }

    func renew() throws -> Data {
        state.withLock { state in
            state.renewals += 1
            state.key = state.renewedKey
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
    private var onOpen: (@MainActor () -> Void)?
    let environment = PushEnvironment.development
    var quiet = false
    var delivered: [String] = []
    private(set) var removed: [String] = []
    var afterDeliveredSnapshot: (() -> Void)?
    private(set) var requestsVisible = false
    private(set) var foregroundAlerts: [Bool] = []
    private var onFailure: (@MainActor (String) -> Void)?
    private var onForeground: (@MainActor () -> Void)?
    var holdsAuthorization = false
    var holdsDeliveredSnapshot = false
    private(set) var authorizationReads = 0
    private(set) var deliveredReads = 0
    private var authorizationWaiter: CheckedContinuation<Void, Never>?
    private var deliveredWaiter: CheckedContinuation<Void, Never>?

    func authorization() async -> RequestNotificationAuthorization {
        authorizationReads += 1
        if holdsAuthorization { await withCheckedContinuation { authorizationWaiter = $0 } }
        return allows ? (quiet ? .quiet : .allowed) : .denied
    }
    func releaseAuthorization() {
        holdsAuthorization = false
        authorizationWaiter?.resume()
        authorizationWaiter = nil
    }
    func releaseDeliveredSnapshot() {
        holdsDeliveredSnapshot = false
        deliveredWaiter?.resume()
        deliveredWaiter = nil
    }
    func observeRegistrationFailures(_ handler: @escaping @MainActor (String) -> Void) { onFailure = handler }
    func observeForegroundRequests(_ handler: @escaping @MainActor () -> Void) { onForeground = handler }
    func setRequestsVisible(_ visible: Bool) { requestsVisible = visible }
    func deliveredRequestIdentifiers() async -> [String] {
        deliveredReads += 1
        if holdsDeliveredSnapshot { await withCheckedContinuation { deliveredWaiter = $0 } }
        let snapshot = delivered
        afterDeliveredSnapshot?()
        return snapshot
    }
    func removeDeliveredRequests(identifiers: [String]) { removed += identifiers }
    func failRegistration(_ message: String) { onFailure?(message) }
    func foreground() {
        foregroundAlerts.append(!requestsVisible)
        onForeground?()
    }

    init(allows: Bool) { self.allows = allows }

    func requestAuthorization() async -> Bool {
        asked += 1
        return allows
    }

    func registerForPushes() { registrations += 1 }

    private(set) var unregistrations = 0
    func unregisterForPushes() { unregistrations += 1 }

    func observeOpens(_ handler: @escaping @MainActor () -> Void) { onOpen = handler }

    /// The owner opens a notification.
    func open() { onOpen?() }
}

/// A relay start that ignores task cancellation until the test explicitly releases its response.
/// All unrelated vault operations forward to the in-memory test service.
private actor SuspendedQuestionsAttachService: VaultService {
    enum Completion: CaseIterable, Sendable { case success, relayError, keyError }
    private let inner = SpyVaultService()
    private var response: CheckedContinuation<AttachInfo, any Error>?
    private var started = false
    private var startWaiter: CheckedContinuation<Void, Never>?
    private var cancelWaiter: CheckedContinuation<Void, Never>?
    private(set) var pollCalls = 0
    private(set) var cancelCalls = 0

    func waitForStart() async {
        if started { return }
        await withCheckedContinuation { startWaiter = $0 }
    }

    func waitForCancel() async {
        if cancelCalls > 0 { return }
        await withCheckedContinuation { cancelWaiter = $0 }
    }

    func complete(_ completion: Completion) {
        let continuation = response
        response = nil
        switch completion {
        case .success:
            continuation?.resume(returning: AttachInfo(
                state: .waiting, team: "Notifications", words: ["amber", "marble"], expiresAt: 4_000_000_000))
        case .relayError:
            continuation?.resume(throwing: VaultError(.linkInvalid, "The old relay link was rejected."))
        case .keyError:
            continuation?.resume(throwing: CompanionKeyError.authenticationFailed)
        }
    }

    func joinAttach(link: String, deviceName: String, answerKey: Data) async throws -> AttachInfo {
        try await withCheckedThrowingContinuation { continuation in
            response = continuation
            started = true
            startWaiter?.resume()
            startWaiter = nil
        }
    }
    func joinAttachPoll() async throws -> AttachInfo {
        pollCalls += 1
        throw VaultError(.invalidInput, "An obsolete request must not poll.")
    }
    func joinAttachCancel() async throws {
        cancelCalls += 1
        cancelWaiter?.resume()
        cancelWaiter = nil
    }

    func info() async throws -> CoreInfo { try await inner.info() }
    func select(vaultID: String) async throws { try await inner.select(vaultID: vaultID) }
    func unlock(passphrase: String, keep: Bool) async throws { try await inner.unlock(passphrase: passphrase, keep: keep) }
    func lock() async throws { try await inner.lock() }
    func suspend() async throws { try await inner.suspend() }
    func resume() async throws -> Bool { try await inner.resume() }
    func checkPassphrase(_ passphrase: String) async throws -> Bool { try await inner.checkPassphrase(passphrase) }
    func createLocalVault(name: String, passphrase: String) async throws -> VaultEntry {
        try await inner.createLocalVault(name: name, passphrase: passphrase)
    }
    func removeVault(id: String, force: Bool) async throws -> Bool { try await inner.removeVault(id: id, force: force) }
    func joinStart(link: String, deviceName: String, answerKey: Data?) async throws -> JoinInfo {
        try await inner.joinStart(link: link, deviceName: deviceName, answerKey: answerKey)
    }
    func joinPoll() async throws -> JoinInfo { try await inner.joinPoll() }
    func joinCancel() async throws { try await inner.joinCancel() }
    func joinFinish(passphrase: String) async throws -> VaultEntry { try await inner.joinFinish(passphrase: passphrase) }
    func items(archived: ArchiveFilter) async throws -> [ItemRow] { try await inner.items(archived: archived) }
    func item(id: UInt64) async throws -> ItemDetail { try await inner.item(id: id) }
    func reveal(id: UInt64, field: String) async throws -> String { try await inner.reveal(id: id, field: field) }
    func totp(id: UInt64, field: String) async throws -> TotpCode { try await inner.totp(id: id, field: field) }
    func history(id: UInt64) async throws -> [ItemEvent] { try await inner.history(id: id) }
    func save(id: UInt64?, revision: UInt64?, draft: ItemDraft) async throws -> SavedItem {
        try await inner.save(id: id, revision: revision, draft: draft)
    }
    func archive(id: UInt64, archived: Bool) async throws { try await inner.archive(id: id, archived: archived) }
    func delete(id: UInt64, revision: UInt64) async throws { try await inner.delete(id: id, revision: revision) }
    func generate(_ options: GeneratorOptions) async throws -> GeneratedPassword { try await inner.generate(options) }
    func strength(_ value: String) async throws -> Strength { try await inner.strength(value) }
    func watchtower() async throws -> WatchtowerReport { try await inner.watchtower() }
    func sync() async throws -> SyncStatus { try await inner.sync() }
    func syncStatus() async throws -> SyncStatus { try await inner.syncStatus() }
    func syncWait(timeout: Int) async throws -> Bool { try await inner.syncWait(timeout: timeout) }
    func takeNewPassphrase(_ passphrase: String) async throws -> PassphraseChange {
        try await inner.takeNewPassphrase(passphrase)
    }
    func useRelayCopy() async throws -> SyncStatus { try await inner.useRelayCopy() }
    func devices() async throws -> [RelayDevice] { try await inner.devices() }
    func autofillList(domains: [String]) async throws -> AutofillList { try await inner.autofillList(domains: domains) }
    func autofillCredential(id: UInt64) async throws -> FillCredential { try await inner.autofillCredential(id: id) }
    func credentialIdentities() async throws -> [CredentialIdentity] { try await inner.credentialIdentities() }
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

        init(allows: Bool = true, now: @escaping @MainActor () -> Date = { Date() }, onCompanionCode: @escaping @MainActor (String) -> String? = { _ in nil }) {
            push = ScriptedPush(allows: allows)
            let suite = "questions-\(UUID().uuidString)"
            defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            model = QuestionsModel(
                service: service, signer: signer, push: push, deviceName: "Test iPhone", defaults: defaults,
                now: now, retryInterval: .milliseconds(10), onCompanionCode: onCompanionCode)
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

    @Test("the bar of a production question: Allow production: ACTION in PROJECT first, in red, the rest in the menu")
    func productionBar() {
        let card = PreviewVaultService.sampleQuestion().card!
        let bar = AnswerBar.make(for: card)
        #expect(bar.primary?.label == "Allow production: Deploy in synthetic-shop")
        #expect(bar.primary?.destructive == true)
        #expect(bar.primary?.answer == RemoteAnswer(kind: .allowProduction))
        #expect(AnswerBar.note(bar.primary, card) == "Remembered for all agents in synthetic-shop, production included")
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
        let projectCard = Self.card(validAnswers: ["once", "in_project:deploy"])
        let project = AnswerBar.make(for: projectCard)
        #expect(project.primary?.label == "Allow Deploy in synthetic-shop")
        #expect(project.primary?.destructive == false)
        #expect(AnswerBar.note(project.primary, projectCard) == "Remembered for all agents in synthetic-shop")
        #expect(project.menu.isEmpty)
        var long = Self.card(validAnswers: ["once", "in_project:read"])
        long.question.action = .read
        long.question.project = .init(key: "/x/.git", label: "a-project-with-a-very-long-name")
        #expect(AnswerBar.make(for: long).primary?.label == "Allow Read in a-project-with-a-very-l…")
        #expect(AnswerBar.note(AnswerBar.make(for: long).primary, long)
            == "Remembered for all agents in a-project-with-a-very-long-name")
        let correction = AnswerBar.make(for: Self.card(validAnswers: ["correct_environment"]))
        #expect(correction.primary?.label == "Development")
        #expect(correction.allowOnce == nil)
        #expect(correction.menu.map(\.label) == ["Production"])
        let noProject = AnswerBar.make(for: Self.card(validAnswers: ["once", "in_project:deploy"], project: false))
        #expect(noProject.primary == nil)
        // Production offered, but no project to remember it in: no main answer, and no note.
        let productionCard = Self.card(validAnswers: ["once", "production:deploy"], project: false)
        let production = AnswerBar.make(for: productionCard)
        #expect(production.primary == nil)
        #expect(production.allowOnce?.answer.kind == .approveOnce)
        #expect(production.menu.isEmpty)
        #expect(AnswerBar.note(production.primary, productionCard) == nil)
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
        #expect(fixture.model.delivery(for: question) == .sent(.allowProduction))
        #expect(fixture.model.deliveryText(for: fixture.model.questions[0])
            == QuestionsModel.sentText)
    }

    @Test("Deny and the stricter answers go without Face ID")
    func stricterAnswersNeedNoFaceID() async throws {
        for kind in [AnswerKind.deny, .disconnect, .correctEnvironment] {
            let fixture = Fixture()
            let question = await fixture.withQuestion()
            let bar = AnswerBar.make(for: question.card!)
            let choice = try #require(([bar.deny] + bar.menu).first {
                $0.answer.kind == kind && (kind != .correctEnvironment || $0.answer.environment == .production)
            })
            await fixture.model.send(choice, for: question)
            #expect(fixture.signer.reasons.isEmpty)
            let sent = await fixture.service.sentAnswers()
            #expect(sent.map(\.answer.kind) == [kind])
            #expect(sent.allSatisfy { $0.signature == nil })
        }
    }

    @Test("a cancelled Face ID sends nothing")
    func cancelledFaceID() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        fixture.signer.fail(with: .cancelled)
        await fixture.model.send(AnswerBar.make(for: question.card!).allowOnce!, for: fixture.model.questions[0])
        #expect(await fixture.service.sentAnswers().isEmpty)
        #expect(fixture.model.delivery(for: question) == nil)
    }

    @Test("a new Face ID enrollment makes a new answer key but does not register it")
    func biometryChanged() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        fixture.signer.fail(with: .biometryChanged)
        await fixture.model.send(AnswerBar.make(for: question.card!).allowOnce!, for: fixture.model.questions[0])
        #expect(await fixture.service.sentAnswers().isEmpty)
        #expect(fixture.signer.renewals == 1)
        #expect(await fixture.service.answerKeyRegistrations() == 1)
        #expect(await fixture.service.registeredAnswerKey() != fixture.signer.key)
        guard case .failed(let message) = fixture.model.delivery(for: question) else {
            Issue.record("no failure shown")
            return
        }
        #expect(message.contains("Face ID changed"))
        #expect(message.contains("remove this iPhone in Settings"))
    }

    @Test("a network failure sends the same answer again; a settled question says so")
    func retriesAndLateAnswers() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        await fixture.service.failNextAnswer(VaultError(.relayUnreachable, "The relay is not reachable."))
        await fixture.model.send(AnswerBar.make(for: question.card!).deny, for: fixture.model.questions[0])
        #expect(await fixture.service.sentAnswers().count == 1)
        #expect(fixture.model.delivery(for: question) == .sent(.deny))

        // A known accepted answer cannot be submitted a second time while its Mac is offline.
        await fixture.model.send(AnswerBar.make(for: question.card!).deny, for: fixture.model.questions[0])
        #expect(await fixture.service.sentAnswers().count == 1)
        #expect(fixture.model.delivery(for: question) == .sent(.deny))
        let late = Fixture()
        let lateQuestion = await late.withQuestion()
        await late.service.failNextAnswer(VaultError(.alreadyAnswered, "Already answered on another device."))
        await late.model.send(AnswerBar.make(for: lateQuestion.card!).deny, for: lateQuestion)
        #expect(late.model.deliveries[lateQuestion.qid] == .failed("Already answered."))

        await fixture.service.settleQuestion(qid: question.qid, by: "Test iPhone")
        await fixture.model.refresh()
        #expect(fixture.model.waitingCount == 0)
        #expect(fixture.model.deliveryText(for: fixture.model.questions[0]) == "Confirmed on Test iPhone")
    }

    @Test("a removed device gets a notice and no registration")
    func removedDevice() async {
        let fixture = Fixture()
        await fixture.service.setQuestions(
            enabled: true, questions: [PreviewVaultService.sampleQuestion()], removed: true)
        await fixture.model.refresh()
        #expect(fixture.model.status.removed)
        #expect(fixture.model.questions.isEmpty)
        #expect(fixture.model.notice?.contains("removed from questions") == true)
        #expect(await fixture.service.answerKeyRegistrations() == 0)
    }

    @Test("a row that has not synced yet gets a notice and no registration")
    func notRegisteredYet() async {
        let fixture = Fixture()
        await fixture.service.setQuestions(
            enabled: true, questions: [PreviewVaultService.sampleQuestion()], registered: false)
        await fixture.model.refresh()
        #expect(!fixture.model.status.registered)
        #expect(fixture.model.notice?.contains("Waiting for the Mac") == true)
        #expect(await fixture.service.answerKeyRegistrations() == 0)
    }

    @Test("a row with this key needs no registration and clears the notice")
    func sameKeyNeedsNothing() async {
        let fixture = Fixture()
        await fixture.service.setQuestions(enabled: true, registered: false)
        await fixture.model.refresh()
        #expect(fixture.model.notice != nil)
        await fixture.service.setQuestions(
            enabled: true, questions: [PreviewVaultService.sampleQuestion()], answerKey: fixture.signer.key)
        await fixture.model.refresh()
        #expect(fixture.model.notice == nil)
        #expect(await fixture.service.answerKeyRegistrations() == 0)
    }

    // MARK: Notifications

    @Test("notifications ask for permission when turned on, and the token goes to the relay")
    func notifications() async {
        let refused = Fixture(allows: false)
        _ = await refused.withQuestion()
        await refused.model.setNotifications(true)
        #expect(refused.push.asked == 1)
        #expect(refused.model.notificationsOn)
        #expect(refused.model.notificationStatus == .denied)
        #expect(refused.model.notificationNeedsSettings)
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
        // iOS delivers nothing more.
        #expect(fixture.push.unregistrations == 1)
        await fixture.model.receivePushToken(Data([4]))
        #expect(await fixture.service.currentPushToken() == nil)
    }

    @Test("without a vault that sends requests through the relay, the status says so, not Apple")
    func noRelayVaultStatus() async {
        let fixture = Fixture()
        await fixture.model.refresh()
        await fixture.model.setNotifications(true)
        #expect(fixture.model.notificationStatus == .noRelayVault)
        #expect(!fixture.model.notificationCanRetry)
        _ = await fixture.withQuestion()
        #expect(fixture.model.notificationStatus == .registering)
    }

    @Test("OS revocation and APNs failure are visible, and registration can recover")
    func effectiveNotificationStatus() async {
        let fixture = Fixture()
        _ = await fixture.withQuestion()
        await fixture.model.setNotifications(true)
        #expect(fixture.model.notificationStatus == .registering)
        fixture.push.failRegistration("Synthetic registration error.")
        #expect(fixture.model.notificationStatus == .failed("Synthetic registration error."))
        #expect(fixture.model.notificationCanRetry)
        await fixture.model.retryNotifications()
        #expect(fixture.push.registrations == 2)
        await fixture.model.receivePushToken(Data([7]))
        #expect(fixture.model.notificationStatus == .ready)
        fixture.push.allows = false
        let asks = fixture.push.asked
        await fixture.model.refreshNotificationStatus()
        #expect(fixture.model.notificationsOn)
        #expect(fixture.model.notificationStatus == .denied)
        #expect(fixture.model.notificationNeedsSettings)
        #expect(fixture.push.asked == asks, "Refreshing settings must not request permission")
        fixture.push.allows = true
        fixture.push.quiet = true
        await fixture.model.refreshNotificationStatus()
        #expect(fixture.model.notificationStatus == .quiet)
    }

    @Test("settlement clears only the delivered snapshot when no request still waits")
    func reconcileDeliveredAlerts() async {
        let fixture = Fixture()
        await fixture.service.addQuestionsVault(id: "complete-list", name: "Test", team: "t_test")
        let question = await fixture.withQuestion()
        fixture.push.delivered = ["old-private-alert"]
        await fixture.model.refresh()
        #expect(fixture.push.removed.isEmpty)
        await fixture.model.send(AnswerBar.make(for: question.card!).deny, for: question)
        #expect(fixture.push.removed.isEmpty, "Relay acceptance is not settlement")
        await fixture.service.settleQuestion(qid: question.qid, by: "Test Mac")
        fixture.push.afterDeliveredSnapshot = { fixture.push.delivered += ["new-alert-during-refresh"] }
        await fixture.model.refresh()
        await fixture.model.alertReconciliationFinished()
        #expect(fixture.push.removed == ["old-private-alert"])
        #expect(!fixture.push.removed.contains("new-alert-during-refresh"))
    }

    @Test("an offline Mac leaves a sent answer unconfirmed, never refused")
    func offlineMacRemainsUnconfirmed() async {
        var time = Date()
        let fixture = Fixture(now: { time })
        let question = await fixture.withQuestion()
        await fixture.model.send(AnswerBar.make(for: question.card!).deny, for: question)
        #expect(fixture.model.outcome(for: question)?.text == QuestionsModel.sentText)
        #expect(fixture.model.waitingCount == 0)
        time = time.addingTimeInterval(61)
        #expect(fixture.model.outcome(for: question) == QuestionOutcome(text: QuestionsModel.unconfirmedText, tone: .neutral))
        #expect(fixture.model.needsConfirmation(for: question))
        time = time.addingTimeInterval(301)
        #expect(fixture.model.outcome(for: question)?.text == QuestionsModel.unconfirmedText)
        await fixture.model.refresh()
        #expect(fixture.model.outcome(for: fixture.model.questions[0])?.text == QuestionsModel.unconfirmedText)
        #expect(fixture.model.delivery(for: question) == .sent(.deny))
    }

    @Test("foreground quieting is limited to an unlocked visible list")
    func visibleRequests() async {
        let fixture = Fixture()
        fixture.model.setRequestsPresented(true)
        fixture.model.setRequestsVisible(true)
        #expect(!fixture.push.requestsVisible)
        await fixture.service.addQuestionsVault(id: "complete-list", name: "Test", team: "t_test")
        _ = await fixture.withQuestion()
        #expect(fixture.push.requestsVisible)
        fixture.model.setRequestsVisible(false)
        #expect(!fixture.push.requestsVisible)
        fixture.model.setRequestsVisible(true)
        fixture.model.vaultDidLock()
        #expect(!fixture.push.requestsVisible)
    }

    @Test("parent Settings, dismissal, and tab changes retain foreground request alerts")
    func coveredRequestsKeepAlerts() async {
        let fixture = Fixture()
        await fixture.service.addQuestionsVault(id: "complete-list", name: "Test", team: "t_test")
        _ = await fixture.withQuestion()
        fixture.model.setRequestsPresented(true)
        fixture.model.setRequestsVisible(true)
        fixture.push.foreground()
        #expect(fixture.push.foregroundAlerts == [false], "The actual uncovered Requests list updates quietly")

        // Requests remains mounted when Settings opens above it.
        fixture.model.setRequestsPresented(false)
        fixture.model.setRequestsVisible(true)
        fixture.push.foreground()
        #expect(!fixture.push.requestsVisible)
        #expect(fixture.push.foregroundAlerts == [false, true])

        // Parent ui.sheet becomes nil before its dismissal finishes. The parent gate stays false.
        fixture.model.setRequestsPresented(false)
        fixture.push.foreground()
        #expect(fixture.push.foregroundAlerts == [false, true, true])
        fixture.model.setRequestsPresented(true)  // Parent sheet onDismiss.
        fixture.push.foreground()
        #expect(fixture.push.foregroundAlerts == [false, true, true, false])

        // A tab change must win even if the mounted list sends another appearance update.
        fixture.model.setRequestsPresented(false)
        fixture.model.setRequestsVisible(true)
        fixture.push.foreground()
        #expect(fixture.push.foregroundAlerts == [false, true, true, false, true])
    }

    @Test("a stalled OS permission read cannot block discovery of an unconnected vault")
    func permissionReadDoesNotBlockConnectionState() async {
        let fixture = Fixture()
        fixture.push.holdsAuthorization = true
        await fixture.service.setQuestions(enabled: false)
        let watching = Task { await fixture.model.watch() }
        for _ in 0..<1_000 {
            if fixture.push.authorizationReads > 0 && fixture.model.phase == .off { break }
            await Task.yield()
        }
        #expect(fixture.push.authorizationReads == 1)
        #expect(fixture.model.phase == .off)
        #expect(fixture.model.canConnect)
        #expect(fixture.push.asked == 0)
        fixture.push.releaseAuthorization()
        watching.cancel()
        await watching.value
    }

    @Test("stalled delivered-alert housekeeping cannot block connection discovery or clear a new request")
    func deliveredReadDoesNotBlockConnectionState() async {
        let fixture = Fixture()
        await fixture.service.addQuestionsVault(id: "complete-list", name: "Test", team: "t_test")
        let question = await fixture.withQuestion()
        await fixture.service.settleQuestion(qid: question.qid, by: "Test Mac")
        fixture.push.delivered = ["old-private-alert"]
        fixture.push.holdsDeliveredSnapshot = true
        await fixture.model.refresh()
        for _ in 0..<1_000 {
            if fixture.push.deliveredReads > 0 { break }
            await Task.yield()
        }
        #expect(fixture.model.phase == .ready)
        #expect(fixture.push.deliveredReads == 1)

        // A new request arrives while the notification daemon still has not returned its snapshot.
        let newer = PreviewVaultService.sampleQuestion(qid: "newer")
        await fixture.service.setQuestions(enabled: true, questions: [newer])
        await fixture.model.refresh()
        #expect(fixture.model.waiting.map(\.qid) == ["newer"])
        fixture.push.releaseDeliveredSnapshot()
        await fixture.model.alertReconciliationFinished()
        #expect(fixture.push.removed.isEmpty)
    }

    // MARK: The long poll

    @Test("a long poll that ends at once without news waits before the next one, longer each time")
    func quickWaitsBackOff() async {
        let fixture = Fixture()
        // This iPhone was removed from the team: the status is still enabled, so the list is
        // ready, and an older core answers each wait at once.
        await fixture.service.setQuestions(enabled: true, removed: true)
        await fixture.service.scriptQuestionWaits(Array(repeating: false, count: 1000))
        let watching = Task { await fixture.model.watch() }
        try? await Task.sleep(for: .milliseconds(400))
        watching.cancel()
        await watching.value
        #expect(fixture.model.phase == .ready)
        let used = 1000 - (await fixture.service.questionWaitsLeft())
        // 10, 20, 40, 80, 160 ms of pause: a handful of calls, not a busy loop.
        #expect(used >= 2 && used <= 10, "\(used) waits in 400 ms")
    }

    // MARK: The vault of an answer

    @Test("an answer to a question of a vault whose questions are not open is refused before Face ID")
    func answerOfAVaultThatIsNotOpen() async throws {
        let fixture = Fixture()
        _ = await fixture.withQuestion()
        var question = PreviewVaultService.sampleQuestion(qid: "ZmFtaWx5LXF1ZXN0aW9uLTAwMQ")
        question.vaultID = "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
        question.vaultName = "Family"
        let bar = AnswerBar.make(for: try #require(question.card))
        await fixture.model.send(try #require(bar.allowOnce), for: question)
        #expect(fixture.signer.reasons.isEmpty, "no Face ID")
        #expect(await fixture.service.sentAnswers().isEmpty)
        #expect(
            fixture.model.delivery(for: question)
                == .failed("Family is locked on this iPhone. Unlock it in Requests, then answer."))
        // Deny needs no Face ID, and it is refused too: never the key of the selected vault.
        await fixture.model.send(bar.deny, for: question)
        #expect(await fixture.service.sentAnswers().isEmpty)
    }

    @Test("a journal attempt during retry preserves exactly one original signed payload")
    func ownAttemptDuringRetry() async throws {
        let service = AttemptedAnswerService()
        let question = PreviewVaultService.sampleQuestion()
        await service.install(question)
        let signer = ScriptedSigner()
        let model = QuestionsModel(service: service, signer: signer, push: nil,
            deviceName: "Synthetic iPhone", retryInterval: .milliseconds(1))
        await model.refresh()
        let sending = Task { await model.send(AnswerBar.make(for: question.card!).allowOnce!, for: question) }
        await service.waitForPost()
        await model.refresh()
        let attempted = try #require(model.questions.first)
        #expect(attempted.answered == .approveOnce)
        await model.send(AnswerBar.make(for: question.card!).deny, for: attempted)
        #expect(await service.payloads.count == 1)
        await service.failFirstPost()
        await sending.value
        let payloads = await service.payloads
        #expect(payloads.count == 2)
        #expect(payloads.first == payloads.last)
        #expect(await service.preparations == 1)
        #expect(signer.reasons.count == 1)
        #expect(model.delivery(for: question) == .sent(.approveOnce))
    }

    @Test("a restored attempt without known acceptance never claims Answer sent")
    func restoredAttemptIsUnconfirmed() async {
        let fixture = Fixture()
        var attempted = PreviewVaultService.sampleQuestion()
        attempted.answered = .approveOnce
        await fixture.service.setQuestions(enabled: true, questions: [attempted])
        await fixture.model.refresh()
        #expect(fixture.model.deliveryText(for: attempted) == QuestionsModel.unconfirmedText)
        #expect(fixture.model.outcome(for: attempted) == QuestionOutcome(text: QuestionsModel.unconfirmedText, tone: .neutral))
    }

    @Test("history is only available metadata, clears locally, and disappears on leave")
    func historyPrivacyAndClear() async throws {
        let fixture = Fixture()
        _ = await fixture.withQuestion()
        let info = try await fixture.service.info()
        let vaultID = try #require(info.selected)
        let entry = RequestHistoryEntry(id: "relay:\(vaultID):synthetic", vaultID: vaultID,
            qid: "synthetic", title: "SYNTHETIC_TOKEN", agent: "codex", project: "Synthetic",
            action: "Read", production: false, deviceName: "Synthetic Mac",
            firstSeenAt: 100, lastSeenAt: 120, expiresAt: 300, selectedKind: "approve_once", sentAt: 125)
        await fixture.service.setRequestHistory([
            RequestHistoryVault(vaultID: vaultID, vaultName: "Synthetic", availability: .available, entries: [entry])
        ])
        await fixture.model.refreshHistory()
        #expect(fixture.model.history == [entry])
        #expect(fixture.model.history.first?.outcome == nil)
        await fixture.model.clearLocalHistory(vaultID: vaultID)
        #expect(fixture.model.history.isEmpty)
        #expect(await fixture.service.sentAnswers().isEmpty)
        await fixture.service.setRequestHistory([
            RequestHistoryVault(vaultID: vaultID, vaultName: "Synthetic", availability: .available, entries: [entry])
        ])
        await fixture.model.refreshHistory()
        #expect(fixture.model.history.count == 1)
        fixture.model.vaultWillLeave()
        #expect(fixture.model.historyVaults.isEmpty)
        #expect(fixture.model.history.isEmpty)
        #expect(fixture.model.receiptQuestions.isEmpty)
        #expect(fixture.model.questions.isEmpty)
    }

    @Test("a request changed while Face ID is pending never posts the old choice")
    func changedDuringAuthentication() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        fixture.signer.beforeSigning {
            var changed = question
            changed.card?.digest = "changed-digest"
            changed.card?.run.command = ["rm", "-rf", "important"]
            await fixture.service.setQuestions(enabled: true, questions: [changed])
            await fixture.model.refresh()
        }
        await fixture.model.send(AnswerBar.make(for: question.card!).allowOnce!, for: question)
        #expect(await fixture.service.sentAnswers().isEmpty)
        #expect(fixture.model.receiptQuestions.count == 1)
        #expect(fixture.model.outcome(for: fixture.model.receiptQuestions[0])?.tone != .allowed)
    }

    @Test("a lock while Face ID is pending drops request and receipt metadata")
    func lockedDuringAuthentication() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        fixture.signer.beforeSigning { await fixture.model.vaultDidLock() }
        await fixture.model.send(AnswerBar.make(for: question.card!).allowOnce!, for: question)
        #expect(await fixture.service.sentAnswers().isEmpty)
        #expect(fixture.model.questions.isEmpty)
        #expect(fixture.model.receiptQuestions.isEmpty)
        #expect(fixture.model.history.isEmpty)
        #expect(fixture.model.phase == .locked)
    }

    @Test("duplicate taps during Face ID cannot prepare another answer")
    func duplicateDuringAuthentication() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        let bar = AnswerBar.make(for: question.card!)
        fixture.signer.beforeSigning { await fixture.model.send(bar.deny, for: question) }
        await fixture.model.send(bar.allowOnce!, for: question)
        #expect(await fixture.service.sentAnswers().map(\.answer.kind) == [.approveOnce])
        #expect(fixture.model.receiptQuestions.count == 1)
        #expect(fixture.model.outcome(for: fixture.model.receiptQuestions[0])?.tone == .neutral)
    }

    @Test("an unoffered answer cannot be prepared or authenticated")
    func unofferedChoice() async {
        let fixture = Fixture()
        var question = await fixture.withQuestion()
        question.card?.question.validAnswers = ["once"]
        await fixture.service.setQuestions(enabled: true, questions: [question])
        await fixture.model.refresh()
        let choice = AnswerBar.Choice(answer: RemoteAnswer(kind: .allowProduction), label: "Allow production")
        await fixture.model.send(choice, for: question)
        #expect(await fixture.service.sentAnswers().isEmpty)
        #expect(fixture.signer.reasons.isEmpty)
    }

    // MARK: Connecting a vault from iCloud Drive

    @Test("a cancelled or dismissed relay start cannot replace a newer companion scan", arguments:
        [false, true], SuspendedQuestionsAttachService.Completion.allCases)
    fileprivate func obsoleteRelayStart(dismiss: Bool, completion: SuspendedQuestionsAttachService.Completion) async {
        let fixture = Fixture()
        let service = SuspendedQuestionsAttachService()
        var companionCodes: [String] = []
        let model = QuestionsModel(
            service: service, signer: fixture.signer, push: fixture.push, deviceName: "Test iPhone",
            defaults: fixture.defaults,
            onCompanionCode: { companionCodes.append($0); return nil })
        let request = Task {
            await model.startAttach(link: "https://apassy-relay.example/link#apassy_lnk_old")
        }
        // This gate resumes only after joinAttach has suspended its result, without sleep timing.
        await service.waitForStart()
        #expect(model.attach == .starting)
        if dismiss { model.dismissAttach() } else { model.cancelAttach() }
        let companionCode = pairingLinkText(expiresIn: 300)
        await model.startAttach(link: companionCode)
        #expect(model.attach == .companion)

        await service.complete(completion)
        await request.value
        #expect(model.attach == .companion)
        #expect(companionCodes == [companionCode])
        #expect(await service.pollCalls == 0)
        model.dismissAttach()
    }

    @Test("cancelling a current waiting relay connection still cancels it on the service")
    func cancelCurrentRelayAttach() async {
        let fixture = Fixture()
        let service = SuspendedQuestionsAttachService()
        let model = QuestionsModel(
            service: service, signer: fixture.signer, push: fixture.push, deviceName: "Test iPhone",
            defaults: fixture.defaults)
        let request = Task {
            await model.startAttach(link: "https://apassy-relay.example/link#apassy_lnk_current")
        }
        await service.waitForStart()
        await service.complete(.success)
        await request.value
        guard case .waiting = model.attach else {
            Issue.record("the current response did not reach waiting")
            return
        }
        model.cancelAttach()
        await service.waitForCancel()
        #expect(model.attach == nil)
        #expect(await service.cancelCalls == 1)
    }

    @Test("Connect this iPhone routes a companion QR after dismissal without starting a relay join")
    func companionFromConnectSheet() async throws {
        let pairing = PairingModelTests.Fixture(polls: [.waiting, .paired])
        let fixture = Fixture(onCompanionCode: { pairing.model.receiveCode($0) })
        await fixture.model.refresh()
        let code = pairingLinkText(expiresIn: 300)
        #expect(QuestionsModel.isConnectionCode(code))
        #expect(QuestionsModel.isConnectionCode("  \(code) \n"))
        #expect(!QuestionsModel.isLink(code))
        await fixture.model.startAttach(link: "  \(code) \n")
        #expect(fixture.model.attach == .companion)
        #expect(fixture.model.phase == .off)
        #expect(await fixture.service.attachedAnswerKey() == nil)
        #expect(fixture.signer.renewals == 0)
        #expect(fixture.signer.reasons.isEmpty)
        #expect(pairing.model.step == .welcome)
        #expect(pairing.model.hasScannedCode)
        #expect(pairing.mac.requests.isEmpty)

        // The host dismisses the scanner before opening the prepared companion flow.
        fixture.model.dismissAttach()
        #expect(fixture.model.attach == nil)
        #expect(pairing.model.hasScannedCode)
        pairing.model.startScanning()
        #expect(await waitUntil {
            if case .code = pairing.model.step { return true }
            return false
        })
        #expect(await waitUntil { pairing.model.step == .paired(macName: "Mac mini") })
        #expect(pairing.paired.isEmpty)
        pairing.model.finish()
        #expect(pairing.paired.count == 1)
    }

    @Test("Connect this iPhone rejects malformed or expired companion QR without a relay fallback")
    func invalidCompanionFromConnectSheet() async {
        let valid = pairingLinkText(expiresIn: 300)
        let invalid = [
            pairingLinkText(expiresIn: -10),
            valid + "&v=1",
            valid.replacingOccurrences(of: "p=48620", with: "p=0"),
            "apassy://pair/wrong/link#apassy_lnk_abc",
            "APASSY://pair/wrong/link#apassy_lnk_abc",
        ]
        for code in invalid {
            var called = false
            let fixture = Fixture(onCompanionCode: { _ in called = true; return nil })
            await fixture.model.startAttach(link: code)
            guard case .failed = fixture.model.attach else {
                Issue.record("invalid companion code started a connection")
                continue
            }
            #expect(!called)
            #expect(await fixture.service.attachedAnswerKey() == nil)
        }
    }

    @Test("an existing companion pairing keeps its keys and stays in the connect sheet")
    func companionGuardFromConnectSheet() async throws {
        let pairing = PairingModelTests.Fixture(polls: [.paired])
        #expect(await pairing.scanToCode())
        #expect(await waitUntil { pairing.model.step == .paired(macName: "Mac mini") })
        let saved = try #require(try pairing.store.load())
        let fixture = Fixture(onCompanionCode: { pairing.model.receiveCode($0) })
        await fixture.model.startAttach(link: pairingLinkText(expiresIn: 300))
        guard case .failed = fixture.model.attach else {
            Issue.record("existing pairing was replaced")
            return
        }
        #expect(try pairing.store.load() == saved)
        #expect(pairing.model.step == .paired(macName: "Mac mini"))
        #expect(await fixture.service.attachedAnswerKey() == nil)
        pairing.model.finish()
    }

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
        #expect(await fixture.service.attachedAnswerKey() == fixture.signer.key)
    }

    @Test("Connect pairing offers push only after confirmation and an explicit notification action")
    func connectPairingPush() async {
        let fixture = Fixture()
        await fixture.model.refresh()
        await fixture.model.startAttach(
            link: "https://relay.example.test/link#apassy_lnk_t_7k2m5q4x3c_00&handoff=synthetic.capsule",
            pollInterval: .milliseconds(10))
        guard case .waiting = fixture.model.attach else { Issue.record("no safety words"); return }
        #expect(fixture.push.asked == 0)
        #expect(fixture.signer.renewals == 1, "A retained Keychain key from before reinstall is not reused")
        await fixture.model.attachFinished()
        #expect(fixture.model.attach == .attached)
        #expect(fixture.model.phase == .ready)
        #expect(await fixture.service.attachedAnswerKey() == fixture.signer.key)
        #expect(fixture.push.asked == 0, "Pairing does not prompt for notifications")
        await fixture.model.setNotifications(true)
        #expect(fixture.push.asked == 1)
        await fixture.model.receivePushToken(Data([9, 8, 7]))
        #expect(await fixture.service.currentPushToken() == Data([9, 8, 7]))
        fixture.model.dismissAttach()
        #expect(fixture.model.attach == nil)
        #expect(fixture.model.phase == .ready, "Open Requests keeps the confirmed connection")
    }

    @Test("a removed device connects again with a new answer key")
    func attachAfterRemoval() async {
        let fixture = Fixture()
        await fixture.service.setQuestions(enabled: true, removed: true)
        await fixture.model.refresh()
        #expect(fixture.model.status.removed)
        let oldKey = fixture.signer.key
        await fixture.model.startAttach(
            link: "https://apassy-relay.example/link#apassy_lnk_t_7k2m5q4x3c_00", pollInterval: .milliseconds(10))
        #expect(fixture.signer.renewals == 1)
        #expect(fixture.signer.key != oldKey)
        #expect(await fixture.service.attachedAnswerKey() == fixture.signer.key)
        fixture.model.cancelAttach()
    }

    // MARK: The outcome in place of the bar

    @Test("an open question has no outcome; this iPhone's answer, a settle, or the expiry replace the bar")
    func outcomes() async {
        let fixture = Fixture()
        let question = await fixture.withQuestion()
        #expect(fixture.model.outcome(for: fixture.model.questions[0]) == nil)

        await fixture.model.send(AnswerBar.make(for: question.card!).deny, for: fixture.model.questions[0])
        #expect(fixture.model.outcome(for: fixture.model.questions[0])
            == QuestionOutcome(text: QuestionsModel.sentText, tone: .neutral))

        await fixture.service.settleQuestion(qid: question.qid, by: "Mac mini")
        await fixture.model.refresh()
        #expect(fixture.model.outcome(for: fixture.model.questions[0])
            == QuestionOutcome(text: "Allowed on Mac mini", tone: .allowed))

        var denied = PreviewVaultService.sampleQuestion()
        denied.state = .settled
        denied.settle = QuestionSettle(outcome: "denied", deviceName: "MacBook Pro", at: 1)
        #expect(fixture.model.outcome(for: denied) == QuestionOutcome(text: "Denied on MacBook Pro", tone: .denied))
        denied.settle = QuestionSettle(outcome: "timed_out", at: 1)
        #expect(fixture.model.outcome(for: denied)?.text == "Expired")

        let late = PreviewVaultService.sampleQuestion(qid: "late", now: Date().addingTimeInterval(-301))
        #expect(late.state == .open)
        #expect(fixture.model.outcome(for: late) == QuestionOutcome(text: "Expired", tone: .neutral))
    }

    // MARK: Opening a notification

    @Test("a generic notification refreshes the list once without choosing a question")
    func notificationOpensTheList() async {
        let fixture = Fixture()
        let older = PreviewVaultService.sampleQuestion(qid: "older", now: Date().addingTimeInterval(-60))
        let newer = PreviewVaultService.sampleQuestion(qid: "newer")
        var expired = PreviewVaultService.sampleQuestion(qid: "ended", now: Date().addingTimeInterval(5))
        expired.state = .expired
        await fixture.service.setQuestions(enabled: true, questions: [older, newer, expired])
        await fixture.model.refresh()
        #expect(await fixture.model.takeFocus(stillFree: { true }) == nil)
        #expect(fixture.model.focusRequests == 0)

        fixture.push.open()
        #expect(fixture.model.focusRequests == 1)
        #expect(await fixture.model.takeFocus(stillFree: { true }) == nil)
        #expect(await fixture.model.takeFocus(stillFree: { true }) == nil)

        await fixture.service.setQuestions(enabled: true, questions: [expired])
        await fixture.model.refresh()
        fixture.push.open()
        #expect(fixture.model.focusRequests == 2)
        #expect(await fixture.model.takeFocus(stillFree: { true }) == nil)
    }

    @Test("an old generic push never opens an unrelated newer request")
    func staleNotificationRefreshesTheList() async {
        let fixture = Fixture()
        let older = PreviewVaultService.sampleQuestion(qid: "older", now: Date().addingTimeInterval(-60))
        await fixture.service.setQuestions(enabled: true, questions: [older])
        await fixture.model.refresh()
        // The list on the iPhone is old: the newer question reaches it only with the refresh.
        let newer = PreviewVaultService.sampleQuestion(qid: "newer")
        var settled = older
        settled.state = .settled
        settled.settle = QuestionSettle(outcome: "approved", deviceName: "Test Mac", at: 1)
        await fixture.service.setQuestions(enabled: true, questions: [settled, newer])
        fixture.push.open()
        #expect(await fixture.model.takeFocus(stillFree: { true }) == nil)
        #expect(fixture.model.waiting.map(\.qid) == ["newer"])
        #expect(fixture.model.unlockPrompt == nil)
    }

    @Test("an opened notification opens nothing when the owner opened something during the refresh")
    func notificationYieldsToTheOwner() async {
        let fixture = Fixture()
        await fixture.service.setQuestions(enabled: true, questions: [PreviewVaultService.sampleQuestion(qid: "q")])
        await fixture.model.refresh()
        fixture.push.open()
        var asked = 0
        #expect(await fixture.model.takeFocus(stillFree: { asked += 1; return false }) == nil)
        #expect(asked == 1)
        // The request is used up: a later look opens nothing either.
        #expect(await fixture.model.takeFocus(stillFree: { true }) == nil)
    }
}

/// Models a durable attempted marker becoming visible while an exact signed POST is retried.
private actor AttemptedAnswerService: VaultService {
    struct Payload: Equatable, Sendable {
        let qid: String
        let answer: RemoteAnswer
        let time: Int64
        let signature: Data?
        let vaultID: String?
    }
    private let inner = PreviewVaultService()
    private var question: RemoteQuestion?
    private var post: CheckedContinuation<Void, Never>?
    private var started: CheckedContinuation<Void, Never>?
    private(set) var payloads: [Payload] = []
    private(set) var preparations = 0

    func install(_ question: RemoteQuestion) async {
        self.question = question
        await inner.setQuestions(enabled: true, questions: [question])
    }
    func questionsList() async throws -> QuestionsList { try await inner.questionsList() }
    func answerKeyRegister(publicKey: Data) async throws -> AnswerKeyRegistration {
        try await inner.answerKeyRegister(publicKey: publicKey)
    }
    func questionAnswerString(qid: String, answer: RemoteAnswer, vaultID: String?) async throws -> PreparedAnswer {
        preparations += 1
        return try await inner.questionAnswerString(qid: qid, answer: answer, vaultID: vaultID)
    }
    func questionAnswer(qid: String, answer: RemoteAnswer, time: Int64, signature: Data?, vaultID: String?) async throws -> SentAnswer {
        payloads.append(Payload(qid: qid, answer: answer, time: time, signature: signature, vaultID: vaultID))
        if payloads.count == 1 {
            var pending = question!
            pending.answered = answer.kind
            let key = await inner.registeredAnswerKey()
            await inner.setQuestions(enabled: true, questions: [pending], answerKey: key)
            await withCheckedContinuation { continuation in
                post = continuation
                started?.resume()
                started = nil
            }
            throw VaultError(.relayUnreachable, "Synthetic lost response")
        }
        return SentAnswer(id: 2, at: time, kind: answer.kind)
    }
    func waitForPost() async {
        if post != nil { return }
        await withCheckedContinuation { started = $0 }
    }
    func failFirstPost() { post?.resume(); post = nil }
    func info() async throws -> CoreInfo { try await inner.info() }
    func select(vaultID: String) async throws { try await inner.select(vaultID: vaultID) }
    func unlock(passphrase: String, keep: Bool) async throws { try await inner.unlock(passphrase: passphrase, keep: keep) }
    func lock() async throws { try await inner.lock() }
    func suspend() async throws { try await inner.suspend() }
    func resume() async throws -> Bool { try await inner.resume() }
    func checkPassphrase(_ passphrase: String) async throws -> Bool { try await inner.checkPassphrase(passphrase) }
    func createLocalVault(name: String, passphrase: String) async throws -> VaultEntry {
        try await inner.createLocalVault(name: name, passphrase: passphrase)
    }
    func removeVault(id: String, force: Bool) async throws -> Bool { try await inner.removeVault(id: id, force: force) }
    func joinStart(link: String, deviceName: String, answerKey: Data?) async throws -> JoinInfo {
        try await inner.joinStart(link: link, deviceName: deviceName, answerKey: answerKey)
    }
    func joinPoll() async throws -> JoinInfo { try await inner.joinPoll() }
    func joinCancel() async throws { try await inner.joinCancel() }
    func joinFinish(passphrase: String) async throws -> VaultEntry { try await inner.joinFinish(passphrase: passphrase) }
    func items(archived: ArchiveFilter) async throws -> [ItemRow] { try await inner.items(archived: archived) }
    func item(id: UInt64) async throws -> ItemDetail { try await inner.item(id: id) }
    func reveal(id: UInt64, field: String) async throws -> String { try await inner.reveal(id: id, field: field) }
    func totp(id: UInt64, field: String) async throws -> TotpCode { try await inner.totp(id: id, field: field) }
    func history(id: UInt64) async throws -> [ItemEvent] { try await inner.history(id: id) }
    func save(id: UInt64?, revision: UInt64?, draft: ItemDraft) async throws -> SavedItem {
        try await inner.save(id: id, revision: revision, draft: draft)
    }
    func archive(id: UInt64, archived: Bool) async throws { try await inner.archive(id: id, archived: archived) }
    func delete(id: UInt64, revision: UInt64) async throws { try await inner.delete(id: id, revision: revision) }
    func generate(_ options: GeneratorOptions) async throws -> GeneratedPassword { try await inner.generate(options) }
    func strength(_ value: String) async throws -> Strength { try await inner.strength(value) }
    func watchtower() async throws -> WatchtowerReport { try await inner.watchtower() }
    func sync() async throws -> SyncStatus { try await inner.sync() }
    func syncStatus() async throws -> SyncStatus { try await inner.syncStatus() }
    func syncWait(timeout: Int) async throws -> Bool { try await inner.syncWait(timeout: timeout) }
    func takeNewPassphrase(_ passphrase: String) async throws -> PassphraseChange {
        try await inner.takeNewPassphrase(passphrase)
    }
    func useRelayCopy() async throws -> SyncStatus { try await inner.useRelayCopy() }
    func devices() async throws -> [RelayDevice] { try await inner.devices() }
    func autofillList(domains: [String]) async throws -> AutofillList { try await inner.autofillList(domains: domains) }
    func autofillCredential(id: UInt64) async throws -> FillCredential { try await inner.autofillCredential(id: id) }
    func credentialIdentities() async throws -> [CredentialIdentity] { try await inner.credentialIdentities() }
}
