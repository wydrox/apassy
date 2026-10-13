import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Observation

/// Notification permission and the APNs registration (`PushRegistrar` in the app).
@MainActor
protocol PushPermission: AnyObject {
    /// Ask iOS once; true when the owner allows notifications.
    func requestAuthorization() async -> Bool
    /// Ask iOS for a device token. It arrives in `QuestionsModel.receivePushToken`.
    func registerForPushes()
    /// The APNs environment of this build.
    var environment: PushEnvironment { get }
    /// Call `handler` when the owner opens a notification of a question.
    func observeOpens(_ handler: @escaping @MainActor () -> Void)
}

/// The buttons of a question, as on the Mac (ADR 0026): Deny · Allow Once · the main answer, and
/// a "⋯" menu with the stricter answers and the environment of an item.
struct AnswerBar: Equatable {
    struct Choice: Equatable, Identifiable {
        let answer: RemoteAnswer
        let label: String
        /// Red: Disconnect in the menu, and the production answer in the bar.
        var destructive = false

        var id: String { "\(answer.kind.rawValue)-\(answer.itemID ?? "")-\(answer.environment?.rawValue ?? "")" }
    }

    var deny: Choice
    var allowOnce: Choice?
    /// "Allow Deploy in shop", "Allow production: Deploy in shop" (red, as on the Mac, so it never
    /// looks like the project answer), or "Development".
    var primary: Choice?
    var menu: [Choice]

    /// A project name in a button, at most 24 characters.
    static func short(_ text: String) -> String {
        guard text.count > 24 else { return text }
        return String(text.prefix(23)) + "…"
    }

    /// The bar of `card`. The main answer is production first, then the project answer, then the
    /// correction of a credential that is production only by default (as `primary` on the Mac).
    static func make(for card: QuestionCard) -> AnswerBar {
        let question = card.question
        let offered = Set(question.validAnswers)
        let action = question.action
        let project = question.project.map { short($0.label) }
        let unconfirmed = question.items.filter(\.unconfirmed)
        let corrects = offered.contains("correct_environment") && !unconfirmed.isEmpty
        var primary: Choice?
        if let project, offered.contains("production:\(action.rawValue)") {
            primary = Choice(
                answer: RemoteAnswer(kind: .allowProduction),
                label: "Allow production: \(action.label) in \(project)", destructive: true)
        } else if let project, offered.contains("in_project:\(action.rawValue)") {
            primary = Choice(answer: RemoteAnswer(kind: .approveInProject), label: "Allow \(action.label) in \(project)")
        }
        var menu: [Choice] = []
        for item in corrects ? unconfirmed : [] {
            let suffix = unconfirmed.count > 1 ? ": \(item.name)" : ""
            let development = Choice(
                answer: RemoteAnswer(kind: .correctEnvironment, itemID: item.itemID, environment: .development),
                label: "Development\(suffix)")
            if primary == nil {
                primary = development
            } else {
                menu.append(development)
            }
            menu.append(
                Choice(
                    answer: RemoteAnswer(kind: .correctEnvironment, itemID: item.itemID, environment: .production),
                    label: "Production\(suffix)"))
        }
        if offered.contains("never_for_agent") {
            menu.append(Choice(answer: RemoteAnswer(kind: .neverForAgent), label: "Not for this agent"))
        }
        if offered.contains("always_ask_for_agent") {
            menu.append(Choice(answer: RemoteAnswer(kind: .alwaysAskForAgent), label: "Always ask for this agent"))
        }
        if offered.contains("disconnect") {
            menu.append(Choice(answer: RemoteAnswer(kind: .disconnect), label: "Disconnect", destructive: true))
        }
        return AnswerBar(
            deny: Choice(answer: RemoteAnswer(kind: .deny), label: "Deny", destructive: true),
            allowOnce: offered.contains("once")
                ? Choice(answer: RemoteAnswer(kind: .approveOnce), label: "Allow Once") : nil,
            primary: primary, menu: menu)
    }

    /// The line under the bar: what the main answer remembers.
    static func note(_ primary: Choice?, _ card: QuestionCard) -> String? {
        guard let primary, let project = card.question.project?.label else { return nil }
        switch primary.answer.kind {
        case .approveInProject: return "Remembered for all agents in \(project)"
        case .allowProduction: return "Remembered for all agents in \(project), production included"
        case .correctEnvironment: return "Remembered for this credential"
        default: return nil
        }
    }
}

/// How a question ended, or what this iPhone did with it: it takes the place of the answer bar.
struct QuestionOutcome: Equatable {
    enum Tone: Equatable {
        case allowed
        case denied
        case neutral
    }

    var text: String
    var tone: Tone
}

/// Questions through the relay on this iPhone (contract relay-questions-v1, section 13): the list
/// of the questions of the vaults, the answer bar, Face ID for the answers that give authority, the
/// answer key of each questions team, the notifications, and the connection of a vault from iCloud
/// Drive to its notifications team.
///
/// A core that keeps the questions of every unlocked vault lists them all (`vaults`), and each
/// answer names the vault of its question. An older core lists the selected vault only; then the
/// push token and its removal reach the team of each vault when that vault is selected.
@MainActor
@Observable
final class QuestionsModel {
    enum Phase: Equatable {
        case loading
        /// The vault has no questions team: connect this iPhone.
        case off
        case ready
        /// The vault is locked: its questions show after the unlock.
        case locked
        case failed(String)
    }

    /// What happened to this iPhone's answer to a question.
    enum Delivery: Equatable {
        case sending
        /// The relay took it; the settle says whether it counted.
        case sent(AnswerKind)
        case failed(String)
    }

    /// Connecting a vault from iCloud Drive to its notifications team (plan §A7).
    enum AttachStep: Equatable {
        /// A valid companion QR is prepared. Dismiss the relay sheet before showing its flow.
        case companion
        case starting
        /// The Mac shows the same words and waits for the owner to confirm.
        case waiting(AttachInfo)
        case attached
        case failed(String)
    }

    static let notificationsKey = "ApassyQuestionNotifications"
    /// Notifications were turned off: the token must leave every questions team, also the teams
    /// of the vaults that are not open now.
    static let pushClearKey = "ApassyQuestionPushClear"
    /// The teams that the token already left since then.
    static let pushClearedKey = "ApassyQuestionPushCleared"

    private(set) var phase = Phase.loading
    /// The selected vault.
    private(set) var status = QuestionsStatus.off
    /// The questions of every vault in the list.
    private(set) var questions: [RemoteQuestion] = []
    /// The vaults whose questions the core keeps; empty with an older core (the selected vault).
    private(set) var vaults: [QuestionsVault] = []
    private(set) var deliveries: [String: Delivery] = [:]
    private(set) var attach: AttachStep?
    /// A problem with the answer key or the notifications, for a line under the list.
    private(set) var notice: String?
    private(set) var notificationsOn: Bool
    /// Counts the notifications that the owner opened; Decisions then opens the newest question.
    private(set) var focusRequests = 0
    /// The name of this iPhone that a connection gives the Mac, so that two devices are told apart.
    var deviceName: String

    @ObservationIgnored private let service: any VaultService
    @ObservationIgnored private let signers: any AnswerSigners
    @ObservationIgnored private weak var push: (any PushPermission)?
    @ObservationIgnored private let defaults: UserDefaults
    /// Keeps the name of a connection for the next one.
    @ObservationIgnored private let onDeviceName: @MainActor (String) -> Void
    @ObservationIgnored private let now: @MainActor () -> Date
    @ObservationIgnored private let retryInterval: Duration
    @ObservationIgnored private let onCompanionCode: @MainActor (String) -> String?
    @ObservationIgnored private var attachTask: Task<Void, Never>?
    /// A response belongs only to the scanner attempt that started it. Cancelling/dismissing
    /// invalidates even a service call that cannot be cancelled while it awaits the relay.
    @ObservationIgnored private var attachGeneration = 0
    @ObservationIgnored private var askedForToken = false
    /// The APNs token of this launch, and the questions teams that got it.
    @ObservationIgnored private var pushToken: Data?
    @ObservationIgnored private var tokenTeams: Set<String> = []
    /// Whether the core lists every vault that it keeps (`QuestionsList.vaults`).
    @ObservationIgnored private var listsEveryVault = false
    @ObservationIgnored private var focusPending = false

    init(
        service: any VaultService, signers: any AnswerSigners, push: (any PushPermission)?, deviceName: String,
        defaults: UserDefaults = .standard, now: @escaping @MainActor () -> Date = { Date() },
        retryInterval: Duration = .seconds(2),
        onCompanionCode: @escaping @MainActor (String) -> String? = { _ in
            "This code pairs the iPhone companion. Open Decisions > Devices > Mac on Wi-Fi to pair with your Mac."
        },
        onDeviceName: @escaping @MainActor (String) -> Void = { _ in }
    ) {
        self.service = service
        self.signers = signers
        self.push = push
        self.deviceName = deviceName
        self.onDeviceName = onDeviceName
        self.defaults = defaults
        self.now = now
        self.retryInterval = retryInterval
        self.onCompanionCode = onCompanionCode
        notificationsOn = defaults.bool(forKey: Self.notificationsKey)
        push?.observeOpens { [weak self] in self?.notificationOpened() }
    }

    /// One answer key for every team: the tests with one vault.
    convenience init(
        service: any VaultService, signer: any AnswerSigner, push: (any PushPermission)?, deviceName: String,
        defaults: UserDefaults = .standard, now: @escaping @MainActor () -> Date = { Date() },
        retryInterval: Duration = .seconds(2),
        onCompanionCode: @escaping @MainActor (String) -> String? = { _ in
            "This code pairs the iPhone companion. Open Decisions > Devices > Mac on Wi-Fi to pair with your Mac."
        }
    ) {
        self.init(
            service: service, signers: SharedAnswerSigners(signer: signer), push: push, deviceName: deviceName,
            defaults: defaults, now: now, retryInterval: retryInterval, onCompanionCode: onCompanionCode)
    }

    /// The vaults of the list: each vault that the core keeps, or the selected vault.
    var contexts: [QuestionsVault] {
        vaults.isEmpty ? [QuestionsVault(vaultID: "", vaultName: "", status: status)] : vaults
    }

    /// Whether the rows name their vault: the questions of two vaults or more show.
    var namesVaults: Bool { vaults.count >= 2 }

    /// Whether "Connect this iPhone" is offered: the selected vault has no questions team, or this
    /// iPhone was removed from it.
    var canConnect: Bool {
        switch phase {
        case .off, .failed: true
        case .ready: !status.enabled || status.removed
        case .loading, .locked: false
        }
    }

    /// The vault of `question`, with this iPhone's row in its team.
    func vault(of question: RemoteQuestion) -> QuestionsVault? {
        guard let id = question.vaultID else { return vaults.isEmpty ? contexts.first : nil }
        return vaults.first { $0.vaultID == id }
    }

    /// The questions that wait for an answer now.
    var waiting: [RemoteQuestion] {
        let at = Int64(now().timeIntervalSince1970)
        return questions.filter { $0.state == .open && $0.expiresAt > at }
    }

    var waitingCount: Int { waiting.count }

    // MARK: The list

    /// Read the list. For each vault with a questions team, check the answer key of this iPhone in
    /// its row, then bring the push token to the teams that do not have it, or take it away.
    func refresh() async {
        do {
            let list = try await service.questionsList()
            status = list.status
            vaults = list.vaults ?? []
            listsEveryVault = list.vaults != nil
            questions = list.questions
            let enabled = contexts.contains { $0.status.enabled }
            phase = enabled ? .ready : .off
            if enabled { await checkAnswerKeys() }
            await updatePushToken()
        } catch let error as VaultError where error.code == .locked {
            // Nothing can be answered while the vault is locked: say so, never an empty list.
            questions = []
            vaults = []
            phase = .locked
        } catch {
            if case .ready = phase {
                notice = error.localizedDescription
            } else {
                phase = .failed(error.localizedDescription)
            }
        }
    }

    /// Read the list, then wait for changes with the long poll while the task runs.
    func watch() async {
        await refresh()
        askForTokenOnce()
        while !Task.isCancelled {
            guard phase == .ready else {
                // A locked vault opens soon after the owner returns: look again shortly.
                try? await Task.sleep(for: phase == .locked ? retryInterval : .seconds(30))
                await refresh()
                askForTokenOnce()
                continue
            }
            do {
                if try await service.questionsWait(timeout: 25) { await refresh() }
            } catch {
                if Task.isCancelled { return }
                try? await Task.sleep(for: retryInterval)
                await refresh()
            }
        }
    }

    /// Each launch with notifications on asks iOS for the token again (contract section 10.8),
    /// once a vault is open, so the token can reach the relay.
    private func askForTokenOnce() {
        guard phase == .ready, !askedForToken else { return }
        askedForToken = true
        registerPushesIfOn()
    }

    /// The answer key of this iPhone in the row of each vault, in one notice. With two vaults or
    /// more, each line names its vault.
    private func checkAnswerKeys() async {
        var problems: [String] = []
        for context in contexts where context.status.enabled {
            guard let problem = await checkAnswerKey(context) else { continue }
            problems.append(namesVaults ? "\(context.vaultName): \(problem)" : problem)
        }
        notice = problems.isEmpty ? nil : problems.joined(separator: "\n")
    }

    /// The Mac that confirmed this iPhone wrote the row, so this only checks that the row is there
    /// with the key of its team. The core writes nothing, and it checks the selected vault only.
    private func checkAnswerKey(_ context: QuestionsVault) async -> String? {
        let row = context.status
        if row.removed {
            return "This device was removed from questions. To answer again, connect it again with a new link from a Mac."
        }
        guard row.registered else {
            return "Waiting for the Mac that confirmed this iPhone: its vault must sync to this iPhone before it can answer."
        }
        guard let signer = signers.signer(team: row.teamID, registered: row.answerKey) else {
            return Self.noKeyText
        }
        do {
            let key = try signer.publicKey()
            if row.answerKey == key { return nil }
            guard !listsEveryVault || row.teamID == status.teamID else {
                return row.answerKey == nil ? nil : Self.keyChangedText
            }
            _ = try await service.answerKeyRegister(publicKey: key)
            setAnswerKey(key, team: row.teamID)
            return nil
        } catch let error as CompanionKeyError {
            return "To answer here, Apassy needs Face ID on this iPhone. \(error.localizedDescription)"
        } catch let error as VaultError {
            return error.message
        } catch {
            return error.localizedDescription
        }
    }

    private func setAnswerKey(_ key: Data, team: String?) {
        if status.teamID == team { status.answerKey = key }
        for at in vaults.indices where vaults[at].status.teamID == team { vaults[at].status.answerKey = key }
    }

    static let noKeyText =
        "This iPhone has no answer key for this vault. On a Mac, remove this iPhone in Settings › Devices, then connect it again."
    static let keyChangedText =
        "The answer key of this iPhone changed. On a Mac, remove this iPhone in Settings › Devices, then connect it again."

    // MARK: Answers

    /// The text of the Face ID prompt (contract section 5.3): the agent with control characters and
    /// `"` removed, at most 40 characters, and the answer.
    static func faceIDReason(agent: String, answer: String) -> String {
        let cleaned = String(
            String.UnicodeScalarView(
                agent.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) && $0 != "\"" }))
        let name = String(cleaned.prefix(40))
        return "answer a question of agent \"\(name)\": \(answer)"
    }

    /// Send `choice` for `question`. An answer that gives authority asks for Face ID first; the
    /// others go at once. A network failure sends the same signed answer again while it is young.
    func send(_ choice: AnswerBar.Choice, for question: RemoteQuestion) async {
        guard deliveries[question.qid] != .sending, let card = question.card else { return }
        deliveries[question.qid] = .sending
        // The row of this iPhone in the team of the question's vault: its key signs.
        let row = vault(of: question)?.status ?? status
        do {
            let prepared = try await service.questionAnswerString(
                qid: question.qid, answer: choice.answer, vaultID: question.vaultID)
            var signature: Data?
            if prepared.needsFaceID {
                guard let signer = signers.signer(team: row.teamID, registered: row.answerKey) else {
                    throw VaultError(.notRegistered, Self.noKeyText)
                }
                signature = try await signer.sign(
                    Data(prepared.answerString.utf8),
                    reason: Self.faceIDReason(agent: card.run.agent, answer: choice.label))
            }
            let sent = try await post(question, choice.answer, prepared, signature)
            deliveries[question.qid] = .sent(sent.kind)
        } catch CompanionKeyError.cancelled {
            deliveries[question.qid] = nil
        } catch CompanionKeyError.biometryChanged {
            deliveries[question.qid] = .failed(
                "Face ID changed on this iPhone, so Apassy made a new answer key. On a Mac, remove this iPhone in Settings › Devices, then connect it again. Answer on the Mac for now.")
            // A new key for this team only: the rows of the other vaults keep theirs.
            _ = try? signers.renew(team: row.teamID)
        } catch let error as VaultError {
            deliveries[question.qid] = .failed(Self.message(for: error, asker: question.askerName))
        } catch {
            deliveries[question.qid] = .failed(error.localizedDescription)
        }
        await refresh()
    }

    /// Post, and post again after a network failure while the time of the answer is younger than
    /// 55 s (contract section 13, step 4).
    private func post(
        _ question: RemoteQuestion, _ answer: RemoteAnswer, _ prepared: PreparedAnswer, _ signature: Data?
    ) async throws -> SentAnswer {
        while true {
            do {
                return try await service.questionAnswer(
                    qid: question.qid, answer: answer, time: prepared.time, signature: signature,
                    vaultID: question.vaultID)
            } catch let error as VaultError
                where error.code == .relayUnreachable
                && Int64(now().timeIntervalSince1970) - prepared.time < 55 && !Task.isCancelled
            {
                try await Task.sleep(for: retryInterval)
            }
        }
    }

    static func message(for error: VaultError, asker: String) -> String {
        switch error.code {
        case .removed: "This device was removed from questions."
        case .alreadyAnswered: "Already answered."
        case .expired: "Expired."
        case .notRouted: "This device cannot answer this question."
        case .staleAnswer: "This answer is too old to send. Answer again."
        default: error.message
        }
    }

    /// The line under a question that this iPhone answered.
    func deliveryText(for question: RemoteQuestion) -> String? {
        if let settle = question.settle {
            if settle.outcome == "replaced" { return "The request changed. A new question follows." }
            if let name = settle.deviceName { return "Answered on \(name)" }
            return settle.outcome == "timed_out" ? "Expired" : "Ended on \(question.askerName)"
        }
        switch deliveries[question.qid] {
        case .sending: return "Sending…"
        case .sent: return Self.sentText
        case .failed(let message): return message
        case nil:
            if question.answered != nil { return Self.sentText }
            if question.state == .expired { return "Expired" }
            return question.problem
        }
    }

    /// What takes the place of the answer bar: how the question ended, the answer this iPhone
    /// sent, or its expiry. Nil while the owner can answer.
    func outcome(for question: RemoteQuestion) -> QuestionOutcome? {
        if let settle = question.settle {
            let place = settle.deviceName.map { " on \($0)" } ?? ""
            switch settle.outcome {
            case "approved": return QuestionOutcome(text: "Allowed\(place)", tone: .allowed)
            case "denied": return QuestionOutcome(text: "Denied\(place)", tone: .denied)
            case "timed_out": return QuestionOutcome(text: "Expired", tone: .neutral)
            case "replaced":
                return QuestionOutcome(text: "The request changed. A new question follows.", tone: .neutral)
            default: return QuestionOutcome(text: "Ended on \(question.askerName)", tone: .neutral)
            }
        }
        if case .sent = deliveries[question.qid] { return QuestionOutcome(text: Self.sentText, tone: .neutral) }
        if question.answered != nil, deliveries[question.qid] == nil {
            return QuestionOutcome(text: Self.sentText, tone: .neutral)
        }
        if question.state != .open || question.expiresAt <= Int64(now().timeIntervalSince1970) {
            return QuestionOutcome(text: "Expired", tone: .neutral)
        }
        return nil
    }

    static let sentText = "Sent. The Mac checks it; if the run does not continue within a minute, the answer was refused."

    // MARK: Opening a notification

    /// The owner opened a notification. It holds no question (contract section 14.1), so
    /// Decisions opens the newest one that waits.
    func notificationOpened() {
        focusPending = true
        focusRequests += 1
    }

    /// The question to open after a notification, once, or nil: the newest that waits after the
    /// list is read again, so the question the notification announced opens even when the list
    /// was old. `stillFree` is asked after the refresh: false when the owner opened something
    /// meanwhile, and then nothing opens, so a question never changes under the owner's finger.
    func takeFocus(stillFree: () -> Bool) async -> String? {
        guard focusPending else { return nil }
        focusPending = false
        await refresh()
        guard stillFree() else { return nil }
        return waiting.max { $0.createdAt < $1.createdAt }?.qid
    }

    // MARK: Notifications

    /// "Notifications through the relay" on this iPhone. The permission is asked here, at the first
    /// time it is turned on, never at launch (contract section 14.2).
    func setNotifications(_ on: Bool) async {
        if on {
            guard let push, await push.requestAuthorization() else {
                notice = "Notifications are off for Apassy in Settings. Questions still show while Apassy is open."
                notificationsOn = false
                defaults.set(false, forKey: Self.notificationsKey)
                return
            }
            notificationsOn = true
            defaults.set(true, forKey: Self.notificationsKey)
            defaults.removeObject(forKey: Self.pushClearKey)
            defaults.removeObject(forKey: Self.pushClearedKey)
            tokenTeams = []
            push.registerForPushes()
            await updatePushToken()
        } else {
            notificationsOn = false
            defaults.set(false, forKey: Self.notificationsKey)
            // Every team, also those of the vaults that are not open now: each is cleared when
            // its vault is in the list.
            defaults.set(true, forKey: Self.pushClearKey)
            defaults.set([String](), forKey: Self.pushClearedKey)
            tokenTeams = []
            await refresh()
        }
    }

    /// At launch: a new token for the relay when notifications are on.
    func registerPushesIfOn() {
        if notificationsOn { push?.registerForPushes() }
    }

    /// A device token from iOS. It is kept for this launch and goes to the relay of each questions
    /// team in the list, now and when another vault opens.
    func receivePushToken(_ token: Data) async {
        if token != pushToken { tokenTeams = [] }
        pushToken = token
        await updatePushToken()
    }

    /// The teams of the list that can get a token: a questions team, and this iPhone not removed.
    private var pushTeams: Set<String> {
        Set(contexts.filter { $0.status.enabled && !$0.status.removed }.compactMap(\.status.teamID))
    }

    private func updatePushToken() async {
        await clearPushToken()
        await sendPushToken()
    }

    /// Send the token to the teams of the list that do not have it in this launch. A core that keeps
    /// every unlocked vault sends it to the team of each at once; an older core to the team of the
    /// selected vault, so the other teams get it when their vault is selected.
    private func sendPushToken() async {
        guard notificationsOn, let push, let token = pushToken else { return }
        let teams = pushTeams
        guard !teams.isSubset(of: tokenTeams) else { return }
        do {
            try await service.pushTokenSet(token: token, environment: push.environment)
            tokenTeams.formUnion(teams)
        } catch let error as VaultError where error.code == .noQuestions || error.code == .locked {
            // No team yet, or the vault locked: the token goes at the next refresh.
        } catch {
            notice = error.localizedDescription
        }
    }

    /// After notifications were turned off: take the token away from the teams of the list that
    /// still have it. A team that is not in the list now is remembered until its vault is.
    private func clearPushToken() async {
        guard !notificationsOn, defaults.bool(forKey: Self.pushClearKey) else { return }
        var cleared = Set(defaults.stringArray(forKey: Self.pushClearedKey) ?? [])
        let teams = Set(contexts.filter { $0.status.enabled }.compactMap(\.status.teamID))
        guard !teams.isSubset(of: cleared) else { return }
        do {
            try await service.pushTokenClear()
        } catch let error as VaultError where error.code == .noQuestions || error.code == .removed {
            // Nothing to take away.
        } catch {
            return  // The next refresh tries again.
        }
        cleared.formUnion(teams)
        defaults.set(cleared.sorted(), forKey: Self.pushClearedKey)
    }

    // MARK: Connecting a vault from iCloud Drive

    /// Whether `text` looks like a device link of the relay.
    static func isLink(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines).contains("apassy_lnk_")
    }

    /// The paste action accepts either flow. The relay still validates its token in the core.
    static func isConnectionCode(_ text: String) -> Bool {
        isLink(text) || (try? PairingLink.parse(text)) != nil
    }

    func startAttach(link: String, pollInterval: Duration = .seconds(2)) async {
        switch attach {
        case nil, .failed: break
        default: return
        }
        attachGeneration += 1
        let generation = attachGeneration
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            _ = try PairingLink.parse(trimmed, now: now())
            if let problem = onCompanionCode(trimmed) {
                attach = .failed(problem)
            } else {
                attach = .companion
            }
            return
        } catch let error as PairingLinkError {
            // An invalid companion code must never fall through to the relay token heuristic.
            if error != .notAPairingLink || trimmed.lowercased().hasPrefix("apassy:") {
                attach = .failed(error.localizedDescription)
                return
            }
        } catch {
            attach = .failed(error.localizedDescription)
            return
        }
        guard Self.isLink(link) else {
            attach = .failed("This is not a device link of the Apassy relay. On the Mac, make a new link.")
            return
        }
        if let problem = JoinModel.deviceNameProblem(deviceName) {
            attach = .failed(problem)
            return
        }
        let name = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        attach = .starting
        do {
            // Each questions team has its own answer key. The core rejects a key that belonged to a
            // removed row: a removed iPhone gets a new key for that team only.
            let team = VaultText.linkTeam(trimmed) ?? status.teamID
            let renews = status.removed && (status.teamID == nil || team == status.teamID)
            let key = try renews ? signers.renew(team: team) : signers.joinKey(team: team)
            let info = try await service.joinAttach(link: trimmed, deviceName: name, answerKey: key)
            onDeviceName(name)
            guard isCurrentAttach(generation), attach == .starting else { return }
            attach = .waiting(info)
            attachTask?.cancel()
            attachTask = Task { [weak self] in await self?.pollAttach(every: pollInterval, generation: generation) }
        } catch let error as CompanionKeyError {
            guard isCurrentAttach(generation), attach == .starting else { return }
            attach = .failed("To answer here, Apassy needs Face ID on this iPhone. \(error.localizedDescription)")
        } catch {
            guard isCurrentAttach(generation), attach == .starting else { return }
            attach = .failed(error.localizedDescription)
        }
    }

    private func isCurrentAttach(_ generation: Int) -> Bool {
        generation == attachGeneration && !Task.isCancelled
    }

    private func pollAttach(every interval: Duration, generation: Int) async {
        while isCurrentAttach(generation), case .waiting = attach {
            try? await Task.sleep(for: interval)
            guard isCurrentAttach(generation), case .waiting = attach else { return }
            do {
                let info = try await service.joinAttachPoll()
                guard isCurrentAttach(generation), case .waiting = attach else { return }
                if info.state == .attached {
                    attach = .attached
                    await refresh()
                    guard isCurrentAttach(generation), attach == .attached else { return }
                    registerPushesIfOn()
                    return
                }
                attach = .waiting(info)
            } catch let error as VaultError where [.joinRefused, .linkInvalid, .invalidInput].contains(error.code) {
                guard isCurrentAttach(generation), case .waiting = attach else { return }
                attach = .failed(error.message)
                return
            } catch {
                guard isCurrentAttach(generation), case .waiting = attach else { return }
                // No network: the next poll tries again.
            }
        }
    }

    func cancelAttach() {
        attachGeneration += 1
        attachTask?.cancel()
        attachTask = nil
        if case .waiting = attach { Task { try? await service.joinAttachCancel() } }
        attach = nil
    }

    func dismissAttach() {
        attachGeneration += 1
        attachTask?.cancel()
        attachTask = nil
        attach = nil
    }

    /// Wait for the poll of a connection to end, for the tests.
    func attachFinished() async {
        await attachTask?.value
    }
}
