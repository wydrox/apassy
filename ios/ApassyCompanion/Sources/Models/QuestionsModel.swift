import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Observation

/// Signs the answers that give authority with the answer key, after Face ID for each answer
/// (contract relay-questions-v1, section 5.3).
protocol AnswerSigner: Sendable {
    /// The public key (X9.63), made on first use.
    func publicKey() throws -> Data
    /// A signature (DER). The owner sees `reason` in the Face ID prompt.
    func sign(_ message: Data, reason: String) async throws -> Data
    /// A new key, after a new Face ID enrollment made the old one unusable.
    func renew() throws -> Data
}

/// The answer key in the Secure Enclave, bound to the current biometric set with no passcode
/// fallback (as the companion approval key), under a keychain service of its own so the companion
/// pairing keeps its keys. The Simulator has software keys.
struct EnclaveAnswerSigner: AnswerSigner {
    static let service = "com.wydrox.apassy.questions"

    func publicKey() throws -> Data { try keys().approvalPublicKey }

    func sign(_ message: Data, reason: String) async throws -> Data {
        try await keys().signApproval(message, reason: reason)
    }

    func renew() throws -> Data {
        try CompanionKeyStore.createNew(service: Self.service).approvalPublicKey
    }

    private func keys() throws -> any CompanionKeys {
        if let keys = try CompanionKeyStore.loadExisting(service: Self.service) { return keys }
        return try CompanionKeyStore.createNew(service: Self.service)
    }
}

/// Notification permission and the APNs registration (`PushRegistrar` in the app).
@MainActor
protocol PushPermission: AnyObject {
    /// Ask iOS once; true when the owner allows notifications.
    func requestAuthorization() async -> Bool
    /// Ask iOS for a device token. It arrives in `QuestionsModel.receivePushToken`.
    func registerForPushes()
    /// The APNs environment of this build.
    var environment: PushEnvironment { get }
}

/// The buttons of a question, as on the Mac (ADR 0026): Deny · Allow Once · the main answer, and
/// a "⋯" menu with the stricter answers and the environment of an item.
struct AnswerBar: Equatable {
    struct Choice: Equatable, Identifiable {
        let answer: RemoteAnswer
        let label: String
        var destructive = false

        var id: String { "\(answer.kind.rawValue)-\(answer.itemID ?? "")-\(answer.environment?.rawValue ?? "")" }
    }

    var deny: Choice
    var allowOnce: Choice?
    /// "Allow production: Deploy in shop", "Allow Deploy in shop", or "Development".
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
                answer: RemoteAnswer(kind: .allowProduction), label: "Allow production: \(action.label) in \(project)")
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
}

/// Questions through the relay on this iPhone (contract relay-questions-v1, section 13): the list
/// of the questions of the vault, the answer bar, Face ID for the answers that give authority, the
/// answer key in the vault, the notifications, and the connection of a vault from iCloud Drive to
/// its notifications team.
@MainActor
@Observable
final class QuestionsModel {
    enum Phase: Equatable {
        case loading
        /// The vault has no questions team: connect this iPhone.
        case off
        case ready
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
        case starting
        /// The Mac shows the same words and waits for the owner to confirm.
        case waiting(AttachInfo)
        case attached
        case failed(String)
    }

    static let notificationsKey = "ApassyQuestionNotifications"

    private(set) var phase = Phase.loading
    private(set) var status = QuestionsStatus.off
    private(set) var questions: [RemoteQuestion] = []
    private(set) var deliveries: [String: Delivery] = [:]
    private(set) var attach: AttachStep?
    /// A problem with the answer key or the notifications, for a line under the list.
    private(set) var notice: String?
    private(set) var notificationsOn: Bool

    @ObservationIgnored private let service: any VaultService
    @ObservationIgnored private let signer: any AnswerSigner
    @ObservationIgnored private weak var push: (any PushPermission)?
    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let deviceName: String
    @ObservationIgnored private let now: @MainActor () -> Date
    @ObservationIgnored private let retryInterval: Duration
    @ObservationIgnored private var attachTask: Task<Void, Never>?
    @ObservationIgnored private var askedForToken = false

    init(
        service: any VaultService, signer: any AnswerSigner, push: (any PushPermission)?, deviceName: String,
        defaults: UserDefaults = .standard, now: @escaping @MainActor () -> Date = { Date() },
        retryInterval: Duration = .seconds(2)
    ) {
        self.service = service
        self.signer = signer
        self.push = push
        self.deviceName = deviceName
        self.defaults = defaults
        self.now = now
        self.retryInterval = retryInterval
        notificationsOn = defaults.bool(forKey: Self.notificationsKey)
    }

    /// The questions that wait for an answer now.
    var waiting: [RemoteQuestion] {
        let at = Int64(now().timeIntervalSince1970)
        return questions.filter { $0.state == .open && $0.expiresAt > at }
    }

    var waitingCount: Int { waiting.count }

    // MARK: The list

    /// Read the list. With a questions team, register the answer key of this iPhone when the vault
    /// does not have it.
    func refresh() async {
        do {
            let list = try await service.questionsList()
            status = list.status
            questions = list.questions
            phase = list.status.enabled ? .ready : .off
            if list.status.enabled { await registerAnswerKey() }
        } catch let error as VaultError where error.code == .locked {
            questions = []
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
        // Each launch with notifications on sends the token again (contract section 10.8), once
        // the vault is open, so the token can reach the relay.
        if phase == .ready, !askedForToken {
            askedForToken = true
            registerPushesIfOn()
        }
        while !Task.isCancelled {
            guard phase == .ready else {
                try? await Task.sleep(for: .seconds(30))
                await refresh()
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

    /// The answer key of this iPhone in the vault. The Mac that confirmed this iPhone wrote the
    /// row, so this only checks that the row is there with this key. The core writes nothing.
    private func registerAnswerKey() async {
        if status.removed {
            notice = "This device was removed from questions. To answer again, connect it again with a new link from a Mac."
            return
        }
        guard status.registered else {
            notice = "Waiting for the Mac that confirmed this iPhone: its vault must sync to this iPhone before it can answer."
            return
        }
        do {
            let key = try signer.publicKey()
            if status.answerKey == key {
                notice = nil
                return
            }
            _ = try await service.answerKeyRegister(publicKey: key)
            status.answerKey = key
        } catch let error as CompanionKeyError {
            notice = "To answer here, Apassy needs Face ID on this iPhone. \(error.localizedDescription)"
        } catch let error as VaultError {
            notice = error.message
        } catch {
            notice = error.localizedDescription
        }
    }

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
        do {
            let prepared = try await service.questionAnswerString(qid: question.qid, answer: choice.answer)
            var signature: Data?
            if prepared.needsFaceID {
                signature = try await signer.sign(
                    Data(prepared.answerString.utf8),
                    reason: Self.faceIDReason(agent: card.run.agent, answer: choice.label))
            }
            let sent = try await post(question.qid, choice.answer, prepared, signature)
            deliveries[question.qid] = .sent(sent.kind)
        } catch CompanionKeyError.cancelled {
            deliveries[question.qid] = nil
        } catch CompanionKeyError.biometryChanged {
            deliveries[question.qid] = .failed(
                "Face ID changed on this iPhone, so Apassy made a new answer key. On a Mac, remove this iPhone in Settings › Devices, then connect it again. Answer on the Mac for now.")
            _ = try? signer.renew()
        } catch let error as VaultError {
            deliveries[question.qid] = .failed(Self.message(for: error, asker: question.askerName))
        } catch {
            deliveries[question.qid] = .failed(error.localizedDescription)
        }
        await refresh()
    }

    /// Post, and post again after a network failure while the time of the answer is younger than
    /// 55 s (contract section 13, step 4).
    private func post(_ qid: String, _ answer: RemoteAnswer, _ prepared: PreparedAnswer, _ signature: Data?)
        async throws -> SentAnswer
    {
        while true {
            do {
                return try await service.questionAnswer(
                    qid: qid, answer: answer, time: prepared.time, signature: signature)
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
        case .sent: return "Sent. The Mac checks it; if the run does not continue within a minute, the answer was refused."
        case .failed(let message): return message
        case nil:
            if question.answered != nil { return "Sent. The Mac checks it; if the run does not continue within a minute, the answer was refused." }
            if question.state == .expired { return "Expired" }
            return question.problem
        }
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
            push.registerForPushes()
        } else {
            notificationsOn = false
            defaults.set(false, forKey: Self.notificationsKey)
            try? await service.pushTokenClear()
        }
    }

    /// At launch: a new token for the relay when notifications are on.
    func registerPushesIfOn() {
        if notificationsOn { push?.registerForPushes() }
    }

    /// A device token from iOS: it goes to the relay of the questions team.
    func receivePushToken(_ token: Data) async {
        guard notificationsOn, let push else { return }
        do {
            try await service.pushTokenSet(token: token, environment: push.environment)
        } catch let error as VaultError where error.code == .noQuestions || error.code == .locked {
            // No team yet, or the vault locked: the token goes at the next launch.
        } catch {
            notice = error.localizedDescription
        }
    }

    // MARK: Connecting a vault from iCloud Drive

    /// Whether `text` looks like a device link of the relay.
    static func isLink(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines).contains("apassy_lnk_")
    }

    func startAttach(link: String, pollInterval: Duration = .seconds(2)) async {
        guard Self.isLink(link) else {
            attach = .failed("This is not a device link of the Apassy relay. On the Mac, make a new link.")
            return
        }
        attach = .starting
        do {
            // The core rejects a key that belonged to a removed row: a removed iPhone gets a new one.
            let key = try status.removed ? signer.renew() : signer.publicKey()
            let info = try await service.joinAttach(
                link: link.trimmingCharacters(in: .whitespacesAndNewlines), deviceName: deviceName, answerKey: key)
            attach = .waiting(info)
            attachTask?.cancel()
            attachTask = Task { [weak self] in await self?.pollAttach(every: pollInterval) }
        } catch let error as CompanionKeyError {
            attach = .failed("To answer here, Apassy needs Face ID on this iPhone. \(error.localizedDescription)")
        } catch {
            attach = .failed(error.localizedDescription)
        }
    }

    private func pollAttach(every interval: Duration) async {
        while !Task.isCancelled, case .waiting = attach {
            try? await Task.sleep(for: interval)
            guard !Task.isCancelled, case .waiting = attach else { return }
            do {
                let info = try await service.joinAttachPoll()
                if info.state == .attached {
                    attach = .attached
                    await refresh()
                    registerPushesIfOn()
                    return
                }
                attach = .waiting(info)
            } catch let error as VaultError where [.joinRefused, .linkInvalid, .invalidInput].contains(error.code) {
                attach = .failed(error.message)
                return
            } catch {
                // No network: the next poll tries again.
            }
        }
    }

    func cancelAttach() {
        attachTask?.cancel()
        attachTask = nil
        if case .waiting = attach { Task { try? await service.joinAttachCancel() } }
        attach = nil
    }

    func dismissAttach() {
        attachTask?.cancel()
        attachTask = nil
        attach = nil
    }

    /// Wait for the poll of a connection to end, for the tests.
    func attachFinished() async {
        await attachTask?.value
    }
}
