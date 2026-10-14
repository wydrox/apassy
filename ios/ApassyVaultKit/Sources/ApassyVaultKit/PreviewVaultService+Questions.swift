import Foundation

/// The questions of the preview vault: one synthetic question of the contract's test vectors,
/// answers kept in memory, and a join that the "Mac" confirms at the second poll. No value is
/// real, and nothing leaves the process.
///
/// With `addQuestionsVault`, it answers as a core that keeps the questions of every unlocked
/// vault: the list has `vaults` and each question its vault, and the push token reaches every
/// team. Without, it answers as an older core: the selected vault only.
public struct PreviewQuestions: Sendable {
    public struct Sent: Sendable, Equatable {
        public var qid: String
        public var answer: RemoteAnswer
        public var time: Int64
        public var signature: Data?
        /// The `vaultID` of the call.
        public var vaultID: String? = nil
    }

    /// Another unlocked vault with a questions team.
    struct Other: Sendable {
        var id: String
        var name: String
        var team: String
        var questions: [RemoteQuestion]
        var answerKey: Data?
        var registered: Bool
        var removed: Bool
        var pushToken: Data?
        /// The core holds its context: it was unlocked in this session, and no lock or suspend
        /// came since.
        var open = true

        var status: QuestionsStatus {
            QuestionsStatus(
                enabled: true, teamID: team, relayDeviceID: 4,
                deviceUUID: answerKey == nil ? nil : "7a2d1f3b-4c5e-4f60-9a1b-2c3d4e5f6a7b", answerKey: answerKey,
                hasKey: true, registered: registered, removed: removed)
        }
    }

    var enabled = false
    var questions: [RemoteQuestion] = []
    var answerKey: Data?
    var sent: [Sent] = []
    var pushToken: Data?
    var attach: AttachInfo?
    var attachPolls = 0
    /// The next `questionAnswer` fails with this error.
    var nextAnswerError: VaultError?
    var waits: [Bool] = []
    var registrations = 0
    /// The row of this iPhone is in the vault (the Mac that confirmed it wrote the row).
    var registered = true
    /// The owner removed this iPhone on a Mac.
    var removed = false
    /// The answer key that the last `joinAttach` / `joinStart` sent.
    var attachAnswerKey: Data?
    var others: [Other] = []
    /// The selected vault keeps its context after a selection, until a lock or a suspend.
    var ownOpen = false
    /// The vault IDs of each `questionsUnlock`, in order.
    var unlocks: [String] = []

    public init() {}
}

extension PreviewVaultService {
    /// The question of the contract's test vectors (section 7.1), open for five minutes.
    public static func sampleQuestion(qid: String = "oKGio6SlpqeoqaqrrK2urw", now: Date = Date()) -> RemoteQuestion {
        let at = Int64(now.timeIntervalSince1970)
        let card = QuestionCard(
            askerDevice: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", createdAt: at,
            run: QuestionRun(
                id: "123456789012345", agent: "claude-code", command: ["npm", "run", "migrate"],
                cwd: "/tmp/synthetic-shop", envNames: ["DATABASE_URL", "API_TOKEN"],
                purpose: "Apply the new migration.", risk: "production credential: always asks the owner",
                userRequest: "Deploy the new schema to staging.", requestSource: "from the host hook",
                agentRequest: "Run the migration."),
            question: QuestionInfo(
                items: [
                    .init(itemID: "7", name: "Shop database", production: true, unconfirmed: false, alwaysAsk: false),
                    .init(itemID: "9", name: "API token", production: false, unconfirmed: true, alwaysAsk: false),
                ],
                project: .init(key: "/tmp/synthetic-shop/.git", label: "synthetic-shop"), action: .deploy,
                production: true, why: "A production credential goes to a deploy.",
                validAnswers: [
                    "once", "production:deploy", "correct_environment", "never_for_agent", "always_ask_for_agent",
                    "disconnect",
                ]),
            digest: "f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d")
        return RemoteQuestion(
            qid: qid, state: .open, askerName: "MacBook Pro", createdAt: at, expiresAt: at + 300, card: card)
    }

    // MARK: Test and preview hooks

    /// Turn the questions team on or off, with these questions.
    public func setQuestions(
        enabled: Bool, questions: [RemoteQuestion] = [], answerKey: Data? = nil, registered: Bool = true,
        removed: Bool = false
    ) {
        questionsState.enabled = enabled
        questionsState.questions = questions
        questionsState.answerKey = answerKey
        questionsState.registered = registered
        questionsState.removed = removed
    }

    /// Another unlocked vault with its own questions team and questions. From then on the service
    /// answers as a core that keeps the questions of every unlocked vault.
    ///
    /// - Parameters:
    ///   - onPhone: the vault is on this iPhone too (`info`), as a relay vault of `team`.
    ///   - open: the core holds its context now; false: `questionsUnlock` makes it, with the
    ///     passphrase of the preview.
    public func addQuestionsVault(
        id: String, name: String, team: String, questions: [RemoteQuestion] = [], answerKey: Data? = nil,
        registered: Bool = true, removed: Bool = false, onPhone: Bool = false, open: Bool = true
    ) {
        questionsState.others.removeAll { $0.id == id }
        questionsState.others.append(
            .init(
                id: id, name: name, team: team, questions: questions, answerKey: answerKey, registered: registered,
                removed: removed, open: open))
        if onPhone, !vaults.contains(where: { $0.id == id }) {
            vaults.append(
                VaultEntry(
                    id: id, name: name, relayURL: "https://relay.apassy.example", teamID: team, deviceID: 4,
                    addedAt: 1_791_000_100))
        }
    }

    /// The vault IDs of each `questionsUnlock`, in order.
    public func questionsUnlocks() -> [String] { questionsState.unlocks }

    /// Whether the core holds the questions context of the other vault `vaultID`.
    public func hasQuestionsContext(vaultID: String) -> Bool {
        questionsState.others.first { $0.id == vaultID }?.open ?? false
    }

    /// A lock, a suspend, or a removal drops the context of every vault, as the core does.
    func dropQuestionContexts() {
        questionsState.ownOpen = false
        for at in questionsState.others.indices { questionsState.others[at].open = false }
    }

    /// The push token in the team of the vault `vaultID` (the selected vault: `currentPushToken`).
    public func pushToken(vaultID: String) -> Data? {
        questionsState.others.first { $0.id == vaultID }?.pushToken
    }

    /// The answer key that the last `joinAttach` sent.
    public func attachedAnswerKey() -> Data? { questionsState.attachAnswerKey }

    /// The answers that `questionAnswer` took, in order.
    public func sentAnswers() -> [PreviewQuestions.Sent] { questionsState.sent }

    public func registeredAnswerKey() -> Data? { questionsState.answerKey }

    public func answerKeyRegistrations() -> Int { questionsState.registrations }

    public func currentPushToken() -> Data? { questionsState.pushToken }

    /// The next answer fails with `error`, as the relay or the core would.
    public func failNextAnswer(_ error: VaultError) { questionsState.nextAnswerError = error }

    /// The answers of the next `questionsWait` calls; after them it answers false.
    public func scriptQuestionWaits(_ waits: [Bool]) { questionsState.waits = waits }

    /// The Mac settles a question.
    public func settleQuestion(qid: String, by device: String) {
        guard let at = questionsState.questions.firstIndex(where: { $0.qid == qid }) else { return }
        questionsState.questions[at].state = .settled
        questionsState.questions[at].settle = QuestionSettle(
            outcome: "approved", deviceName: device, deviceKind: "iphone", kind: nil,
            at: Int64(Date().timeIntervalSince1970))
    }

    // MARK: VaultService

    private var questionsStatus: QuestionsStatus {
        QuestionsStatus(
            enabled: questionsState.enabled, teamID: questionsState.enabled ? "t_7k2m5q4x3c" : nil,
            relayDeviceID: questionsState.enabled ? 3 : nil,
            deviceUUID: questionsState.answerKey == nil ? nil : "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
            answerKey: questionsState.answerKey, hasKey: questionsState.enabled,
            registered: questionsState.enabled && questionsState.registered,
            removed: questionsState.enabled && questionsState.removed)
    }

    private func requireQuestions() throws {
        guard questionsState.enabled else {
            throw VaultError(.noQuestions, "Questions through the relay are off for this vault.")
        }
    }

    /// The other vault of `vaultID`, or else the one that holds `qid`; nil for the selected vault.
    private func other(qid: String, vaultID: String?) -> Int? {
        if let vaultID { return questionsState.others.firstIndex { $0.id == vaultID } }
        return questionsState.others.firstIndex { $0.questions.contains { $0.qid == qid } }
    }

    private func openQuestion(_ qid: String, other: Int? = nil) throws -> RemoteQuestion {
        let questions: [RemoteQuestion]
        if let other {
            guard questionsState.others[other].open else {
                throw VaultError(.locked, "Unlock this vault to answer its questions.")
            }
            questions = questionsState.others[other].questions
        } else {
            try requireQuestions()
            questions = questionsState.questions
        }
        guard let question = questions.first(where: { $0.qid == qid }) else {
            throw VaultError(.expired, "This question expired.")
        }
        switch question.state {
        case .open: return question
        case .settled: throw VaultError(.alreadyAnswered, "Already answered on another device.")
        case .expired: throw VaultError(.expired, "This question expired.")
        }
    }

    private static func tagged(_ questions: [RemoteQuestion], _ id: String, _ name: String) -> [RemoteQuestion] {
        questions.map { question in
            var question = question
            question.vaultID = id
            question.vaultName = name
            return question
        }
    }

    /// The selected vault has a context: it is open, or it was since the last lock or suspend.
    private var ownContext: Bool { unlocked || questionsState.ownOpen }

    public func questionsList() async throws -> QuestionsList {
        if unlocked { questionsState.ownOpen = true }
        let openOthers = questionsState.others.filter(\.open)
        guard ownContext || !openOthers.isEmpty else { throw VaultError(.locked, "The vault is locked.") }
        let own = ownContext && questionsState.enabled && !questionsState.removed ? questionsState.questions : []
        guard !questionsState.others.isEmpty else { return QuestionsList(status: questionsStatus, questions: own) }
        let selected = try await info().selectedVault
        let (id, name) = (selected?.id ?? "", selected?.name ?? "This vault")
        var vaults: [QuestionsVault] = []
        if questionsState.enabled, ownContext {
            vaults.append(QuestionsVault(vaultID: id, vaultName: name, status: questionsStatus))
        }
        var questions = Self.tagged(own, id, name)
        for other in openOthers {
            vaults.append(QuestionsVault(vaultID: other.id, vaultName: other.name, status: other.status))
            if !other.removed { questions += Self.tagged(other.questions, other.id, other.name) }
        }
        return QuestionsList(status: questionsStatus, questions: questions, vaults: vaults)
    }

    public func questionsUnlock(vaultID: String, passphrase: String) async throws -> QuestionsStatus {
        guard vaults.contains(where: { $0.id == vaultID }) else {
            throw VaultError(.noVault, "This vault is not on this iPhone.")
        }
        // The key derivation of the core takes a moment.
        try await Task.sleep(for: .milliseconds(100))
        guard passphrase == Self.passphrase else {
            throw VaultError(.wrongPassphrase, "The passphrase does not open this vault.")
        }
        questionsState.unlocks.append(vaultID)
        if vaultID == selected {
            questionsState.ownOpen = true
            return questionsStatus
        }
        guard let at = questionsState.others.firstIndex(where: { $0.id == vaultID }) else { return .off }
        questionsState.others[at].open = true
        return questionsState.others[at].status
    }

    public func questionsWait(timeout: Int) async throws -> Bool {
        if questionsState.waits.isEmpty {
            try await Task.sleep(for: .milliseconds(200))
            return false
        }
        return questionsState.waits.removeFirst()
    }

    public func questionOpen(qid: String) async throws -> RemoteQuestion { try openQuestion(qid) }

    public func questionAnswerString(qid: String, answer: RemoteAnswer) async throws -> PreparedAnswer {
        try await questionAnswerString(qid: qid, answer: answer, vaultID: nil)
    }

    public func questionAnswerString(qid: String, answer: RemoteAnswer, vaultID: String?) async throws
        -> PreparedAnswer
    {
        let other = other(qid: qid, vaultID: vaultID)
        let question = try openQuestion(qid, other: other)
        let status = other.map { questionsState.others[$0].status } ?? questionsStatus
        let time = Int64(Date().timeIntervalSince1970)
        let line =
            switch answer.kind {
            case .approveInProject, .allowProduction:
                "\(answer.kind.rawValue):\(question.card?.question.action.rawValue ?? ""):/tmp/synthetic-shop/.git"
            case .correctEnvironment:
                "correct_environment:\(answer.environment?.rawValue ?? ""):\(answer.itemID ?? "")"
            default: answer.kind.rawValue
            }
        let text = [
            "apassy-question-answer-v1", status.deviceUUID ?? "", status.teamID ?? "", qid, line,
            question.card?.digest ?? "", String(time),
        ].joined(separator: "\n")
        return PreparedAnswer(time: time, answerString: text, needsFaceID: answer.needsFaceID)
    }

    public func questionAnswer(qid: String, answer: RemoteAnswer, time: Int64, signature: Data?) async throws
        -> SentAnswer
    {
        try await questionAnswer(qid: qid, answer: answer, time: time, signature: signature, vaultID: nil)
    }

    public func questionAnswer(
        qid: String, answer: RemoteAnswer, time: Int64, signature: Data?, vaultID: String?
    ) async throws -> SentAnswer {
        let other = other(qid: qid, vaultID: vaultID)
        _ = try openQuestion(qid, other: other)
        let status = other.map { questionsState.others[$0].status } ?? questionsStatus
        if status.removed { throw VaultError(.removed, "This device was removed from questions.") }
        if let error = questionsState.nextAnswerError {
            questionsState.nextAnswerError = nil
            throw error
        }
        guard status.answerKey != nil else {
            throw VaultError(.notRegistered, "Turn on answers on this iPhone first.")
        }
        if answer.needsFaceID != (signature != nil) {
            throw VaultError(.invalidInput, "This answer needs Face ID.")
        }
        questionsState.sent.append(
            .init(qid: qid, answer: answer, time: time, signature: signature, vaultID: vaultID))
        if let other {
            if let at = questionsState.others[other].questions.firstIndex(where: { $0.qid == qid }) {
                questionsState.others[other].questions[at].answered = answer.kind
            }
        } else if let at = questionsState.questions.firstIndex(where: { $0.qid == qid }) {
            questionsState.questions[at].answered = answer.kind
        }
        return SentAnswer(id: UInt64(questionsState.sent.count), at: time, kind: answer.kind)
    }

    public func answerKeyRegister(publicKey: Data) async throws -> AnswerKeyRegistration {
        try requireQuestions()
        guard publicKey.count == 65, publicKey.first == 0x04 else {
            throw VaultError(.invalidInput, "The answer key is not a P-256 public key.")
        }
        if questionsState.removed { throw VaultError(.removed, "This device was removed from questions.") }
        if let row = questionsState.answerKey, row != publicKey {
            throw VaultError(
                .answerKeyChanged,
                "The answer key of this iPhone changed. On a Mac, remove this iPhone in Settings › Devices, then connect it again.")
        }
        questionsState.answerKey = publicKey
        questionsState.registered = true
        questionsState.registrations += 1
        return AnswerKeyRegistration(
            deviceUUID: "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b", teamID: "t_7k2m5q4x3c", relayDeviceID: 3)
    }

    public func pushTokenSet(token: Data, environment: PushEnvironment) async throws {
        if questionsState.others.isEmpty { try requireQuestions() }
        if questionsState.enabled { questionsState.pushToken = token }
        for at in questionsState.others.indices where questionsState.others[at].open {
            questionsState.others[at].pushToken = token
        }
    }

    public func pushTokenClear() async throws {
        questionsState.pushToken = nil
        for at in questionsState.others.indices { questionsState.others[at].pushToken = nil }
    }

    public func joinAttach(link: String, deviceName: String, answerKey: Data) async throws -> AttachInfo {
        guard link.contains("apassy_lnk_") else {
            throw VaultError(.linkInvalid, "This is not a device link of the Apassy relay.")
        }
        guard !questionsState.enabled || questionsState.removed else {
            throw VaultError(.invalidInput, "This vault gets questions through the relay already.")
        }
        questionsState.attachPolls = 0
        questionsState.attachAnswerKey = answerKey
        let info = AttachInfo(
            state: .waiting, team: "Notifications", words: ["amber", "marble"],
            expiresAt: Int64(Date().timeIntervalSince1970) + 600)
        questionsState.attach = info
        return info
    }

    public func joinAttachPoll() async throws -> AttachInfo {
        guard var info = questionsState.attach else {
            throw VaultError(.invalidInput, "No connection waits. Scan the code of the Mac again.")
        }
        questionsState.attachPolls += 1
        if questionsState.attachPolls >= 2 {
            info.state = .attached
            questionsState.attach = nil
            questionsState.enabled = true
            // The Mac that confirms writes the row of this iPhone with the key that it sent.
            questionsState.answerKey = questionsState.attachAnswerKey
            questionsState.registered = true
            questionsState.removed = false
        } else {
            questionsState.attach = info
        }
        return info
    }

    public func joinAttachCancel() async throws { questionsState.attach = nil }
}
