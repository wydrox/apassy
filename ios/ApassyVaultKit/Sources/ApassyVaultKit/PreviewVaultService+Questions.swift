import Foundation

/// The questions of the preview vault: one synthetic question of the contract's test vectors,
/// answers kept in memory, and a join that the "Mac" confirms at the second poll. No value is
/// real, and nothing leaves the process.
public struct PreviewQuestions: Sendable {
    public struct Sent: Sendable, Equatable {
        public var qid: String
        public var answer: RemoteAnswer
        public var time: Int64
        public var signature: Data?
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
    public func setQuestions(enabled: Bool, questions: [RemoteQuestion] = [], answerKey: Data? = nil) {
        questionsState.enabled = enabled
        questionsState.questions = questions
        questionsState.answerKey = answerKey
    }

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
            answerKey: questionsState.answerKey, hasKey: questionsState.enabled)
    }

    private func requireQuestions() throws {
        guard questionsState.enabled else {
            throw VaultError(.noQuestions, "Questions through the relay are off for this vault.")
        }
    }

    private func openQuestion(_ qid: String) throws -> RemoteQuestion {
        try requireQuestions()
        guard let question = questionsState.questions.first(where: { $0.qid == qid }) else {
            throw VaultError(.expired, "This question expired.")
        }
        switch question.state {
        case .open: return question
        case .settled: throw VaultError(.alreadyAnswered, "Already answered on another device.")
        case .expired: throw VaultError(.expired, "This question expired.")
        }
    }

    public func questionsList() async throws -> QuestionsList {
        QuestionsList(status: questionsStatus, questions: questionsState.enabled ? questionsState.questions : [])
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
        let question = try openQuestion(qid)
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
            "apassy-question-answer-v1", questionsStatus.deviceUUID ?? "", "t_7k2m5q4x3c", qid, line,
            question.card?.digest ?? "", String(time),
        ].joined(separator: "\n")
        return PreparedAnswer(time: time, answerString: text, needsFaceID: answer.needsFaceID)
    }

    public func questionAnswer(qid: String, answer: RemoteAnswer, time: Int64, signature: Data?) async throws
        -> SentAnswer
    {
        _ = try openQuestion(qid)
        if let error = questionsState.nextAnswerError {
            questionsState.nextAnswerError = nil
            throw error
        }
        guard questionsState.answerKey != nil else {
            throw VaultError(.notRegistered, "Turn on answers on this iPhone first.")
        }
        if answer.needsFaceID != (signature != nil) {
            throw VaultError(.invalidInput, "This answer needs Face ID.")
        }
        questionsState.sent.append(.init(qid: qid, answer: answer, time: time, signature: signature))
        if let at = questionsState.questions.firstIndex(where: { $0.qid == qid }) {
            questionsState.questions[at].answered = answer.kind
        }
        return SentAnswer(id: UInt64(questionsState.sent.count), at: time, kind: answer.kind)
    }

    public func answerKeyRegister(publicKey: Data) async throws -> AnswerKeyRegistration {
        try requireQuestions()
        guard publicKey.count == 65, publicKey.first == 0x04 else {
            throw VaultError(.invalidInput, "The answer key is not a P-256 public key.")
        }
        questionsState.answerKey = publicKey
        questionsState.registrations += 1
        return AnswerKeyRegistration(
            deviceUUID: "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b", teamID: "t_7k2m5q4x3c", relayDeviceID: 3)
    }

    public func pushTokenSet(token: Data, environment: PushEnvironment) async throws {
        try requireQuestions()
        questionsState.pushToken = token
    }

    public func pushTokenClear() async throws { questionsState.pushToken = nil }

    public func joinAttach(link: String, deviceName: String) async throws -> AttachInfo {
        guard link.contains("apassy_lnk_") else {
            throw VaultError(.linkInvalid, "This is not a device link of the Apassy relay.")
        }
        guard !questionsState.enabled else {
            throw VaultError(.invalidInput, "This vault gets questions through the relay already.")
        }
        questionsState.attachPolls = 0
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
        } else {
            questionsState.attach = info
        }
        return info
    }

    public func joinAttachCancel() async throws { questionsState.attach = nil }
}
