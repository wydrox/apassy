import Foundation

// Questions through the relay (contract relay-questions-v1; ios-core-v1 section 5.10): the
// models of the core's answers, and the kinds of answer. The core opens and checks each card;
// every text here is for display, with control and format characters replaced.

/// The questions of the vaults, and whether the selected vault has a questions team. A core that
/// keeps the questions of every unlocked vault lists them all, with `vaults`; an older core lists
/// the selected vault only, and `vaults` is nil.
public struct QuestionsList: Codable, Sendable, Equatable {
    /// The selected vault.
    public var status: QuestionsStatus
    public var questions: [RemoteQuestion]
    /// One entry per vault with a questions context (the vaults unlocked this session), or nil
    /// from an older core.
    public var vaults: [QuestionsVault]?

    public init(status: QuestionsStatus, questions: [RemoteQuestion], vaults: [QuestionsVault]? = nil) {
        self.status = status
        self.questions = questions
        self.vaults = vaults
    }

    /// No questions team: the vault gets no questions through the relay.
    public static let off = QuestionsList(status: .off, questions: [])

    enum CodingKeys: String, CodingKey {
        case status, questions, vaults
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(QuestionsStatus.self, forKey: .status)
        questions = try container.decode([RemoteQuestion].self, forKey: .questions)
        // A list of vaults that this app cannot read is left out: the selected vault still
        // answers as with an older core.
        vaults = try? container.decodeIfPresent([QuestionsVault].self, forKey: .vaults)
    }
}

/// A vault whose questions the core keeps: its questions team and this iPhone's row in it.
public struct QuestionsVault: Codable, Sendable, Equatable, Identifiable {
    public var vaultID: String
    public var vaultName: String
    public var status: QuestionsStatus

    public var id: String { vaultID }

    public init(vaultID: String, vaultName: String, status: QuestionsStatus) {
        self.vaultID = vaultID
        self.vaultName = vaultName
        self.status = status
    }

    enum CodingKeys: String, CodingKey {
        case status
        case vaultID = "vault_id"
        case vaultName = "vault_name"
    }
}

public struct QuestionsStatus: Codable, Sendable, Equatable {
    /// Whether the vault has a questions team (relay sync, or `joinAttach`).
    public var enabled: Bool
    public var teamID: String?
    public var relayDeviceID: UInt64?
    /// This iPhone's `trusted_device` row, once registered.
    public var deviceUUID: String?
    /// The registered answer key (X9.63), when there is one.
    public var answerKey: Data?
    /// Whether the vault holds a question key. Without it no card opens: the vault needs a sync.
    public var hasKey: Bool
    /// Whether the row of this iPhone is in the vault (the Mac that confirmed it wrote the row).
    public var registered: Bool
    /// Whether the owner removed this iPhone on a Mac. Then the list has no questions.
    public var removed: Bool

    public init(
        enabled: Bool, teamID: String? = nil, relayDeviceID: UInt64? = nil, deviceUUID: String? = nil,
        answerKey: Data? = nil, hasKey: Bool = false, registered: Bool = false, removed: Bool = false
    ) {
        self.enabled = enabled
        self.teamID = teamID
        self.relayDeviceID = relayDeviceID
        self.deviceUUID = deviceUUID
        self.answerKey = answerKey
        self.hasKey = hasKey
        self.registered = registered
        self.removed = removed
    }

    public static let off = QuestionsStatus(enabled: false)

    enum CodingKeys: String, CodingKey {
        case enabled
        case teamID = "team_id"
        case relayDeviceID = "relay_device_id"
        case deviceUUID = "device_uuid"
        case answerKey = "answer_key"
        case hasKey = "has_key"
        case registered
        case removed
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try container.decode(Bool.self, forKey: .enabled)
        teamID = try container.decodeIfPresent(String.self, forKey: .teamID)
        relayDeviceID = try container.decodeIfPresent(UInt64.self, forKey: .relayDeviceID)
        deviceUUID = try container.decodeIfPresent(String.self, forKey: .deviceUUID)
        answerKey = try container.decodeIfPresent(String.self, forKey: .answerKey).flatMap(Base64URL.decode)
        hasKey = try container.decode(Bool.self, forKey: .hasKey)
        registered = try container.decodeIfPresent(Bool.self, forKey: .registered) ?? false
        removed = try container.decodeIfPresent(Bool.self, forKey: .removed) ?? false
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(enabled, forKey: .enabled)
        try container.encodeIfPresent(teamID, forKey: .teamID)
        try container.encodeIfPresent(relayDeviceID, forKey: .relayDeviceID)
        try container.encodeIfPresent(deviceUUID, forKey: .deviceUUID)
        try container.encodeIfPresent(answerKey.map(Base64URL.encode), forKey: .answerKey)
        try container.encode(hasKey, forKey: .hasKey)
        try container.encode(registered, forKey: .registered)
        try container.encode(removed, forKey: .removed)
    }
}

/// A question of the relay as this iPhone sees it.
public struct RemoteQuestion: Codable, Sendable, Equatable, Identifiable {
    public enum State: String, Codable, Sendable { case open, settled, expired }

    public var qid: String
    public var state: State
    /// The asking Mac.
    public var askerName: String
    public var createdAt: Int64
    public var expiresAt: Int64
    /// Why the card cannot be shown ("Sync this vault to read this question." …), or nil.
    public var problem: String?
    public var card: QuestionCard?
    public var settle: QuestionSettle?
    /// The kind of the answer this iPhone sent, while the core remembers it.
    public var answered: AnswerKind?
    /// The vault that got the question, from a core that keeps the questions of every unlocked
    /// vault; nil from an older core (then it is the selected vault).
    public var vaultID: String?
    public var vaultName: String?

    public var id: String { qid }

    public init(
        qid: String, state: State, askerName: String, createdAt: Int64, expiresAt: Int64, problem: String? = nil,
        card: QuestionCard? = nil, settle: QuestionSettle? = nil, answered: AnswerKind? = nil,
        vaultID: String? = nil, vaultName: String? = nil
    ) {
        self.qid = qid
        self.state = state
        self.askerName = askerName
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.problem = problem
        self.card = card
        self.settle = settle
        self.answered = answered
        self.vaultID = vaultID
        self.vaultName = vaultName
    }

    enum CodingKeys: String, CodingKey {
        case qid, state, problem, card, settle, answered
        case askerName = "asker_name"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
        case vaultID = "vault_id"
        case vaultName = "vault_name"
    }
}

/// The card of a question: the run that waits on the Mac, and the question about it.
public struct QuestionCard: Codable, Sendable, Equatable {
    public var askerDevice: String
    public var createdAt: Int64
    public var run: QuestionRun
    public var question: QuestionInfo
    public var digest: String

    public init(askerDevice: String, createdAt: Int64, run: QuestionRun, question: QuestionInfo, digest: String) {
        self.askerDevice = askerDevice
        self.createdAt = createdAt
        self.run = run
        self.question = question
        self.digest = digest
    }

    enum CodingKeys: String, CodingKey {
        case run, question, digest
        case askerDevice = "asker_device"
        case createdAt = "created_at"
    }
}

public struct QuestionRun: Codable, Sendable, Equatable {
    public struct Remember: Codable, Sendable, Equatable {
        public var pattern: String
        public var approvals: UInt32
        public var needed: UInt32
    }

    public var id: String
    public var agent: String
    public var command: [String]
    public var cwd: String
    public var envNames: [String]
    public var purpose: String
    public var risk: String
    public var userRequest: String
    public var requestSource: String
    public var agentRequest: String
    public var remember: Remember?

    public init(
        id: String, agent: String, command: [String], cwd: String, envNames: [String], purpose: String,
        risk: String, userRequest: String, requestSource: String, agentRequest: String, remember: Remember? = nil
    ) {
        self.id = id
        self.agent = agent
        self.command = command
        self.cwd = cwd
        self.envNames = envNames
        self.purpose = purpose
        self.risk = risk
        self.userRequest = userRequest
        self.requestSource = requestSource
        self.agentRequest = agentRequest
        self.remember = remember
    }

    enum CodingKeys: String, CodingKey {
        case id, agent, command, cwd, purpose, risk, remember
        case envNames = "env_names"
        case userRequest = "user_request"
        case requestSource = "request_source"
        case agentRequest = "agent_request"
    }
}

/// The kind of action of a question: what the command does with the credential.
public enum QuestionAction: String, Codable, Sendable {
    case read, change, deploy, delete

    /// The word in a button: "Read", "Change", "Deploy", "Delete" (as on the Mac).
    public var label: String {
        switch self {
        case .read: "Read"
        case .change: "Change"
        case .deploy: "Deploy"
        case .delete: "Delete"
        }
    }
}

public struct QuestionInfo: Codable, Sendable, Equatable {
    public struct Item: Codable, Sendable, Equatable, Identifiable {
        public var itemID: String
        public var name: String
        public var production: Bool
        /// Production only by default: the question offers "Development" and "Production".
        public var unconfirmed: Bool
        public var alwaysAsk: Bool

        public var id: String { itemID }

        public init(itemID: String, name: String, production: Bool, unconfirmed: Bool, alwaysAsk: Bool) {
            self.itemID = itemID
            self.name = name
            self.production = production
            self.unconfirmed = unconfirmed
            self.alwaysAsk = alwaysAsk
        }

        enum CodingKeys: String, CodingKey {
            case name, production, unconfirmed
            case itemID = "item_id"
            case alwaysAsk = "always_ask"
        }
    }

    public struct Project: Codable, Sendable, Equatable {
        /// The project key for display, shortened.
        public var key: String
        public var label: String

        public init(key: String, label: String) {
            self.key = key
            self.label = label
        }
    }

    public var items: [Item]
    public var project: Project?
    public var action: QuestionAction
    public var production: Bool
    public var why: String
    /// The answers that the question offers, as the card has them: `once`, `in_project:deploy`,
    /// `production:deploy`, `never_for_agent`, `always_ask_for_agent`, `disconnect`,
    /// `correct_environment`. "Deny" is always valid.
    public var validAnswers: [String]

    public init(
        items: [Item], project: Project?, action: QuestionAction, production: Bool, why: String,
        validAnswers: [String]
    ) {
        self.items = items
        self.project = project
        self.action = action
        self.production = production
        self.why = why
        self.validAnswers = validAnswers
    }

    enum CodingKeys: String, CodingKey {
        case items, project, action, production, why
        case validAnswers = "valid_answers"
    }
}

/// How the asking Mac ended a question.
public struct QuestionSettle: Codable, Sendable, Equatable {
    /// `approved`, `denied`, `timed_out`, `invalidated`, or `replaced`.
    public var outcome: String
    public var deviceName: String?
    /// `mac` or `iphone`.
    public var deviceKind: String?
    public var kind: String?
    public var at: Int64
    public var replacedBy: String?

    public init(
        outcome: String, deviceName: String? = nil, deviceKind: String? = nil, kind: String? = nil, at: Int64,
        replacedBy: String? = nil
    ) {
        self.outcome = outcome
        self.deviceName = deviceName
        self.deviceKind = deviceKind
        self.kind = kind
        self.at = at
        self.replacedBy = replacedBy
    }

    enum CodingKeys: String, CodingKey {
        case outcome, kind, at
        case deviceName = "device_name"
        case deviceKind = "device_kind"
        case replacedBy = "replaced_by"
    }
}

/// The kinds of answer (contract section 9.1).
public enum AnswerKind: String, Codable, Sendable, CaseIterable {
    case approveOnce = "approve_once"
    case approveInProject = "approve_in_project"
    case allowProduction = "allow_production"
    case correctEnvironment = "correct_environment"
    case deny
    case neverForAgent = "never_for_agent"
    case alwaysAskForAgent = "always_ask_for_agent"
    case disconnect
}

/// The environment of a correction.
public enum QuestionEnvironment: String, Codable, Sendable {
    case development, production
}

/// An answer to send: its kind, and for a correction the item and the environment. The core
/// fills in the action and the exact project key from the card.
public struct RemoteAnswer: Sendable, Equatable, Hashable {
    public var kind: AnswerKind
    public var itemID: String?
    public var environment: QuestionEnvironment?

    public init(kind: AnswerKind, itemID: String? = nil, environment: QuestionEnvironment? = nil) {
        self.kind = kind
        self.itemID = itemID
        self.environment = environment
    }

    /// Whether this answer gives authority, so the answer key signs it after Face ID (contract
    /// section 5.3). The others take authority away: the core signs them without Face ID.
    public var needsFaceID: Bool {
        switch kind {
        case .approveOnce, .approveInProject, .allowProduction: true
        case .correctEnvironment: environment == .development
        case .deny, .neverForAgent, .alwaysAskForAgent, .disconnect: false
        }
    }

    /// The parameters of the core call.
    public var parameters: [String: Any] {
        var params: [String: Any] = ["kind": kind.rawValue]
        if let itemID { params["item_id"] = itemID }
        if let environment { params["environment"] = environment.rawValue }
        return params
    }
}

/// The exact string to sign, from the core.
public struct PreparedAnswer: Codable, Sendable, Equatable {
    /// The time of the answer, set before the Face ID prompt.
    public var time: Int64
    public var answerString: String
    public var needsFaceID: Bool

    public init(time: Int64, answerString: String, needsFaceID: Bool) {
        self.time = time
        self.answerString = answerString
        self.needsFaceID = needsFaceID
    }

    enum CodingKeys: String, CodingKey {
        case time
        case answerString = "answer_string"
        case needsFaceID = "needs_face_id"
    }
}

/// The relay took the answer. Only the settle says whether it counted.
public struct SentAnswer: Codable, Sendable, Equatable {
    public var id: UInt64
    public var at: Int64
    public var kind: AnswerKind

    public init(id: UInt64, at: Int64, kind: AnswerKind) {
        self.id = id
        self.at = at
        self.kind = kind
    }
}

public struct AnswerKeyRegistration: Codable, Sendable, Equatable {
    public var deviceUUID: String
    public var teamID: String
    public var relayDeviceID: UInt64

    public init(deviceUUID: String, teamID: String, relayDeviceID: UInt64) {
        self.deviceUUID = deviceUUID
        self.teamID = teamID
        self.relayDeviceID = relayDeviceID
    }

    enum CodingKeys: String, CodingKey {
        case deviceUUID = "device_uuid"
        case teamID = "team_id"
        case relayDeviceID = "relay_device_id"
    }
}

/// A join of a notifications-only team (plan §A7).
public struct AttachInfo: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable { case waiting, attached }

    public var state: State
    public var team: String
    /// The two safety words. The Mac shows the same words for this iPhone.
    public var words: [String]
    public var expiresAt: Int64

    public init(state: State, team: String, words: [String], expiresAt: Int64) {
        self.state = state
        self.team = team
        self.words = words
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case state, team, words
        case expiresAt = "expires_at"
    }
}

/// The APNs environment of this build (`aps-environment`).
public enum PushEnvironment: String, Sendable {
    case development, production
}

/// b64u without padding, as the wire has it.
public enum Base64URL {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ text: String) -> Data? {
        guard !text.contains("="), !text.contains("+"), !text.contains("/") else { return nil }
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        return Data(base64Encoded: base64)
    }
}

/// The calls of section 5.10 that a service without a relay does not have.
public extension VaultService {
    func questionsList() async throws -> QuestionsList { .off }

    func questionsWait(timeout: Int) async throws -> Bool { false }

    func questionOpen(qid: String) async throws -> RemoteQuestion {
        throw VaultError(.noQuestions, "This vault gets no questions through the relay.")
    }

    func questionAnswerString(qid: String, answer: RemoteAnswer) async throws -> PreparedAnswer {
        throw VaultError(.noQuestions, "This vault gets no questions through the relay.")
    }

    func questionAnswer(qid: String, answer: RemoteAnswer, time: Int64, signature: Data?) async throws
        -> SentAnswer
    {
        throw VaultError(.noQuestions, "This vault gets no questions through the relay.")
    }

    /// A service that keeps the questions of one vault answers for it, without `vaultID`.
    func questionAnswerString(qid: String, answer: RemoteAnswer, vaultID: String?) async throws -> PreparedAnswer {
        try await questionAnswerString(qid: qid, answer: answer)
    }

    func questionAnswer(qid: String, answer: RemoteAnswer, time: Int64, signature: Data?, vaultID: String?)
        async throws -> SentAnswer
    {
        try await questionAnswer(qid: qid, answer: answer, time: time, signature: signature)
    }

    func answerKeyRegister(publicKey: Data) async throws -> AnswerKeyRegistration {
        throw VaultError(.noQuestions, "This vault gets no questions through the relay.")
    }

    func pushTokenSet(token: Data, environment: PushEnvironment) async throws {
        throw VaultError(.noQuestions, "This vault gets no questions through the relay.")
    }

    func pushTokenClear() async throws {}

    func joinAttach(link: String, deviceName: String, answerKey: Data) async throws -> AttachInfo {
        throw VaultError(.notAllowed, "This service cannot connect to the relay.")
    }

    func joinAttachPoll() async throws -> AttachInfo {
        throw VaultError(.notAllowed, "This service cannot connect to the relay.")
    }

    func joinAttachCancel() async throws {}
}
