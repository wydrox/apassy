import Foundation

// The agents of the Macs (contract relay-feed-v1; ios-core-v1 section 5.12): the models of the
// core's answers. The core opens and checks each feed; every text here is for display, with
// control and format characters replaced. The feed holds no value: credentials are named by their
// UUID and title only.
//
// The decoding is tolerant: a member that is missing or of another form takes its empty value, and
// an element of a list that cannot be read is left out, so a newer core never empties the tab. The
// members that name a thing (a vault, a Mac, an agent, an exception) are required for their element.

/// The agents of every vault with a questions context (the vaults unlocked in this session).
public struct FeedList: Decodable, Sendable, Equatable {
    public var vaults: [FeedVault]

    public init(vaults: [FeedVault]) { self.vaults = vaults }

    public static let empty = FeedList(vaults: [])

    enum CodingKeys: String, CodingKey { case vaults }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        vaults = container.lossy(FeedVault.self, forKey: .vaults)
    }
}

/// A vault, its questions team, the row of this iPhone in it, and the Macs that publish its agents.
public struct FeedVault: Decodable, Sendable, Equatable, Identifiable {
    public var vaultID: String
    public var vaultName: String
    public var teamID: String
    /// The vault holds the row of this iPhone: it can send actions.
    public var registered: Bool
    /// The row has an answer key: it can send the Face ID kinds (`never`, `always_ask`).
    public var answerKey: Bool
    /// The code of the last relay call of this vault that failed (`feed_unavailable`,
    /// `relay_unreachable`, `removed`, …), until one works.
    public var error: String?
    public var macs: [FeedMac]

    public var id: String { vaultID }

    public init(
        vaultID: String, vaultName: String, teamID: String, registered: Bool = true, answerKey: Bool = true,
        error: String? = nil, macs: [FeedMac]
    ) {
        self.vaultID = vaultID
        self.vaultName = vaultName
        self.teamID = teamID
        self.registered = registered
        self.answerKey = answerKey
        self.error = error
        self.macs = macs
    }

    enum CodingKeys: String, CodingKey {
        case registered, error, macs
        case vaultID = "vault_id"
        case vaultName = "vault_name"
        case teamID = "team_id"
        case answerKey = "answer_key"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        vaultID = try container.decode(String.self, forKey: .vaultID)
        vaultName = container.text(forKey: .vaultName)
        teamID = container.text(forKey: .teamID)
        registered = container.flag(forKey: .registered)
        answerKey = container.flag(forKey: .answerKey)
        error = container.optionalText(forKey: .error)
        macs = container.lossy(FeedMac.self, forKey: .macs)
    }
}

/// A Mac of the vault and its last good feed.
public struct FeedMac: Decodable, Sendable, Equatable, Identifiable {
    /// The `trusted_device` UUID of the Mac: the target of an action.
    public var device: String
    /// Its device number in the team.
    public var relayDeviceID: UInt64?
    /// The name of its `trusted_device` row.
    public var name: String
    /// Null when no feed of this Mac opened in this session (`problem` says why).
    public var seq: UInt64?
    public var generatedAt: Int64?
    /// The feed is more than 24 hours old: the app dims the Mac and offers no action.
    public var stale: Bool
    /// The Mac left something out to fit: "Some older uses are on the Mac only."
    public var truncated: Bool
    /// Why the last feed of this Mac could not be shown ("Sync this vault to see …").
    public var problem: String?
    /// This iPhone can act on this feed. False for a vault that is not selected when the feed
    /// came after its keys were read (the Mac may have been removed from it since): select the
    /// vault first. Missing (an older core): true.
    public var canAct: Bool
    /// The last feed of this Mac says that it checks the names of an action (relay-feed-v1
    /// section 7.1). False: Apassy on that Mac is older (0.5.2) and takes no removal from this
    /// iPhone; the app says to update it. Missing (an older core): true.
    public var checksNames: Bool
    public var week: FeedWeek?
    public var agents: [FeedAgent]

    public var id: String { device }

    public init(
        device: String, relayDeviceID: UInt64? = nil, name: String, seq: UInt64? = nil, generatedAt: Int64? = nil,
        stale: Bool = false, truncated: Bool = false, problem: String? = nil, canAct: Bool = true,
        checksNames: Bool = true, week: FeedWeek? = nil, agents: [FeedAgent] = []
    ) {
        self.device = device
        self.relayDeviceID = relayDeviceID
        self.name = name
        self.seq = seq
        self.generatedAt = generatedAt
        self.stale = stale
        self.truncated = truncated
        self.problem = problem
        self.canAct = canAct
        self.checksNames = checksNames
        self.week = week
        self.agents = agents
    }

    enum CodingKeys: String, CodingKey {
        case device, name, seq, stale, truncated, problem, week, agents
        case relayDeviceID = "relay_device_id"
        case generatedAt = "generated_at"
        case canAct = "can_act"
        case checksNames = "checks_names"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        device = try container.decode(String.self, forKey: .device)
        relayDeviceID = try? container.decodeIfPresent(UInt64.self, forKey: .relayDeviceID)
        name = container.text(forKey: .name)
        seq = try? container.decodeIfPresent(UInt64.self, forKey: .seq)
        generatedAt = try? container.decodeIfPresent(Int64.self, forKey: .generatedAt)
        stale = container.flag(forKey: .stale)
        truncated = container.flag(forKey: .truncated)
        problem = container.optionalText(forKey: .problem)
        canAct = ((try? container.decodeIfPresent(Bool.self, forKey: .canAct)) ?? nil) ?? true
        checksNames = ((try? container.decodeIfPresent(Bool.self, forKey: .checksNames)) ?? nil) ?? true
        week = try? container.decodeIfPresent(FeedWeek.self, forKey: .week)
        agents = container.lossy(FeedAgent.self, forKey: .agents)
    }
}

/// The Decisions of the Mac for this vault in the last 7 days.
public struct FeedWeek: Decodable, Sendable, Equatable {
    public var byYou: UInt64
    public var automatic: UInt64

    public init(byYou: UInt64, automatic: UInt64) {
        self.byYou = byYou
        self.automatic = automatic
    }

    enum CodingKeys: String, CodingKey {
        case byYou = "by_you"
        case automatic
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        byYou = container.count(forKey: .byYou)
        automatic = container.count(forKey: .automatic)
    }
}

/// The host of an agent, for its icon.
public enum FeedHost: String, Sendable, Equatable {
    case claude, codex, t3, other
}

/// An agent of the vault on a Mac.
public struct FeedAgent: Decodable, Sendable, Equatable, Identifiable {
    /// `agent.id` on that Mac (decimal text).
    public var id: String
    public var name: String
    public var host: FeedHost
    /// `mac`: the agent reaches the broker through the socket of the publishing Mac.
    public var place: String
    /// The agent is disconnected.
    public var revoked: Bool
    /// After it, the agent must reconnect on the Mac.
    public var tokenExpiresAt: Int64?
    public var lastUseAt: Int64?
    public var usesThisWeek: UInt64
    /// Project labels, most used first. Never a path.
    public var projects: [String]
    /// The owner's sentence for the bouncer. Read only here.
    public var note: String
    /// "Only these items": the agent sees only the items of its `only` exceptions.
    public var restricted: Bool
    public var actions: [FeedActionUse]
    public var exceptions: [FeedException]
    /// Newest first.
    public var recent: [FeedUse]

    public init(
        id: String, name: String, host: FeedHost = .other, place: String = "mac", revoked: Bool = false,
        tokenExpiresAt: Int64? = nil, lastUseAt: Int64? = nil, usesThisWeek: UInt64 = 0, projects: [String] = [],
        note: String = "", restricted: Bool = false, actions: [FeedActionUse] = [], exceptions: [FeedException] = [],
        recent: [FeedUse] = []
    ) {
        self.id = id
        self.name = name
        self.host = host
        self.place = place
        self.revoked = revoked
        self.tokenExpiresAt = tokenExpiresAt
        self.lastUseAt = lastUseAt
        self.usesThisWeek = usesThisWeek
        self.projects = projects
        self.note = note
        self.restricted = restricted
        self.actions = actions
        self.exceptions = exceptions
        self.recent = recent
    }

    enum CodingKeys: String, CodingKey {
        case id, name, host, revoked, projects, note, restricted, actions, exceptions, recent
        case place = "where"
        case tokenExpiresAt = "token_expires_at"
        case lastUseAt = "last_use_at"
        case usesThisWeek = "uses_this_week"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = container.text(forKey: .name)
        host = FeedHost(rawValue: container.text(forKey: .host)) ?? .other
        place = container.text(forKey: .place)
        revoked = container.flag(forKey: .revoked)
        tokenExpiresAt = try? container.decodeIfPresent(Int64.self, forKey: .tokenExpiresAt)
        lastUseAt = try? container.decodeIfPresent(Int64.self, forKey: .lastUseAt)
        usesThisWeek = container.count(forKey: .usesThisWeek)
        projects = container.lossy(String.self, forKey: .projects)
        note = container.text(forKey: .note)
        restricted = container.flag(forKey: .restricted)
        actions = container.lossy(FeedActionUse.self, forKey: .actions)
        exceptions = container.lossy(FeedException.self, forKey: .exceptions)
        recent = container.lossy(FeedUse.self, forKey: .recent)
    }
}

/// What an agent did with one kind of action in the last 7 days.
public struct FeedActionUse: Decodable, Sendable, Equatable, Identifiable {
    public var action: QuestionAction
    public var allowed: UInt64
    public var notAllowed: UInt64
    public var projects: [String]

    public var id: String { action.rawValue }

    public init(action: QuestionAction, allowed: UInt64, notAllowed: UInt64 = 0, projects: [String] = []) {
        self.action = action
        self.allowed = allowed
        self.notAllowed = notAllowed
        self.projects = projects
    }

    enum CodingKeys: String, CodingKey {
        case action, allowed, projects
        case notAllowed = "not_allowed"
    }

    /// An action of another kind is left out of the list.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        action = try container.decode(QuestionAction.self, forKey: .action)
        allowed = container.count(forKey: .allowed)
        notAllowed = container.count(forKey: .notAllowed)
        projects = container.lossy(String.self, forKey: .projects)
    }
}

/// The kinds of exception of an agent (ADR 0025).
public enum FeedExceptionKind: String, Sendable, Equatable, Hashable {
    /// The agent never gets the item.
    case never
    /// Every use of the item by the agent asks the owner.
    case alwaysAsk = "always_ask"
    /// The item is on the "only these items" list of the agent.
    case only

    /// Whether removing it gives the agent authority, so the answer key signs it after Face ID
    /// (relay-feed-v1 section 9.1). Removing `only` makes the agent see less: the core signs it.
    public var needsFaceID: Bool { self != .only }

    /// "Never", "Always ask", "Only".
    public var label: String {
        switch self {
        case .never: "Never"
        case .alwaysAsk: "Always ask"
        case .only: "Only"
        }
    }
}

/// An exception of an agent for one credential.
public struct FeedException: Decodable, Sendable, Equatable, Hashable {
    /// The item's UUID; nil when the item is gone ("A deleted credential", no action).
    public var item: String?
    /// The title in the Mac's vault.
    public var itemTitle: String
    /// The title of the item with that UUID in the vault on this iPhone, else nil.
    public var title: String?
    /// Whether the vault on this iPhone holds the item; nil when its items were not read.
    public var here: Bool?
    public var kind: FeedExceptionKind
    /// Signed by the action: it names this exception and no later one.
    public var createdAt: Int64

    public init(
        item: String?, itemTitle: String, title: String? = nil, here: Bool? = nil, kind: FeedExceptionKind,
        createdAt: Int64
    ) {
        self.item = item
        self.itemTitle = itemTitle
        self.title = title
        self.here = here
        self.kind = kind
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey {
        case item, title, here, kind
        case itemTitle = "item_title"
        case createdAt = "created_at"
    }

    /// An exception of another kind is left out: the app cannot act on it.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard let kind = FeedExceptionKind(rawValue: try container.decode(String.self, forKey: .kind)) else {
            throw DecodingError.dataCorruptedError(
                forKey: .kind, in: container, debugDescription: "An exception of another kind.")
        }
        self.kind = kind
        createdAt = try container.decode(Int64.self, forKey: .createdAt)
        item = container.optionalText(forKey: .item)
        itemTitle = container.text(forKey: .itemTitle)
        title = container.optionalText(forKey: .title)
        here = try? container.decodeIfPresent(Bool.self, forKey: .here)
    }
}

/// How a use ended.
public enum FeedOutcome: String, Sendable, Equatable {
    case allowed, denied, refused
    case timedOut = "timed_out"
    case other
}

/// Who decided a use.
public enum FeedDecider: String, Sendable, Equatable {
    case bouncer, pattern, answer, owner, rule, other
}

/// A recent use of a credential by the agent. The command is masked twice on the Mac.
public struct FeedUse: Decodable, Sendable, Equatable {
    public var at: Int64
    public var item: String?
    public var itemTitle: String
    public var title: String?
    public var here: Bool?
    public var action: QuestionAction?
    /// A project label, or empty.
    public var project: String
    /// The masked command summary (`[apassy:secret]` in place of a value), or empty.
    public var command: String
    public var outcome: FeedOutcome
    public var decidedBy: FeedDecider
    /// The device that answered, or empty.
    public var answeredOn: String

    public init(
        at: Int64, item: String?, itemTitle: String, title: String? = nil, here: Bool? = nil,
        action: QuestionAction? = .read, project: String = "", command: String = "", outcome: FeedOutcome = .allowed,
        decidedBy: FeedDecider = .bouncer, answeredOn: String = ""
    ) {
        self.at = at
        self.item = item
        self.itemTitle = itemTitle
        self.title = title
        self.here = here
        self.action = action
        self.project = project
        self.command = command
        self.outcome = outcome
        self.decidedBy = decidedBy
        self.answeredOn = answeredOn
    }

    enum CodingKeys: String, CodingKey {
        case at, item, title, here, action, project, command, outcome
        case itemTitle = "item_title"
        case decidedBy = "decided_by"
        case answeredOn = "answered_on"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        at = try container.decode(Int64.self, forKey: .at)
        item = container.optionalText(forKey: .item)
        itemTitle = container.text(forKey: .itemTitle)
        title = container.optionalText(forKey: .title)
        here = try? container.decodeIfPresent(Bool.self, forKey: .here)
        action = QuestionAction(rawValue: container.text(forKey: .action))
        project = container.text(forKey: .project)
        command = container.text(forKey: .command)
        outcome = FeedOutcome(rawValue: container.text(forKey: .outcome)) ?? .other
        decidedBy = FeedDecider(rawValue: container.text(forKey: .decidedBy)) ?? .other
        answeredOn = container.text(forKey: .answeredOn)
    }
}

// MARK: - Actions

/// The removal of one exception of an agent, as the feed of its Mac shows it: the parameters of
/// `feed_action_string` and `feed_action`.
///
/// Two removals are equal when they name the same exception: `feedSeq` (the feed whose list the
/// owner confirmed) does not count, so a removal keeps its state while newer feeds come.
public struct FeedRemoval: Sendable, Equatable, Hashable {
    public var vaultID: String
    /// The `device` of the Mac in `feed_list`.
    public var macDevice: String
    public var agent: String
    public var item: String
    public var kind: FeedExceptionKind
    public var createdAt: Int64
    /// The `seq` of the feed whose list the owner confirmed: the core refuses the action when it
    /// shows another feed of that Mac now (contract section 5.12).
    public var feedSeq: UInt64?

    public init(vaultID: String, macDevice: String, agent: String, item: String, kind: FeedExceptionKind,
                createdAt: Int64, feedSeq: UInt64? = nil) {
        self.vaultID = vaultID
        self.macDevice = macDevice
        self.agent = agent
        self.item = item
        self.kind = kind
        self.createdAt = createdAt
        self.feedSeq = feedSeq
    }

    public static func == (lhs: FeedRemoval, rhs: FeedRemoval) -> Bool {
        lhs.vaultID == rhs.vaultID && lhs.macDevice == rhs.macDevice && lhs.agent == rhs.agent
            && lhs.item == rhs.item && lhs.kind == rhs.kind && lhs.createdAt == rhs.createdAt
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(vaultID)
        hasher.combine(macDevice)
        hasher.combine(agent)
        hasher.combine(item)
        hasher.combine(kind)
        hasher.combine(createdAt)
    }

    /// The parameters of the core call.
    public var parameters: [String: Any] {
        var parameters: [String: Any] = [
            "vault_id": vaultID, "mac_device": macDevice, "agent": agent, "item": item, "kind": kind.rawValue,
            "created_at": createdAt,
        ]
        if let feedSeq { parameters["feed_seq"] = feedSeq }
        return parameters
    }
}

/// The exact action string to sign, from the core (relay-feed-v1 section 9.3).
public struct PreparedFeedAction: Decodable, Sendable, Equatable {
    public var vaultID: String
    /// The team whose answer key signs a Face ID kind. No other team's key may sign it.
    public var teamID: String
    /// Kept for `feed_action`, with `time`.
    public var actionID: String
    public var time: Int64
    public var feedSeq: UInt64?
    public var actionString: String
    public var needsFaceID: Bool
    /// The text of the Face ID prompt.
    public var faceIDReason: String
    /// The names that the action string signs, as the list shows them: the app sends nothing
    /// when one is not the name its confirmation showed (relay-feed-v1 section 9.3).
    public var agentName: String?
    public var credentialName: String?
    public var macName: String?

    public init(
        vaultID: String, teamID: String, actionID: String, time: Int64, feedSeq: UInt64? = nil, actionString: String,
        needsFaceID: Bool, faceIDReason: String, agentName: String? = nil, credentialName: String? = nil,
        macName: String? = nil
    ) {
        self.vaultID = vaultID
        self.teamID = teamID
        self.actionID = actionID
        self.time = time
        self.feedSeq = feedSeq
        self.actionString = actionString
        self.needsFaceID = needsFaceID
        self.faceIDReason = faceIDReason
        self.agentName = agentName
        self.credentialName = credentialName
        self.macName = macName
    }

    enum CodingKeys: String, CodingKey {
        case time
        case vaultID = "vault_id"
        case teamID = "team_id"
        case actionID = "action_id"
        case feedSeq = "feed_seq"
        case actionString = "action_string"
        case needsFaceID = "needs_face_id"
        case faceIDReason = "face_id_reason"
        case agentName = "agent_name"
        case credentialName = "credential_name"
        case macName = "mac_name"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        vaultID = try container.decode(String.self, forKey: .vaultID)
        teamID = try container.decode(String.self, forKey: .teamID)
        actionID = try container.decode(String.self, forKey: .actionID)
        time = try container.decode(Int64.self, forKey: .time)
        feedSeq = try? container.decodeIfPresent(UInt64.self, forKey: .feedSeq)
        actionString = try container.decode(String.self, forKey: .actionString)
        // Missing: ask for Face ID. A wrong guess fails at the core, never silently.
        needsFaceID = (try? container.decodeIfPresent(Bool.self, forKey: .needsFaceID)) ?? true
        faceIDReason = container.text(forKey: .faceIDReason)
        agentName = container.optionalText(forKey: .agentName)
        credentialName = container.optionalText(forKey: .credentialName)
        macName = container.optionalText(forKey: .macName)
    }
}

/// The relay took the action. Only its outcome says whether the Mac applied it.
public struct SentFeedAction: Decodable, Sendable, Equatable {
    public var actionID: String
    /// Null when the relay had the action already (a retry).
    public var seq: UInt64?
    public var createdAt: Int64?
    public var expiresAt: Int64?

    public init(actionID: String, seq: UInt64? = nil, createdAt: Int64? = nil, expiresAt: Int64? = nil) {
        self.actionID = actionID
        self.seq = seq
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case seq
        case actionID = "action_id"
        case createdAt = "created_at"
        case expiresAt = "expires_at"
    }
}

/// The state of an action that this process posted.
public struct FeedActionOutcome: Decodable, Sendable, Equatable {
    public enum Outcome: String, Sendable, Equatable {
        /// Still open on the relay.
        case pending
        case applied, refused, stale, expired
    }

    public var actionID: String
    public var outcome: Outcome
    /// The settle opened with the question key and names this action and this outcome. Without it
    /// the outcome is the relay's word only: the core says `refused`, and the app shows "Not
    /// applied, or unknown", never a removal.
    public var verified: Bool
    /// The Mac's text, for `refused` and `stale`.
    public var reason: String?
    public var feedSeq: UInt64?
    public var at: Int64?

    public init(
        actionID: String, outcome: Outcome, verified: Bool = true, reason: String? = nil, feedSeq: UInt64? = nil,
        at: Int64? = nil
    ) {
        self.actionID = actionID
        self.outcome = outcome
        self.verified = verified
        self.reason = reason
        self.feedSeq = feedSeq
        self.at = at
    }

    enum CodingKeys: String, CodingKey {
        case outcome, verified, reason, at
        case actionID = "action_id"
        case feedSeq = "feed_seq"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        actionID = try container.decode(String.self, forKey: .actionID)
        // An outcome of a later version: still open, as far as this app knows.
        outcome = Outcome(rawValue: container.text(forKey: .outcome)) ?? .pending
        verified = container.flag(forKey: .verified)
        reason = container.optionalText(forKey: .reason)
        feedSeq = try? container.decodeIfPresent(UInt64.self, forKey: .feedSeq)
        at = try? container.decodeIfPresent(Int64.self, forKey: .at)
    }
}

/// The calls of section 5.12 that a service without the feed does not have: an older core.
public extension VaultService {
    func feedList() async throws -> FeedList { throw VaultError.feedUnsupported }

    func feedWait(timeout: Int) async throws -> Bool { throw VaultError.feedUnsupported }

    func feedActionString(_ removal: FeedRemoval, actionID: String?, time: Int64?) async throws -> PreparedFeedAction {
        throw VaultError.feedUnsupported
    }

    func feedAction(_ removal: FeedRemoval, actionID: String, time: Int64, signature: Data?) async throws
        -> SentFeedAction
    {
        throw VaultError.feedUnsupported
    }

    func feedActionWait(actionID: String, vaultID: String?, timeout: Int) async throws -> FeedActionOutcome {
        throw VaultError.feedUnsupported
    }
}

public extension VaultError {
    /// A service that does not read the agents of the Macs.
    static let feedUnsupported = VaultError(
        .unsupported, "This version of Apassy does not show the agents of your Macs. Update Apassy.")
}

// MARK: - Tolerant decoding

/// An element of a list that may not decode: it is left out.
private struct Lossy<Value: Decodable>: Decodable {
    let value: Value?

    init(from decoder: any Decoder) throws { value = try? Value(from: decoder) }
}

extension KeyedDecodingContainer {
    fileprivate func lossy<Value: Decodable>(_ type: Value.Type, forKey key: Key) -> [Value] {
        ((try? decodeIfPresent([Lossy<Value>].self, forKey: key)) ?? nil)?.compactMap(\.value) ?? []
    }

    fileprivate func text(forKey key: Key) -> String {
        ((try? decodeIfPresent(String.self, forKey: key)) ?? nil) ?? ""
    }

    fileprivate func optionalText(forKey key: Key) -> String? {
        (try? decodeIfPresent(String.self, forKey: key)) ?? nil
    }

    fileprivate func flag(forKey key: Key) -> Bool {
        ((try? decodeIfPresent(Bool.self, forKey: key)) ?? nil) ?? false
    }

    fileprivate func count(forKey key: Key) -> UInt64 {
        ((try? decodeIfPresent(UInt64.self, forKey: key)) ?? nil) ?? 0
    }
}
