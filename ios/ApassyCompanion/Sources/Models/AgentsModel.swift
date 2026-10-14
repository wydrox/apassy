import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Observation

/// One agent as a feed shows it: the agent, its Mac, and the vault of that Mac.
struct AgentEntry: Equatable, Identifiable {
    let vaultID: String
    let vaultName: String
    let teamID: String
    /// The vault holds the row of this iPhone: it can send actions.
    let registered: Bool
    /// The row has an answer key: it can send the removals that need Face ID.
    let answerKey: Bool
    let mac: FeedMac
    let agent: FeedAgent

    var id: String { Self.id(vaultID: vaultID, mac: mac.device, agent: agent.id) }

    static func id(vaultID: String, mac: String, agent: String) -> String { "\(vaultID)/\(mac)/\(agent)" }
}

/// The agents of one Mac in one vault: a section of the list.
struct AgentSection: Equatable, Identifiable {
    let vaultID: String
    let vaultName: String
    let mac: FeedMac
    /// "Mac mini", or "Work · Mac mini" when the list has the Macs of two vaults or more.
    let title: String
    let agents: [AgentEntry]

    var id: String { "\(vaultID)/\(mac.device)" }
}

/// The Agents tab on the relay feed (contract relay-feed-v1; ios-core-v1 section 5.12): the agents
/// that each Mac publishes for each unlocked vault, read with `feed_list` and followed with the
/// long poll `feed_wait` while the tab shows, and the removal of an exception of an agent.
///
/// The feed holds no secret: credentials are named by their title only. A removal that gives the
/// agent authority back (`never`, `always_ask`) is signed by the answer key of the vault's own
/// questions team after Face ID; the core signs the removal of an `only` item. No key of another
/// team ever signs.
@MainActor
@Observable
final class AgentsModel {
    enum Phase: Equatable {
        case loading
        /// No Mac publishes its agents to this iPhone yet (or the core or the relay cannot carry
        /// them): the tab says where the agents are (`AgentsReach`).
        case noFeed
        /// At least one Mac of an unlocked vault: its agents, or why they do not show.
        case ready
        /// The vault is locked: nothing shows until it opens.
        case locked
        case failed(String)
    }

    /// A removal of an exception while it runs and after it ended.
    enum Removal: Equatable {
        /// Face ID, the relay, or the Mac: what it waits for now.
        case working(String)
        /// The Mac applied it: "Removed on Mac mini."
        case removed(String)
        /// Nothing was removed; the text says why and what to do.
        case failed(String)
    }

    private(set) var phase = Phase.loading
    private(set) var vaults: [FeedVault] = []
    /// A problem while the list shows (a failed refresh), for a line under it.
    private(set) var notice: String?
    private(set) var removals: [FeedRemoval: Removal] = [:]

    @ObservationIgnored private let service: any VaultService
    @ObservationIgnored private let signers: any AnswerSigners
    /// The answer key that the row of this iPhone holds in `team` for the vault (from the
    /// questions), so that the signer of that row signs; nil when it is not known.
    @ObservationIgnored private let registeredKey: @MainActor (_ vaultID: String, _ team: String) -> Data?
    @ObservationIgnored private let now: @MainActor () -> Date
    @ObservationIgnored private let retryInterval: Duration
    /// The long poll of `feed_action_wait` (0 to 25 s).
    @ObservationIgnored private let actionWait: Int
    /// Counts the locks and the leaves of the app: work of an earlier one stops.
    @ObservationIgnored private var generation = 0
    /// The service has no feed calls (an older core): the tab stays on `AgentsReach`.
    @ObservationIgnored private var unsupported = false
    /// The exceptions that a Mac applied a removal of, with the `seq` of the feed that showed them:
    /// hidden until that Mac sends another feed.
    @ObservationIgnored private var hidden: [FeedRemoval: UInt64?] = [:]

    init(
        service: any VaultService, signers: any AnswerSigners,
        registeredKey: @escaping @MainActor (_ vaultID: String, _ team: String) -> Data? = { _, _ in nil },
        now: @escaping @MainActor () -> Date = { Date() }, retryInterval: Duration = .seconds(2),
        actionWait: Int = 25
    ) {
        self.service = service
        self.signers = signers
        self.registeredKey = registeredKey
        self.now = now
        self.retryInterval = retryInterval
        self.actionWait = actionWait
    }

    /// What the tab shows.
    enum Screen: Equatable {
        case loading
        /// The honest screen of `AgentsReach`: where the agents are, and the one action that helps.
        case reach
        case list
        case failed(String)
    }

    var screen: Screen {
        switch phase {
        case .loading: .loading
        // Locked: the tabs show only once the vault is open, so this is the moment of a resume.
        case .noFeed, .locked: .reach
        case .ready: .list
        case .failed(let message): .failed(message)
        }
    }

    // MARK: The list

    /// Whether the sections name their vault: the Macs of two vaults or more show.
    var namesVaults: Bool { vaults.filter { !$0.macs.isEmpty }.count >= 2 }

    /// The agents by Mac, and by vault when there are two or more, in the order of the core.
    var sections: [AgentSection] {
        let names = namesVaults
        return vaults.flatMap { vault in
            vault.macs.map { mac in
                AgentSection(
                    vaultID: vault.vaultID, vaultName: vault.vaultName, mac: mac,
                    title: names ? "\(vault.vaultName) · \(mac.name)" : mac.name,
                    agents: mac.agents.map { agent in
                        AgentEntry(
                            vaultID: vault.vaultID, vaultName: vault.vaultName, teamID: vault.teamID,
                            registered: vault.registered, answerKey: vault.answerKey, mac: mac,
                            agent: visible(agent, vaultID: vault.vaultID, mac: mac))
                    })
            }
        }
    }

    /// The agent with this ID (`AgentEntry.id`), as the list shows it now.
    func entry(_ id: String) -> AgentEntry? {
        for section in sections {
            if let entry = section.agents.first(where: { $0.id == id }) { return entry }
        }
        return nil
    }

    /// The agents that are connected (not disconnected), for "4 connected".
    var connectedCount: Int { sections.flatMap(\.agents).filter { !$0.agent.revoked }.count }

    /// The agent without the exceptions whose removal its Mac applied, until that Mac reports again.
    private func visible(_ agent: FeedAgent, vaultID: String, mac: FeedMac) -> FeedAgent {
        guard !hidden.isEmpty else { return agent }
        var agent = agent
        agent.exceptions.removeAll { exception in
            guard let removal = Self.removal(exception, vaultID: vaultID, mac: mac.device, agent: agent.id),
                let seq = hidden[removal]
            else { return false }
            return seq == mac.seq
        }
        return agent
    }

    /// Read the feeds of every unlocked vault.
    func refresh() async {
        guard !unsupported else {
            phase = .noFeed
            return
        }
        let started = generation
        do {
            let list = try await service.feedList()
            // A lock while the list was read: its agents must not show again.
            guard started == generation else { return }
            vaults = list.vaults
            notice = nil
            phase = vaults.contains { !$0.macs.isEmpty } ? .ready : .noFeed
            forgetHidden()
        } catch let error as VaultError where error.code == .locked {
            guard started == generation else { return }
            showLocked()
        } catch let error as VaultError where error.code == .unsupported || error.code == .feedUnavailable {
            guard started == generation else { return }
            if error.code == .unsupported { unsupported = true }
            vaults = []
            phase = .noFeed
        } catch {
            guard started == generation else { return }
            if case .ready = phase {
                notice = error.localizedDescription
            } else {
                phase = .failed(error.localizedDescription)
            }
        }
    }

    /// A hidden exception shows again once its Mac sent another feed, or left the list.
    private func forgetHidden() {
        hidden = hidden.filter { removal, seq in
            vaults.first { $0.vaultID == removal.vaultID }?.macs.first { $0.device == removal.macDevice }?.seq == seq
        }
    }

    /// Read the list, then follow it with the long poll while the task runs: the Agents tab or an
    /// agent page is on the screen (contract section 5.12).
    func watch() async {
        await refresh()
        while !Task.isCancelled {
            let waits = phase == .ready || (phase == .noFeed && !vaults.isEmpty)
            guard waits, !unsupported else {
                // Locked: the vault opens soon after the owner returns. No Mac: look again now
                // and then, without a poll that would answer at once.
                let pause: Duration =
                    switch phase {
                    case .locked, .loading: retryInterval
                    default: unsupported ? .seconds(3600) : .seconds(30)
                    }
                try? await Task.sleep(for: pause)
                if Task.isCancelled { return }
                await refresh()
                continue
            }
            let started = ContinuousClock.now
            do {
                if try await service.feedWait(timeout: 25) {
                    await refresh()
                } else if ContinuousClock.now - started < .seconds(1) {
                    // A poll that answers at once (a vault without a team): no busy loop.
                    try? await Task.sleep(for: retryInterval)
                }
            } catch {
                if Task.isCancelled { return }
                try? await Task.sleep(for: retryInterval)
                await refresh()
            }
        }
    }

    // MARK: The lock

    /// The vault locks: the core drops the feeds of every vault, and so does the tab.
    func vaultDidLock() {
        generation += 1
        removals = [:]
        hidden = [:]
        showLocked()
    }

    /// The app leaves the screen: the core suspends and drops the actions it posted, so a removal
    /// that waits for its Mac ends here, honestly.
    func vaultWillLeave() {
        generation += 1
        for (removal, state) in removals {
            guard case .working = state else { continue }
            removals[removal] = .failed(
                "Apassy closed before the Mac answered. Pull to refresh to see whether the exception is still there.")
        }
    }

    /// The vault opened again (an unlock or a resume).
    func vaultDidOpen() {
        Task { await refresh() }
    }

    private func showLocked() {
        vaults = []
        notice = nil
        phase = .locked
    }

    // MARK: Removing an exception

    /// The removal of `exception` as the feed of `entry` shows it; nil for a deleted credential.
    func removal(of exception: FeedException, in entry: AgentEntry) -> FeedRemoval? {
        Self.removal(exception, vaultID: entry.vaultID, mac: entry.mac.device, agent: entry.agent.id)
    }

    private static func removal(_ exception: FeedException, vaultID: String, mac: String, agent: String)
        -> FeedRemoval?
    {
        guard let item = exception.item else { return nil }
        return FeedRemoval(
            vaultID: vaultID, macDevice: mac, agent: agent, item: item, kind: exception.kind,
            createdAt: exception.createdAt)
    }

    /// Why `exception` offers no "Remove" now, or nil when it does.
    func removalBlock(of exception: FeedException, in entry: AgentEntry) -> String? {
        if exception.item == nil { return "The credential was deleted on the Mac." }
        if entry.mac.stale { return "Remove it when \(entry.mac.name) reports again." }
        if entry.agent.revoked { return "This agent is disconnected." }
        if !entry.registered {
            return "This iPhone can remove exceptions once the vault has synced from the Mac that confirmed it."
        }
        if exception.kind.needsFaceID, !entry.answerKey {
            return "Connect this iPhone again on a Mac to use Face ID here."
        }
        return nil
    }

    /// Whether a removal of `exception` runs now.
    func isRemoving(_ exception: FeedException, in entry: AgentEntry) -> Bool {
        guard let removal = removal(of: exception, in: entry), case .working = removals[removal] else { return false }
        return true
    }

    /// The results of the removals of `entry` that ended, for the lines under its exceptions.
    func results(of entry: AgentEntry) -> [(removal: FeedRemoval, state: Removal)] {
        removals
            .filter { $0.key.vaultID == entry.vaultID && $0.key.macDevice == entry.mac.device && $0.key.agent == entry.agent.id }
            .map { (removal: $0.key, state: $0.value) }
            .sorted { $0.removal.item < $1.removal.item }
    }

    /// Remove `exception` of `entry` on its Mac: the action string of the core; for a kind that
    /// gives authority back, Face ID and the answer key of the vault's team; the post; then the
    /// outcome that the Mac settles. The owner confirmed it before.
    func remove(_ exception: FeedException, in entry: AgentEntry) async {
        guard let removal = removal(of: exception, in: entry), removalBlock(of: exception, in: entry) == nil else {
            return
        }
        if case .working = removals[removal] { return }
        let mac = entry.mac.name
        let started = generation
        removals[removal] = .working("Removing…")
        do {
            let prepared = try await service.feedActionString(removal, actionID: nil, time: nil)
            guard started == generation else { return }
            // The string must be of this vault and its team: no other team's key signs it.
            guard prepared.vaultID == removal.vaultID, !entry.teamID.isEmpty, prepared.teamID == entry.teamID else {
                throw VaultError(.invalidInput, "This action is not for the team of this vault, so nothing was sent.")
            }
            var signature: Data?
            if prepared.needsFaceID || removal.kind.needsFaceID {
                signature = try await sign(prepared, vaultID: removal.vaultID, agent: entry.agent.name)
                guard started == generation else { return }
            }
            let sent = try await post(removal, prepared, signature, started: started)
            guard started == generation else { return }
            removals[removal] = .working("Waiting for \(mac)…")
            let outcome = try await settle(sent, vaultID: removal.vaultID, started: started)
            guard started == generation else { return }
            removals[removal] = Self.result(of: outcome, mac: mac)
            if outcome.outcome == .applied, outcome.verified { hidden[removal] = entry.mac.seq }
        } catch is CancellationError {
            if started == generation { removals[removal] = nil }
            return
        } catch CompanionKeyError.cancelled {
            if started == generation { removals[removal] = nil }
            return
        } catch CompanionKeyError.biometryChanged {
            guard started == generation else { return }
            removals[removal] = .failed(
                "Face ID changed on this iPhone, so Apassy made a new answer key. On a Mac, remove this iPhone in Settings › Devices, then connect it again. Remove the exception on the Mac for now.")
            // A new key for this team only: the rows of the other vaults keep theirs.
            _ = try? signers.renew(team: entry.teamID)
            return
        } catch let error as VaultError {
            guard started == generation else { return }
            removals[removal] = .failed(Self.message(for: error, mac: mac))
        } catch {
            guard started == generation else { return }
            removals[removal] = .failed(error.localizedDescription)
        }
        await refresh()
    }

    /// Clear the line of an ended removal.
    func dismissResult(_ removal: FeedRemoval) {
        if case .working = removals[removal] { return }
        removals[removal] = nil
    }

    /// Sign the action string with the answer key of the team of `prepared` after Face ID, with the
    /// core's reason. The row's registered key, when known, must be that key.
    private func sign(_ prepared: PreparedFeedAction, vaultID: String, agent: String) async throws -> Data {
        let registered = registeredKey(vaultID, prepared.teamID)
        guard let signer = signers.signer(team: prepared.teamID, registered: registered) else {
            throw VaultError(.notRegistered, QuestionsModel.noKeyText)
        }
        if let registered, try signer.publicKey() != registered {
            throw VaultError(.notRegistered, QuestionsModel.keyChangedText)
        }
        let reason = prepared.faceIDReason.isEmpty ? Self.faceIDReason(agent: agent) : prepared.faceIDReason
        return try await signer.sign(Data(prepared.actionString.utf8), reason: reason)
    }

    /// The reason of the Face ID prompt when the core gives none (contract section 5.12).
    static func faceIDReason(agent: String) -> String {
        let cleaned = String(
            String.UnicodeScalarView(
                agent.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) && $0 != "\"" }))
        return "remove an exception of agent \"\(cleaned.prefix(40))\""
    }

    /// Post, and post again after a network failure while the time of the action is younger than
    /// 55 s; the same `action_id`, `time`, and signature, so the relay takes it once.
    private func post(_ removal: FeedRemoval, _ prepared: PreparedFeedAction, _ signature: Data?, started: Int)
        async throws -> SentFeedAction
    {
        while true {
            do {
                return try await service.feedAction(
                    removal, actionID: prepared.actionID, time: prepared.time, signature: signature)
            } catch let error as VaultError
                where error.code == .relayUnreachable
                && Int64(now().timeIntervalSince1970) - prepared.time < 55 && started == generation
            {
                try await Task.sleep(for: retryInterval)
            }
        }
    }

    /// Wait for the Mac to settle the action. The core says `expired` once it is open past its end.
    private func settle(_ sent: SentFeedAction, vaultID: String, started: Int) async throws -> FeedActionOutcome {
        while true {
            guard started == generation, !Task.isCancelled else { throw CancellationError() }
            let asked = ContinuousClock.now
            do {
                let outcome = try await service.feedActionWait(
                    actionID: sent.actionID, vaultID: vaultID, timeout: actionWait)
                if outcome.outcome != .pending { return outcome }
                if let end = sent.expiresAt, Int64(now().timeIntervalSince1970) > end + 60 {
                    return FeedActionOutcome(actionID: sent.actionID, outcome: .expired, verified: false)
                }
                if ContinuousClock.now - asked < .seconds(1) { try await Task.sleep(for: retryInterval) }
            } catch let error as VaultError where error.code == .relayUnreachable || error.code == .rateLimited {
                try await Task.sleep(for: retryInterval)
            }
        }
    }

    /// What the owner reads after the Mac settled.
    static func result(of outcome: FeedActionOutcome, mac: String) -> Removal {
        switch outcome.outcome {
        case .applied:
            return outcome.verified
                ? .removed("Removed on \(mac).")
                : .failed(
                    "\(mac) reports it removed, but this iPhone could not check that answer. Sync this vault, then pull to refresh.")
        case .refused:
            let reason = outcome.reason?.trimmingCharacters(in: .whitespacesAndNewlines.union(.init(charactersIn: ".")))
            if let reason, !reason.isEmpty { return .failed("\(mac) refused it: \(reason).") }
            return .failed("\(mac) refused it.")
        case .stale:
            return .failed("\(mac) did not accept it: the exception changed. Pull to refresh.")
        case .expired, .pending:
            return .failed("\(mac) did not answer. It may be asleep or locked.")
        }
    }

    static func message(for error: VaultError, mac: String) -> String {
        switch error.code {
        case .notFound: "The list on \(mac) changed. Pull to refresh."
        case .staleAction: "This took too long, so nothing was sent. Remove it again."
        case .staleFeed: "\(mac) has not reported for a day. Remove it when it reports again."
        case .notRouted: "\(mac) does not take actions from this iPhone."
        case .removed: "This iPhone was removed from this vault on a Mac."
        case .locked: "Apassy locked before \(mac) answered. Unlock, then pull to refresh."
        default: error.message
        }
    }
}

// MARK: - Text

/// The words of the Agents tab, kept here so the tests read them.
enum AgentsText {
    /// "No uses this week", "1 use this week", "54 uses this week".
    static func uses(_ count: UInt64) -> String {
        switch count {
        case 0: "No uses this week"
        case 1: "1 use this week"
        default: "\(count) uses this week"
        }
    }

    /// The second line of a row: "Mac mini · 54 uses this week".
    static func subtitle(_ entry: AgentEntry) -> String {
        if entry.agent.revoked { return "\(entry.mac.name) · Disconnected" }
        return "\(entry.mac.name) · \(uses(entry.agent.usesThisWeek))"
    }

    /// A short age: "now", "5m", "2h", "3d". A time ahead of this iPhone's clock is "now".
    static func ago(_ at: Int64, now: Date) -> String {
        let seconds = Int64(now.timeIntervalSince1970) - at
        if seconds < 60 { return "now" }
        if seconds < 3600 { return "\(seconds / 60)m" }
        if seconds < 86400 { return "\(seconds / 3600)h" }
        return "\(seconds / 86400)d"
    }

    /// "From Mac mini, 2 min ago": where and when the list was made.
    static func from(_ mac: FeedMac, now: Date) -> String {
        guard let at = mac.generatedAt else { return "From \(mac.name)" }
        let seconds = Int64(now.timeIntervalSince1970) - at
        let when: String =
            if seconds < 60 { "just now" }
            else if seconds < 3600 { "\(seconds / 60) min ago" }
            else if seconds < 86400 { seconds / 3600 == 1 ? "1 hour ago" : "\(seconds / 3600) hours ago" }
            else { seconds / 86400 == 1 ? "1 day ago" : "\(seconds / 86400) days ago" }
        return "From \(mac.name), \(when)"
    }

    /// The line of a Mac whose feed is more than a day old (contract section 5.12).
    static func staleNote(_ mac: FeedMac) -> String {
        guard let at = mac.generatedAt else { return "\(mac.name) has not reported yet." }
        let date = Date(timeIntervalSince1970: TimeInterval(at))
        return "\(mac.name) has not reported since \(date.formatted(.dateTime.month(.wide).day())). Open Apassy on it to update this list."
    }

    /// The name of a credential of the feed: the title on this iPhone, else the Mac's title "not on
    /// this iPhone", or "A deleted credential".
    static func credential(item: String?, itemTitle: String, title: String?, here: Bool?) -> String {
        guard item != nil else { return "A deleted credential" }
        if let title, !title.isEmpty { return title }
        let name = itemTitle.isEmpty ? "A credential" : itemTitle
        return here == false ? "\(name) (not on this iPhone)" : name
    }

    static func credential(_ exception: FeedException) -> String {
        credential(item: exception.item, itemTitle: exception.itemTitle, title: exception.title, here: exception.here)
    }

    static func credential(_ use: FeedUse) -> String {
        credential(item: use.item, itemTitle: use.itemTitle, title: use.title, here: use.here)
    }

    /// "Never: Stripe live key".
    static func exception(_ exception: FeedException) -> String {
        "\(exception.kind.label): \(credential(exception))"
    }

    /// The question of the confirmation, which names the agent, the credential, and the Mac.
    static func confirmTitle(_ exception: FeedException, agent: String, mac: String) -> String {
        "Remove “\(exception.kind.label)” for \(credential(exception)) from \(agent) on \(mac)?"
    }

    static func confirmMessage(_ exception: FeedException, agent: String, mac: String) -> String {
        let name = credential(exception)
        let what: String =
            switch exception.kind {
            case .never: "\(agent) can ask for \(name) again, and the bouncer decides each use."
            case .alwaysAsk: "The bouncer decides the uses of \(name) by \(agent) again, without asking you each time."
            case .only: "\(agent) no longer sees \(name)."
            }
        let how = exception.kind.needsFaceID ? " Face ID confirms it, and \(mac) applies it." : " \(mac) applies it."
        return what + how
    }

    /// The mark of a recent use.
    enum Mark: Equatable {
        /// Allowed without the owner (the bouncer, a rule, a pattern).
        case allowed
        /// Allowed by the owner's answer.
        case allowedByYou
        case denied
        case timedOut
    }

    static func mark(_ use: FeedUse) -> Mark {
        switch use.outcome {
        case .allowed, .other: use.decidedBy == .owner || use.decidedBy == .answer ? .allowedByYou : .allowed
        case .denied, .refused: .denied
        case .timedOut: .timedOut
        }
    }

    /// "Allowed by a rule", "You allowed it on iPhone", "Denied by the bouncer"…
    static func outcome(_ use: FeedUse) -> String {
        let device = use.answeredOn.isEmpty ? "" : " on \(use.answeredOn)"
        switch use.outcome {
        case .timedOut: return "No answer in time"
        case .refused: return "Refused"
        case .allowed, .denied, .other:
            let verb = use.outcome == .denied ? "denied" : "allowed"
            switch use.decidedBy {
            case .owner, .answer: return "You \(verb) it\(device)"
            case .rule: return "\(verb.capitalized) by a rule"
            case .pattern: return "\(verb.capitalized) by a remembered command"
            case .bouncer, .other: return "\(verb.capitalized) by the bouncer"
            }
        }
    }
}
