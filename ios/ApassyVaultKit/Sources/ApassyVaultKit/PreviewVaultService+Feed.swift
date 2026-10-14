import Foundation

/// The agents of the Macs in the preview vault (contract ios-core-v1 section 5.12): synthetic feeds
/// of two Macs and two vaults, actions kept in memory, and outcomes as the tests script them. No
/// value is real, no feed holds a value, and nothing leaves the process.
///
/// Without `setFeed`, the service answers as a core whose vaults have no Mac that publishes yet:
/// an empty list.
public struct PreviewFeed: Sendable {
    /// A removal that `feedAction` took.
    public struct Sent: Sendable, Equatable {
        public var removal: FeedRemoval
        public var actionID: String
        public var time: Int64
        public var signature: Data?
        /// The `feed_seq` and the string of the prepared action that was sent: the core keeps
        /// them by action ID.
        public var feedSeq: UInt64?
        public var actionString: String
    }

    /// The answer of one `feedActionWait`.
    public struct Scripted: Sendable, Equatable {
        public var outcome: FeedActionOutcome.Outcome
        public var verified: Bool
        public var reason: String?

        public init(_ outcome: FeedActionOutcome.Outcome, verified: Bool = true, reason: String? = nil) {
            self.outcome = outcome
            self.verified = verified
            self.reason = reason
        }
    }

    var vaults: [FeedVault] = []
    var waits: [Bool] = []
    var outcomes: [Scripted] = []
    var prepared: [PreparedFeedAction] = []
    /// The strings that `feedActionString` made, by action ID: `feedAction` sends these.
    var preparedByID: [String: PreparedFeedAction] = [:]
    var sent: [Sent] = []
    /// The removal of each action that `feedAction` took, by action ID.
    var posted: [String: FeedRemoval] = [:]
    var nextListError: VaultError?
    var nextStringError: VaultError?
    var nextActionError: VaultError?
    var listCalls = 0
    var waitCalls = 0

    public init() {}
}

extension PreviewVaultService {
    /// The device UUIDs of the synthetic Macs.
    public enum PreviewMacs {
        public static let macMini = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d"
        public static let macBookPro = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
        public static let workMacBookPro = "2b3c4d5e-6f70-4a8b-9cad-1e2f3a4b5c6d"
    }

    /// The feeds of two Macs and two vaults, as `feed_list` answers them: "Personal" (the preview
    /// vault) with a Mac mini that reported two minutes ago and a MacBook Pro that has not reported
    /// for three days (stale), and "Work" with another MacBook Pro. Synthetic names only.
    public static func sampleFeed(now: Date = Date()) -> [FeedVault] {
        let at = Int64(now.timeIntervalSince1970)
        let hour: Int64 = 3600
        let day: Int64 = 86400
        func item(_ n: Int) -> String { "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a\(String(format: "%02d", n))" }

        let claude = FeedAgent(
            id: "4", name: "Claude Code", host: .claude, tokenExpiresAt: at + 90 * day, lastUseAt: at - 2 * hour,
            usesThisWeek: 54, projects: ["acme-billing", "apassy"], note: "Deploys only from the main branch.",
            actions: [
                FeedActionUse(action: .read, allowed: 41, projects: ["acme-billing", "apassy"]),
                FeedActionUse(action: .deploy, allowed: 9, notAllowed: 2, projects: ["acme-billing"]),
                FeedActionUse(action: .change, allowed: 2, projects: ["apassy"]),
            ],
            exceptions: [
                FeedException(
                    item: item(4), itemTitle: "Production Postgres", title: "Production Postgres", here: true,
                    kind: .alwaysAsk, createdAt: at - 9 * day)
            ],
            recent: [
                FeedUse(
                    at: at - 2 * hour, item: item(2), itemTitle: "Stripe live key", title: "Stripe live key", here: true,
                    action: .read, project: "acme-billing", command: "stripe payouts list --limit 10",
                    outcome: .allowed, decidedBy: .rule),
                FeedUse(
                    at: at - 5 * hour, item: item(4), itemTitle: "Production Postgres", title: "Production Postgres",
                    here: true, action: .deploy, project: "acme-billing",
                    command: "npm run migrate -- --url [apassy:secret]", outcome: .allowed, decidedBy: .owner,
                    answeredOn: "iPhone"),
                FeedUse(
                    at: at - 26 * hour, item: item(4), itemTitle: "Production Postgres", title: "Production Postgres",
                    here: true, action: .deploy, project: "acme-billing", command: "npm run migrate",
                    outcome: .denied, decidedBy: .owner, answeredOn: "Mac mini"),
                FeedUse(
                    at: at - 2 * day, item: item(3), itemTitle: "OpenAI", title: "OpenAI", here: true, action: .read,
                    project: "apassy", command: "node scripts/summarize.js", outcome: .allowed, decidedBy: .bouncer),
            ])
        let codex = FeedAgent(
            id: "7", name: "Codex", host: .codex, tokenExpiresAt: at + 60 * day, lastUseAt: at - day,
            usesThisWeek: 21, projects: ["newsletter"],
            actions: [FeedActionUse(action: .read, allowed: 20, notAllowed: 1, projects: ["newsletter"])],
            exceptions: [
                FeedException(
                    item: item(2), itemTitle: "Stripe live key", title: "Stripe live key", here: true, kind: .never,
                    createdAt: at - 4 * day)
            ],
            recent: [
                FeedUse(
                    at: at - day, item: item(3), itemTitle: "OpenAI", title: "OpenAI", here: true, action: .read,
                    project: "newsletter", command: "node scripts/summarize.js", outcome: .allowed,
                    decidedBy: .pattern),
                FeedUse(
                    at: at - 2 * day, item: nil, itemTitle: "", action: .read, project: "newsletter",
                    command: "node scripts/send.js", outcome: .refused, decidedBy: .bouncer),
            ])
        let t3 = FeedAgent(
            id: "9", name: "T3 Code", host: .t3, tokenExpiresAt: at + 30 * day, lastUseAt: at - 3 * day,
            usesThisWeek: 12, projects: ["apassy"],
            actions: [FeedActionUse(action: .read, allowed: 12, projects: ["apassy"])],
            recent: [
                FeedUse(
                    at: at - 3 * day, item: item(1), itemTitle: "GitHub", title: "GitHub", here: true, action: .read,
                    project: "apassy", command: "gh pr list", outcome: .allowed, decidedBy: .bouncer)
            ])
        let ci = FeedAgent(
            id: "2", name: "CI on GitHub", host: .other, tokenExpiresAt: at + 20 * day, lastUseAt: at - 4 * day,
            usesThisWeek: 6, projects: ["acme-billing"], note: "CI agent for Acme, only the Stripe test key.",
            actions: [FeedActionUse(action: .deploy, allowed: 5, notAllowed: 1, projects: ["acme-billing"])],
            exceptions: [
                FeedException(
                    item: item(2), itemTitle: "Stripe live key", title: "Stripe live key", here: true, kind: .never,
                    createdAt: at - 20 * day),
                FeedException(
                    item: item(4), itemTitle: "Production Postgres", title: "Production Postgres", here: true,
                    kind: .never, createdAt: at - 20 * day),
            ],
            recent: [
                FeedUse(
                    at: at - 4 * day, item: item(5), itemTitle: "Deploy key", title: "Deploy key", here: true,
                    action: .deploy, project: "acme-billing", command: "ssh deploy@[apassy:secret]",
                    outcome: .allowed, decidedBy: .rule)
            ])
        let workClaude = FeedAgent(
            id: "3", name: "Claude Code", host: .claude, tokenExpiresAt: at + 90 * day, lastUseAt: at - 40 * 60,
            usesThisWeek: 8, projects: ["edge-worker"], restricted: true,
            actions: [FeedActionUse(action: .deploy, allowed: 8, projects: ["edge-worker"])],
            exceptions: [
                FeedException(
                    item: item(11), itemTitle: "Cloudflare API", title: nil, here: false, kind: .only,
                    createdAt: at - 12 * day),
                FeedException(
                    item: item(5), itemTitle: "Deploy key", title: "Deploy key", here: true, kind: .only,
                    createdAt: at - 12 * day),
            ],
            recent: [
                FeedUse(
                    at: at - 40 * 60, item: item(11), itemTitle: "Cloudflare API", here: false, action: .deploy,
                    project: "edge-worker", command: "wrangler deploy", outcome: .allowed, decidedBy: .answer,
                    answeredOn: "iPhone")
            ])
        let bot = FeedAgent(
            id: "5", name: "Release bot", host: .other, revoked: true, tokenExpiresAt: at - 2 * day,
            lastUseAt: at - 30 * day)
        return [
            FeedVault(
                vaultID: "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c", vaultName: "Personal", teamID: "t_7k2m5q4x3c",
                macs: [
                    FeedMac(
                        device: PreviewMacs.macMini, relayDeviceID: 2, name: "Mac mini", seq: UInt64(at - 120),
                        generatedAt: at - 120, week: FeedWeek(byYou: 7, automatic: 128),
                        agents: [claude, codex, t3]),
                    FeedMac(
                        device: PreviewMacs.macBookPro, relayDeviceID: 5, name: "MacBook Pro", seq: UInt64(at - 3 * day),
                        generatedAt: at - 3 * day, stale: true, week: FeedWeek(byYou: 1, automatic: 6), agents: [ci]),
                ]),
            FeedVault(
                vaultID: "8e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b", vaultName: "Work", teamID: "t_wq3k7m2p5x",
                macs: [
                    FeedMac(
                        device: PreviewMacs.workMacBookPro, relayDeviceID: 3, name: "MacBook Pro",
                        seq: UInt64(at - 300), generatedAt: at - 300, truncated: true,
                        week: FeedWeek(byYou: 2, automatic: 31), agents: [workClaude, bot])
                ]),
        ]
    }

    // MARK: Test and preview hooks

    /// The feeds that `feedList` answers, as the core shows them.
    public func setFeed(_ vaults: [FeedVault]) { feedState.vaults = vaults }

    /// The answers of the next `feedWait` calls; after them it answers false.
    public func scriptFeedWaits(_ waits: [Bool]) { feedState.waits = waits }

    /// The answers of the next `feedActionWait` calls; after them it answers `applied`.
    public func scriptFeedOutcomes(_ outcomes: [PreviewFeed.Scripted]) { feedState.outcomes = outcomes }

    public func failNextFeedList(_ error: VaultError) { feedState.nextListError = error }

    public func failNextFeedActionString(_ error: VaultError) { feedState.nextStringError = error }

    /// The next `feedAction` fails with `error`, as the relay or the core would.
    public func failNextFeedAction(_ error: VaultError) { feedState.nextActionError = error }

    /// The removals that `feedAction` took, in order.
    public func sentFeedActions() -> [PreviewFeed.Sent] { feedState.sent }

    /// The strings that `feedActionString` made, in order.
    public func preparedFeedActions() -> [PreparedFeedAction] { feedState.prepared }

    public func feedListCalls() -> Int { feedState.listCalls }

    public func feedWaitCalls() -> Int { feedState.waitCalls }

    // MARK: VaultService

    /// The core keeps the feeds in the questions contexts: none after a lock or a suspend.
    private func requireFeedContext() throws {
        let open = unlocked || questionsState.ownOpen || questionsState.others.contains(where: \.open)
        guard open else { throw VaultError(.locked, "The vault is locked.") }
    }

    public func feedList() async throws -> FeedList {
        feedState.listCalls += 1
        try requireFeedContext()
        if let error = feedState.nextListError {
            feedState.nextListError = nil
            throw error
        }
        return FeedList(vaults: feedState.vaults)
    }

    public func feedWait(timeout: Int) async throws -> Bool {
        feedState.waitCalls += 1
        try requireFeedContext()
        if feedState.waits.isEmpty {
            try await Task.sleep(for: .milliseconds(200))
            try requireFeedContext()
            return false
        }
        return feedState.waits.removeFirst()
    }

    private struct Found {
        var vault: Int
        var mac: Int
        var agent: Int
        var exception: Int
    }

    private func find(_ removal: FeedRemoval) throws -> Found {
        let gone = VaultError(.notFound, "This list of the Mac changed. Look at it again.")
        guard let vault = feedState.vaults.firstIndex(where: { $0.vaultID == removal.vaultID }) else { throw gone }
        guard let mac = feedState.vaults[vault].macs.firstIndex(where: { $0.device == removal.macDevice }) else {
            throw gone
        }
        let agents = feedState.vaults[vault].macs[mac].agents
        guard let agent = agents.firstIndex(where: { $0.id == removal.agent }) else { throw gone }
        guard
            let exception = agents[agent].exceptions.firstIndex(where: {
                $0.item == removal.item && $0.kind == removal.kind && $0.createdAt == removal.createdAt
            })
        else { throw gone }
        if agents[agent].revoked { throw VaultError(.invalidInput, "This agent is disconnected.") }
        return Found(vault: vault, mac: mac, agent: agent, exception: exception)
    }

    private func actionString(_ removal: FeedRemoval, found: Found, actionID: String, time: Int64) -> String {
        let vault = feedState.vaults[found.vault]
        let mac = vault.macs[found.mac]
        return [
            "apassy-feed-action-v1", "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b", mac.device, vault.teamID, actionID,
            "remove_exception:\(removal.agent):\(removal.item):\(removal.kind.rawValue):\(removal.createdAt)",
            String(mac.seq ?? 0), String(time),
        ].joined(separator: "\n")
    }

    private static func newActionID() -> String {
        Base64URL.encode(Data((0..<16).map { _ in UInt8.random(in: 0...255) }))
    }

    public func feedActionString(_ removal: FeedRemoval, actionID: String?, time: Int64?) async throws
        -> PreparedFeedAction
    {
        try requireFeedContext()
        if let error = feedState.nextStringError {
            feedState.nextStringError = nil
            throw error
        }
        let found = try find(removal)
        let vault = feedState.vaults[found.vault]
        guard vault.macs[found.mac].canAct else {
            throw VaultError(.invalidInput, "Select this vault on this iPhone to act on the agents of its Macs.")
        }
        guard vault.registered else {
            throw VaultError(.notRegistered, "This iPhone cannot send actions yet: the vault must sync to this iPhone first.")
        }
        if removal.kind.needsFaceID, !vault.answerKey {
            throw VaultError(.notRegistered, "Connect this iPhone again on a Mac to use Face ID here.")
        }
        let id = actionID ?? Self.newActionID()
        let at = time ?? Int64(Date().timeIntervalSince1970)
        let agent = vault.macs[found.mac].agents[found.agent]
        let prepared = PreparedFeedAction(
            vaultID: vault.vaultID, teamID: vault.teamID, actionID: id, time: at, feedSeq: vault.macs[found.mac].seq,
            actionString: actionString(removal, found: found, actionID: id, time: at),
            needsFaceID: removal.kind.needsFaceID,
            faceIDReason: "remove an exception of agent \"\(String(agent.name.prefix(40)))\"")
        feedState.prepared.append(prepared)
        feedState.preparedByID[id] = prepared
        return prepared
    }

    public func feedAction(_ removal: FeedRemoval, actionID: String, time: Int64, signature: Data?) async throws
        -> SentFeedAction
    {
        try requireFeedContext()
        let now = Int64(Date().timeIntervalSince1970)
        if time + 55 < now { throw VaultError(.staleAction, "This action is too old to send. Do it again.") }
        // The core sends the string that it prepared, also after a newer feed of the Mac; the
        // exception must still be in the newest feed.
        guard let prepared = feedState.preparedByID[actionID], prepared.time == time,
            prepared.vaultID == removal.vaultID
        else {
            throw VaultError(.staleAction, "This action was not prepared on this iPhone. Do it again.")
        }
        let macName =
            feedState.vaults.first { $0.vaultID == removal.vaultID }?.macs.first { $0.device == removal.macDevice }?
            .name ?? "the Mac"
        guard let found = try? find(removal) else {
            throw VaultError(.notFound, "The list on \(macName) changed. Try again.")
        }
        let mac = feedState.vaults[found.vault].macs[found.mac]
        if mac.stale {
            throw VaultError(.staleFeed, "The Mac has not reported for a day. Act on it when it reports again.")
        }
        if removal.kind.needsFaceID, signature == nil {
            throw VaultError(.invalidInput, "This action needs Face ID.")
        }
        if !removal.kind.needsFaceID, signature != nil {
            throw VaultError(.invalidInput, "This action is signed by the core.")
        }
        if let error = feedState.nextActionError {
            feedState.nextActionError = nil
            throw error
        }
        feedState.sent.append(
            .init(
                removal: removal, actionID: actionID, time: time, signature: signature, feedSeq: prepared.feedSeq,
                actionString: prepared.actionString))
        feedState.posted[actionID] = removal
        return SentFeedAction(
            actionID: actionID, seq: UInt64(feedState.sent.count), createdAt: now, expiresAt: now + 300)
    }

    public func feedActionWait(actionID: String, vaultID: String?, timeout: Int) async throws -> FeedActionOutcome {
        try requireFeedContext()
        guard let removal = feedState.posted[actionID] else {
            throw VaultError(.notFound, "This action is not known on this iPhone.")
        }
        // The Mac takes a moment to apply it.
        try await Task.sleep(for: .milliseconds(150))
        let next = feedState.outcomes.isEmpty ? PreviewFeed.Scripted(.applied) : feedState.outcomes.removeFirst()
        if next.outcome == .applied, next.verified, let found = try? find(removal) {
            // The core hides the exception until the next feed of that Mac.
            feedState.vaults[found.vault].macs[found.mac].agents[found.agent].exceptions.remove(at: found.exception)
        }
        let at = Int64(Date().timeIntervalSince1970)
        return FeedActionOutcome(
            actionID: actionID, outcome: next.outcome, verified: next.verified,
            reason: next.verified ? next.reason : nil, feedSeq: nil, at: next.verified ? at : nil)
    }
}
