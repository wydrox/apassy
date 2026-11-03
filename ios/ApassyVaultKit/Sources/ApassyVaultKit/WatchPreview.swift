import Foundation

/// A state of the watch for a screenshot or a preview (`-ApassyWatchPreview <state>`, ios/README.md).
public enum WatchPreviewState: String, CaseIterable, Sendable {
    case unpaired, failed, removed, words, connected, empty, requests, detail, denyonly, sent, notconfirmed,
        allowed, denied, expired, settings
}

/// Synthetic data of the watch: no real vault, Mac, agent, or key. The answer keys are in memory only.
public enum WatchPreview {
    public static let vault = WatchVault(id: "d070dc14-a3ac-42c2-95aa-cc85d6d58900", name: "Personal")
    public static let mac = "Studio Mac"
    public static let team = "t_7k2m5q4x3c"
    public static let deviceName = "Synthetic Apple Watch"
    /// A synthetic Connect code: it has the form of one, and opens nothing.
    public static let link = "https://relay.example.test/join#apassy_lnk_t_7k2m5q4x3c_0123456789abcdef&handoff=2.c3ludGhldGlj.c3ludGhldGlj.c3ludGhldGlj"

    /// The model of the watch in `state`, over `PreviewWatchService`.
    @MainActor
    public static func model(_ state: WatchPreviewState) -> WatchAppModel {
        let keys = MemoryWatchAnswerKeys(checkTime: .seconds(1))
        let key = (try? keys.create(team: team)) ?? Data()
        let replica = MemoryWatchReplicaStore(WatchReplicaSecret(passphrase: "synthetic-preview-passphrase", team: team))
        let now = UInt64(Date.now.timeIntervalSince1970)
        let complete = request(answerKey: key, created: now - 30, expires: now + 270)
        var service = PreviewWatchService(state: .ready, requests: [complete])
        var launchLink: String?
        var progress: [String: WatchAnswerProgress] = [:]
        var path: [WatchRoute] = []
        var settings = false
        switch state {
        case .unpaired:
            replica.delete()
            service = PreviewWatchService(state: .unpaired)
        case .failed:
            replica.delete()
            service = PreviewWatchService(
                state: .unpaired, connection: .fails(VaultError(.joinRefused, "The Mac refused this watch.")))
            launchLink = link
        case .removed:
            service = PreviewWatchService(state: .removed)
        case .words:
            replica.delete()
            service = PreviewWatchService(state: .unpaired, connection: .waits)
            launchLink = link
        case .connected:
            replica.delete()
            service = PreviewWatchService(state: .unpaired, connection: .attaches)
            launchLink = link
        case .empty:
            service = PreviewWatchService(state: .ready)
        case .requests:
            service = PreviewWatchService(state: .ready, requests: [
                complete,
                request(
                    agent: "Codex", credential: "Stripe key", environment: "development", delivery: "placeholder",
                    action: "read", hosts: ["api.stripe.com"], reason: "Check the status of a synthetic payment.",
                    requestID: "82", answerKey: key, created: now - 60, expires: now + 240),
                settled(
                    request(credential: "Synthetic API key", requestID: "79", answerKey: key, created: now - 200,
                        expires: now + 100), choice: .allow_once, byWatch: false),
                request(
                    agent: "Codex", credential: "Synthetic database URL", requestID: "77", state: "expired",
                    answerKey: key, created: now - 500, expires: now - 200),
            ])
        case .detail:
            path = [.request(complete.id)]
        case .denyonly:
            let incomplete = request(
                action: nil, hosts: [], validAnswers: [.deny],
                localReviewReason: "The agent did not name an action or hosts.", requestID: "83", answerKey: key,
                created: now - 20, expires: now + 280)
            service = PreviewWatchService(state: .ready, requests: [incomplete])
            path = [.request(incomplete.id)]
        case .sent:
            service = PreviewWatchService(state: .ready, requests: [complete], settles: false)
            progress = [complete.id: .sent(.allow_once, at: .now)]
            path = [.request(complete.id)]
        case .notconfirmed:
            service = PreviewWatchService(state: .ready, requests: [complete], settles: false)
            progress = [complete.id: .sent(.allow_once, at: .now.addingTimeInterval(-61))]
            path = [.request(complete.id)]
        case .allowed, .denied:
            let choice: AccessChoice = state == .allowed ? .allow_once : .deny
            let answered = settled(complete, choice: choice, byWatch: true)
            service = PreviewWatchService(state: .ready, requests: [answered])
            progress = [answered.id: .sent(choice, at: .now)]
            path = [.request(answered.id)]
        case .expired:
            let expired = request(requestID: "80", state: "expired", answerKey: key, created: now - 400, expires: now - 100)
            service = PreviewWatchService(state: .ready, requests: [expired])
            path = [.request(expired.id)]
        case .settings:
            settings = true
        }
        return WatchAppModel(
            service: service, keys: keys, replica: replica, deviceName: deviceName, launchLink: launchLink,
            progress: progress, path: path, showsSettings: settings, pollInterval: .milliseconds(600))
    }

    /// A synthetic access request of `mac`.
    public static func request(
        agent: String = "Claude Code", credential: String = "GitHub token", environment: String = "production",
        delivery: String = "real_value", action: String? = "deploy",
        hosts: [String] = ["api.github.com", "uploads.github.com"],
        project: String? = "shop", cwd: String = "/Users/owner/Dev/shop",
        reason: String = "Need to push the release tag.", validAnswers: [AccessChoice] = [.deny, .allow_once],
        localReviewReason: String? = nil, requestID: String = "81", state: String = "open", answerKey: Data?,
        created: UInt64, expires: UInt64
    ) -> RelayAccessRequest {
        let card = RelayAccessCard(
            vault_id: vault.id, team_id: team, qid: "oKGio6SlpqeoqaqrrK2u\(requestID)", key_id: "630dcd2966c43366",
            to: "member", request_id: requestID,
            asker: .init(device: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", relay_device_id: 1, name: mac),
            vault_name: vault.name,
            agent: .init(id: "7", name: agent, host: "claude-code", host_source: "agent_claimed"),
            item: .init(
                local_id: "12", uuid: "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c", revision: "4", name: credential,
                environment: environment, delivery: delivery, binding_name: "GITHUB_TOKEN"),
            project: project.map { RelayAccessCard.Project(key: "\(cwd)/.git", label: $0) }, cwd: cwd, action: action, hosts: hosts,
            scope_source: "agent_requested_mac_checked", reason: reason,
            policy_digest: String(repeating: "b", count: 64), created_at: created, expires_at: expires,
            valid_answers: validAnswers, local_review_reason: localReviewReason)
        return RelayAccessRequest(
            vault_id: vault.id, card: card, digest: String(repeating: "a", count: 64), state: state, receipt: nil,
            answer_key: answerKey.map(Base64URL.encode))
    }

    /// `request` with the receipt of `choice`, answered by a watch or by an iPhone.
    public static func settled(_ request: RelayAccessRequest, choice: AccessChoice, byWatch: Bool) -> RelayAccessRequest {
        let card = request.card
        let receipt = AccessReceipt(
            vault_id: card.vault_id, team_id: card.team_id, qid: card.qid, request_id: card.request_id,
            asker: card.asker.device, digest: request.digest, outcome: choice == .deny ? "denied" : "allowed_once",
            answered_by: "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
            device_name: byWatch ? deviceName : "Synthetic iPhone", device_kind: byWatch ? "watch" : "iphone",
            kind: choice.rawValue, at: UInt64(Date.now.timeIntervalSince1970), expires_at: card.expires_at)
        return RelayAccessRequest(
            vault_id: request.vault_id, card: card, digest: request.digest, state: "settled", receipt: receipt,
            answer_key: request.answer_key)
    }
}
