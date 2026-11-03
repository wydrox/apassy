import ApassyVaultKit
import CryptoKit
import Foundation

/// The demo of the iPhone app ("Try the Demo", `-ApassyDemo`): one vault of synthetic data in
/// memory, so App Review and new owners can try the app without a Mac. It is the preview vault
/// (`PreviewVaultService`) with more content: logins with websites and one-time codes, a passkey,
/// API keys, notes, folders, a planted duplicate, the agents of a Mac with their uses, one waiting
/// run question and one waiting access request from "Mac mini (demo)", and a list of past
/// decisions.
///
/// Nothing in it is real, nothing is written to disk, and nothing leaves the process: the service
/// is an actor over dictionaries. This module is linked by the app and the watch app only, never by
/// the AutoFill extension, so AutoFill never sees a demo item.
public enum DemoVault {
    /// The name of the demo vault.
    public static let name = "Demo"
    /// The passphrase of the demo vault. The lock screen of the demo shows it.
    public static let passphrase = "demo passphrase"
    /// The Mac that asks in the demo.
    public static let macName = "Mac mini (demo)"
    /// The second Mac of the agents list.
    public static let laptopName = "MacBook Pro (demo)"
    /// The questions team of the demo vault.
    public static let team = "t_7k2m5q4x3c"
    /// The vault ID of the demo vault.
    public static var vaultID: String { PreviewVaultService.vaultID }
    /// The ID of the waiting access request.
    public static let accessRequestID = "demo-81"
    /// The qid of the waiting run question.
    public static let runQuestionID = "ZGVtby1ydW4tcXVlc3Rpb24"
    /// How long the waiting requests of a new demo wait: long enough to try them.
    public static let waitLifetime: Int64 = 1800
    /// The relying party of the demo passkey.
    public static let passkeyRelyingParty = "demo.example.com"

    /// A new demo vault, unlocked, with all its content.
    ///
    /// - Parameter answerKey: the public key (X9.63) of the demo answer key
    ///   (`DemoSession.answerKey`), which the row of this iPhone holds, so Allow Once can sign.
    public static func make(answerKey: Data, now: Date = Date()) async -> PreviewVaultService {
        let service = PreviewVaultService(
            empty: false, unlocked: false, vaultName: name, syncSource: nil, passphrase: passphrase)
        // Open with the passphrase kept, as a vault that the owner unlocked: a short trip to another
        // app suspends it and opens it again on return (the lock after five minutes still applies).
        try? await service.unlock(passphrase: passphrase, keep: true)
        await addItems(to: service)
        await service.setQuestionsReportVaultScope(true)
        await service.setQuestions(enabled: true, questions: [runQuestion(now: now)], answerKey: answerKey)
        await service.setAccessRequests([
            accessRequest(answerKey: answerKey, now: now),
            pastAccessRequest(answerKey: answerKey, now: now),
        ])
        await service.setRequestHistory([
            RequestHistoryVault(vaultID: vaultID, vaultName: name, availability: .available, entries: history(now: now))
        ])
        await service.setFeed(feed(now: now))
        return service
    }

    // MARK: - Items

    /// The items that the demo adds to the preview items (GitHub with a one-time code, the Stripe
    /// and OpenAI keys, a database, an SSH key, Netflix, the Wi-Fi, and a conflict copy).
    private static func addItems(to service: PreviewVaultService) async {
        let personal = PreviewOrganize.FolderID.personal
        let shop = ItemDraft(
            title: "Example Shop", kind: .login, notes: "Synthetic account of the demo.", tags: ["home"],
            fields: [
                .named("username", "demo@example.com", secret: false),
                .named("password", "synthetic-Shop-4mQ8!vR2", secret: true),
                .detail("Website", "https://shop.example.com", secret: false),
                .detail("One-time password", "otpauth://totp/Shop:demo?secret=GEZDGNBVGY3TQOJQ", secret: true),
            ])
        let note = ItemDraft(
            title: "Recovery notes", kind: .custom,
            notes: "Synthetic note of the demo. The recovery codes of the demo accounts are in the safe at home.",
            tags: ["home"], fields: [.detail("Location", "Home safe", secret: false)])
        // The planted duplicate: the same website and username as "Netflix".
        let duplicate = ItemDraft(
            title: "Netflix (old)", kind: .login, notes: "", tags: ["home"],
            fields: [
                .named("username", "family@example.com", secret: false),
                .named("password", "synthetic-older-Netflix", secret: true),
                .detail("Website", "https://www.netflix.com", secret: false),
            ])
        for draft in [shop, note, duplicate] {
            if let saved = try? await service.save(id: nil, revision: nil, draft: draft) {
                try? await service.setItemFolder(id: saved.id, folder: personal)
            }
        }
        // A passkey, made by the preview authenticator: a key of this process only.
        let registration = PasskeyRegistration(
            rpID: passkeyRelyingParty, userName: "demo@example.com", userDisplayName: "Demo owner",
            userHandle: Data("demo-owner".utf8), clientDataHash: Data(SHA256.hash(data: Data("demo".utf8))),
            algorithms: [PasskeyAlgorithm.es256], excluded: [], attach: nil, title: "Demo passkey")
        if let created = try? await service.passkeyRegister(registration) {
            try? await service.setItemFolder(id: created.id, folder: personal)
        }
    }

    // MARK: - Requests

    /// The waiting run question: Claude Code wants to read the Stripe live key.
    public static func runQuestion(now: Date = Date()) -> RemoteQuestion {
        let at = Int64(now.timeIntervalSince1970) - 8
        let card = QuestionCard(
            askerDevice: PreviewVaultService.PreviewMacs.macMini, createdAt: at,
            run: QuestionRun(
                id: "900000000000001", agent: "claude-code", command: ["stripe", "payouts", "list", "--limit", "10"],
                cwd: "/Users/demo/Dev/acme-billing", envNames: ["STRIPE_SECRET_KEY"],
                purpose: "List the last payouts.", risk: "production credential: always asks the owner",
                userRequest: "Check the last payouts.", requestSource: "from the host hook",
                agentRequest: "Read the payouts with the Stripe key."),
            question: QuestionInfo(
                items: [
                    .init(itemID: "101", name: "Stripe live key", production: true, unconfirmed: false, alwaysAsk: false)
                ],
                project: .init(key: "/Users/demo/Dev/acme-billing/.git", label: "acme-billing"), action: .read,
                production: true, why: "This is a production key, and there is no rule for reading in acme-billing yet.",
                validAnswers: ["once", "production:read", "never_for_agent", "always_ask_for_agent", "disconnect"]),
            digest: String(repeating: "d", count: 64))
        return RemoteQuestion(
            qid: runQuestionID, state: .open, askerName: macName, createdAt: at, expiresAt: at + waitLifetime,
            card: card)
    }

    /// The waiting access request: Codex asks to read the OpenAI key once.
    public static func accessRequest(answerKey: Data, now: Date = Date()) -> RelayAccessRequest {
        let created = UInt64(now.timeIntervalSince1970) - 20
        return access(
            id: accessRequestID, agent: "Codex", host: "codex", item: "OpenAI", binding: "OPENAI_API_KEY",
            hosts: ["api.openai.com"], reason: "Summarize the newsletter draft with the OpenAI API.",
            project: "newsletter", created: created, expires: created + UInt64(waitLifetime), state: "open",
            answerKey: answerKey)
    }

    /// An access request that the owner allowed yesterday, for History.
    static func pastAccessRequest(answerKey: Data, now: Date = Date()) -> RelayAccessRequest {
        let created = UInt64(now.timeIntervalSince1970) - 86_400
        let open = access(
            id: "demo-79", agent: "Claude Code", host: "claude-code", item: "GitHub", binding: "GITHUB_TOKEN",
            hosts: ["api.github.com"], reason: "Open the pull request of the release.", project: "acme-billing",
            created: created, expires: created + 300, state: "open", answerKey: answerKey)
        let card = open.card
        let receipt = AccessReceipt(
            vault_id: card.vault_id, team_id: card.team_id, qid: card.qid, request_id: card.request_id,
            asker: card.asker.device, digest: open.digest, outcome: "allowed_once",
            answered_by: "6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b", device_name: "iPhone (demo)", device_kind: "iphone",
            kind: AccessChoice.allow_once.rawValue, at: created + 40, expires_at: card.expires_at)
        return RelayAccessRequest(
            vault_id: open.vault_id, card: card, digest: open.digest, state: "settled", receipt: receipt,
            answer_key: open.answer_key)
    }

    static func access(
        id: String, agent: String, host: String, item: String, binding: String, hosts: [String], reason: String,
        project: String, created: UInt64, expires: UInt64, state: String, answerKey: Data,
        rowVaultID: String = DemoVault.vaultID
    ) -> RelayAccessRequest {
        let cwd = "/Users/demo/Dev/\(project)"
        let card = RelayAccessCard(
            vault_id: "d070dc14-a3ac-42c2-95aa-cc85d6d58900", team_id: team,
            qid: Base64URL.encode(Data("demo-access-\(id)".utf8)), key_id: "630dcd2966c43366", to: "member",
            request_id: id,
            asker: .init(device: PreviewVaultService.PreviewMacs.macMini, relay_device_id: 2, name: macName),
            vault_name: name,
            agent: .init(id: "7", name: agent, host: host, host_source: "agent_claimed"),
            item: .init(
                local_id: "102", uuid: "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a03", revision: "3", name: item,
                environment: "development", delivery: "placeholder", binding_name: binding),
            project: .init(key: "\(cwd)/.git", label: project), cwd: cwd, action: "read", hosts: hosts,
            scope_source: "agent_requested_mac_checked", reason: reason,
            policy_digest: String(repeating: "b", count: 64), created_at: created, expires_at: expires,
            valid_answers: [.deny, .allow_once], local_review_reason: nil)
        return RelayAccessRequest(
            vault_id: rowVaultID, card: card, digest: String(repeating: "a", count: 64), state: state, receipt: nil,
            answer_key: Base64URL.encode(answerKey))
    }

    // MARK: - History and agents

    /// The past decisions of Requests › History: one allowed, one denied.
    static func history(now: Date) -> [RequestHistoryEntry] {
        let at = Int64(now.timeIntervalSince1970)
        return [
            RequestHistoryEntry(
                id: "relay:\(vaultID):demo-approved", vaultID: vaultID, qid: "demo-approved",
                title: "GitHub", agent: "codex", project: "newsletter", action: "read", production: false,
                deviceName: macName, firstSeenAt: at - 3600, lastSeenAt: at - 3540, expiresAt: at - 3300,
                selectedKind: "approve_once", attemptedAt: at - 3590, sentAt: at - 3589, outcome: "approved",
                confirmedKind: "approve_once", confirmedAt: at - 3588, confirmedBy: macName),
            RequestHistoryEntry(
                id: "relay:\(vaultID):demo-denied", vaultID: vaultID, qid: "demo-denied",
                title: "Production Postgres", agent: "claude-code", project: "acme-billing", action: "deploy",
                production: true, deviceName: macName, firstSeenAt: at - 7200, lastSeenAt: at - 7140,
                expiresAt: at - 6900, selectedKind: "deny", attemptedAt: at - 7190, sentAt: at - 7189,
                outcome: "denied", confirmedKind: "deny", confirmedAt: at - 7188, confirmedBy: macName),
        ]
    }

    /// The agents of the demo vault: the Mac mini with Claude Code, Codex, and T3 Code, and a
    /// MacBook Pro that has not reported for three days.
    static func feed(now: Date) -> [FeedVault] {
        guard var vault = PreviewVaultService.sampleFeed(now: now).first(where: { $0.vaultID == vaultID }) else {
            return []
        }
        vault.vaultName = name
        for index in vault.macs.indices {
            vault.macs[index].name = index == 0 ? macName : laptopName
        }
        return [vault]
    }
}
