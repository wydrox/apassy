import ApassyVaultKit
import Foundation

/// The synthetic data of the demo (docs/store/app-store/screenshots.md, "Demo data"): logins with
/// websites and one-time codes, a passkey, an API key, an SSH key, notes, two folders, one weak
/// and two reused passwords, one planted duplicate, three agents of "Mac mini (demo)" with their
/// uses, one waiting run question, one waiting access request, and past decisions.
///
/// No value is real: the hosts are `example.com` names, the secrets are made-up text, and the
/// one-time code secret is the RFC 4648 example. It lives in the app target only; the AutoFill
/// extension does not compile this file and never sees these items.
enum DemoData {
    static let vaultID = "de30de30de30de30de30de30de30de30"
    static let vaultName = "Demo"
    /// Typed only when Face ID is not used: the lock screen of the demo shows it.
    static let passphrase = "demo passphrase"
    static let macName = "Mac mini (demo)"
    static let deviceName = "iPhone (demo)"
    /// The questions team of the preview service (`PreviewVaultService.questionsStatus`).
    static let teamID = "t_7k2m5q4x3c"
    static let macDevice = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d"
    static let agentName = "Coding agent"
    /// The waiting run question and the waiting access request stay open this long.
    static let openFor: Int64 = 3600

    /// The item IDs in the order of `items` (the preview service numbers from 100), for
    /// `-ApassyOpen item:<id>`.
    enum ItemID {
        static let gitHub: UInt64 = 100
        static let gitHubCopy: UInt64 = 101
        static let stripe: UInt64 = 102
        static let deployServer: UInt64 = 103
        static let router: UInt64 = 104
        static let mail: UInt64 = 105
        static let forum: UInt64 = 106
        static let wifi: UInt64 = 107
        static let notes: UInt64 = 108
        static let shop: UInt64 = 109
    }

    struct Item {
        var draft: ItemDraft
        /// "Work" or "Side project", nil at the top level.
        var folder: String?
    }

    static let workFolder = "Work"
    static let sideProjectFolder = "Side project"

    private static let reused = "demo-Shared-Pass-2026"

    static let items: [Item] = [
        Item(
            draft: ItemDraft(
                title: "GitHub", kind: .login, notes: "Demo account. No real account behind it.", tags: ["work"],
                fields: [
                    .named("username", "demo@example.com", secret: false),
                    .named("password", "demo-Gh7kQ2m-Xr9v-Lp4w", secret: true),
                    .detail("Website", "https://github.example.com", secret: false),
                    .detail(
                        "One-time password", "otpauth://totp/GitHub:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                        secret: true),
                ]),
            folder: workFolder),
        // The planted duplicate of GitHub: the same website host and username (Find duplicates).
        Item(
            draft: ItemDraft(
                title: "GitHub (copy)", kind: .login, notes: "", tags: ["work"],
                fields: [
                    .named("username", "demo@example.com", secret: false),
                    .named("password", "demo-Gh7kQ2m-Xr9v-Lp4w", secret: true),
                    .detail("Website", "https://github.example.com", secret: false),
                ]),
            folder: workFolder),
        Item(
            draft: ItemDraft(
                title: "Stripe test key", kind: .apiKey, notes: "A made-up test key for the demo.", tags: ["billing"],
                fields: [
                    .named("service", "stripe", secret: false),
                    .named("project", "shop", secret: false),
                    .named("token", "sk_test_DEMO_not_a_real_key", secret: true),
                ]),
            folder: sideProjectFolder),
        Item(
            draft: ItemDraft(
                title: "Deploy server", kind: .sshKey, notes: "", tags: [],
                fields: [
                    .named("private_key", "Demo private key: not a real key.", secret: true),
                    .named("public_key", "ssh-ed25519 AAAAdemo deploy@demo", secret: false),
                ]),
            folder: workFolder),
        // Weak, for Watchtower.
        Item(
            draft: ItemDraft(
                title: "Router", kind: .login, notes: "", tags: ["home"],
                fields: [
                    .named("username", "admin", secret: false),
                    .named("password", "password1", secret: true),
                    .detail("Website", "http://router.example.com", secret: false),
                ]),
            folder: nil),
        // Mail and Forum share a password, for Watchtower.
        Item(
            draft: ItemDraft(
                title: "Mail", kind: .login, notes: "", tags: [],
                fields: [
                    .named("username", "demo@example.com", secret: false),
                    .named("password", reused, secret: true),
                    .detail("Website", "https://mail.example.com", secret: false),
                ]),
            folder: nil),
        Item(
            draft: ItemDraft(
                title: "Forum", kind: .login, notes: "", tags: [],
                fields: [
                    .named("username", "demo@example.com", secret: false),
                    .named("password", reused, secret: true),
                    .detail("Website", "https://forum.example.com", secret: false),
                    .detail(
                        "One-time password", "otpauth://totp/Forum:demo@example.com?secret=GEZDGNBVGY3TQOJQ", secret: true),
                ]),
            folder: nil),
        Item(
            draft: ItemDraft(
                title: "Wi-Fi at home", kind: .custom, notes: "Network name: DemoNet", tags: ["home"],
                fields: [.detail("Wi-Fi password", "demo wifi words", secret: true)]),
            folder: nil),
        Item(
            draft: ItemDraft(
                title: "Notes", kind: .custom, notes: "Demo note. Everything in this vault is sample data.", tags: [],
                fields: []),
            folder: nil),
    ]

    /// The passkey login, made with a synthetic key at the start of the demo.
    static let passkeyRP = "shop.example.com"
    static let passkeyTitle = "Shop"

    // MARK: Seed

    /// Fill the empty demo vault of `service`. In memory only: the calls are those of the screens.
    static func seed(_ service: PreviewVaultService, signers: any AnswerSigners, now: Date = Date()) async throws {
        var folders: [String: String] = [:]
        for name in [workFolder, sideProjectFolder] {
            folders[name] = try await service.createFolder(parent: nil, name: name).uuid
        }
        for item in items {
            let saved = try await service.save(id: nil, revision: nil, draft: item.draft)
            if let folder = item.folder, let uuid = folders[folder] {
                try await service.setItemFolder(id: saved.id, folder: uuid)
            }
        }
        _ = try await service.passkeyRegister(
            PasskeyRegistration(
                rpID: passkeyRP, userName: "demo@example.com", userDisplayName: "Demo", userHandle: Data("demo-user".utf8),
                clientDataHash: Data(repeating: 7, count: 32), algorithms: [-7], excluded: [], attach: nil,
                title: passkeyTitle))
        let answerKey = try signers.joinKey(team: teamID)
        await service.setQuestionsReportVaultScope(true)
        await service.setQuestions(enabled: true, questions: [runQuestion(now: now)], answerKey: answerKey)
        await service.setAccessRequests([accessRequest(answerKey: answerKey)])
        await service.setRequestHistory([
            RequestHistoryVault(vaultID: vaultID, vaultName: vaultName, availability: .available, entries: history(now: now))
        ])
        await service.setFeed(feed(now: now))
    }

    // MARK: Requests

    /// The run that waits on the Mac: the coding agent wants the Stripe test key for a deploy.
    static func runQuestion(now: Date) -> RemoteQuestion {
        let at = Int64(now.timeIntervalSince1970) - 12
        let card = QuestionCard(
            askerDevice: macDevice, createdAt: at,
            run: QuestionRun(
                id: "900001", agent: agentName, command: ["npm", "run", "deploy:staging"],
                cwd: "/Users/demo/Dev/shop", envNames: ["STRIPE_SECRET_KEY"], purpose: "Deploy the shop to staging.",
                risk: "", userRequest: "Deploy the new checkout page to staging.", requestSource: "from the host hook",
                agentRequest: "Run the staging deploy."),
            question: QuestionInfo(
                items: [
                    .init(itemID: "102", name: "Stripe test key", production: false, unconfirmed: false, alwaysAsk: false)
                ],
                project: .init(key: "/Users/demo/Dev/shop/.git", label: "shop"), action: .deploy, production: false,
                why: "The coding agent has not used Stripe test key for a deploy in shop before.",
                validAnswers: ["once", "in_project:deploy", "never_for_agent", "always_ask_for_agent", "disconnect"]),
            digest: String(repeating: "0", count: 64))
        return RemoteQuestion(
            qid: "ZGVtby1ydW4tcXVlc3Rpb24", state: .open, askerName: macName, createdAt: at, expiresAt: at + openFor,
            card: card)
    }

    /// The access request that waits: the coding agent asks to read the GitHub login once.
    static func accessRequest(answerKey: Data) -> RelayAccessRequest {
        PreviewVaultService.accessRequest(
            answerKey: answerKey, expiresIn: UInt64(openFor), requestID: "501", vaultID: vaultID, vaultName: vaultName,
            teamID: teamID, askerName: macName, agentName: agentName, agentHost: "other", itemName: "GitHub",
            environment: "development", bindingName: "GITHUB_TOKEN", projectLabel: "shop",
            cwd: "/Users/demo/Dev/shop", action: "read", hosts: ["api.github.example.com"],
            reason: "List the open pull requests of the shop.", createdAgo: 20)
    }

    /// The past decisions of Requests > History.
    static func history(now: Date) -> [RequestHistoryEntry] {
        let at = Int64(now.timeIntervalSince1970)
        return [
            RequestHistoryEntry(
                id: "relay:\(vaultID):demo-approved", vaultID: vaultID, qid: "demo-approved", title: "GitHub",
                agent: agentName, project: "shop", action: "read", production: false, deviceName: macName,
                firstSeenAt: at - 3600, lastSeenAt: at - 3540, expiresAt: at - 3480, selectedKind: "approve_once",
                attemptedAt: at - 3590, sentAt: at - 3589, outcome: "approved", confirmedKind: "approve_once",
                confirmedAt: at - 3588, confirmedBy: macName),
            RequestHistoryEntry(
                id: "relay:\(vaultID):demo-denied", vaultID: vaultID, qid: "demo-denied", title: "Stripe test key",
                agent: "Deploy bot", project: "shop", action: "deploy", production: false, deviceName: macName,
                firstSeenAt: at - 7200, lastSeenAt: at - 7140, expiresAt: at - 7080, selectedKind: "deny",
                attemptedAt: at - 7190, sentAt: at - 7189, outcome: "denied", confirmedKind: "deny",
                confirmedAt: at - 7188, confirmedBy: macName),
            RequestHistoryEntry(
                id: "relay:\(vaultID):demo-unconfirmed", vaultID: vaultID, qid: "demo-unconfirmed", title: "Deploy server",
                agent: "Test runner", project: "shop", action: "read", production: false, deviceName: macName,
                firstSeenAt: at - 86_400, lastSeenAt: at - 86_340, expiresAt: at - 86_280, selectedKind: "deny",
                attemptedAt: at - 86_390),
        ]
    }

    // MARK: Agents

    /// The agents that "Mac mini (demo)" publishes for the demo vault.
    static func feed(now: Date) -> [FeedVault] {
        let at = Int64(now.timeIntervalSince1970)
        let hour: Int64 = 3600
        let day: Int64 = 86400
        func item(_ n: Int) -> String { "de30de30de30de30de30de30de30de\(String(format: "%02d", n))" }
        let coding = FeedAgent(
            id: "4", name: agentName, host: .other, tokenExpiresAt: at + 90 * day, lastUseAt: at - 2 * hour,
            usesThisWeek: 38, projects: ["shop", "website"], note: "Deploys only from the main branch.",
            actions: [
                FeedActionUse(action: .read, allowed: 30, projects: ["shop", "website"]),
                FeedActionUse(action: .deploy, allowed: 6, notAllowed: 2, projects: ["shop"]),
            ],
            exceptions: [
                FeedException(
                    item: item(3), itemTitle: "Deploy server", title: "Deploy server", here: true, kind: .alwaysAsk,
                    createdAt: at - 9 * day)
            ],
            recent: [
                FeedUse(
                    at: at - 2 * hour, item: item(1), itemTitle: "GitHub", title: "GitHub", here: true, action: .read,
                    project: "shop", command: "gh pr list", outcome: .allowed, decidedBy: .bouncer),
                FeedUse(
                    at: at - 5 * hour, item: item(2), itemTitle: "Stripe test key", title: "Stripe test key", here: true,
                    action: .deploy, project: "shop", command: "npm run deploy:staging", outcome: .allowed,
                    decidedBy: .owner, answeredOn: deviceName),
                FeedUse(
                    at: at - 26 * hour, item: item(3), itemTitle: "Deploy server", title: "Deploy server", here: true,
                    action: .deploy, project: "website", command: "scp dist/ deploy@server.example.com:",
                    outcome: .denied, decidedBy: .owner, answeredOn: macName),
            ])
        let tests = FeedAgent(
            id: "7", name: "Test runner", host: .other, tokenExpiresAt: at + 60 * day, lastUseAt: at - day,
            usesThisWeek: 14, projects: ["shop"],
            actions: [FeedActionUse(action: .read, allowed: 14, projects: ["shop"])],
            recent: [
                FeedUse(
                    at: at - day, item: item(2), itemTitle: "Stripe test key", title: "Stripe test key", here: true,
                    action: .read, project: "shop", command: "npm test", outcome: .allowed, decidedBy: .pattern)
            ])
        let deploy = FeedAgent(
            id: "9", name: "Deploy bot", host: .other, tokenExpiresAt: at + 30 * day, lastUseAt: at - 2 * day,
            usesThisWeek: 3, projects: ["shop"], note: "Only the staging deploy.",
            actions: [FeedActionUse(action: .deploy, allowed: 2, notAllowed: 1, projects: ["shop"])],
            exceptions: [
                FeedException(
                    item: item(2), itemTitle: "Stripe test key", title: "Stripe test key", here: true, kind: .never,
                    createdAt: at - 2 * day)
            ],
            recent: [
                FeedUse(
                    at: at - 2 * day, item: item(2), itemTitle: "Stripe test key", title: "Stripe test key", here: true,
                    action: .deploy, project: "shop", command: "npm run deploy:production", outcome: .refused,
                    decidedBy: .rule)
            ])
        let mac = FeedMac(
            device: macDevice, relayDeviceID: 1, name: macName, seq: 12, generatedAt: at - 120,
            agents: [coding, tests, deploy])
        return [FeedVault(vaultID: vaultID, vaultName: vaultName, teamID: teamID, macs: [mac])]
    }
}
