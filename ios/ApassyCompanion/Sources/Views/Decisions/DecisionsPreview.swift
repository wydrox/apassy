import ApassyVaultKit
import SwiftUI

#if DEBUG

    /// Synthetic questions for the previews and the Simulator, as in the mockup (screen 5). No
    /// value is real, and nothing leaves the process.
    enum DecisionsPreview {
        static func questions(now: Date = Date()) -> [RemoteQuestion] {
            [
                question(
                    qid: "c3RyaXBlLWxpdmUtcXVlc3Rpb24", agent: "claude-code", item: "Stripe live", production: true,
                    project: "acme-billing", command: ["stripe", "payouts", "list", "--limit", "10"],
                    env: ["STRIPE_SECRET_KEY"],
                    why: "This is a production key, and there is no rule for reading in acme-billing yet.",
                    answers: ["once", "production:read", "never_for_agent", "always_ask_for_agent", "disconnect"],
                    waited: 8, now: now),
                question(
                    qid: "b3BlbmFpLWFwaS1xdWVzdGlvbi0", agent: "codex", item: "OpenAI API", production: false,
                    project: "newsletter", command: ["git", "status", "--short"], env: ["OPENAI_API_KEY"],
                    why: "Codex has not used OpenAI API in newsletter before.",
                    answers: ["once", "in_project:read", "never_for_agent", "always_ask_for_agent", "disconnect"],
                    waited: 61, now: now),
            ]
        }

        /// The questions of a second vault, "Work", asked by another Mac.
        static func workQuestions(now: Date = Date()) -> [RemoteQuestion] {
            [
                question(
                    qid: "Y2xvdWRmbGFyZS13b3JrLXF1ZXN0", agent: "claude-code", item: "Cloudflare API", production: true,
                    project: "edge-worker", command: ["wrangler", "deploy"], env: ["CLOUDFLARE_API_TOKEN"],
                    why: "This is a production key, and there is no rule for reading in edge-worker yet.",
                    answers: ["once", "production:read", "never_for_agent", "always_ask_for_agent", "disconnect"],
                    waited: 25, asker: "MacBook Pro", now: now)
            ]
        }

        /// The question of a third vault, "Family", whose questions are locked until it opens.
        static func familyQuestions(now: Date = Date()) -> [RemoteQuestion] {
            [
                question(
                    qid: "ZmFtaWx5LWhvbWUtcXVlc3Rpb24", agent: "codex", item: "Home router", production: false,
                    project: "home-lab", command: ["ansible-playbook", "router.yml"], env: ["ROUTER_PASSWORD"],
                    why: "Codex has not used Home router in home-lab before.",
                    answers: ["once", "in_project:read", "never_for_agent", "always_ask_for_agent", "disconnect"],
                    waited: 4, asker: "iMac", now: now)
            ]
        }

        /// The second vault of `-ApassyPreviewDecisions vaults`.
        static let workVault = (id: "8e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b", name: "Work", team: "t_wq3k7m2p5x")
        /// The locked vault of `-ApassyPreviewDecisions locked`.
        static let familyVault = (id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", name: "Family", team: "t_fffffffff2")

        private static func question(
            qid: String, agent: String, item: String, production: Bool, project: String, command: [String],
            env: [String], why: String, answers: [String], waited: Int64, asker: String = "Mac mini", now: Date
        ) -> RemoteQuestion {
            let at = Int64(now.timeIntervalSince1970) - waited
            let card = QuestionCard(
                askerDevice: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", createdAt: at,
                run: QuestionRun(
                    id: "90000\(waited)", agent: agent, command: command, cwd: "/Users/me/Dev/\(project)",
                    envNames: env, purpose: "", risk: "", userRequest: "", requestSource: "",
                    agentRequest: ""),
                question: QuestionInfo(
                    items: [.init(itemID: qid, name: item, production: production, unconfirmed: false, alwaysAsk: false)],
                    project: .init(key: "/Users/me/Dev/\(project)/.git", label: project), action: .read,
                    production: production, why: why, validAnswers: answers),
                digest: String(repeating: "0", count: 64))
            return RemoteQuestion(
                qid: qid, state: .open, askerName: asker, createdAt: at,
                expiresAt: at + Int64(Decisions.questionLifetime), card: card)
        }
    }

    #if targetEnvironment(simulator)
        extension View {
            /// A development aid of the Simulator: with `-ApassyPreviewVault -ApassyPreviewDecisions
            /// list|detail|vaults|locked`, the preview vault gets the synthetic questions; `detail`
            /// opens the newest as a notification would; `vaults` adds a second vault, "Work", with
            /// its own questions team, as a core that keeps every unlocked vault lists it; `locked`
            /// adds a third vault on this iPhone too, "Family", whose questions are not open: its row
            /// has Unlock, and the passphrase of the preview opens it.
            func decisionsPreviewSeed(_ model: QuestionsModel?) -> some View {
                modifier(DecisionsPreviewSeed(model: model))
            }
        }

        private struct DecisionsPreviewSeed: ViewModifier {
            let model: QuestionsModel?
            @Environment(VaultModel.self) private var vault: VaultModel?
            @Environment(RootModel.self) private var root: RootModel?

            func body(content: Content) -> some View {
                content.task {
                    guard let mode = UserDefaults.standard.string(forKey: "ApassyPreviewDecisions"),
                        let model, let service = vault?.service as? PreviewVaultService
                    else { return }
                    // The rows of this iPhone hold the answer key of each team (software keys in
                    // the Simulator), as after a confirmed connection.
                    let signers = root?.answerSigners
                    await service.setQuestionsReportVaultScope(true)
                    await service.setQuestions(
                        enabled: true, questions: DecisionsPreview.questions(),
                        answerKey: try? signers?.joinKey(team: "t_7k2m5q4x3c"))
                    if mode == "vaults" || mode == "locked" {
                        let work = DecisionsPreview.workVault
                        await service.addQuestionsVault(
                            id: work.id, name: work.name, team: work.team, questions: DecisionsPreview.workQuestions(),
                            answerKey: try? signers?.joinKey(team: work.team))
                    }
                    if mode == "locked" {
                        let family = DecisionsPreview.familyVault
                        await service.addQuestionsVault(
                            id: family.id, name: family.name, team: family.team,
                            questions: DecisionsPreview.familyQuestions(),
                            answerKey: try? signers?.joinKey(team: family.team), onPhone: true, open: false)
                        await vault?.refreshInfo()
                    }
                    if let info = try? await service.info(), let id = info.selected {
                        let now = Int64(Date().timeIntervalSince1970)
                        let fixtures = [
                            RequestHistoryEntry(id: "relay:\(id):history-approved", vaultID: id,
                                qid: "history-approved", title: "GitHub read token", agent: "codex",
                                project: "website", action: "read", production: false, deviceName: "Mac mini",
                                firstSeenAt: now - 3600, lastSeenAt: now - 3540, expiresAt: now - 3480,
                                selectedKind: "approve_once", attemptedAt: now - 3590, sentAt: now - 3589,
                                outcome: "approved", confirmedKind: "approve_once", confirmedAt: now - 3588,
                                confirmedBy: "Mac mini"),
                            RequestHistoryEntry(id: "relay:\(id):history-unconfirmed", vaultID: id,
                                qid: "history-unconfirmed", title: "Deploy token", agent: "claude-code",
                                project: "website", action: "deploy", production: true, deviceName: "MacBook Pro",
                                firstSeenAt: now - 7200, lastSeenAt: now - 7140, expiresAt: now - 7080,
                                selectedKind: "deny", attemptedAt: now - 7190),
                        ]
                        await service.setRequestHistory([RequestHistoryVault(
                            vaultID: id, vaultName: "Personal", availability: .available, entries: fixtures)])
                    }
                    await model.refresh()
                    if mode == "detail" { model.notificationOpened() }
                }
            }
        }
    #endif

#endif
