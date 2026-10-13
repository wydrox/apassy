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
                    project: "newsletter", command: ["node", "scripts/summarize.js"], env: ["OPENAI_API_KEY"],
                    why: "Codex has not used OpenAI API in newsletter before.",
                    answers: ["once", "in_project:read", "never_for_agent", "always_ask_for_agent", "disconnect"],
                    waited: 61, now: now),
            ]
        }

        private static func question(
            qid: String, agent: String, item: String, production: Bool, project: String, command: [String],
            env: [String], why: String, answers: [String], waited: Int64, now: Date
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
                qid: qid, state: .open, askerName: "Mac mini", createdAt: at,
                expiresAt: at + Int64(Decisions.questionLifetime), card: card)
        }
    }

    #if targetEnvironment(simulator)
        extension View {
            /// A development aid of the Simulator: with `-ApassyPreviewVault -ApassyPreviewDecisions
            /// list|detail`, the preview vault gets the synthetic questions; `detail` opens the newest
            /// as a notification would.
            func decisionsPreviewSeed(_ model: QuestionsModel?) -> some View {
                modifier(DecisionsPreviewSeed(model: model))
            }
        }

        private struct DecisionsPreviewSeed: ViewModifier {
            let model: QuestionsModel?
            @Environment(VaultModel.self) private var vault: VaultModel?

            func body(content: Content) -> some View {
                content.task {
                    guard let mode = UserDefaults.standard.string(forKey: "ApassyPreviewDecisions"),
                        let model, let service = vault?.service as? PreviewVaultService
                    else { return }
                    await service.setQuestions(enabled: true, questions: DecisionsPreview.questions())
                    await model.refresh()
                    if mode == "detail" { model.notificationOpened() }
                }
            }
        }
    #endif

#endif
