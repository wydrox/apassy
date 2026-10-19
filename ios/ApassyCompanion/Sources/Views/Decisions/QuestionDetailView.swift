import ApassyCompanionKit
import ApassyVaultKit
import SwiftUI

/// A question through the relay as the mockup's "Decision" (screen 6): the question in one
/// sentence, its facts, the command, why the owner is asked, and the fixed glass bar: Allow ACTION
/// in PROJECT (in red as "Allow production: ACTION in PROJECT"), Deny, Allow Once. "⋯" holds the
/// agent exceptions and the environment of a credential. Allowing asks for Face ID; the stricter answers do not. Once the question ended
/// (expired, answered on another device, or sent from here) the outcome takes the place of the bar.
struct QuestionDetailView: View {
    let model: QuestionsModel
    let requestIdentity: String
    @State private var tapGuard = AnswerGuard()

    private var question: RemoteQuestion? { model.questions.first { $0.requestIdentity == requestIdentity }
        ?? model.receiptQuestions.first { $0.requestIdentity == requestIdentity } }

    var body: some View {
        Group {
            if let question, let card = question.card {
                // Each second: the timer, and the bar that gives way to "Expired".
                TimelineView(.periodic(from: .now, by: 1)) { _ in
                    content(question, card, outcome: model.outcome(for: question))
                }
            } else if let question {
                ContentUnavailableView(
                    "This question could not be read", systemImage: "lock.trianglebadge.exclamationmark",
                    description: Text(question.problem ?? "Expired."))
            } else {
                ContentUnavailableView(
                    "Request unavailable", systemImage: "questionmark.circle",
                    description: Text("Refresh Requests to check its current state. It may have ended or its vault may be locked."))
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        // The bar takes the place of the tab bar, as in the mockup.
        .toolbarVisibility(.hidden, for: .tabBar)
    }

    private func content(_ question: RemoteQuestion, _ card: QuestionCard, outcome: QuestionOutcome?) -> some View {
        let bar = AnswerBar.make(for: card)
        let agent = AgentName.display(card.run.agent)
        return List {
            Section {
                DecisionHeader(
                    agent: agent, sentence: "\(agent) wants to use \(question.credentialTitle)",
                    detail: card.question.project?.label,
                    deadline: outcome == nil
                        ? Date(timeIntervalSince1970: TimeInterval(question.expiresAt)) : nil)
            }
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 0, trailing: 16))
            facts(question, card)
            Section("Command") {
                DecisionCommand(line: CommandDisplay.line(card.run.command))
                LabeledContent("Folder") {
                    Text(card.run.cwd).font(.callout.monospaced()).lineLimit(2).truncationMode(.head)
                }
            }
            Section("Why you are asked") {
                Text(card.question.why)
                if !card.run.risk.isEmpty {
                    Text(card.run.risk).font(.footnote).foregroundStyle(.secondary)
                }
            }
            if !card.run.userRequest.isEmpty || !card.run.agentRequest.isEmpty {
                Section("Requests") {
                    if !card.run.userRequest.isEmpty { labeled("You asked", card.run.userRequest) }
                    if !card.run.agentRequest.isEmpty { labeled("The agent says", card.run.agentRequest) }
                }
            }
        }
        .contentMargins(.bottom, 24, for: .scrollContent)
        // A tap meant for the list or a notification must not answer this question.
        .onAppear { tapGuard.arm(now: Date()) }
        .onChange(of: question.card) { _, _ in tapGuard.arm(now: Date()) }
        .toolbar {
            if outcome == nil, !bar.menu.isEmpty {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        ForEach(bar.menu) { choice in
                            Button(choice.label, role: choice.destructive ? .destructive : nil) {
                                answer(choice, question)
                            }
                        }
                    } label: {
                        Label("More answers", systemImage: "ellipsis")
                    }
                }
            }
        }
        .safeAreaInset(edge: .bottom) {
            if let outcome {
                VStack(spacing: 0) {
                    DecisionOutcomeBar(outcome: outcome)
                    if model.needsConfirmation(for: question) {
                        Button("Check Again") { Task { await model.refresh() } }
                            .buttonStyle(.bordered)
                            .padding(.bottom, 8)
                    }
                }
            } else {
                actions(question, card, bar)
            }
        }
    }

    private func facts(_ question: RemoteQuestion, _ card: QuestionCard) -> some View {
        Section {
            ForEach(card.question.items) { item in
                LabeledContent("Credential") {
                    HStack(spacing: 6) {
                        Text(item.name).lineLimit(1)
                        if item.production {
                            DecisionTag(text: "Production", tint: .red)
                        }
                    }
                }
            }
            LabeledContent("Action", value: card.question.action.label)
            if let project = card.question.project {
                LabeledContent("Project", value: project.label)
            }
            LabeledContent("Environment", value: Decisions.environment(card.question.items))
            if !card.run.envNames.isEmpty {
                LabeledContent("Variables") {
                    Text(card.run.envNames.joined(separator: ", ")).font(.callout.monospaced())
                }
            }
            LabeledContent("Asked on", value: question.askerName)
            if model.namesVaults, let vault = question.vaultName {
                LabeledContent("Vault", value: vault)
            }
        }
    }

    private func labeled(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value)
        }
        .accessibilityElement(children: .combine)
    }

    /// The fixed bottom glass bar of the mockup.
    private func actions(_ question: RemoteQuestion, _ card: QuestionCard, _ bar: AnswerBar) -> some View {
        let busy = model.delivery(for: question) == .sending
        return DecisionBar {
            if case .failed(let message) = model.delivery(for: question) {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if let primary = bar.primary {
                Button { answer(primary, question) } label: {
                    Text(primary.label).lineLimit(1).frame(maxWidth: .infinity)
                }
                .decisionButton(primary.destructive ? .production : .primary)
            }
            HStack(spacing: 8) {
                Button(role: .destructive) { answer(bar.deny, question) } label: {
                    Text(bar.deny.label).frame(maxWidth: .infinity)
                }
                .decisionButton(.deny)
                if let once = bar.allowOnce {
                    Button { answer(once, question) } label: {
                        Text(once.label).frame(maxWidth: .infinity)
                    }
                    .decisionButton(.secondary)
                }
            }
            if busy {
                Text("Sending…").font(.caption).foregroundStyle(.secondary)
            } else if let note = AnswerBar.note(bar.primary, card) {
                Text(note).font(.caption).foregroundStyle(.secondary)
            }
        }
        .disabled(busy)
    }

    private func answer(_ choice: AnswerBar.Choice, _ question: RemoteQuestion) {
        guard tapGuard.accepts(now: Date()) else { return }
        Task { await model.send(choice, for: question) }
    }
}

#if DEBUG
    #Preview {
        let service = PreviewVaultService()
        let model = QuestionsModel(
            service: service, signers: TeamAnswerSigners(), push: nil, deviceName: "Test iPhone")
        NavigationStack {
            QuestionDetailView(model: model, requestIdentity: PreviewVaultService.sampleQuestion().requestIdentity)
        }
        .task {
            await service.setQuestions(enabled: true, questions: [PreviewVaultService.sampleQuestion()])
            await model.refresh()
        }
    }
#endif
