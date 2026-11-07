import ApassyCompanionKit
import ApassyVaultKit
import SwiftUI

/// A v1 relay question with the same owner choices as the Mac, or a connect request (card v2).
struct QuestionDetailView: View {
    let model: QuestionsModel
    let requestIdentity: String
    @State private var tapGuard = AnswerGuard()
    @State private var commentQuestion: RemoteQuestion?

    private var question: RemoteQuestion? { model.questions.first { $0.requestIdentity == requestIdentity }
        ?? model.receiptQuestions.first { $0.requestIdentity == requestIdentity } }

    var body: some View {
        Group {
            if let question, let connect = question.connect {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    ConnectRequestDetail(model: model, question: question, connect: connect, now: context.date)
                }
            } else if let question, let card = question.card {
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
        .sheet(item: $commentQuestion) { snapshot in
            DismissCommentSheet { answer in
                Task { await model.send(.init(answer: answer, label: "Dismiss with comment", destructive: true), for: snapshot) }
            }
        }
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
            // What the request is for comes before the command (owner, 2026-11-07: a raw
            // command alone does not say whether to allow it).
            if !card.run.purpose.isEmpty || !card.run.userRequest.isEmpty || showsAgentRequest(card) {
                Section("Requests") {
                    if !card.run.purpose.isEmpty { labeled("Purpose", card.run.purpose) }
                    if !card.run.userRequest.isEmpty { labeled("You asked", card.run.userRequest) }
                    if showsAgentRequest(card) { labeled("The agent says", card.run.agentRequest) }
                }
            }
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
        }
        .contentMargins(.bottom, 24, for: .scrollContent)
        // A tap meant for the list or a notification must not answer this question.
        .onAppear { tapGuard.arm(now: Date()) }
        .onChange(of: question.card) { _, _ in tapGuard.arm(now: Date()) }
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
                        if item.production && !item.unconfirmed {
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

    /// Some Macs copy the purpose into the agent request; the same text is shown once.
    private func showsAgentRequest(_ card: QuestionCard) -> Bool {
        !card.run.agentRequest.isEmpty && card.run.agentRequest != card.run.purpose
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
            if let note = bar.labelNote {
                Text(note)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
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
                if let secondary = bar.secondaryApproval {
                    Button { answer(secondary, question) } label: {
                        Text(secondary.label).frame(maxWidth: .infinity)
                    }
                    .decisionButton(.primary)
                }
            }
            ForEach(bar.menu) { choice in
                Button(choice.label, role: choice.destructive ? .destructive : nil) { answer(choice, question) }
                    .decisionButton(choice.destructive ? .deny : .primary)
            }
            if busy {
                Text("Sending…").font(.caption).foregroundStyle(.secondary)
            }
        }
        .disabled(busy)
    }

    private func answer(_ choice: AnswerBar.Choice, _ question: RemoteQuestion) {
        guard tapGuard.accepts(now: Date()) else { return }
        if choice.answer.kind == .denyWithComment {
            commentQuestion = question
            return
        }
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

/// A connect request (card v2 `kind = connect`), as in the mockup: "<name> wants to connect", the
/// Mac and the time left, the Code row, one warning line, and Deny / Allow (Face ID).
struct ConnectRequestDetail: View {
    let model: QuestionsModel
    let question: RemoteQuestion
    let connect: ConnectRequestCard
    let now: Date
    @State private var tapGuard = AnswerGuard()

    var body: some View {
        let outcome = model.outcome(for: question)
        List {
            Section {
                DecisionHeader(
                    agent: connect.clientName, sentence: "\(connect.clientName) wants to connect",
                    detail: connect.macName,
                    deadline: outcome == nil ? Date(timeIntervalSince1970: TimeInterval(question.expiresAt)) : nil)
            }
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 0, trailing: 16))
            Section {
                LabeledContent("Code") {
                    Text(connect.code).font(.title3.monospaced()).tracking(3).foregroundStyle(.primary)
                }
                .accessibilityIdentifier("connect.code")
            } footer: {
                Label(QuestionsModel.connectCodeWarning(code: connect.code), systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            // Where the code goes back (review 0.5.16); a program on a computer is a warning.
            if let returnsTo = connect.returnsTo {
                Section {
                    Label(
                        returnsTo,
                        systemImage: connect.localRedirect ? "exclamationmark.triangle" : "arrow.uturn.backward"
                    )
                    .foregroundStyle(connect.localRedirect ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                    .accessibilityIdentifier("connect.returnsTo")
                }
            }
            Section {
                LabeledContent("Asked on", value: question.askerName)
                if model.namesVaults, let vault = question.vaultName {
                    LabeledContent("Vault", value: vault)
                }
            }
        }
        .contentMargins(.bottom, 24, for: .scrollContent)
        .onAppear { tapGuard.arm(now: Date()) }
        .onChange(of: question.connect) { _, _ in tapGuard.arm(now: Date()) }
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
                actions
            }
        }
    }

    private var actions: some View {
        let busy = model.delivery(for: question) == .sending
        let enabled = model.canAnswerConnect(question, now: now)
        return DecisionBar {
            if case .failed(let message) = model.delivery(for: question) {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(spacing: 8) {
                Button(role: .destructive) { answer(allow: false) } label: {
                    Text("Deny").frame(maxWidth: .infinity)
                }
                .decisionButton(.deny)
                Button { answer(allow: true) } label: {
                    Label("Allow", systemImage: "faceid").frame(maxWidth: .infinity)
                }
                .decisionButton(.primary)
            }
            .disabled(!enabled)
            if busy {
                Text("Sending…").font(.caption).foregroundStyle(.secondary)
            }
        }
        .disabled(busy)
    }

    private func answer(allow: Bool) {
        guard tapGuard.accepts(now: Date()), model.canAnswerConnect(question, now: Date()) else { return }
        Task { await model.answerConnect(allow: allow, for: question) }
    }
}
