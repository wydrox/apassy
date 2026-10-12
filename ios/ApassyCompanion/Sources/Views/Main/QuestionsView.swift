import ApassyVaultKit
import SwiftUI

/// Questions through the relay (contract relay-questions-v1), as the "Decisions" list of the iOS
/// mockup (docs/design/ios-v1-mockup.html): what waits, with a timer, then what ended. A question
/// opens in `QuestionDetailView`. The view is self-contained, with its own navigation stack, so the
/// navigation rewrite can move it into a Decisions tab.
///
/// Requests and suggestions of the mockup are not in contract relay-questions-v1: the relay
/// carries only waiting runs. "Development or production?" is an answer of the question itself.
struct QuestionsView: View {
    let model: QuestionsModel
    var onSettings: (() -> Void)?
    @State private var showsConnect = false

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Decisions")
                .toolbar {
                    if let onSettings {
                        ToolbarItem(placement: .topBarLeading) {
                            Button(action: onSettings) {
                                Label("Settings", systemImage: "gearshape")
                            }
                        }
                    }
                }
                .navigationDestination(for: String.self) { qid in
                    QuestionDetailView(model: model, qid: qid)
                }
        }
        .sheet(isPresented: $showsConnect, onDismiss: { model.dismissAttach() }) {
            ConnectQuestionsView(model: model)
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .loading:
            ProgressView()
        case .failed(let message):
            ContentUnavailableView {
                Label("Apassy cannot read the questions", systemImage: "exclamationmark.triangle")
            } description: {
                Text(message)
            } actions: {
                Button("Try again") { Task { await model.refresh() } }
                    .buttonStyle(.borderedProminent)
            }
        case .off:
            ContentUnavailableView {
                Label("No questions here yet", systemImage: "questionmark.bubble")
            } description: {
                Text(
                    "Agents ask before they use a credential. To answer on this iPhone, open Apassy on your Mac, choose Settings > Devices > Notifications through the relay, add an iPhone, and scan the code here."
                )
            } actions: {
                Button("Connect this iPhone") { showsConnect = true }
                    .buttonStyle(.borderedProminent)
            }
        case .ready:
            list
        }
    }

    private var list: some View {
        let waiting = model.waiting
        let ended = model.questions.filter { question in !waiting.contains { $0.qid == question.qid } }
        return List {
            Section("Waiting") {
                if waiting.isEmpty {
                    Text("Nothing waits. When an agent asks on your Mac, the question shows here.")
                        .foregroundStyle(.secondary)
                }
                ForEach(waiting) { question in
                    NavigationLink(value: question.qid) { QuestionRow(model: model, question: question) }
                }
            }
            if !ended.isEmpty {
                Section("Ended") {
                    ForEach(ended) { question in
                        QuestionRow(model: model, question: question)
                    }
                }
            }
            Section {
                Toggle(
                    "Notifications",
                    isOn: Binding(
                        get: { model.notificationsOn },
                        set: { on in Task { await model.setNotifications(on) } }))
            } header: {
                Text("On this iPhone")
            } footer: {
                Text("A notification says only \u{201C}A question is waiting\u{201D}. Apple sees no question.")
            }
            if let notice = model.notice {
                Section { Text(notice).font(.footnote).foregroundStyle(.secondary) }
            }
            if !model.status.hasKey {
                Section {
                    Text("This vault has no question key yet. Sync it with your Mac to read its questions.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
        .refreshable { await model.refresh() }
    }
}

/// "4:52": minutes and seconds left, rounded up (as `clock` on the Mac).
func questionClock(expiresAt: Int64, now: Date) -> String {
    let left = max(0, Double(expiresAt) - now.timeIntervalSince1970)
    let seconds = Int(left.rounded(.up))
    return "\(seconds / 60):" + String(format: "%02d", seconds % 60)
}

extension RemoteQuestion {
    /// The credential of the row: the first item, and how many more.
    var credentialTitle: String {
        guard let items = card?.question.items, let first = items.first else { return "A question" }
        return items.count > 1 ? "\(first.name) +\(items.count - 1)" : first.name
    }

    /// "Claude Code · acme-billing".
    var agentLine: String {
        guard let card else { return "Asked on \(askerName)" }
        return [card.run.agent, card.question.project?.label].compactMap { $0 }.joined(separator: " · ")
    }
}

/// One row: the credential, the agent and the project, and the timer of a waiting question.
private struct QuestionRow: View {
    let model: QuestionsModel
    let question: RemoteQuestion

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(question.credentialTitle).font(.headline)
                Text(question.agentLine).font(.subheadline).foregroundStyle(.secondary)
                if let line = model.deliveryText(for: question) {
                    Text(line).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if question.state == .open {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    Text(questionClock(expiresAt: question.expiresAt, now: context.date))
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// A question as the mockup's "Decision": who wants what, the grouped facts, the command, why the
/// owner is asked, and a fixed bottom glass bar: the main answer, then Deny and Allow Once. "⋯"
/// holds the agent exceptions and the environment of a credential. Allowing asks for Face ID;
/// denying does not.
struct QuestionDetailView: View {
    let model: QuestionsModel
    let qid: String

    private var question: RemoteQuestion? { model.questions.first { $0.qid == qid } }

    var body: some View {
        Group {
            if let question, let card = question.card {
                let bar = AnswerBar.make(for: card)
                List {
                    header(question, card)
                    facts(question, card)
                    Section("Command") {
                        Text(card.run.command.joined(separator: " "))
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                        Text(card.run.cwd).font(.caption.monospaced()).foregroundStyle(.secondary)
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
                            if !card.run.agentRequest.isEmpty { labeled("The agent asked", card.run.agentRequest) }
                        }
                    }
                }
                .toolbar {
                    if question.state == .open, !bar.menu.isEmpty {
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
                    if question.state == .open {
                        actions(question, card, bar)
                    }
                }
            } else if let question {
                ContentUnavailableView(
                    "This question could not be read", systemImage: "lock.trianglebadge.exclamationmark",
                    description: Text(question.problem ?? "Expired."))
            } else {
                ContentUnavailableView("Expired", systemImage: "clock")
            }
        }
        .navigationBarTitleDisplayMode(.inline)
    }

    private func header(_ question: RemoteQuestion, _ card: QuestionCard) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 6) {
                Text("\(card.run.agent) wants to use \(question.credentialTitle)")
                    .font(.title2.bold())
                HStack(spacing: 4) {
                    if let project = card.question.project { Text("\(project.label) ·") }
                    if question.state == .open {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            Text("\(questionClock(expiresAt: question.expiresAt, now: context.date)) left")
                                .monospacedDigit()
                        }
                    }
                }
                .font(.subheadline)
                .foregroundStyle(.secondary)
                if let line = model.deliveryText(for: question) {
                    Text(line).font(.callout.bold())
                }
            }
            .listRowBackground(Color.clear)
        }
    }

    private func facts(_ question: RemoteQuestion, _ card: QuestionCard) -> some View {
        Section {
            ForEach(card.question.items) { item in
                LabeledContent("Credential") {
                    HStack(spacing: 6) {
                        Text(item.name)
                        if item.production {
                            Text("Production")
                                .font(.caption.bold())
                                .foregroundStyle(.red)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(.red.opacity(0.12), in: Capsule())
                        } else if item.unconfirmed {
                            Text("Production?")
                                .font(.caption.bold())
                                .foregroundStyle(.orange)
                        }
                    }
                }
            }
            LabeledContent("Action", value: card.question.action.label)
            if !card.run.envNames.isEmpty {
                LabeledContent("Variables", value: card.run.envNames.joined(separator: ", "))
            }
            LabeledContent("Asked on", value: question.askerName)
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
        let busy = model.deliveries[question.qid] == .sending
        return VStack(spacing: 8) {
            if let primary = bar.primary {
                Button { answer(primary, question) } label: {
                    Text(primary.label).frame(maxWidth: .infinity, minHeight: 34)
                }
                .buttonStyle(.glassProminent)
            }
            HStack(spacing: 8) {
                Button(role: .destructive) { answer(bar.deny, question) } label: {
                    Text(bar.deny.label).frame(maxWidth: .infinity, minHeight: 34)
                }
                .buttonStyle(.glass)
                if let once = bar.allowOnce {
                    Button { answer(once, question) } label: {
                        Text(once.label).frame(maxWidth: .infinity, minHeight: 34)
                    }
                    .buttonStyle(.glass)
                }
            }
            if let note = Self.note(bar.primary, card) {
                Text(note).font(.caption).foregroundStyle(.secondary)
            }
        }
        .disabled(busy)
        .padding(12)
        .glassEffect(in: .rect(cornerRadius: 32))
        .padding(.horizontal, 12)
    }

    /// The line under the bar: what the main answer remembers.
    static func note(_ primary: AnswerBar.Choice?, _ card: QuestionCard) -> String? {
        guard let primary, let project = card.question.project?.label else { return nil }
        switch primary.answer.kind {
        case .approveInProject, .allowProduction: return "Remembered for all agents in \(project)"
        case .correctEnvironment: return "Remembered for this credential"
        default: return nil
        }
    }

    private func answer(_ choice: AnswerBar.Choice, _ question: RemoteQuestion) {
        Task { await model.send(choice, for: question) }
    }
}

/// Connect a vault from iCloud Drive to its notifications team: the link of the Mac, the two
/// safety words while the Mac confirms, then done.
private struct ConnectQuestionsView: View {
    let model: QuestionsModel
    @State private var link = ""
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                switch model.attach {
                case nil, .failed:
                    Section {
                        CodeScannerPanel(
                            accessibilityLabel: "Camera for the device link", use: "to read the link of your Mac"
                        ) { code in
                            link = code
                            Task { await model.startAttach(link: code) }
                        }
                        .frame(minHeight: 240)
                        TextField("Or paste the link", text: $link, axis: .vertical)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button("Connect") { Task { await model.startAttach(link: link) } }
                            .disabled(!QuestionsModel.isLink(link))
                    } footer: {
                        if case .failed(let message) = model.attach {
                            Text(message).foregroundStyle(.red)
                        } else {
                            Text("On your Mac: Settings > Devices > Notifications through the relay > Add an iPhone.")
                        }
                    }
                case .starting:
                    Section { ProgressView("Connecting…") }
                case .waiting(let info):
                    Section {
                        Text(info.words.joined(separator: " "))
                            .font(.largeTitle.bold())
                            .frame(maxWidth: .infinity)
                    } header: {
                        Text("Your Mac shows these words")
                    } footer: {
                        Text(
                            "Confirm on the Mac only when it shows the same two words. Then this iPhone gets the questions of \(info.team)."
                        )
                    }
                case .attached:
                    Section {
                        Label("Connected. The questions of this vault show here.", systemImage: "checkmark.circle")
                    }
                }
            }
            .navigationTitle("Connect this iPhone")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if model.attach == .attached {
                        Button("Done") { dismiss() }
                    } else {
                        Button("Cancel") {
                            model.cancelAttach()
                            dismiss()
                        }
                    }
                }
            }
        }
    }
}

extension View {
    /// Read the questions and wait for new ones while the app is not in the background.
    func questionsPolling(_ model: QuestionsModel?) -> some View {
        modifier(QuestionsPolling(model: model))
    }
}

private struct QuestionsPolling: ViewModifier {
    let model: QuestionsModel?
    @Environment(\.scenePhase) private var scenePhase

    func body(content: Content) -> some View {
        content
            .task(id: CoverPolicy.polls(in: AppPhase(scenePhase))) {
                if CoverPolicy.polls(in: AppPhase(scenePhase)), let model { await model.watch() }
            }
    }
}

/// The Approvals tab of the vault until the navigation rewrite: the questions through the relay,
/// and the companion that approves the runs of a Mac on this Wi-Fi (ADR 0020). The tabs stay as
/// they are.
struct ApprovalsHub: View {
    enum Source: String, CaseIterable, Identifiable {
        case questions
        case companion

        var id: String { rawValue }

        var label: String {
            switch self {
            case .questions: "Questions"
            case .companion: "Mac on Wi-Fi"
            }
        }
    }

    let questions: QuestionsModel?
    let companion: AppModel
    var onSettings: (() -> Void)?
    @Binding var source: Source

    var body: some View {
        Group {
            switch source {
            case .questions:
                if let questions {
                    QuestionsView(model: questions, onSettings: onSettings)
                } else {
                    ProgressView()
                }
            case .companion:
                ApprovalsView(app: companion, onSettings: onSettings)
            }
        }
        .safeAreaInset(edge: .top, spacing: 0) {
            Picker("Approvals", selection: $source) {
                ForEach(Source.allCases) { source in
                    Text(source.label).tag(source)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 16)
            .padding(.vertical, 4)
        }
    }
}

#if DEBUG
    #Preview {
        let service = PreviewVaultService()
        let model = QuestionsModel(
            service: service, signer: EnclaveAnswerSigner(), push: nil, deviceName: "Test iPhone")
        QuestionsView(model: model)
            .task {
                await service.setQuestions(enabled: true, questions: [PreviewVaultService.sampleQuestion()])
                await model.refresh()
            }
    }
#endif
