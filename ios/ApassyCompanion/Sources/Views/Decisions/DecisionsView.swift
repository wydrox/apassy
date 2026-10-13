import ApassyCompanionKit
import ApassyVaultKit
import SwiftUI

/// A screen pushed in Decisions. A request from an agent (mockup screen 8) gets its own case once
/// the Mac sends requests to the iPhone.
enum DecisionRoute: Hashable {
    /// A question through the relay, by its qid.
    case question(String)
    /// A run of the Mac on this Wi-Fi, as the owner opened it: the detail keeps that version.
    case run(PendingRun)

    func hash(into hasher: inout Hasher) {
        switch self {
        case .question(let qid): hasher.combine("question-\(qid)")
        case .run(let run): hasher.combine("run-\(run.id)-\(run.digest)")
        }
    }
}

/// Decisions (ADR 0026 §8, mockup screen 5): what blocks an agent now, with a timer, then the
/// requests and the suggestions. Questions through the relay and the runs of the Mac on this Wi-Fi
/// are one list. Requests and suggestions live in the Mac's vault and do not reach the iPhone yet,
/// so their sections say so and show nothing else.
struct DecisionsView: View {
    @Environment(RootModel.self) private var root: RootModel?
    let questions: QuestionsModel?
    let companion: AppModel
    var onSettings: (() -> Void)?
    @State private var path: [DecisionRoute] = []
    @State private var showsConnect = false
    @State private var showsMac = false

    private var session: SessionModel? {
        if case .paired(let session) = companion.phase { return session }
        return nil
    }

    /// Whether a pushed screen shows something that still waits for an answer.
    private func opensWaiting(_ route: DecisionRoute, questions: QuestionsModel) -> Bool {
        switch route {
        case .question(let qid): questions.waiting.contains { $0.qid == qid }
        case .run(let run): session?.runs.contains { $0.id == run.id } ?? false
        }
    }

    var body: some View {
        NavigationStack(path: $path) {
            // Each second: the timers, and the rows that expire leave Waiting.
            TimelineView(.periodic(from: .now, by: 1)) { context in
                list(now: context.date)
            }
            .navigationTitle("Decisions")
            .toolbar { toolbar }
            .navigationDestination(for: DecisionRoute.self) { route in
                switch route {
                case .question(let qid):
                    // A new view for each question, so that its tap guard starts again.
                    if let questions { QuestionDetailView(model: questions, qid: qid).id(qid) }
                case .run(let run):
                    if let session {
                        RunDetailView(session: session, run: run, presentation: .pushed)
                    } else {
                        ContentUnavailableView("This run no longer waits", systemImage: "clock")
                    }
                }
            }
        }
        .sheet(isPresented: $showsConnect, onDismiss: {
            let opensCompanion = questions?.attach == .companion
            questions?.dismissAttach()
            if opensCompanion { root?.openPreparedCompanion() }
        }) {
            if let questions { ConnectQuestionsView(model: questions) }
        }
        .sheet(isPresented: $showsMac) {
            ApprovalsView(app: companion)
                .presentationDragIndicator(.visible)
        }
        // The owner opened a notification: it holds no question, so open the newest one. Only on
        // a free screen: never when the owner opened something while the list was read again, and
        // never over a question or a run that still waits, which the owner may be about to answer.
        .onChange(of: questions?.focusRequests ?? 0, initial: true) { _, requests in
            guard requests > 0, let questions else { return }
            let before = path
            Task {
                let qid = await questions.takeFocus(stillFree: {
                    path == before && !path.contains { opensWaiting($0, questions: questions) }
                })
                if let qid { path = [.question(qid)] }
            }
        }
        .alert(
            "Apassy could not finish",
            isPresented: Binding(
                get: { session?.actionError != nil },
                set: { if !$0 { session?.actionError = nil } })
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(session?.actionError ?? "")
        }
    }

    // MARK: The list

    private func list(now: Date) -> some View {
        let waiting = Decisions.waiting(questions: questions?.questions ?? [], session: session, now: now)
        let ended = (questions?.questions ?? []).filter { question in
            !waiting.contains { $0.id == "question-\(question.qid)" }
        }
        return List {
            Section("Waiting") {
                ForEach(waiting) { decision in
                    NavigationLink(value: route(decision)) {
                        WaitingRow(decision: decision, now: now)
                    }
                }
                if waiting.isEmpty { emptyWaiting }
                if let session, session.state != .connected, !session.runs.isEmpty {
                    Text("\(session.macName) does not answer. Its runs are the last known.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            Section("Requests") {
                ForEach(session?.accessRequests ?? []) { request in
                    AccessRequestRow(request: request, isDenying: session?.denying.contains(request.id) == true) {
                        Task { await session?.deny(request) }
                    }
                }
                if let session {
                    if session.accessRequests.isEmpty {
                        Text("No requests").font(.subheadline).foregroundStyle(.secondary)
                    }
                } else {
                    macOnly
                }
            }
            Section("Suggestions") { macOnly }
            if !ended.isEmpty, let questions {
                Section("Ended") {
                    ForEach(ended) { question in
                        NavigationLink(value: DecisionRoute.question(question.qid)) {
                            EndedRow(model: questions, question: question)
                        }
                    }
                }
            }
            notices
        }
        .refreshable {
            await questions?.refresh()
            await session?.refresh()
        }
    }

    private func route(_ decision: WaitingDecision) -> DecisionRoute {
        switch decision.source {
        case .question(let question): .question(question.qid)
        case .run(let run): .run(run)
        }
    }

    private var macOnly: some View {
        Text("Available when the Mac is connected")
            .font(.subheadline)
            .foregroundStyle(.secondary)
    }

    /// Nothing waits: why, and the way to connect this iPhone when the questions are not set up.
    @ViewBuilder
    private var emptyWaiting: some View {
        switch questions?.phase {
        case .loading where session?.runs.isEmpty ?? true:
            ProgressView().frame(maxWidth: .infinity)
        case .failed(let message):
            VStack(alignment: .leading, spacing: 8) {
                Label("Apassy cannot read the questions", systemImage: "exclamationmark.triangle")
                    .font(.headline)
                Text(message).font(.subheadline).foregroundStyle(.secondary)
                Button("Try again") { Task { await questions?.refresh() } }
                    .buttonStyle(.bordered)
            }
            .padding(.vertical, 4)
        case .off:
            VStack(alignment: .leading, spacing: 8) {
                Label("Nothing waits", systemImage: "checkmark.circle")
                    .font(.headline)
                Text(
                    "To answer agents on this iPhone, open Apassy on your Mac, choose Settings > Devices > Notifications through the relay, add an iPhone, and scan the code here."
                )
                .font(.subheadline)
                .foregroundStyle(.secondary)
                Button("Connect this iPhone") { showsConnect = true }
                    .buttonStyle(.borderedProminent)
            }
            .padding(.vertical, 4)
        default:
            VStack(alignment: .leading, spacing: 4) {
                Label("Nothing waits", systemImage: "checkmark.circle")
                    .font(.headline)
                Text("When an agent asks, the question shows here with the time left.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 4)
        }
    }

    @ViewBuilder
    private var notices: some View {
        if let questions {
            if let notice = questions.notice {
                Section { Text(notice).font(.footnote).foregroundStyle(.secondary) }
            }
            if questions.phase == .ready, !questions.status.hasKey {
                Section {
                    Text("This vault has no question key yet. Sync it with your Mac to read its questions.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: Toolbar

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        if let onSettings {
            ToolbarItem(placement: .topBarLeading) {
                Button(action: onSettings) {
                    Label("Settings", systemImage: "gearshape")
                }
            }
        }
        ToolbarItem(placement: .topBarTrailing) {
            Menu {
                if let questions {
                    switch questions.phase {
                    case .ready:
                        Section {
                            Toggle(
                                "Notifications",
                                isOn: Binding(
                                    get: { questions.notificationsOn },
                                    set: { on in Task { await questions.setNotifications(on) } }))
                        } footer: {
                            Text("A notification says only \u{201C}A question is waiting\u{201D}. Apple sees no question.")
                        }
                    case .off, .failed:
                        Button("Connect this iPhone", systemImage: "qrcode.viewfinder") { showsConnect = true }
                    case .loading:
                        EmptyView()
                    }
                }
                Button(session.map { "\($0.macName) on Wi-Fi" } ?? "Mac on Wi-Fi", systemImage: "wifi") {
                    showsMac = true
                }
            } label: {
                Label("Devices", systemImage: "ellipsis")
            }
        }
    }
}

/// One row of Waiting (mockup screen 5): the agent, the credential, the project, a red dot for
/// production, and the time left.
private struct WaitingRow: View {
    let decision: WaitingDecision
    let now: Date

    var body: some View {
        HStack(spacing: 12) {
            AgentAvatar(agent: decision.agent)
            VStack(alignment: .leading, spacing: 2) {
                Text(decision.title).lineLimit(1)
                Text(decision.subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 8)
            if decision.production {
                Circle().fill(.red).frame(width: 8, height: 8)
                    .accessibilityLabel("Production")
            }
            if let left = decision.secondsLeft(now: now) {
                Text(Decisions.clock(left))
                    .font(.subheadline.weight(.medium).monospacedDigit())
                    .foregroundStyle(.orange)
                    .accessibilityLabel("\(left) seconds left")
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// A question that ended: who answered, or that it expired.
private struct EndedRow: View {
    let model: QuestionsModel
    let question: RemoteQuestion

    var body: some View {
        let agent = AgentName.display(question.card?.run.agent ?? question.askerName)
        HStack(spacing: 12) {
            AgentAvatar(agent: agent)
                .opacity(0.5)
            VStack(alignment: .leading, spacing: 2) {
                Text(question.credentialTitle).lineLimit(1)
                Text(model.deliveryText(for: question) ?? agent)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
    #Preview {
        let service = PreviewVaultService()
        let model = QuestionsModel(
            service: service, signer: EnclaveAnswerSigner(), push: nil, deviceName: "Test iPhone")
        DecisionsView(questions: model, companion: AppModel())
            .task {
                await service.setQuestions(enabled: true, questions: DecisionsPreview.questions())
                await model.refresh()
            }
    }
#endif
