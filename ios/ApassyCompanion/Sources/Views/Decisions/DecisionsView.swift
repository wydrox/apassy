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
/// are one list. Suggestions live in the Mac's vault and do not reach the iPhone yet, and requests
/// come only from a Mac paired on Wi-Fi, so their sections say where they are (`AgentsReach`). A
/// vault whose questions are not open shows one row with Unlock.
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
        // The passphrase of a locked vault, for its questions only: the vault on screen stays.
        .sheet(
            item: Binding(get: { questions?.unlockPrompt }, set: { questions?.unlockPrompt = $0 }),
            onDismiss: { questions?.unlockPromptClosed() }
        ) { locked in
            if let questions { QuestionsUnlockSheet(model: questions, locked: locked) }
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
        let waiting = Decisions.waiting(
            questions: questions?.questions ?? [], session: session, namesVaults: questions?.namesVaults ?? false,
            now: now)
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
                if let questions, questions.phase != .locked {
                    let stored = questions.faceIDLocked
                    if !stored.isEmpty {
                        FaceIDLockedRow(
                            vaults: stored, opening: stored.contains { questions.opening.contains($0.id) }
                        ) {
                            Task { await questions.unlockFaceIDTapped() }
                        }
                    }
                    ForEach(questions.passphraseLocked) { locked in
                        LockedVaultRow(locked: locked, opening: questions.opening.contains(locked.id)) {
                            Task { await questions.unlockTapped(locked) }
                        }
                    }
                }
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
                    macPlace(.requests)
                }
            }
            Section("Suggestions") { macPlace(.suggestions) }
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

    /// A part of the Mac's vault that does not reach this iPhone: where it is, and the one action.
    private func macPlace(_ place: AgentsReach.Place) -> some View {
        let reach = AgentsReach(questions: questions, companion: companion)
        return MacPlaceRow(note: reach.note(place), action: reach.action(place)) { action in
            switch action {
            case .pairOnWiFi: showsMac = true
            case .connect: showsConnect = true
            case .openDecisions: break
            }
        }
    }

    /// Nothing waits: why, and the way to connect this iPhone when the questions are not set up.
    @ViewBuilder
    private var emptyWaiting: some View {
        switch questions?.phase {
        case .loading where session?.runs.isEmpty ?? true:
            ProgressView().frame(maxWidth: .infinity)
        case .locked:
            VStack(alignment: .leading, spacing: 4) {
                Label("The vault is locked", systemImage: "lock")
                    .font(.headline)
                Text("Unlock it to read and answer the questions of your agents.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 4)
        case .failed(let message):
            VStack(alignment: .leading, spacing: 8) {
                Label("Apassy cannot read the questions", systemImage: "exclamationmark.triangle")
                    .font(.headline)
                Text(message).font(.subheadline).foregroundStyle(.secondary)
                Button("Try again") { Task { await questions?.refresh() } }
                    .buttonStyle(.bordered)
            }
            .padding(.vertical, 4)
        case .off where questions?.lockedVaults.isEmpty ?? true:
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
            if let pending = questions.notificationsPendingText {
                Section { Text(pending).font(.footnote).foregroundStyle(.secondary) }
            }
            if questions.phase == .ready {
                ForEach(questions.contexts.filter { $0.status.enabled && !$0.status.hasKey }) { vault in
                    Section {
                        Text(
                            questions.namesVaults
                                ? "\(vault.vaultName) has no question key yet. Sync it with your Mac to read its questions."
                                : "This vault has no question key yet. Sync it with your Mac to read its questions."
                        )
                        .font(.footnote).foregroundStyle(.secondary)
                    }
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
                    if questions.phase == .ready {
                        Section {
                            Toggle(
                                "Notifications",
                                isOn: Binding(
                                    get: { questions.notificationsOn },
                                    set: { on in Task { await questions.setNotifications(on) } }))
                        } footer: {
                            Text("A notification says only \u{201C}A question is waiting\u{201D}. Apple sees no question.")
                        }
                    }
                    if questions.canConnect {
                        Button("Connect this iPhone", systemImage: "qrcode.viewfinder") { showsConnect = true }
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
                if let vault = decision.vault {
                    Text(vault)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
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

/// A vault whose questions are not open now and whose passphrase is not stored behind Face ID (or
/// did not open it): one row with Unlock, which shows the passphrase sheet.
private struct LockedVaultRow: View {
    let locked: LockedVault
    let opening: Bool
    let unlock: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.fill")
                .foregroundStyle(.secondary)
                .frame(width: 36)
                .accessibilityHidden(true)
            Text(locked.text)
                .font(.subheadline)
            Spacer(minLength: 8)
            if opening {
                ProgressView()
                    .accessibilityLabel("Opening \(locked.name)")
            } else {
                Button("Unlock", action: unlock)
                    .buttonStyle(.bordered)
                    .accessibilityLabel("Unlock \(locked.name)")
            }
        }
        .padding(.vertical, 2)
    }
}

/// The locked vaults whose passphrase is stored behind Face ID: one row, and one Face ID opens the
/// questions of them all. Face ID never asks by itself after a return to the app.
private struct FaceIDLockedRow: View {
    let vaults: [LockedVault]
    let opening: Bool
    let unlock: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "faceid")
                .foregroundStyle(.secondary)
                .frame(width: 36)
                .accessibilityHidden(true)
            Text(LockedVault.faceIDText(vaults))
                .font(.subheadline)
            Spacer(minLength: 8)
            if opening {
                ProgressView()
                    .accessibilityLabel("Opening the locked vaults")
            } else {
                Button("Unlock", action: unlock)
                    .buttonStyle(.bordered)
                    .accessibilityLabel("Unlock with Face ID")
            }
        }
        .padding(.vertical, 2)
    }
}

/// The passphrase of a locked vault, to read its questions. The core opens the vault, reads what
/// the questions need, and closes it again: the vault on screen does not change. The field is
/// cleared when the app leaves the screen and when the sheet closes.
struct QuestionsUnlockSheet: View {
    let model: QuestionsModel
    let locked: LockedVault
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.dismiss) private var dismiss
    @State private var passphrase = ""
    @State private var message: String?
    @FocusState private var focused: Bool

    private var working: Bool { model.opening.contains(locked.id) }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Passphrase", text: $passphrase)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.go)
                        .focused($focused)
                        .onSubmit(unlock)
                        .disabled(working)
                } header: {
                    Text("Passphrase of “\(locked.name)”")
                } footer: {
                    if let message {
                        Text(message).foregroundStyle(.red)
                    } else {
                        Text("Apassy opens the questions of “\(locked.name)” only. The vault on screen stays as it is.")
                    }
                }
            }
            .navigationTitle("Unlock “\(locked.name)”")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        passphrase = ""
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if working {
                        ProgressView()
                    } else {
                        Button("Unlock", action: unlock)
                            .disabled(passphrase.isEmpty)
                    }
                }
            }
        }
        .presentationDetents([.medium])
        .onAppear { focused = true }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { passphrase = "" }
        }
        .onDisappear { passphrase = "" }
    }

    private func unlock() {
        let typed = passphrase
        guard !typed.isEmpty else { return }
        passphrase = ""
        message = nil
        Task { message = await model.unlockQuestions(locked, passphrase: typed) }
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
            service: service, signers: TeamAnswerSigners(), push: nil, deviceName: "Test iPhone")
        DecisionsView(questions: model, companion: AppModel())
            .task {
                await service.setQuestions(enabled: true, questions: DecisionsPreview.questions())
                await model.refresh()
            }
    }
#endif
