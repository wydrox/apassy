import ApassyCompanionKit
import ApassyVaultKit
import SwiftUI

/// Source-qualified navigation in Requests.
enum DecisionRoute: Hashable {
    /// A question through the relay, by its vault-qualified request identity.
    case question(String)
    case history(String)
    /// A run of the Mac on this Wi-Fi, as the owner opened it: the detail keeps that version.
    case run(sourceID: String, run: PendingRun)

    func hash(into hasher: inout Hasher) {
        switch self {
        case .question(let qid): hasher.combine("question-\(qid)")
        case .history(let id): hasher.combine("history-\(id)")
        case .run(let sourceID, let run): hasher.combine("run-\(sourceID)-\(run.id)-\(run.digest)")
        }
    }
}

/// Native Waiting / History destinations share the existing Requests navigation and pairing flows.
struct DecisionsView: View {
    @Environment(RootModel.self) private var root: RootModel?
    @Environment(\.scenePhase) private var scenePhase
    let questions: QuestionsModel?
    let companion: AppModel
    var onSettings: (() -> Void)?
    /// Parent tab selection and sheet presentation/dismissal gate.
    var isPresented = false
    @State private var path: [DecisionRoute] = []
    @State private var showsConnect = false
    @State private var showsMac = false
    @State private var localSheetPresented = false
    @State private var destination = Destination.waiting
    @State private var historyQuery = ""
    @State private var historyFilter = RequestHistoryPresentation.Filter.all
    @State private var heldRuns: [String: PendingRun] = [:]
    @State private var heldAccess: [String: AccessRequest] = [:]
    @State private var heldRunDates: [String: Date] = [:]
    @State private var runReceipts: [String: RequestsLocalReceipt] = [:]
    @State private var accessReceipts: [String: RequestsLocalReceipt] = [:]

    private enum Destination: String, CaseIterable, Identifiable {
        case waiting = "Waiting", history = "History"
        var id: Self { self }
    }

    private var session: SessionModel? {
        if case .paired(let session) = companion.phase { return session }
        return nil
    }

    private var requestsListVisible: Bool {
        scenePhase == .active && destination == .waiting && path.isEmpty && !showsConnect && !showsMac && !localSheetPresented
            && questions?.unlockPrompt == nil && session?.actionError == nil
    }

    var body: some View {
        NavigationStack(path: $path) {
            VStack(spacing: 0) {
                Picker("Requests view", selection: $destination) {
                    ForEach(Destination.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("requests.destination")
                .padding(.horizontal)
                .padding(.vertical, 8)
                if destination == .waiting {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        list(now: context.date)
                    }
                } else if let questions {
                    RequestsHistoryView(model: questions, query: $historyQuery, filter: $historyFilter)
                } else {
                    RequestsList {
                        ContentUnavailableView("History unavailable", systemImage: "lock")
                            .listRowBackground(Color.clear)
                    }
                }
            }
            .navigationTitle("Requests")
            .navigationBarTitleDisplayMode(.large)
            .toolbar { toolbar }
            .navigationDestination(for: DecisionRoute.self) { route in
                switch route {
                case .question(let identity):
                    if let questions { QuestionDetailView(model: questions, requestIdentity: identity).id(identity) }
                case .history(let id):
                    if let questions { RequestHistoryDetailView(model: questions, entryID: id) }
                case .run(let sourceID, let run):
                    if let session, session.requestSourceID == sourceID {
                        RunDetailView(session: session, run: run, presentation: .pushed)
                    } else {
                        ContentUnavailableView("This run no longer waits", systemImage: "clock")
                    }
                }
            }
        }
        .sheet(isPresented: $showsConnect, onDismiss: {
            localSheetPresented = false
            let opensCompanion = questions?.attach == .companion
            questions?.dismissAttach()
            if opensCompanion { root?.openPreparedCompanion() }
        }) {
            if let questions {
                ConnectQuestionsView(model: questions)
                    .onAppear { localSheetPresented = true }
            }
        }
        .sheet(isPresented: $showsMac, onDismiss: { localSheetPresented = false }) {
            ApprovalsView(app: companion)
                .presentationDragIndicator(.visible)
                .onAppear { localSheetPresented = true }
        }
        // The passphrase of a locked vault, for its questions only: the vault on screen stays.
        .sheet(
            item: Binding(get: { questions?.unlockPrompt }, set: { questions?.unlockPrompt = $0 }),
            onDismiss: {
                localSheetPresented = false
                questions?.unlockPromptClosed()
            }
        ) { locked in
            if let questions {
                QuestionsUnlockSheet(model: questions, locked: locked)
                    .onAppear { localSheetPresented = true }
            }
        }
        .onAppear {
            questions?.setRequestsPresented(isPresented)
            questions?.setRequestsVisible(requestsListVisible)
        }
        .onDisappear { questions?.setRequestsVisible(false) }
        .onChange(of: isPresented, initial: true) { _, presented in
            questions?.setRequestsPresented(presented)
        }
        .onChange(of: requestsListVisible) { _, visible in questions?.setRequestsVisible(visible) }
        // A generic push identifies no request. Return to the list and refresh it; picking a
        // newer request could make an old alert appear to authorize something unrelated.
        .onChange(of: questions?.focusRequests ?? 0, initial: true) { _, requests in
            guard requests > 0, let questions else { return }
            path = []
            destination = .waiting
            Task { _ = await questions.takeFocus(stillFree: { true }) }
        }
        .onChange(of: questions?.phase) { _, phase in
            if phase == .locked { historyQuery = "" }
        }
        .onChange(of: session?.requestSourceID) { _, _ in
            path = []
            heldRuns.removeAll()
            heldAccess.removeAll()
            heldRunDates.removeAll()
            runReceipts.removeAll()
            accessReceipts.removeAll()
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
        let waiting = waitingRows(now: now)
        let access = accessRows
        let hasUnavailableVaults = questions?.contexts.contains { $0.error != nil } ?? false
        return RequestsList {
            if waiting.isEmpty && access.isEmpty && (questions?.lockedVaults.isEmpty ?? true) && !hasUnavailableVaults {
                emptyWaiting
                    .listRowBackground(Color.clear)
            }
            Section {
                ForEach(waiting) { decision in
                    switch decision.source {
                    case .question(let question):
                        if let questions {
                            RequestsWaitingRow(model: questions, question: question, now: now)
                        }
                    case .run(let run):
                        if let session {
                            let receiptKey = "\(session.requestSourceID):run:\(run.id):\(run.digest)"
                            RequestsRunRow(session: session, run: run, now: now,
                                hold: {
                                    heldRuns[run.id] = run
                                    heldRunDates[run.id] = decision.createdAt
                                },
                                dismissReceipt: {
                                    heldRuns[run.id] = nil
                                    heldRunDates[run.id] = nil
                                    runReceipts[receiptKey] = nil
                                },
                                receipt: Binding(get: { runReceipts[receiptKey] ?? .idle },
                                    set: { value in
                                        guard self.session?.requestSourceID == session.requestSourceID else { return }
                                        runReceipts[receiptKey] = value
                                    }))
                                .id("\(session.requestSourceID):\(run.id):\(run.digest)")
                        }
                    }
                }
                if let session {
                    ForEach(access) { request in
                        let receiptKey = "\(session.requestSourceID):access:\(request.id)"
                        RequestsAccessRow(session: session, request: request,
                            hold: { heldAccess[request.id] = request },
                            dismissReceipt: {
                                heldAccess[request.id] = nil
                                accessReceipts[receiptKey] = nil
                            },
                            receipt: Binding(get: { accessReceipts[receiptKey] ?? .idle },
                                set: { value in
                                    guard self.session?.requestSourceID == session.requestSourceID else { return }
                                    accessReceipts[receiptKey] = value
                                }))
                            .id("\(session.requestSourceID):access:\(request.id)")
                    }
                }
                if let questions, questions.phase != .locked {
                    let stored = questions.faceIDLocked
                    if !stored.isEmpty {
                        FaceIDLockedRow(vaults: stored,
                            opening: stored.contains { questions.opening.contains($0.id) }) {
                            Task { await questions.unlockFaceIDTapped() }
                        }
                    }
                    ForEach(questions.passphraseLocked) { locked in
                        LockedVaultRow(locked: locked, opening: questions.opening.contains(locked.id)) {
                            Task { await questions.unlockTapped(locked) }
                        }
                    }
                }
            }
            if let session, session.state != .connected {
                Section {
                    Label("\(session.macName) is unavailable", systemImage: "wifi.exclamationmark")
                    if let fetchedAt = session.fetchedAt {
                        Text("Last updated \(fetchedAt.formatted(date: .omitted, time: .shortened))")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Button("Retry") { Task { await session.refresh() } }.frame(minHeight: 44)
                }
            }
            if let questions, let error = questions.refreshError, !waiting.isEmpty {
                Section {
                    Label("Couldn’t refresh", systemImage: "exclamationmark.triangle")
                    Text(error).font(.subheadline).foregroundStyle(.secondary)
                    if let updated = questions.lastUpdated {
                        Text("Last updated \(updated.formatted(date: .omitted, time: .shortened))")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Button("Retry") { Task { await questions.refresh() } }.frame(minHeight: 44)
                }
            }
            notices
        }
        .refreshable {
            await questions?.refresh()
            await session?.refresh()
        }
    }

    /// Keep a submitted row in its chronological slot until its explicit Done action.
    private func waitingRows(now: Date) -> [WaitingDecision] {
        let receipts = questions?.receiptQuestions ?? []
        let receiptIDs = Set(receipts.map(\.requestIdentity))
        var rows = Decisions.waiting(
            questions: (questions?.questions ?? []).filter { !receiptIDs.contains($0.requestIdentity) },
            session: session, namesVaults: questions?.namesVaults ?? false, now: now)
        rows.removeAll { decision in
            if case .run(let run) = decision.source { return heldRuns[run.id] != nil }
            return false
        }
        rows += receipts.map { question in
            WaitingDecision(source: .question(question),
                createdAt: Date(timeIntervalSince1970: TimeInterval(question.createdAt)),
                deadline: Date(timeIntervalSince1970: TimeInterval(question.expiresAt)), vault: question.vaultLine)
        }
        rows += heldRuns.values.map { run in
            WaitingDecision(source: .run(run), createdAt: heldRunDates[run.id], deadline: nil)
        }
        return rows.sorted {
            let lhs = $0.createdAt ?? .distantPast
            let rhs = $1.createdAt ?? .distantPast
            return lhs == rhs ? $0.id < $1.id : lhs > rhs
        }
    }

    private var accessRows: [AccessRequest] {
        let live = (session?.accessRequests ?? []).filter { heldAccess[$0.id] == nil }
        return (live + Array(heldAccess.values)).sorted { $0.id < $1.id }
    }

    @ViewBuilder
    private var emptyWaiting: some View {
        switch questions?.phase {
        case .loading where session?.runs.isEmpty ?? true:
            ProgressView("Loading requests…").frame(maxWidth: .infinity)
        case .locked:
            ContentUnavailableView("The vault is locked", systemImage: "lock",
                description: Text("Unlock to view its requests."))
        case .failed(let message):
            ContentUnavailableView {
                Label("Couldn’t refresh", systemImage: "exclamationmark.triangle")
            } description: { Text(message) } actions: {
                Button("Retry") { Task { await questions?.refresh() } }
                    .buttonStyle(.bordered).frame(minHeight: 44)
            }
        case .off where session == nil && (questions?.lockedVaults.isEmpty ?? true):
            ContentUnavailableView {
                Label("Connect a Mac", systemImage: "desktopcomputer")
            } description: { Text("Approve requests on this iPhone.") } actions: {
                Button("Connect Mac") { showsConnect = true }.buttonStyle(.bordered).frame(minHeight: 44)
            }
        default:
            ContentUnavailableView {
                Label("No requests waiting", systemImage: "checkmark.circle")
            } actions: {
                Button("View History") { destination = .history }.buttonStyle(.bordered).frame(minHeight: 44)
            }
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
            ForEach(questions.contexts.filter { $0.error != nil }) { vault in
                Section {
                    Label("\(vault.vaultName) is unavailable", systemImage: "exclamationmark.triangle")
                    if let error = vault.error {
                        Text(error).font(.footnote).foregroundStyle(.secondary)
                    }
                    Button("Retry") { Task { await questions.refresh() } }
                        .frame(minHeight: 44)
                        .accessibilityLabel("Retry \(vault.vaultName) requests")
                }
            }
            if questions.phase == .ready {
                ForEach(questions.contexts.filter { $0.error == nil && $0.status.enabled && !$0.status.hasKey }) { vault in
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
        if destination == .waiting {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    if let questions {
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
