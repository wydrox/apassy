import ApassyCompanionKit
import SwiftUI

/// A run of the Mac on this Wi-Fi as a decision: the same layout as a question through the relay
/// (mockup screen 6), with the fixed glass bar where the actions of the companion map: Allow and
/// Remember (when the Mac offers it), Deny, Allow Once.
///
/// The view keeps the run as the owner opened it and sends that run's digest. When the inbox
/// later shows another digest for the same run, the view shows the new run and Allow stays off
/// until the owner confirms that they read it (`RunSnapshot`), so the owner never approves
/// something that the screen did not show.
struct RunDetailView: View {
    /// A sheet of the companion's Inbox, or a screen pushed in Decisions.
    enum Presentation {
        case sheet
        case pushed
    }

    let session: SessionModel
    let presentation: Presentation
    @State private var snapshot: RunSnapshot
    @State private var phase = Phase.idle
    @State private var approvals = 0
    @State private var denials = 0
    @State private var failures = 0
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dynamicTypeSize) private var typeSize

    init(session: SessionModel, run: PendingRun, presentation: Presentation = .sheet) {
        self.session = session
        self.presentation = presentation
        _snapshot = State(initialValue: RunSnapshot(run))
    }

    private static let topID = "top"
    private static let changedNotice =
        "The Mac changed this run. The new version is shown. Read it again before you allow it."

    enum Action: Equatable {
        case deny
        case approve
        case approveAndRemember
    }

    enum Phase: Equatable {
        case idle
        case working(Action)
        case done(String, approved: Bool)
        case failed(String)

        var isWorking: Bool {
            if case .working = self { return true }
            return false
        }

        var isDone: Bool {
            if case .done = self { return true }
            return false
        }
    }

    /// The run on the screen.
    private var shown: PendingRun { snapshot.run }

    /// The run that the Mac has now for this ID, or nil.
    private var live: PendingRun? { session.run(id: snapshot.run.id) }

    private var availability: RunSnapshot.Availability { snapshot.availability(live: live) }

    private var isBusy: Bool { phase.isWorking || phase.isDone }

    private var canApprove: Bool { snapshot.canApprove(live: live) && !isBusy }

    private var canDeny: Bool { snapshot.canDeny(live: live) && !isBusy }

    /// The owner has not read the version on the screen yet.
    private var showsReviewNotice: Bool {
        snapshot.needsReview || availability == .changed
    }

    /// When the Mac ends the run, from the run on the Mac now: the snapshot's own seconds are from
    /// when it was taken, while `fetchedAt` moves with each poll.
    private var deadline: Date? {
        let run = live ?? shown
        guard availability != .gone, !phase.isDone, let fetchedAt = session.fetchedAt,
            let waited = run.waitingSeconds
        else { return nil }
        return fetchedAt.addingTimeInterval(TimeInterval(max(0, session.approvalTimeout - max(0, waited))))
    }

    var body: some View {
        switch presentation {
        case .sheet:
            NavigationStack {
                content
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button(role: .close) { dismiss() }
                                .disabled(phase.isWorking)
                        }
                    }
            }
            .presentationDetents([.medium, .large])
            .presentationDragIndicator(.visible)
            .interactiveDismissDisabled(phase.isWorking)
        case .pushed:
            content
                .navigationBarBackButtonHidden(phase.isWorking)
                // The bar takes the place of the tab bar, as in the mockup.
                .toolbar(.hidden, for: .tabBar)
        }
    }

    private var content: some View {
        let agent = AgentName.display(shown.agent)
        return ScrollViewReader { proxy in
            List {
                Section {
                    DecisionHeader(
                        agent: agent, sentence: "\(agent) wants to run a command",
                        detail: shown.cwd?.split(separator: "/").last.map(String.init), deadline: deadline)
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets(top: 0, leading: 16, bottom: 0, trailing: 16))
                .id(Self.topID)
                banner
                fields
            }
            .contentMargins(.bottom, 24, for: .scrollContent)
            .scrollEdgeEffectStyle(.soft, for: .bottom)
            // The digest of the run on the Mac decides. The time left changes each poll and is
            // not part of it. `initial: true` also checks the first appearance: a poll can land
            // between the last inbox render (the run that the row passed in) and the view's
            // first body, and then the digest never changes again while the view is open, so
            // a plain `onChange` would leave the old run on the screen with no way to confirm.
            // `observe` returns true only when the digest differs, so the scroll and the
            // announcement run for a real change and not for an unchanged first appearance.
            .onChange(of: live?.digest, initial: true) {
                if snapshot.observe(live) {
                    withAnimation(reduceMotion ? nil : .snappy) { proxy.scrollTo(Self.topID, anchor: .top) }
                    AccessibilityNotification.Announcement(Self.changedNotice).post()
                }
            }
        }
        .navigationTitle("Run")
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .bottom) { actionBar }
        .sensoryFeedback(.success, trigger: approvals)
        .sensoryFeedback(.impact(flexibility: .soft), trigger: denials)
        .sensoryFeedback(.error, trigger: failures)
    }

    // MARK: Fields

    @ViewBuilder
    private var banner: some View {
        if availability != .gone, showsReviewNotice {
            Section {
                CalloutView(
                    symbol: "exclamationmark.triangle.fill",
                    text:
                        "The Mac changed this run. The new version is shown below. Read it again, then confirm, before you allow it."
                )
            }
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets())
        }
    }

    @ViewBuilder
    private var fields: some View {
        Section {
            LabeledContent("Agent", value: shown.agent)
            if let cwd = shown.cwd, !cwd.isEmpty {
                LabeledContent("Folder") {
                    Text(cwd).font(.callout.monospaced()).lineLimit(2).truncationMode(.head)
                }
            }
            LabeledContent("Asked on", value: session.macName)
        }
        Section("Command") {
            DecisionCommand(line: CommandDisplay.line(shown.command))
        }
        if !shown.envNames.isEmpty {
            Section {
                VariableCapsules(names: shown.envNames)
            } header: {
                Text("Variables")
            } footer: {
                Text("Names only. Apassy never sends a value to this iPhone.")
            }
        }
        if !shown.risk.isEmpty || !shown.purpose.isEmpty {
            Section("Why you are asked") {
                if !shown.risk.isEmpty {
                    Label {
                        Text(shown.risk)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                }
                if !shown.purpose.isEmpty {
                    labeled("Purpose", shown.purpose)
                }
            }
        }
        Section("Requests") {
            if shown.userRequest.isEmpty {
                Text("The Mac has no request text for this run.")
                    .foregroundStyle(.secondary)
            } else {
                labeled("You asked", shown.userRequest)
                if !shown.requestSource.isEmpty {
                    Text("Source: \(shown.requestSource)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            if !shown.agentRequest.isEmpty && shown.agentRequest != shown.userRequest {
                labeled("The agent says", shown.agentRequest)
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

    // MARK: Actions

    @ViewBuilder
    private var actionBar: some View {
        if case .done(let text, let approved) = phase {
            DecisionOutcomeBar(outcome: QuestionOutcome(text: text, tone: approved ? .allowed : .denied))
        } else if availability == .gone {
            DecisionOutcomeBar(
                outcome: QuestionOutcome(text: "Decided on your Mac, or the time ran out", tone: .neutral))
        } else {
            DecisionBar {
                if case .failed(let message) = phase {
                    Label {
                        Text(message)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } icon: {
                        Image(systemName: "xmark.octagon.fill")
                            .foregroundStyle(.red)
                    }
                    .font(.footnote)
                }
                buttons
            }
        }
    }

    @ViewBuilder
    private var buttons: some View {
        if snapshot.needsReview && availability == .current && !isBusy {
            Button {
                withAnimation(reduceMotion ? nil : .snappy) { snapshot.confirmReading() }
            } label: {
                Label("I have read the new version", systemImage: "checkmark")
                    .frame(maxWidth: .infinity)
            }
            .decisionButton(.primary)
        } else if shown.remember != nil {
            Button {
                perform(.approveAndRemember)
            } label: {
                label("Allow and Remember", action: .approveAndRemember)
            }
            .decisionButton(.primary)
            .disabled(!canApprove)
        }
        let layout =
            typeSize.isAccessibilitySize ? AnyLayout(VStackLayout(spacing: 8)) : AnyLayout(HStackLayout(spacing: 8))
        layout {
            Button(role: .destructive) {
                perform(.deny)
            } label: {
                label("Deny", action: .deny)
            }
            .decisionButton(.deny)
            .disabled(!canDeny)
            Button {
                perform(.approve)
            } label: {
                label("Allow Once", action: .approve)
            }
            .decisionButton(.secondary)
            .disabled(!canApprove)
        }
        if let offer = shown.remember {
            Text("Allow and Remember teaches \(offer.pattern) (\(offer.approvals) of \(offer.needed))")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
    }

    private func label(_ title: String, action: Action) -> some View {
        Group {
            if phase == .working(action) {
                ProgressView()
            } else {
                Text(title)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private func perform(_ action: Action) {
        guard action == .deny ? canDeny : canApprove else { return }
        let run = shown
        phase = .working(action)
        Task {
            do {
                switch action {
                case .deny:
                    try await session.deny(run)
                    finish("Denied", approved: false)
                case .approve:
                    _ = try await session.approve(run, remember: false)
                    finish("Allowed", approved: true)
                case .approveAndRemember:
                    let outcome = try await session.approve(run, remember: true)
                    finish(outcome == .approvedAndRemembered ? "Allowed and remembered" : "Allowed", approved: true)
                }
            } catch is CancellationError {
                phase = .idle
            } catch {
                phase = .failed(error.localizedDescription)
                failures += 1
            }
        }
    }

    /// Show the result in the bar, give the haptic, and close the view a moment later.
    private func finish(_ text: String, approved: Bool) {
        withAnimation(reduceMotion ? nil : .bouncy) {
            phase = .done(text, approved: approved)
        }
        if approved { approvals += 1 } else { denials += 1 }
        Task {
            try? await Task.sleep(for: .seconds(1.2))
            dismiss()
        }
    }
}

#if DEBUG
    #Preview("Run") {
        RunDetailView(session: .preview(), run: PreviewData.migrateRun)
    }

    #Preview("Run with a long command") {
        RunDetailView(session: .preview(), run: PreviewData.quotedRun)
    }

    #Preview("Run in Decisions") {
        NavigationStack {
            RunDetailView(session: .preview(), run: PreviewData.migrateRun, presentation: .pushed)
        }
    }
#endif
