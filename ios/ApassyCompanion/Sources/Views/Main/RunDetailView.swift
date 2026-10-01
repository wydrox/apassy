import ApassyCompanionKit
import LocalAuthentication
import SwiftUI

/// Every field of a run, and the buttons to decide it.
///
/// The view keeps the run as the owner opened it and sends that run's digest. When the inbox
/// later shows another digest for the same run, the view shows the new run and Approve stays off
/// until the owner confirms that they read it (`RunSnapshot`), so the owner never approves
/// something that the screen did not show.
struct RunDetailView: View {
    let session: SessionModel
    @State private var snapshot: RunSnapshot
    @State private var phase = Phase.idle
    @State private var approvals = 0
    @State private var denials = 0
    @State private var failures = 0
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dynamicTypeSize) private var typeSize
    @Namespace private var glass

    init(session: SessionModel, run: PendingRun) {
        self.session = session
        _snapshot = State(initialValue: RunSnapshot(run))
    }

    private static let topID = "top"
    private static let changedNotice =
        "The Mac changed this run. The new version is shown. Read it again before you approve."

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

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        banner
                            .id(Self.topID)
                        fields
                    }
                    .padding(.horizontal, 20)
                    .padding(.vertical, 12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .scrollEdgeEffectStyle(.soft, for: .bottom)
                // The digest of the run on the Mac decides. The time left changes each poll and is
                // not part of it. `initial: true` also checks the first appearance: a poll can land
                // between the last inbox render (the run that the row passed in) and the sheet's
                // first body, and then the digest never changes again while the sheet is open, so
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
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .close) { dismiss() }
                        .disabled(phase.isWorking)
                }
            }
            .safeAreaInset(edge: .bottom) { actionBar }
        }
        .presentationDetents([.medium, .large])
        .presentationDragIndicator(.visible)
        .interactiveDismissDisabled(phase.isWorking)
        .sensoryFeedback(.success, trigger: approvals)
        .sensoryFeedback(.impact(flexibility: .soft), trigger: denials)
        .sensoryFeedback(.error, trigger: failures)
    }

    // MARK: Fields

    @ViewBuilder
    private var banner: some View {
        if availability == .gone {
            if !phase.isDone {
                CalloutView(
                    symbol: "clock.badge.exclamationmark.fill",
                    text:
                        "This run no longer waits. It was decided on your Mac, or its time ran out. Nothing more can be approved here."
                )
            }
        } else if showsReviewNotice {
            CalloutView(
                symbol: "exclamationmark.triangle.fill",
                text:
                    "The Mac changed this run. The new version is shown below. Read it again, then confirm, before you approve."
            )
        }
    }

    private var fields: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(spacing: 8) {
                Image(systemName: "terminal")
                    .accessibilityHidden(true)
                Text(shown.agent)
                    .font(.title3.weight(.semibold))
            }
            if availability != .gone {
                // The time left comes from the run on the Mac now: the snapshot's own seconds are
                // from when it was taken, while `fetchedAt` moves with each poll.
                TimeLeftView(run: live ?? shown, timeout: session.approvalTimeout, fetchedAt: session.fetchedAt)
            }
            Field("Your request") {
                if shown.userRequest.isEmpty {
                    Text("The Mac has no request text for this run.")
                        .foregroundStyle(.secondary)
                } else {
                    Text(shown.userRequest)
                }
                if !shown.requestSource.isEmpty {
                    Text("Source: \(shown.requestSource)")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            if !shown.agentRequest.isEmpty && shown.agentRequest != shown.userRequest {
                Field("What the agent says") {
                    Text(shown.agentRequest)
                }
            }
            if !shown.purpose.isEmpty {
                Field("Purpose") {
                    Text(shown.purpose)
                }
            }
            if !shown.risk.isEmpty {
                Field("Risk") {
                    Label {
                        Text(shown.risk)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                }
            }
            if let cwd = shown.cwd, !cwd.isEmpty {
                Field("Folder") {
                    Text(cwd)
                        .font(.system(.callout, design: .monospaced))
                }
            }
            Field("Command") {
                Text(CommandDisplay.line(shown.command))
                    .font(.system(.callout, design: .monospaced))
            }
            if !shown.envNames.isEmpty {
                Field("Variables") {
                    VariableCapsules(names: shown.envNames)
                    Text("Names only. Apassy never sends a value to this iPhone.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            if let offer = shown.remember {
                Field("Approve and remember") {
                    Text(
                        "Approve and remember teaches \(Text(offer.pattern).font(.system(.body, design: .monospaced))) (\(offer.approvals) of \(offer.needed))"
                    )
                }
            }
        }
    }

    // MARK: Actions

    private var actionBar: some View {
        VStack(spacing: 10) {
            if case .failed(let message) = phase {
                Label {
                    Text(message)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } icon: {
                    Image(systemName: "xmark.octagon.fill")
                        .foregroundStyle(.red)
                }
                .font(.callout)
                .padding(12)
                .background(.red.opacity(0.12), in: .rect(cornerRadius: 14, style: .continuous))
            }
            GlassEffectContainer(spacing: 12) {
                if case .done(let text, let approved) = phase {
                    Label(text, systemImage: approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .font(.headline)
                        .padding(.horizontal, 24)
                        .padding(.vertical, 14)
                        .frame(maxWidth: .infinity)
                        .glassEffect(.regular.tint((approved ? Color.green : Color.red).opacity(0.3)), in: .capsule)
                        .glassEffectID("result", in: glass)
                } else {
                    buttons
                }
            }
        }
        .controlSize(.large)
        .padding(.horizontal, 20)
        .padding(.bottom, 8)
    }

    private var buttons: some View {
        VStack(spacing: 12) {
            if snapshot.needsReview && availability == .current && !isBusy {
                Button {
                    withAnimation(reduceMotion ? nil : .snappy) { snapshot.confirmReading() }
                } label: {
                    Label("I have read the new version", systemImage: "checkmark")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .glassEffectID("review", in: glass)
            }
            let layout = typeSize.isAccessibilitySize ? AnyLayout(VStackLayout(spacing: 12)) : AnyLayout(HStackLayout(spacing: 12))
            layout {
                Button(role: .destructive) {
                    perform(.deny)
                } label: {
                    label("Deny", symbol: "xmark", action: .deny)
                }
                .buttonStyle(.glass)
                .tint(.red)
                .disabled(!canDeny)
                .glassEffectID("deny", in: glass)
                Button {
                    perform(.approve)
                } label: {
                    label("Approve", symbol: BiometryIcon.symbol, action: .approve)
                }
                .buttonStyle(.glassProminent)
                .disabled(!canApprove)
                .glassEffectID("approve", in: glass)
            }
            if shown.remember != nil {
                Button {
                    perform(.approveAndRemember)
                } label: {
                    label("Approve and remember", symbol: BiometryIcon.symbol, action: .approveAndRemember)
                }
                .buttonStyle(.glass)
                .disabled(!canApprove)
                .glassEffectID("remember", in: glass)
            }
        }
    }

    private func label(_ title: String, symbol: String, action: Action) -> some View {
        Group {
            if phase == .working(action) {
                ProgressView()
            } else {
                Label(title, systemImage: symbol)
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
                    finish("Approved", approved: true)
                case .approveAndRemember:
                    let outcome = try await session.approve(run, remember: true)
                    finish(outcome == .approvedAndRemembered ? "Approved and remembered" : "Approved", approved: true)
                }
            } catch is CancellationError {
                phase = .idle
            } catch {
                phase = .failed(error.localizedDescription)
                failures += 1
            }
        }
    }

    /// Show the result in the bar, give the haptic, and close the sheet a moment later.
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

/// A titled block of a run.
private struct Field<Content: View>: View {
    let title: LocalizedStringKey
    @ViewBuilder let content: Content

    init(_ title: LocalizedStringKey, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
                .accessibilityAddTraits(.isHeader)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The symbol of the biometry of this iPhone, for the Approve buttons.
enum BiometryIcon {
    static let symbol: String = {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch context.biometryType {
        case .touchID: return "touchid"
        case .opticID: return "opticid"
        default: return "faceid"
        }
    }()
}

#if DEBUG
    #Preview("Run") {
        RunDetailView(session: .preview(), run: PreviewData.migrateRun)
    }

    #Preview("Run with a long command") {
        RunDetailView(session: .preview(), run: PreviewData.quotedRun)
    }
#endif
