import ApassyVaultKit
import SwiftUI

/// Agent Access in Settings uses the relay feed (contract relay-feed-v1): the
/// agents that each Mac publishes for the unlocked vaults, by Mac, and by vault when there are two
/// or more. Read only, except the removal of an exception in an agent's page.
///
/// While no Mac publishes its agents to this iPhone, the page shows no list and no invented data:
/// it says where the agents are, by the state of this iPhone (`AgentsReach`), with the one action
/// that helps now. Settings owns the long poll while this access flow is on screen.
struct AgentsView: View {
    let model: AgentsModel?
    let questions: QuestionsModel?
    let companion: AppModel
    var embedded = false
    var close: (() -> Void)?
    @Environment(RootModel.self) private var root: RootModel?
    @Environment(VaultUI.self) private var ui: VaultUI?
    @Environment(\.scenePhase) private var scenePhase
    @State private var showsConnect = false
    @State private var path: [String] = []

    var body: some View {
        Group {
            if embedded {
                page
                    .navigationDestination(item: seededAgent) { id in
                        if let model { AgentDetailView(model: model, id: id) }
                    }
            } else {
                NavigationStack {
                    page.navigationDestination(item: seededAgent) { id in
                        if let model { AgentDetailView(model: model, id: id) }
                    }
                }
            }
        }
        // Here, not on the tabs: the feeds are followed only while Agents shows (contract 5.12).
        .task(id: CoverPolicy.polls(in: AppPhase(scenePhase))) {
            if !embedded, CoverPolicy.polls(in: AppPhase(scenePhase)), let model { await model.watch() }
        }
        // The same sheet as "Connect this iPhone" in Decisions.
        .sheet(
            isPresented: $showsConnect,
            onDismiss: {
                let opensCompanion = questions?.attach == .companion
                let opensRequests = questions?.attach == .attached
                questions?.dismissAttach()
                if opensCompanion { root?.openPreparedCompanion() }
                if opensRequests {
                    ui?.tab = .decisions
                    close?()
                }
            }
        ) {
            if let questions { ConnectQuestionsView(model: questions) }
        }
        #if DEBUG && targetEnvironment(simulator)
            .agentsPreviewSeed(model, path: $path)
        #endif
    }

    private var page: some View {
        content
            .navigationTitle("Agent Access")
            .navigationBarTitleDisplayMode(.inline)
            .navigationSubtitle(subtitle)
    }

    // Simulator routes use the same Settings destination as a user tap.
    private var seededAgent: Binding<String?> {
        Binding(get: { path.first }, set: { path = $0.map { [$0] } ?? [] })
    }

    private var subtitle: String {
        guard let model, model.screen == .list else { return "" }
        let count = model.agentCount
        return count == 1 ? "1 agent" : "\(count) agents"
    }

    @ViewBuilder
    private var content: some View {
        switch model?.screen ?? .reach {
        case .loading:
            ProgressView()
        case .reach:
            reach
        case .failed(let message):
            ContentUnavailableView {
                Label("Apassy cannot read the agents", systemImage: "exclamationmark.triangle")
            } description: {
                Text(message)
            } actions: {
                Button("Try Again") { Task { await model?.refresh() } }
                    .buttonStyle(.bordered)
            }
        case .list:
            if let model { AgentsList(model: model) }
        }
    }

    /// No Mac publishes its agents here: where they are, and the one action that helps now.
    private var reach: some View {
        let reach = AgentsReach(questions: questions, companion: companion)
        return ContentUnavailableView {
            Label(reach.title, systemImage: "laptopcomputer")
        } description: {
            Text(reach.message)
        } actions: {
            switch reach.action {
            case .connect:
                Button("Connect this iPhone") { showsConnect = true }
                    .buttonStyle(.borderedProminent)
            case .openDecisions:
                Button("Open Requests") {
                    ui?.tab = .decisions
                    close?()
                }
                .buttonStyle(.bordered)
            case .pairOnWiFi, nil:
                EmptyView()
            }
        }
    }
}

/// The agents by Mac (mockup screen 9). A Mac whose feed is more than a day old is dimmed and says
/// since when.
private struct AgentsList: View {
    let model: AgentsModel

    var body: some View {
        // Each minute: "2h", "From Mac mini, 5 min ago".
        TimelineView(.periodic(from: .now, by: 60)) { context in
            List {
                ForEach(model.sections) { section in
                    Section {
                        if let problem = section.mac.problem {
                            Label(problem, systemImage: "exclamationmark.triangle")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                        ForEach(section.agents) { entry in
                            NavigationLink {
                                AgentDetailView(model: model, id: entry.id)
                            } label: {
                                AgentRow(entry: entry, now: context.date)
                            }
                            .opacity(section.mac.stale ? 0.5 : 1)
                        }
                        if section.agents.isEmpty, section.mac.problem == nil, section.mac.seq != nil {
                            Text("No agents of \(section.vaultName) on \(section.mac.name) yet.")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    } header: {
                        HStack(spacing: 6) {
                            Text(section.title)
                            if section.mac.stale { CapView(label: "Not reporting", symbol: "clock") }
                        }
                    } footer: {
                        Text(
                            section.mac.stale
                                ? AgentsText.staleNote(section.mac) : AgentsText.from(section.mac, now: context.date))
                    }
                }
                if let notice = model.notice {
                    Section {
                        Label(notice, systemImage: "exclamationmark.triangle")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Section {
                } footer: {
                    Text(
                        "Agents see the names of credentials, never the values. The bouncer on each Mac decides each use."
                    )
                }
            }
        }
        .refreshable { await model.refresh() }
    }
}

/// A row of an agent: its round tile, its name, "Mac mini · 5 uses this week", its exceptions, and
/// its last use.
private struct AgentRow: View {
    let entry: AgentEntry
    let now: Date

    var body: some View {
        HStack(spacing: 12) {
            AgentAvatar(agent: entry.agent.name)
                .saturation(entry.agent.revoked ? 0 : 1)
            VStack(alignment: .leading, spacing: 2) {
                // The name, its exceptions, and the last use on one line; the Mac and the uses
                // below, at full width.
                HStack(spacing: 6) {
                    Text(entry.agent.name).lineLimit(1)
                    let exceptions = entry.agent.exceptions.count
                    if exceptions > 0 {
                        CapView(label: exceptions == 1 ? "1 exception" : "\(exceptions) exceptions")
                    }
                    Spacer(minLength: 8)
                    if let last = entry.agent.lastUseAt {
                        Text(AgentsText.ago(last, now: now))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .accessibilityLabel("Last use \(AgentsText.ago(last, now: now))")
                    }
                }
                Text(AgentsText.subtitle(entry))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

extension AgentsReach {
    /// The state of this iPhone: the questions through the relay, and the Mac paired on Wi-Fi.
    @MainActor
    init(questions: QuestionsModel?, companion: AppModel?) {
        var wifiMac: String?
        if case .paired(let session) = companion?.phase { wifiMac = session.macName }
        self.init(questions: questions?.phase, removed: questions?.status.removed ?? false, wifiMac: wifiMac)
    }
}

/// A part of the Mac's vault that does not reach this iPhone: where it lives (`AgentsReach.note`),
/// and the one action that helps now.
struct MacPlaceRow: View {
    let note: String
    var action: AgentsReach.Action?
    var perform: (AgentsReach.Action) -> Void = { _ in }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(note, systemImage: "laptopcomputer")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            if let action {
                Button(action.title) { perform(action) }
                    .buttonStyle(.bordered)
            }
        }
        .padding(.vertical, 2)
    }
}

#if DEBUG
    #Preview("No feed") {
        AgentsView(model: nil, questions: nil, companion: AppModel())
    }
#endif
