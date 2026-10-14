import ApassyVaultKit
import SwiftUI

/// One agent as its Mac reports it: its use this week, its projects, what it sees (names, never
/// values), its actions, its recent uses, the note for the bouncer (read only), and its exceptions,
/// each with "Remove" when this iPhone can send that removal. A stale Mac is dimmed and takes no
/// action.
struct AgentDetailView: View {
    let model: AgentsModel
    /// `AgentEntry.id`.
    let id: String
    /// The exception and the list as the tap saw them: the alert shows only these, and the removal
    /// is of this list (its feed `seq` and names), whatever feed lands while the alert is up.
    @State private var confirming: Confirmation?

    struct Confirmation: Equatable {
        let exception: FeedException
        let entry: AgentEntry
    }

    var body: some View {
        if let entry = model.entry(id) {
            TimelineView(.periodic(from: .now, by: 60)) { context in
                page(entry, now: context.date)
            }
            .navigationTitle(entry.agent.name)
            .navigationBarTitleDisplayMode(.inline)
            .alert(
                confirming.map {
                    AgentsText.confirmTitle($0.exception, agent: $0.entry.agent.name, mac: $0.entry.mac.name)
                } ?? "",
                isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
                presenting: confirming
            ) { shown in
                Button("Remove", role: .destructive) {
                    Task { await model.remove(shown.exception, in: shown.entry) }
                }
                Button("Cancel", role: .cancel) {}
            } message: { shown in
                Text(AgentsText.confirmMessage(shown.exception, agent: shown.entry.agent.name, mac: shown.entry.mac.name))
            }
            #if DEBUG && targetEnvironment(simulator)
                .agentsConfirmSeed(entry) { confirming = Confirmation(exception: $0, entry: entry) }
            #endif
        } else {
            ContentUnavailableView(
                "This agent is not listed now", systemImage: "cpu",
                description: Text("Its Mac does not report it any more. Pull to refresh the list of agents."))
        }
    }

    private func page(_ entry: AgentEntry, now: Date) -> some View {
        let agent = entry.agent
        let dim = entry.mac.stale ? 0.5 : 1
        return ScrollViewReader { reader in
            List {
                Section {
                    header(entry)
                }
                .listRowBackground(Color.clear)
                .listRowInsets(.init(top: 0, leading: 0, bottom: 8, trailing: 0))

                if entry.mac.stale {
                    Section {
                        Label(AgentsText.staleNote(entry.mac), systemImage: "clock.badge.exclamationmark")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }

                Group {
                    week(agent)
                    if !agent.projects.isEmpty { projects(agent) }
                    sees(entry)
                    if !agent.recent.isEmpty { recent(entry, now: now) }
                    if !agent.note.isEmpty {
                        Section {
                            Text(agent.note)
                        } header: {
                            Text("Note for the bouncer")
                        } footer: {
                            Text("Change it in Agents on \(entry.mac.name).")
                        }
                    }
                }
                .opacity(dim)

                exceptions(entry)

                Section {
                } footer: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(AgentsText.from(entry.mac, now: now))
                        if entry.mac.truncated { Text("Some older uses are on the Mac only.") }
                    }
                }
            }
            .refreshable { await model.refresh() }
            #if DEBUG && targetEnvironment(simulator)
                .agentsScrollSeed { reader.scrollTo($0, anchor: .top) }
            #endif
        }
    }

    // MARK: Sections

    private func header(_ entry: AgentEntry) -> some View {
        let agent = entry.agent
        return VStack(spacing: 8) {
            AgentAvatar(agent: agent.name, large: true)
                .saturation(agent.revoked ? 0 : 1)
            Text(agent.name)
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            Text("On \(entry.mac.name) · \(entry.vaultName)")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            let caps = caps(entry)
            if !caps.isEmpty {
                HStack(spacing: 6) {
                    ForEach(caps, id: \.label) { cap in CapView(label: cap.label, red: cap.red) }
                }
            }
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }

    private func caps(_ entry: AgentEntry) -> [(label: String, red: Bool)] {
        var caps: [(label: String, red: Bool)] = []
        if entry.agent.revoked { caps.append(("Disconnected", false)) }
        if entry.agent.restricted { caps.append(("Only these items", false)) }
        if !entry.agent.revoked, let end = entry.agent.tokenExpiresAt, end < Int64(Date().timeIntervalSince1970) {
            caps.append(("Reconnect on \(entry.mac.name)", true))
        }
        return caps
    }

    private func week(_ agent: FeedAgent) -> some View {
        Section("This week") {
            LabeledContent("Uses", value: "\(agent.usesThisWeek)")
            ForEach(agent.actions) { use in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(use.action.label)
                        Spacer()
                        Text("\(use.allowed) allowed")
                            .foregroundStyle(.secondary)
                        if use.notAllowed > 0 {
                            Text("· \(use.notAllowed) not allowed")
                                .foregroundStyle(.red)
                        }
                    }
                    if !use.projects.isEmpty {
                        Text(use.projects.joined(separator: ", "))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                    }
                }
                .accessibilityElement(children: .combine)
            }
        }
    }

    private func projects(_ agent: FeedAgent) -> some View {
        Section("Projects") {
            FlowLayout {
                ForEach(agent.projects, id: \.self) { project in
                    CapView(label: project, symbol: "folder")
                }
            }
            .padding(.vertical, 2)
        }
    }

    /// What the agent sees: the names of its "only these items" that the Mac lists, or every
    /// credential of the vault. Never a value. The feed holds the `only` rows only: access that
    /// the owner granted on the Mac is not in it, so the list is not the whole of it.
    private func sees(_ entry: AgentEntry) -> some View {
        let only = entry.agent.exceptions.filter { $0.kind == .only }
        return Section {
            if entry.agent.restricted {
                ForEach(only, id: \.self) { exception in
                    credentialRow(AgentsText.credential(exception))
                }
                if only.isEmpty {
                    Text("None listed").foregroundStyle(.secondary)
                }
            } else {
                Label("Every credential in \(entry.vaultName)", systemImage: "key.horizontal")
            }
        } header: {
            Text("Sees")
        } footer: {
            if entry.agent.restricted {
                Text("\(AgentsText.seesFooter(mac: entry.mac.name)) The names only, never the values.")
            } else {
                Text("The names only, never the values.")
            }
        }
        .id("sees")
    }

    private func recent(_ entry: AgentEntry, now: Date) -> some View {
        Section("Recent uses") {
            ForEach(Array(entry.agent.recent.enumerated()), id: \.offset) { _, use in
                UseRow(use: use, now: now)
            }
        }
    }

    // MARK: Exceptions

    private func exceptions(_ entry: AgentEntry) -> some View {
        let shown = Set(entry.agent.exceptions.compactMap { model.removal(of: $0, in: entry) })
        let ended = model.results(of: entry).filter { !shown.contains($0.removal) }
        return Section {
            ForEach(entry.agent.exceptions, id: \.self) { exception in
                exceptionRow(exception, entry: entry)
            }
            ForEach(ended, id: \.removal) { result in
                resultLine(result.state)
            }
            if entry.agent.exceptions.isEmpty, ended.isEmpty {
                Text("No exceptions").foregroundStyle(.secondary)
            }
        } header: {
            Text("Exceptions")
        } footer: {
            Text("Exceptions come from your answers. Removing one that limits the agent asks for Face ID.")
        }
        .id("exceptions")
    }

    private func exceptionRow(_ exception: FeedException, entry: AgentEntry) -> some View {
        let removal = model.removal(of: exception, in: entry)
        let state = removal.flatMap { model.removals[$0] }
        let block = model.removalBlock(of: exception, in: entry)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                ProviderTile(
                    style: .of(provider: nil, title: AgentsText.credential(exception), kind: .apiKey), scale: 0.7)
                Text(AgentsText.exception(exception))
                    .lineLimit(2)
                Spacer(minLength: 8)
                if case .working(let text) = state {
                    ProgressView()
                        .accessibilityLabel(text)
                } else if block == nil {
                    // On a vault that is not selected, Face ID reads its keys again first. The
                    // alert then shows the list as it is after that read: its exception, names,
                    // and seq are what the removal signs.
                    Button("Remove") {
                        Task {
                            guard await model.removeTapped(exception, in: entry) else { return }
                            let now = model.entry(id) ?? entry
                            let same = now.agent.exceptions.first {
                                $0.item == exception.item && $0.kind == exception.kind
                                    && $0.createdAt == exception.createdAt
                            }
                            confirming = Confirmation(exception: same ?? exception, entry: now)
                        }
                    }
                        .buttonStyle(.bordered)
                        .buttonBorderShape(.capsule)
                        .tint(.red)
                        .accessibilityLabel("Remove \(AgentsText.exception(exception))")
                }
            }
            .opacity(entry.mac.stale ? 0.5 : 1)
            if case .working(let text) = state {
                Text(text).font(.footnote).foregroundStyle(.secondary)
            } else if let state {
                resultLine(state)
            } else if let block, exception.item != nil {
                Text(block).font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private func resultLine(_ state: AgentsModel.Removal) -> some View {
        switch state {
        case .removed(let text):
            Label(text, systemImage: "checkmark.circle.fill")
                .font(.footnote)
                .foregroundStyle(.green)
        case .failed(let text):
            Label(text, systemImage: "exclamationmark.triangle.fill")
                .font(.footnote)
                .foregroundStyle(.orange)
        case .working(let text):
            Label(text, systemImage: "hourglass")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    private func credentialRow(_ name: String) -> some View {
        HStack(spacing: 12) {
            ProviderTile(style: .of(provider: nil, title: name, kind: .apiKey), scale: 0.7)
            Text(name)
        }
    }
}

/// A recent use: its mark (allowed, allowed by you, denied, no answer), the credential and the
/// action, the masked command, who decided, and when.
private struct UseRow: View {
    let use: FeedUse
    let now: Date

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            mark
            VStack(alignment: .leading, spacing: 2) {
                Text(title).lineLimit(1)
                if !use.command.isEmpty {
                    Text(use.command)
                        .font(.footnote.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Text(AgentsText.outcome(use))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Text(AgentsText.ago(use.at, now: now))
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }

    private var title: String {
        var parts = [AgentsText.credential(use)]
        if let action = use.action { parts.append(action.label) }
        if !use.project.isEmpty { parts.append(use.project) }
        return parts.joined(separator: " · ")
    }

    private var mark: some View {
        let (symbol, color): (String, Color) =
            switch AgentsText.mark(use) {
            case .allowed: ("checkmark", .green)
            case .allowedByYou: ("person.fill", .blue)
            case .denied: ("xmark", .red)
            case .timedOut: ("clock", .gray)
            }
        return Image(systemName: symbol)
            .font(.system(size: 11, weight: .bold))
            .foregroundStyle(.white)
            .frame(width: 22, height: 22)
            .background(color, in: .circle)
            .accessibilityLabel(AgentsText.outcome(use))
    }
}
