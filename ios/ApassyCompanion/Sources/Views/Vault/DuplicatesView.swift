import ApassyVaultKit
import SwiftUI

/// "Find duplicates": the groups of items that hold the same credential, with the item to keep and
/// a merge after the owner check. Settings › General and a finished import push it. It shows titles,
/// kinds, times, and the labels of the fields that differ, never a value.
struct DuplicatesView: View {
    @State private var model: DuplicatesModel
    /// The group whose merge waits for the confirmation.
    @State private var confirming: DuplicateGroup?
    @State private var confirmingAll = false

    init(vault: VaultModel) {
        _model = State(initialValue: DuplicatesModel(vault: vault))
    }

    var body: some View {
        content
            .navigationTitle("Duplicates")
            .navigationBarTitleDisplayMode(.inline)
            .task { await model.load() }
            .refreshable { await model.load() }
            .interactiveDismissDisabled(model.isMerging)
            .confirmationDialog(
                confirming.map { model.confirmationTitle(for: $0) } ?? "",
                isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
                titleVisibility: .visible, presenting: confirming
            ) { group in
                Button("Merge") { merge(group) }
                Button("Cancel", role: .cancel) {}
            } message: { _ in
                Text(DuplicatesModel.mergeMessage)
            }
            .confirmationDialog(model.mergeAllTitle, isPresented: $confirmingAll, titleVisibility: .visible) {
                Button("Merge") { mergeAll() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(DuplicatesModel.mergeAllMessage)
            }
            .alert(
                "Apassy could not finish",
                isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } })
            ) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(model.alert ?? "")
            }
    }

    @ViewBuilder
    private var content: some View {
        switch model.phase {
        case .loading:
            ProgressView("Looking for duplicates…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .failed(let message):
            ContentUnavailableView {
                Label("Apassy could not look for duplicates", systemImage: "exclamationmark.triangle")
            } description: {
                Text(message)
            } actions: {
                Button("Try again") { Task { await model.load() } }
                    .buttonStyle(.bordered)
            }
        case .loaded:
            if model.groups.isEmpty {
                ContentUnavailableView {
                    Label("No duplicates found.", systemImage: "checkmark.circle")
                } description: {
                    Text("No two items in this vault hold the same credential.")
                }
            } else {
                list
            }
        }
    }

    private var list: some View {
        Form {
            ForEach(model.groups) { group in
                groupSection(group)
            }
            if !model.identicalGroups.isEmpty {
                Section {
                    Button("Merge all identical", systemImage: "square.on.square") { confirmingAll = true }
                        .disabled(model.isMerging)
                } footer: {
                    Text(
                        "Merges each group whose items have the same values. Merged items go to the archive, where you can restore them."
                    )
                }
            }
        }
        .disabled(model.isMerging)
    }

    private func groupSection(_ group: DuplicateGroup) -> some View {
        Section {
            ForEach(group.items) { member in
                memberRow(member)
            }
            Label(group.differenceSummary, systemImage: group.identical ? "equal.circle" : "notequal.circle")
                .foregroundStyle(.secondary)
            if group.mergeable {
                if model.canChoose(in: group) {
                    Picker(
                        "Keep",
                        selection: Binding(
                            get: { model.keepID(for: group) ?? group.keep },
                            set: { model.choose($0, for: group) })
                    ) {
                        ForEach(group.keepable) { member in
                            Text(member.title).tag(member.id)
                        }
                    }
                } else if let kept = model.keptMember(of: group) {
                    LabeledContent("Keep", value: kept.title)
                }
                Button("Merge", systemImage: "arrow.triangle.merge") { confirming = group }
            }
        } footer: {
            if !group.mergeable, let reason = group.reason {
                Text(reason)
            } else if group.items.contains(where: \.hasPasskey) {
                Text("The item with the passkey is kept: a passkey stays in its own item.")
            }
        }
    }

    private func memberRow(_ member: DuplicateMember) -> some View {
        HStack(spacing: 12) {
            Image(systemName: member.kind.symbol)
                .foregroundStyle(.secondary)
                .frame(width: 24)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(member.title)
                    .lineLimit(2)
                Text(detail(member))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
            if member.hasPasskey {
                Image(systemName: "person.badge.key.fill")
                    .foregroundStyle(.tint)
                    .accessibilityLabel("Has a passkey")
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// "Login · Changed 3 Nov 2026".
    private func detail(_ member: DuplicateMember) -> String {
        guard member.changedAt > 0 else { return member.kind.label }
        let date = Date(timeIntervalSince1970: TimeInterval(member.changedAt)).formatted(date: .abbreviated, time: .omitted)
        return "\(member.kind.label) · Changed \(date)"
    }

    private func merge(_ group: DuplicateGroup) {
        Task {
            if let kept = await model.merge(group) {
                Toast.shared.show("Merged into “\(kept.title)”.")
            }
        }
    }

    private func mergeAll() {
        Task {
            let count = await model.mergeAllIdentical()
            if count > 0 {
                Toast.shared.show(count == 1 ? "Merged 1 group." : "Merged \(count) groups.")
            }
        }
    }
}
