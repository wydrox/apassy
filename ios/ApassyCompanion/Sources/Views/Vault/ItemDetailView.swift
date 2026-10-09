import ApassyVaultKit
import SwiftUI

/// The screen of one item, from a route. It makes the model once.
struct ItemDetailScreen: View {
    let id: UInt64
    @Environment(VaultModel.self) private var vault

    var body: some View {
        ItemDetailView(model: ItemDetailModel(id: id, vault: vault))
    }
}

/// An item: its header, its fields in their order, notes, tags, times, and history.
struct ItemDetailView: View {
    @State private var model: ItemDetailModel
    @Environment(VaultModel.self) private var vault
    @Environment(VaultUI.self) private var ui
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingDelete = false
    /// The removal that the owner asked for, as it was said to them.
    @State private var pendingPasskeyRemoval: PasskeyRemovalPlan?
    @State private var showsHistory = false

    init(model: ItemDetailModel) {
        _model = State(initialValue: model)
    }

    var body: some View {
        content
            .navigationTitle(model.title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { toolbar }
            .task(id: vault.itemsVersion) { await model.load() }
            .onChange(of: vault.revealEpoch) { model.dropSecrets() }
            .onDisappear { model.dropSecrets() }
            .fullScreenCover(
                item: Binding(get: { model.largeType }, set: { if $0 == nil { model.closeLargeType() } })
            ) { large in
                LargeTypeView(largeType: large) { model.closeLargeType() }
            }
            .confirmationDialog(
                "Delete “\(model.title)”?", isPresented: $confirmingDelete, titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    Task {
                        if await model.delete() { dismiss() }
                    }
                }
            } message: {
                Text("The item is deleted on this iPhone and, at the next sync, on your Macs. To keep it out of the way instead, archive it.")
            }
            .confirmationDialog(
                pendingPasskeyRemoval?.dialogTitle ?? "",
                isPresented: Binding(
                    get: { pendingPasskeyRemoval != nil }, set: { if !$0 { pendingPasskeyRemoval = nil } }),
                titleVisibility: .visible, presenting: pendingPasskeyRemoval
            ) { plan in
                Button(plan.actionTitle, role: .destructive) {
                    Task {
                        if await model.removePasskey(plan), plan.deletesLogin, model.isGone { dismiss() }
                    }
                }
            } message: { plan in
                Text(plan.message)
            }
            #if targetEnvironment(simulator)
                .task(id: model.detail?.id) { await demoReveal() }
            #endif
    }

    @ViewBuilder
    private var content: some View {
        if model.isGone {
            ContentUnavailableView(
                "This item is not in the vault", systemImage: "trash",
                description: Text("It was deleted on this iPhone or on a Mac."))
        } else if let detail = model.detail {
            List {
                Section {
                    header(detail.row)
                }
                .listRowBackground(Color.clear)
                if detail.row.conflictOf != nil { conflictBanner(detail.row) }
                if !detail.fields.isEmpty {
                    Section {
                        ForEach(detail.fields) { field in
                            FieldRow(field: field, model: model)
                        }
                    }
                }
                if let passkey = detail.passkey { passkeySection(passkey) }
                if !detail.notes.isEmpty {
                    Section("Notes") {
                        Text(detail.notes)
                            .textSelection(.enabled)
                    }
                }
                if !detail.row.tags.isEmpty {
                    Section("Tags") {
                        FlowLayout(spacing: 8) {
                            ForEach(detail.row.tags, id: \.self) { tag in
                                TagChip(text: tag)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
                times(detail.row)
                history
            }
        } else if let error = model.loadError {
            ContentUnavailableView {
                Label("Apassy cannot open this item", systemImage: "exclamationmark.triangle")
            } description: {
                Text(error)
            } actions: {
                Button("Try again") { Task { await model.load() } }
                    .buttonStyle(.bordered)
            }
        } else {
            ProgressView()
        }
    }

    private func header(_ row: ItemRow) -> some View {
        VStack(spacing: 10) {
            ItemIcon(kind: row.kind, scale: 1.8)
            Text(row.title)
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            if !row.subtitle.isEmpty {
                Text(row.subtitle)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 6) {
                Text(row.kind.label)
                if row.hasPasskey || model.detail?.passkey != nil { Text("· Passkey") }
                if row.archived { Text("· Archived") }
                if model.isFavorite { Text("· Favorite") }
            }
            .font(.footnote.weight(.medium))
            .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
    }

    /// The passkey: what it signs in to, never its key. The key has no reveal, copy, or large
    /// type; it leaves the vault as a signature, or through the system export to another app
    /// after the owner check.
    private func passkeySection(_ passkey: PasskeySummary) -> some View {
        Section {
            LabeledContent("Website", value: passkey.rpID)
            if !passkey.userName.isEmpty {
                LabeledContent("Account", value: passkey.userName)
            }
            if !passkey.userDisplayName.isEmpty, passkey.userDisplayName != passkey.userName {
                LabeledContent("Display name", value: passkey.userDisplayName)
            }
            LabeledContent("Passkey ID", value: VaultText.shortID(passkey.credentialID))
                .accessibilityHint("The first characters of the ID of the passkey, to tell it apart.")
            if let plan = model.passkeyRemovalPlan {
                Button(plan.actionTitle, systemImage: plan.systemImage, role: .destructive) {
                    pendingPasskeyRemoval = plan
                }
            }
        } header: {
            Label("Passkey", systemImage: "person.badge.key")
        } footer: {
            Text(PasskeyRemovalPlan.footer(website: passkey.rpID))
        }
    }

    private func conflictBanner(_ row: ItemRow) -> some View {
        Section {
            let original = model.original
            CalloutView(
                symbol: "exclamationmark.triangle.fill",
                text:
                    "A sync kept both versions of “\(original?.title ?? "the item")”. Keep the one you need and archive the other.")
                .listRowInsets(EdgeInsets())
                .listRowBackground(Color.clear)
            if let original {
                NavigationLink(value: VaultRoute.item(original.id)) {
                    Label("Open “\(original.title)”", systemImage: "arrow.uturn.backward")
                }
            }
        }
    }

    private func times(_ row: ItemRow) -> some View {
        Section {
            timeRow("Added", row.addedAt)
            timeRow("Changed", row.changedAt)
            timeRow("Used", row.usedAt)
        }
    }

    @ViewBuilder
    private func timeRow(_ label: String, _ seconds: Int64?) -> some View {
        LabeledContent(label) {
            if let date = VaultText.date(seconds) {
                Text(date, format: .relative(presentation: .named))
            } else {
                Text("Never")
            }
        }
    }

    private var history: some View {
        Section {
            DisclosureGroup("History", isExpanded: $showsHistory) {
                if let events = model.history {
                    if events.isEmpty {
                        Text("No history yet.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(Array(events.enumerated()), id: \.offset) { _, event in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(event.detail)
                            Text(Date(timeIntervalSince1970: TimeInterval(event.at)), format: .relative(presentation: .named))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .accessibilityElement(children: .combine)
                    }
                } else {
                    ProgressView()
                }
            }
            .onChange(of: showsHistory) { _, shows in
                if shows, model.history == nil { Task { await model.loadHistory() } }
            }
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        if let detail = model.detail {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Edit") { ui.sheet = .edit(detail) }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    if !detail.row.archived {
                        Button(
                            model.isFavorite ? "Remove from favorites" : "Favorite",
                            systemImage: model.isFavorite ? "star.slash" : "star"
                        ) { model.toggleFavorite() }
                    }
                    Button(
                        detail.row.archived ? "Restore" : "Archive",
                        systemImage: detail.row.archived ? "tray.and.arrow.up" : "archivebox"
                    ) {
                        Task { await model.setArchived(!detail.row.archived) }
                    }
                    Divider()
                    if let plan = model.passkeyRemovalPlan {
                        Button(plan.actionTitle, systemImage: plan.systemImage, role: .destructive) {
                            pendingPasskeyRemoval = plan
                        }
                    }
                    Button("Delete", systemImage: "trash", role: .destructive) { confirmingDelete = true }
                } label: {
                    Label("More", systemImage: "ellipsis")
                }
            }
        }
    }

    #if targetEnvironment(simulator)
        private func demoReveal() async {
            guard let field = model.detail?.fields.first(where: { $0.secret && $0.role != .totp }) else { return }
            if ui.demoLargeType {
                ui.demoLargeType = false
                await model.showLargeType(field)
                return
            }
            guard ui.demoReveal else { return }
            ui.demoReveal = false
            await model.reveal(field)
            if let code = model.detail?.fields.first(where: { $0.role == .totp }) { await model.showCode(code) }
        }
    #endif
}

/// A tag as a chip.
struct TagChip: View {
    let text: String
    var onRemove: (() -> Void)?

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: "tag")
                .font(.caption2)
                .accessibilityHidden(true)
            Text(text)
                .font(.subheadline)
            if let onRemove {
                Button(action: onRemove) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Remove the tag \(text)")
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(.tint.opacity(0.12), in: .capsule)
    }
}

// MARK: - Fields

/// One field: plain (tap to copy), secret (reveal and copy after the owner check), a one-time
/// password, a website, or a key in several lines.
struct FieldRow: View {
    let field: FieldView
    let model: ItemDetailModel
    @Environment(\.openURL) private var openURL

    var body: some View {
        Group {
            if field.role == .totp {
                TotpRow(field: field, model: model)
            } else if field.secret {
                secretRow
            } else {
                plainRow
            }
        }
        .contextMenu { menu }
    }

    private var label: some View {
        Text(field.label)
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    private var plainRow: some View {
        HStack(alignment: .center, spacing: 12) {
            Button {
                Task { await model.copy(field) }
            } label: {
                VStack(alignment: .leading, spacing: 3) {
                    label
                    if field.multiline {
                        KeyBlock(text: field.value ?? "")
                    } else {
                        Text(field.value ?? "")
                            .foregroundStyle(field.role == .website ? Color.accentColor : .primary)
                            .lineLimit(3)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityHint("Copies the \(VaultText.phrase(field.label))")
            if field.role == .website, let url = VaultText.websiteURL(field.value ?? "") {
                Button {
                    openURL(url)
                } label: {
                    Image(systemName: "safari")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Open \(VaultText.host(field.value ?? ""))")
            }
        }
    }

    private var secretRow: some View {
        HStack(alignment: .center, spacing: 14) {
            VStack(alignment: .leading, spacing: 3) {
                label
                if let value = model.revealed[field.name] {
                    if field.multiline || value.contains("\n") {
                        KeyBlock(text: value, colored: true)
                    } else {
                        Text(SecretText.attributed(value))
                            .font(.body.monospaced())
                            .lineLimit(4)
                    }
                } else {
                    HiddenSecret()
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if model.working.contains(field.name) {
                ProgressView()
            }
            Button {
                if model.isRevealed(field) { model.hide(field) } else { Task { await model.reveal(field) } }
            } label: {
                Image(systemName: model.isRevealed(field) ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(model.isRevealed(field) ? "Hide the \(VaultText.phrase(field.label))" : "Show the \(VaultText.phrase(field.label))")
            Button {
                Task { await model.copy(field) }
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Copy the \(VaultText.phrase(field.label))")
        }
    }

    @ViewBuilder
    private var menu: some View {
        if field.role == .totp {
            Button("Copy code", systemImage: "doc.on.doc") { Task { await model.copyCode(field) } }
        } else {
            Button("Copy", systemImage: "doc.on.doc") { Task { await model.copy(field) } }
            if field.secret {
                if model.isRevealed(field) {
                    Button("Hide", systemImage: "eye.slash") { model.hide(field) }
                } else {
                    Button("Show", systemImage: "eye") { Task { await model.reveal(field) } }
                }
            }
            Button("Large type", systemImage: "textformat.size.larger") { Task { await model.showLargeType(field) } }
            if field.role == .website, let url = VaultText.websiteURL(field.value ?? "") {
                Button("Open", systemImage: "safari") { openURL(url) }
            }
        }
    }
}

/// A key in several lines, monospaced, in a block that scrolls sideways.
struct KeyBlock: View {
    let text: String
    var colored = false

    var body: some View {
        ScrollView(.horizontal) {
            Group {
                if colored { Text(SecretText.attributed(text)) } else { Text(text) }
            }
            .font(.footnote.monospaced())
            .fixedSize()
            .padding(10)
        }
        .background(.quaternary.opacity(0.6), in: .rect(cornerRadius: 10, style: .continuous))
    }
}

/// A one-time password: hidden until the owner check, then the live code with a countdown. The
/// next code comes from the core when the period ends, while the item is on the screen.
struct TotpRow: View {
    let field: FieldView
    let model: ItemDetailModel
    @ScaledMetric(relativeTo: .title2) private var ring: CGFloat = 26

    var body: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 3) {
                Text(field.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let shown = model.codes[field.name] {
                    Text(VaultText.groupedCode(shown.code.code))
                        .font(.title2.monospacedDigit().weight(.semibold))
                        .foregroundStyle(.tint)
                        .accessibilityLabel(VaultText.spokenCode(shown.code.code))
                } else {
                    Text(verbatim: "••• •••")
                        .font(.title2.monospaced())
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("hidden")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if model.working.contains(field.name) { ProgressView() }
            if let shown = model.codes[field.name] {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    countdown(shown, at: context.date)
                }
                Button {
                    Task { await model.copyCode(field) }
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Copy the one-time password")
            } else {
                Button {
                    Task { await model.showCode(field) }
                } label: {
                    Label("Show code", systemImage: "eye")
                }
                .buttonStyle(.borderless)
            }
        }
        .task(id: model.codes[field.name] != nil) {
            if model.codes[field.name] != nil { await model.runCode(field) }
        }
    }

    private func countdown(_ shown: ItemDetailModel.ShownCode, at date: Date) -> some View {
        let left = shown.remaining(at: date)
        let period = Double(max(1, shown.code.period))
        return ZStack {
            Circle()
                .stroke(.quaternary, lineWidth: 3)
            Circle()
                .trim(from: 0, to: left / period)
                .stroke(left < 6 ? Color.orange : Color.accentColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: left)
            Text("\(Int(left.rounded(.up)))")
                .font(.caption2.monospacedDigit().weight(.semibold))
        }
        .frame(width: ring, height: ring)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(Int(left.rounded(.up))) seconds left")
    }
}

// MARK: - Large type

/// A value across the screen, one character per cell with its position, so it can be typed on
/// another device.
struct LargeTypeView: View {
    let largeType: ItemDetailModel.LargeType
    let close: () -> Void

    private let columns = [GridItem(.adaptive(minimum: 52), spacing: 8)]

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVGrid(columns: columns, spacing: 8) {
                    ForEach(Array(largeType.value.enumerated()), id: \.offset) { index, character in
                        cell(index: index, character: character)
                    }
                }
                .padding()
            }
            .navigationTitle(largeType.label)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .close, action: close)
                }
            }
        }
    }

    private func cell(index: Int, character: Character) -> some View {
        let kind = VaultText.characterClass(character)
        return VStack(spacing: 4) {
            Text(kind == .space ? "␣" : String(character))
                .font(.system(size: 34, weight: .medium, design: .monospaced))
                .foregroundStyle(color(kind))
                .minimumScaleFactor(0.5)
            Text("\(index + 1)")
                .font(.caption2.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 64)
        .background(.quaternary.opacity(0.5), in: .rect(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(index + 1): \(kind == .space ? "space" : String(character))")
    }

    private func color(_ kind: VaultText.CharacterClass) -> Color {
        switch kind {
        case .digit: .blue
        case .symbol: .orange
        case .space: .secondary
        case .letter: .primary
        }
    }
}
