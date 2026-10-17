import ApassyVaultKit
import SwiftUI

/// Choose Login, Paste, or Other while keeping the selected destination.
/// Paste also supports QR codes and batches (ADR 0025 §4, ADR 0026 §4 and §8).
struct NewCredentialView: View {
    /// The folder that the sheet opened in; nil: the top level.
    let folder: String?
    var onSaved: ([(id: UInt64, title: String)], String?) -> Void
    @Environment(VaultModel.self) private var vault
    /// The kind chosen for the full editor.
    @State private var manualKind: ItemKind?
    @State private var manualFolder: String?
    @State private var initialFolder: String?
    @State private var isPasting = false
    @State private var folders: [Folder] = []
    @State private var confirmsChooserDiscard = false
    @Environment(\.dismiss) private var dismiss

    init(
        folder: String?,
        onSaved: @escaping ([(id: UInt64, title: String)], String?) -> Void = { _, _ in }
    ) {
        self.folder = folder
        self.onSaved = onSaved
        _manualFolder = State(initialValue: folder)
        _initialFolder = State(initialValue: folder)
    }

    var body: some View {
        if let manualKind {
            ItemEditorView(model: ItemEditorModel(kind: manualKind, folder: manualFolder), onSaved: onSaved)
        } else if isPasting {
            PasteSheet(
                model: NewCredentialModel(service: vault.service, folder: manualFolder), onSaved: onSaved
            ) { kind, folder in
                manualFolder = folder
                manualKind = kind
            }
        } else {
            NavigationStack {
                Form {
                    Section {
                        Button("Login", systemImage: "person.crop.rectangle") { manualKind = .login }
                        Button("Paste", systemImage: "doc.on.clipboard") { isPasting = true }
                        Menu("Other", systemImage: "ellipsis.circle") {
                            ForEach(ItemKind.allCases.filter { $0 != .login }) { kind in
                                Button(kind.label, systemImage: kind.symbol) { manualKind = kind }
                            }
                        }
                    } footer: {
                        Text(
                            "Save a username and password with Login. Paste a key, a .env file or several credentials. Choose Other for an SSH key, database or custom item."
                        )
                    }
                    if !folders.isEmpty || manualFolder != nil {
                        Section {
                            FolderMenuRow(folders: folders, selection: $manualFolder)
                        }
                    }
                }
                .navigationTitle("New Credential")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel", role: .cancel) {
                            if manualFolder != initialFolder { confirmsChooserDiscard = true } else { dismiss() }
                        }
                        .confirmationDialog(
                            "Discard changes?", isPresented: $confirmsChooserDiscard, titleVisibility: .visible
                        ) {
                            Button("Discard Changes", role: .destructive) { dismiss() }
                            Button("Keep Editing") { confirmsChooserDiscard = false }
                        }
                    }
                }
            }
            .interactiveDismissDisabled(manualFolder != initialFolder)
            .task {
                do {
                    folders = try await vault.service.folders()
                } catch let error as VaultError where VaultModel.lacksFolders(error) {
                    folders = []
                    manualFolder = nil
                    initialFolder = nil
                } catch {}
            }
        }
    }
}

/// The paste field, the detected rows, and the folder.
private struct PasteSheet: View {
    @State private var model: NewCredentialModel
    let onManual: (ItemKind, String?) -> Void
    let onSaved: ([(id: UInt64, title: String)], String?) -> Void
    @Environment(VaultModel.self) private var vault
    @Environment(\.dismiss) private var dismiss
    @FocusState private var editing: Bool
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var scanning = false
    @State private var confirmsDiscard = false
    @State private var pendingManualKind: ItemKind?
    /// Three lines of the field, so the card keeps its size when the mask shows.
    @ScaledMetric(relativeTo: .body) private var maskHeight: CGFloat = 60

    init(
        model: NewCredentialModel,
        onSaved: @escaping ([(id: UInt64, title: String)], String?) -> Void,
        onManual: @escaping (ItemKind, String?) -> Void
    ) {
        _model = State(initialValue: model)
        self.onManual = onManual
        self.onSaved = onSaved
    }

    var body: some View {
        NavigationStack {
            Form {
                pasteSection
                if !model.rows.isEmpty {
                    foundSection
                } else if model.showsNothingFound {
                    Section {
                        Label(NewCredentialModel.nothingFound, systemImage: "text.magnifyingglass")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                } else if let message = model.detectError {
                    Section {
                        Label(message, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                }
                Section {
                    if !model.folders.isEmpty || model.folder != nil {
                        FolderMenuRow(folders: model.folders, selection: $model.folder)
                    }
                } footer: {
                    Text("Everything else is set automatically. Recognition runs on this iPhone.")
                }
                if let error = model.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
                Section("Create another way") {
                    Button("Login", systemImage: "person.crop.rectangle") { chooseManual(.login) }
                    Menu("Other", systemImage: "ellipsis.circle") {
                        ForEach(ItemKind.allCases.filter { $0 != .login }) { kind in
                            Button(kind.label, systemImage: kind.symbol) { chooseManual(kind) }
                        }
                    }
                }
            }
            .disabled(model.isAdding)
            .navigationTitle("Paste Credentials")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel, action: cancel)
                        .disabled(model.isAdding)
                        .confirmationDialog(
                            "Discard changes?", isPresented: $confirmsDiscard, titleVisibility: .visible
                        ) {
                            Button("Discard Changes", role: .destructive, action: discard)
                            Button("Keep Editing") {
                                confirmsDiscard = false
                                pendingManualKind = nil
                            }
                        } message: {
                            Text("The pasted text and your choices will be lost.")
                        }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(role: .confirm) {
                        editing = false
                        Task {
                            if let added = await model.add(in: vault) {
                                onSaved(added.map { (id: $0.id, title: $0.title) }, model.savedFolder)
                                dismiss()
                            }
                        }
                    } label: {
                        if model.isAdding { ProgressView() } else { Text(model.addLabel) }
                    }
                    .disabled(!model.canAdd)
                }
            }
            .sheet(isPresented: $scanning) { scanner }
        }
        .interactiveDismissDisabled(model.preventsDismissal)
        .task { await model.loadFolders() }
        #if targetEnvironment(simulator)
            .task { await fillFromLaunchArgument() }
        #endif
        // Explicit discard, successful Add, and the lock drop the paste.
        .onDisappear { model.clear() }
        .onChange(of: vault.isUnlocked) { _, unlocked in
            if !unlocked { close() }
        }
        // The app left the screen (the background, the app switcher): the paste goes as revealed
        // values go, and the sheet stays open, empty.
        .onChange(of: vault.revealEpoch, initial: true) { _, epoch in
            editing = false
            model.follow(revealEpoch: epoch)
        }
    }

    private func cancel() {
        guard !model.isAdding else { return }
        pendingManualKind = nil
        if model.hasChanges { confirmsDiscard = true } else { close() }
    }

    private func chooseManual(_ kind: ItemKind) {
        guard !model.isAdding else { return }
        if model.hasText {
            pendingManualKind = kind
            confirmsDiscard = true
        } else {
            onManual(kind, model.folder)
        }
    }

    private func discard() {
        guard !model.isAdding else { return }
        if let kind = pendingManualKind {
            let folder = model.folder
            model.clear()
            onManual(kind, folder)
        } else {
            close()
        }
    }

    private func close() {
        model.clear()
        dismiss()
    }

    // MARK: The paste

    /// The field shows the raw text only while the owner edits it; else the core's masks.
    private var showsMask: Bool { !editing && model.hasText }

    private var pasteSection: some View {
        Section {
            ZStack(alignment: .topLeading) {
                TextField(
                    "Paste a key, a .env file, a database URL, or an otpauth:// link.", text: $model.text,
                    axis: .vertical
                )
                .lineLimit(3...8)
                .font(.callout.monospaced())
                .focused($editing)
                // A secret: no suggestions, no learning, no writing tools, hidden in snapshots.
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .writingToolsBehavior(.disabled)
                .privacySensitive()
                // Hidden, the raw text must not size the card either.
                .opacity(showsMask ? 0 : 1)
                .frame(maxHeight: showsMask ? 0 : nil)
                .clipped()
                .accessibilityHidden(showsMask)
                .accessibilityLabel("Paste a credential")
                if showsMask {
                    Text(model.maskedText)
                        .font(.callout.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(8)
                        .frame(maxWidth: .infinity, minHeight: maskHeight, alignment: .topLeading)
                        .contentShape(.rect)
                        .onTapGesture { editing = true }
                        .accessibilityLabel("The pasted text, hidden")
                        .accessibilityHint("Double-tap to edit it.")
                        .accessibilityAddTraits(.isButton)
                }
            }
            .padding(.vertical, 4)
        } footer: {
            let layout =
                dynamicTypeSize.isAccessibilitySize
                ? AnyLayout(VStackLayout(alignment: .leading, spacing: 8))
                : AnyLayout(HStackLayout(spacing: 8))
            layout {
                PasteButton(payloadType: String.self) { strings in
                    guard let pasted = strings.first else { return }
                    Task { @MainActor in
                        editing = false
                        model.text = pasted
                        await model.detectNow()
                    }
                }
                .labelStyle(.titleAndIcon)
                .buttonBorderShape(.capsule)
                Button("Scan QR code", systemImage: "qrcode.viewfinder") {
                    editing = false
                    scanning = true
                }
                .buttonStyle(.bordered)
                .buttonBorderShape(.capsule)
                if model.hasText {
                    Button("Clear", systemImage: "xmark.circle") {
                        editing = false
                        model.clear()
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.circle)
                    .accessibilityLabel("Clear the pasted text")
                }
            }
            .font(.subheadline.weight(.semibold))
            .controlSize(.small)
            .padding(.top, 6)
            .textCase(nil)
        }
        // "Add" sends the text as it is: it cannot change meanwhile.
        .disabled(model.isAdding)
    }

    private var scanner: some View {
        NavigationStack {
            VStack(spacing: 16) {
                CodeScannerPanel(
                    accessibilityLabel: "Camera for the QR code of a credential",
                    use: "to read the QR code of a credential"
                ) { code in
                    // An otpauth:// code or any other text goes through the same detection.
                    scanning = false
                    Task { @MainActor in
                        model.text = code
                        await model.detectNow()
                    }
                }
                Spacer()
            }
            .padding()
            .navigationTitle("Scan a QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .close) { scanning = false }
                }
            }
        }
    }

    // MARK: The rows

    private var foundSection: some View {
        Section("Found") {
            ForEach(model.rows) { row in
                FoundRow(
                    row: row, hasCheckbox: model.hasChoices,
                    title: Binding(get: { row.title }, set: { model.setTitle($0, row: row.id) }),
                    keep: Binding(get: { row.keep }, set: { model.setKeep($0, row: row.id) }))
            }
        }
        // The checkboxes and the titles that "Add" sends stay as they are while it runs.
        .disabled(model.isAdding)
    }

    #if targetEnvironment(simulator)
        /// A development aid of the Simulator: `-ApassyPasteDemo stripe|env` fills the paste with
        /// synthetic values that the preview vault detects.
        private func fillFromLaunchArgument() async {
            let demo: String
            switch UserDefaults.standard.string(forKey: "ApassyPasteDemo") {
            case "stripe": demo = "sk_test_EXAMPLE00000000000000000000"
            case "env":
                demo = """
                    STRIPE_SECRET_KEY=sk_test_EXAMPLE00000000000000000000
                    GITHUB_TOKEN=ghp_EXAMPLE000000000000000000000000000000
                    DATABASE_URL=postgres://app:EXAMPLE-password@db.example.com:5432/app
                    """
            default: return
            }
            model.text = demo
            await model.detectNow()
        }
    #endif
}

/// One detected credential: the checkbox of a paste with several, the provider tile, the title
/// (editable), the Mac's line, the core's mask of the secret, and the environment cap.
private struct FoundRow: View {
    let row: NewCredentialModel.Row
    let hasCheckbox: Bool
    @Binding var title: String
    @Binding var keep: Bool

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            if hasCheckbox {
                Button {
                    keep.toggle()
                } label: {
                    Image(systemName: keep ? "checkmark.circle.fill" : "circle")
                        .font(.title2)
                        .foregroundStyle(keep ? Color.accentColor : Color.secondary)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Add \(row.found.title)")
                .accessibilityValue(keep ? "On" : "Off")
            }
            ProviderTile(
                style: .of(provider: row.found.provider, title: row.found.title, kind: row.found.kind),
                scale: 30 / 38)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    TextField(row.found.title, text: $title)
                        .font(.body)
                        .submitLabel(.done)
                        .accessibilityLabel("Title of the credential on row \(row.id + 1)")
                    if let cap = row.found.cap { EnvironmentCap(label: cap.label, red: cap.red) }
                }
                if row.keep, let message = row.nameValidationMessage {
                    Text(message)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                Text(row.found.rowLine)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                Text(row.masked)
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .accessibilityLabel("Secret, hidden")
            }
            .opacity(hasCheckbox && !keep ? 0.5 : 1)
        }
    }
}

/// The environment that a signal found, as the Mac's cap: red for production.
private struct EnvironmentCap: View {
    let label: String
    let red: Bool

    var body: some View {
        Text(label)
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .foregroundStyle(red ? Color.red : Color.secondary)
            .background(
                red ? Color.red.opacity(0.12) : Color.secondary.opacity(0.12), in: .rect(cornerRadius: 7)
            )
            .fixedSize()
    }
}

/// The folder of an item: its path, and a menu of the folder tree with indented names. "New
/// Credential" and the editor show it.
struct FolderMenuRow: View {
    let folders: [Folder]
    @Binding var selection: String?

    private var destinationLabel: String {
        if let selection, !folders.contains(where: { $0.uuid == selection }) { return "Unavailable folder" }
        return FolderMenu.label(folders, selection)
    }

    var body: some View {
        LabeledContent("Folder") {
            Menu {
                Picker("Folder", selection: $selection) {
                    ForEach(FolderMenu.choices(folders)) { choice in
                        Text(String(repeating: "\u{2003}", count: choice.depth) + choice.name)
                            .tag(choice.id)
                    }
                }
                .pickerStyle(.inline)
            } label: {
                HStack(spacing: 4) {
                    Text(destinationLabel)
                        .lineLimit(1)
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.caption)
                }
            }
            .accessibilityLabel("Folder, \(destinationLabel)")
        }
    }
}
