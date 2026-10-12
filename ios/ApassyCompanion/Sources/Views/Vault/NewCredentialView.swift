import ApassyVaultKit
import SwiftUI

/// "New Credential", in a sheet: paste (or scan a QR code), then Add (ADR 0025 §4, ADR 0026 §4
/// and §8). "Fill in by hand" turns the sheet into the full editor of a kind.
struct NewCredentialView: View {
    /// The folder that the sheet opened in; nil: the top level.
    let folder: String?
    @Environment(VaultModel.self) private var vault
    /// The kind of the full editor, after "Fill in by hand".
    @State private var manualKind: ItemKind?
    @State private var manualFolder: String?

    init(folder: String?) {
        self.folder = folder
    }

    var body: some View {
        if let manualKind {
            ItemEditorView(model: ItemEditorModel(kind: manualKind, folder: manualFolder))
        } else {
            PasteSheet(model: NewCredentialModel(service: vault.service, folder: folder)) { kind, folder in
                manualFolder = folder
                manualKind = kind
            }
        }
    }
}

/// The paste field, the detected rows, and the folder.
private struct PasteSheet: View {
    @State private var model: NewCredentialModel
    let onManual: (ItemKind, String?) -> Void
    @Environment(VaultModel.self) private var vault
    @Environment(\.dismiss) private var dismiss
    @FocusState private var editing: Bool
    @State private var scanning = false
    /// Three lines of the field, so the card keeps its size when the mask shows.
    @ScaledMetric(relativeTo: .body) private var maskHeight: CGFloat = 60

    init(model: NewCredentialModel, onManual: @escaping (ItemKind, String?) -> Void) {
        _model = State(initialValue: model)
        self.onManual = onManual
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
                    if !model.folders.isEmpty {
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
                Section {
                    Menu {
                        ForEach(ItemKind.allCases) { kind in
                            Button(kind.label, systemImage: kind.symbol) {
                                let folder = model.folder
                                model.clear()
                                onManual(kind, folder)
                            }
                        }
                    } label: {
                        Label("Fill in by hand", systemImage: "square.and.pencil")
                    }
                } footer: {
                    Text("A login, an SSH key, or another kind, field by field.")
                }
            }
            .navigationTitle("New Credential")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel) { close() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(role: .confirm) {
                        editing = false
                        Task {
                            if await model.add(in: vault) != nil { dismiss() }
                        }
                    } label: {
                        if model.isAdding { ProgressView() } else { Text(model.addLabel) }
                    }
                    .disabled(!model.canAdd)
                }
            }
            .sheet(isPresented: $scanning) { scanner }
        }
        .interactiveDismissDisabled(model.isAdding)
        .task { await model.loadFolders() }
        #if targetEnvironment(simulator)
            .task { await fillFromLaunchArgument() }
        #endif
        // Each way out drops the paste: Cancel, Add, a swipe down, and the lock.
        .onDisappear { model.clear() }
        .onChange(of: vault.isUnlocked) { _, unlocked in
            if !unlocked { close() }
        }
        // The app left the screen: the field shows the masks again.
        .onChange(of: vault.revealEpoch) { editing = false }
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
            HStack(spacing: 8) {
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
            .background(red ? Color.red.opacity(0.12) : Color.secondary.opacity(0.12), in: .rect(cornerRadius: 7))
            .fixedSize()
    }
}

/// The folder of an item: its path, and a menu of the folder tree with indented names. "New
/// Credential" and the editor show it.
struct FolderMenuRow: View {
    let folders: [Folder]
    @Binding var selection: String?

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
                    Text(FolderMenu.label(folders, selection))
                        .lineLimit(1)
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.caption)
                }
            }
            .accessibilityLabel("Folder, \(FolderMenu.label(folders, selection))")
        }
    }
}
