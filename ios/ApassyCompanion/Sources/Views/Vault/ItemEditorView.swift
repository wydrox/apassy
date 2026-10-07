import ApassyVaultKit
import SwiftUI

/// The form of a new or an edited item, in a sheet.
struct ItemEditorView: View {
    @State private var model: ItemEditorModel
    @Environment(VaultModel.self) private var vault
    @Environment(\.dismiss) private var dismiss
    /// The built-in field that the generator fills.
    @State private var generatorField: GeneratorTarget?
    @State private var scanningCode = false
    @State private var newTag = ""
    @State private var scanNote: String?

    struct GeneratorTarget: Identifiable {
        let name: String
        var id: String { name }
    }

    init(model: ItemEditorModel) {
        _model = State(initialValue: model)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $model.title)
                        .font(.headline)
                } header: {
                    Text("Title")
                }
                mainFields
                if model.kind == .login { loginExtras }
                detailsSection
                tagsSection
                Section("Notes") {
                    TextField("Notes", text: $model.notes, axis: .vertical)
                        .lineLimit(3...12)
                }
                if let error = model.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", role: .cancel) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(role: .confirm) {
                        Task {
                            if await model.save(in: vault) != nil { dismiss() }
                        }
                    } label: {
                        if model.isSaving { ProgressView() } else { Text("Save") }
                    }
                    .disabled(model.isSaving)
                }
            }
            .sheet(item: $generatorField) { target in
                GeneratorView(model: GeneratorModel(service: vault.service)) { value in
                    model.values[target.name] = value
                }
                .environment(vault)
            }
            .sheet(isPresented: $scanningCode) { otpScanner }
        }
        .interactiveDismissDisabled(model.isSaving)
    }

    private var title: String {
        guard model.isNew else { return "Edit “\(model.existing?.title ?? "")”" }
        return model.kind == .custom ? "New item" : "New \(VaultText.phrase(model.kind.label))"
    }

    // MARK: Fields of the kind

    @ViewBuilder
    private var mainFields: some View {
        Section {
            if model.kind == .custom {
                if model.isNew {
                    TextField("Field name, such as wifi_password", text: $model.customName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.body.monospaced())
                } else {
                    LabeledContent("Field name", value: model.customName)
                }
                SecretInput(
                    placeholder: model.isNew ? "Secret value" : "Unchanged", text: $model.customValue)
            }
            ForEach(model.specs) { spec in
                if spec.secret {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(spec.label)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if model.removedSecrets.contains(spec.name) {
                            HStack {
                                Text("Removed on save")
                                    .foregroundStyle(.secondary)
                                Spacer()
                                Button("Undo") { model.removedSecrets.remove(spec.name) }
                                    .buttonStyle(.borderless)
                            }
                        } else {
                            SecretInput(
                                placeholder: model.isUnchanged(spec.name) ? "Unchanged" : spec.label,
                                text: value(spec.name), multiline: spec.multiline,
                                onGenerate: spec.role == .password
                                    ? { generatorField = GeneratorTarget(name: spec.name) } : nil)
                        }
                        if !spec.required, model.storedSecrets.contains(spec.name), !model.removedSecrets.contains(spec.name) {
                            Button("Remove \(VaultText.phrase(spec.label))", role: .destructive) {
                                model.values[spec.name] = nil
                                model.removedSecrets.insert(spec.name)
                            }
                            .buttonStyle(.borderless)
                            .font(.footnote)
                        }
                    }
                } else {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(spec.label)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        TextField(spec.label, text: value(spec.name), axis: spec.multiline ? .vertical : .horizontal)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .font(spec.multiline ? .footnote.monospaced() : .body)
                            .keyboardType(spec.role == .username ? .emailAddress : .default)
                    }
                }
            }
        } header: {
            Text(model.kind.label)
        } footer: {
            if !model.isNew {
                Text("A secret that you leave empty keeps its stored value.")
            }
        }
    }

    private var loginExtras: some View {
        Group {
            Section("Website") {
                TextField("https://example.com", text: $model.website)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            Section {
                if model.otpRemoved {
                    HStack {
                        Text("Removed on save")
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button("Undo") { model.otpRemoved = false }
                            .buttonStyle(.borderless)
                    }
                } else {
                    SecretInput(
                        placeholder: model.otpStored ? "Unchanged" : "otpauth:// link or setup key", text: $model.otp)
                    Button("Scan QR code", systemImage: "qrcode.viewfinder") {
                        scanNote = nil
                        scanningCode = true
                    }
                    if model.otpStored {
                        Button("Remove one-time password", role: .destructive) {
                            model.otp = ""
                            model.otpRemoved = true
                        }
                    }
                }
            } header: {
                Text("One-time password")
            } footer: {
                Text("The setup code of the website: the QR code, or the key under it.")
            }
        }
    }

    private var otpScanner: some View {
        NavigationStack {
            VStack(spacing: 16) {
                CodeScannerPanel(
                    accessibilityLabel: "Camera for the setup code", use: "to read the setup code of the one-time password"
                ) { text in
                    if let uri = VaultText.otpURI(from: text) {
                        model.otp = uri
                        scanningCode = false
                    } else {
                        scanNote = "This is not the setup code of a one-time password."
                    }
                }
                if let scanNote {
                    CalloutView(symbol: "exclamationmark.triangle.fill", text: scanNote)
                }
                Spacer()
            }
            .padding()
            .navigationTitle("Scan the setup code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .close) { scanningCode = false }
                }
            }
        }
    }

    // MARK: Custom details

    private var detailsSection: some View {
        Section {
            ForEach($model.details) { $detail in
                VStack(alignment: .leading, spacing: 8) {
                    TextField("Label", text: $detail.label)
                        .font(.caption.weight(.semibold))
                    if detail.hidden {
                        SecretInput(placeholder: detail.stored ? "Unchanged" : "Value", text: $detail.value)
                    } else {
                        TextField("Value", text: $detail.value, axis: .vertical)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                    Toggle("Hidden", isOn: $detail.hidden)
                        .font(.footnote)
                }
            }
            .onDelete { model.removeDetails(at: $0) }
            Button("Add a detail", systemImage: "plus.circle") { model.addDetail() }
                .disabled(!model.canAddDetail)
        } header: {
            Text("Custom details")
        } footer: {
            Text("At most 10. A hidden detail shows only after Face ID or the passphrase.")
        }
    }

    private var tagsSection: some View {
        Section {
            if !model.tags.isEmpty {
                FlowLayout(spacing: 8) {
                    ForEach(model.tags, id: \.self) { tag in
                        TagChip(text: tag) { model.removeTag(tag) }
                    }
                }
                .padding(.vertical, 4)
            }
            HStack {
                TextField("Add a tag", text: $newTag)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .onSubmit(addTag)
                Button("Add", action: addTag)
                    .buttonStyle(.borderless)
                    .disabled(newTag.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if let message = model.tagMessage {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Tags")
        }
    }

    private func addTag() {
        if model.addTag(newTag) { newTag = "" }
    }

    private func value(_ name: String) -> Binding<String> {
        Binding(get: { model.values[name] ?? "" }, set: { model.values[name] = $0 })
    }
}

/// A secret that the owner types: hidden with a show button, or in several lines for a key.
struct SecretInput: View {
    let placeholder: String
    @Binding var text: String
    var multiline = false
    var onGenerate: (() -> Void)?
    @State private var shows = false

    var body: some View {
        HStack(spacing: 12) {
            Group {
                if multiline {
                    // A key is pasted in several lines; a secure field would join them.
                    TextField(placeholder, text: $text, axis: .vertical)
                        .font(.footnote.monospaced())
                        .lineLimit(3...8)
                } else if shows {
                    TextField(placeholder, text: $text)
                        .font(.body.monospaced())
                } else {
                    SecureField(placeholder, text: $text)
                }
            }
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            if !multiline {
                Button {
                    shows.toggle()
                } label: {
                    Image(systemName: shows ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(shows ? "Hide what you typed" : "Show what you typed")
            }
            if let onGenerate {
                Button(action: onGenerate) {
                    Label("Generate", systemImage: "dice")
                        .labelStyle(.iconOnly)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Generate a password")
            }
        }
    }
}
