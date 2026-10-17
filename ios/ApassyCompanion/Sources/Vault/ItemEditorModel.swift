import ApassyVaultKit
import Foundation
import Observation

/// The form of a new or an edited item, and the draft it sends (contract ios-core-v1, 5.3).
///
/// A secret of an existing item starts empty with the placeholder "Unchanged" and goes as
/// `value: nil`, which keeps the stored value, unless the owner types a new one. The kind of an
/// existing item cannot change. Fields that the form does not show are sent as they are, so an
/// edit on the iPhone never drops what a Mac stored.
@MainActor
@Observable
final class ItemEditorModel {
    /// A built-in field of a kind.
    struct FieldSpec: Equatable, Identifiable {
        let name: String
        let label: String
        let secret: Bool
        let required: Bool
        var multiline = false
        let role: FieldRole

        var id: String { name }
    }

    /// A custom detail: a label, a value, and whether it is hidden.
    struct Detail: Identifiable, Equatable {
        let id = UUID()
        var label: String
        var value: String
        var hidden: Bool
        /// The stored field name of a hidden detail that has a value. Its value stays while the
        /// field is empty, also when the label changes: the draft names the stored field.
        var storedName: String? = nil

        var stored: Bool { storedName != nil }
    }

    /// Where a field of the form came from: a built-in name, or the label of a custom detail.
    enum Key: Equatable {
        case name(String)
        case label(String)

        func field(_ value: String?, secret: Bool) -> DraftField {
            switch self {
            case .name(let name): .named(name, value, secret: secret)
            case .label(let label): .detail(label, value, secret: secret)
            }
        }
    }

    static let detailLimit = 10
    static let tagLimit = 32

    let kind: ItemKind
    /// The item that is edited, or nil for a new one.
    let existing: ItemRow?
    /// The passkey of the login. The form never shows its key and does not send it: the core
    /// keeps the passkey through the edit, and its password becomes optional.
    let passkey: PasskeySummary?

    var title: String
    var notes: String
    private(set) var tags: [String]
    var pendingTag = ""
    /// The built-in fields by name.
    var values: [String: String] = [:]
    /// A login: the website and the one-time password.
    var website = ""
    var otp = ""
    /// The one-time password of the stored item is removed on save.
    var otpRemoved = false
    /// The other kind: the name and the value of its main secret field.
    var customName = ""
    var customValue = ""
    var details: [Detail] = []
    /// The folder of the item; nil: the top level (contract 5.11, `item_folder_set`).
    var folder: String?
    /// The folder that the stored item is in; nil for a new item.
    private(set) var storedFolder: String?
    /// The folders of the vault, depth first. Empty until `loadFolders`, and with a core without
    /// folders: the form then shows no folder row.
    private(set) var folders: [Folder] = []
    private var foldersLoaded = false
    /// Optional built-in secrets of the stored item that the owner removes.
    var removedSecrets: Set<String> = []
    private(set) var error: String?
    /// The content was saved, but its destination could not be changed. Keep this visible
    /// until the owner retries successfully or explicitly leaves the editor.
    private(set) var moveFailure: String?
    private(set) var tagMessage: String?
    private(set) var isSaving = false

    private(set) var storedSecrets: Set<String> = []
    private(set) var otpStored = false
    private var websiteKey = Key.label("Website")
    private var otpKey = Key.label("One-time password")
    /// Fields of the stored item that the form does not show.
    private var extras: [DraftField] = []
    @ObservationIgnored private var initialForm: FormState?
    /// A successful write survives a later folder failure; retries address this exact item.
    private(set) var savedItem: SavedItem?
    private var savedDraft: ItemDraft?
    var savedTitle: String? { savedDraft?.title }
    var savedFolder: String? { storedFolder }

    /// Report only persisted content and its actual retained location. This also lets an owner
    /// explicitly leave after a folder failure and find the saved item through the same route.
    /// Draft edits made after that write are deliberately absent from the result.
    @discardableResult
    func reportSavedResult(to report: ([(id: UInt64, title: String)], String?) -> Void) -> Bool {
        guard !isSaving, let savedItem, let savedTitle else { return false }
        report([(id: savedItem.id, title: savedTitle)], savedFolder)
        return true
    }

    private struct FormState: Equatable {
        var title: String
        var notes: String
        var tags: [String]
        var pendingTag: String
        var values: [String: String]
        var website: String
        var otp: String
        var otpRemoved: Bool
        var customName: String
        var customValue: String
        var details: [Detail]
        var folder: String?
        var removedSecrets: Set<String>
    }

    private var form: FormState {
        FormState(
            title: title, notes: notes, tags: tags, pendingTag: pendingTag, values: values,
            website: website, otp: otp, otpRemoved: otpRemoved, customName: customName,
            customValue: customValue, details: details, folder: folder, removedSecrets: removedSecrets)
    }

    var hasChanges: Bool { initialForm.map { $0 != form } ?? false }
    var preventsDismissal: Bool { isSaving || hasChanges || moveFailure != nil }

    /// Visible requirements, before Save. The core remains the final validator.
    var validationMessages: [String] {
        var messages: [String] = []
        let name = title.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty { messages.append("Enter a name.") }
        if name.utf8.count > 128 { messages.append("Use a shorter name.") }
        for spec in specs where spec.required {
            let value = values[spec.name] ?? ""
            let empty =
                spec.secret ? value.isEmpty : value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            if empty && !(spec.secret && isUnchanged(spec.name)) {
                messages.append("Enter \(VaultText.phrase(spec.label)).")
            }
        }
        if kind == .custom {
            let name = customName.trimmingCharacters(in: .whitespaces)
            if customValue.isEmpty && !(storedSecrets.contains(name) && !isNew) {
                messages.append("Enter a secret value.")
            }
            if name.isEmpty {
                messages.append("Enter a field name.")
            } else if name.utf8.count > 64
                || !name.utf8.allSatisfy({
                    (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 95
                })
            {
                messages.append(
                    "Use letters, numbers or underscores for the field name (at most 64 characters).")
            }
        }
        if let folder, foldersLoaded, !folders.contains(where: { $0.uuid == folder }) {
            messages.append("Choose an available folder.")
        }
        if detailCount > Self.detailLimit { messages.append("An item has at most 10 custom details.") }
        if details.contains(where: {
            !$0.value.isEmpty && $0.label.trimmingCharacters(in: .whitespaces).isEmpty
        }) {
            messages.append("Give each custom detail a label.")
        }
        return messages
    }

    @discardableResult
    func commitPendingTag() -> Bool {
        guard !pendingTag.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            pendingTag = ""
            return true
        }
        guard addTag(pendingTag) else { return false }
        pendingTag = ""
        return true
    }

    /// A new item of `kind`, in `folder` (the folder that the owner adds in).
    init(kind: ItemKind, folder: String? = nil) {
        self.kind = kind
        existing = nil
        passkey = nil
        title = ""
        notes = ""
        tags = []
        self.folder = folder
        initialForm = form
    }

    /// An existing item. Secret values are not read: they start empty ("Unchanged").
    init(detail: ItemDetail) {
        kind = detail.row.kind
        existing = detail.row
        passkey = detail.passkey
        title = detail.row.title
        notes = detail.notes
        tags = detail.row.tags
        folder = detail.row.folder
        storedFolder = detail.row.folder
        let specs = Self.specs(kind)
        for field in detail.fields {
            if !field.custom, specs.contains(where: { $0.name == field.name }) {
                if field.secret {
                    storedSecrets.insert(field.name)
                } else {
                    values[field.name] = field.value ?? ""
                }
            } else if kind == .login, field.role == .website, website.isEmpty, !field.secret {
                website = field.value ?? ""
                websiteKey = field.custom ? .label(field.label) : .name(field.name)
            } else if kind == .login, field.role == .totp, !otpStored {
                otpStored = true
                otpKey = field.custom ? .label(field.label) : .name(field.name)
            } else if kind == .custom, !field.custom, field.secret, customName.isEmpty,
                !Self.builtInNames.contains(field.name)
            {
                customName = field.name
                storedSecrets.insert(field.name)
            } else if field.custom {
                details.append(
                    Detail(
                        label: field.label, value: field.secret ? "" : field.value ?? "", hidden: field.secret,
                        storedName: field.secret ? field.name : nil))
            } else {
                extras.append(.named(field.name, field.secret ? nil : field.value, secret: field.secret))
            }
        }
        initialForm = form
    }

    var isNew: Bool { existing == nil }

    static let builtInNames: Set<String> = [
        "username", "password", "token", "private_key", "passphrase", "host", "database", "public_key",
        "service",
        "project", "website", "url",
    ]

    /// The built-in fields of a kind, in the order of the Mac.
    static func specs(_ kind: ItemKind) -> [FieldSpec] {
        switch kind {
        case .login:
            [
                FieldSpec(
                    name: "username", label: "Username", secret: false, required: true, role: .username),
                FieldSpec(
                    name: "password", label: "Password", secret: true, required: true, role: .password),
            ]
        case .apiKey:
            [
                FieldSpec(name: "token", label: "Token", secret: true, required: true, role: .token),
                FieldSpec(
                    name: "service", label: "Service", secret: false, required: false, role: .service),
                FieldSpec(
                    name: "project", label: "Project", secret: false, required: false, role: .project),
            ]
        case .sshKey:
            [
                FieldSpec(
                    name: "private_key", label: "Private key", secret: true, required: true, multiline: true,
                    role: .privateKey),
                FieldSpec(
                    name: "passphrase", label: "Key passphrase", secret: true, required: false,
                    role: .keyPassphrase),
                FieldSpec(
                    name: "public_key", label: "Public key", secret: false, required: false, multiline: true,
                    role: .publicKey),
            ]
        case .database:
            [
                FieldSpec(name: "host", label: "Host", secret: false, required: true, role: .host),
                FieldSpec(
                    name: "database", label: "Database", secret: false, required: true, role: .database),
                FieldSpec(
                    name: "username", label: "Username", secret: false, required: true, role: .username),
                FieldSpec(
                    name: "password", label: "Password", secret: true, required: true, role: .password),
            ]
        case .custom:
            []
        }
    }

    /// The fields of the form. A login with a passkey signs in without a password, so its
    /// username and password are optional.
    var specs: [FieldSpec] {
        guard passkey != nil, kind == .login else { return Self.specs(kind) }
        return Self.specs(kind).map {
            FieldSpec(
                name: $0.name, label: $0.label, secret: $0.secret, required: false, multiline: $0.multiline,
                role: $0.role)
        }
    }

    /// A secret field of the stored item that keeps its value while it is empty.
    func isUnchanged(_ name: String) -> Bool {
        storedSecrets.contains(name) && (values[name] ?? "").isEmpty && !removedSecrets.contains(name)
    }

    // MARK: Custom details

    /// The custom details that the item has: the details, and a login's website and code.
    var detailCount: Int {
        var count = details.count
        if kind == .login {
            if !website.trimmingCharacters(in: .whitespaces).isEmpty { count += 1 }
            if !otp.isEmpty || (otpStored && !otpRemoved) { count += 1 }
        }
        return count
    }

    var canAddDetail: Bool { detailCount < Self.detailLimit }

    func addDetail() {
        guard canAddDetail else { return }
        details.append(Detail(label: "", value: "", hidden: false))
    }

    func removeDetails(at offsets: IndexSet) {
        for index in offsets.sorted(by: >) where details.indices.contains(index) {
            details.remove(at: index)
        }
    }

    func removeDetail(_ id: UUID) {
        details.removeAll { $0.id == id }
    }

    // MARK: Tags

    /// Add a tag. False with `tagMessage` when it cannot be added.
    @discardableResult
    func addTag(_ text: String) -> Bool {
        let tag = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !tag.isEmpty else { return false }
        if tags.contains(where: { $0.caseInsensitiveCompare(tag) == .orderedSame }) {
            tagMessage = "The item has this tag."
            return false
        }
        guard tag.utf8.count <= 64 else {
            tagMessage = "Use a shorter tag."
            return false
        }
        guard tags.count < Self.tagLimit else {
            tagMessage = "An item has at most 32 tags."
            return false
        }
        tagMessage = nil
        tags.append(tag)
        return true
    }

    func removeTag(_ tag: String) {
        tags.removeAll { $0 == tag }
        tagMessage = nil
    }

    // MARK: The folder

    /// Read the folder choices. A deleted stored folder follows the core to the top level;
    /// an explicit destination for a new item stays selected until the owner replaces it.
    func loadFolders(from service: any VaultService) async {
        do {
            folders = try await service.folders()
            foldersLoaded = true
        } catch let error as VaultError where VaultModel.lacksFolders(error) {
            // An older core cannot represent any folder; preserve its documented fallback.
            folders = []
            foldersLoaded = false
            folder = nil
            storedFolder = nil
            initialForm?.folder = nil
            return
        } catch {
            // Reading folders must never silently redirect an explicitly chosen destination.
            return
        }
        let known = Set(folders.map(\.uuid))
        if !isNew {
            if let folder, folder == storedFolder, !known.contains(folder) { self.folder = nil }
            if let initialFolder = initialForm?.folder, initialFolder == storedFolder, !known.contains(initialFolder) {
                initialForm?.folder = nil
            }
            if let storedFolder, !known.contains(storedFolder) { self.storedFolder = nil }
        }
    }

    /// Save moves the item: a new item that goes into a folder, or a stored item whose folder
    /// the owner changed.
    var movesFolder: Bool { folder != storedFolder }

    var folderLabel: String { FolderMenu.label(folders, folder) }

    // MARK: The draft

    /// The body that `save` sends.
    func draft() -> ItemDraft {
        var fields: [DraftField] = []
        if kind == .custom {
            let name = customName.trimmingCharacters(in: .whitespaces)
            let keeps = !isNew && storedSecrets.contains(name) && customValue.isEmpty
            fields.append(.named(name, keeps ? nil : customValue, secret: true))
        }
        for spec in specs {
            let typed = values[spec.name] ?? ""
            if spec.secret {
                if removedSecrets.contains(spec.name) { continue }
                if !typed.isEmpty {
                    fields.append(.named(spec.name, typed, secret: true))
                } else if storedSecrets.contains(spec.name) {
                    fields.append(.named(spec.name, nil, secret: true))
                } else if spec.required {
                    // The core says what is missing, in its words.
                    fields.append(.named(spec.name, "", secret: true))
                }
            } else {
                let value = typed.trimmingCharacters(in: .whitespacesAndNewlines)
                if value.isEmpty, !spec.required { continue }
                fields.append(.named(spec.name, value, secret: false))
            }
        }
        if kind == .login {
            let site = website.trimmingCharacters(in: .whitespacesAndNewlines)
            if !site.isEmpty { fields.append(websiteKey.field(site, secret: false)) }
            let code = otp.trimmingCharacters(in: .whitespacesAndNewlines)
            if !code.isEmpty {
                fields.append(otpKey.field(code, secret: true))
            } else if otpStored, !otpRemoved {
                fields.append(otpKey.field(nil, secret: true))
            }
        }
        for detail in details {
            let label = detail.label.trimmingCharacters(in: .whitespaces)
            if detail.hidden {
                if let storedName = detail.storedName, detail.value.isEmpty {
                    fields.append(DraftField(name: storedName, label: label, value: nil, secret: true))
                    continue
                }
                if label.isEmpty, detail.value.isEmpty { continue }
                fields.append(.detail(label, detail.value, secret: true))
            } else {
                let value = detail.value.trimmingCharacters(in: .whitespacesAndNewlines)
                if label.isEmpty, value.isEmpty { continue }
                fields.append(.detail(label, value, secret: false))
            }
        }
        fields += extras
        return ItemDraft(
            title: title.trimmingCharacters(in: .whitespacesAndNewlines), kind: kind, notes: notes,
            tags: tags,
            fields: fields)
    }

    /// Capture the complete submission before the first suspension, including its destination.
    /// A failed move retains the saved identity, so retry cannot create the item twice.
    func save(in vault: VaultModel) async -> SavedItem? {
        guard !isSaving else { return nil }
        guard commitPendingTag() else {
            error = tagMessage
            return nil
        }
        if let message = validationMessages.first {
            error = message
            return nil
        }
        let submitted = draft()
        let destination = folder
        let destinationLabel = folderLabel
        isSaving = true
        defer { isSaving = false }
        do {
            let saved: SavedItem
            if let savedItem, savedDraft == submitted {
                saved = savedItem
            } else {
                saved = try await vault.save(
                    id: savedItem?.id ?? existing?.id,
                    revision: savedItem?.revision ?? existing?.revision, draft: submitted)
                savedItem = saved
                savedDraft = submitted
            }
            if destination != storedFolder {
                do {
                    try await vault.service.setItemFolder(id: saved.id, folder: destination)
                    storedFolder = destination
                    await vault.didImport()
                } catch {
                    let message =
                        "Saved “\(submitted.title)”, but could not move it to \(destinationLabel). \(error.localizedDescription) Choose a folder and retry Save; the same item will be used."
                    moveFailure = message
                    self.error = message
                    if let retained = try? await vault.service.item(id: saved.id) {
                        storedFolder = retained.row.folder
                    }
                    if (error as? VaultError)?.code == .locked { vault.report(error) }
                    return nil
                }
            }
            error = nil
            moveFailure = nil
            return saved
        } catch {
            self.error = error.localizedDescription
            return nil
        }
    }

}
