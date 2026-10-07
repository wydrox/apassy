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

    var title: String
    var notes: String
    private(set) var tags: [String]
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
    /// Optional built-in secrets of the stored item that the owner removes.
    var removedSecrets: Set<String> = []
    private(set) var error: String?
    private(set) var tagMessage: String?
    private(set) var isSaving = false

    private(set) var storedSecrets: Set<String> = []
    private(set) var otpStored = false
    private var websiteKey = Key.label("Website")
    private var otpKey = Key.label("One-time password")
    /// Fields of the stored item that the form does not show.
    private var extras: [DraftField] = []

    /// A new item of `kind`.
    init(kind: ItemKind) {
        self.kind = kind
        existing = nil
        title = ""
        notes = ""
        tags = []
    }

    /// An existing item. Secret values are not read: they start empty ("Unchanged").
    init(detail: ItemDetail) {
        kind = detail.row.kind
        existing = detail.row
        title = detail.row.title
        notes = detail.notes
        tags = detail.row.tags
        let specs = Self.specs(kind)
        for field in detail.fields {
            if !field.custom, specs.contains(where: { $0.name == field.name }) {
                if field.secret { storedSecrets.insert(field.name) } else { values[field.name] = field.value ?? "" }
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
    }

    var isNew: Bool { existing == nil }

    static let builtInNames: Set<String> = [
        "username", "password", "token", "private_key", "passphrase", "host", "database", "public_key", "service",
        "project", "website", "url",
    ]

    /// The built-in fields of a kind, in the order of the Mac.
    static func specs(_ kind: ItemKind) -> [FieldSpec] {
        switch kind {
        case .login:
            [
                FieldSpec(name: "username", label: "Username", secret: false, required: true, role: .username),
                FieldSpec(name: "password", label: "Password", secret: true, required: true, role: .password),
            ]
        case .apiKey:
            [
                FieldSpec(name: "token", label: "Token", secret: true, required: true, role: .token),
                FieldSpec(name: "service", label: "Service", secret: false, required: false, role: .service),
                FieldSpec(name: "project", label: "Project", secret: false, required: false, role: .project),
            ]
        case .sshKey:
            [
                FieldSpec(
                    name: "private_key", label: "Private key", secret: true, required: true, multiline: true,
                    role: .privateKey),
                FieldSpec(name: "passphrase", label: "Key passphrase", secret: true, required: false, role: .keyPassphrase),
                FieldSpec(
                    name: "public_key", label: "Public key", secret: false, required: false, multiline: true,
                    role: .publicKey),
            ]
        case .database:
            [
                FieldSpec(name: "host", label: "Host", secret: false, required: true, role: .host),
                FieldSpec(name: "database", label: "Database", secret: false, required: true, role: .database),
                FieldSpec(name: "username", label: "Username", secret: false, required: true, role: .username),
                FieldSpec(name: "password", label: "Password", secret: true, required: true, role: .password),
            ]
        case .custom:
            []
        }
    }

    var specs: [FieldSpec] { Self.specs(kind) }

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
            title: title.trimmingCharacters(in: .whitespacesAndNewlines), kind: kind, notes: notes, tags: tags,
            fields: fields)
    }

    /// Save through the vault. The core's message shows on failure.
    func save(in vault: VaultModel) async -> SavedItem? {
        guard !isSaving else { return nil }
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            error = "Type a title."
            return nil
        }
        isSaving = true
        defer { isSaving = false }
        do {
            let saved = try await vault.save(id: existing?.id, revision: existing?.revision, draft: draft())
            error = nil
            return saved
        } catch {
            self.error = error.localizedDescription
            return nil
        }
    }
}
