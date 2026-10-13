import Foundation

/// The folders and the credential options of the preview vault: "Acme" › "Billing" and
/// "Personal", providers Stripe, GitHub, and PostgreSQL, and one production credential ("Stripe
/// live key"). The detection knows a few synthetic shapes (`sk_live_`, `sk_test_`, `ghp_`,
/// `postgres://`, and `.env` lines) and follows the rules of the core closely enough for the
/// screens. No value is real, and nothing leaves the process.
public struct PreviewOrganize: Sendable {
    /// The UUIDs of the sample folders.
    public enum FolderID {
        public static let acme = "0d5f8a2c-4b1e-4c3a-9e7d-acme00000001"
        public static let billing = "0d5f8a2c-4b1e-4c3a-9e7d-b111ing00002"
        public static let personal = "0d5f8a2c-4b1e-4c3a-9e7d-pe2s0na10003"
    }

    /// What the credential screen shows besides the row.
    struct Options: Sendable {
        var envName: String? = nil
        var alwaysAsk = false
        var environment: CredentialEnvironment? = nil
        var source: DeclarationSource? = nil

        /// The red dot: production that the owner or a signal set.
        var production: Bool { environment == .production && source?.isConfirmed == true }
    }

    static let sampleFolders = [
        Folder(uuid: FolderID.acme, parent: nil, name: "Acme", position: 0, count: 0),
        Folder(uuid: FolderID.billing, parent: FolderID.acme, name: "Billing", position: 0, count: 0),
        Folder(uuid: FolderID.personal, parent: nil, name: "Personal", position: 1, count: 0),
    ]

    /// The folders; `count` is computed when they are read.
    var folders: [Folder] = []
    var options: [UInt64: Options] = [:]

    public init() {}
}

/// A detection with its values, inside the preview only.
private struct PreviewFound {
    var found: DetectedCredential
    var fields: [(name: String, label: String, role: FieldRole, value: String, secret: Bool)]
}

extension PreviewVaultService {
    private static let mask = "••••••••"

    // MARK: Helpers

    private func requireFolder(_ uuid: String) throws {
        guard organizeState.folders.contains(where: { $0.uuid == uuid }) else {
            throw VaultError(.notFound, "The folder is gone. Another device may have deleted it.")
        }
    }

    private func depth(_ uuid: String?) -> Int { organizeState.folders.path(to: uuid).count }

    private func subtree(_ uuid: String) -> Set<String> {
        var found: Set<String> = [uuid]
        var grew = true
        while grew {
            grew = false
            for folder in organizeState.folders where folder.parent.map(found.contains) == true && !found.contains(folder.uuid) {
                found.insert(folder.uuid)
                grew = true
            }
        }
        return found
    }

    /// Levels below `uuid`, the folder itself counting 1.
    private func height(_ uuid: String) -> Int {
        let below = organizeState.folders.children(of: uuid).map { height($0.uuid) }.max() ?? 0
        return below + 1
    }

    private static func cleanName(_ name: String) throws -> String {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.utf8.count <= Folder.maxNameBytes,
            !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else {
            throw VaultError(
                .invalidInput,
                "Type a name of at most \(Folder.maxNameBytes) bytes, without control characters. Folders nest at most \(Folder.maxDepth) levels deep."
            )
        }
        return name
    }

    private func requireFreeName(_ name: String, in parent: String?, except: String? = nil) throws {
        if organizeState.folders.contains(where: {
            $0.parent == parent && $0.uuid != except && $0.name.lowercased() == name.lowercased()
        }) {
            throw VaultError(.exists, "A folder with this name is already there.")
        }
    }

    private func nextPosition(in parent: String?) -> Int64 {
        (organizeState.folders.children(of: parent).map(\.position).max() ?? -1) + 1
    }

    /// The detail with the folder path and the options, as the core answers it.
    func organizeDetail(_ detail: ItemDetail) -> ItemDetail {
        var detail = detail
        let options = organizeState.options[detail.id] ?? PreviewOrganize.Options()
        detail.folderPath = organizeState.folders.path(to: detail.row.folder)
        detail.envName = options.envName
        detail.alwaysAsk = options.alwaysAsk
        detail.environment = options.environment
        detail.environmentSource = options.source
        return detail
    }

    // MARK: Folders

    public func folders() async throws -> [Folder] {
        try requireUnlocked()
        // Depth first; each level by position, then name.
        func level(_ parent: String?) -> [Folder] {
            organizeState.folders.children(of: parent)
                .sorted { ($0.position, $0.name) < ($1.position, $1.name) }
                .flatMap { folder -> [Folder] in
                    var folder = folder
                    folder.count = items.values.filter { $0.row.folder == folder.uuid && !$0.row.archived }.count
                    return [folder] + level(folder.uuid)
                }
        }
        return level(nil)
    }

    public func createFolder(parent: String?, name: String) async throws -> Folder {
        try requireUnlocked()
        let name = try Self.cleanName(name)
        if let parent { try requireFolder(parent) }
        guard depth(parent) + 1 <= Folder.maxDepth else {
            throw VaultError(
                .invalidInput,
                "Type a name of at most \(Folder.maxNameBytes) bytes, without control characters. Folders nest at most \(Folder.maxDepth) levels deep."
            )
        }
        try requireFreeName(name, in: parent)
        let folder = Folder(
            uuid: UUID().uuidString.lowercased(), parent: parent, name: name, position: nextPosition(in: parent),
            count: 0)
        organizeState.folders.append(folder)
        return folder
    }

    public func renameFolder(uuid: String, name: String) async throws {
        try requireUnlocked()
        let name = try Self.cleanName(name)
        try requireFolder(uuid)
        guard let index = organizeState.folders.firstIndex(where: { $0.uuid == uuid }) else { return }
        guard organizeState.folders[index].name != name else { return }
        try requireFreeName(name, in: organizeState.folders[index].parent, except: uuid)
        organizeState.folders[index].name = name
    }

    public func moveFolder(uuid: String, parent: String?) async throws {
        try requireUnlocked()
        try requireFolder(uuid)
        if let parent {
            try requireFolder(parent)
            guard !subtree(uuid).contains(parent) else {
                throw VaultError(
                    .invalidInput,
                    "A folder cannot move into itself or one of its subfolders. Folders nest at most \(Folder.maxDepth) levels deep."
                )
            }
        }
        guard let index = organizeState.folders.firstIndex(where: { $0.uuid == uuid }) else { return }
        guard organizeState.folders[index].parent != parent else { return }
        guard depth(parent) + height(uuid) <= Folder.maxDepth else {
            throw VaultError(
                .invalidInput,
                "A folder cannot move into itself or one of its subfolders. Folders nest at most \(Folder.maxDepth) levels deep."
            )
        }
        try requireFreeName(organizeState.folders[index].name, in: parent, except: uuid)
        organizeState.folders[index].position = nextPosition(in: parent)
        organizeState.folders[index].parent = parent
    }

    public func deleteFolder(uuid: String) async throws -> Int {
        try requireUnlocked()
        try requireFolder(uuid)
        let parent = organizeState.folders.first { $0.uuid == uuid }?.parent
        var moved = 0
        for (id, item) in items where item.row.folder == uuid {
            items[id]?.row.folder = parent
            moved += 1
        }
        var position = nextPosition(in: parent)
        for index in organizeState.folders.indices where organizeState.folders[index].parent == uuid {
            organizeState.folders[index].parent = parent
            organizeState.folders[index].position = position
            position += 1
        }
        organizeState.folders.removeAll { $0.uuid == uuid }
        return moved
    }

    public func setItemFolder(id: UInt64, folder: String?) async throws {
        _ = try stored(id)
        if let folder { try requireFolder(folder) }
        items[id]?.row.folder = folder
    }

    // MARK: Adding by paste

    public func detect(text: String) async throws -> [DetectedCredential] {
        try requireUnlocked()
        guard text.utf8.count <= 1_048_576 else {
            throw VaultError(.invalidInput, "The text is too large. Paste at most 1 MB.")
        }
        return Self.previewDetect(text).map(\.found)
    }

    public func addPasted(text: String, folder: String?, pick: [Int]?, titles: [Int: String]) async throws
        -> [PastedItem]
    {
        try requireUnlocked()
        let found = Self.previewDetect(text)
        guard !found.isEmpty else {
            throw VaultError(
                .invalidInput,
                "Apassy found no credential in the text. Paste a secret, a KEY=value line, a .env file, a URL with a password, or an otpauth:// link."
            )
        }
        let picked = pick ?? Array(found.indices)
        guard Set(picked).count == picked.count, picked.allSatisfy(found.indices.contains),
            titles.keys.allSatisfy(found.indices.contains)
        else {
            throw VaultError(.invalidInput, "The picked credentials do not match the text. Paste it again.")
        }
        guard !picked.isEmpty else { throw VaultError(.invalidInput, "Pick at least one credential.") }
        if let folder {
            guard organizeState.folders.contains(where: { $0.uuid == folder }) else {
                throw VaultError(.notFound, "The folder is gone. Select another folder.")
            }
        }
        var added: [PastedItem] = []
        for index in picked.sorted() {
            var one = found[index]
            if let typed = titles[index]?.trimmingCharacters(in: .whitespacesAndNewlines), !typed.isEmpty {
                one.found.title = typed
            }
            added.append(insertPasted(one, folder: folder))
        }
        return added
    }

    private func freeTitle(_ title: String) -> String {
        let taken = Set(items.values.map { $0.row.title.lowercased() })
        guard taken.contains(title.lowercased()) else { return title }
        var number = 2
        while taken.contains("\(title) \(number)".lowercased()) { number += 1 }
        return "\(title) \(number)"
    }

    private func insertPasted(_ one: PreviewFound, folder: String?) -> PastedItem {
        let id = nextID
        nextID += 1
        let now = Int64(Date().timeIntervalSince1970)
        let title = freeTitle(one.found.title)
        var secrets: [String: String] = [:]
        let fields = one.fields.map { field -> FieldView in
            if field.secret { secrets[field.name] = field.value }
            return FieldView(
                name: field.name, label: field.label, secret: field.secret, value: field.secret ? nil : field.value,
                role: field.role, custom: false)
        }
        let taken = Set(organizeState.options.values.compactMap(\.envName))
        let envName = one.found.envName.map { taken.contains($0) ? "APASSY_ITEM_\(id)" : $0 } ?? "APASSY_ITEM_\(id)"
        let options = PreviewOrganize.Options(
            envName: envName, environment: one.found.environment, source: one.found.environmentSource)
        let row = ItemRow(
            id: id, revision: 1, title: title, kind: one.found.kind,
            subtitle: fields.first { $0.role == .username || $0.role == .host }?.value ?? "", websites: [], tags: [],
            archived: false, hasTotp: false, conflictOf: nil, addedAt: now, changedAt: now, usedAt: nil,
            hasPassword: Self.storesPassword(secrets), folder: folder, provider: one.found.provider,
            production: options.production)
        items[id] = Stored(row: row, notes: "", fields: fields, secrets: secrets)
        organizeState.options[id] = options
        return PastedItem(
            id: id, revision: 1, title: title,
            summary: [title, envName, one.found.environment.rawValue].joined(separator: " · "))
    }

    // MARK: Options

    public func setItemOptions(id: UInt64, alwaysAsk: Bool?, environment: CredentialEnvironment?) async throws {
        _ = try stored(id)
        var options = organizeState.options[id] ?? PreviewOrganize.Options()
        if let alwaysAsk { options.alwaysAsk = alwaysAsk }
        if let environment {
            options.environment = environment
            options.source = .owner
        }
        organizeState.options[id] = options
        items[id]?.row.production = options.production
    }

    // MARK: The synthetic detection

    private static func previewDetect(_ text: String) -> [PreviewFound] {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.utf8.count <= 1_048_576 else { return [] }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).enumerated().map {
            (number: $0.offset + 1, text: $0.element.trimmingCharacters(in: .whitespaces))
        }
        let entries = lines.filter { !$0.text.isEmpty && !$0.text.hasPrefix("#") }
        let assignments = entries.compactMap { line in assignment(line.text).map { (line.number, $0.key, $0.value) } }
        let isEnv =
            assignments.count == entries.count
            && (entries.count >= 2 || assignments.first.map { $0.1 == $0.1.uppercased() && $0.1.contains("_") } == true)
        let values: [(line: Int?, key: String?, value: String)] =
            isEnv ? assignments.map { ($0.0, $0.1, $0.2) } : [(nil, nil, text)]
        return values.enumerated().map { index, entry in
            classify(entry.value, key: entry.key, line: entry.line, index: index)
        }
    }

    private static func assignment(_ line: String) -> (key: String, value: String)? {
        var line = Substring(line)
        if line.hasPrefix("export ") { line = line.dropFirst(7) }
        guard let equals = line.firstIndex(of: "=") else { return nil }
        let key = line[..<equals].trimmingCharacters(in: .whitespaces)
        var value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
        if value.count >= 2, let first = value.first, first == value.last, first == "\"" || first == "'" {
            value = String(value.dropFirst().dropLast())
        }
        guard let head = key.first, head.isLetter || head == "_",
            key.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }), !value.isEmpty
        else { return nil }
        return (key, value)
    }

    private static func titled(_ key: String) -> String {
        key.split(separator: "_").map { $0.prefix(1).uppercased() + $0.dropFirst().lowercased() }.joined(separator: " ")
    }

    private static func classify(_ value: String, key: String?, line: Int?, index: Int) -> PreviewFound {
        let key = key?.uppercased()
        func make(
            _ title: String, _ kind: ItemKind, _ provider: String?, _ envName: String?, _ hosts: [String],
            _ environment: CredentialEnvironment, _ source: DeclarationSource,
            _ fields: [(name: String, label: String, role: FieldRole, value: String, secret: Bool)],
            preview: (String) -> String
        ) -> PreviewFound {
            let summary = ([title] + (envName.map { [$0] } ?? []) + [environment.rawValue]).joined(separator: " · ")
            let shown = fields.map {
                DetectedField(name: $0.name, label: $0.label, secret: $0.secret, preview: $0.secret ? preview($0.value) : $0.value)
            }
            return PreviewFound(
                found: DetectedCredential(
                    index: index, title: title, kind: kind, provider: provider, envName: envName, hosts: hosts,
                    environment: environment, environmentSource: source, risk: "high", line: line, summary: summary,
                    fields: shown),
                fields: fields)
        }
        for (prefix, mode, environment) in [
            ("sk_live_", "live", CredentialEnvironment.production), ("sk_test_", "test", .development),
        ] where value.hasPrefix(prefix) && value.count > prefix.count {
            return make(
                "Stripe \(mode)", .apiKey, "Stripe", key ?? "STRIPE_SECRET_KEY", ["api.stripe.com"], environment,
                .signal, [("token", "Token", .token, value, true)], preview: { _ in prefix + mask })
        }
        if value.hasPrefix("ghp_"), value.count > 4 {
            return make(
                "GitHub token", .apiKey, "GitHub", key ?? "GITHUB_TOKEN", ["api.github.com"], .production, .default,
                [("token", "Token", .token, value, true)], preview: { _ in "ghp_" + mask })
        }
        if value.hasPrefix("postgres://") || value.hasPrefix("postgresql://"),
            let url = URLComponents(string: value), let host = url.host, let password = url.password
        {
            let database = url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            var fields: [(name: String, label: String, role: FieldRole, value: String, secret: Bool)] = [
                ("host", "Host", .host, url.port.map { "\(host):\($0)" } ?? host, false)
            ]
            if !database.isEmpty { fields.append(("database", "Database", .database, database, false)) }
            if let user = url.user { fields.append(("username", "Username", .username, user, false)) }
            fields.append(("password", "Password", .password, password, true))
            return make(
                "PostgreSQL database", .database, "PostgreSQL", key ?? "DATABASE_URL", [], .production, .default, fields,
                preview: { _ in mask })
        }
        let name = key?.lowercased() ?? "secret"
        return make(
            key.map(titled) ?? "Credential", .custom, nil, key, [], .production, .default,
            [(name, name, .other, value, true)], preview: { _ in mask })
    }
}
