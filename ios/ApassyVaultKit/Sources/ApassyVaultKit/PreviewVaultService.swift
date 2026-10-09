import CryptoKit
import Foundation

/// A vault in memory with synthetic items, for `#Preview`, the model tests, and the UI
/// work before the core is linked. It follows the contract closely enough for the
/// screens: a join waits for two polls, the passphrase is `passphrase`, and a sync
/// changes nothing. No value in it is real.
public actor PreviewVaultService: VaultService {
    public static let passphrase = "preview passphrase"

    private struct Stored {
        var row: ItemRow
        var notes: String
        var fields: [FieldView]
        var secrets: [String: String]
        var passkey: Passkey? = nil
    }

    /// A synthetic passkey with a key made here.
    private struct Passkey {
        var summary: PasskeySummary
        var key: P256.Signing.PrivateKey
    }

    private var vaults: [VaultEntry]
    private var selected: String?
    private var unlocked: Bool
    private var join: JoinInfo?
    private var joinPolls = 0
    private var items: [UInt64: Stored] = [:]
    private var nextID: UInt64 = 100
    private var status: SyncStatus

    /// - Parameters:
    ///   - empty: no vault on this iPhone (the setup flow).
    ///   - unlocked: the vault starts unlocked.
    public init(empty: Bool = false, unlocked: Bool = true) {
        let vault = VaultEntry(
            id: "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c", name: "Personal",
            relayURL: nil, teamID: nil, deviceID: nil,
            addedAt: 1_791_000_000, syncSource: "icloud")
        vaults = empty ? [] : [vault]
        selected = empty ? nil : vault.id
        self.unlocked = !empty && unlocked
        status = SyncStatus(
            enabled: !empty, state: empty ? .off : .ok, message: empty ? "" : "Saved to the iCloud file.", version: 41,
            lastSyncAt: Int64(Date().timeIntervalSince1970) - 60, pushed: false, merged: nil)
        if !empty {
            for sample in Self.samples() {
                items[nextID] = Self.make(sample, id: nextID)
                nextID += 1
            }
        }
    }

    // MARK: - Synthetic items

    private struct Sample {
        var title: String
        var kind: ItemKind
        var tags: [String]
        var notes: String
        var fields: [(name: String, label: String, role: FieldRole, value: String, secret: Bool, custom: Bool)]
        var conflictOf: UInt64? = nil
        var archived = false
        var daysOld: Int64 = 3
    }

    private static func samples() -> [Sample] {
        [
            Sample(
                title: "GitHub", kind: .login, tags: ["work"], notes: "Personal account. Recovery codes are in the safe.",
                fields: [
                    ("username", "Username", .username, "octocat", false, false),
                    ("password", "Password", .password, "synthetic-Pw-7Hq2!kLm9x", true, false),
                    ("x_57656273697465", "Website", .website, "https://github.com", false, true),
                    (
                        "x_4f6e652d74696d652070617373776f7264", "One-time password", .totp,
                        "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP", true, true
                    ),
                ]),
            Sample(
                title: "Stripe live key", kind: .apiKey, tags: ["billing", "production"], notes: "",
                fields: [
                    ("service", "Service", .service, "stripe", false, false),
                    ("project", "Project", .project, "shop", false, false),
                    ("token", "Token", .token, "sk_synthetic_4eC39HqLyjWDarjtT1zdp7dc", true, false),
                ]),
            Sample(
                title: "OpenAI", kind: .apiKey, tags: ["ai"], notes: "",
                fields: [("token", "Token", .token, "synthetic-openai-key-0000", true, false)]),
            Sample(
                title: "Production Postgres", kind: .database, tags: ["production"], notes: "Read replica: db-ro.internal",
                fields: [
                    ("host", "Host", .host, "db.internal.example.com", false, false),
                    ("database", "Database", .database, "shop", false, false),
                    ("username", "Username", .username, "app", false, false),
                    ("password", "Password", .password, "short1", true, false),
                ]),
            Sample(
                title: "Deploy key", kind: .sshKey, tags: [], notes: "",
                fields: [
                    (
                        "private_key", "Private key", .privateKey,
                        "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n-----END OPENSSH PRIVATE KEY-----", true,
                        false
                    ),
                    ("public_key", "Public key", .publicKey, "deploy@ci", false, false),
                ]),
            Sample(
                title: "Netflix", kind: .login, tags: ["home"], notes: "",
                fields: [
                    ("username", "Username", .username, "family@example.com", false, false),
                    ("password", "Password", .password, "short1", true, false),
                    ("x_75726c", "url", .website, "netflix.com", false, true),
                ], daysOld: 500),
            Sample(
                title: "Wi-Fi at home", kind: .custom, tags: ["home"], notes: "Guest network: Apassy-Guest",
                fields: [("wifi_password", "wifi_password", .other, "synthetic wifi words", true, false)]),
            Sample(
                title: "GitHub (conflict copy, MacBook Pro)", kind: .login, tags: ["work"], notes: "",
                fields: [
                    ("username", "Username", .username, "octocat", false, false),
                    ("password", "Password", .password, "synthetic-older-Pw", true, false),
                ], conflictOf: 100),
            Sample(
                title: "Old Heroku", kind: .apiKey, tags: [], notes: "",
                fields: [("token", "Token", .token, "synthetic-heroku", true, false)], archived: true),
        ]
    }

    private func insert(_ sample: Sample) {
        items[nextID] = Self.make(sample, id: nextID)
        nextID += 1
    }

    private static func make(_ sample: Sample, id: UInt64) -> Stored {
        let now = Int64(Date().timeIntervalSince1970)
        let subtitle =
            sample.fields.first { $0.role == .username }?.value
            ?? sample.fields.first { $0.role == .host || $0.role == .publicKey || $0.role == .service }?.value
            ?? ""
        var secrets: [String: String] = [:]
        let fields = sample.fields.map { field -> FieldView in
            if field.secret { secrets[field.name] = field.value }
            return FieldView(
                name: field.name, label: field.label, secret: field.secret, value: field.secret ? nil : field.value,
                role: field.role, custom: field.custom)
        }
        let row = ItemRow(
            id: id, revision: 1, title: sample.title, kind: sample.kind, subtitle: subtitle,
            websites: sample.fields.filter { $0.role == .website }.map(\.value), tags: sample.tags,
            archived: sample.archived, hasTotp: sample.fields.contains { $0.role == .totp },
            conflictOf: sample.conflictOf, addedAt: now - 86_400 * 400, changedAt: now - 86_400 * sample.daysOld,
            usedAt: nil, hasPassword: Self.storesPassword(secrets))
        return Stored(row: row, notes: sample.notes, fields: fields, secrets: secrets)
    }

    // MARK: - Helpers

    /// As the core: a password counts when its value is not empty. The row says so without the value.
    private static func storesPassword(_ secrets: [String: String]) -> Bool {
        secrets["password"].map { !$0.isEmpty } == true
    }

    /// Test support: a stored secret password with no value. The ordinary calls refuse it, but
    /// the core can hold one (an older import). The row follows the stored value.
    func storeEmptyPasswordForTesting(id: UInt64) throws {
        var item = try stored(id)
        item.secrets["password"] = ""
        if !item.fields.contains(where: { $0.name == "password" }) {
            item.fields.append(
                FieldView(name: "password", label: "Password", secret: true, value: nil, role: .password, custom: false))
        }
        item.row.hasPassword = Self.storesPassword(item.secrets)
        items[id] = item
    }

    private func requireVault() throws {
        guard selected != nil else { throw VaultError(.noVault, "No vault is open on this iPhone.") }
    }

    private func requireUnlocked() throws {
        try requireVault()
        guard unlocked else { throw VaultError(.locked, "The vault is locked.") }
    }

    private func stored(_ id: UInt64) throws -> Stored {
        try requireUnlocked()
        guard let item = items[id] else { throw VaultError(.notFound, "This item is not in the vault any more.") }
        return item
    }

    private static func label(for name: String) -> (String, FieldRole) {
        switch name {
        case "username": ("Username", .username)
        case "password": ("Password", .password)
        case "token": ("Token", .token)
        case "private_key": ("Private key", .privateKey)
        case "passphrase": ("Key passphrase", .keyPassphrase)
        case "host": ("Host", .host)
        case "database": ("Database", .database)
        case "public_key": ("Public key", .publicKey)
        case "service": ("Service", .service)
        case "project": ("Project", .project)
        default: (name, .other)
        }
    }

    // MARK: - 5.1

    public func info() async throws -> CoreInfo {
        CoreInfo(vaults: vaults, selected: selected, unlocked: unlocked, join: join, schema: 16, version: "0.3.4")
    }

    public func select(vaultID: String) async throws {
        guard vaults.contains(where: { $0.id == vaultID }) else {
            throw VaultError(.noVault, "This vault is not on this iPhone.")
        }
        selected = vaultID
        unlocked = false
    }

    private var kept = false
    private var suspended = false

    public func suspend() async throws {
        if unlocked { suspended = true }
        unlocked = false
    }

    public func resume() async throws -> Bool {
        if suspended && kept { unlocked = true }
        suspended = false
        return unlocked
    }

    public func unlock(passphrase: String, keep: Bool) async throws {
        kept = keep
        try requireVault()
        try await Task.sleep(for: .milliseconds(300))
        guard passphrase == Self.passphrase else {
            throw VaultError(.wrongPassphrase, "The passphrase does not open this vault.")
        }
        unlocked = true
    }

    public func lock() async throws {
        unlocked = false
        kept = false
        suspended = false
    }

    public func checkPassphrase(_ passphrase: String) async throws -> Bool {
        try requireVault()
        return passphrase == Self.passphrase
    }

    public func createLocalVault(name: String, passphrase: String) async throws -> VaultEntry {
        guard passphrase.utf8.count >= 12 else {
            throw VaultError(.invalidInput, "The passphrase needs at least 12 characters.")
        }
        let vault = VaultEntry(
            id: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), name: name, relayURL: nil,
            teamID: nil, deviceID: nil, addedAt: Int64(Date().timeIntervalSince1970))
        vaults.append(vault)
        selected = vault.id
        unlocked = true
        return vault
    }

    public func openICloudVault(url: URL, name: String, passphrase: String) async throws -> VaultEntry {
        guard passphrase == Self.passphrase else {
            throw VaultError(.wrongPassphrase, "The passphrase does not open this vault.")
        }
        let vault = VaultEntry(id: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
            name: name, relayURL: nil, teamID: nil, deviceID: nil,
            addedAt: Int64(Date().timeIntervalSince1970), syncSource: "icloud")
        vaults.append(vault)
        selected = vault.id
        unlocked = true
        status = SyncStatus(enabled: true, state: .ok, message: "Saved to the iCloud file.",
            version: 1, lastSyncAt: Int64(Date().timeIntervalSince1970), pushed: false, merged: nil)
        return vault
    }

    public func reconnectICloudVault(url: URL, vaultID: String) async throws {
        try requireUnlocked()
        guard selected == vaultID, vaults.first(where: { $0.id == vaultID })?.isICloud == true else {
            throw VaultError(.invalidInput, "Select the iCloud vault first.")
        }
    }

    public func removeVault(id: String, force: Bool) async throws -> Bool {
        let leftRelay = vaults.first(where: { $0.id == id })?.isRelay == true
        vaults.removeAll { $0.id == id }
        if selected == id {
            selected = vaults.first?.id
            unlocked = false
            items = [:]
        }
        return leftRelay
    }

    // MARK: - 5.2

    public func joinStart(link: String, deviceName: String) async throws -> JoinInfo {
        guard link.contains("apassy_lnk_") else {
            throw VaultError(.linkInvalid, "This is not a device link of the Apassy relay.")
        }
        joinPolls = 0
        let info = JoinInfo(
            state: .waiting, team: "Personal", words: ["amber", "marble"],
            expiresAt: Int64(Date().timeIntervalSince1970) + 600)
        join = info
        return info
    }

    public func joinPoll() async throws -> JoinInfo {
        guard var info = join else { throw VaultError(.invalidInput, "No join waits.") }
        joinPolls += 1
        if joinPolls >= 2 { info.state = .ready }
        join = info
        return info
    }

    public func joinCancel() async throws { join = nil }

    public func joinFinish(passphrase: String) async throws -> VaultEntry {
        guard join?.state == .ready else { throw VaultError(.invalidInput, "The Mac did not confirm this iPhone yet.") }
        guard passphrase == Self.passphrase else {
            throw VaultError(.wrongPassphrase, "The passphrase does not open this vault.")
        }
        join = nil
        let vault = VaultEntry(
            id: "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c", name: "Personal", relayURL: "https://apassy-relay.wyderka.cc",
            teamID: "t_7k2m5q4x3c", deviceID: 3, addedAt: Int64(Date().timeIntervalSince1970))
        vaults = [vault]
        selected = vault.id
        unlocked = true
        status = SyncStatus(
            enabled: true, state: .ok, message: "Up to date.", version: 41,
            lastSyncAt: Int64(Date().timeIntervalSince1970), pushed: false, merged: nil)
        if items.isEmpty {
            for sample in Self.samples() { insert(sample) }
        }
        return vault
    }

    // MARK: - 5.3

    public func items(archived: ArchiveFilter) async throws -> [ItemRow] {
        try requireUnlocked()
        return items.values.map(\.row)
            .filter {
                switch archived {
                case .no: !$0.archived
                case .yes: $0.archived
                case .all: true
                }
            }
            .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }

    public func item(id: UInt64) async throws -> ItemDetail {
        let item = try stored(id)
        return ItemDetail(row: item.row, notes: item.notes, fields: item.fields, passkey: item.passkey?.summary)
    }

    public func reveal(id: UInt64, field: String) async throws -> String {
        let item = try stored(id)
        if let value = item.secrets[field] { return value }
        if let value = item.fields.first(where: { $0.name == field })?.value { return value }
        throw VaultError(.notFound, "This field is not in the item.")
    }

    public func totp(id: UInt64, field: String) async throws -> TotpCode {
        _ = try stored(id)
        let now = Int(Date().timeIntervalSince1970)
        let counter = now / 30
        let code = String(format: "%06d", (counter &* 7_919 &+ Int(id)) % 1_000_000)
        return TotpCode(code: code, period: 30, remaining: 30 - now % 30, digits: 6)
    }

    public func history(id: UInt64) async throws -> [ItemEvent] {
        let item = try stored(id)
        return [
            ItemEvent(at: item.row.changedAt ?? 0, kind: "edited", detail: "Changed on MacBook Pro"),
            ItemEvent(at: item.row.addedAt ?? 0, kind: "added", detail: "Added"),
        ]
    }

    public func save(id: UInt64?, revision: UInt64?, draft: ItemDraft) async throws -> SavedItem {
        try requireUnlocked()
        let title = draft.title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty else { throw VaultError(.invalidInput, "The item name is required.") }
        var old: Stored?
        if let id {
            old = try stored(id)
            guard old?.row.revision == revision else {
                throw VaultError(.conflict, "This item changed. Open it again to see the new version.")
            }
            guard old?.row.kind == draft.kind else {
                throw VaultError(.invalidInput, "The item category cannot change. Delete the item and add a new one.")
            }
        }
        var fields: [FieldView] = []
        var secrets: [String: String] = [:]
        for field in draft.fields {
            let name: String
            let label: String
            var role: FieldRole
            let custom = field.label != nil
            if let detail = field.label {
                name = "x_" + detail.utf8.map { String(format: "%02x", $0) }.joined()
                label = detail
                let lower = detail.lowercased()
                role = lower.hasPrefix("website") || lower.hasPrefix("url") ? .website : .other
                if field.secret, lower.hasPrefix("one-time password") { role = .totp }
            } else {
                name = field.name ?? ""
                (label, role) = Self.label(for: name)
            }
            if name.hasPrefix("passkey_") {
                throw VaultError(.invalidInput, "This field name is reserved.")
            }
            if field.secret {
                guard let value = field.value ?? old?.secrets[name], !value.isEmpty else {
                    throw VaultError(.invalidInput, "Enter a value for \(label).")
                }
                secrets[name] = value
            }
            fields.append(
                FieldView(
                    name: name, label: label, secret: field.secret,
                    value: field.secret ? nil : field.value?.trimmingCharacters(in: .whitespacesAndNewlines),
                    role: role, custom: custom))
        }
        let newID = id ?? nextID
        if id == nil { nextID += 1 }
        let now = Int64(Date().timeIntervalSince1970)
        let row = ItemRow(
            id: newID, revision: (revision ?? 0) + 1, title: title, kind: draft.kind,
            subtitle: fields.first { $0.role == .username }?.value ?? fields.first { $0.role == .host }?.value ?? "",
            websites: fields.filter { $0.role == .website }.compactMap(\.value), tags: draft.tags,
            archived: old?.row.archived ?? false, hasTotp: fields.contains { $0.role == .totp },
            conflictOf: old?.row.conflictOf, addedAt: old?.row.addedAt ?? now, changedAt: now, usedAt: nil,
            hasPasskey: old?.passkey != nil, hasPassword: Self.storesPassword(secrets))
        items[newID] = Stored(row: row, notes: draft.notes, fields: fields, secrets: secrets, passkey: old?.passkey)
        return SavedItem(id: newID, revision: row.revision)
    }

    public func archive(id: UInt64, archived: Bool) async throws {
        var item = try stored(id)
        item.row.archived = archived
        items[id] = item
    }

    public func delete(id: UInt64, revision: UInt64) async throws {
        let item = try stored(id)
        guard item.row.revision == revision else {
            throw VaultError(.conflict, "This item changed. Open it again to see the new version.")
        }
        items[id] = nil
    }

    // MARK: - 5.4

    public func generate(_ options: GeneratorOptions) async throws -> GeneratedPassword {
        var rng = SystemRandomNumberGenerator()
        switch options.style {
        case .pin:
            let value = String((0..<options.length).map { _ in "0123456789".randomElement(using: &rng)! })
            return GeneratedPassword(value: value, bits: Double(options.length) * log2(10))
        case .memorable:
            let words = ["amber", "marble", "river", "copper", "lantern", "meadow", "orbit", "velvet", "harbor", "cedar"]
            let picked = (0..<options.words).map { _ -> String in
                let word = words.randomElement(using: &rng)!
                return options.capitalize ? word.capitalized : word
            }
            return GeneratedPassword(
                value: picked.joined(separator: options.separator), bits: Double(options.words) * log2(7776))
        case .random:
            var alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if options.digits { alphabet += "0123456789" }
            if options.symbols { alphabet += "!#$%&*+-=?@^_~" }
            let value = String((0..<options.length).map { _ in alphabet.randomElement(using: &rng)! })
            return GeneratedPassword(value: value, bits: Double(options.length) * log2(Double(alphabet.count)))
        }
    }

    public func strength(_ value: String) async throws -> Strength {
        let bits = Double(value.count) * 4.5
        let score =
            switch bits {
            case ..<28: 0
            case ..<36: 1
            case ..<60: 2
            case ..<80: 3
            default: 4
            }
        return Strength(bits: bits, score: score)
    }

    public func watchtower() async throws -> WatchtowerReport {
        try requireUnlocked()
        let live = items.values.filter { !$0.row.archived }
        let weak = live.filter { ($0.secrets["password"]?.count ?? 99) < 8 }.map(\.row.id).sorted()
        var groups: [String: [UInt64]] = [:]
        for item in live {
            if let password = item.secrets["password"] { groups[password, default: []].append(item.row.id) }
        }
        let now = Int64(Date().timeIntervalSince1970)
        return WatchtowerReport(
            weak: weak, reused: groups.values.filter { $0.count > 1 }.map { $0.sorted() },
            old: live.filter { ($0.row.changedAt ?? now) < now - 86_400 * 365 && $0.secrets["password"] != nil }
                .map(\.row.id),
            conflicts: live.filter { $0.row.conflictOf != nil }.map(\.row.id),
            checked: live.filter { $0.secrets["password"] != nil }.count)
    }

    // MARK: - 5.5

    public func sync() async throws -> SyncStatus {
        try requireUnlocked()
        try await Task.sleep(for: .milliseconds(600))
        status.lastSyncAt = Int64(Date().timeIntervalSince1970)
        return currentSyncStatus()
    }

    private func currentSyncStatus() -> SyncStatus {
        guard let vault = vaults.first(where: { $0.id == selected }), vault.syncs else {
            return SyncStatus(enabled: false, state: .off, message: "", version: 0,
                lastSyncAt: nil, pushed: false, merged: nil)
        }
        var current = status
        current.enabled = true
        if vault.isICloud, current.state == .ok { current.message = "Saved to the iCloud file." }
        return current
    }

    public func syncStatus() async throws -> SyncStatus { currentSyncStatus() }

    public func syncWait(timeout: Int) async throws -> Bool {
        try requireUnlocked()
        try await Task.sleep(for: .seconds(max(1, min(timeout, 5))))
        return false
    }

    public func takeNewPassphrase(_ passphrase: String) async throws -> PassphraseChange {
        guard passphrase == Self.passphrase else {
            throw VaultError(.wrongPassphrase, "The passphrase does not open this vault.")
        }
        status.state = .ok
        return PassphraseChange(status: status, rekeyed: true)
    }

    public func useRelayCopy() async throws -> SyncStatus {
        guard vaults.first(where: { $0.id == selected })?.isRelay == true else {
            throw VaultError(.notAllowed, "This vault does not use a relay.")
        }
        status.state = .ok
        return status
    }

    public func devices() async throws -> [RelayDevice] {
        guard vaults.first(where: { $0.id == selected })?.isRelay == true else { return [] }
        let now = Int64(Date().timeIntervalSince1970)
        return [
            RelayDevice(id: 1, name: "Mac mini", this: false, lastSeenAt: now - 120),
            RelayDevice(id: 2, name: "MacBook Pro", this: false, lastSeenAt: now - 86_400),
            RelayDevice(id: 3, name: "iPhone", this: true, lastSeenAt: now),
        ]
    }

    // MARK: - 5.7

    private func fill(_ item: Stored) -> FillCandidate {
        FillCandidate(
            id: item.row.id, title: item.row.title, username: item.row.subtitle, website: item.row.websites.first,
            hasTotp: item.row.hasTotp)
    }

    public func autofillList(domains: [String]) async throws -> AutofillList {
        try requireUnlocked()
        let logins = items.values.filter { $0.row.kind == .login && !$0.row.archived }
            .sorted { $0.row.title < $1.row.title }
        let hosts = domains.map { $0.lowercased() }
        let matches = logins.filter { item in
            item.row.websites.contains { site in hosts.contains { site.lowercased().contains($0) } }
        }
        let others = logins.filter { item in !matches.contains { $0.row.id == item.row.id } }
        return AutofillList(matches: matches.map(fill), others: others.map(fill))
    }

    public func autofillCredential(id: UInt64) async throws -> FillCredential {
        let item = try stored(id)
        return FillCredential(username: item.row.subtitle, password: item.secrets["password"] ?? "")
    }

    public func identitySet() async throws -> IdentitySet {
        let passwords = try await credentialIdentities()
        let passkeys = activePasskeys().map {
            PasskeyIdentity(
                id: $0.row.id, rpID: $0.passkey!.summary.rpID, userName: $0.passkey!.summary.accountName,
                credentialID: $0.passkey!.summary.credentialID, userHandle: $0.passkey!.summary.userHandle)
        }
        let codes = items.values.filter { $0.row.kind == .login && !$0.row.archived && $0.row.hasTotp }
            .sorted { $0.row.id < $1.row.id }
            .flatMap { item in
                item.row.websites.compactMap { site -> CodeIdentity? in
                    guard let host = URL(string: site.contains("://") ? site : "https://\(site)")?.host() else { return nil }
                    return CodeIdentity(id: item.row.id, title: item.row.title, username: item.row.subtitle, host: host)
                }
            }
        return IdentitySet(passwords: passwords, passkeys: passkeys, codes: codes)
    }

    // MARK: - Passkeys

    private func activePasskeys() -> [Stored] {
        items.values.filter { $0.passkey != nil && !$0.row.archived && $0.row.conflictOf == nil }
            .sorted { $0.row.id < $1.row.id }
    }

    public func passkeys(rpID: String, allowed: [Data]) async throws -> [PasskeyCandidate] {
        try requireUnlocked()
        return activePasskeys().compactMap { item in
            guard let summary = item.passkey?.summary, summary.rpID == rpID,
                allowed.isEmpty || allowed.contains(summary.credentialID)
            else { return nil }
            return PasskeyCandidate(
                id: item.row.id, title: item.row.title, rpID: summary.rpID, userName: summary.userName,
                userDisplayName: summary.userDisplayName, credentialID: summary.credentialID,
                userHandle: summary.userHandle)
        }
    }

    public func passkeyAssert(_ request: PasskeyAssertionRequest) async throws -> PasskeyAssertion {
        try PasskeyRequestCheck.clientDataHash(request.clientDataHash)
        let item = try stored(request.id)
        guard let passkey = item.passkey, passkey.summary.rpID == request.rpID,
            passkey.summary.credentialID == request.credentialID
        else { throw VaultError(.notFound, "This passkey is not in the vault.") }
        let authenticator = PreviewAuthenticator(rpID: passkey.summary.rpID, key: passkey.key)
        let data = authenticator.assertionData()
        return PasskeyAssertion(
            credentialID: passkey.summary.credentialID, userHandle: passkey.summary.userHandle, authenticatorData: data,
            signature: try authenticator.sign(data, clientDataHash: request.clientDataHash))
    }

    public func passkeyRegister(_ request: PasskeyRegistration) async throws -> PasskeyCreated {
        try requireUnlocked()
        try PasskeyRequestCheck.clientDataHash(request.clientDataHash)
        guard request.algorithms.isEmpty || request.algorithms.contains(PasskeyAlgorithm.es256) else {
            throw VaultError(.unsupportedAlgorithm, "The website accepts no passkey algorithm of Apassy.")
        }
        if !request.excluded.isEmpty, !(try await passkeys(rpID: request.rpID, allowed: request.excluded)).isEmpty {
            throw VaultError(.excluded, "This account has a passkey in the vault already.")
        }
        let credentialID = Data(SymmetricKey(size: .bits256).withUnsafeBytes { Array($0) })
        let key = P256.Signing.PrivateKey()
        let summary = PasskeySummary(
            rpID: request.rpID, userName: request.userName, userDisplayName: request.userDisplayName,
            credentialID: credentialID, userHandle: request.userHandle)
        let id: UInt64
        if let attach = request.attach {
            var item = try stored(attach.id)
            guard item.row.revision == attach.revision else {
                throw VaultError(.conflict, "This item changed. Open it again to see the new version.")
            }
            guard item.row.kind == .login, item.passkey == nil else {
                throw VaultError(.invalidInput, "Only a login without a passkey can take one.")
            }
            item.passkey = Passkey(summary: summary, key: key)
            item.row.hasPasskey = true
            item.row.revision += 1
            items[attach.id] = item
            id = attach.id
        } else {
            id = insertPasskeyLogin(title: request.title, summary: summary, key: key)
        }
        return PasskeyCreated(
            id: id, credentialID: credentialID,
            attestationObject: PreviewAuthenticator(rpID: request.rpID, key: key).attestationObject(credentialID: credentialID))
    }

    private func insertPasskeyLogin(title: String, summary: PasskeySummary, key: P256.Signing.PrivateKey) -> UInt64 {
        let id = nextID
        nextID += 1
        let now = Int64(Date().timeIntervalSince1970)
        var fields: [FieldView] = []
        if !summary.userName.isEmpty {
            fields.append(
                FieldView(name: "username", label: "Username", secret: false, value: summary.userName, role: .username,
                    custom: false))
        }
        fields.append(
            FieldView(name: "x_57656273697465", label: "Website", secret: false, value: "https://\(summary.rpID)",
                role: .website, custom: true))
        let row = ItemRow(
            id: id, revision: 1, title: title.isEmpty ? summary.rpID : title, kind: .login, subtitle: summary.userName,
            websites: ["https://\(summary.rpID)"], tags: [], archived: false, hasTotp: false, conflictOf: nil,
            addedAt: now, changedAt: now, usedAt: nil, hasPasskey: true, hasPassword: false)
        items[id] = Stored(row: row, notes: "", fields: fields, secrets: [:], passkey: Passkey(summary: summary, key: key))
        return id
    }

    public func passkeyImport(_ accounts: [PasskeyImportAccount]) async throws -> PasskeyImportResult {
        try requireUnlocked()
        var result = PasskeyImportResult(imported: 0, skippedExisting: 0, failed: 0)
        for account in accounts {
            if items.values.contains(where: {
                $0.passkey?.summary.rpID == account.rpID && $0.passkey?.summary.credentialID == account.credentialID
            }) {
                result.skippedExisting += 1
                continue
            }
            guard let key = try? P256.Signing.PrivateKey(derRepresentation: account.key),
                PasskeyRequestCheck.importable(
                    rpID: account.rpID, credentialID: account.credentialID, userHandle: account.userHandle)
            else {
                result.failed += 1
                continue
            }
            let summary = PasskeySummary(
                rpID: account.rpID, userName: account.userName, userDisplayName: account.userDisplayName,
                credentialID: account.credentialID, userHandle: account.userHandle)
            _ = insertPasskeyLogin(title: account.title, summary: summary, key: key)
            result.imported += 1
        }
        return result
    }

    public func passkeyRemove(id: UInt64, revision: UInt64) async throws {
        var item = try stored(id)
        guard item.row.revision == revision else {
            throw VaultError(.conflict, "This item changed. Open it again to see the new version.")
        }
        guard item.passkey != nil else { throw VaultError(.notFound, "This login has no passkey.") }
        // As the core does: a login without a password has no other way in, so it goes whole.
        guard Self.storesPassword(item.secrets) else {
            items[id] = nil
            return
        }
        item.passkey = nil
        item.row.hasPasskey = false
        item.row.revision += 1
        items[id] = item
    }

    public func credentialExport() async throws -> CredentialExport {
        try requireUnlocked()
        var exported: [ExportedItem] = []
        var skipped = 0
        for item in items.values.sorted(by: { $0.row.id < $1.row.id }) {
            guard item.row.kind == .login, !item.row.archived, item.row.conflictOf == nil else {
                skipped += 1
                continue
            }
            var totp: ExportedTotp?
            if let field = item.fields.first(where: { $0.role == .totp }), let uri = item.secrets[field.name],
                let components = URLComponents(string: uri),
                let secret = components.queryItems?.first(where: { $0.name == "secret" })?.value,
                let bytes = OTPAuthURI.decodeBase32(secret)
            {
                totp = ExportedTotp(secret: bytes, period: 30, digits: 6, algorithm: "sha1", issuer: item.row.title, user: item.row.subtitle)
            }
            exported.append(
                ExportedItem(
                    id: item.row.id, title: item.row.title, notes: item.notes, tags: item.row.tags,
                    createdAt: item.row.addedAt, changedAt: item.row.changedAt,
                    username: item.row.subtitle.isEmpty ? nil : item.row.subtitle, password: item.secrets["password"],
                    websites: item.row.websites, totp: totp,
                    passkey: item.passkey.map {
                        ExportedPasskey(
                            rpID: $0.summary.rpID, credentialID: $0.summary.credentialID, userHandle: $0.summary.userHandle,
                            userName: $0.summary.userName, userDisplayName: $0.summary.userDisplayName,
                            key: $0.key.derRepresentation)
                    }))
        }
        return CredentialExport(items: exported, skipped: skipped)
    }

    public func credentialIdentities() async throws -> [CredentialIdentity] {
        try requireUnlocked()
        return items.values.filter { $0.row.kind == .login && !$0.row.archived }.flatMap { item in
            item.row.websites.compactMap { site -> CredentialIdentity? in
                let url = URL(string: site.contains("://") ? site : "https://\(site)")
                guard let host = url?.host() else { return nil }
                return CredentialIdentity(id: item.row.id, username: item.row.subtitle, host: host)
            }
        }
    }
}
