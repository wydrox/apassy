import Foundation

// The answers of the vault core (contract ios-core-v1, section 5). JSON keys are
// snake_case; the decoder of `VaultWire` converts them.

/// A vault on this iPhone (contract section 5.1).
public struct VaultEntry: Codable, Sendable, Hashable, Identifiable {
    public var id: String
    public var name: String
    public var relayURL: String?
    public var teamID: String?
    public var deviceID: UInt64?
    public var addedAt: Int64

    public init(id: String, name: String, relayURL: String?, teamID: String?, deviceID: UInt64?, addedAt: Int64) {
        self.id = id
        self.name = name
        self.relayURL = relayURL
        self.teamID = teamID
        self.deviceID = deviceID
        self.addedAt = addedAt
    }

    enum CodingKeys: String, CodingKey {
        case id, name
        case relayURL = "relay_url"
        case teamID = "team_id"
        case deviceID = "device_id"
        case addedAt = "added_at"
    }

    /// Whether the vault syncs through the relay.
    public var syncs: Bool { relayURL != nil }
}

/// The answer of `info`.
public struct CoreInfo: Codable, Sendable, Equatable {
    public var vaults: [VaultEntry]
    public var selected: String?
    public var unlocked: Bool
    public var join: JoinInfo?
    public var schema: Int
    public var version: String

    public init(vaults: [VaultEntry], selected: String?, unlocked: Bool, join: JoinInfo?, schema: Int, version: String) {
        self.vaults = vaults
        self.selected = selected
        self.unlocked = unlocked
        self.join = join
        self.schema = schema
        self.version = version
    }

    /// The selected vault.
    public var selectedVault: VaultEntry? { vaults.first { $0.id == selected } }
}

/// A join that waits for the Mac, or that has the copy (contract section 5.2).
public struct JoinInfo: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable { case waiting, ready }

    public var state: State
    /// The name of the vault (the relay team).
    public var team: String
    /// The two safety words. The Mac shows the same words for this iPhone.
    public var words: [String]
    public var expiresAt: Int64

    public init(state: State, team: String, words: [String], expiresAt: Int64) {
        self.state = state
        self.team = team
        self.words = words
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case state, team, words
        case expiresAt = "expires_at"
    }
}

/// The kind of an item. The Mac calls it the category.
public enum ItemKind: String, Codable, Sendable, CaseIterable, Identifiable {
    case login
    case apiKey = "api_key"
    case sshKey = "ssh_key"
    case database
    case custom

    public var id: String { rawValue }

    /// The name in the app, singular.
    public var label: String {
        switch self {
        case .login: "Login"
        case .apiKey: "API key"
        case .sshKey: "SSH key"
        case .database: "Database"
        case .custom: "Other"
        }
    }

    /// The name of a list of items of this kind.
    public var pluralLabel: String {
        switch self {
        case .login: "Logins"
        case .apiKey: "API keys"
        case .sshKey: "SSH keys"
        case .database: "Databases"
        case .custom: "Other"
        }
    }

    /// An SF Symbol.
    public var symbol: String {
        switch self {
        case .login: "person.badge.key"
        case .apiKey: "key.horizontal"
        case .sshKey: "terminal"
        case .database: "cylinder.split.1x2"
        case .custom: "square.grid.2x2"
        }
    }
}

/// An item in a list (contract section 5.3, `Row`).
public struct ItemRow: Codable, Sendable, Hashable, Identifiable {
    public var id: UInt64
    public var revision: UInt64
    public var title: String
    public var kind: ItemKind
    public var subtitle: String
    public var websites: [String]
    public var tags: [String]
    public var archived: Bool
    public var hasTotp: Bool
    public var conflictOf: UInt64?
    public var addedAt: Int64?
    public var changedAt: Int64?
    public var usedAt: Int64?

    public init(
        id: UInt64, revision: UInt64, title: String, kind: ItemKind, subtitle: String, websites: [String],
        tags: [String], archived: Bool, hasTotp: Bool, conflictOf: UInt64?, addedAt: Int64?,
        changedAt: Int64?, usedAt: Int64?
    ) {
        self.id = id
        self.revision = revision
        self.title = title
        self.kind = kind
        self.subtitle = subtitle
        self.websites = websites
        self.tags = tags
        self.archived = archived
        self.hasTotp = hasTotp
        self.conflictOf = conflictOf
        self.addedAt = addedAt
        self.changedAt = changedAt
        self.usedAt = usedAt
    }

    enum CodingKeys: String, CodingKey {
        case id, revision, title, kind, subtitle, websites, tags, archived
        case hasTotp = "has_totp"
        case conflictOf = "conflict_of"
        case addedAt = "added_at"
        case changedAt = "changed_at"
        case usedAt = "used_at"
    }
}

/// What the app does with a field (contract section 5.3).
public enum FieldRole: String, Codable, Sendable {
    case username, password, token
    case privateKey = "private_key"
    case keyPassphrase = "key_passphrase"
    case host, database
    case publicKey = "public_key"
    case service, project, website, totp, other

    /// Unknown roles of a newer core decode as `other`.
    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = FieldRole(rawValue: raw) ?? .other
    }
}

/// A field of an item (contract section 5.3, `Field`).
public struct FieldView: Codable, Sendable, Hashable, Identifiable {
    public var name: String
    public var label: String
    public var secret: Bool
    /// The value of a plain field. Always nil for a secret field: `reveal` gives it.
    public var value: String?
    public var role: FieldRole
    /// A custom detail (`x_<hex label>`).
    public var custom: Bool

    public var id: String { name }

    public init(name: String, label: String, secret: Bool, value: String?, role: FieldRole, custom: Bool) {
        self.name = name
        self.label = label
        self.secret = secret
        self.value = value
        self.role = role
        self.custom = custom
    }

    /// A value that reads better in several lines (a key).
    public var multiline: Bool { role == .privateKey || role == .publicKey }
}

/// An item with its fields (contract section 5.3, `Detail`).
public struct ItemDetail: Codable, Sendable, Hashable, Identifiable {
    public var row: ItemRow
    public var notes: String
    public var fields: [FieldView]

    public var id: UInt64 { row.id }

    public init(row: ItemRow, notes: String, fields: [FieldView]) {
        self.row = row
        self.notes = notes
        self.fields = fields
    }

    enum CodingKeys: String, CodingKey { case notes, fields }

    public init(from decoder: any Decoder) throws {
        row = try ItemRow(from: decoder)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        notes = try container.decode(String.self, forKey: .notes)
        fields = try container.decode([FieldView].self, forKey: .fields)
    }

    public func encode(to encoder: any Encoder) throws {
        try row.encode(to: encoder)
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(notes, forKey: .notes)
        try container.encode(fields, forKey: .fields)
    }

    /// The first field with `role`.
    public func field(_ role: FieldRole) -> FieldView? { fields.first { $0.role == role } }
}

/// A field of a draft (contract section 5.3, `Draft`): a built-in `name`, or the
/// `label` of a custom detail.
public struct DraftField: Codable, Sendable, Hashable {
    public var name: String?
    public var label: String?
    /// nil on a secret field of an existing item keeps the stored value.
    public var value: String?
    public var secret: Bool

    public static func named(_ name: String, _ value: String?, secret: Bool) -> DraftField {
        DraftField(name: name, label: nil, value: value, secret: secret)
    }

    public static func detail(_ label: String, _ value: String?, secret: Bool) -> DraftField {
        DraftField(name: nil, label: label, value: value, secret: secret)
    }

    public init(name: String?, label: String?, value: String?, secret: Bool) {
        self.name = name
        self.label = label
        self.value = value
        self.secret = secret
    }
}

/// The body of a new or edited item.
public struct ItemDraft: Codable, Sendable, Hashable {
    public var title: String
    public var kind: ItemKind
    public var notes: String
    public var tags: [String]
    public var fields: [DraftField]

    public init(title: String, kind: ItemKind, notes: String, tags: [String], fields: [DraftField]) {
        self.title = title
        self.kind = kind
        self.notes = notes
        self.tags = tags
        self.fields = fields
    }
}

/// The answer of `save`.
public struct SavedItem: Codable, Sendable, Equatable {
    public var id: UInt64
    public var revision: UInt64

    public init(id: UInt64, revision: UInt64) {
        self.id = id
        self.revision = revision
    }
}

/// A one-time code (contract section 7).
public struct TotpCode: Codable, Sendable, Equatable {
    public var code: String
    public var period: Int
    public var remaining: Int
    public var digits: Int

    public init(code: String, period: Int, remaining: Int, digits: Int) {
        self.code = code
        self.period = period
        self.remaining = remaining
        self.digits = digits
    }
}

/// An entry of the history of an item.
public struct ItemEvent: Codable, Sendable, Hashable {
    public var at: Int64
    public var kind: String
    public var detail: String

    public init(at: Int64, kind: String, detail: String) {
        self.at = at
        self.kind = kind
        self.detail = detail
    }
}

public enum ArchiveFilter: String, Codable, Sendable {
    case no, yes, all
}

/// The options of the password generator (contract section 5.4).
public struct GeneratorOptions: Codable, Sendable, Hashable {
    public enum Style: String, Codable, Sendable, CaseIterable, Identifiable {
        case random, memorable, pin
        public var id: String { rawValue }
        public var label: String {
            switch self {
            case .random: "Random"
            case .memorable: "Memorable"
            case .pin: "PIN"
            }
        }
    }

    public var style: Style
    public var length: Int
    public var digits: Bool
    public var symbols: Bool
    public var words: Int
    public var separator: String
    public var capitalize: Bool

    public init(
        style: Style = .random, length: Int = 24, digits: Bool = true, symbols: Bool = true, words: Int = 5,
        separator: String = "-", capitalize: Bool = true
    ) {
        self.style = style
        self.length = length
        self.digits = digits
        self.symbols = symbols
        self.words = words
        self.separator = separator
        self.capitalize = capitalize
    }

    /// The length range of a style.
    public static func lengths(_ style: Style) -> ClosedRange<Int> {
        style == .pin ? 4...12 : 8...64
    }

    /// The separators of a memorable password.
    public static let separators = ["-", ".", "_", " ", ","]
}

public struct GeneratedPassword: Codable, Sendable, Equatable {
    public var value: String
    public var bits: Double

    public init(value: String, bits: Double) {
        self.value = value
        self.bits = bits
    }
}

/// The strength of a value (contract section 9).
public struct Strength: Codable, Sendable, Equatable {
    public var bits: Double
    /// 0 (very weak) to 4 (very strong).
    public var score: Int

    public init(bits: Double, score: Int) {
        self.bits = bits
        self.score = score
    }

    public var label: String {
        switch score {
        case ..<1: "Very weak"
        case 1: "Weak"
        case 2: "Fair"
        case 3: "Strong"
        default: "Very strong"
        }
    }
}

/// The answer of `watchtower` (contract section 9). IDs only.
public struct WatchtowerReport: Codable, Sendable, Equatable {
    public var weak: [UInt64]
    public var reused: [[UInt64]]
    public var old: [UInt64]
    public var conflicts: [UInt64]
    public var checked: Int

    public init(weak: [UInt64], reused: [[UInt64]], old: [UInt64], conflicts: [UInt64], checked: Int) {
        self.weak = weak
        self.reused = reused
        self.old = old
        self.conflicts = conflicts
        self.checked = checked
    }

    /// The number of items that need a look.
    public var issueCount: Int {
        Set(weak + reused.flatMap(\.self) + old + conflicts).count
    }
}

/// The state of the relay sync of the selected vault (contract section 5.5).
public struct SyncStatus: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable {
        case off, never, ok, offline
        case needsPassphrase = "needs_passphrase"
        case removed, damaged
        case staleCopy = "stale_copy"
        case forkedCopy = "forked_copy"
        case busy, error

        public init(from decoder: any Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = State(rawValue: raw) ?? .error
        }
    }

    public struct Merged: Codable, Sendable, Equatable {
        public var inserted: Int
        public var updated: Int
        public var deleted: Int
        public var conflicts: Int

        public init(inserted: Int, updated: Int, deleted: Int, conflicts: Int) {
            self.inserted = inserted
            self.updated = updated
            self.deleted = deleted
            self.conflicts = conflicts
        }
    }

    public var enabled: Bool
    public var state: State
    public var message: String
    public var version: UInt64
    public var lastSyncAt: Int64?
    public var pushed: Bool
    public var merged: Merged?

    public init(
        enabled: Bool, state: State, message: String, version: UInt64, lastSyncAt: Int64?, pushed: Bool,
        merged: Merged?
    ) {
        self.enabled = enabled
        self.state = state
        self.message = message
        self.version = version
        self.lastSyncAt = lastSyncAt
        self.pushed = pushed
        self.merged = merged
    }

    enum CodingKeys: String, CodingKey {
        case enabled, state, message, version, pushed, merged
        case lastSyncAt = "last_sync_at"
    }
}

/// A device of the relay team of the vault.
public struct RelayDevice: Codable, Sendable, Hashable, Identifiable {
    public var id: UInt64
    public var name: String
    public var this: Bool
    public var lastSeenAt: Int64?

    public init(id: UInt64, name: String, this: Bool, lastSeenAt: Int64?) {
        self.id = id
        self.name = name
        self.this = this
        self.lastSeenAt = lastSeenAt
    }

    enum CodingKeys: String, CodingKey {
        case id, name, this
        case lastSeenAt = "last_seen_at"
    }
}

/// A login that AutoFill can offer (contract section 5.7).
public struct FillCandidate: Codable, Sendable, Hashable, Identifiable {
    public var id: UInt64
    public var title: String
    public var username: String
    public var website: String?
    public var hasTotp: Bool

    public init(id: UInt64, title: String, username: String, website: String?, hasTotp: Bool) {
        self.id = id
        self.title = title
        self.username = username
        self.website = website
        self.hasTotp = hasTotp
    }

    enum CodingKeys: String, CodingKey {
        case id, title, username, website
        case hasTotp = "has_totp"
    }
}

public struct AutofillList: Codable, Sendable, Equatable {
    public var matches: [FillCandidate]
    public var others: [FillCandidate]

    public init(matches: [FillCandidate], others: [FillCandidate]) {
        self.matches = matches
        self.others = others
    }
}

/// A username and password for AutoFill. Keep it only until it is handed to iOS.
public struct FillCredential: Codable, Sendable {
    public var username: String
    public var password: String

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}

/// A login for the QuickType bar of iOS: no password.
public struct CredentialIdentity: Codable, Sendable, Hashable {
    public var id: UInt64
    public var username: String
    public var host: String

    public init(id: UInt64, username: String, host: String) {
        self.id = id
        self.username = username
        self.host = host
    }
}

/// The answer of `take_new_passphrase`.
public struct PassphraseChange: Codable, Sendable, Equatable {
    public var status: SyncStatus
    /// Whether the vault took the typed passphrase. False when the iPhone had no anchor
    /// ("Use the relay copy"): the passphrase only opened the copy, and the vault keeps its
    /// own, so the app must not store the typed one for Face ID.
    public var rekeyed: Bool

    public init(status: SyncStatus, rekeyed: Bool) {
        self.status = status
        self.rekeyed = rekeyed
    }
}
