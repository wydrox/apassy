import Foundation

/// Coverage is only relay requests observed on this iPhone. No command, prompt or secret is saved.
public struct RequestHistorySnapshot: Decodable, Sendable, Equatable {
    public var vaults: [RequestHistoryVault]
    public var retentionDays: Int
    public var maxEntriesPerVault: Int

    public init(vaults: [RequestHistoryVault], retentionDays: Int = 30, maxEntriesPerVault: Int = 1000) {
        self.vaults = vaults
        self.retentionDays = retentionDays
        self.maxEntriesPerVault = maxEntriesPerVault
    }

    enum CodingKeys: String, CodingKey {
        case vaults
        case retentionDays = "retention_days"
        case maxEntriesPerVault = "max_entries_per_vault"
    }
}

public enum RequestHistoryAvailability: String, Decodable, Sendable {
    case available, locked, unavailable
}

/// Locked/unavailable scopes carry no entries or counts. Unlock never happens implicitly.
public struct RequestHistoryVault: Decodable, Sendable, Equatable, Identifiable {
    public var vaultID: String
    public var vaultName: String
    public var availability: RequestHistoryAvailability
    public var entries: [RequestHistoryEntry]
    public var error: String?
    public var id: String { vaultID }

    public init(vaultID: String, vaultName: String, availability: RequestHistoryAvailability,
                entries: [RequestHistoryEntry] = [], error: String? = nil) {
        self.vaultID = vaultID
        self.vaultName = vaultName
        self.availability = availability
        self.entries = availability == .available ? entries : []
        self.error = error
    }

    enum CodingKeys: String, CodingKey {
        case availability, entries, error
        case vaultID = "vault_id"
        case vaultName = "vault_name"
    }

    public init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        vaultID = try values.decode(String.self, forKey: .vaultID)
        vaultName = try values.decode(String.self, forKey: .vaultName)
        availability = try values.decode(RequestHistoryAvailability.self, forKey: .availability)
        entries = availability == .available ? try values.decode([RequestHistoryEntry].self, forKey: .entries) : []
        error = try values.decodeIfPresent(String.self, forKey: .error)
    }
}

/// `sentAt` proves delivery only. `outcome` comes exclusively from a verified matching settle.
/// Execution is never inferred; history detail must describe it as not reported.
public struct RequestHistoryEntry: Decodable, Sendable, Equatable, Identifiable {
    public var id: String
    public var vaultID: String
    public var qid: String
    public var source: String
    public var title: String
    public var agent: String
    public var project: String?
    public var action: String
    public var production: Bool
    public var deviceName: String
    public var firstSeenAt: Int64
    public var lastSeenAt: Int64
    public var expiresAt: Int64
    public var selectedKind: String?
    public var selectedEnvironment: String?
    public var selectedItemID: String?
    public var attemptedAt: Int64?
    public var sentAt: Int64?
    public var outcome: String?
    public var confirmedKind: String?
    public var confirmedAt: Int64?
    public var confirmedBy: String?
    public var replacedBy: String?

    public init(
        id: String,
        vaultID: String,
        qid: String,
        source: String = "relay",
        title: String,
        agent: String,
        project: String? = nil,
        action: String,
        production: Bool,
        deviceName: String,
        firstSeenAt: Int64,
        lastSeenAt: Int64,
        expiresAt: Int64,
        selectedKind: String? = nil,
        selectedEnvironment: String? = nil,
        selectedItemID: String? = nil,
        attemptedAt: Int64? = nil,
        sentAt: Int64? = nil,
        outcome: String? = nil,
        confirmedKind: String? = nil,
        confirmedAt: Int64? = nil,
        confirmedBy: String? = nil,
        replacedBy: String? = nil
    ) {
        self.id = id
        self.vaultID = vaultID
        self.qid = qid
        self.source = source
        self.title = title
        self.agent = agent
        self.project = project
        self.action = action
        self.production = production
        self.deviceName = deviceName
        self.firstSeenAt = firstSeenAt
        self.lastSeenAt = lastSeenAt
        self.expiresAt = expiresAt
        self.selectedKind = selectedKind
        self.selectedEnvironment = selectedEnvironment
        self.selectedItemID = selectedItemID
        self.attemptedAt = attemptedAt
        self.sentAt = sentAt
        self.outcome = outcome
        self.confirmedKind = confirmedKind
        self.confirmedAt = confirmedAt
        self.confirmedBy = confirmedBy
        self.replacedBy = replacedBy
    }

    enum CodingKeys: String, CodingKey {
        case id
        case vaultID = "vault_id"
        case qid
        case source
        case title
        case agent
        case project
        case action
        case production
        case deviceName = "device_name"
        case firstSeenAt = "first_seen_at"
        case lastSeenAt = "last_seen_at"
        case expiresAt = "expires_at"
        case selectedKind = "selected_kind"
        case selectedEnvironment = "selected_environment"
        case selectedItemID = "selected_item_id"
        case attemptedAt = "attempted_at"
        case sentAt = "sent_at"
        case outcome
        case confirmedKind = "confirmed_kind"
        case confirmedAt = "confirmed_at"
        case confirmedBy = "confirmed_by"
        case replacedBy = "replaced_by"
    }
}
