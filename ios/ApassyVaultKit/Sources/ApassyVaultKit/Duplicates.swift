import Foundation

// Duplicate items (core ops `duplicates` and `duplicates_merge`, role app only). Imports and sync
// conflicts leave items that hold the same credential. The core finds the groups and merges a group
// into one item: the kept item takes the fields that it lacks, and the other members go to the
// archive, where the owner can bring them back. No value is in these types: titles, kinds, times,
// and the labels of the fields that differ.

/// One item of a duplicate group.
public struct DuplicateMember: Codable, Sendable, Hashable, Identifiable {
    public var id: UInt64
    public var title: String
    public var kind: ItemKind
    /// The revision that a merge must name (`conflict` when the item changed since).
    public var revision: UInt64
    public var hasPasskey: Bool
    /// Unix seconds; 0 when the core knows no time.
    public var changedAt: Int64

    public init(id: UInt64, title: String, kind: ItemKind, revision: UInt64, hasPasskey: Bool, changedAt: Int64) {
        self.id = id
        self.title = title
        self.kind = kind
        self.revision = revision
        self.hasPasskey = hasPasskey
        self.changedAt = changedAt
    }

    enum CodingKeys: String, CodingKey {
        case id, title, kind, revision
        case hasPasskey = "has_passkey"
        case changedAt = "changed_at"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UInt64.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        kind = try container.decode(ItemKind.self, forKey: .kind)
        revision = try container.decode(UInt64.self, forKey: .revision)
        hasPasskey = try container.decodeIfPresent(Bool.self, forKey: .hasPasskey) ?? false
        changedAt = try container.decodeIfPresent(Int64.self, forKey: .changedAt) ?? 0
    }
}

/// Items that hold the same credential (`duplicates`).
public struct DuplicateGroup: Codable, Sendable, Hashable, Identifiable {
    public var items: [DuplicateMember]
    /// The item that the core suggests to keep.
    public var keep: UInt64
    /// The labels of the fields whose values differ, such as "Password" or "Notes". Never a value.
    public var differences: [String]
    /// Every value is the same in each member.
    public var identical: Bool
    /// False when the core cannot merge the group; `reason` says why.
    public var mergeable: Bool
    public var reason: String?

    public init(
        items: [DuplicateMember], keep: UInt64, differences: [String], identical: Bool, mergeable: Bool,
        reason: String?
    ) {
        self.items = items
        self.keep = keep
        self.differences = differences
        self.identical = identical
        self.mergeable = mergeable
        self.reason = reason
    }

    /// The IDs of the members, sorted: a group stays the same group across reloads.
    public var id: [UInt64] { items.map(\.id).sorted() }

    /// The members that may be kept. When a member has a passkey only that member may be kept: a
    /// passkey stays in its own item (the core refuses another choice).
    public var keepable: [DuplicateMember] {
        let withPasskey = items.filter(\.hasPasskey)
        return withPasskey.isEmpty ? items : withPasskey
    }

    /// The suggested member to keep, when it may be kept; else the first that may.
    public var suggestedKeep: UInt64? {
        let choices = keepable
        if choices.contains(where: { $0.id == keep }) { return keep }
        return choices.first?.id
    }

    public func member(_ id: UInt64) -> DuplicateMember? { items.first { $0.id == id } }

    /// The members other than `keep`, with the revisions to merge them at.
    public func others(keeping keep: UInt64) -> [DuplicateMergeOther] {
        items.filter { $0.id != keep }.map { DuplicateMergeOther(id: $0.id, revision: $0.revision) }
    }

    /// "Same values", or "Differs: Password, Notes".
    public var differenceSummary: String {
        if identical || differences.isEmpty { return "Same values" }
        return "Differs: " + differences.joined(separator: ", ")
    }
}

/// A member of a merge that goes to the archive, at the revision that the owner saw.
public struct DuplicateMergeOther: Codable, Sendable, Hashable {
    public var id: UInt64
    public var revision: UInt64

    public init(id: UInt64, revision: UInt64) {
        self.id = id
        self.revision = revision
    }
}

/// The answer of `duplicates_merge`: the kept item at its new revision, and the archived members.
public struct DuplicateMergeResult: Codable, Sendable, Equatable {
    public var id: UInt64
    public var revision: UInt64
    public var archived: [UInt64]

    public init(id: UInt64, revision: UInt64, archived: [UInt64]) {
        self.id = id
        self.revision = revision
        self.archived = archived
    }
}
