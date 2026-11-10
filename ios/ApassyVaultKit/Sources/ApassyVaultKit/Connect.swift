import Foundation

// Apassy Connect on this iPhone (contract ios-core-v1 section 5.14, plan s7 unit I1): the iPhone
// joins the account of a Mac and shows the plan of that account as text. The core gives no price,
// no currency, and no URL, and the iPhone never creates an account or starts a purchase (App
// Store Review Guideline 3.1, plan section 6).

/// A join of this iPhone to a Connect account: the words, while the Mac confirms.
public struct ConnectJoin: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable { case waiting, confirmed }

    public var state: State
    public var accountID: String
    /// The name of the Mac that made the code and confirms.
    public var confirmer: String
    /// The six safety words; the Mac shows the same words.
    public var words: [String]
    public var expiresAt: Int64

    public init(state: State, accountID: String, confirmer: String, words: [String], expiresAt: Int64) {
        self.state = state
        self.accountID = accountID
        self.confirmer = confirmer
        self.words = words
        self.expiresAt = expiresAt
    }

    enum CodingKeys: String, CodingKey {
        case state, confirmer, words
        case accountID = "account_id"
        case expiresAt = "expires_at"
    }
}

/// The plan of the account (connect-billing-v1 section 8): its name, its state, and its times.
/// It has no price and no currency.
public struct ConnectPlan: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable {
        case none, pending, active, trialing
        case pastDue = "past_due"
        case readOnly = "read_only"
        case suspended
        /// A state of a newer Connect: shown as "Not on Connect".
        case unknown

        public init(from decoder: any Decoder) throws {
            let text = try decoder.singleValueContainer().decode(String.self)
            self = Status(rawValue: text) ?? .unknown
        }
    }

    public struct Group: Codable, Sendable, Equatable {
        /// `family` or `team`.
        public var kind: String
        /// `owner`, `admin`, or `member`.
        public var role: String

        public init(kind: String, role: String) {
            self.kind = kind
            self.role = role
        }
    }

    /// For a Family: the active people and the people of the plan ("3 of 4 people").
    public struct People: Codable, Sendable, Equatable {
        public var active: Int
        public var of: Int

        public init(active: Int, of: Int) {
            self.active = active
            self.of = of
        }
    }

    /// `personal`, `family`, `team`, or nil.
    public var plan: String?
    public var status: Status
    public var entitled: Bool
    public var renewsAt: Int64?
    public var endsAt: Int64?
    public var graceUntil: Int64?
    public var readOnlyUntil: Int64?
    public var deleteAt: Int64?
    public var group: Group?
    public var people: People?

    public init(
        plan: String?, status: Status, entitled: Bool, renewsAt: Int64? = nil, endsAt: Int64? = nil,
        graceUntil: Int64? = nil, readOnlyUntil: Int64? = nil, deleteAt: Int64? = nil, group: Group? = nil,
        people: People? = nil
    ) {
        self.plan = plan
        self.status = status
        self.entitled = entitled
        self.renewsAt = renewsAt
        self.endsAt = endsAt
        self.graceUntil = graceUntil
        self.readOnlyUntil = readOnlyUntil
        self.deleteAt = deleteAt
        self.group = group
        self.people = people
    }

    enum CodingKeys: String, CodingKey {
        case plan, status, entitled, group, people
        case renewsAt = "renews_at"
        case endsAt = "ends_at"
        case graceUntil = "grace_until"
        case readOnlyUntil = "read_only_until"
        case deleteAt = "delete_at"
    }
}

/// A device of the Connect account, as `connect_status` lists it.
public struct ConnectDevice: Codable, Sendable, Equatable {
    public var deviceID: String
    public var name: String
    /// `mac`, `iphone`, or `linux`.
    public var platform: String
    /// True for this iPhone.
    public var isThisDevice: Bool
    /// True when the core verified the chain of statements of this device. When false, the app
    /// shows "Not verified".
    public var verified: Bool

    public init(deviceID: String, name: String, platform: String, isThisDevice: Bool, verified: Bool) {
        self.deviceID = deviceID
        self.name = name
        self.platform = platform
        self.isThisDevice = isThisDevice
        self.verified = verified
    }

    enum CodingKeys: String, CodingKey {
        case name, platform, verified
        case deviceID = "device_id"
        case isThisDevice = "this"
    }
}

/// `connect_status`: whether this iPhone is a device of a Connect account, and its plan.
public struct ConnectStatus: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable { case none, account }

    public var state: State
    /// True when Connect says a Mac removed this iPhone from its account, or the key of this iPhone
    /// is gone. With state `account`, the key and the account file stay until `connectForget`.
    public var removed: Bool
    public var accountID: String?
    public var deviceName: String?
    /// Nil when Connect did not answer and no earlier answer is known.
    public var plan: ConnectPlan?
    /// True when Connect did not answer: `plan` is the last answer of this session.
    public var stale: Bool
    /// True when this iPhone reaches its Mac through Apassy Connect (plan s7 unit I2).
    public var dialRoute: Bool
    /// A join that waits for the Mac.
    public var join: ConnectJoin?
    /// The devices of the account, each with `verified`; empty when Connect did not answer.
    public var devices: [ConnectDevice]

    /// The devices of the account that this iPhone could not verify.
    public var unverifiedDevices: [ConnectDevice] { devices.filter { !$0.verified } }

    public init(
        state: State, removed: Bool = false, accountID: String? = nil, deviceName: String? = nil,
        plan: ConnectPlan? = nil, stale: Bool = false, dialRoute: Bool = false, join: ConnectJoin? = nil,
        devices: [ConnectDevice] = []
    ) {
        self.state = state
        self.removed = removed
        self.accountID = accountID
        self.deviceName = deviceName
        self.plan = plan
        self.stale = stale
        self.dialRoute = dialRoute
        self.join = join
        self.devices = devices
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(State.self, forKey: .state)
        removed = try container.decodeIfPresent(Bool.self, forKey: .removed) ?? false
        accountID = try container.decodeIfPresent(String.self, forKey: .accountID)
        deviceName = try container.decodeIfPresent(String.self, forKey: .deviceName)
        plan = try container.decodeIfPresent(ConnectPlan.self, forKey: .plan)
        stale = try container.decodeIfPresent(Bool.self, forKey: .stale) ?? false
        dialRoute = try container.decodeIfPresent(Bool.self, forKey: .dialRoute) ?? false
        join = try container.decodeIfPresent(ConnectJoin.self, forKey: .join)
        devices = try container.decodeIfPresent([ConnectDevice].self, forKey: .devices) ?? []
    }

    enum CodingKeys: String, CodingKey {
        case state, removed, plan, stale, join, devices
        case accountID = "account_id"
        case deviceName = "device_name"
        case dialRoute = "dial_route"
    }
}

/// Whether `text` is the code of "Add a device…" of Apassy Connect on the Mac:
/// `apassy_alk_<account id>_<64 hex>_<32 hex>`: the account id, the secret, and the fingerprint of the
/// keys (connect-account-v1 section 2), 123 characters in all. Returns the trimmed code, or
/// nil. The core checks it again.
public func connectLinkCode(_ text: String) -> String? {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.hasPrefix("apassy_alk_") else { return nil }
    let rest = trimmed.dropFirst("apassy_alk_".count)
    let base32 = Set("abcdefghijklmnopqrstuvwxyz234567")
    let hex = Set("0123456789abcdef")
    let account = rest.prefix(14)
    guard account.count == 14, account.hasPrefix("acc_"), account.dropFirst(4).allSatisfy(base32.contains),
        rest.dropFirst(14).first == "_"
    else { return nil }
    let tail = rest.dropFirst(15)
    guard tail.count == 64 + 1 + 32 else { return nil }
    let secret = tail.prefix(64)
    let fingerprint = tail.dropFirst(65)
    guard secret.allSatisfy(hex.contains), tail.dropFirst(64).first == "_", fingerprint.allSatisfy(hex.contains)
    else { return nil }
    return trimmed
}
