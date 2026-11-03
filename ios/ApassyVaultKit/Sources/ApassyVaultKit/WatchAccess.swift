import Foundation

// The Apple Watch that answers access requests only (ADR 0039, contract ios-core-v1 section
// 5.13). The watch has its own relay key, its own answer key, and a questions-only replica
// vault; it never holds a credential.

/// The vault that the watch answers access requests for.
public struct WatchVault: Codable, Equatable, Sendable {
    public let id: String
    public let name: String

    public init(id: String, name: String) {
        self.id = id
        self.name = name
    }
}

/// The answer of `watch_connect_start` and `watch_connect_poll`.
public struct WatchConnectInfo: Decodable, Equatable, Sendable {
    public enum State: String, Decodable, Sendable { case waiting, attached }

    public let state: State
    /// The six safety words, while the watch waits for the Mac.
    public let words: [String]
    /// When the code of the Mac expires (seconds since 1970), while the watch waits.
    public let expiresAt: UInt64?
    /// The connected vault, once attached.
    public let vault: WatchVault?

    public init(state: State, words: [String] = [], expiresAt: UInt64? = nil, vault: WatchVault? = nil) {
        self.state = state
        self.words = words
        self.expiresAt = expiresAt
        self.vault = vault
    }

    enum CodingKeys: String, CodingKey {
        case state, words, vault
        case expiresAt = "expires_at"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(State.self, forKey: .state)
        words = try container.decodeIfPresent([String].self, forKey: .words) ?? []
        expiresAt = try container.decodeIfPresent(UInt64.self, forKey: .expiresAt)
        vault = try container.decodeIfPresent(WatchVault.self, forKey: .vault)
    }
}

/// The answer of `watch_status`: the state of the watch and of its replica vault.
public struct WatchStatus: Decodable, Equatable, Sendable {
    public enum State: String, Decodable, Sendable { case unpaired, connecting, locked, ready, removed }

    /// The row of this watch in the replica (only while the replica is unlocked).
    public struct Own: Decodable, Equatable, Sendable {
        /// The vault holds the row of this watch.
        public let found: Bool
        /// The row is of kind `watch` and holds the answer key of this watch.
        public let answerKeyMatches: Bool

        public init(found: Bool, answerKeyMatches: Bool) {
            self.found = found
            self.answerKeyMatches = answerKeyMatches
        }

        enum CodingKeys: String, CodingKey {
            case found
            case answerKeyMatches = "answer_key_matches"
        }
    }

    public let state: State
    public let vault: WatchVault?
    /// The names of the Macs that can ask (the live Mac rows of the replica).
    public let macs: [String]
    public let own: Own?

    public init(state: State, vault: WatchVault? = nil, macs: [String] = [], own: Own? = nil) {
        self.state = state
        self.vault = vault
        self.macs = macs
        self.own = own
    }

    enum CodingKeys: String, CodingKey { case state, vault, macs, own }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(State.self, forKey: .state)
        vault = try container.decodeIfPresent(WatchVault.self, forKey: .vault)
        macs = try container.decodeIfPresent([String].self, forKey: .macs) ?? []
        own = try container.decodeIfPresent(Own.self, forKey: .own)
    }
}

/// The WatchConnectivity message that hands a Connect code from the iPhone to the watch
/// (ADR 0039 section 6). The iPhone never uses or keeps the link.
public enum WatchHandoff {
    /// The message: `[linkKey: <the text of the code>]`.
    public static let linkKey = "apassy.connect-link"
    /// The reply when the watch took the link: `[okKey: true]`.
    public static let okKey = "ok"
    /// The reply when the watch refused it: `[errorKey: <a sentence for the owner>]`.
    public static let errorKey = "error"
}

/// The connection of the watch, which it publishes to the paired iPhone with
/// `updateApplicationContext` (ADR 0039 section 6) for Settings › Devices › Apple Watch. It holds
/// only the state and the name of the vault, never a key, a link, or a request.
public enum WatchConnectionReport: Equatable, Sendable {
    case notConnected
    /// A Mac removed this watch.
    case removed
    case connected(vault: String)

    public static let stateKey = "apassy.watch-state"
    public static let vaultKey = "apassy.watch-vault"

    /// The application context for WatchConnectivity.
    public var context: [String: Any] {
        switch self {
        case .notConnected: [Self.stateKey: "not-connected"]
        case .removed: [Self.stateKey: "removed"]
        case .connected(let vault): [Self.stateKey: "connected", Self.vaultKey: vault]
        }
    }

    /// The report in an application context, or nil when the watch sent none (or a newer one).
    public init?(context: [String: Any]) {
        switch context[Self.stateKey] as? String {
        case "not-connected": self = .notConnected
        case "removed": self = .removed
        case "connected": self = .connected(vault: context[Self.vaultKey] as? String ?? "")
        default: return nil
        }
    }
}

/// A screen of the watch on top of Requests.
public enum WatchRoute: Hashable, Sendable {
    /// A request, by `RelayAccessRequest.id`.
    case request(String)
    /// Its exact identities.
    case identities(String)
}

/// The scene phase of the watch app, without SwiftUI.
public enum WatchScenePhase: Sendable, Equatable {
    case active, inactive, background
}
