import ApassyVaultKit
import Foundation

// The agents of the Macs over the core (contract ios-core-v1 section 5.12, relay-feed-v1). The
// core refuses these calls in the AutoFill extension.
extension CoreVaultService {
    public func feedList() async throws -> FeedList { try await call("feed_list") }

    private struct FeedWaited: Decodable, Sendable { var changed: Bool }

    public func feedWait(timeout: Int) async throws -> Bool {
        try await call("feed_wait", ["timeout": min(max(timeout, 1), 25)], as: FeedWaited.self).changed
    }

    public func feedActionString(_ removal: FeedRemoval, actionID: String?, time: Int64?) async throws
        -> PreparedFeedAction
    {
        var params = removal.parameters
        if let actionID { params["action_id"] = actionID }
        if let time { params["time"] = time }
        return try await call("feed_action_string", params)
    }

    public func feedAction(_ removal: FeedRemoval, actionID: String, time: Int64, signature: Data?) async throws
        -> SentFeedAction
    {
        var params = removal.parameters
        params["action_id"] = actionID
        params["time"] = time
        if let signature { params["signature"] = Base64URL.encode(signature) }
        return try await call("feed_action", params)
    }

    public func feedActionWait(actionID: String, vaultID: String?, timeout: Int) async throws -> FeedActionOutcome {
        var params: [String: Any] = ["action_id": actionID, "timeout": min(max(timeout, 0), 25)]
        if let vaultID { params["vault_id"] = vaultID }
        return try await call("feed_action_wait", params)
    }
}
