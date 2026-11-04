import Foundation

/// The calls of the Apple Watch core (contract ios-core-v1 section 5.13, ADR 0039):
/// `WatchCoreService` over the Rust core, `PreviewWatchService` for previews and tests.
///
/// The access-request calls take and give the same models as the iPhone (`AccessRequests.swift`).
public protocol WatchService: Sendable {
    /// The state of the watch and of its replica. `answerKey` (X9.63) lets the core check that
    /// the row of this watch holds this key.
    func status(answerKey: Data?) async throws -> WatchStatus
    /// Register the Connect code with a new relay key, the name, and the answer key of this watch.
    /// The core makes the replica vault with `passphrase` once the Mac sends the handoff.
    func connectStart(link: String, name: String, answerKey: Data, passphrase: String) async throws
        -> WatchConnectInfo
    /// `waiting`, or `attached` once the replica vault is open.
    func connectPoll() async throws -> WatchConnectInfo
    func connectCancel() async throws
    /// Leave the team and delete the replica vault. The watch is `unpaired` after it.
    func forget() async throws

    func select(vaultID: String) async throws
    func unlock(passphrase: String) async throws
    func lock() async throws
    func suspend() async throws

    func accessRequestsList() async throws -> AccessRequestsSnapshot
    func accessRequestPrepare(_ request: RelayAccessRequest, choice: AccessChoice) async throws
        -> PreparedAccessAnswer
    func accessRequestAnswer(
        _ request: RelayAccessRequest, choice: AccessChoice, prepared: PreparedAccessAnswer, signature: Data?
    ) async throws -> SentAccessAnswer
    func accessRequestCancelPrepared() async
    /// A long poll: waits up to `timeout` seconds (1 to 25) for new or changed requests.
    func wait(timeout: Int) async throws -> Bool

    /// "Notifications on this watch" (push-gateway-v1 section 11): the core exchanges the APNs
    /// token of the watch at the push gateway for a handle of the kind `watch` and gives the node
    /// the handle, never the token. The hosted relay has no watch push: `push_unavailable`.
    func pushTokenSet(token: Data, environment: PushEnvironment) async throws
    /// Take the handle off the node.
    func pushTokenClear() async throws
    /// The summary key of the watch's questions team, for its Notification Service Extension.
    func pushSummaryKeys() async throws -> [PushSummaryKey]

    /// Why the last relay call of `connectStart` that could not reach the relay failed, in the
    /// words of the network layer of this watch (error codes, not a sentence for the owner), or
    /// nil when it is not known.
    func networkProblem() async -> String?
}

extension WatchService {
    public func pushTokenSet(token: Data, environment: PushEnvironment) async throws {
        throw VaultError(.notAllowed, "Notifications on this watch are not available in this build.")
    }

    public func pushTokenClear() async throws {}

    public func pushSummaryKeys() async throws -> [PushSummaryKey] { [] }

    public func networkProblem() async -> String? { nil }
}
