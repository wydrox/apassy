import ApassyCoreFFI
import ApassyVaultKit
import Foundation

/// `WatchService` over the Rust core with the role `watch` (ADR 0039, contract ios-core-v1
/// section 5.13). Every call name and parameter of the watch is in this file.
///
/// On watchOS the relay HTTP of the core goes through URLSession (`URLSessionCoreTransport`),
/// installed before the core starts. The access-request calls take the same parameters as on the
/// iPhone (`CoreVaultService+Questions.swift`).
public final class WatchCoreService: WatchService, @unchecked Sendable {
    private enum Op {
        static let status = "watch_status"
        static let connectStart = "watch_connect_start"
        static let connectPoll = "watch_connect_poll"
        static let connectCancel = "watch_connect_cancel"
        static let forget = "watch_forget"
        static let select = "select"
        static let unlock = "unlock"
        static let lock = "lock"
        static let suspend = "suspend"
        static let list = "access_requests_list"
        static let prepare = "access_request_prepare"
        static let answer = "access_request_answer"
        static let cancelPrepared = "access_request_cancel_prepared"
        static let wait = "questions_wait"
    }

    private struct Empty: Decodable, Sendable {}
    private struct Waited: Decodable, Sendable { var changed: Bool }

    private let core: CorePointer
    private let queue = DispatchQueue(label: "com.wydrox.apassy.watch-core", qos: .userInitiated, attributes: .concurrent)

    /// - Parameters:
    ///   - dataDirectory: the data folder of the watch app (its replica vault and state).
    ///   - deviceName: the name of the watch, when a link names none.
    public init(dataDirectory: URL, deviceName: String) throws {
        #if os(watchOS)
            URLSessionCoreTransport.install()
        #endif
        let config: [String: Any] = [
            "data_dir": dataDirectory.path(percentEncoded: false),
            "role": "watch",
            // The access guards live in the data folder, which the app excludes from backups.
            "request_guard_storage_ready": true,
            "device_name": deviceName,
        ]
        let text = String(decoding: try JSONSerialization.data(withJSONObject: config), as: UTF8.self)
        guard let core = text.withCString({ apassy_core_new($0) }) else {
            throw VaultError(.internal, "The vault core did not start.")
        }
        self.core = CorePointer(raw: core)
    }

    deinit { apassy_core_free(core.raw) }

    private func call<R: Decodable & Sendable>(_ op: String, _ params: [String: Any] = [:], as: R.Type = R.self)
        async throws -> R
    {
        try await CoreWire.call(core, on: queue, op, params)
    }

    private func call(_ op: String, _ params: [String: Any] = [:]) async throws {
        _ = try await call(op, params, as: Empty.self)
    }

    // MARK: - The watch

    public func status(answerKey: Data?) async throws -> WatchStatus {
        var params: [String: Any] = [:]
        if let answerKey { params["answer_key"] = Base64URL.encode(answerKey) }
        return try await call(Op.status, params)
    }

    public func connectStart(link: String, name: String, answerKey: Data, passphrase: String) async throws
        -> WatchConnectInfo
    {
        try await call(
            Op.connectStart,
            ["link": link, "name": name, "answer_key": Base64URL.encode(answerKey), "passphrase": passphrase])
    }

    public func connectPoll() async throws -> WatchConnectInfo { try await call(Op.connectPoll) }

    public func connectCancel() async throws { try await call(Op.connectCancel) }

    public func forget() async throws { try await call(Op.forget) }

    // MARK: - The replica vault

    public func select(vaultID: String) async throws { try await call(Op.select, ["vault_id": vaultID]) }

    public func unlock(passphrase: String) async throws {
        try await call(Op.unlock, ["passphrase": passphrase, "keep": false])
    }

    public func lock() async throws { try await call(Op.lock) }

    public func suspend() async throws { try await call(Op.suspend) }

    // MARK: - Access requests (as CoreVaultService+Questions)

    public func accessRequestsList() async throws -> AccessRequestsSnapshot { try await call(Op.list) }

    public func accessRequestPrepare(_ request: RelayAccessRequest, choice: AccessChoice) async throws
        -> PreparedAccessAnswer
    {
        try await call(
            Op.prepare,
            ["vault_id": request.vault_id, "qid": request.card.qid, "digest": request.digest, "kind": choice.rawValue])
    }

    public func accessRequestAnswer(
        _ request: RelayAccessRequest, choice: AccessChoice, prepared: PreparedAccessAnswer, signature: Data?
    ) async throws -> SentAccessAnswer {
        var input: [String: Any] = [
            "vault_id": request.vault_id, "qid": request.card.qid, "digest": request.digest,
            "kind": choice.rawValue, "time": prepared.time,
        ]
        if let signature { input["signature"] = Base64URL.encode(signature) }
        return try await call(Op.answer, input)
    }

    public func accessRequestCancelPrepared() async { try? await call(Op.cancelPrepared) }

    public func wait(timeout: Int) async throws -> Bool {
        try await call(Op.wait, ["timeout": min(max(timeout, 1), 25)], as: Waited.self).changed
    }
}
