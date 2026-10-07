import ApassyCoreFFI
import ApassyVaultKit
import Foundation

/// `VaultService` over the Rust core (contract ios-core-v1). One per process: the app,
/// or the AutoFill extension with `role: .autofill`.
///
/// Each call runs on a concurrent queue, never on the main thread. The core takes calls
/// from several threads at once, so a long poll or a sync does not hold up item calls.
public final class CoreVaultService: VaultService, @unchecked Sendable {
    public enum Role: String, Sendable { case app, autofill }

    /// The core is thread-safe (contract section 2); the pointer never changes.
    private struct Pointer: @unchecked Sendable { let raw: OpaquePointer }

    private let core: Pointer
    private let queue = DispatchQueue(label: "com.wydrox.apassy.core", qos: .userInitiated, attributes: .concurrent)

    /// - Parameters:
    ///   - dataDirectory: the App Group data folder (`SharedContainer.dataDirectory()`).
    ///   - deviceName: the name that the relay and the Macs show for this iPhone.
    public init(dataDirectory: URL, deviceName: String, role: Role) throws {
        let config: [String: Any] = [
            "data_dir": dataDirectory.path(percentEncoded: false),
            "device_name": deviceName,
            "role": role.rawValue,
        ]
        let data = try JSONSerialization.data(withJSONObject: config)
        let text = String(decoding: data, as: UTF8.self)
        guard let core = text.withCString({ apassy_core_new($0) }) else {
            throw VaultError(.internal, "The vault core did not start.")
        }
        self.core = Pointer(raw: core)
    }

    deinit {
        apassy_core_free(core.raw)
    }

    // MARK: - The wire

    private struct Envelope<Result: Decodable>: Decodable {
        struct Failure: Decodable {
            var code: String
            var message: String
        }

        var ok: Bool
        var result: Result?
        var error: Failure?
    }

    private struct Empty: Decodable {}

    /// One call: `op` with `params`, decoded as `R`.
    private func call<R: Decodable & Sendable>(
        _ op: String, _ params: [String: Any] = [:], as: R.Type = R.self
    ) async throws -> R {
        var request = params
        request["op"] = op
        let data = try JSONSerialization.data(withJSONObject: request)
        let text = String(decoding: data, as: UTF8.self)
        return try await withCheckedThrowingContinuation { continuation in
            queue.async { [core] in
                let answer: Data = text.withCString { request in
                    let pointer = apassy_core_call(core.raw, request)
                    defer { apassy_core_free_string(pointer) }
                    return Data(bytes: pointer, count: strlen(pointer))
                }
                do {
                    let envelope = try JSONDecoder().decode(Envelope<R>.self, from: answer)
                    if envelope.ok, let result = envelope.result {
                        continuation.resume(returning: result)
                    } else if let failure = envelope.error {
                        let code = VaultError.Code(rawValue: failure.code) ?? .internal
                        continuation.resume(throwing: VaultError(code, failure.message))
                    } else {
                        continuation.resume(throwing: VaultError(.internal, "The vault core gave no answer."))
                    }
                } catch {
                    continuation.resume(throwing: VaultError(.internal, "The answer of the vault core is not valid."))
                }
            }
        }
    }

    private func call(_ op: String, _ params: [String: Any] = [:]) async throws {
        _ = try await call(op, params, as: Empty.self)
    }

    private static func json<T: Encodable>(_ value: T) throws -> Any {
        try JSONSerialization.jsonObject(with: JSONEncoder().encode(value))
    }

    // MARK: - 5.1

    public func info() async throws -> CoreInfo { try await call("info") }

    public func select(vaultID: String) async throws { try await call("select", ["vault_id": vaultID]) }

    public func unlock(passphrase: String, keep: Bool) async throws {
        try await call("unlock", ["passphrase": passphrase, "keep": keep])
    }

    public func lock() async throws { try await call("lock") }

    public func suspend() async throws { try await call("suspend") }

    private struct Resumed: Decodable, Sendable { var unlocked: Bool }

    public func resume() async throws -> Bool { try await call("resume", as: Resumed.self).unlocked }

    private struct Checked: Decodable, Sendable { var ok: Bool }

    public func checkPassphrase(_ passphrase: String) async throws -> Bool {
        try await call("check_passphrase", ["passphrase": passphrase], as: Checked.self).ok
    }

    private struct VaultAnswer: Decodable, Sendable { var vault: VaultEntry }

    public func createLocalVault(name: String, passphrase: String) async throws -> VaultEntry {
        try await call("create_local_vault", ["name": name, "passphrase": passphrase], as: VaultAnswer.self).vault
    }

    private struct Removed: Decodable, Sendable {
        var leftRelay: Bool
        enum CodingKeys: String, CodingKey { case leftRelay = "left_relay" }
    }

    public func removeVault(id: String, force: Bool) async throws -> Bool {
        try await call("remove_vault", ["vault_id": id, "force": force], as: Removed.self).leftRelay
    }

    // MARK: - 5.2

    public func joinStart(link: String, deviceName: String) async throws -> JoinInfo {
        try await call("join_start", ["link": link, "device_name": deviceName])
    }

    public func joinPoll() async throws -> JoinInfo { try await call("join_poll") }

    public func joinCancel() async throws { try await call("join_cancel") }

    public func joinFinish(passphrase: String) async throws -> VaultEntry {
        try await call("join_finish", ["passphrase": passphrase], as: VaultAnswer.self).vault
    }

    // MARK: - 5.3

    private struct Items: Decodable, Sendable { var items: [ItemRow] }

    public func items(archived: ArchiveFilter) async throws -> [ItemRow] {
        try await call("items", ["archived": archived.rawValue], as: Items.self).items
    }

    public func item(id: UInt64) async throws -> ItemDetail { try await call("item", ["id": id]) }

    private struct Revealed: Decodable, Sendable { var value: String }

    public func reveal(id: UInt64, field: String) async throws -> String {
        try await call("reveal", ["id": id, "field": field], as: Revealed.self).value
    }

    public func totp(id: UInt64, field: String) async throws -> TotpCode {
        try await call("totp", ["id": id, "field": field])
    }

    private struct Events: Decodable, Sendable { var events: [ItemEvent] }

    public func history(id: UInt64) async throws -> [ItemEvent] {
        try await call("history", ["id": id], as: Events.self).events
    }

    public func save(id: UInt64?, revision: UInt64?, draft: ItemDraft) async throws -> SavedItem {
        try await call(
            "save",
            [
                "id": id.map { $0 as Any } ?? NSNull(),
                "revision": revision.map { $0 as Any } ?? NSNull(),
                "item": try Self.json(draft),
            ])
    }

    public func archive(id: UInt64, archived: Bool) async throws {
        try await call("archive", ["id": id, "archived": archived])
    }

    public func delete(id: UInt64, revision: UInt64) async throws {
        try await call("delete", ["id": id, "revision": revision])
    }

    // MARK: - 5.4

    public func generate(_ options: GeneratorOptions) async throws -> GeneratedPassword {
        guard var params = try Self.json(options) as? [String: Any] else {
            throw VaultError(.internal, "The generator options are not valid.")
        }
        params["op"] = nil
        return try await call("generate", params)
    }

    public func strength(_ value: String) async throws -> Strength { try await call("strength", ["value": value]) }

    public func watchtower() async throws -> WatchtowerReport { try await call("watchtower") }

    // MARK: - 5.5

    private struct StatusAnswer: Decodable, Sendable { var status: SyncStatus }

    public func sync() async throws -> SyncStatus { try await call("sync", as: StatusAnswer.self).status }

    public func syncStatus() async throws -> SyncStatus { try await call("sync_status", as: StatusAnswer.self).status }

    private struct Waited: Decodable, Sendable { var changed: Bool }

    public func syncWait(timeout: Int) async throws -> Bool {
        try await call("sync_wait", ["timeout": timeout], as: Waited.self).changed
    }

    public func takeNewPassphrase(_ passphrase: String) async throws -> SyncStatus {
        try await call("take_new_passphrase", ["passphrase": passphrase], as: StatusAnswer.self).status
    }

    public func useRelayCopy() async throws -> SyncStatus {
        try await call("use_relay_copy", as: StatusAnswer.self).status
    }

    private struct Devices: Decodable, Sendable { var devices: [RelayDevice] }

    public func devices() async throws -> [RelayDevice] { try await call("devices", as: Devices.self).devices }

    // MARK: - 5.7

    public func autofillList(domains: [String]) async throws -> AutofillList {
        try await call("autofill_list", ["domains": domains])
    }

    public func autofillCredential(id: UInt64) async throws -> FillCredential {
        try await call("autofill_credential", ["id": id])
    }

    private struct Identities: Decodable, Sendable { var identities: [CredentialIdentity] }

    public func credentialIdentities() async throws -> [CredentialIdentity] {
        try await call("credential_identities", as: Identities.self).identities
    }
}
