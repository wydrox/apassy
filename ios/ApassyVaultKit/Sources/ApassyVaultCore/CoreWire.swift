import ApassyCoreFFI
import ApassyVaultKit
import Foundation

/// The core pointer. The core is thread-safe (contract section 2); the pointer never changes.
struct CorePointer: @unchecked Sendable { let raw: OpaquePointer }

/// One JSON call of the core (contract section 4), shared by `CoreVaultService` (the iPhone)
/// and `WatchCoreService` (the Apple Watch, ADR 0039).
enum CoreWire {
    private struct Envelope<Result: Decodable>: Decodable {
        struct Failure: Decodable {
            var code: String
            var message: String
            var rekeyed: Bool?
        }

        var ok: Bool
        var result: Result?
        var error: Failure?
    }

    /// `op` with `params` on `queue`, never on the main thread, decoded as `R`.
    static func call<R: Decodable & Sendable>(
        _ core: CorePointer, on queue: DispatchQueue, _ op: String, _ params: [String: Any]
    ) async throws -> R {
        var request = params
        request["op"] = op
        let data = try JSONSerialization.data(withJSONObject: request)
        let text = String(decoding: data, as: UTF8.self)
        return try await withCheckedThrowingContinuation { continuation in
            queue.async {
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
                        continuation.resume(throwing: VaultError(code, failure.message, rekeyed: failure.rekeyed ?? false))
                    } else {
                        continuation.resume(throwing: VaultError(.internal, "The vault core gave no answer."))
                    }
                } catch {
                    continuation.resume(throwing: VaultError(.internal, "The answer of the vault core is not valid."))
                }
            }
        }
    }
}
