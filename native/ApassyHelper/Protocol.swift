// JSON-lines protocol of the Apassy native helper.
//
// One request is one JSON object on one line. The helper writes one JSON
// object on one line for each request. The contract is in
// docs/operations/native-app.md. Keep the error codes in sync with
// src/native/mod.rs.
//
// The helper never writes a secret value to stderr or to a log. Only a
// successful keychain_read response carries a value, in `secret_b64`.

import Foundation

let protocolVersion = 1
let helperVersion = "0.1.0"
let maxRequestBytes = 64 * 1024

/// Stable error codes. The Rust client maps each code to a typed variant.
enum ErrorCode: String {
    case invalidRequest = "invalid_request"
    case cancelled = "cancelled"
    case fallback = "fallback"
    case notAvailable = "not_available"
    case notEnrolled = "not_enrolled"
    case lockedOut = "locked_out"
    case failed = "failed"
    case keychainUnavailable = "keychain_unavailable"
    case notFound = "not_found"
    case biometryChanged = "biometry_changed"
    case notificationsUnavailable = "notifications_unavailable"
    case notificationsDenied = "notifications_denied"
    case callerNotAllowed = "caller_not_allowed"
    case internalError = "internal"
}

struct HelperError: Error {
    let code: ErrorCode
    let message: String

    init(_ code: ErrorCode, _ message: String) {
        self.code = code
        self.message = message
    }
}

typealias Fields = [String: Any]

/// A parsed request. Field access validates type, length, and characters.
struct Request {
    let cmd: String
    let fields: Fields

    static func parse(_ line: String) throws -> Request {
        if line.utf8.count > maxRequestBytes {
            throw HelperError(.invalidRequest, "The request is larger than \(maxRequestBytes) bytes.")
        }
        guard let data = line.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let fields = object as? Fields
        else {
            throw HelperError(.invalidRequest, "The request is not a JSON object.")
        }
        guard let cmd = fields["cmd"] as? String, !cmd.isEmpty else {
            throw HelperError(.invalidRequest, "The request has no \"cmd\" string.")
        }
        return Request(cmd: cmd, fields: fields)
    }

    func string(_ name: String) throws -> String {
        guard let value = fields[name] as? String else {
            throw HelperError(.invalidRequest, "The field \"\(name)\" must be a string.")
        }
        return value
    }

    /// An identifier: 1 to 64 characters from A-Z, a-z, 0-9, ".", "_", "-".
    func identifier(_ name: String) throws -> String {
        let value = try string(name)
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard (1...64).contains(value.count),
              value.unicodeScalars.allSatisfy({ allowed.contains($0) })
        else {
            throw HelperError(.invalidRequest, "The field \"\(name)\" must have 1 to 64 characters from A-Z, a-z, 0-9, '.', '_', '-'.")
        }
        return value
    }

    /// Display text: `min` to `max` characters, no control characters.
    func text(_ name: String, min: Int, max: Int) throws -> String {
        let value = try string(name)
        guard (min...max).contains(value.count),
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else {
            throw HelperError(.invalidRequest, "The field \"\(name)\" must have \(min) to \(max) characters and no control characters.")
        }
        return value
    }
}

/// Write one response line to stdout and flush it.
func writeResponse(_ object: Fields) {
    var body = object
    if body["ok"] == nil {
        body["ok"] = true
    }
    let data: Data
    do {
        data = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
    } catch {
        let fallback = "{\"error\":\"internal\",\"message\":\"The helper could not encode its response.\",\"ok\":false}"
        FileHandle.standardOutput.write(Data((fallback + "\n").utf8))
        return
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

func errorResponse(_ error: HelperError) -> Fields {
    ["ok": false, "error": error.code.rawValue, "message": error.message]
}

/// A thread-safe box for a result from a completion handler.
final class ResultBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T?

    func set(_ value: T) {
        lock.lock()
        stored = value
        lock.unlock()
    }

    func get() -> T? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }
}
