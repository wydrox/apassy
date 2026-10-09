// What the bridge accepts from the extension, what it writes to the app, and what it
// accepts back. Pure functions: the tests compile this file without the server.
//
// A request of the extension is one call of the iOS core wire (contract.txt), with
// standard base64 bytes. The bridge accepts only the calls below, checks every field,
// refuses any other field (for example "verified" or "peer"), and forwards a
// re-encoded copy. So the app never sees a field that the bridge did not check, and
// the provenance in the envelope comes from the bridge alone.
//
// To the app (stdout, one JSON object per line):
//   {"type":"ready","v":1,"socket":"<path>"}
//   {"type":"request","v":1,"rid":"<UUID>","peer":{…},"payload":{"op":…}}
//   {"type":"cancel","v":1,"rid":"<UUID>","reason":"peer_closed"|"timeout"|"bridge_closing"}
// From the app (stdin, one JSON object per line):
//   {"type":"response","rid":"<UUID>","result":{"ok":true,"result":{…}}}
//   {"type":"response","rid":"<UUID>","result":{"ok":false,"error":{"code":"…","message":"…"}}}
//   {"type":"shutdown"}

import Foundation

typealias JSONObject = [String: Any]

/// The calls of the extension.
enum BridgeOp: String, CaseIterable {
    case passkeyList = "passkey_list"
    case passkeyAssert = "passkey_assert"
    case passkeyRegister = "passkey_register"
    case autofillList = "autofill_list"
    case autofillCredential = "autofill_credential"
    case autofillCode = "autofill_code"
    case credentialIdentities = "credential_identities"

    /// The app runs a fresh owner check (Touch ID or passphrase) before it answers.
    var needsOwnerCheck: Bool {
        switch self {
        case .passkeyAssert, .passkeyRegister, .autofillCredential, .autofillCode: true
        case .passkeyList, .autofillList, .credentialIdentities: false
        }
    }
}

/// A refused request. The message never quotes a value of the request.
struct RequestError: Error, Equatable {
    let message: String

    init(_ message: String) {
        self.message = message
    }
}

struct CheckedRequest {
    let op: BridgeOp
    /// The re-encoded call, with "op".
    let payload: JSONObject
}

enum WireLimits {
    static let maxRpIdBytes = 253
    static let maxCredentialIdBytes = 1023
    static let maxUserHandleBytes = 64
    static let maxPersonBytes = 256
    static let maxTitleBytes = 128
    static let maxCredentials = 256
    static let maxAlgorithms = 32
    static let maxDomains = 16
    static let maxDomainBytes = 2048
    /// JSON numbers above 2^53 - 1 lose precision in many readers.
    static let maxInteger: UInt64 = (1 << 53) - 1
    static let maxErrorMessageCharacters = 1024
}

// MARK: - Requests of the extension

func checkRequest(_ body: Data) throws -> CheckedRequest {
    guard body.count <= BridgeConstants.maxRequestBytes else {
        throw RequestError("The request is too large.")
    }
    guard let object = try? JSONSerialization.jsonObject(with: body), let fields = object as? JSONObject else {
        throw RequestError("The request is not a JSON object.")
    }
    let reader = FieldReader(fields)
    guard let name = fields["op"] as? String, let op = BridgeOp(rawValue: name) else {
        throw RequestError("The request names no call of AutoFill.")
    }
    var payload: JSONObject = ["op": op.rawValue]
    switch op {
    case .passkeyList:
        try reader.only(["op", "rp_id", "allowed"])
        payload["rp_id"] = try reader.rpId("rp_id")
        payload["allowed"] = try reader.base64List("allowed", maxBytes: WireLimits.maxCredentialIdBytes, optional: true)
    case .passkeyAssert:
        try reader.only(["op", "id", "rp_id", "credential_id", "client_data_hash"])
        payload["id"] = try reader.integer("id")
        payload["rp_id"] = try reader.rpId("rp_id")
        payload["credential_id"] = try reader.base64("credential_id", minBytes: 1, maxBytes: WireLimits.maxCredentialIdBytes)
        payload["client_data_hash"] = try reader.base64("client_data_hash", minBytes: 32, maxBytes: 32)
    case .passkeyRegister:
        try reader.only([
            "op", "rp_id", "user_name", "user_display_name", "user_handle", "client_data_hash", "algorithms",
            "excluded", "attach_id", "attach_revision", "title",
        ])
        payload["rp_id"] = try reader.rpId("rp_id")
        payload["user_name"] = try reader.text("user_name", maxBytes: WireLimits.maxPersonBytes)
        payload["user_display_name"] = try reader.text("user_display_name", maxBytes: WireLimits.maxPersonBytes, optional: true)
        payload["user_handle"] = try reader.base64("user_handle", minBytes: 1, maxBytes: WireLimits.maxUserHandleBytes)
        payload["client_data_hash"] = try reader.base64("client_data_hash", minBytes: 32, maxBytes: 32)
        payload["algorithms"] = try reader.algorithms("algorithms")
        payload["excluded"] = try reader.base64List("excluded", maxBytes: WireLimits.maxCredentialIdBytes, optional: true)
        let attachId = try reader.optionalInteger("attach_id")
        let attachRevision = try reader.optionalInteger("attach_revision")
        switch (attachId, attachRevision) {
        case let (id?, revision?):
            payload["attach_id"] = id
            payload["attach_revision"] = revision
        case (nil, nil):
            break
        default:
            throw RequestError("Adding a passkey to a login needs its id and its revision.")
        }
        payload["title"] = try reader.text("title", maxBytes: WireLimits.maxTitleBytes, optional: true)
    case .autofillList:
        try reader.only(["op", "domains"])
        payload["domains"] = try reader.domains("domains")
    case .autofillCredential, .autofillCode:
        try reader.only(["op", "id"])
        payload["id"] = try reader.integer("id")
    case .credentialIdentities:
        try reader.only(["op"])
    }
    return CheckedRequest(op: op, payload: payload)
}

/// Typed access to the fields of one request. Each check names the field, never its value.
struct FieldReader {
    let fields: JSONObject

    init(_ fields: JSONObject) {
        self.fields = fields
    }

    func only(_ allowed: Set<String>) throws {
        guard Set(fields.keys).isSubset(of: allowed) else {
            throw RequestError("The request has a field that this call does not take.")
        }
    }

    func string(_ name: String) throws -> String {
        guard let value = fields[name] as? String else {
            throw RequestError("The field \"\(name)\" must be a string.")
        }
        return value
    }

    func rpId(_ name: String) throws -> String {
        let value = try string(name)
        guard isRelyingPartyId(value) else {
            throw RequestError("The field \"\(name)\" is not a valid website.")
        }
        return value
    }

    /// Text without control or bidi formatting characters. Absent counts as "" when optional.
    func text(_ name: String, maxBytes: Int, optional: Bool = false) throws -> String {
        if optional, fields[name] == nil {
            return ""
        }
        let value = try string(name)
        guard value.utf8.count <= maxBytes, !hasHiddenCharacters(value) else {
            throw RequestError("The field \"\(name)\" is too long or has control characters.")
        }
        return value
    }

    func base64(_ name: String, minBytes: Int, maxBytes: Int) throws -> String {
        let value = try string(name)
        guard let bytes = canonicalBase64(value, maxBytes: maxBytes), bytes.count >= minBytes else {
            throw RequestError("The field \"\(name)\" is not valid base64 of the right size.")
        }
        return value
    }

    func base64List(_ name: String, maxBytes: Int, optional: Bool) throws -> [String] {
        guard let raw = fields[name] else {
            if optional { return [] }
            throw RequestError("The field \"\(name)\" is missing.")
        }
        guard let list = raw as? [Any], list.count <= WireLimits.maxCredentials else {
            throw RequestError("The field \"\(name)\" must be a list of at most \(WireLimits.maxCredentials) values.")
        }
        return try list.map { item in
            guard let text = item as? String, let bytes = canonicalBase64(text, maxBytes: maxBytes), !bytes.isEmpty else {
                throw RequestError("The field \"\(name)\" has a value that is not valid base64.")
            }
            return text
        }
    }

    func integer(_ name: String) throws -> UInt64 {
        guard let value = jsonInteger(fields[name]) else {
            throw RequestError("The field \"\(name)\" must be a whole number.")
        }
        return value
    }

    func optionalInteger(_ name: String) throws -> UInt64? {
        guard let raw = fields[name], !(raw is NSNull) else {
            return nil
        }
        guard let value = jsonInteger(raw) else {
            throw RequestError("The field \"\(name)\" must be a whole number.")
        }
        return value
    }

    func algorithms(_ name: String) throws -> [Int64] {
        guard let raw = fields[name] else {
            return []
        }
        guard let list = raw as? [Any], list.count <= WireLimits.maxAlgorithms else {
            throw RequestError("The field \"\(name)\" must be a list of at most \(WireLimits.maxAlgorithms) numbers.")
        }
        return try list.map { item in
            guard let number = item as? NSNumber, !isBoolean(number), !CFNumberIsFloatType(number),
                  number.int64Value >= Int64(Int32.min), number.int64Value <= Int64(Int32.max),
                  number == NSNumber(value: number.int64Value)
            else {
                throw RequestError("The field \"\(name)\" has a value that is not an algorithm number.")
            }
            return number.int64Value
        }
    }

    func domains(_ name: String) throws -> [String] {
        guard let list = fields[name] as? [Any], list.count <= WireLimits.maxDomains else {
            throw RequestError("The field \"\(name)\" must be a list of at most \(WireLimits.maxDomains) values.")
        }
        return try list.map { item in
            guard let text = item as? String, !text.isEmpty, text.utf8.count <= WireLimits.maxDomainBytes,
                  !hasHiddenCharacters(text)
            else {
                throw RequestError("The field \"\(name)\" has a value that is not a website.")
            }
            return text
        }
    }
}

/// A relying party ID as the core accepts it: ASCII letters, digits, "-", ".", "_".
func isRelyingPartyId(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    guard !bytes.isEmpty, bytes.count <= WireLimits.maxRpIdBytes,
          let first = bytes.first, let last = bytes.last,
          first != UInt8(ascii: "."), first != UInt8(ascii: "-"),
          last != UInt8(ascii: "."), last != UInt8(ascii: "-"),
          !value.contains("..")
    else {
        return false
    }
    return bytes.allSatisfy { byte in
        (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
            || byte == UInt8(ascii: "-") || byte == UInt8(ascii: ".") || byte == UInt8(ascii: "_")
    }
}

/// Control characters and the invisible bidi and zero-width formatting characters.
func hasHiddenCharacters(_ value: String) -> Bool {
    value.unicodeScalars.contains { scalar in
        CharacterSet.controlCharacters.contains(scalar)
            || (0x200B...0x200F).contains(scalar.value) || (0x202A...0x202E).contains(scalar.value)
            || (0x2066...0x2069).contains(scalar.value) || scalar.value == 0xFEFF
    }
}

/// The bytes of canonical standard base64 with padding, or nil. Canonical means that
/// encoding the bytes again gives the same text, so the spare bits are zero.
func canonicalBase64(_ text: String, maxBytes: Int) -> Data? {
    guard !text.isEmpty, text.utf8.count % 4 == 0, text.utf8.count / 4 * 3 <= maxBytes + 2,
          let bytes = Data(base64Encoded: text), bytes.count <= maxBytes,
          bytes.base64EncodedString() == text
    else {
        return nil
    }
    return bytes
}

func isBoolean(_ number: NSNumber) -> Bool {
    CFGetTypeID(number) == CFBooleanGetTypeID()
}

/// A JSON whole number from 0 to 2^53 - 1. Not a boolean, not a fraction.
func jsonInteger(_ raw: Any?) -> UInt64? {
    guard let number = raw as? NSNumber, !isBoolean(number), !CFNumberIsFloatType(number) else {
        return nil
    }
    let value = number.int64Value
    guard value >= 0, UInt64(value) <= WireLimits.maxInteger, number == NSNumber(value: value) else {
        return nil
    }
    return UInt64(value)
}

// MARK: - Lines to the app

/// The provenance of a request, set by the bridge after the peer check. The app takes
/// it from the bridge (its own child), never from the extension.
struct Provenance {
    /// "code_signature", or "development_override" in a development build. The app must
    /// refuse "development_override" in a release.
    let check: String
    let signingIdentifier: String
    let team: String
    let pid: pid_t
    let path: String

    var json: JSONObject {
        [
            "source": "macos_autofill_extension",
            "check": check,
            "signing_identifier": signingIdentifier,
            "team": team,
            "pid": Int(pid),
            "path": path,
        ]
    }
}

func jsonLine(_ object: JSONObject) -> Data? {
    guard JSONSerialization.isValidJSONObject(object),
          var data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    else {
        return nil
    }
    data.append(0x0A)
    return data
}

func readyLine(socket: String) -> Data? {
    jsonLine(["type": "ready", "v": BridgeConstants.protocolVersion, "socket": socket])
}

func requestLine(rid: String, request: CheckedRequest, peer: Provenance) -> Data? {
    jsonLine([
        "type": "request", "v": BridgeConstants.protocolVersion, "rid": rid,
        "owner_check": request.op.needsOwnerCheck, "peer": peer.json, "payload": request.payload,
    ])
}

enum CancelReason: String {
    case peerClosed = "peer_closed"
    case timeout = "timeout"
    case bridgeClosing = "bridge_closing"
}

func cancelLine(rid: String, reason: CancelReason) -> Data? {
    jsonLine(["type": "cancel", "v": BridgeConstants.protocolVersion, "rid": rid, "reason": reason.rawValue])
}

// MARK: - Lines from the app

enum AppMessage {
    case response(rid: String, result: JSONObject)
    case shutdown
}

func parseAppLine(_ line: Data) throws -> AppMessage {
    guard line.count <= BridgeConstants.maxResponseBytes + 4096 else {
        throw RequestError("The line of the app is too large.")
    }
    guard let object = try? JSONSerialization.jsonObject(with: line), let fields = object as? JSONObject,
          let type = fields["type"] as? String
    else {
        throw RequestError("The line of the app is not a JSON object with a type.")
    }
    switch type {
    case "shutdown":
        return .shutdown
    case "response":
        guard Set(fields.keys).isSubset(of: ["type", "rid", "result"]),
              let rid = fields["rid"] as? String, UUID(uuidString: rid) != nil,
              let result = fields["result"] as? JSONObject
        else {
            throw RequestError("The response of the app has a wrong shape.")
        }
        return .response(rid: rid, result: try checkResult(result))
    default:
        throw RequestError("The app sent an unknown line type.")
    }
}

/// The result as the core writes it: {"ok":true,"result":{…}} or
/// {"ok":false,"error":{"code","message"}}. The bridge forwards only these shapes.
func checkResult(_ result: JSONObject) throws -> JSONObject {
    guard let okNumber = result["ok"] as? NSNumber, isBoolean(okNumber) else {
        throw RequestError("The result has no \"ok\" boolean.")
    }
    if okNumber.boolValue {
        guard Set(result.keys) == ["ok", "result"], result["result"] is JSONObject else {
            throw RequestError("A successful result must have a \"result\" object.")
        }
    } else {
        guard Set(result.keys) == ["ok", "error"], let error = result["error"] as? JSONObject,
              Set(error.keys) == ["code", "message"],
              let code = error["code"] as? String, isErrorCode(code),
              let message = error["message"] as? String, message.count <= WireLimits.maxErrorMessageCharacters
        else {
            throw RequestError("A failed result must have an error with a code and a message.")
        }
    }
    return result
}

func isErrorCode(_ code: String) -> Bool {
    let bytes = Array(code.utf8)
    guard (1...64).contains(bytes.count), let first = bytes.first, first >= 0x61, first <= 0x7A else {
        return false
    }
    return bytes.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == UInt8(ascii: "_") }
}

// MARK: - Frames to the extension

/// The frame of a result for the extension, or nil when it is too large.
func resultFrame(_ result: JSONObject) -> Data? {
    guard JSONSerialization.isValidJSONObject(result),
          let body = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys, .withoutEscapingSlashes])
    else {
        return nil
    }
    return try? encodeFrame(body, max: BridgeConstants.maxResponseBytes)
}

/// The frame of an error of the bridge itself.
func errorFrame(code: String, message: String) -> Data? {
    resultFrame(["ok": false, "error": ["code": code, "message": message]])
}
