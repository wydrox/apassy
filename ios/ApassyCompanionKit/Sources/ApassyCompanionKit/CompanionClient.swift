// The client of the companion wire (contract sections 5 to 8).

import Foundation

/// The clock of the client.
public typealias TimeSource = @Sendable () -> Date
/// The source of request nonces. It returns 16 bytes each time.
public typealias NonceSource = @Sendable () -> Data

/// The answer to a pair request: the code to show, and the end of the window.
public struct PairingStart: Sendable, Equatable {
    /// The 6-digit code as the phone shows it: `348 942`. The owner types it on the Mac.
    public let code: String
    /// The end of the pairing window, Unix seconds.
    public let expiresAt: Int64
}

/// Talks to the Mac. Each signed request has a new time, a new nonce, and a signature over the
/// exact bytes that it sends.
public actor CompanionClient {
    /// An approval is sent again only while it is this young, in seconds. The Mac refuses an
    /// approval older than 60 s, so the margin keeps a late retry from a pointless refusal.
    static let approvalRetryWindow: Int64 = 55

    public static let randomNonce: NonceSource = { RandomBytes.make(16) }

    private let deviceID: String
    private let endpoint: CompanionEndpoint
    private let keys: any CompanionKeys
    private let transport: any CompanionTransport
    private let now: TimeSource
    private let nonce: NonceSource
    private var pairProof: String?

    /// The host that answered last. The app saves it in the pairing record.
    public private(set) var lastGoodHost: String?

    /// - Parameters:
    ///   - deviceID: 32 lowercase hex characters (`DeviceID.random()`).
    ///   - endpoint: The Mac.
    ///   - keys: The device keys.
    ///   - lastGoodHost: The host to try first.
    ///   - transport: The transport. The default is HTTPS with the pin check.
    ///   - now: The clock.
    ///   - nonce: The source of 16-byte nonces.
    public init(
        deviceID: String,
        endpoint: CompanionEndpoint,
        keys: any CompanionKeys,
        lastGoodHost: String? = nil,
        transport: (any CompanionTransport)? = nil,
        now: @escaping TimeSource = { Date() },
        nonce: @escaping NonceSource = CompanionClient.randomNonce
    ) {
        self.deviceID = deviceID
        self.endpoint = endpoint
        self.keys = keys
        self.lastGoodHost = lastGoodHost
        self.transport = transport ?? PinnedURLSessionTransport(pin: endpoint.pin)
        self.now = now
        self.nonce = nonce
    }

    /// A client for the pairing of a link.
    public init(
        link: PairingLink,
        deviceID: String,
        keys: any CompanionKeys,
        transport: (any CompanionTransport)? = nil,
        now: @escaping TimeSource = { Date() },
        nonce: @escaping NonceSource = CompanionClient.randomNonce
    ) {
        self.init(
            deviceID: deviceID, endpoint: link.endpoint, keys: keys, transport: transport, now: now, nonce: nonce)
    }

    /// A client for a paired Mac.
    public init(
        record: PairingRecord,
        keys: any CompanionKeys,
        transport: (any CompanionTransport)? = nil,
        now: @escaping TimeSource = { Date() },
        nonce: @escaping NonceSource = CompanionClient.randomNonce
    ) {
        self.init(
            deviceID: record.deviceID, endpoint: record.endpoint, keys: keys, lastGoodHost: record.lastGoodHost,
            transport: transport, now: now, nonce: nonce)
    }

    // MARK: Pairing

    /// Send the pair request (contract 5.3) and return the code to show.
    ///
    /// The code is computed here, after the Mac answered 200. It asks for Face ID once, for the
    /// approval key signature of the pair string.
    public func pair(link: PairingLink, deviceName: String) async throws -> PairingStart {
        try checkDeviceID()
        guard link.endpoint == endpoint else {
            throw CompanionError.invalidInput("The link is for another Mac than this client. Nothing was sent.")
        }
        if link.isExpired(at: now()) { throw CompanionError.linkExpired }
        try Self.checkDeviceName(deviceName)

        let requestKey = keys.requestPublicKey
        let approvalKey = keys.approvalPublicKey
        let pairString = try SigningStrings.pair(
            deviceID: deviceID, deviceName: deviceName, requestKey: requestKey, approvalKey: approvalKey)
        let message = Data(pairString.utf8)
        let proof = B64U.encode(SigningStrings.pairProof(secret: link.secret, pairString: pairString))
        let requestSignature = try keys.signRequest(message)
        let approvalSignature = try await keys.signApproval(
            message, reason: ApprovalPrompt.pairReason(macName: link.macName))

        let body = try Self.encode(
            PairRequestBody(
                deviceID: deviceID,
                deviceName: deviceName,
                requestKey: B64U.encode(requestKey),
                approvalKey: B64U.encode(approvalKey),
                requestKeySignature: B64U.encode(requestSignature),
                approvalKeySignature: B64U.encode(approvalSignature),
                proof: proof))
        let response = try await perform(method: "POST", path: "/v1/pair", body: body, signed: false)
        if response.status == 401 {
            throw link.isExpired(at: now()) ? CompanionError.linkExpired : CompanionError.linkRejected
        }
        let answer = try decode(PairResponse.self, from: response)
        pairProof = proof
        return PairingStart(
            code: PairingCode.display(secret: link.secret, requestKey: requestKey, approvalKey: approvalKey),
            expiresAt: answer.expiresAt)
    }

    /// Ask where the pairing is (contract 5.5). The app asks every 2 s after `pair`.
    ///
    /// When the Mac has dropped the answer (404), a signed status decides: `paired` when the Mac
    /// knows this device, else `expired`.
    public func pairStatus() async throws -> PairState {
        try checkDeviceID()
        guard let proof = pairProof else {
            throw CompanionError.invalidInput("No pairing is in progress.")
        }
        let response = try await perform(
            method: "GET", path: "/v1/pair/\(deviceID)", body: Data(), signed: false,
            headers: ["X-Apassy-Pair-Proof": proof])
        if response.status == 404 {
            do {
                return .paired(macName: try await status().macName)
            } catch CompanionError.unpaired {
                return .expired
            }
        }
        let answer = try decode(PairStatusResponse.self, from: response)
        guard let state = answer.pairState else { throw CompanionError.invalidResponse }
        return state
    }

    /// The record to save after the Mac said `paired`.
    public func pairingRecord(macName: String) -> PairingRecord {
        PairingRecord(
            deviceID: deviceID, macName: macName, hosts: endpoint.hosts, port: endpoint.port, pin: endpoint.pin,
            pairedAt: nowSeconds(), lastGoodHost: lastGoodHost)
    }

    // MARK: Signed requests

    /// `GET /v1/status`.
    public func status() async throws -> StatusInfo {
        try decode(StatusInfo.self, from: try await signed(method: "GET", path: "/v1/status"))
    }

    /// `GET /v1/inbox`: the runs that wait, the access requests, and the activity.
    public func inbox() async throws -> Inbox {
        try decode(Inbox.self, from: try await signed(method: "GET", path: "/v1/inbox"))
    }

    /// Approve a run, or approve and remember, with a Face ID signature (contract section 7).
    ///
    /// After a network error, a 423, or a 500, it sends the same approval signature again, with a
    /// new nonce, once, while the approval is younger than 55 s. The owner sees Face ID once.
    ///
    /// - Throws: `CompanionKeyError` when the owner cancels or the key cannot sign,
    ///   `CompanionError.approvalUnconfirmed` when a first attempt may have arrived and the retry
    ///   finds no run that waits or gets no answer either.
    public func approve(run: PendingRun, remember: Bool) async throws -> ApproveOutcome {
        try checkDeviceID()
        try Self.checkRunID(run.id)
        try Self.checkDigest(run.digest)
        if remember && run.remember == nil {
            throw CompanionError.invalidInput("This run has no offer to remember. Nothing was approved.")
        }
        let time = nowSeconds()
        let message = try SigningStrings.approve(
            deviceID: deviceID,
            action: remember ? .approveAndRemember : .approve,
            runID: run.id,
            digest: run.digest,
            time: time)
        let signature = try await keys.signApproval(
            Data(message.utf8), reason: ApprovalPrompt.approveReason(agent: run.agent))
        let body = try Self.encode(
            ApproveRequestBody(
                digest: run.digest, remember: remember, time: time, approvalSignature: B64U.encode(signature)))
        let path = "/v1/runs/\(run.id)/approve"

        do {
            return try await sendApproval(path: path, body: body)
        } catch let first as CompanionError {
            guard Self.mayHaveArrived(first) || first.isVaultLocked else { throw first }
            // The first attempt may have reached the Mac after a network error or a 500. A 423
            // says that the vault stopped it, so nothing was approved.
            let unknown = Self.mayHaveArrived(first)
            guard nowSeconds() - time < Self.approvalRetryWindow else {
                throw unknown ? CompanionError.approvalUnconfirmed : first
            }
            do {
                return try await sendApproval(path: path, body: body)
            } catch let second as CompanionError {
                // After a first attempt that may have arrived, a run that no longer waits may have
                // been approved by it, and a second failure without an answer tells nothing.
                if unknown, Self.isNotWaiting(second) || Self.hasNoAnswer(second) {
                    throw CompanionError.approvalUnconfirmed
                }
                throw second
            }
        }
    }

    /// Deny a run. It needs no Face ID.
    public func deny(run: PendingRun) async throws {
        try Self.checkRunID(run.id)
        _ = try decode(
            OutcomeResponse.self, from: try await signed(method: "POST", path: "/v1/runs/\(run.id)/deny", body: Self.emptyObject))
    }

    /// Deny an access request. The phone cannot give access.
    public func denyAccessRequest(id: String) async throws {
        try Self.checkRunID(id)
        _ = try decode(
            OutcomeResponse.self,
            from: try await signed(method: "POST", path: "/v1/access-requests/\(id)/deny", body: Self.emptyObject))
    }

    /// Remove this pairing from the Mac (`DELETE /v1/device`). The app then deletes its keys and
    /// its record. A Mac that no longer knows this device counts as done.
    public func unpair() async throws {
        do {
            _ = try decode(OutcomeResponse.self, from: try await signed(method: "DELETE", path: "/v1/device"))
        } catch CompanionError.unpaired {
            return
        }
    }

    // MARK: Internals

    static let emptyObject = Data("{}".utf8)

    /// A network error or a 500: the request may have reached the Mac.
    private static func mayHaveArrived(_ error: CompanionError) -> Bool {
        switch error {
        case .notReachable: return true
        case .server(500, _, _): return true
        default: return false
        }
    }

    /// The Mac says that no run with this ID waits.
    private static func isNotWaiting(_ error: CompanionError) -> Bool {
        if case .server(404, "not_waiting", _) = error { return true }
        return false
    }

    /// No host gave an answer, or the Mac answered with a 500: what the Mac did is not known.
    private static func hasNoAnswer(_ error: CompanionError) -> Bool {
        switch error {
        case .notReachable, .localNetworkDenied, .pinMismatchOnAllHosts: return true
        case .server(500, _, _): return true
        default: return false
        }
    }

    private func sendApproval(path: String, body: Data) async throws -> ApproveOutcome {
        try decode(ApproveResponse.self, from: try await signed(method: "POST", path: path, body: body)).outcome
    }

    private func signed(method: String, path: String, body: Data = Data()) async throws -> TransportResponse {
        try await perform(method: method, path: path, body: body, signed: true)
    }

    private func nowSeconds() -> Int64 {
        Int64(now().timeIntervalSince1970.rounded(.down))
    }

    /// Send to the hosts in order until one answers. The last good host goes first. A signed
    /// request is signed again for each host, with a new time and nonce.
    private func perform(
        method: String,
        path: String,
        body: Data,
        signed: Bool,
        headers extra: [String: String] = [:]
    ) async throws -> TransportResponse {
        var failures: [TransportFailure] = []
        for host in orderedHosts() {
            var headers = extra
            if !body.isEmpty { headers["Content-Type"] = "application/json" }
            if signed {
                headers.merge(try signedHeaders(method: method, path: path, body: body)) { $1 }
            }
            let request = TransportRequest(
                host: host, port: endpoint.port, method: method, path: path, headers: headers, body: body)
            do {
                let response = try await transport.send(request)
                lastGoodHost = host
                return response
            } catch {
                if error == .cancelled { throw CancellationError() }
                failures.append(error)
            }
        }
        throw CompanionError.from(failures: failures)
    }

    private func orderedHosts() -> [String] {
        guard let last = lastGoodHost, endpoint.hosts.contains(last) else { return endpoint.hosts }
        return [last] + endpoint.hosts.filter { $0 != last }
    }

    /// The four headers of contract section 6.
    private func signedHeaders(method: String, path: String, body: Data) throws -> [String: String] {
        try checkDeviceID()
        let time = nowSeconds()
        let nonceBytes = nonce()
        guard nonceBytes.count == 16 else {
            throw CompanionError.invalidInput("The nonce must have 16 bytes. Nothing was sent.")
        }
        let nonceText = B64U.encode(nonceBytes)
        let string = try SigningStrings.request(
            method: method, path: path, deviceID: deviceID, time: time, nonce: nonceText, body: body)
        let signature = try keys.signRequest(Data(string.utf8))
        return [
            "X-Apassy-Device": deviceID,
            "X-Apassy-Time": String(time),
            "X-Apassy-Nonce": nonceText,
            "X-Apassy-Signature": B64U.encode(signature),
        ]
    }

    private func decode<T: Decodable>(_ type: T.Type, from response: TransportResponse) throws -> T {
        guard response.status == 200 else {
            throw CompanionError.from(status: response.status, body: response.body)
        }
        do {
            return try JSONDecoder().decode(T.self, from: response.body)
        } catch {
            throw CompanionError.invalidResponse
        }
    }

    private func checkDeviceID() throws {
        guard DeviceID.isValid(deviceID) else {
            throw CompanionError.invalidInput("The device ID is not 32 lowercase hex characters. Nothing was sent.")
        }
    }

    /// The name of the phone: 1 to 40 characters (scalars), no control character, no space at the
    /// start or the end (contract section 2, "Characters").
    public static func checkDeviceName(_ name: String) throws {
        let scalars = name.unicodeScalars
        guard (1...TextRules.maxNameScalars).contains(scalars.count), !TextRules.hasControl(name),
            let first = scalars.first, let last = scalars.last,
            !TextRules.isSpace(first), !TextRules.isSpace(last)
        else {
            throw CompanionError.invalidInput(
                "The device name must have 1 to 40 characters, with no control character and no space at the start or the end.")
        }
    }

    private static func checkRunID(_ id: String) throws {
        guard !id.isEmpty, id.utf8.count <= 20, id.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else {
            throw CompanionError.invalidInput("The ID is not a decimal number. Nothing was sent.")
        }
    }

    private static func checkDigest(_ digest: String) throws {
        guard digest.utf8.count == 64, Hex.decode(digest) != nil else {
            throw CompanionError.invalidInput("The digest of the run is not 64 hex characters. Nothing was approved.")
        }
    }

    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return try encoder.encode(value)
    }
}

extension CompanionError {
    /// A 423: the vault was locked or changed during the request.
    fileprivate var isVaultLocked: Bool {
        if case .server(423, _, _) = self { return true }
        return false
    }
}
