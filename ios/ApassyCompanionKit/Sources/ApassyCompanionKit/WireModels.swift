// The JSON bodies of the wire (contract sections 4, 5, and 7).
//
// IDs are strings. A response can have fields that these types do not know; they are ignored.
// None of these types holds a secret value.

import Foundation

/// The body of `POST /v1/pair`.
struct PairRequestBody: Encodable, Equatable {
    var v = 1
    var deviceID: String
    var deviceName: String
    var requestKey: String
    var approvalKey: String
    var requestKeySignature: String
    var approvalKeySignature: String
    var proof: String

    enum CodingKeys: String, CodingKey {
        case v
        case deviceID = "device_id"
        case deviceName = "device_name"
        case requestKey = "request_key"
        case approvalKey = "approval_key"
        case requestKeySignature = "request_key_signature"
        case approvalKeySignature = "approval_key_signature"
        case proof
    }
}

/// The answer to `POST /v1/pair`.
public struct PairResponse: Decodable, Sendable, Equatable {
    /// The end of the pairing window, Unix seconds.
    public let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case expiresAt = "expires_at"
    }
}

/// The answer to `GET /v1/pair/<device_id>`.
public struct PairStatusResponse: Decodable, Sendable, Equatable {
    public let state: String
    public let macName: String?

    enum CodingKeys: String, CodingKey {
        case state
        case macName = "mac_name"
    }

    /// The state as a value, or nil for a state that this version does not know.
    public var pairState: PairState? {
        switch state {
        case "waiting": return .waiting
        case "paired": return macName.map { .paired(macName: $0) }
        case "denied": return .denied
        case "expired": return .expired
        default: return nil
        }
    }
}

/// Where a pairing is, as the Mac reports it.
public enum PairState: Sendable, Equatable {
    /// The owner has not confirmed yet.
    case waiting
    case paired(macName: String)
    case denied
    case expired
}

/// The answer to `GET /v1/status`.
public struct StatusInfo: Decodable, Sendable, Equatable {
    public let v: Int
    public let macName: String
    public let appVersion: String
    public let approvalTimeoutSeconds: Int
    public let device: DeviceInfo

    enum CodingKeys: String, CodingKey {
        case v
        case macName = "mac_name"
        case appVersion = "app_version"
        case approvalTimeoutSeconds = "approval_timeout_seconds"
        case device
    }
}

/// This phone, as the Mac knows it.
public struct DeviceInfo: Decodable, Sendable, Equatable {
    public let id: String
    public let name: String
    public let pairedAt: Int64

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case pairedAt = "paired_at"
    }
}

/// The answer to `GET /v1/inbox`.
public struct Inbox: Decodable, Sendable, Equatable {
    /// The runs that wait, oldest first.
    public let runs: [PendingRun]
    public let accessRequests: [AccessRequest]
    /// The newest 50 entries, newest first.
    public let activity: [ActivityEntry]

    public init(runs: [PendingRun], accessRequests: [AccessRequest], activity: [ActivityEntry]) {
        self.runs = runs
        self.accessRequests = accessRequests
        self.activity = activity
    }

    enum CodingKeys: String, CodingKey {
        case runs
        case accessRequests = "access_requests"
        case activity
    }
}

/// A run that waits for the owner.
public struct PendingRun: Decodable, Sendable, Equatable, Identifiable {
    public let id: String
    public let agent: String
    public let command: [String]
    public let cwd: String?
    public let envNames: [String]
    public let purpose: String
    public let risk: String
    public let userRequest: String
    public let requestSource: String
    public let agentRequest: String
    /// The offer to remember the pattern, or nil.
    public let remember: RememberOffer?
    /// Opaque. The phone sends it back with the approval.
    public let digest: String
    /// Seconds since the run started to wait, or nil when the Mac does not know.
    public let waitingSeconds: Int?

    public init(
        id: String, agent: String, command: [String], cwd: String?, envNames: [String], purpose: String,
        risk: String, userRequest: String, requestSource: String, agentRequest: String,
        remember: RememberOffer?, digest: String, waitingSeconds: Int?
    ) {
        self.id = id
        self.agent = agent
        self.command = command
        self.cwd = cwd
        self.envNames = envNames
        self.purpose = purpose
        self.risk = risk
        self.userRequest = userRequest
        self.requestSource = requestSource
        self.agentRequest = agentRequest
        self.remember = remember
        self.digest = digest
        self.waitingSeconds = waitingSeconds
    }

    enum CodingKeys: String, CodingKey {
        case id, agent, command, cwd, purpose, risk, remember, digest
        case envNames = "env_names"
        case userRequest = "user_request"
        case requestSource = "request_source"
        case agentRequest = "agent_request"
        case waitingSeconds = "waiting_seconds"
    }
}

/// The offer to remember a pattern after enough approvals (ADR 0010).
public struct RememberOffer: Decodable, Sendable, Equatable {
    public let pattern: String
    public let approvals: Int
    public let needed: Int

    public init(pattern: String, approvals: Int, needed: Int) {
        self.pattern = pattern
        self.approvals = approvals
        self.needed = needed
    }
}

/// An agent asks for access to an item (ADR 0012). The phone can only deny it.
public struct AccessRequest: Decodable, Sendable, Equatable, Identifiable {
    public let id: String
    public let agent: String
    public let itemName: String
    public let reason: String
    public let cwd: String?
    public let requestedAt: Int64

    public init(id: String, agent: String, itemName: String, reason: String, cwd: String?, requestedAt: Int64) {
        self.id = id
        self.agent = agent
        self.itemName = itemName
        self.reason = reason
        self.cwd = cwd
        self.requestedAt = requestedAt
    }

    enum CodingKeys: String, CodingKey {
        case id, agent, reason, cwd
        case itemName = "item_name"
        case requestedAt = "requested_at"
    }
}

/// One entry of the activity log.
public struct ActivityEntry: Decodable, Sendable, Equatable, Identifiable {
    public let id: String
    public let at: Int64
    public let agent: String
    /// `allow`, `deny`, or `error`.
    public let decision: String
    public let summary: String
    public let reason: String

    public init(id: String, at: Int64, agent: String, decision: String, summary: String, reason: String) {
        self.id = id
        self.at = at
        self.agent = agent
        self.decision = decision
        self.summary = summary
        self.reason = reason
    }
}

/// The body of `POST /v1/runs/<id>/approve`.
struct ApproveRequestBody: Encodable, Equatable {
    var digest: String
    var remember: Bool
    var time: Int64
    var approvalSignature: String

    enum CodingKeys: String, CodingKey {
        case digest, remember, time
        case approvalSignature = "approval_signature"
    }
}

/// The outcome of an approval.
public enum ApproveOutcome: String, Decodable, Sendable, Equatable {
    case approved
    case approvedAndRemembered = "approved_and_remembered"
}

/// The answer to an approval: `{"outcome":"approved"}`.
struct ApproveResponse: Decodable {
    let outcome: ApproveOutcome
}

/// The answer to a denial or to `DELETE /v1/device`.
struct OutcomeResponse: Decodable {
    let outcome: String
}

/// The body of an error answer (contract section 4).
struct ErrorEnvelope: Decodable {
    struct Body: Decodable {
        let code: String
        let message: String
    }

    let error: Body
}
