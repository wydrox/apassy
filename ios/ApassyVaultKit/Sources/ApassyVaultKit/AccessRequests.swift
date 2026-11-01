import Foundation

public enum AccessChoice: String, Codable, Sendable { case deny, allow_once }

public struct RelayAccessCard: Codable, Equatable, Sendable {
    public struct Asker: Codable, Equatable, Sendable {
        public let device: String
        public let relay_device_id: UInt64
        public let name: String
    }
    public struct Agent: Codable, Equatable, Sendable {
        public let id: String
        public let name: String
        public let host: String?
        public let host_source: String
    }
    public struct Item: Codable, Equatable, Sendable {
        public let local_id: String
        public let uuid: String
        public let revision: String
        public let name: String
        public let environment: String
        public let delivery: String
        public let binding_name: String
    }
    public struct Project: Codable, Equatable, Sendable {
        public let key: String
        public let label: String
    }
    public let vault_id: String
    public let team_id: String
    public let qid: String
    public let key_id: String
    public let to: String
    public let request_id: String
    public let asker: Asker
    public let vault_name: String
    public let agent: Agent
    public let item: Item
    public let project: Project?
    public let cwd: String
    public let action: String?
    public let hosts: [String]
    public let scope_source: String
    public let reason: String
    public let policy_digest: String
    public let created_at: UInt64
    public let expires_at: UInt64
    public let valid_answers: [AccessChoice]
    public let local_review_reason: String?
}

public struct AccessReceipt: Codable, Equatable, Sendable {
    public let vault_id: String
    public let team_id: String
    public let qid: String
    public let request_id: String
    public let asker: String
    public let digest: String
    public let outcome: String
    public let answered_by: String?
    public let device_name: String?
    public let device_kind: String?
    public let kind: String?
    public let at: UInt64
    public let expires_at: UInt64
}

/// ApassyCore verifies the Mac signature and trust before returning this projection.
public struct RelayAccessRequest: Codable, Equatable, Identifiable, Sendable {
    public let vault_id: String
    public let card: RelayAccessCard
    public let digest: String
    public let state: String
    public let receipt: AccessReceipt?
    public let answer_key: String?
    public var id: String { "\(vault_id):\(card.vault_id):\(card.asker.device):\(card.request_id):\(card.qid):\(digest)" }
}
public struct AccessRequestsSnapshot: Decodable, Sendable {
    public let protocolName: String
    public let version: Int
    public let requests: [RelayAccessRequest]
    enum CodingKeys:String,CodingKey { case protocolName = "protocol",version,requests }
}
public struct PreparedAccessAnswer: Decodable, Sendable {
    public let bytes: String
    public let time: UInt64
    public let digest: String
    public let needs_face_id: Bool
    public let retry_before: UInt64
}
public struct SentAccessAnswer: Decodable, Sendable { public let sent: Bool }
