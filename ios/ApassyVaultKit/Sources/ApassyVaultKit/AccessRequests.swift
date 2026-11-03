import Foundation

public enum AccessChoice: String, Codable, Sendable { case deny, allow_once }

public struct RelayAccessCard: Codable, Equatable, Sendable {
  public struct Asker: Codable, Equatable, Sendable {
    public let device: String
    public let relay_device_id: UInt64
    public let name: String
    public init(
      device: String,
      relay_device_id: UInt64,
      name: String
    ) {
      self.device = device
      self.relay_device_id = relay_device_id
      self.name = name
    }
  }
  public struct Agent: Codable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let host: String?
    public let host_source: String
    public init(
      id: String,
      name: String,
      host: String?,
      host_source: String
    ) {
      self.id = id
      self.name = name
      self.host = host
      self.host_source = host_source
    }
  }
  public struct Item: Codable, Equatable, Sendable {
    public let local_id: String
    public let uuid: String
    public let revision: String
    public let name: String
    public let environment: String
    public let delivery: String
    public let binding_name: String
    public init(
      local_id: String,
      uuid: String,
      revision: String,
      name: String,
      environment: String,
      delivery: String,
      binding_name: String
    ) {
      self.local_id = local_id
      self.uuid = uuid
      self.revision = revision
      self.name = name
      self.environment = environment
      self.delivery = delivery
      self.binding_name = binding_name
    }
  }
  public struct Project: Codable, Equatable, Sendable {
    public let key: String
    public let label: String
    public init(
      key: String,
      label: String
    ) {
      self.key = key
      self.label = label
    }
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
  public init(
    vault_id: String,
    team_id: String,
    qid: String,
    key_id: String,
    to: String,
    request_id: String,
    asker: Asker,
    vault_name: String,
    agent: Agent,
    item: Item,
    project: Project?,
    cwd: String,
    action: String?,
    hosts: [String],
    scope_source: String,
    reason: String,
    policy_digest: String,
    created_at: UInt64,
    expires_at: UInt64,
    valid_answers: [AccessChoice],
    local_review_reason: String?
  ) {
    self.vault_id = vault_id
    self.team_id = team_id
    self.qid = qid
    self.key_id = key_id
    self.to = to
    self.request_id = request_id
    self.asker = asker
    self.vault_name = vault_name
    self.agent = agent
    self.item = item
    self.project = project
    self.cwd = cwd
    self.action = action
    self.hosts = hosts
    self.scope_source = scope_source
    self.reason = reason
    self.policy_digest = policy_digest
    self.created_at = created_at
    self.expires_at = expires_at
    self.valid_answers = valid_answers
    self.local_review_reason = local_review_reason
  }
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
  public init(
    vault_id: String,
    team_id: String,
    qid: String,
    request_id: String,
    asker: String,
    digest: String,
    outcome: String,
    answered_by: String?,
    device_name: String?,
    device_kind: String?,
    kind: String?,
    at: UInt64,
    expires_at: UInt64
  ) {
    self.vault_id = vault_id
    self.team_id = team_id
    self.qid = qid
    self.request_id = request_id
    self.asker = asker
    self.digest = digest
    self.outcome = outcome
    self.answered_by = answered_by
    self.device_name = device_name
    self.device_kind = device_kind
    self.kind = kind
    self.at = at
    self.expires_at = expires_at
  }
}

/// ApassyCore verifies the Mac signature and trust before returning this projection.
public struct RelayAccessRequest: Codable, Equatable, Identifiable, Sendable {
  public let vault_id: String
  public let card: RelayAccessCard
  public let digest: String
  public let state: String
  public let receipt: AccessReceipt?
  public let answer_key: String?
  public var id: String {
    "\(vault_id):\(card.vault_id):\(card.asker.device):\(card.request_id):\(card.qid):\(digest)"
  }
  public init(
    vault_id: String,
    card: RelayAccessCard,
    digest: String,
    state: String,
    receipt: AccessReceipt?,
    answer_key: String?
  ) {
    self.vault_id = vault_id
    self.card = card
    self.digest = digest
    self.state = state
    self.receipt = receipt
    self.answer_key = answer_key
  }
}
public struct AccessRequestsSnapshot: Decodable, Sendable {
  public let protocolName: String
  public let version: Int
  public let requests: [RelayAccessRequest]
  enum CodingKeys: String, CodingKey {
    case protocolName = "protocol"
    case version, requests
  }
}
public struct PreparedAccessAnswer: Decodable, Sendable {
  public let bytes: String
  public let time: UInt64
  public let digest: String
  public let needs_face_id: Bool
  public let retry_before: UInt64
}
public struct SentAccessAnswer: Decodable, Sendable { public let sent: Bool }

/// The display of agent and Mac text of an access request, on the iPhone and the watch.
public enum AccessText {
  /// Plain text: a backslash doubled, and control, format, line separator, and paragraph separator
  /// characters (bidirectional overrides, U+2028, U+2029 among them) shown as `\u{…}`, so nothing
  /// can hide, break, or reorder the text around it.
  public static func escaped(_ text: String) -> String {
    text.unicodeScalars.map { scalar in
      if scalar.value == 92 { return "\\\\" }
      let category = scalar.properties.generalCategory
      if CharacterSet.controlCharacters.contains(scalar)
        || category == .format || category == .lineSeparator || category == .paragraphSeparator
      {
        return "\\u{\(String(scalar.value, radix: 16))}"
      }
      return String(scalar)
    }.joined()
  }
}
