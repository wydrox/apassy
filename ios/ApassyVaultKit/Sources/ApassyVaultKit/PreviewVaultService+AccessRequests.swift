import Foundation

/// In-memory UI/model fixtures only. Production uses the signature-verifying Rust core.
extension PreviewVaultService {
    public struct AccessPost: Sendable {
        public let identity: String
        public let choice: AccessChoice
        public let signature: Data?
    }
    public func setAccessRequests(_ rows: [RelayAccessRequest]) { accessPreviewRows = rows }
    public func accessPosts() -> [AccessPost] { accessPreviewPosts }
    public func failNextAccessAnswer(_ error: VaultError) { accessPreviewFailures.append(error) }
    public func accessRequestsList() throws -> AccessRequestsSnapshot {
        guard unlocked else { throw VaultError(.locked, "Unlock the fixture vault.") }
        return AccessRequestsSnapshot(protocolName:"apassy-access-request", version:1, requests:accessPreviewRows)
    }
    public func accessRequestsHistory() throws -> AccessRequestsSnapshot {
        guard unlocked else { throw VaultError(.locked, "Unlock the fixture vault.") }
        return AccessRequestsSnapshot(protocolName:"apassy-access-request", version:1, requests:accessPreviewRows.filter { $0.receipt != nil })
    }
    public func accessRequestPrepare(_ request: RelayAccessRequest, choice: AccessChoice) throws -> PreparedAccessAnswer {
        guard unlocked, accessPreviewRows.contains(where: { $0.id == request.id && $0.state == "open" }),
            request.card.valid_answers.contains(choice), (accessPreviewAttempts[request.id] ?? 0) < 3
        else { throw VaultError(.accessUnavailable, "Review on the synthetic Mac.") }
        let now = UInt64(Date.now.timeIntervalSince1970)
        guard now < request.card.expires_at else { throw VaultError(.expired, "The fixture request expired.") }
        return PreparedAccessAnswer(bytes:Base64URL.encode(Data("synthetic:\(request.id):\(choice.rawValue):\(now)".utf8)),
            time:now,digest:request.digest,needs_face_id:choice == .allow_once,retry_before:min(now+50,request.card.expires_at))
    }
    public func accessRequestAnswer(_ request: RelayAccessRequest, choice: AccessChoice, prepared: PreparedAccessAnswer, signature: Data?) throws -> SentAccessAnswer {
        guard unlocked, let index = accessPreviewRows.firstIndex(where: { $0.id == request.id && $0.state == "open" }),
            (accessPreviewAttempts[request.id] ?? 0) < 3, (choice == .allow_once) == (signature != nil),
            prepared.digest == request.digest, UInt64(Date.now.timeIntervalSince1970) < prepared.retry_before
        else { throw VaultError(.accessUnavailable, "The fixture answer is unavailable.") }
        accessPreviewAttempts[request.id, default:0] += 1
        accessPreviewPosts.append(AccessPost(identity:request.id,choice:choice,signature:signature))
        if !accessPreviewFailures.isEmpty { throw accessPreviewFailures.removeFirst() }
        let c = request.card
        let receipt = AccessReceipt(vault_id:c.vault_id,team_id:c.team_id,qid:c.qid,request_id:c.request_id,asker:c.asker.device,digest:request.digest,
            outcome:choice == .deny ? "denied" : "allowed_once",answered_by:"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b",device_name:"Synthetic iPhone",device_kind:"iphone",
            kind:choice.rawValue,at:UInt64(Date.now.timeIntervalSince1970),expires_at:c.expires_at)
        accessPreviewRows[index] = RelayAccessRequest(vault_id:request.vault_id,card:c,digest:request.digest,state:"settled",receipt:receipt,answer_key:request.answer_key)
        return SentAccessAnswer(sent:true)
    }
    public func accessRequestCancelPrepared() {}

    public static func sampleAccessRequest(answerKey: Data? = nil, expiresIn: UInt64 = 300, requestID: String = "81") -> RelayAccessRequest {
        let now = UInt64(Date.now.timeIntervalSince1970)
        let c = RelayAccessCard(vault_id:"d070dc14-a3ac-42c2-95aa-cc85d6d58900",team_id:"t_7k2m5q4x3c",qid:"oKGio6SlpqeoqaqrrK2urw",
            key_id:"630dcd2966c43366",to:"member",request_id:requestID,
            asker:.init(device:"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d",relay_device_id:1,name:"Synthetic Mac mini"),
            vault_name:"Synthetic vault",agent:.init(id:"4",name:"Synthetic Codex agent",host:"codex",host_source:"agent_claimed"),
            item:.init(local_id:"7",uuid:"3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c",revision:"12",name:"Synthetic API key",environment:"development",delivery:"placeholder",binding_name:"API_TOKEN"),
            project:.init(key:"/tmp/synthetic-project/.git",label:"synthetic-project"),cwd:"/tmp/synthetic-project/long-similar-path/source",
            action:"read",hosts:["api.example.test","api.example.test:8443","xn--bcher-kva.example"],
            scope_source:"agent_requested_mac_checked",reason:"Read synthetic service status. Agent text is a claim, not command verification.",
            policy_digest:String(repeating:"b",count:64),created_at:now,expires_at:now+expiresIn,valid_answers:[.deny,.allow_once],local_review_reason:nil)
        return RelayAccessRequest(vault_id:"4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c",card:c,digest:String(repeating:"a",count:64),state:"open",receipt:nil,
            answer_key:Base64URL.encode(answerKey ?? Data([4]+[UInt8](repeating:1,count:64))))
    }
}
