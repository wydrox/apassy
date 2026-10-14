import ApassyVaultKit
import Foundation

// Questions through the relay over the core (contract ios-core-v1 section 5.10). The core refuses
// these calls in the AutoFill extension.
extension CoreVaultService {
    /// The questions of every vault that the core keeps (`vaults`), or of the selected vault with
    /// an older core.
    public func questionsList() async throws -> QuestionsList { try await call("questions_list") }

    private struct Waited: Decodable, Sendable { var changed: Bool }

    public func questionsWait(timeout: Int) async throws -> Bool {
        try await call("questions_wait", ["timeout": timeout], as: Waited.self).changed
    }

    public func questionOpen(qid: String) async throws -> RemoteQuestion {
        try await call("question_open", ["qid": qid])
    }

    public func questionAnswerString(qid: String, answer: RemoteAnswer) async throws -> PreparedAnswer {
        try await questionAnswerString(qid: qid, answer: answer, vaultID: nil)
    }

    public func questionAnswerString(qid: String, answer: RemoteAnswer, vaultID: String?) async throws
        -> PreparedAnswer
    {
        var params = answer.parameters
        params["qid"] = qid
        if let vaultID { params["vault_id"] = vaultID }
        return try await call("question_answer_string", params)
    }

    public func questionAnswer(qid: String, answer: RemoteAnswer, time: Int64, signature: Data?) async throws
        -> SentAnswer
    {
        try await questionAnswer(qid: qid, answer: answer, time: time, signature: signature, vaultID: nil)
    }

    public func questionAnswer(
        qid: String, answer: RemoteAnswer, time: Int64, signature: Data?, vaultID: String?
    ) async throws -> SentAnswer {
        var params = answer.parameters
        params["qid"] = qid
        params["time"] = time
        if let signature { params["signature"] = Base64URL.encode(signature) }
        if let vaultID { params["vault_id"] = vaultID }
        return try await call("question_answer", params)
    }

    public func answerKeyRegister(publicKey: Data) async throws -> AnswerKeyRegistration {
        try await call("answer_key_register", ["public_key": Base64URL.encode(publicKey)])
    }

    public func pushTokenSet(token: Data, environment: PushEnvironment) async throws {
        let hex = token.map { String(format: "%02x", $0) }.joined()
        try await call("push_token_set", ["token": hex, "environment": environment.rawValue])
    }

    public func pushTokenClear() async throws { try await call("push_token_clear") }

    public func joinAttach(link: String, deviceName: String, answerKey: Data) async throws -> AttachInfo {
        try await call(
            "join_attach",
            ["link": link, "device_name": deviceName, "answer_key": Base64URL.encode(answerKey)])
    }

    public func joinAttachPoll() async throws -> AttachInfo { try await call("join_attach_poll") }

    public func joinAttachCancel() async throws { try await call("join_attach_cancel") }
}
