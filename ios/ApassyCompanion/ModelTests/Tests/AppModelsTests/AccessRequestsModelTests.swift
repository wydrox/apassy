import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Synchronization
import Testing
@testable import AppModels

private final class AccessSigner: AnswerSigner {
    struct State {
        var count = 0
        var ordinary = 0
        var renewals = 0
        var held = false
        var supported = true
        var failure: CompanionKeyError?
        var context: ApprovalAuthentication?
    }
    let state = Mutex(State())
    var canSignAccess: Bool { state.withLock { $0.supported } }
    var count: Int { state.withLock { $0.count } }
    var invalidated: Bool { state.withLock { $0.context?.isCancelled == true } }
    func publicKey() throws -> Data { Data([4] + [UInt8](repeating:1,count:64)) }
    func renew() throws -> Data { state.withLock { $0.renewals += 1 }; return try publicKey() }
    func sign(_ message: Data, reason: String) async throws -> Data {
        state.withLock { $0.ordinary += 1 }; return Data("ordinary".utf8)
    }
    func signAccess(_ message: Data, reason: String, authentication: ApprovalAuthentication) async throws -> Data {
        state.withLock { $0.count += 1; $0.context = authentication }
        // Deliberately return even after cancellation: the model must discard stale completion.
        while state.withLock({ $0.held }) { try await Task.sleep(for:.milliseconds(1)) }
        if let error = state.withLock({ $0.failure }) { throw error }
        return Data("fixture-signature".utf8)
    }
}

@MainActor
struct AccessRequestsModelTests {
    private func fixture() async -> (PreviewVaultService,AccessSigner,AccessRequestsModel,RelayAccessRequest) {
        let service = PreviewVaultService()
        let signer = AccessSigner()
        let row = PreviewVaultService.sampleAccessRequest()
        await service.setAccessRequests([row])
        let model = AccessRequestsModel(service:service,signers:SharedAnswerSigners(signer:signer))
        await model.refresh()
        return (service,signer,model,row)
    }
    private func started(_ signer: AccessSigner) async {
        for _ in 0..<1000 {
            if signer.count > 0 { return }
            try? await Task.sleep(for:.milliseconds(1))
        }
        Issue.record("The fixture signer did not start")
    }
    @Test func denyDoesNotUseBiometryOrTheAnswerSigner() async {
        let (service,signer,model,row) = await fixture()
        signer.state.withLock { $0.supported = false }
        await model.answer(row,choice:.deny)
        #expect(signer.count == 0)
        #expect(signer.state.withLock { $0.ordinary } == 0)
        let posts = await service.accessPosts()
        #expect(posts.count == 1 && posts[0].signature == nil && posts[0].choice == .deny)
        #expect(model.requests.first?.receipt?.outcome == "denied")
    }
    @Test func eachAllowNeedsItsOwnFreshSignerInvocation() async throws {
        let (service,signer,model,row) = await fixture()
        _ = try await signer.sign(Data("unlock".utf8),reason:"unlock")
        await model.answer(row,choice:.allow_once)
        #expect(signer.count == 1 && signer.invalidated)
        let next = PreviewVaultService.sampleAccessRequest(requestID:"82")
        await service.setAccessRequests([next]); await model.refresh()
        await model.answer(next,choice:.allow_once)
        #expect(signer.count == 2 && signer.invalidated)
        #expect(await service.accessPosts().count == 2)
    }
    @Test func cancellationInvalidatesTheContextAndDiscardsLateCompletion() async {
        let (service,signer,model,row) = await fixture()
        signer.state.withLock { $0.held = true }
        let task = Task { await model.answer(row,choice:.allow_once) }
        await started(signer)
        model.cancel(clear:false)
        #expect(signer.invalidated)
        signer.state.withLock { $0.held = false }
        await task.value
        #expect(await service.accessPosts().isEmpty)
        await model.answer(row,choice:.deny)
        #expect(signer.count == 1)
        #expect(await service.accessPosts().first?.choice == .deny)
    }
    @Test func backgroundOrVaultSwitchNeverPostsALateSignature() async {
        let (service,signer,model,row) = await fixture()
        signer.state.withLock { $0.held = true }
        let task = Task { await model.answer(row,choice:.allow_once) }
        await started(signer); model.cancel()
        signer.state.withLock { $0.held = false }; await task.value
        #expect(signer.invalidated && model.requests.isEmpty)
        #expect(await service.accessPosts().isEmpty)
    }
    @Test func doubleTapCannotStartAnotherMatchOrPost() async {
        let (service,signer,model,row) = await fixture()
        signer.state.withLock { $0.held = true }
        let task = Task { await model.answer(row,choice:.allow_once) }
        await started(signer)
        await model.answer(row,choice:.allow_once)
        #expect(signer.count == 1)
        signer.state.withLock { $0.held = false }; await task.value
        #expect(await service.accessPosts().count == 1)
    }
    @Test func unsupportedBiometryEnrollmentFailureAndExpiryFailClosed() async {
        let (service,signer,model,row) = await fixture()
        signer.state.withLock { $0.supported = false }
        await model.answer(row,choice:.allow_once)
        #expect(signer.count == 0 && !model.canAllow(row))
        signer.state.withLock { $0.supported = true; $0.failure = .biometryChanged }
        await model.answer(row,choice:.allow_once)
        #expect(signer.invalidated && signer.state.withLock { $0.renewals } == 0)
        #expect(await service.accessPosts().isEmpty)
        let expired = PreviewVaultService.sampleAccessRequest(expiresIn:0,requestID:"83")
        await service.setAccessRequests([expired]); await model.refresh()
        #expect(!model.actionable(expired))
        await model.answer(expired,choice:.deny)
        #expect(await service.accessPosts().isEmpty)
    }
    @Test func uncertainTransportRetriesReuseOneSignatureAndNeverExceedThreePosts() async {
        let (service,signer,model,row)=await fixture()
        await service.failNextAccessAnswer(VaultError(.relayUnreachable,"synthetic lost reply"))
        await service.failNextAccessAnswer(VaultError(.relayUnreachable,"synthetic lost reply"))
        await model.answer(row,choice:.allow_once)
        let posts=await service.accessPosts()
        #expect(posts.count==3 && signer.count==1)
        #expect(posts.allSatisfy {$0.signature==posts.first?.signature && $0.identity==row.id})
        await model.answer(row,choice:.deny)
        #expect(await service.accessPosts().count==3)
    }
    @Test func replacingTheExactRowInvalidatesPendingAuthentication() async {
        let (service,signer,model,row)=await fixture();signer.state.withLock {$0.held=true}
        let task=Task {await model.answer(row,choice:.allow_once)};await started(signer)
        await service.setAccessRequests([PreviewVaultService.sampleAccessRequest(requestID:"different")]);await model.refresh()
        #expect(signer.invalidated)
        signer.state.withLock {$0.held=false};await task.value
        #expect(await service.accessPosts().isEmpty)
    }

}
