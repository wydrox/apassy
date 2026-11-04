import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// The questions of a vault whose team is on a node: the relay inside the Mac app, on the tailnet,
/// behind a pinned certificate (plan S2–S3 unit N6, contract node-pairing-v1). Settings > Devices
/// says "via your Mac" with the node's name; a node that does not answer (Tailscale is off on
/// this iPhone) is one quiet line in Requests, never a card or a notice. Synthetic values only;
/// nothing leaves the process.
@MainActor
@Suite("Questions via your Mac")
struct NodeQuestionsTests {
    static let origin = "https://100.64.0.7:8444"
    static let work = (id: "8e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b", name: "Work", team: "t_wq3k7m2p5x")
    static let family = (id: "0a1b2c3d4e5f60718293a4b5c6d7e8f9", name: "Family", team: "t_fffffffff2")

    @MainActor
    final class Fixture {
        let service = PreviewVaultService(empty: false, unlocked: false)
        let settings = makeSettings()
        let defaults: UserDefaults
        let vault: VaultModel
        let questions: QuestionsModel
        let question: RemoteQuestion

        init() async {
            let suite = "questions-node-\(UUID().uuidString)"
            defaults = UserDefaults(suiteName: suite)!
            defaults.removePersistentDomain(forName: suite)
            question = PreviewVaultService.sampleQuestion(qid: "bm9kZS1xdWVzdGlvbi0wMDAwMQ")
            await service.setQuestions(enabled: true, questions: [question])
            await service.setQuestionsReportVaultScope(true)
            (vault, _) = makeVault(service: service, settings: settings)
            questions = QuestionsModel(
                service: service, signers: SharedAnswerSigners(signer: ScriptedSigner()), push: nil,
                deviceName: "Test iPhone", defaults: defaults, retryInterval: .milliseconds(10))
            questions.follow(vault)
            await vault.start()
            await vault.unlock(passphrase: PreviewVaultService.passphrase)
            await questions.reopenFinished()
        }

        /// The contexts that Requests shows as "<vault> is unavailable", with Retry.
        var unavailableRows: [QuestionsVault] {
            questions.contexts.filter { $0.error != nil && !questions.isUnreachableNode($0) }
        }
    }

    @Test("a team on a node is via your Mac, with the name of its vault entry; a hosted team is via Apassy relay")
    func routes() async {
        let fixture = await Fixture()
        await fixture.service.addQuestionsVault(
            id: Self.work.id, name: Self.work.name, team: Self.work.team, onPhone: true,
            node: NodeInfo(origin: Self.origin, name: "Mac mini"))
        // The new vault entry (with the node's name) is in the list of vaults.
        await fixture.vault.refreshInfo()
        await fixture.questions.refresh()
        let routes = fixture.questions.questionRoutes
        #expect(routes.map(\.vault.vaultID) == [previewVaultID, Self.work.id])
        #expect(routes.first { $0.vault.vaultID == previewVaultID }?.route == .viaApassyRelay)
        // The core names the origin only; the name comes from the entry of that origin.
        let work = routes.first { $0.vault.vaultID == Self.work.id }
        #expect(work?.vault.status.node == NodeInfo(origin: Self.origin))
        #expect(work?.route == .viaYourMac(name: "Mac mini"))
        #expect(work?.route.text == "via your Mac")
        #expect(work?.route.detail == "Through Tailscale to Mac mini.")
        #expect(fixture.questions.tailscaleOffLine == nil)
    }

    @Test("a node that stops answering is one quiet line: no card, no notice, and no Connect")
    func nodeOnlyUnreachable() async {
        let fixture = await Fixture()
        await fixture.service.setQuestionsNode(NodeInfo(origin: Self.origin))
        await fixture.questions.refresh()
        #expect(fixture.questions.phase == .ready)
        #expect(fixture.questions.questionRoutes.first?.route == .viaYourMac(name: nil))

        // Tailscale goes off on this iPhone: the node does not answer, and the whole list fails.
        await fixture.service.setQuestionsNode(NodeInfo(origin: Self.origin), unreachable: true)
        await fixture.questions.refresh()
        #expect(fixture.questions.phase == .ready, "never the failure card")
        #expect(fixture.questions.notice == nil)
        #expect(fixture.questions.unreachableNodes.map(\.id) == [previewVaultID])
        #expect(fixture.questions.tailscaleOffLine == "Turn on Tailscale on this iPhone to reach your Mac.")
        #expect(fixture.questions.refreshError != nil, "the answers wait for the next read")
        #expect(!fixture.questions.canConnect)
        #expect(fixture.unavailableRows.isEmpty)

        // Tailscale is on again: the line goes.
        await fixture.service.setQuestionsNode(NodeInfo(origin: Self.origin))
        await fixture.questions.refresh()
        #expect(fixture.questions.tailscaleOffLine == nil)
        #expect(fixture.questions.unreachableNodes.isEmpty)
        #expect(fixture.questions.refreshError == nil)
        #expect(fixture.questions.waiting.map(\.qid) == [fixture.question.qid])
    }

    @Test("beside a vault that answers, only the node's vault gets the line; a hosted failure keeps its row")
    func nodeAmongOthers() async {
        let fixture = await Fixture()
        let workQuestion = PreviewVaultService.sampleQuestion(qid: "d29yay1xdWVzdGlvbi0wMDAwMQ")
        await fixture.service.addQuestionsVault(
            id: Self.work.id, name: Self.work.name, team: Self.work.team, questions: [workQuestion], onPhone: true)
        await fixture.service.addQuestionsVault(
            id: Self.family.id, name: Self.family.name, team: Self.family.team, onPhone: true,
            error: VaultError.Code.relayUnreachable.rawValue)
        await fixture.service.setQuestionsNode(NodeInfo(origin: Self.origin), unreachable: true)
        await fixture.vault.reload()
        await fixture.questions.refresh()
        #expect(fixture.questions.phase == .ready)
        #expect(fixture.questions.unreachableNodes.map(\.id) == [previewVaultID])
        #expect(fixture.questions.tailscaleOffLine == "Turn on Tailscale on this iPhone to reach your Mac.")
        // The questions of Work show; the node's question does not.
        #expect(fixture.questions.waiting.map(\.qid) == [workQuestion.qid])
        // Family is on a hosted relay that failed: its own row stays, it is no node.
        #expect(fixture.unavailableRows.map(\.vaultID) == [Self.family.id])
    }

    @Test("a lock forgets the nodes that did not answer")
    func lockForgets() async {
        let fixture = await Fixture()
        await fixture.service.setQuestionsNode(NodeInfo(origin: Self.origin))
        await fixture.questions.refresh()
        await fixture.service.setQuestionsNode(NodeInfo(origin: Self.origin), unreachable: true)
        await fixture.questions.refresh()
        #expect(!fixture.questions.unreachableNodes.isEmpty)
        await fixture.vault.lock()
        #expect(fixture.questions.unreachableNodes.isEmpty)
        #expect(fixture.questions.tailscaleOffLine == nil)
    }
}
