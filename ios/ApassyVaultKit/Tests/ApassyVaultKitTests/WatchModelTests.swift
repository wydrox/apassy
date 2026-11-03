import Foundation
import Testing
@testable import ApassyVaultKit

/// The models of the Apple Watch over the in-memory watch core (ADR 0039): the connection, the
/// answers, the background, and the removal. Synthetic data and in-memory keys only.
@MainActor
@Suite struct WatchModelTests {
    private let team = WatchPreview.team

    private func model(
        _ service: PreviewWatchService, keys: MemoryWatchAnswerKeys, replica: MemoryWatchReplicaStore
    ) -> WatchAppModel {
        WatchAppModel(
            service: service, keys: keys, replica: replica, deviceName: "Synthetic Apple Watch Series",
            pollInterval: .milliseconds(10), retryDelays: [.zero, .zero])
    }

    /// A connected watch with one open request whose row holds the key of this watch.
    private func connected(
        keys: MemoryWatchAnswerKeys = MemoryWatchAnswerKeys(), state: WatchStatus.State = .ready,
        settles: Bool = true, registered: Data? = nil
    ) throws -> (WatchAppModel, PreviewWatchService, MemoryWatchAnswerKeys, String) {
        let key = try keys.create(team: team)
        let now = UInt64(Date.now.timeIntervalSince1970)
        let request = WatchPreview.request(answerKey: registered ?? key, created: now - 10, expires: now + 290)
        let service = PreviewWatchService(state: state, requests: [request], settles: settles)
        let replica = MemoryWatchReplicaStore(WatchReplicaSecret(passphrase: "synthetic-passphrase-1", team: team))
        return (model(service, keys: keys, replica: replica), service, keys, request.id)
    }

    // MARK: - Connect

    @Test func anUnpairedWatchTakesAConnectCodeAndConnects() async throws {
        let service = PreviewWatchService(state: .unpaired, connection: .attaches)
        let keys = MemoryWatchAnswerKeys()
        let replica = MemoryWatchReplicaStore()
        let model = model(service, keys: keys, replica: replica)
        await model.scenePhaseChanged(.active)
        #expect(model.screen == .connect(nil))
        #expect(model.receiveLink("not a code") != nil)
        #expect(model.screen == .connect(nil))
        #expect(model.receiveLink(WatchPreview.link) == nil)
        #expect(model.screen == .connecting)
        await model.connectFinished()
        #expect(model.screen == .connected(vault: "Personal", macs: ["Studio Mac"]))
        #expect(keys.publicKey(team: team) != nil)
        #expect(try replica.load()?.team == team)
        // A connected watch takes no other code.
        model.finishConnecting()
        #expect(model.screen == .requests)
        #expect(model.receiveLink(WatchPreview.link) != nil)
    }

    @Test func aRefusedConnectionShowsTheReasonAndForgetsTheNewKeys() async throws {
        let service = PreviewWatchService(
            state: .unpaired, connection: .fails(VaultError(.joinRefused, "The Mac refused this watch.")))
        let keys = MemoryWatchAnswerKeys()
        let replica = MemoryWatchReplicaStore()
        let model = model(service, keys: keys, replica: replica)
        await model.scenePhaseChanged(.active)
        #expect(model.receiveLink(WatchPreview.link) == nil)
        await model.connectFinished()
        #expect(model.screen == .connect(.wordsDiffer))
        #expect(keys.publicKey(team: team) == nil)
        #expect(try replica.load() == nil)
    }

    @Test func cancelOnTheWordsGoesBackWithoutAReason() async throws {
        let service = PreviewWatchService(state: .unpaired, connection: .waits)
        let keys = MemoryWatchAnswerKeys()
        let replica = MemoryWatchReplicaStore()
        let model = model(service, keys: keys, replica: replica)
        await model.scenePhaseChanged(.active)
        #expect(model.receiveLink(WatchPreview.link) == nil)
        for _ in 0..<100 where model.screen == .connecting { try await Task.sleep(for: .milliseconds(5)) }
        #expect(model.screen == .words(PreviewWatchService.words))
        model.cancelConnect()
        #expect(model.screen == .connect(nil))
        await model.connectFinished()
        #expect(try await service.status(answerKey: nil).state == .unpaired)
        #expect(keys.publicKey(team: team) == nil)
        #expect(try replica.load() == nil)
    }

    // MARK: - Answers

    @Test func denyNeedsNoKeyAndIsConfirmedHere() async throws {
        let (model, service, keys, id) = try connected()
        await model.scenePhaseChanged(.active)
        #expect(model.screen == .requests)
        #expect(model.requests.rows.map(\.id) == [id])
        #expect(model.requests.phase(for: id, at: .now) == .decide(allowOnce: true, notes: []))
        model.requests.answer(id, choice: .deny)
        await model.requests.answerFinished()
        let posts = await service.postedAnswers()
        #expect(posts.count == 1 && posts.first?.choice == .deny && posts.first?.signature == nil)
        #expect(keys.signatureCount == 0)
        guard case .result(let result) = model.requests.phase(for: id, at: .now) else {
            Issue.record("not a result")
            return
        }
        #expect(result.outcome == .denied && result.answeredOn == "This watch")
        #expect(model.requests.isConfirmedHere(id))
    }

    @Test func allowOnceSignsWithTheKeyOfThisWatch() async throws {
        let (model, service, keys, id) = try connected(state: .locked)
        await model.scenePhaseChanged(.active)
        #expect(model.screen == .requests)
        model.requests.answer(id, choice: .allow_once)
        #expect(model.requests.phase(for: id, at: .now) == .checkingWrist)
        await model.requests.answerFinished()
        let posts = await service.postedAnswers()
        #expect(posts.count == 1 && posts.first?.choice == .allow_once && posts.first?.signature != nil)
        #expect(keys.signatureCount == 1)
        #expect(model.requests.isConfirmedHere(id))
    }

    @Test func allowOnceOffTheWristSendsNothingAndKeepsDeny() async throws {
        let (model, service, _, id) = try connected(keys: MemoryWatchAnswerKeys(refusesWrist: true))
        await model.scenePhaseChanged(.active)
        model.requests.answer(id, choice: .allow_once)
        await model.requests.answerFinished()
        #expect(await service.postedAnswers().isEmpty)
        #expect(model.requests.phase(for: id, at: .now)
            == .decide(allowOnce: true, notes: ["Allow once needs this watch unlocked on your wrist. Nothing was sent."]))
        model.requests.answer(id, choice: .deny)
        await model.requests.answerFinished()
        #expect(await service.postedAnswers().map { $0.choice } == [.deny])
    }

    @Test func allowOnceNeedsTheKeyThatTheMacRegistered() async throws {
        let other = Data([4] + [UInt8](repeating: 9, count: 64))
        let (model, service, keys, id) = try connected(registered: other)
        await model.scenePhaseChanged(.active)
        #expect(model.requests.phase(for: id, at: .now)
            == .decide(allowOnce: false, notes: ["Allow once is off: connect this watch again."]))
        model.requests.answer(id, choice: .allow_once)
        await model.requests.answerFinished()
        #expect(await service.postedAnswers().isEmpty)
        #expect(keys.signatureCount == 0)
    }

    @Test func aSentAnswerWithoutASettleWaitsForTheMac() async throws {
        let (model, _, _, id) = try connected(settles: false)
        await model.scenePhaseChanged(.active)
        model.requests.answer(id, choice: .deny)
        await model.requests.answerFinished()
        #expect(model.requests.phase(for: id, at: .now) == .sent)
        #expect(model.requests.phase(for: id, at: .now.addingTimeInterval(61)) == .notConfirmed)
        // No second answer, not even another choice.
        model.requests.answer(id, choice: .allow_once)
        #expect(model.requests.phase(for: id, at: .now) == .sent)
    }

    @Test func anUnreachableRelayPostsTheSameAnswerAtMostThreeTimes() async throws {
        let (model, service, _, id) = try connected(settles: false)
        for _ in 0..<3 { await service.failNextAnswer(VaultError(.relayUnreachable, "offline")) }
        await model.scenePhaseChanged(.active)
        model.requests.answer(id, choice: .deny)
        await model.requests.answerFinished()
        #expect(await service.postedAnswers().count == 3)
        #expect(model.requests.phase(for: id, at: .now) == .notConfirmed)
    }

    // MARK: - Background, removal

    @Test func theBackgroundCancelsTheWristCheckAndDropsTheRequests() async throws {
        let (model, service, keys, id) = try connected(keys: MemoryWatchAnswerKeys(checkTime: .milliseconds(200)))
        await model.scenePhaseChanged(.active)
        model.path = [.request(id)]
        model.requests.answer(id, choice: .allow_once)
        try await Task.sleep(for: .milliseconds(20))
        await model.scenePhaseChanged(.background)
        #expect(model.requests.rows.isEmpty)
        #expect(model.path.isEmpty)
        #expect(model.requests.progress[id] == nil)
        await model.requests.answerFinished()
        #expect(await service.postedAnswers().isEmpty)
        #expect(keys.signatureCount == 0)
        // Active again: the replica opens and the request is back, unanswered.
        await model.scenePhaseChanged(.active)
        #expect(model.requests.rows.map(\.id) == [id])
    }

    @Test func aRemovalOnAMacShowsRemoved() async throws {
        let (model, service, _, _) = try connected()
        await model.scenePhaseChanged(.active)
        await service.setState(.removed)
        await model.refreshRequests()
        #expect(model.screen == .removed)
        #expect(model.requests.rows.isEmpty)
    }

    @Test func removeThisWatchDeletesItsKeysAndPassphrase() async throws {
        let (model, service, keys, _) = try connected()
        await model.scenePhaseChanged(.active)
        model.showsSettings = true
        model.forget()
        #expect(!model.showsSettings)
        await model.forgetFinished()
        #expect(model.screen == .connect(nil))
        #expect(keys.publicKey(team: team) == nil)
        #expect(try await service.status(answerKey: nil).state == .unpaired)
    }

    @Test func aRowWithoutTheAnswerKeyOfTheWatchTurnsAllowOnceOff() async throws {
        let (model, _, _, id) = try connected()
        await model.scenePhaseChanged(.active)
        model.requests.setAllowOffReason("Update Apassy on your Mac to connect this watch.")
        #expect(model.requests.phase(for: id, at: .now)
            == .decide(allowOnce: false, notes: ["Update Apassy on your Mac to connect this watch."]))
    }

    // MARK: - Review fixes

    /// The view computes the phase with the real time: an explicit timeline starts at its first
    /// entry, the future expiry, which reads as expired.
    @Test func anOpenRequestWithAFutureExpiryIsActionableAsTheViewEvaluatesIt() async throws {
        let (model, _, _, id) = try connected()
        await model.scenePhaseChanged(.active)
        #expect(model.requests.currentPhase(for: id) == .decide(allowOnce: true, notes: []))
        let firstEntry = try #require(model.requests.deadlines(for: id).first)
        #expect(firstEntry > .now)
        #expect(model.requests.phase(for: id, at: firstEntry) == .expired)
        let row = try #require(model.requests.request(id))
        #expect(WatchRequestText.rowStatus(row, at: .now).hasPrefix("Until "))
    }

    @Test func cancelDuringASlowStartCancelsTheJoin() async throws {
        let service = PreviewWatchService(state: .unpaired, connection: .waits, startDelay: .milliseconds(150))
        let keys = MemoryWatchAnswerKeys()
        let replica = MemoryWatchReplicaStore()
        let model = model(service, keys: keys, replica: replica)
        await model.scenePhaseChanged(.active)
        #expect(model.receiveLink(WatchPreview.link) == nil)
        try await Task.sleep(for: .milliseconds(20))
        model.cancelConnect()
        #expect(model.screen == .connect(nil))
        await model.connectFinished()
        // The cancel came after the start returned: no join stays in the core.
        #expect(try await service.status(answerKey: nil).state == .unpaired)
        #expect(model.screen == .connect(nil))
        #expect(keys.publicKey(team: team) == nil)
        #expect(try replica.load() == nil)
    }

    @Test func theAppReopensAfterBackgroundInactiveActive() async throws {
        let (model, service, _, id) = try connected()
        await model.scenePhaseChanged(.active)
        await model.scenePhaseChanged(.background)
        #expect(model.requests.rows.isEmpty)
        #expect(try await service.status(answerKey: nil).state == .locked)
        await model.scenePhaseChanged(.inactive)
        #expect(model.isLive)
        await model.scenePhaseChanged(.active)
        #expect(try await service.status(answerKey: nil).state == .ready)
        #expect(model.requests.rows.map(\.id) == [id])
    }

    @Test func theBackgroundDuringAnUnlockKeepsTheReplicaClosed() async throws {
        let keys = MemoryWatchAnswerKeys()
        let key = try keys.create(team: team)
        let now = UInt64(Date.now.timeIntervalSince1970)
        let request = WatchPreview.request(answerKey: key, created: now - 10, expires: now + 290)
        let service = PreviewWatchService(state: .locked, requests: [request], unlockDelay: .milliseconds(150))
        let replica = MemoryWatchReplicaStore(WatchReplicaSecret(passphrase: "synthetic-passphrase-1", team: team))
        let model = model(service, keys: keys, replica: replica)
        model.setScenePhase(.active)
        try await Task.sleep(for: .milliseconds(40))
        await model.scenePhaseChanged(.background)
        #expect(model.requests.rows.isEmpty)
        #expect(try await service.status(answerKey: nil).state == .locked)
        await model.scenePhaseChanged(.active)
        #expect(model.requests.rows.map(\.id) == [request.id])
    }

    @Test func wristDownKeepsTheLongPollWithoutRestartingIt() async throws {
        let (model, _, _, _) = try connected()
        await model.scenePhaseChanged(.active)
        #expect(model.isLive)
        model.setScenePhase(.inactive)
        #expect(model.isLive)
        model.setScenePhase(.background)
        #expect(!model.isLive)
    }

    @Test func denyOnAnotherRequestEndsAWristCheckThatRuns() async throws {
        let keys = MemoryWatchAnswerKeys(checkTime: .milliseconds(300))
        let key = try keys.create(team: team)
        let now = UInt64(Date.now.timeIntervalSince1970)
        let first = WatchPreview.request(requestID: "81", answerKey: key, created: now - 10, expires: now + 290)
        let second = WatchPreview.request(requestID: "82", answerKey: key, created: now - 5, expires: now + 290)
        let service = PreviewWatchService(state: .ready, requests: [first, second])
        let replica = MemoryWatchReplicaStore(WatchReplicaSecret(passphrase: "synthetic-passphrase-1", team: team))
        let model = model(service, keys: keys, replica: replica)
        await model.scenePhaseChanged(.active)
        model.requests.answer(first.id, choice: .allow_once)
        #expect(model.requests.currentPhase(for: first.id) == .checkingWrist)
        try await Task.sleep(for: .milliseconds(20))
        model.requests.answer(second.id, choice: .deny)
        #expect(model.requests.progress[first.id] == nil)
        await model.requests.answerFinished()
        let posts = await service.postedAnswers()
        #expect(posts.map { $0.id } == [second.id])
        #expect(posts.first?.choice == .deny)
        #expect(keys.signatureCount == 0)
    }

    @Test func aWatchWithoutAPasscodeTurnsAllowOnceOff() async throws {
        let (model, _, _, id) = try connected(keys: MemoryWatchAnswerKeys(canSign: false))
        await model.scenePhaseChanged(.active)
        #expect(model.requests.currentPhase(for: id)
            == .decide(allowOnce: false, notes: ["Allow once needs this watch unlocked on your wrist."]))
    }

    @Test func everyPreviewStateBuilds() {
        for state in WatchPreviewState.allCases {
            let model = WatchPreview.model(state)
            #expect(model.screen == .starting, "\(state)")
        }
    }
}
