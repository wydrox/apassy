import ApassyCompanionKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("SessionModel")
struct SessionModelTests {
    /// A session on a scripted Mac and an in-memory store. `ended` collects the notices.
    @MainActor
    final class Fixture {
        let mac = ScriptedConnection()
        let store = InMemoryPairingStore(PreviewData.record)
        var ended: [String?] = []
        var session: SessionModel!

        init(pollInterval: Duration = .seconds(2)) {
            session = SessionModel(
                record: PreviewData.record, mac: mac, keysInSecureEnclave: false, store: store,
                pollInterval: pollInterval, onEnded: { [unowned self] in ended.append($0) })
        }
    }

    @Test("it starts connecting, then shows the inbox and the status")
    func firstRefresh() async {
        let f = Fixture()
        #expect(f.session.state == .connecting)
        #expect(f.session.inbox == nil)
        await f.session.refresh()
        #expect(f.session.state == .connected)
        #expect(f.session.runs.count == 2)
        #expect(f.session.accessRequests.count == 1)
        #expect(f.session.waitingCount == 3)
        #expect(f.session.status?.macName == "Mac mini")
        #expect(f.session.approvalTimeout == 120)
        #expect(f.session.run(id: PreviewData.migrateRun.id)?.agent == "claude-code")
        #expect(f.session.fetchedAt != nil)
    }

    @Test("each failure of the Mac gives its own state, and the last inbox stays")
    func states() async {
        let f = Fixture()
        await f.session.refresh()
        let cases: [(ScriptedConnection.Failure, SessionModel.ConnectionState)] = [
            (.unreachable, .unreachable),
            (.localNetworkDenied, .localNetworkDenied),
            (.pinMismatch, .pinMismatch),
            (.server(status: 500, code: "internal", message: "Something broke."), .problem("Something broke.")),
        ]
        for (failure, state) in cases {
            await f.mac.fail(with: failure)
            await f.session.refresh()
            #expect(f.session.state == state)
            #expect(f.session.runs.count == 2)
        }
        await f.mac.fail(with: .none)
        await f.session.refresh()
        #expect(f.session.state == .connected)
    }

    @Test("a 401 unpaired deletes the pairing and ends once, with the message")
    func unpairedByTheMac() async {
        let f = Fixture()
        await f.mac.fail(with: .unpaired)
        await f.session.refresh()
        #expect((try? f.store.load()) == nil)
        #expect(f.ended == [CompanionError.unpaired.errorDescription])
        await f.session.refresh()
        #expect(f.ended.count == 1)
    }

    @Test("polling asks again and again, and stops when the task is cancelled")
    func polling() async {
        let f = Fixture(pollInterval: .milliseconds(20))
        let task = Task { await f.session.poll() }
        #expect(await waitUntil { f.session.state == .connected })
        var count = 0
        for _ in 0..<200 where count < 3 {
            count = await f.mac.inboxCalls
            try? await Task.sleep(for: .milliseconds(10))
        }
        #expect(count >= 3)
        task.cancel()
        await task.value
        let after = await f.mac.inboxCalls
        try? await Task.sleep(for: .milliseconds(100))
        #expect(await f.mac.inboxCalls == after)
    }

    @Test("approve sends the run as shown, and the run leaves the inbox")
    func approve() async throws {
        let f = Fixture()
        await f.session.refresh()
        let run = try #require(f.session.run(id: PreviewData.migrateRun.id))
        let outcome = try await f.session.approve(run, remember: true)
        #expect(outcome == .approvedAndRemembered)
        #expect(await f.mac.calls == ["approve 123456789012345 remember=true digest=abab"])
        #expect(f.session.run(id: run.id) == nil)
        #expect(f.session.runs.count == 1)
    }

    @Test("an error of the Mac reaches the caller as it is, and the run stays")
    func approveRefused() async throws {
        let f = Fixture()
        await f.session.refresh()
        let run = try #require(f.session.run(id: PreviewData.migrateRun.id))
        let message = "The run changed while you decided. Nothing was approved."
        await f.mac.fail(with: .server(status: 409, code: "changed", message: message))
        do {
            _ = try await f.session.approve(run, remember: false)
            Issue.record("the approval should have failed")
        } catch {
            #expect(error.localizedDescription == message)
        }
        #expect(f.session.run(id: run.id) != nil)
        #expect(f.ended.isEmpty)
    }

    @Test("deny removes the run, and an access request is denied by its ID")
    func deny() async throws {
        let f = Fixture()
        await f.session.refresh()
        try await f.session.deny(PreviewData.quotedRun)
        await f.session.deny(PreviewData.accessRequest)
        #expect(await f.mac.calls == ["deny 123456789012346", "denyAccess 42"])
        #expect(f.session.run(id: PreviewData.quotedRun.id) == nil)
        #expect(f.session.accessRequests.isEmpty)
        #expect(f.session.actionError == nil)
        #expect(f.session.denying.isEmpty)
    }

    @Test("a refused denial of an access request sets the message for the alert")
    func denyRefused() async {
        let f = Fixture()
        await f.session.refresh()
        await f.mac.fail(with: .server(status: 404, code: "not_waiting", message: "The request no longer waits."))
        await f.session.deny(PreviewData.accessRequest)
        #expect(f.session.actionError == "The request no longer waits.")
        #expect(f.session.accessRequests.count == 1)
    }

    @Test("unpair tells the Mac, deletes the record, and ends")
    func unpair() async {
        let f = Fixture()
        await f.session.refresh()
        await f.session.unpair()
        #expect(await f.mac.calls == ["unpair"])
        #expect((try? f.store.load()) == nil)
        #expect(f.ended == ["This iPhone is unpaired."])
    }

    @Test("unpair deletes the record even when the Mac is not reachable, and says so")
    func unpairOffline() async {
        let f = Fixture()
        await f.mac.fail(with: .unreachable)
        await f.session.unpair()
        #expect((try? f.store.load()) == nil)
        #expect(f.ended.count == 1)
        #expect(f.ended[0]?.contains("Remove it in Settings > iPhone companion") == true)
    }

    @Test("forget deletes the record and does not ask the Mac")
    func forget() async {
        let f = Fixture()
        await f.mac.fail(with: .pinMismatch)
        await f.session.refresh()
        #expect(f.session.state == .pinMismatch)
        f.session.forgetMac()
        #expect(await f.mac.calls.isEmpty)
        #expect((try? f.store.load()) == nil)
        #expect(f.ended.count == 1)
    }

    @Test("a refused delete keeps the session and shows the error")
    func unpairDeleteFails() async {
        struct StoreFailure: LocalizedError {
            var errorDescription: String? { "The keychain refused the request (code -25308)." }
        }
        struct RefusingStore: PairingStore {
            func load() throws -> PairingRecord? { PreviewData.record }
            func save(_ record: PairingRecord) throws {}
            func delete() throws { throw StoreFailure() }
        }
        var ended = 0
        let session = SessionModel(
            record: PreviewData.record, mac: ScriptedConnection(), keysInSecureEnclave: false,
            store: RefusingStore(), onEnded: { _ in ended += 1 })
        await session.unpair()
        #expect(ended == 0)
        #expect(session.actionError?.contains("could not delete the pairing") == true)
        #expect(!session.isEnding)
    }

    // MARK: Keys that cannot be used

    @Test("a key that cannot be used ends the pairing: the Mac is asked, the record goes, the flow shows the message",
        arguments: [CompanionKeyError.biometryChanged, CompanionKeyError.invalidKey])
    func unusableKey(error: CompanionKeyError) async throws {
        let f = Fixture()
        await f.session.refresh()
        let run = try #require(f.session.run(id: PreviewData.migrateRun.id))
        await f.mac.fail(with: .approvalKey(error))
        do {
            _ = try await f.session.approve(run, remember: false)
            Issue.record("the approval should have failed")
        } catch let thrown as CompanionKeyError {
            #expect(thrown == error)
        }
        // The Mac was asked to remove this iPhone (best effort), the record is gone, and the flow
        // got the message, once.
        #expect(await f.mac.calls == ["unpair"])
        #expect((try? f.store.load()) == nil)
        #expect(f.ended == [error.errorDescription])
        #expect(f.session.isEnding)
        // The polling does nothing more.
        let before = await f.mac.inboxCalls
        await f.session.refresh()
        #expect(await f.mac.inboxCalls == before)
    }

    @Test("a failed match or a cancelled prompt keeps the pairing, and the run stays",
        arguments: [CompanionKeyError.authenticationFailed, CompanionKeyError.cancelled, CompanionKeyError.lockedOut])
    func retryableKey(error: CompanionKeyError) async throws {
        let f = Fixture()
        await f.session.refresh()
        let run = try #require(f.session.run(id: PreviewData.migrateRun.id))
        await f.mac.fail(with: .approvalKey(error))
        do {
            _ = try await f.session.approve(run, remember: false)
            Issue.record("the approval should have failed")
        } catch let thrown as CompanionKeyError {
            #expect(thrown == error)
        }
        #expect(f.ended.isEmpty)
        #expect((try? f.store.load()) != nil)
        #expect(f.session.run(id: run.id) != nil)
        #expect(!f.session.isEnding)
        // The owner tries again and it works.
        await f.mac.fail(with: .none)
        #expect(try await f.session.approve(run, remember: false) == .approved)
    }

    // MARK: What a tab shows

    @Test("a tab shows the connection in place of its rows before the first answer, and for another Mac")
    func connectionScreen() async {
        let f = Fixture()
        #expect(f.session.showsConnectionScreen(rows: 0))
        await f.session.refresh()
        #expect(!f.session.showsConnectionScreen(rows: 3))
        #expect(!f.session.showsConnectionScreen(rows: 0))

        // Not the paired Mac: its rows are of no use, and "Forget this Mac" is on this screen.
        await f.mac.fail(with: .pinMismatch)
        await f.session.refresh()
        #expect(f.session.state == .pinMismatch)
        #expect(f.session.showsConnectionScreen(rows: 3))
        #expect(f.session.showsConnectionScreen(rows: 0))
    }

    @Test("without rows, a Mac that does not answer shows its state and not a blank list; with rows the last ones stay")
    func connectionScreenWithoutRows() async {
        let f = Fixture()
        await f.mac.setInbox(Inbox(runs: [], accessRequests: [], activity: []))
        await f.session.refresh()
        #expect(f.session.waitingCount == 0)
        for failure in [
            ScriptedConnection.Failure.unreachable, .localNetworkDenied,
            .server(status: 500, code: "internal", message: "Something broke."),
        ] {
            await f.mac.fail(with: failure)
            await f.session.refresh()
            #expect(f.session.state != .connected)
            #expect(f.session.showsConnectionScreen(rows: 0))
            // A tab that has rows keeps them, marked as not up to date.
            #expect(!f.session.showsConnectionScreen(rows: 2))
        }
        await f.mac.fail(with: .none)
        await f.session.refresh()
        #expect(!f.session.showsConnectionScreen(rows: 0))
    }
}
