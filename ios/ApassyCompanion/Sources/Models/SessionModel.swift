import ApassyCompanionKit
import Foundation
import Observation

/// One paired Mac: the connection to it, and what it last said. Everything here lives in memory.
/// Nothing of the inbox or the activity is written to disk.
@MainActor
@Observable
final class SessionModel {
    /// How the last request to the Mac went.
    enum ConnectionState: Equatable {
        case connecting
        case connected
        case unreachable
        case localNetworkDenied
        /// Every host answered with another certificate.
        case pinMismatch
        case problem(String)
    }

    /// The time that the Mac gives a run before it ends it, until the Mac says otherwise.
    static let defaultApprovalTimeout = 120

    private(set) var record: PairingRecord
    private(set) var state: ConnectionState = .connecting
    private(set) var inbox: Inbox?
    /// When `inbox` arrived. The time left of a run counts from it.
    private(set) var fetchedAt: Date?
    private(set) var status: StatusInfo?
    private(set) var lastGoodHost: String?
    /// True while the pairing is being removed.
    private(set) var isEnding = false
    /// Access requests whose denial is on its way.
    private(set) var denying: Set<String> = []
    /// A message for an alert, or nil.
    var actionError: String?
    let keysInSecureEnclave: Bool

    private let mac: any MacConnection
    private let store: any PairingStore
    private let onEnded: @MainActor (String?) -> Void
    private let pollInterval: Duration
    private var isRefreshing = false

    init(
        record: PairingRecord,
        mac: any MacConnection,
        keysInSecureEnclave: Bool,
        store: any PairingStore,
        pollInterval: Duration = .seconds(2),
        onEnded: @escaping @MainActor (String?) -> Void
    ) {
        self.record = record
        self.mac = mac
        self.keysInSecureEnclave = keysInSecureEnclave
        self.store = store
        self.onEnded = onEnded
        self.pollInterval = pollInterval
        self.lastGoodHost = record.lastGoodHost
    }

    var macName: String { status?.macName ?? record.macName }
    var approvalTimeout: Int { status?.approvalTimeoutSeconds ?? Self.defaultApprovalTimeout }
    var runs: [PendingRun] { inbox?.runs ?? [] }
    var accessRequests: [AccessRequest] { inbox?.accessRequests ?? [] }
    var activity: [ActivityEntry] { inbox?.activity ?? [] }
    /// What waits for the owner, for the badge of the Inbox tab.
    var waitingCount: Int { runs.count + accessRequests.count }

    func run(id: String) -> PendingRun? {
        runs.first { $0.id == id }
    }

    /// Whether a tab shows the state of the connection in place of its rows. `rows` is how many
    /// rows the tab has from the last inbox.
    ///
    /// That is so before the first answer, and when the Mac is not the one that was paired: its
    /// rows are of no use then, and the way out ("Forget this Mac") is on that screen. While the
    /// Mac does not answer, rows from the last inbox stay, marked as not up to date. Without rows,
    /// a blank list would say nothing, so the state shows instead.
    func showsConnectionScreen(rows: Int) -> Bool {
        if inbox == nil || state == .pinMismatch { return true }
        return state != .connected && rows == 0
    }

    // MARK: Polling

    /// Ask for the inbox every 2 s until the task is cancelled. The tabs start it while the app is
    /// active and cancel it in the background.
    func poll() async {
        while !Task.isCancelled {
            await refresh()
            try? await Task.sleep(for: pollInterval)
        }
    }

    /// Fetch the inbox once. A call while another fetch runs does nothing.
    func refresh() async {
        guard !isRefreshing, !isEnding else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            let fresh = try await mac.inbox()
            inbox = fresh
            fetchedAt = Date()
            state = .connected
            await noteHost()
            if status == nil { await refreshStatus() }
        } catch {
            await handle(error)
        }
    }

    /// Fetch the status of the Mac: its name, its version, the approval time, and this iPhone.
    func refreshStatus() async {
        if let fresh = try? await mac.status() { status = fresh }
    }

    private func noteHost() async {
        let host = await mac.lastGoodHost
        lastGoodHost = host
        guard let host, host != record.lastGoodHost else { return }
        record.lastGoodHost = host
        // The host is a convenience. A failed save only costs one more try on the next start.
        try? store.save(record)
    }

    private func handle(_ error: Error) async {
        if error is CancellationError { return }
        switch error as? CompanionError {
        case .unpaired?:
            end(notice: CompanionError.unpaired.errorDescription)
        case .notReachable?:
            state = .unreachable
        case .localNetworkDenied?:
            state = .localNetworkDenied
        case .pinMismatchOnAllHosts?:
            state = .pinMismatch
        default:
            state = .problem(error.localizedDescription)
        }
    }

    // MARK: Decisions

    /// Approve a run with Face ID. Throws the message for the owner: the Mac's own, or the key's.
    ///
    /// A key that cannot be used again (the biometric enrollment changed, or the key is gone) ends
    /// the pairing, as a 401 unpaired does: the owner has to pair again (contract 5.2). A failed
    /// match or a cancelled prompt is not that. The key is fine, and the owner can try again.
    func approve(_ run: PendingRun, remember: Bool) async throws -> ApproveOutcome {
        do {
            let outcome = try await mac.approve(run: run, remember: remember)
            removeRun(id: run.id)
            return outcome
        } catch CompanionError.unpaired {
            end(notice: CompanionError.unpaired.errorDescription)
            throw CompanionError.unpaired
        } catch let error as CompanionKeyError where error.keyIsUnusable {
            await endBecauseKeyIsUnusable(error)
            throw error
        }
    }

    func deny(_ run: PendingRun) async throws {
        do {
            try await mac.deny(run: run)
            removeRun(id: run.id)
        } catch CompanionError.unpaired {
            end(notice: CompanionError.unpaired.errorDescription)
            throw CompanionError.unpaired
        }
    }

    /// Deny an access request. An error goes to `actionError`.
    func deny(_ request: AccessRequest) async {
        guard !denying.contains(request.id) else { return }
        denying.insert(request.id)
        defer { denying.remove(request.id) }
        do {
            try await mac.denyAccessRequest(id: request.id)
            if let current = inbox {
                inbox = Inbox(
                    runs: current.runs, accessRequests: current.accessRequests.filter { $0.id != request.id },
                    activity: current.activity)
            }
        } catch CompanionError.unpaired {
            end(notice: CompanionError.unpaired.errorDescription)
        } catch is CancellationError {
        } catch {
            actionError = error.localizedDescription
        }
    }

    private func removeRun(id: String) {
        guard let current = inbox else { return }
        inbox = Inbox(
            runs: current.runs.filter { $0.id != id }, accessRequests: current.accessRequests,
            activity: current.activity)
    }

    // MARK: Ending the pairing

    /// Tell the Mac, then delete the keys and the record here. The Mac not answering does not stop
    /// the deletion: the owner can remove the device on the Mac.
    func unpair() async {
        guard !isEnding else { return }
        isEnding = true
        var notice = "This iPhone is unpaired."
        do {
            try await mac.unpair()
        } catch {
            notice =
                "This iPhone is unpaired here. The Mac did not answer, so it may still list this iPhone. Remove it in Settings > iPhone companion in Apassy on your Mac."
        }
        finishEnding(notice: notice)
    }

    /// Delete the pairing on this iPhone only. The Mac is not asked.
    func forgetMac() {
        guard !isEnding else { return }
        isEnding = true
        finishEnding(notice: "The pairing with this Mac is deleted on this iPhone. Pair it again to use Apassy.")
    }

    /// The Mac ended the pairing (401 unpaired): delete it here and go back to the pairing flow.
    private func end(notice: String?) {
        guard !isEnding else { return }
        isEnding = true
        dropPairing(notice: notice)
    }

    /// The approval key cannot be used again. Ask the Mac to remove this iPhone, as far as it
    /// answers (the request key still works), then delete the pairing here and show the flow with
    /// the message. The polling stops at once, so nothing else asks the Mac meanwhile.
    private func endBecauseKeyIsUnusable(_ error: CompanionKeyError) async {
        guard !isEnding else { return }
        isEnding = true
        try? await mac.unpair()
        dropPairing(notice: error.localizedDescription)
    }

    private func dropPairing(notice: String?) {
        // A failed delete leaves a record that the next start finds unpaired or without keys, so
        // the flow goes on either way.
        try? store.delete()
        onEnded(notice)
    }

    private func finishEnding(notice: String) {
        do {
            try store.delete()
        } catch {
            isEnding = false
            actionError = "Apassy could not delete the pairing from this iPhone. \(error.localizedDescription)"
            return
        }
        onEnded(notice)
    }
}

#if DEBUG

extension SessionModel {
    /// A session on synthetic data, for the previews. It never touches the network or the keychain.
    static func preview(
        inbox: Inbox? = PreviewData.inbox,
        state: ConnectionState = .connected
    ) -> SessionModel {
        let session = SessionModel(
            record: PreviewData.record, mac: PreviewConnection(), keysInSecureEnclave: true,
            store: InMemoryPairingStore(PreviewData.record), onEnded: { _ in })
        session.inbox = inbox
        session.fetchedAt = Date()
        session.state = state
        session.status = PreviewData.status
        session.lastGoodHost = PreviewData.record.lastGoodHost
        return session
    }
}

#endif
