import Foundation

/// The watch core in memory, with synthetic data only: the previews, the screenshots
/// (`-ApassyWatchPreview`), and the tests. Production uses `WatchCoreService` over the Rust core,
/// which checks every signature.
public actor PreviewWatchService: WatchService {
    /// What `watch_connect_start` and `watch_connect_poll` do.
    public enum Connection: Sendable {
        /// Waits for the Mac for ever.
        case waits
        /// Attached at the first poll.
        case attaches
        /// The first call fails.
        case fails(VaultError)
    }

    public static let words = ["amber", "cobalt", "harbor", "lunar", "orbit", "velvet"]

    private var state: WatchStatus.State
    private var vault: WatchVault?
    private var macs: [String]
    private var rows: [RelayAccessRequest]
    private let connection: Connection
    private var posts: [(id: String, choice: AccessChoice, signature: Data?)] = []
    private var failures: [VaultError] = []
    private let settles: Bool
    /// How long `watch_connect_start` and `unlock` take: the core sets the join, and opens the
    /// replica, only when they return.
    private let startDelay: Duration
    private let unlockDelay: Duration

    public init(
        state: WatchStatus.State, vault: WatchVault? = WatchPreview.vault, macs: [String] = [WatchPreview.mac],
        requests: [RelayAccessRequest] = [], connection: Connection = .waits, settles: Bool = true,
        startDelay: Duration = .zero, unlockDelay: Duration = .zero
    ) {
        self.startDelay = startDelay
        self.unlockDelay = unlockDelay
        self.state = state
        self.vault = state == .unpaired ? nil : vault
        self.macs = macs
        self.rows = requests
        self.connection = connection
        self.settles = settles
    }

    // MARK: Fixture controls

    public func setRequests(_ requests: [RelayAccessRequest]) { rows = requests }
    public func setState(_ value: WatchStatus.State) { state = value }
    public func failNextAnswer(_ error: VaultError) { failures.append(error) }
    /// The answers posted so far: the request, the choice, and the signature (Allow once).
    public func postedAnswers() -> [(id: String, choice: AccessChoice, signature: Data?)] { posts }

    // MARK: WatchService

    public func status(answerKey: Data?) throws -> WatchStatus {
        let own = state == .ready ? WatchStatus.Own(found: true, answerKeyMatches: true) : nil
        return WatchStatus(state: state, vault: state == .unpaired ? nil : vault, macs: state == .ready ? macs : [], own: own)
    }

    public func connectStart(link: String, name: String, answerKey: Data, passphrase: String) async throws
        -> WatchConnectInfo
    {
        guard state == .unpaired || state == .removed else {
            throw VaultError(.alreadyConnected, "This watch is connected to a vault already. Forget it first.")
        }
        if case .fails(let error) = connection { throw error }
        // Not cancellable, as the relay call of the core: a cancel meanwhile finds no join.
        await Self.pause(startDelay)
        state = .connecting
        return WatchConnectInfo(
            state: .waiting, words: Self.words, expiresAt: UInt64(Date.now.timeIntervalSince1970) + 600)
    }

    public func connectPoll() throws -> WatchConnectInfo {
        guard state == .connecting else { throw VaultError(.invalidInput, "No connection waits.") }
        switch connection {
        case .attaches:
            state = .ready
            let vault = vault ?? WatchPreview.vault
            self.vault = vault
            return WatchConnectInfo(state: .attached, vault: vault)
        case .waits, .fails:
            return WatchConnectInfo(
                state: .waiting, words: Self.words, expiresAt: UInt64(Date.now.timeIntervalSince1970) + 600)
        }
    }

    public func connectCancel() { if state == .connecting { state = .unpaired } }

    public func forget() {
        state = .unpaired
        vault = nil
        rows = []
    }

    public func select(vaultID: String) throws {
        guard vault?.id == vaultID else { throw VaultError(.notFound, "No such vault.") }
    }

    public func unlock(passphrase: String) async throws {
        guard state == .locked || state == .ready else { throw VaultError(.noVault, "No vault.") }
        await Self.pause(unlockDelay)
        state = .ready
    }

    public func lock() { if state == .ready { state = .locked } }

    public func suspend() { lock() }

    public func accessRequestsList() throws -> AccessRequestsSnapshot {
        switch state {
        case .ready: break
        case .removed: throw VaultError(.removed, "A Mac removed this watch.")
        default: throw VaultError(.locked, "The vault is locked.")
        }
        return AccessRequestsSnapshot(protocolName: "apassy-access-request", version: 1, requests: rows)
    }

    public func accessRequestPrepare(_ request: RelayAccessRequest, choice: AccessChoice) throws
        -> PreparedAccessAnswer
    {
        guard state == .ready, rows.contains(where: { $0.id == request.id && $0.state == "open" }),
            request.card.valid_answers.contains(choice)
        else { throw VaultError(.accessUnavailable, "Review on the synthetic Mac.") }
        let now = UInt64(Date.now.timeIntervalSince1970)
        guard now < request.card.expires_at else { throw VaultError(.expired, "The fixture request expired.") }
        return PreparedAccessAnswer(
            bytes: Base64URL.encode(Data("synthetic:\(request.id):\(choice.rawValue):\(now)".utf8)),
            time: now, digest: request.digest, needs_face_id: choice == .allow_once,
            retry_before: min(now + 50, request.card.expires_at))
    }

    public func accessRequestAnswer(
        _ request: RelayAccessRequest, choice: AccessChoice, prepared: PreparedAccessAnswer, signature: Data?
    ) throws -> SentAccessAnswer {
        guard state == .ready, let index = rows.firstIndex(where: { $0.id == request.id && $0.state == "open" }),
            (choice == .allow_once) == (signature != nil), prepared.digest == request.digest
        else { throw VaultError(.accessUnavailable, "The fixture answer is unavailable.") }
        posts.append((request.id, choice, signature))
        if !failures.isEmpty { throw failures.removeFirst() }
        if settles {
            rows[index] = WatchPreview.settled(rows[index], choice: choice, byWatch: true)
        }
        return SentAccessAnswer(sent: true)
    }

    public func accessRequestCancelPrepared() {}

    /// A pause that a cancelled caller cannot shorten, as a blocking call of the core.
    private static func pause(_ duration: Duration) async {
        guard duration > .zero else { return }
        await Task.detached { _ = try? await Task.sleep(for: duration) }.value
    }

    /// No change comes by itself: the wait ends after a short time.
    public func wait(timeout: Int) async throws -> Bool {
        try await Task.sleep(for: .seconds(min(max(timeout, 1), 25)))
        return false
    }
}
