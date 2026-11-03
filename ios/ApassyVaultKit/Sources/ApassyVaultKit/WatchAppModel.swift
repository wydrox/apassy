import Foundation
import Observation

/// Why a connection of the watch did not happen (flow spec S1, "After a failed attempt").
public enum WatchConnectProblem: Equatable, Sendable {
    case wordsDiffer
    case codeExpired
    case relayUnreachable
    /// A sentence of the core or of this watch.
    case other(String)

    public var text: String {
        switch self {
        case .wordsDiffer: "The words didn't match, so nothing was connected. Start again on your iPhone."
        case .codeExpired: "The code expired. Show a new code on your Mac."
        case .relayUnreachable: "Couldn't reach the relay. Check that this watch is online, then start again on your iPhone."
        case .other(let message): message
        }
    }

    static func of(_ error: any Error) -> WatchConnectProblem {
        guard let error = error as? VaultError else {
            return .other("This watch couldn't make its keys. Set a passcode on this watch, then start again on your iPhone.")
        }
        switch error.code {
        case .safetyMismatch, .joinRefused: return .wordsDiffer
        case .linkInvalid, .expired: return .codeExpired
        case .relayUnreachable, .rateLimited, .busy: return .relayUnreachable
        default: return .other(error.message)
        }
    }
}

/// The screen of the watch that replaces Requests until the watch is connected.
public enum WatchScreen: Equatable, Sendable {
    /// The first status (well under 2 s, no network).
    case starting
    /// S1: not connected, with the reason of a failed attempt.
    case connect(WatchConnectProblem?)
    /// S1, Removed: a Mac removed this watch.
    case removed
    /// S3, loading: the link is being registered.
    case connecting
    /// S3: the six safety words.
    case words([String])
    /// S5: connected to `vault`, on these Macs.
    case connected(vault: String, macs: [String])
    /// A1 and the screens above it.
    case requests
    /// The core did not start on this watch.
    case unavailable(String)

    /// S1: the watch takes a link from the iPhone.
    public var takesLink: Bool {
        switch self {
        case .connect, .removed: true
        default: false
        }
    }
}

/// The Apple Watch app (ADR 0039): its connection, its replica vault, and its requests.
///
/// The replica opens when the app becomes active and suspends in the background. In the
/// background a running signature is cancelled and the requests are dropped (ADR 0033 section 7).
@MainActor @Observable
public final class WatchAppModel {
    public private(set) var screen: WatchScreen = .starting
    public private(set) var status: WatchStatus?
    /// The screens on top of Requests (one `NavigationStack`).
    public var path: [WatchRoute]
    /// This watch (the settings sheet).
    public var showsSettings: Bool
    public let requests: WatchRequestsModel
    public private(set) var phase: WatchScenePhase = .inactive

    @ObservationIgnored private let service: (any WatchService)?
    @ObservationIgnored private let keys: any WatchAnswerKeys
    @ObservationIgnored private let replica: any WatchReplicaStore
    @ObservationIgnored private let deviceName: String
    @ObservationIgnored private let pollInterval: Duration
    @ObservationIgnored private var launchLink: String?
    @ObservationIgnored private var connectTask: Task<Void, Never>?
    @ObservationIgnored private var connectGeneration = 0
    @ObservationIgnored private var started = false
    @ObservationIgnored private var opening = false

    /// - Parameters:
    ///   - service: the core, or nil when it did not start (`startupError` says why).
    ///   - deviceName: the name of the watch, for the link name (`WatchConnectLink.defaultName`).
    ///   - launchLink: a Connect code to start with (a development aid of the Simulator).
    ///   - progress, path, showsSettings: the state of a preview.
    public init(
        service: (any WatchService)?, keys: any WatchAnswerKeys, replica: any WatchReplicaStore,
        deviceName: String, startupError: String? = nil, launchLink: String? = nil,
        progress: [String: WatchAnswerProgress] = [:], path: [WatchRoute] = [], showsSettings: Bool = false,
        pollInterval: Duration = .seconds(2), retryDelays: [Duration] = [.seconds(2), .seconds(4)]
    ) {
        self.service = service
        self.keys = keys
        self.replica = replica
        self.deviceName = deviceName
        self.launchLink = launchLink
        self.path = path
        self.showsSettings = showsSettings
        self.pollInterval = pollInterval
        self.requests = WatchRequestsModel(
            service: service ?? UnavailableWatchService(), keys: keys, progress: progress, retryDelays: retryDelays)
        if service == nil {
            screen = .unavailable(startupError ?? "Apassy couldn't open its data on this watch.")
        }
    }

    /// The live updates run: the requests show and the app is active.
    public var isLive: Bool { screen == .requests && phase == .active }

    /// The Macs that can ask, escaped.
    public var macs: [String] { (status?.macs ?? []).map(WatchRequestText.escaped) }

    /// The connected vault, escaped.
    public var vaultName: String? { status?.vault.map { WatchRequestText.escaped($0.name) } }

    // MARK: - The scene

    public func scenePhaseChanged(_ phase: WatchScenePhase) async {
        let previous = self.phase
        self.phase = phase
        switch phase {
        case .active:
            if !started {
                started = true
                await start()
            } else if previous == .background, screen == .requests {
                await open()
            }
        case .inactive:
            // Wrist down (Always On): the screens redact themselves; nothing is dropped.
            break
        case .background:
            requests.clearSensitive()
            path = []
            showsSettings = false
            if screen == .requests, let service { try? await service.suspend() }
        }
    }

    /// The first status after launch.
    func start() async {
        guard let service else { return }
        do {
            let status = try await service.status(answerKey: nil)
            self.status = status
            switch status.state {
            case .unpaired:
                screen = .connect(nil)
            case .connecting:
                // A connection of an earlier launch does not survive; start again.
                try? await service.connectCancel()
                screen = .connect(nil)
            case .removed:
                screen = .removed
            case .locked, .ready:
                screen = .requests
                await open()
            }
        } catch {
            screen = .unavailable(error.localizedDescription)
        }
        if screen.takesLink, let link = launchLink {
            launchLink = nil
            _ = receiveLink(link)
        }
    }

    /// Unlock the replica with the passphrase of the keychain, then read the requests.
    func open() async {
        guard let service, !opening else { return }
        opening = true
        defer { opening = false }
        do {
            guard let secret = try replica.load() else {
                // The keychain lost the passphrase (the passcode was turned off): connect again.
                await forgetLocally(problem: .other(WatchListNotice.connectAgain.message))
                return
            }
            var status = try await service.status(answerKey: keys.publicKey(team: secret.team))
            if status.state == .locked {
                if let vault = status.vault { try await service.select(vaultID: vault.id) }
                try await service.unlock(passphrase: secret.passphrase)
                status = try await service.status(answerKey: keys.publicKey(team: secret.team))
            }
            apply(status)
            guard screen == .requests else { return }
            await refreshRequests()
        } catch let error as VaultError where error.code == .wrongPassphrase {
            await forgetLocally(problem: .other(WatchListNotice.connectAgain.message))
        } catch {
            screen = .unavailable(error.localizedDescription)
        }
    }

    private func apply(_ status: WatchStatus) {
        self.status = status
        switch status.state {
        case .removed:
            requests.clearSensitive()
            path = []
            showsSettings = false
            screen = .removed
        case .unpaired:
            requests.reset()
            screen = .connect(nil)
        case .ready, .locked, .connecting:
            if let own = status.own, own.found, !own.answerKeyMatches {
                requests.setAllowOffReason("Update Apassy on your Mac to connect this watch.")
            } else {
                requests.setAllowOffReason(nil)
            }
        }
    }

    /// Read the requests; a removal or a lock found on the way changes the screen.
    public func refreshRequests() async {
        guard let problem = await requests.refresh() else { return }
        let status = try? await service?.status(answerKey: nil)
        switch problem.code {
        case .locked:
            await open()
        case .removed:
            apply(WatchStatus(state: .removed, vault: status?.vault, macs: status?.macs ?? [], own: status?.own))
        default:
            if let status { apply(status) }
        }
    }

    /// Read the status again (the settings sheet).
    public func reloadStatus() async {
        guard let service, screen == .requests else { return }
        let team = (try? replica.load())?.team
        if let status = try? await service.status(answerKey: team.flatMap { keys.publicKey(team: $0) }) {
            apply(status)
        }
    }

    /// The live updates while Requests shows and the app is active: a long poll of the core, with
    /// the backoff of the questions (2, 4, 8, 16, 30 s) after a failure. It ends with its task.
    public func liveUpdates() async {
        guard let service else { return }
        var failures = 0
        while !Task.isCancelled, isLive {
            let began = ContinuousClock.now
            do {
                let changed = try await service.wait(timeout: 25)
                failures = 0
                guard !Task.isCancelled, isLive else { return }
                if changed {
                    await refreshRequests()
                } else if began.duration(to: .now) < .seconds(1) {
                    // A core that cannot wait: refresh every few seconds instead.
                    try await Task.sleep(for: .seconds(5))
                    await refreshRequests()
                }
            } catch is CancellationError {
                return
            } catch {
                failures += 1
                let delays = [2, 4, 8, 16, 30]
                do { try await Task.sleep(for: .seconds(delays[min(failures, delays.count) - 1])) } catch { return }
                guard isLive else { return }
                await refreshRequests()
            }
        }
    }

    // MARK: - Connect

    /// A Connect code from the iPhone (WatchConnectivity) or from a launch argument. Taken only
    /// on S1. Nil when the watch took it; else a sentence for the iPhone.
    public func receiveLink(_ link: String) -> String? {
        guard service != nil else { return "Apassy can't open on this watch." }
        guard screen.takesLink else {
            switch screen {
            case .connecting, .words: return "This watch is connecting. Finish or cancel on the watch."
            default: return "This watch is connected already. Remove it in This watch first."
            }
        }
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard WatchConnectLink.isConnectLink(trimmed), let team = WatchConnectLink.team(of: trimmed) else {
            return "This is not an Apassy Connect code. Show the code of Settings › Devices on your Mac."
        }
        let wasRemoved = screen == .removed
        connectGeneration += 1
        let generation = connectGeneration
        screen = .connecting
        connectTask?.cancel()
        connectTask = Task { [weak self] in
            await self?.connect(link: trimmed, team: team, wasRemoved: wasRemoved, generation: generation)
        }
        return nil
    }

    /// The connection that runs, for tests.
    func connectFinished() async { await connectTask?.value }

    private func connect(link: String, team: String, wasRemoved: Bool, generation: Int) async {
        guard let service else { return }
        do {
            if wasRemoved {
                // The replica of the removed connection goes first.
                try? await service.forget()
                if let old = try? replica.load() { keys.delete(team: old.team) }
                requests.reset()
            }
            if let old = try? replica.load(), old.team != team { keys.delete(team: old.team) }
            let answerKey = try keys.create(team: team)
            let secret = try replica.create(team: team)
            let name = WatchConnectLink.defaultName(deviceName: deviceName)
            var info = try await service.connectStart(
                link: link, name: name, answerKey: answerKey, passphrase: secret.passphrase)
            while generation == connectGeneration, !Task.isCancelled {
                switch info.state {
                case .waiting:
                    if let expiry = info.expiresAt, Date.now.timeIntervalSince1970 >= Double(expiry) {
                        try? await service.connectCancel()
                        fail(.codeExpired, team: team, generation: generation)
                        return
                    }
                    screen = .words(info.words)
                    try await Task.sleep(for: pollInterval)
                    guard generation == connectGeneration else { return }
                    do {
                        info = try await service.connectPoll()
                    } catch let error as VaultError
                        where [.relayUnreachable, .rateLimited, .busy, .io].contains(error.code)
                    {
                        // The connection waits in the core; poll again.
                        continue
                    }
                case .attached:
                    let status = try await service.status(answerKey: answerKey)
                    guard generation == connectGeneration else { return }
                    self.status = status
                    apply(status)
                    let vault = status.vault?.name ?? info.vault?.name ?? ""
                    screen = .connected(
                        vault: WatchRequestText.escaped(vault), macs: status.macs.map(WatchRequestText.escaped))
                    return
                }
            }
        } catch is CancellationError {
            return
        } catch {
            guard generation == connectGeneration else { return }
            fail(WatchConnectProblem.of(error), team: team, generation: generation)
        }
    }

    private func fail(_ problem: WatchConnectProblem, team: String, generation: Int) {
        guard generation == connectGeneration else { return }
        keys.delete(team: team)
        replica.delete()
        screen = .connect(problem)
    }

    /// Cancel on S3: the core gives the join up, and this watch forgets the new keys.
    public func cancelConnect() {
        connectGeneration += 1
        connectTask?.cancel()
        connectTask = nil
        let team = (try? replica.load())?.team
        if let team { keys.delete(team: team) }
        replica.delete()
        screen = .connect(nil)
        guard let service else { return }
        connectTask = Task { try? await service.connectCancel() }
    }

    /// Done on S5.
    public func finishConnecting() {
        guard case .connected = screen else { return }
        screen = .requests
        connectTask = Task { [weak self] in await self?.refreshRequests() }
    }

    // MARK: - Remove

    /// Remove This Watch: the core leaves the team and deletes the replica; the keys and the
    /// passphrase of this watch are deleted. The watch shows S1.
    public func forget() {
        connectGeneration += 1
        connectTask?.cancel()
        showsSettings = false
        path = []
        connectTask = Task { [weak self] in await self?.forgetLocally(problem: nil) }
    }

    /// The removal that runs, for tests.
    func forgetFinished() async { await connectTask?.value }

    private func forgetLocally(problem: WatchConnectProblem?) async {
        requests.reset()
        if let service { try? await service.forget() }
        if let team = (try? replica.load())?.team { keys.delete(team: team) }
        replica.delete()
        status = nil
        screen = .connect(problem)
    }
}

/// The service of a watch whose core did not start: every call fails.
private struct UnavailableWatchService: WatchService {
    private var error: VaultError { VaultError(.internal, "Apassy can't open on this watch.") }
    func status(answerKey: Data?) async throws -> WatchStatus { throw error }
    func connectStart(link: String, name: String, answerKey: Data, passphrase: String) async throws
        -> WatchConnectInfo { throw error }
    func connectPoll() async throws -> WatchConnectInfo { throw error }
    func connectCancel() async throws { throw error }
    func forget() async throws { throw error }
    func select(vaultID: String) async throws { throw error }
    func unlock(passphrase: String) async throws { throw error }
    func lock() async throws { throw error }
    func suspend() async throws { throw error }
    func accessRequestsList() async throws -> AccessRequestsSnapshot { throw error }
    func accessRequestPrepare(_ request: RelayAccessRequest, choice: AccessChoice) async throws
        -> PreparedAccessAnswer { throw error }
    func accessRequestAnswer(
        _ request: RelayAccessRequest, choice: AccessChoice, prepared: PreparedAccessAnswer, signature: Data?
    ) async throws -> SentAccessAnswer { throw error }
    func accessRequestCancelPrepared() async {}
    func wait(timeout: Int) async throws -> Bool { throw error }
}
