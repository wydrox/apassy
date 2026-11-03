import Foundation
import Observation

/// A notice above the requests of the watch (flow spec A1, "Unreadable row").
public struct WatchListNotice: Equatable, Sendable {
    public let title: String
    public let message: String

    public init(title: String, message: String) {
        self.title = title
        self.message = message
    }

    /// The question key was rotated, or the row of this watch changed.
    public static let connectAgain = WatchListNotice(
        title: "Can't read this request", message: "Connect this watch again to read new requests.")
    /// A newer version of the access requests.
    public static let update = WatchListNotice(
        title: "Can't read this request", message: "Update Apassy to read this request.")
}

/// The access requests of the watch and its answers (screens A1 to A4, ADR 0033 section 7 as
/// changed by ADR 0039 section 3). The rules are in `WatchRequestRules`.
///
/// Allow once signs with the answer key of this watch after a check of the wrist; Deny is signed by
/// the core with the relay key and needs no check. An answer goes out at most three times with the
/// same bytes, and never again with a new signature by itself.
@MainActor @Observable
public final class WatchRequestsModel {
    /// The requests, newest first.
    public private(set) var rows: [RelayAccessRequest] = []
    /// The first list of this session came (or failed).
    public private(set) var loaded = false
    /// Offline: the time of the list that the rows show.
    public private(set) var offlineSince: Date?
    /// A list that failed with nothing to show, for the owner.
    public private(set) var failure: String?
    public private(set) var notice: WatchListNotice?
    /// What this watch did with each request.
    public private(set) var progress: [String: WatchAnswerProgress]
    /// Why Allow once is off on this watch for every request (its row), or nil.
    public private(set) var allowOffReason: String?
    /// The requests whose answer key is the key of this watch.
    private var signable: Set<String> = []

    @ObservationIgnored private let service: any WatchService
    @ObservationIgnored private let keys: any WatchAnswerKeys
    @ObservationIgnored private var attempt: (any WatchSigningAttempt)?
    @ObservationIgnored private var answerTask: Task<Void, Never>?
    @ObservationIgnored private var busyID: String?
    @ObservationIgnored private var generation = 0
    @ObservationIgnored private var listGeneration = 0
    @ObservationIgnored private var submitted: Set<String> = []
    @ObservationIgnored private var lastList: Date?
    @ObservationIgnored private let retryDelays: [Duration]

    public init(
        service: any WatchService, keys: any WatchAnswerKeys, progress: [String: WatchAnswerProgress] = [:],
        retryDelays: [Duration] = [.seconds(2), .seconds(4)]
    ) {
        self.service = service
        self.keys = keys
        self.progress = progress
        self.retryDelays = retryDelays
    }

    public func request(_ id: String) -> RelayAccessRequest? { rows.first { $0.id == id } }

    /// The state of the Request screen at `date`.
    public func phase(for id: String, at date: Date) -> WatchRequestPhase {
        let request = self.request(id)
        return WatchRequestRules.phase(
            of: request, progress: progress[id], allowBlock: request.flatMap { self.allowBlock(for: $0) }, at: date)
    }

    /// Why this watch cannot sign Allow once for `request`, or nil when it can.
    public func allowBlock(for request: RelayAccessRequest) -> String? {
        if let allowOffReason { return allowOffReason }
        if !keys.canSign { return "Allow once needs this watch unlocked on your wrist." }
        if request.answer_key == nil { return "Update Apassy on your Mac to connect this watch." }
        if !signable.contains(request.id) { return "Allow once is off: connect this watch again." }
        return nil
    }

    /// The Mac confirmed an answer that this watch sent (the success haptic).
    public func isConfirmedHere(_ id: String) -> Bool {
        guard let request = self.request(id), let receipt = request.receipt else { return false }
        return WatchRequestRules.result(of: receipt, card: request.card, progress: progress[id], at: .now).byThisWatch
    }

    /// The times when a screen changes by itself: the expiry, and the end of the wait for a
    /// confirmation. A coarse timeline, never a countdown.
    public func deadlines(for id: String) -> [Date] {
        guard let request = self.request(id) else { return [] }
        var dates = [Date(timeIntervalSince1970: TimeInterval(request.card.expires_at))]
        if case .sent(_, let at)? = progress[id] { dates.append(at.addingTimeInterval(WatchRequestRules.confirmationWait)) }
        return dates.sorted()
    }

    /// The expiry of every row (the row status changes from "Until" to "Expired").
    public var expiries: [Date] {
        rows.map { Date(timeIntervalSince1970: TimeInterval($0.card.expires_at)) }.sorted()
    }

    /// The state of the row of this watch: Allow once is off for every request with `message`.
    func setAllowOffReason(_ message: String?) { allowOffReason = message }

    // MARK: - The list

    /// Read the list. A membership problem (the watch was removed, the replica is locked) is
    /// returned for `WatchAppModel`; every other failure is shown here.
    @discardableResult
    public func refresh() async -> VaultError? {
        let current = listGeneration
        do {
            let snapshot = try await service.accessRequestsList()
            guard current == listGeneration else { return nil }
            guard snapshot.protocolName == "apassy-access-request", snapshot.version == 1 else {
                notice = .update
                loaded = true
                return nil
            }
            let updated = snapshot.requests.sorted { $0.card.created_at > $1.card.created_at }
            if let busyID, !updated.contains(where: { $0.id == busyID && $0.state == "open" && $0.receipt == nil }) {
                cancelSigning()
            }
            var mine: [String: Data] = [:]
            signable = Set(updated.compactMap { row in
                let team = row.card.team_id
                if mine[team] == nil { mine[team] = keys.publicKey(team: team) }
                return WatchRequestRules.keyMatches(row, own: mine[team]) ? row.id : nil
            })
            rows = updated
            lastList = .now
            offlineSince = nil
            failure = nil
            notice = nil
            loaded = true
            return nil
        } catch let error as VaultError {
            guard current == listGeneration else { return nil }
            loaded = true
            switch error.code {
            case .relayUnreachable, .rateLimited, .busy:
                offlineSince = lastList
                failure = rows.isEmpty ? "Couldn't reach the relay. Check that this watch is online." : nil
                return nil
            case .removed, .locked, .noVault, .noQuestions:
                return error
            case .unreadable, .answerKeyChanged, .notRegistered:
                notice = .connectAgain
                return nil
            case .unsupportedSchema, .unsupported:
                notice = .update
                return nil
            default:
                if error.rekeyed { notice = .connectAgain } else { failure = error.message }
                return nil
            }
        } catch {
            guard current == listGeneration else { return nil }
            loaded = true
            failure = error.localizedDescription
            return nil
        }
    }

    /// Cancel a signature and drop what the screens show: the scene went to the background, the
    /// watch was removed, or it locked (ADR 0033 section 7, "States"). Sent answers stay known.
    public func clearSensitive() {
        cancelSigning()
        listGeneration += 1
        rows = []
        signable = []
        loaded = false
        offlineSince = nil
        failure = nil
        notice = nil
        lastList = nil
        progress = progress.filter { $0.value.postedChoice != nil }
    }

    /// Forget everything, the sent answers too (the watch was removed on this watch).
    func reset() {
        clearSensitive()
        progress = [:]
        submitted = []
        allowOffReason = nil
    }

    // MARK: - Answers

    /// Answer `id`. The task belongs to this model: it ends on the background, never with the view.
    public func answer(_ id: String, choice: AccessChoice) {
        guard busyID == nil, let request = self.request(id), canStart(request, choice: choice, at: .now) else { return }
        generation += 1
        let mine = generation
        busyID = id
        progress[id] = choice == .allow_once ? .checkingWrist : .sending(choice)
        answerTask = Task { [weak self] in await self?.perform(request, choice: choice, generation: mine) }
    }

    /// The answer that runs, for tests.
    func answerFinished() async { await answerTask?.value }

    private func canStart(_ request: RelayAccessRequest, choice: AccessChoice, at date: Date) -> Bool {
        guard request.card.valid_answers.contains(choice), WatchRequestRules.isActionable(request, at: date),
            progress[request.id]?.postedChoice == nil
        else { return false }
        guard choice == .allow_once else { return true }
        return WatchRequestRules.offersAllowOnce(request.card) && allowBlock(for: request) == nil
    }

    /// End a check of the wrist that runs, and discard its result. An answer that was posted stays
    /// "Not confirmed"; nothing else was sent.
    public func cancelSigning() {
        generation += 1
        attempt?.cancel()
        attempt = nil
        answerTask?.cancel()
        answerTask = nil
        if let busyID {
            switch progress[busyID] {
            case .sending(let choice)? where submitted.contains(busyID):
                progress[busyID] = .uncertain(choice)
            case .checkingWrist?, .sending?:
                progress[busyID] = nil
            default:
                break
            }
        }
        busyID = nil
    }

    private func perform(_ current: RelayAccessRequest, choice: AccessChoice, generation mine: Int) async {
        let id = current.id
        defer {
            if mine == generation {
                busyID = nil
                attempt = nil
                answerTask = nil
            }
        }
        do {
            await service.accessRequestCancelPrepared()
            guard mine == generation else { return }
            let prepared = try await service.accessRequestPrepare(current, choice: choice)
            guard mine == generation else { return }
            guard prepared.digest == current.digest, prepared.needs_face_id == (choice == .allow_once),
                let bytes = Base64URL.decode(prepared.bytes)
            else {
                progress[id] = .failed("This access request changed. Nothing was sent.")
                return
            }
            let started = ContinuousClock.now
            let wall = Date.now
            let remainder = min(
                50, Double(prepared.retry_before) - wall.timeIntervalSince1970,
                Double(current.card.expires_at) - wall.timeIntervalSince1970)
            guard remainder > 0 else { throw VaultError(.expired, WatchRequestText.expired) }
            var signature: Data?
            if choice == .allow_once {
                let attempt = keys.attempt(team: current.card.team_id)
                self.attempt = attempt
                // End the check at the deadline of the prepared bytes, even if the system is
                // still checking; a later signature could never be sent.
                let expiry = Task { [weak self] in
                    do { try await Task.sleep(for: .seconds(remainder)) } catch { return }
                    guard let self, mine == self.generation else { return }
                    attempt.cancel()
                }
                defer { expiry.cancel() }
                do {
                    signature = try await withTaskCancellationHandler {
                        try await attempt.sign(bytes)
                    } onCancel: {
                        attempt.cancel()
                    }
                } catch {
                    attempt.cancel()
                    guard mine == generation else { return }
                    progress[id] = .refused
                    return
                }
                attempt.cancel()
                self.attempt = nil
                guard mine == generation else { return }
                progress[id] = .sending(choice)
            }
            // A cancelled, expired, or changed request never posts.
            guard mine == generation, !Task.isCancelled,
                rows.contains(where: { $0.id == id && $0.state == "open" && $0.receipt == nil })
            else {
                if mine == generation { progress[id] = nil }
                return
            }
            let elapsed = started.duration(to: .now)
            guard elapsed < .seconds(50),
                abs(Date.now.timeIntervalSince(wall) - Double(elapsed.components.seconds)) < 2
            else {
                progress[id] = .failed("The time of this watch changed. Nothing was sent. Choose the answer again.")
                return
            }
            for attemptNumber in 0...retryDelays.count {
                guard mine == generation, Date.now.timeIntervalSince1970 < Double(prepared.retry_before),
                    Date.now.timeIntervalSince1970 < Double(current.card.expires_at)
                else { throw VaultError(.expired, WatchRequestText.expired) }
                do {
                    submitted.insert(id)
                    let result = try await service.accessRequestAnswer(
                        current, choice: choice, prepared: prepared, signature: signature)
                    guard mine == generation else { return }
                    progress[id] = result.sent ? .sent(choice, at: .now) : .uncertain(choice)
                    if result.sent { await refresh() }
                    return
                } catch let error as VaultError where error.code == .relayUnreachable && attemptNumber < retryDelays.count {
                    // The same bytes and signature only; the core reserves every uncertain post.
                    try await Task.sleep(for: retryDelays[attemptNumber])
                }
            }
        } catch {
            guard mine == generation else { return }
            if submitted.contains(id) {
                progress[id] = .uncertain(choice)
            } else {
                progress[id] = .failed("Nothing was sent. \(error.localizedDescription)")
            }
        }
    }
}
