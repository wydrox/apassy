import ApassyVaultKit
import Foundation
import Observation

/// Adding a vault of the Mac to this iPhone through the relay (contract ios-core-v1, 5.2): the
/// instructions, the scan of the QR code, the name of this iPhone, the two safety words while the
/// Mac confirms, the passphrase, and the offer of Face ID.
@MainActor
@Observable
final class JoinModel {
    enum Step: Equatable {
        /// What to do on the Mac.
        case instructions
        /// The camera, or paste.
        case scan
        /// The name of this iPhone, before the link goes to the relay.
        case name(link: String)
        /// The link goes to the relay.
        case starting
        /// The Mac shows the same words and waits for the owner to confirm.
        case waiting(JoinInfo)
        /// The Mac confirmed and the copy is here: the passphrase opens it.
        case passphrase(team: String)
        /// The vault is on this iPhone. Face ID unlock is offered.
        case faceID(VaultEntry)
        case done(VaultEntry)
        /// The join ended: the link did not work, the Mac refused, or the words did not match.
        case failed(title: String, message: String)
    }

    var step: Step = .instructions
    var deviceName: String
    /// Why the last scanned or pasted text was not used. The scanner keeps running.
    private(set) var scanNote: String?
    /// A problem while waiting for the Mac, for example no network. Polling goes on.
    private(set) var waitNote: String?
    /// The answer to a wrong passphrase. The owner tries again.
    private(set) var passphraseMessage: String?
    private(set) var isWorking = false
    let biometry: Biometry

    @ObservationIgnored private let service: any VaultService
    @ObservationIgnored private let passphraseStore: any PassphraseStore
    @ObservationIgnored private let settings: VaultSettings
    @ObservationIgnored private let pollInterval: Duration
    @ObservationIgnored private let now: @MainActor () -> Date
    /// Whether the app is in the background now (`VaultModel.isInBackground`).
    @ObservationIgnored private let isAway: @MainActor () -> Bool
    @ObservationIgnored private let onFinished: @MainActor (VaultEntry) -> Void
    @ObservationIgnored private let onCancel: @MainActor () -> Void
    @ObservationIgnored private var pollTask: Task<Void, Never>?
    /// The passphrase that opened the copy, only until the owner answers the Face ID offer.
    @ObservationIgnored private var openedWith: String?

    init(
        service: any VaultService, passphraseStore: any PassphraseStore, settings: VaultSettings, biometry: Biometry,
        deviceName: String, pollInterval: Duration = .seconds(2), now: @escaping @MainActor () -> Date = { Date() },
        isAway: @escaping @MainActor () -> Bool = { false },
        onFinished: @escaping @MainActor (VaultEntry) -> Void, onCancel: @escaping @MainActor () -> Void
    ) {
        self.service = service
        self.passphraseStore = passphraseStore
        self.settings = settings
        self.biometry = biometry
        self.deviceName = deviceName
        self.pollInterval = pollInterval
        self.now = now
        self.isAway = isAway
        self.onFinished = onFinished
        self.onCancel = onCancel
    }

    // MARK: The link

    func showScanner() {
        scanNote = nil
        step = .scan
    }

    /// Text from the scanner or the pasteboard. Text that is not a device link only sets a note.
    func handleCode(_ text: String) {
        switch step {
        case .instructions, .scan: break
        default: return
        }
        guard let link = VaultText.joinLink(from: text) else {
            scanNote = "This is not the code of “Add a device…”. On your Mac, open Apassy > Settings > General > Sync."
            return
        }
        scanNote = nil
        step = .name(link: link)
    }

    // MARK: The name

    var trimmedDeviceName: String {
        deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Why the name cannot be used, or nil. The core takes at most 64 bytes.
    var deviceNameProblem: String? {
        let name = trimmedDeviceName
        if name.isEmpty { return "Type a name for this iPhone." }
        if name.utf8.count > 64 { return "Use a shorter name." }
        if name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) {
            return "Use a name with no control character."
        }
        return nil
    }

    // MARK: Waiting for the Mac

    /// Send the link with the name of this iPhone, then wait for the Mac.
    func start() async {
        guard case .name(let link) = step, deviceNameProblem == nil else { return }
        step = .starting
        waitNote = nil
        do {
            let join = try await service.joinStart(link: link, deviceName: trimmedDeviceName)
            settings.deviceName = trimmedDeviceName
            show(join)
        } catch {
            fail(error)
        }
    }

    private func show(_ join: JoinInfo) {
        switch join.state {
        case .waiting:
            step = .waiting(join)
            startPolling()
        case .ready:
            stopPolling()
            passphraseMessage = nil
            step = .passphrase(team: join.team)
        }
    }

    private func startPolling() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            await self?.poll()
        }
    }

    private func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
    }

    /// Ask the relay every 2 s until the Mac confirmed. A network problem is a note; the link has
    /// its own end, so the owner is not left waiting past it.
    private func poll() async {
        while !Task.isCancelled {
            try? await Task.sleep(for: pollInterval)
            guard !Task.isCancelled, case .waiting(let current) = step else { return }
            do {
                let join = try await service.joinPoll()
                guard !Task.isCancelled else { return }
                waitNote = nil
                if join.state == .ready {
                    pollTask = nil
                    passphraseMessage = nil
                    step = .passphrase(team: join.team)
                    return
                }
                step = .waiting(join)
            } catch let error as VaultError where error.code == .relayUnreachable || error.code == .rateLimited {
                waitNote = error.message
                if now().timeIntervalSince1970 > TimeInterval(current.expiresAt) + 5 {
                    pollTask = nil
                    step = .failed(
                        title: "The link has expired",
                        message: "Select “Add a device…” on your Mac again to make a new code.")
                    return
                }
            } catch {
                guard !Task.isCancelled else { return }
                pollTask = nil
                fail(error)
                return
            }
        }
    }

    /// The seconds until the link ends, for the waiting screen.
    func secondsLeft(_ join: JoinInfo, at date: Date) -> Int {
        max(0, Int(TimeInterval(join.expiresAt) - date.timeIntervalSince1970))
    }

    // MARK: The passphrase

    /// Open the copy. A wrong passphrase keeps the download: the owner tries again.
    func finish(passphrase: String) async {
        guard case .passphrase = step, !isWorking else { return }
        guard !passphrase.isEmpty else {
            passphraseMessage = "Type the passphrase."
            return
        }
        isWorking = true
        defer { isWorking = false }
        do {
            let vault = try await service.joinFinish(passphrase: passphrase)
            // The core selects and unlocks the new vault. When the app went away meanwhile, it
            // must not stay open in the background: the lock screen shows after Continue.
            if isAway() { try? await service.lock() }
            passphraseMessage = nil
            if biometry != .none {
                openedWith = passphrase
                step = .faceID(vault)
            } else {
                step = .done(vault)
            }
        } catch let error as VaultError where error.code == .wrongPassphrase || error.code == .invalidInput {
            passphraseMessage = error.message
        } catch {
            fail(error)
        }
    }

    // MARK: Face ID

    /// Store the passphrase behind Face ID for the lock screen.
    func turnOnFaceID() {
        guard case .faceID(let vault) = step else { return }
        if let passphrase = openedWith {
            do {
                try passphraseStore.save(passphrase, vaultID: vault.id)
                settings.setFaceIDUnlock(true, vaultID: vault.id)
            } catch {
                passphraseMessage = error.localizedDescription
            }
        }
        openedWith = nil
        step = .done(vault)
    }

    func notNow() {
        guard case .faceID(let vault) = step else { return }
        openedWith = nil
        step = .done(vault)
    }

    /// The owner selects Continue on the last screen.
    func complete() {
        guard case .done(let vault) = step else { return }
        onFinished(vault)
    }

    // MARK: Ending

    /// Leave the flow. A join that waits is cancelled on the relay.
    func cancel() async {
        stopPolling()
        openedWith = nil
        switch step {
        case .waiting, .passphrase, .starting:
            try? await service.joinCancel()
        default:
            break
        }
        onCancel()
    }

    /// After a failure: scan a new code.
    func startAgain() {
        stopPolling()
        scanNote = nil
        waitNote = nil
        step = .scan
    }

    private func fail(_ error: any Error) {
        stopPolling()
        let message = error.localizedDescription
        let title: String
        switch (error as? VaultError)?.code {
        case .linkInvalid?: title = "This code does not work"
        case .joinRefused?: title = "The Mac did not add this iPhone"
        case .safetyMismatch?: title = "The words do not match"
        case .relayUnreachable?: title = "The relay does not answer"
        case .unsupportedSchema?: title = "Update Apassy"
        default: title = "This iPhone was not added"
        }
        step = .failed(title: title, message: message)
    }
}
