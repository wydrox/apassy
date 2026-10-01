import ApassyCompanionKit
import Foundation
import Observation

/// The pairing flow: welcome, scan, connect, show the code, and wait for the owner to type it on
/// the Mac (contract section 5).
@MainActor
@Observable
final class PairingModel {
    enum Step: Equatable {
        case welcome
        case scan
        case connecting(macName: String)
        /// The code that the owner types on the Mac, and the end of the pairing window.
        case code(macName: String, code: String, expiresAt: Date)
        case paired(macName: String)
        /// The Mac closed the pairing: cancelled, or three wrong codes.
        case denied
        case expired
        /// The pairing could not start or could not finish.
        case failed(title: String, message: String)
    }

    var step: Step = .welcome
    /// The name that the Mac lists this iPhone under. The owner can edit it.
    var deviceName: String
    /// Why the last scanned code was not used. The scanner keeps running.
    private(set) var scanNote: String?
    /// A problem while waiting for the Mac, for example that it is not reachable. Polling goes on.
    private(set) var waitNote: String?
    /// Why the owner is here again, for example that the Mac removed this iPhone.
    private(set) var notice: String?
    let usesSecureEnclave = CompanionKeyStore.usesSecureEnclave

    private let store: any PairingStore
    private let pollInterval: Duration
    private let makeKeys: () throws -> any CompanionKeys
    private let makeClient: (PairingLink, any CompanionKeys) -> CompanionClient
    private let onPaired: @MainActor (PairingRecord, any CompanionKeys) -> Void
    private var task: Task<Void, Never>?
    private var finished: (record: PairingRecord, keys: any CompanionKeys)?

    init(
        store: any PairingStore,
        notice: String?,
        deviceName: String,
        pollInterval: Duration = .seconds(2),
        makeKeys: @escaping () throws -> any CompanionKeys = { try CompanionKeyStore.createNew() },
        makeClient: @escaping (PairingLink, any CompanionKeys) -> CompanionClient = { link, keys in
            CompanionClient(link: link, deviceID: DeviceID.random(), keys: keys)
        },
        onPaired: @escaping @MainActor (PairingRecord, any CompanionKeys) -> Void
    ) {
        self.store = store
        self.notice = notice
        self.deviceName = deviceName
        self.pollInterval = pollInterval
        self.makeKeys = makeKeys
        self.makeClient = makeClient
        self.onPaired = onPaired
    }

    /// The name as it goes to the Mac: no `White_Space` scalar at the start or the end.
    var trimmedDeviceName: String {
        TextRules.trimmed(deviceName)
    }

    /// Why the name cannot be used, or nil.
    var deviceNameProblem: String? {
        do {
            try CompanionClient.checkDeviceName(trimmedDeviceName)
            return nil
        } catch {
            return "Use 1 to 40 characters, with no control character."
        }
    }

    // MARK: Steps

    func startScanning() {
        guard deviceNameProblem == nil else { return }
        notice = nil
        scanNote = nil
        step = .scan
    }

    func backToWelcome() {
        cancel()
        step = .welcome
    }

    /// Cancel a pairing in progress, delete its keys, and scan again.
    func startAgain() {
        cancel()
        scanNote = nil
        step = .scan
    }

    /// A code came from the scanner. A code that is not a usable pairing link only sets a note.
    func handleScan(_ payload: String) {
        guard case .scan = step else { return }
        let link: PairingLink
        do {
            link = try PairingLink.parse(payload)
        } catch {
            scanNote = error.localizedDescription
            return
        }
        scanNote = nil
        waitNote = nil
        step = .connecting(macName: link.macName)
        task = Task { await pair(link) }
    }

    /// The owner selects Continue after the pairing worked.
    func finish() {
        guard let finished else { return }
        self.finished = nil
        onPaired(finished.record, finished.keys)
    }

    #if targetEnvironment(simulator)
        /// A development aid of the Simulator, which has no camera: launch the app with
        /// `-ApassyPairingLink <link>` and it pairs as if the code had been scanned. A device build
        /// has no such path.
        func startFromLaunchArgument() {
            guard case .welcome = step, deviceNameProblem == nil,
                let text = UserDefaults.standard.string(forKey: "ApassyPairingLink")
            else { return }
            step = .scan
            handleScan(text)
        }
    #endif

    // MARK: Pairing

    private func cancel() {
        task?.cancel()
        task = nil
        waitNote = nil
        deleteKeys()
    }

    /// The keys of a pairing that did not finish are of no use. They are deleted, so that no key
    /// of an unpaired iPhone stays behind.
    private func deleteKeys() {
        try? CompanionKeyStore.deleteAll()
    }

    private func pair(_ link: PairingLink) async {
        let keys: any CompanionKeys
        do {
            keys = try makeKeys()
        } catch {
            fail(title: "This iPhone cannot pair", message: Self.message(for: error))
            return
        }
        // A cancel that came while the keys were made has already deleted the keys of the flow
        // that it ended, before these existed.
        if Task.isCancelled {
            deleteKeys()
            return
        }
        let client = makeClient(link, keys)
        let start: PairingStart
        do {
            // This asks for Face ID once: the approval key signs the pair string.
            start = try await client.pair(link: link, deviceName: trimmedDeviceName)
        } catch is CancellationError {
            return
        } catch CompanionError.linkRejected {
            fail(title: "The Mac refused the link", message: CompanionError.linkRejected.errorDescription ?? "")
            return
        } catch CompanionError.linkExpired {
            fail(title: "The code has expired", message: CompanionError.linkExpired.errorDescription ?? "")
            return
        } catch {
            // The owner may have left while the request ran. The screen is not this flow's any more.
            if Task.isCancelled { return }
            fail(title: "Could not pair", message: Self.message(for: error))
            return
        }
        // The owner may have selected Cancel after the Mac answered and before this code ran. The
        // keys are deleted then, so there is nothing to show a code for and no polling to start.
        guard !Task.isCancelled else { return }
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(start.expiresAt))
        step = .code(macName: link.macName, code: start.code, expiresAt: expiresAt)
        await poll(client: client, keys: keys, expiresAt: expiresAt)
    }

    /// Ask the Mac every 2 s until it says paired, denied, or expired.
    private func poll(client: CompanionClient, keys: any CompanionKeys, expiresAt: Date) async {
        while !Task.isCancelled {
            try? await Task.sleep(for: pollInterval)
            if Task.isCancelled { return }
            do {
                switch try await client.pairStatus() {
                case .waiting:
                    waitNote = nil
                case .paired(let macName):
                    await complete(client: client, keys: keys, macName: macName)
                    return
                case .denied:
                    deleteKeys()
                    step = .denied
                    return
                case .expired:
                    deleteKeys()
                    step = .expired
                    return
                }
            } catch is CancellationError {
                return
            } catch {
                // The Mac may be busy or the network may drop for a moment. The window has its own
                // end, so the owner is not left waiting past it.
                waitNote = error.localizedDescription
                if Date() > expiresAt.addingTimeInterval(5) {
                    deleteKeys()
                    step = .expired
                    return
                }
            }
        }
    }

    private func complete(client: CompanionClient, keys: any CompanionKeys, macName: String) async {
        guard !Task.isCancelled else { return }
        let record = await client.pairingRecord(macName: macName)
        // A cancel must not save a record for keys that it deleted.
        guard !Task.isCancelled else { return }
        do {
            try store.save(record)
        } catch {
            deleteKeys()
            step = .failed(
                title: "The pairing could not be saved",
                message:
                    "The Mac paired with this iPhone, but the keychain refused to save it. \(error.localizedDescription) Remove this iPhone in Settings > iPhone companion in Apassy on your Mac, then pair again."
            )
            return
        }
        finished = (record, keys)
        step = .paired(macName: macName)
    }

    private func fail(title: String, message: String) {
        deleteKeys()
        step = .failed(title: title, message: message)
    }

    /// The text for an error while pairing. The key texts say "Nothing was approved", which is
    /// wrong here: at this point nothing is paired.
    static func message(for error: Error) -> String {
        guard let key = error as? CompanionKeyError else { return error.localizedDescription }
        switch key {
        case .cancelled:
            return "The Face ID check was cancelled. Nothing is paired."
        case .authenticationFailed:
            return "Face ID or Touch ID did not recognise you. Nothing is paired. Try again."
        case .biometryUnavailable:
            return "Face ID or Touch ID is not available now. Nothing is paired."
        case .lockedOut:
            return
                "Face ID or Touch ID is locked. Unlock the iPhone with its passcode, then try again. Nothing is paired."
        case .failed(let code):
            return "The key could not sign (code \(code)). Nothing is paired."
        default:
            return key.localizedDescription
        }
    }
}
