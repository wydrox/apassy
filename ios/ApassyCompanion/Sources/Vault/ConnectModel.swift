import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Observation

/// "Connect to your Mac" (flow spec I1 and I2, contract relay-connect-v1 section 7): scan or paste
/// the code of "Add a device" on the Mac, then go where the code says.
///
/// - `r=sync` (a paid plan), and an old code with no `r`: the relay join of `JoinModel` (name,
///   words, passphrase, Face ID).
/// - `r=connect` (Free): open the vault from iCloud Drive (file, passphrase, Face ID), then join
///   the notifications team of the Mac with that vault (name, words). The core keeps the relay key
///   in the vault, so the vault opens first (ADR 0027 §3). "Only on this Wi-Fi" pairs on the local
///   network instead, with the pairing link of the code.
/// - A pairing link of the local network: the pairing of `PairingModel`.
///
/// The parameters of a code are hints for the screens. The trust comes only from the safety words
/// and the owner check on the Mac.
@MainActor
@Observable
final class ConnectModel {
    /// The pairing on this Wi-Fi of the companion (`AppModel`).
    enum PairingAccess {
        case ready(PairingModel)
        /// This iPhone is paired with a Mac already.
        case paired
        /// The keychain refused to read the pairing.
        case unavailable(String)
    }

    enum Start {
        case scan
        case paste
        /// "Open your vault from iCloud Drive" in Settings, with no code.
        case openVault
    }

    enum Step {
        case scan
        case paste
        /// A Free Mac: open the vault from iCloud Drive, or approve only on this Wi-Fi (I2).
        case openVault
        /// The passphrase and Face ID of the iCloud file.
        case iCloud(ICloudVaultModel)
        /// The name of this iPhone, before the code goes to the relay.
        case name
        /// The code goes to the relay, then the Mac shows the same two words (`QuestionsModel.attach`).
        case words
        case connected(macName: String)
        /// A paid Mac, or an old code: the copy of the vault comes from the relay.
        case join(JoinModel)
        /// "Pair on this network", for a code without a pairing link.
        case pairHelp
        case pairing(PairingModel)
        case failed(title: String, message: String)

        /// One name per screen, for the animation between screens.
        var id: String {
            switch self {
            case .scan: "scan"
            case .paste: "paste"
            case .openVault: "openVault"
            case .iCloud: "iCloud"
            case .name: "name"
            case .words: "words"
            case .connected: "connected"
            case .join: "join"
            case .pairHelp: "pairHelp"
            case .pairing: "pairing"
            case .failed(let title, _): "failed-\(title)"
            }
        }
    }

    private(set) var step: Step
    /// The relay code that the owner scanned or pasted.
    private(set) var link: RelayConnectLink?
    /// Why the last scanned or pasted text was not used. The scanner keeps running.
    private(set) var note: String?
    var deviceName: String
    /// The vault that this flow opened from iCloud Drive. It stays on a cancel after it opened.
    private(set) var openedVault: VaultEntry?
    /// The vault on this iPhone joins the notifications team (Decisions and Settings > Devices).
    let attachesSelectedVault: Bool
    let biometry: Biometry

    @ObservationIgnored private let service: any VaultService
    @ObservationIgnored private let passphraseStore: any PassphraseStore
    @ObservationIgnored private let settings: VaultSettings
    @ObservationIgnored private let questions: QuestionsModel?
    @ObservationIgnored private let isAway: @MainActor () -> Bool
    @ObservationIgnored private let answerKey: (@Sendable () throws -> Data)?
    /// The pairing flow of the companion on this Wi-Fi, or why there is none.
    @ObservationIgnored private let pairing: @MainActor () -> PairingAccess
    @ObservationIgnored private let pollInterval: Duration
    @ObservationIgnored private let onFinished: @MainActor (VaultEntry?) -> Void
    @ObservationIgnored private let onCancel: @MainActor () -> Void
    /// Where Back of the pairing goes.
    @ObservationIgnored private var beforePairing: Step = .scan
    @ObservationIgnored private var ended = false

    init(
        start: Start = .scan, attachesSelectedVault: Bool = false, service: any VaultService,
        passphraseStore: any PassphraseStore, settings: VaultSettings, biometry: Biometry, deviceName: String,
        questions: QuestionsModel?, isAway: @escaping @MainActor () -> Bool = { false },
        answerKey: (@Sendable () throws -> Data)? = nil,
        pairing: @escaping @MainActor () -> PairingAccess = { .paired }, pollInterval: Duration = .seconds(2),
        onFinished: @escaping @MainActor (VaultEntry?) -> Void, onCancel: @escaping @MainActor () -> Void
    ) {
        switch start {
        case .scan: step = .scan
        case .paste: step = .paste
        case .openVault: step = .openVault
        }
        self.attachesSelectedVault = attachesSelectedVault
        self.service = service
        self.passphraseStore = passphraseStore
        self.settings = settings
        self.biometry = biometry
        self.deviceName = deviceName
        self.questions = questions
        self.isAway = isAway
        self.answerKey = answerKey
        self.pairing = pairing
        self.pollInterval = pollInterval
        self.onFinished = onFinished
        self.onCancel = onCancel
    }

    /// The name of the Mac for the screens: from the code, else "your Mac".
    var macName: String { link?.macName ?? "your Mac" }

    /// The connection that waits for the Mac, while the words show.
    var attach: QuestionsModel.AttachStep? { questions?.attach }

    // MARK: The code

    func showScanner() {
        guard !ended else { return }
        note = nil
        step = .scan
    }

    func showPaste() {
        guard !ended else { return }
        note = nil
        step = .paste
    }

    /// Text from the scanner or the paste box. Text that is not a code only sets a note.
    func handle(_ text: String) {
        switch step {
        case .scan, .paste: break
        default: return
        }
        let parsed: ConnectLink
        do {
            parsed = try ConnectLink.parse(text)
        } catch {
            note = error.localizedDescription
            return
        }
        note = nil
        switch parsed {
        case .pairing(let pairingLink):
            startPairing(pairingLink)
        case .relay(let relay):
            link = relay
            if attachesSelectedVault || openedVault != nil {
                // The vault is here: it joins the notifications team, whatever the route. A code of
                // an older Mac has no `r`.
                step = .name
            } else {
                switch relay.route {
                case .connect: step = .openVault
                case .sync: startJoin(relay)
                }
            }
        }
    }

    /// After a failure: scan a new code. A vault that this flow opened stays.
    func scanAgain() {
        guard !ended else { return }
        questions?.dismissAttach()
        link = nil
        note = nil
        step = .scan
    }

    // MARK: A paid Mac

    private func startJoin(_ relay: RelayConnectLink) {
        let join = JoinModel(
            service: service, passphraseStore: passphraseStore, settings: settings, biometry: biometry,
            deviceName: deviceName, pollInterval: pollInterval, isAway: isAway, answerKey: answerKey,
            onFinished: { [weak self] vault in self?.finish(vault) },
            onCancel: { [weak self] in self?.leave() })
        join.onStartAgain = { [weak self] in self?.scanAgain() }
        join.handleCode(relay.text)
        step = .join(join)
    }

    // MARK: A Free Mac: the vault from iCloud Drive

    /// The owner selected a file in "Open from iCloud Drive": the passphrase step.
    func openFile(_ url: URL) {
        guard case .openVault = step, !ended else { return }
        let model = ICloudVaultModel(
            service: service, passphraseStore: passphraseStore, settings: settings, biometry: biometry,
            isAway: isAway,
            onFinished: { [weak self] vault in self?.vaultOpened(vault) },
            onCancel: { [weak self] in self?.vaultCancelled() })
        // With a code, the words come next; without one, the screen says the vault is here.
        model.finishesAtOnce = link != nil
        model.selectFile(url)
        step = .iCloud(model)
    }

    private func vaultOpened(_ vault: VaultEntry) {
        openedVault = vault
        if link != nil {
            step = .name
        } else {
            finish(vault)
        }
    }

    /// Cancel in the iCloud steps removed the local copy: back to the choice, or out.
    private func vaultCancelled() {
        if link != nil {
            step = .openVault
        } else {
            leave()
        }
    }

    // MARK: The name and the words

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

    /// Send the code with the name of this iPhone, and wait for the Mac to confirm the words.
    func connect() async {
        guard case .name = step, deviceNameProblem == nil, let link, !ended else { return }
        guard let questions else {
            step = .failed(
                title: "This iPhone was not connected", message: "Apassy cannot reach the questions of this vault.")
            return
        }
        settings.deviceName = trimmedDeviceName
        step = .words
        await questions.startAttach(link: link.text, deviceName: trimmedDeviceName, pollInterval: pollInterval)
        await questions.attachFinished()
        guard case .words = step else { return }
        switch questions.attach {
        case .attached?:
            questions.dismissAttach()
            step = .connected(macName: macName)
        case .failed(let message)?:
            questions.dismissAttach()
            step = .failed(title: "This iPhone was not connected", message: message)
        default:
            break
        }
    }

    /// The seconds until the code ends, for the words screen.
    func secondsLeft(_ info: AttachInfo, at date: Date) -> Int {
        max(0, Int(TimeInterval(info.expiresAt) - date.timeIntervalSince1970))
    }

    // MARK: On this Wi-Fi

    /// "Only on this Wi-Fi": pair on the local network with the pairing link of the code, or say
    /// how to make one.
    func onlyOnThisWiFi() {
        guard case .openVault = step, !ended else { return }
        if let pairingLink = link?.pairingLink {
            startPairing(pairingLink)
        } else {
            step = .pairHelp
        }
    }

    /// "Scan the code" of "Pair on this network".
    func scanPairingCode() {
        guard case .pairHelp = step else { return }
        startPairing(nil)
    }

    /// Back from "Pair on this network" to the choice.
    func backToChoice() {
        guard case .pairHelp = step else { return }
        step = .openVault
    }

    private func startPairing(_ pairingLink: String?) {
        let model: PairingModel
        switch pairing() {
        case .ready(let ready):
            model = ready
        case .paired:
            step = .failed(
                title: "This iPhone is paired already",
                message:
                    "It approves for a Mac on this Wi-Fi. To pair it with another Mac, unpair it first in Settings > Devices > Pair on this network.")
            return
        case .unavailable(let message):
            step = .failed(title: "This iPhone cannot pair", message: message)
            return
        }
        beforePairing = step
        model.deviceName = TextRules.deviceName(from: deviceName, fallback: "iPhone")
        model.startScanning()
        if let pairingLink { model.handleScan(pairingLink) }
        step = .pairing(model)
    }

    /// The pairing went back to its start (Cancel or Back): back to where it began.
    func pairingLeft() {
        guard case .pairing = step else { return }
        step = beforePairing
    }

    /// The pairing ended and the owner selected Continue.
    func pairingFinished() {
        guard case .pairing = step else { return }
        finish(openedVault)
    }

    // MARK: Ending

    /// Continue on the last screen.
    func complete() {
        guard case .connected = step else { return }
        finish(openedVault)
    }

    /// Cancel on a screen of this flow. A connection that waits is cancelled on the relay; a vault
    /// that this flow opened stays on this iPhone.
    func cancel() async {
        guard !ended else { return }
        switch step {
        case .words:
            questions?.cancelAttach()
        case .iCloud(let model):
            // It removes a copy that it opened, then calls back.
            await model.cancel()
            return
        case .join(let model):
            await model.cancel()
            return
        default:
            break
        }
        if let openedVault {
            finish(openedVault)
        } else {
            leave()
        }
    }

    /// The app went to the background or came back: the iCloud steps lock the vault.
    func enterBackground() {
        if case .iCloud(let model) = step { model.enterBackground() }
    }

    func enterForeground() {
        if case .iCloud(let model) = step { model.enterForeground() }
    }

    private func finish(_ vault: VaultEntry?) {
        guard !ended else { return }
        ended = true
        onFinished(vault)
    }

    private func leave() {
        guard !ended else { return }
        ended = true
        onCancel()
    }
}
