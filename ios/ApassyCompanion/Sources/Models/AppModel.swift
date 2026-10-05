import ApassyCompanionKit
import Foundation
import Observation

/// Which part of the app shows: nothing yet, the pairing flow, or the main tabs.
@MainActor
@Observable
final class AppModel {
    enum Phase {
        case starting
        /// The keychain refused to give the pairing. The owner can try again.
        case loadFailed(String)
        case pairing(PairingModel)
        case paired(SessionModel)
    }

    private(set) var phase: Phase = .starting
    private let store: any PairingStore

    init(store: any PairingStore = KeychainPairingStore()) {
        self.store = store
    }

    /// Read the pairing and its keys, and show the tabs or the pairing flow.
    func start() {
        do {
            guard let record = try store.load() else {
                showPairing(notice: nil)
                return
            }
            guard let keys = try CompanionKeyStore.loadExisting() else {
                try store.delete()
                showPairing(notice: "The keys of the earlier pairing are gone from this iPhone. Pair it again.")
                return
            }
            phase = .paired(makeSession(record: record, keys: keys))
        } catch let error as CompanionKeyError where error.keyIsUnusable {
            // The keys cannot be used again. Deleting them is all the owner can do.
            try? store.delete()
            showPairing(notice: error.localizedDescription)
        } catch {
            phase = .loadFailed(error.localizedDescription)
        }
    }

    private func showPairing(notice: String?) {
        phase = .pairing(
            PairingModel(
                store: store, notice: notice, deviceName: DeviceName.current(),
                makeClient: { link, keys in
                    CompanionClient(link: link, deviceID: DeviceID.random(), keys: PromptTrackingKeys(inner: keys))
                },
                onPaired: { [weak self] record, keys in
                    guard let self else { return }
                    phase = .paired(makeSession(record: record, keys: keys))
                }))
    }

    private func makeSession(record: PairingRecord, keys: any CompanionKeys) -> SessionModel {
        SessionModel(
            record: record,
            mac: CompanionClient(record: record, keys: PromptTrackingKeys(inner: keys)),
            keysInSecureEnclave: keys.isSecureEnclave,
            store: store,
            onEnded: { [weak self] notice in self?.showPairing(notice: notice) })
    }
}
