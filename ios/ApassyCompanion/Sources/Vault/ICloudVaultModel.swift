import ApassyVaultKit
import Foundation
import Observation

/// An existing iCloud file opens in place. No relay join is started.
@MainActor
@Observable
final class ICloudVaultModel {
    enum Step: Equatable {
        case instructions
        case passphrase(URL)
        case faceID(VaultEntry)
        case done(VaultEntry)
        case cancelled
    }

    private(set) var step: Step = .instructions
    private(set) var message: String?
    private(set) var isWorking = false
    let biometry: Biometry
    @ObservationIgnored private let service: any VaultService
    @ObservationIgnored private let store: any PassphraseStore
    @ObservationIgnored private let settings: VaultSettings
    @ObservationIgnored private let isAway: @MainActor () -> Bool
    @ObservationIgnored private let onFinished: @MainActor (VaultEntry) -> Void
    @ObservationIgnored private let onCancel: @MainActor () -> Void
    @ObservationIgnored private var openedWith: String?
    @ObservationIgnored private var openedVault: VaultEntry?
    @ObservationIgnored private var operation: Task<Void, Never>?
    @ObservationIgnored private var ended = false
    @ObservationIgnored private var away = false
    @ObservationIgnored private var backgroundEpoch = 0

    init(service: any VaultService, passphraseStore: any PassphraseStore, settings: VaultSettings,
         biometry: Biometry, isAway: @escaping @MainActor () -> Bool = { false },
         onFinished: @escaping @MainActor (VaultEntry) -> Void, onCancel: @escaping @MainActor () -> Void) {
        self.service = service
        store = passphraseStore
        self.settings = settings
        self.biometry = biometry
        self.isAway = isAway
        self.onFinished = onFinished
        self.onCancel = onCancel
    }

    func selectFile(_ url: URL) {
        guard !isWorking, !ended, openedVault == nil else { return }
        guard url.pathExtension.lowercased() == "apassy" else {
            message = "Select an .apassy file in Files > iCloud Drive > Apassy."
            return
        }
        message = nil
        step = .passphrase(url)
    }

    func chooseAnotherFile() {
        guard !isWorking, !ended, openedVault == nil else { return }
        message = nil
        step = .instructions
    }

    func open(passphrase: String) async {
        guard case .passphrase(let url) = step, !isWorking, !ended, !away, !isAway() else { return }
        guard !passphrase.isEmpty else {
            message = "Type the passphrase."
            return
        }
        isWorking = true
        message = nil
        let epoch = backgroundEpoch
        let task = Task { [self] in
            defer { isWorking = false; operation = nil }
            do {
                let name = url.deletingPathExtension().lastPathComponent
                let entry = try await service.openICloudVault(url: url, name: name, passphrase: passphrase)
                openedVault = entry
                if ended || away || isAway() || backgroundEpoch != epoch {
                    try? await service.lock()
                    openedWith = nil
                    if !ended { step = .done(entry) }
                    return
                }
                if biometry != .none {
                    openedWith = passphrase
                    step = .faceID(entry)
                } else {
                    step = .done(entry)
                }
            } catch {
                guard !ended else { return }
                message = error.localizedDescription + " Select the file in Files > iCloud Drive > Apassy, then try again."
            }
        }
        operation = task
        await task.value
    }

    func turnOnFaceID() {
        guard case .faceID(let entry) = step, !ended, !away, !isAway() else { return }
        defer { openedWith = nil }
        guard let passphrase = openedWith else { return }
        do {
            try store.save(passphrase, vaultID: entry.id)
            settings.setFaceIDUnlock(true, vaultID: entry.id)
            step = .done(entry)
        } catch {
            message = error.localizedDescription
            step = .done(entry)
        }
    }

    func notNow() {
        guard case .faceID(let entry) = step, !ended else { return }
        openedWith = nil
        step = .done(entry)
    }

    func complete() {
        guard case .done(let entry) = step, !ended, !isWorking else { return }
        ended = true
        openedWith = nil
        onFinished(entry)
    }

    func cancel() async {
        guard !ended else { return }
        ended = true
        openedWith = nil
        step = .cancelled
        // Wait for key derivation to end before the root can resume another vault.
        await operation?.value
        if let entry = openedVault {
            try? await service.lock()
            // Imports reject existing IDs. Remove only this new local entry, never the cloud file.
            do {
                _ = try await service.removeVault(id: entry.id, force: true)
                store.remove(vaultID: entry.id)
                settings.forget(vaultID: entry.id)
                openedVault = nil
            } catch {
                message = "The vault is closed. Apassy could not remove its local copy. " + error.localizedDescription
                ended = false
                step = .done(entry)
                return
            }
        }
        onCancel()
    }

    func enterBackground() {
        away = true
        backgroundEpoch += 1
        openedWith = nil
        if case .faceID(let entry) = step { step = .done(entry) }
        if openedVault != nil {
            Task { try? await service.lock() }
        }
    }

    func enterForeground() { away = false }
}

/// Repair a missing or stale iCloud bookmark without importing another vault.
@MainActor
@Observable
final class ICloudReconnectModel {
    private(set) var isWorking = false
    private(set) var message: String?
    @ObservationIgnored private let service: any VaultService
    @ObservationIgnored private let vaultID: String

    init(service: any VaultService, vaultID: String) {
        self.service = service
        self.vaultID = vaultID
    }

    func reconnect(_ url: URL) async -> Bool {
        guard !isWorking else { return false }
        isWorking = true
        defer { isWorking = false }
        do {
            try await service.reconnectICloudVault(url: url, vaultID: vaultID)
            message = nil
            return true
        } catch {
            message = error.localizedDescription + " Select the same vault file in Files > iCloud Drive > Apassy."
            return false
        }
    }
}
