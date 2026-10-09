import ApassyVaultKit
import AuthenticationServices
import Foundation
import Observation

/// Moving logins, one-time passwords, and passkeys between Apassy and another app with Apple's
/// credential exchange (iOS 26). The system shows its own screens, and the data goes from app to
/// app in memory: Apassy writes no file. Each import and each export starts with its own owner
/// check, before Apassy reads what the other app sent or reads keys out of the vault.
@available(iOS 26.0, macOS 26.0, *)
@MainActor
@Observable
final class CredentialExchangeModel {
    /// The system side, so the tests can pass their own.
    struct System {
        /// Read what another app sent (`ASCredentialImportManager.importCredentials(token:)`).
        var importCredentials: @MainActor (UUID) async throws -> ASExportedCredentialData
        /// Show the export sheet of the system; answers the format that the other app takes.
        var requestExport: @MainActor () async throws -> ASExportedCredentialData.FormatVersion
        /// Hand the data to the other app (`ASCredentialExportManager.exportCredentials`).
        var exportCredentials: @MainActor (ASExportedCredentialData) async throws -> Void
    }

    enum State: Equatable {
        case idle
        /// Another app sent its data; the owner imports it once the vault is open.
        case importWaiting
        case working(String)
        /// The owner picked the other app, then the vault locked (the sheet of the system can
        /// send Apassy to the background). Nothing was read from the vault. The owner unlocks
        /// it and continues; Apassy asks again before it reads the keys.
        case exportPaused
        case finished(String)
        case failed(String)
    }

    private(set) var state: State = .idle
    /// The token of the import that waits. It names the data in the system, not the data itself.
    @ObservationIgnored private var token: UUID?
    /// An export that waits for the unlock, bound to the vault that the owner chose it in. The
    /// owner picked the other app for this vault only: no other vault may take its place.
    private struct PendingExport: Equatable {
        var format: ASExportedCredentialData.FormatVersion
        var vaultID: String
    }

    @ObservationIgnored private var pending: PendingExport?
    @ObservationIgnored private let vault: VaultModel
    @ObservationIgnored private let system: System

    init(vault: VaultModel, system: System) {
        self.vault = vault
        self.system = system
    }

    var isWorking: Bool {
        if case .working = state { return true }
        return false
    }

    // MARK: Import

    /// iOS opened Apassy with `ASCredentialExchangeActivity` and its token.
    func receive(token: UUID) {
        guard !isWorking else { return }
        self.token = token
        state = .importWaiting
    }

    /// The import that waits, after the owner check: read the other app's data, save the logins,
    /// one-time passwords, and passkeys, and say what happened in counts.
    func importNow() async {
        guard let token, !isWorking else { return }
        guard vault.isUnlocked else {
            state = .failed("Unlock the vault first.")
            return
        }
        guard await vault.gate.confirm(reason: "Import logins and passkeys from another app") else { return }
        state = .working("Importing…")
        let data: ASExportedCredentialData
        do {
            data = try await system.importCredentials(token)
        } catch {
            self.token = nil
            state = Self.isCancel(error) ? .idle : .failed("Apassy could not read what the other app sent. Start the export there again.")
            return
        }
        self.token = nil
        let plan = CredentialExchangeImport.plan(data)
        let report = await CredentialExchangeImport.run(plan, service: vault.service)
        await vault.didImport()
        state = .finished(report.summary)
    }

    func cancelImport() {
        guard !isWorking else { return }
        token = nil
        state = .idle
    }

    // MARK: Export

    /// Hand every login, one-time password, and passkey to another app that the owner picks in
    /// the sheet of the system. The keys leave the vault only after the owner check and the pick,
    /// straight into the system call. When the vault locked during the pick, the export waits
    /// (`exportPaused`) and nothing is read. The same happens when another vault is open after the
    /// pick: the export belongs to the vault that the owner started it in.
    func export() async {
        guard !isWorking, vault.isUnlocked, let vaultID = vault.vault?.id else { return }
        guard await vault.gate.confirm(reason: "Export your logins and passkeys to another app") else { return }
        pending = nil
        state = .working("Waiting for the other app…")
        do {
            let format = try await system.requestExport()
            await handOver(format: format, vaultID: vaultID)
        } catch {
            fail(error)
        }
    }

    /// Whether the vault that is open now is the one that the paused export belongs to.
    private func isExportVaultOpen(_ vaultID: String) -> Bool {
        vault.isUnlocked && !vault.isSuspended && vault.vault?.id == vaultID
    }

    /// Whether `resumeExport` can run now: the vault of the export is open again. Another vault
    /// does not count.
    var canResumeExport: Bool {
        guard state == .exportPaused, let pending else { return false }
        return isExportVaultOpen(pending.vaultID)
    }

    /// The export waits, and a vault other than its own is selected. The owner opens the first
    /// vault again to go on, or cancels.
    var exportWaitsForAnotherVault: Bool {
        guard state == .exportPaused, let pending else { return false }
        return vault.vault?.id != pending.vaultID
    }

    /// Go on with the export that waited for the unlock. The owner check runs again before Apassy
    /// reads the keys, and the other app and the vault stay the ones the owner picked.
    func resumeExport() async {
        guard canResumeExport, let waiting = pending else { return }
        guard await vault.gate.confirm(reason: "Continue the export of your logins and passkeys") else { return }
        // The check took time. The vault and the export must be the same when it ends.
        guard state == .exportPaused, pending == waiting, isExportVaultOpen(waiting.vaultID) else { return }
        state = .working("Exporting…")
        await handOver(format: waiting.format, vaultID: waiting.vaultID)
    }

    /// Stop the export that waits.
    func cancelPausedExport() {
        guard state == .exportPaused else { return }
        pending = nil
        state = .idle
    }

    /// Read the data out of the vault and give it to the other app at once. Only the vault that
    /// the export belongs to can give data: before the read and after it, another vault ends in a
    /// pause, and the data that was read goes nowhere.
    private func handOver(format: ASExportedCredentialData.FormatVersion, vaultID: String) async {
        guard isExportVaultOpen(vaultID) else {
            pause(format, vaultID: vaultID)
            return
        }
        state = .working("Exporting…")
        do {
            let export = try await vault.service.credentialExport()
            guard isExportVaultOpen(vaultID) else {
                pause(format, vaultID: vaultID)
                return
            }
            let data = CredentialExchangeExport.data(export, vaultID: vaultID, formatVersion: format)
            let count = data.accounts.reduce(0) { $0 + $1.items.count }
            try await system.exportCredentials(data)
            pending = nil
            var message = "Exported \(count) \(count == 1 ? "login" : "logins")."
            if export.skipped > 0 {
                message += " \(export.skipped) other \(export.skipped == 1 ? "item stays" : "items stay") in Apassy only: the transfer takes logins."
            }
            state = .finished(message)
        } catch let error as VaultError where error.code == .locked {
            pause(format, vaultID: vaultID)
        } catch {
            fail(error)
        }
    }

    private func pause(_ format: ASExportedCredentialData.FormatVersion, vaultID: String) {
        pending = PendingExport(format: format, vaultID: vaultID)
        state = .exportPaused
    }

    private func fail(_ error: any Error) {
        pending = nil
        if Self.isCancel(error) {
            state = .idle
        } else {
            state = .failed((error as? VaultError)?.message ?? "The export did not finish. Nothing was changed in Apassy.")
        }
    }

    func dismiss() {
        guard !isWorking, state != .exportPaused else { return }
        state = token == nil ? .idle : .importWaiting
    }

    /// The owner closed the sheet of the system.
    static func isCancel(_ error: any Error) -> Bool {
        if error is CancellationError { return true }
        if let error = error as? ASAuthorizationError, error.code == .canceled { return true }
        let ns = error as NSError
        return ns.domain == ASAuthorizationError.errorDomain && ns.code == ASAuthorizationError.Code.canceled.rawValue
    }
}
