import ApassyVaultKit
import Foundation
import Observation

/// The owner check before a secret leaves the vault for a human: a reveal, a copy, a one-time
/// code, or large type. Uses the app's Face ID window; when biometry fails or is unavailable,
/// asks for the passphrase, typed and checked by the core.
///
/// The passphrase prompt is `prompt`; the app shows it above every screen and calls `submit` or
/// `cancel`.
@MainActor
@Observable
final class OwnerGate {
    /// The passphrase prompt that waits for the owner.
    struct Prompt: Identifiable, Equatable {
        let id = UUID()
        /// What the owner is about to do, for example "Show the password of “GitHub”".
        let reason: String
        var message: String?
        var isChecking = false
    }

    private(set) var prompt: Prompt?
    /// True while a check runs, Face ID or the passphrase.
    private(set) var isChecking = false

    /// A line under the passphrase field: the demo tells its passphrase. Nil for a real vault.
    let passphraseHint: String?

    @ObservationIgnored private let check: any OwnerCheck
    @ObservationIgnored private let service: any VaultService
    @ObservationIgnored private var continuation: CheckedContinuation<Bool, Never>?

    init(check: any OwnerCheck, service: any VaultService, passphraseHint: String? = nil) {
        self.check = check
        self.service = service
        self.passphraseHint = passphraseHint
    }

    var biometry: Biometry { check.biometry }

    /// Ask the owner. True when Face ID matched or the passphrase was right. A second call while a
    /// check runs answers false at once: one action, one check.
    func confirm(reason: String) async -> Bool {
        guard !isChecking else { return false }
        isChecking = true
        defer { isChecking = false }
        if await check.confirm(reason: reason) { return true }
        return await withCheckedContinuation { continuation in
            self.continuation = continuation
            prompt = Prompt(reason: reason)
        }
    }

    /// The owner typed the passphrase. A wrong one keeps the prompt with a message.
    func submit(_ passphrase: String) async {
        guard var current = prompt, !current.isChecking else { return }
        guard !passphrase.isEmpty else {
            current.message = "Type the passphrase."
            prompt = current
            return
        }
        current.isChecking = true
        current.message = nil
        prompt = current
        let message: String?
        do {
            message = try await service.checkPassphrase(passphrase) ? nil : "The passphrase does not open this vault."
        } catch {
            message = error.localizedDescription
        }
        // The prompt may have been cancelled meanwhile (the app went to the background).
        guard prompt?.id == current.id else { return }
        if let message {
            current.isChecking = false
            current.message = message
            prompt = current
        } else {
            finish(true)
        }
    }

    /// The owner closed the prompt, or the app left the screen.
    func cancel() {
        finish(false)
    }

    private func finish(_ allowed: Bool) {
        prompt = nil
        let waiting = continuation
        continuation = nil
        waiting?.resume(returning: allowed)
    }
}
