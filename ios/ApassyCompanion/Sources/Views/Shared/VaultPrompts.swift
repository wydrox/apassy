import ApassyVaultKit
import SwiftUI
import UIKit

/// The owner check of the vault, with the Face ID prompt marked as a system prompt of the app, so
/// the privacy cover does not blank the screen behind it (as `PromptTrackingKeys` does for an
/// approval).
struct PromptTrackingOwnerCheck: OwnerCheck {
    let inner: any OwnerCheck

    var biometry: Biometry { inner.biometry }

    func confirm(reason: String) async -> Bool {
        await PrivacyCover.shared.beginSystemPrompt()
        let allowed = await inner.confirm(reason: reason)
        await PrivacyCover.shared.endSystemPrompt()
        return allowed
    }
}

/// The passphrase store, with the Face ID prompt of a read marked as a system prompt of the app.
struct PromptTrackingPassphraseStore: PassphraseStore {
    let inner: any PassphraseStore

    func hasPassphrase(vaultID: String) -> Bool { inner.hasPassphrase(vaultID: vaultID) }

    func save(_ passphrase: String, vaultID: String) throws { try inner.save(passphrase, vaultID: vaultID) }

    func read(vaultID: String, reason: String) async throws -> String {
        await PrivacyCover.shared.beginSystemPrompt()
        do {
            let passphrase = try await inner.read(vaultID: vaultID, reason: reason)
            await PrivacyCover.shared.endSystemPrompt()
            return passphrase
        } catch {
            await PrivacyCover.shared.endSystemPrompt()
            throw error
        }
    }

    func remove(vaultID: String) { inner.remove(vaultID: vaultID) }
}

/// Time from iOS to finish a vault write after the app leaves the screen. iOS kills a suspended
/// app that holds a file lock in the App Group container, so a save, a sync, or the closing of the
/// vault asks for it.
@MainActor
enum BackgroundWork {
    static func begin(_ name: String) -> @MainActor () -> Void {
        let task = Box()
        task.id = UIApplication.shared.beginBackgroundTask(withName: name) {
            MainActor.assumeIsolated { task.end() }
        }
        return { task.end() }
    }

    @MainActor
    private final class Box {
        var id = UIBackgroundTaskIdentifier.invalid

        func end() {
            guard id != .invalid else { return }
            UIApplication.shared.endBackgroundTask(id)
            id = .invalid
        }
    }
}

// MARK: - Windows above the app

/// A window above the app and its sheets, for the passphrase prompt and the toast. The privacy
/// cover is above both.
@MainActor
private func makeOverlayWindow<Content: View>(level: UIWindow.Level, passthrough: Bool, content: Content) -> UIWindow? {
    guard
        let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene })
            .first(where: { $0.activationState == .foregroundActive })
            ?? UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first
    else { return nil }
    let window = passthrough ? PassthroughWindow(windowScene: scene) : UIWindow(windowScene: scene)
    window.windowLevel = level
    let host = UIHostingController(rootView: content)
    host.view.backgroundColor = .clear
    window.rootViewController = host
    window.backgroundColor = .clear
    return window
}

/// A window that lets touches through to the app below it.
private final class PassthroughWindow: UIWindow {
    override func hitTest(_ point: CGPoint, with event: UIEvent?) -> UIView? { nil }
}

/// The passphrase prompt of the owner check, when Face ID did not confirm. It is a window of its
/// own, so it shows above a sheet too.
@MainActor
final class OwnerPromptWindow {
    static let shared = OwnerPromptWindow()

    private var window: UIWindow?

    func update(_ gate: OwnerGate?) {
        if let gate, gate.prompt != nil {
            guard window == nil else { return }
            window = makeOverlayWindow(level: .alert, passthrough: false, content: OwnerPromptView(gate: gate))
            window?.makeKeyAndVisible()
        } else {
            guard let window else { return }
            window.isHidden = true
            self.window = nil
            window.windowScene?.windows.first { $0.windowLevel == .normal }?.makeKey()
        }
    }
}

/// "Type the passphrase" over a dimmed screen.
struct OwnerPromptView: View {
    let gate: OwnerGate
    @State private var passphrase = ""
    @FocusState private var focused: Bool

    var body: some View {
        ZStack {
            Color.black.opacity(0.35)
                .ignoresSafeArea()
                .accessibilityHidden(true)
            if let prompt = gate.prompt {
                card(prompt)
                    .padding(24)
            }
        }
        .onAppear { focused = true }
    }

    private func card(_ prompt: OwnerGate.Prompt) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Type the passphrase", systemImage: "lock.fill")
                .font(.headline)
            Text(prompt.reason)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            SecureField("Passphrase", text: $passphrase)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                .submitLabel(.done)
                .onSubmit(submit)
                .disabled(prompt.isChecking)
            if let message = prompt.message {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
            HStack(spacing: 12) {
                Button {
                    gate.cancel()
                } label: {
                    Text("Cancel").frame(maxWidth: .infinity)
                }
                .buttonStyle(.glass)
                Button(action: submit) {
                    Group {
                        if prompt.isChecking { ProgressView() } else { Text("Continue") }
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .disabled(prompt.isChecking)
            }
            .controlSize(.large)
        }
        .padding(20)
        .frame(maxWidth: 420)
        .glassEffect(.regular, in: .rect(cornerRadius: 28, style: .continuous))
        .accessibilityAddTraits(.isModal)
    }

    private func submit() {
        let typed = passphrase
        passphrase = ""
        Task { await gate.submit(typed) }
    }
}

/// A short note at the top of the screen, such as "Copied". Touches go through it.
@MainActor
@Observable
final class Toast {
    static let shared = Toast()

    private(set) var message: String?
    @ObservationIgnored private var window: UIWindow?
    @ObservationIgnored private var hideTask: Task<Void, Never>?

    func show(_ message: String) {
        self.message = message
        if window == nil {
            window = makeOverlayWindow(level: .alert - 1, passthrough: true, content: ToastView(toast: self))
            window?.isHidden = false
        }
        AccessibilityNotification.Announcement(message).post()
        hideTask?.cancel()
        hideTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1.8))
            guard !Task.isCancelled, let self else { return }
            self.message = nil
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled else { return }
            self.window?.isHidden = true
            self.window = nil
        }
    }
}

struct ToastView: View {
    let toast: Toast

    var body: some View {
        VStack {
            if let message = toast.message {
                Label(message, systemImage: "doc.on.doc.fill")
                    .font(.footnote.weight(.semibold))
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .glassEffect(.regular, in: .capsule)
                    .transition(.move(edge: .top).combined(with: .opacity))
            }
            Spacer()
        }
        .padding(.top, 8)
        .animation(.snappy, value: toast.message)
        .accessibilityHidden(true)
    }
}
