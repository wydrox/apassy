import ApassyCompanionKit
import SwiftUI
import UIKit

/// Hides the app in the app switcher.
///
/// The cover is a window of its own above everything, so it also covers a sheet. It is opaque, so
/// no command shows through it.
///
/// The cover shows while the app is inactive or in the background (`CoverPolicy`), except that
/// the Face ID prompt of the app and the camera permission dialog do not cover: they make the app
/// inactive for a moment, and they need the screen behind them. Each of them calls
/// `beginSystemPrompt()` before it shows and `endSystemPrompt()` after. The local network dialog
/// of iOS cannot be tracked, so it may cover the app once, on the first connection.
@MainActor
final class PrivacyCover {
    static let shared = PrivacyCover()

    private var windows: [UIWindow] = []
    private var phase = AppPhase.active
    private var systemPromptDepth = 0

    func setPhase(_ phase: AppPhase) {
        self.phase = phase
        update()
    }

    func beginSystemPrompt() {
        systemPromptDepth += 1
        update()
    }

    func endSystemPrompt() {
        systemPromptDepth = max(0, systemPromptDepth - 1)
        update()
    }

    private func update() {
        if CoverPolicy.isCovered(phase: phase, systemPromptDepth: systemPromptDepth) { show() } else { hide() }
    }

    private func show() {
        guard windows.isEmpty else { return }
        for scene in UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }) {
            let window = UIWindow(windowScene: scene)
            window.windowLevel = .alert + 1
            window.rootViewController = UIHostingController(rootView: PrivacyCoverView())
            window.isHidden = false
            windows.append(window)
        }
    }

    private func hide() {
        for window in windows { window.isHidden = true }
        windows.removeAll()
    }
}

extension AppPhase {
    init(_ phase: ScenePhase) {
        switch phase {
        case .active: self = .active
        case .inactive: self = .inactive
        case .background: self = .background
        @unknown default: self = .background
        }
    }
}

/// The keys of the app, with the Face ID prompt marked as a system prompt of the app, so the
/// privacy cover does not blank the screen behind it. Only the prompt is marked, not the network
/// call after it.
struct PromptTrackingKeys: CompanionKeys {
    let inner: any CompanionKeys

    var requestPublicKey: Data { inner.requestPublicKey }
    var approvalPublicKey: Data { inner.approvalPublicKey }
    var isSecureEnclave: Bool { inner.isSecureEnclave }

    func signRequest(_ message: Data) throws -> Data {
        try inner.signRequest(message)
    }

    func signApproval(_ message: Data, reason: String) async throws -> Data {
        await PrivacyCover.shared.beginSystemPrompt()
        do {
            let signature = try await inner.signApproval(message, reason: reason)
            await PrivacyCover.shared.endSystemPrompt()
            return signature
        } catch {
            await PrivacyCover.shared.endSystemPrompt()
            throw error
        }
    }
}

/// What the app switcher shows: the icon of the app and nothing else.
struct PrivacyCoverView: View {
    var body: some View {
        ZStack {
            Color(uiColor: .systemBackground)
            Image("CoverIcon")
                .resizable()
                .scaledToFit()
                .frame(width: 120)
                .clipShape(.rect(cornerRadius: 27, style: .continuous))
                .accessibilityLabel("Apassy")
        }
        .ignoresSafeArea()
    }
}

#if DEBUG
    #Preview {
        PrivacyCoverView()
    }
#endif
