import ApassyCompanionKit
import ApassyVaultDemo
import ApassyVaultKit
import AuthenticationServices
import Observation
import SwiftUI
import UIKit

/// The two roots of the app: the vaults on this iPhone, and the demo while it runs ("Try the
/// Demo", `-ApassyDemo`). One shows at a time. The root of the real vaults keeps its state while
/// the demo shows, and the demo never touches it: leaving the demo drops every value of it and
/// shows the real root again, where it was.
@MainActor
@Observable
final class AppShell {
    let world: LiveAppWorld
    let live: RootModel
    /// The root of the demo, while it shows.
    private(set) var demo: RootModel?
    /// Bumped at each start of the demo, so its screens start fresh.
    private(set) var demoGeneration = 0
    /// The demo is being made: the cover shows, and the real root does not start meanwhile.
    private(set) var isOpeningDemo = false
    @ObservationIgnored private var opening: Task<Void, Never>?

    init() {
        let world = LiveAppWorld()
        self.world = world
        live = RootModel(world: world)
        live.onTryDemo = { [weak self] in self?.openDemo() }
        // `-ApassyDemo`, in every build: open the demo at launch (screenshots, App Review). The
        // vaults of this iPhone are not opened until the owner leaves the demo.
        if ProcessInfo.processInfo.arguments.contains("-ApassyDemo") { openDemo() }
    }

    /// The root that shows.
    var shown: RootModel { demo ?? live }

    /// Whether the vaults of this iPhone were opened in this launch (Face ID window, keychain).
    var liveStarted: Bool { live.vault != nil }

    /// Make a new demo, then show it.
    func openDemo() {
        guard demo == nil, opening == nil else { return }
        isOpeningDemo = true
        opening = Task { [weak self] in
            let session = await DemoSession.open(confirm: { reason in await DemoPrompt.confirm(reason) })
            guard let self else { return }
            let models = DemoAppSession(
                demo: session, world: world, ownerCheck: PromptTrackingOwnerCheck(inner: BiometricOwnerCheck()),
                confirm: { reason in await DemoPrompt.confirm(reason) }, canUseFaceID: { DemoFaceID.available },
                notAvailable: { Toast.shared.show(DemoAppSession.notAvailableText) })
            let root = RootModel(demo: models, world: world)
            root.onLeaveDemo = { [weak self] in self?.leaveDemo() }
            guard !Task.isCancelled else { return }
            demoGeneration += 1
            demo = root
            opening = nil
            isOpeningDemo = false
        }
    }

    /// Leave the demo: its root, its models, and its vault go. The first screen shows again.
    func leaveDemo() {
        opening?.cancel()
        opening = nil
        isOpeningDemo = false
        guard let demo else { return }
        demo.vault?.gate.cancel()
        demo.vault?.stopSync()
        self.demo = nil
        OwnerPromptWindow.shared.update(live.vault?.gate)
    }
}

/// The Face ID prompt of the demo, marked as a prompt of the app so the privacy cover stays off.
enum DemoPrompt {
    @MainActor
    static func confirm(_ reason: String) async -> Bool {
        PrivacyCover.shared.beginSystemPrompt()
        let allowed = await DemoFaceID.confirm(reason)
        PrivacyCover.shared.endSystemPrompt()
        return allowed
    }
}

/// The window content of the app: the root that shows, the scene phase for both roots, and the
/// banner of the demo.
struct AppShellView: View {
    let shell: AppShell
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            if let demo = shell.demo {
                RootView(root: demo)
                    .id("demo-\(shell.demoGeneration)")
            } else if shell.isOpeningDemo {
                // The cover, as at launch: the real root starts only when it shows.
                PrivacyCoverView()
            } else {
                RootView(root: shell.live)
                    .id("live")
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.protectedDataWillBecomeUnavailableNotification)) { _ in
            if shell.liveStarted { FaceIDWindow.app.end() }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.willTerminateNotification)) { _ in
            if shell.liveStarted { FaceIDWindow.app.end() }
        }
        // Another app exports to Apassy (Apple's credential exchange): always the real vaults.
        .onContinueUserActivity(ASCredentialExchangeActivity) { activity in
            shell.live.receiveCredentialExchange(activity)
        }
        // Both roots follow the phase: the real vault locks in the background while the demo shows.
        .onChange(of: scenePhase, initial: true) { _, phase in
            PrivacyCover.shared.setPhase(AppPhase(phase))
            shell.live.scenePhaseChanged(AppPhase(phase))
            shell.demo?.scenePhaseChanged(AppPhase(phase))
        }
    }
}

/// "Demo — sample data only" with "Leave Demo", above the screens of the demo and its sheets.
struct DemoBanner: View {
    let root: RootModel

    var body: some View {
        HStack(spacing: 12) {
            Label("Demo — sample data only", systemImage: "theatermasks.fill")
                .font(.footnote.weight(.semibold))
                .lineLimit(2)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button("Leave Demo") { root.leaveDemo() }
                .font(.footnote.weight(.semibold))
                .buttonStyle(.glassProminent)
                .accessibilityIdentifier("demo.leave")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(.bar)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("demo.banner")
    }
}

extension View {
    /// The banner of the demo at the top, when `root` is the demo.
    ///
    /// A stack, not `safeAreaInset`: the navigation bars of a `NavigationStack` (also inside a
    /// `TabView` and in a sheet) take their place from the safe area of the window, so an inset
    /// put the banner over their titles and Back, Close, and toolbar buttons. Below the banner the
    /// screens get a frame of their own, and their bars start under it. The banner's material
    /// still reaches up under the status bar.
    @ViewBuilder
    func demoBanner(_ root: RootModel?) -> some View {
        if let root, root.isDemo {
            VStack(spacing: 0) {
                DemoBanner(root: root)
                self.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        } else {
            self
        }
    }
}
