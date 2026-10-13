import AVFoundation
import ApassyVaultKit
import SwiftUI

/// No vault and no pairing yet (flow spec I1): one door, "Connect to your Mac". The code of the
/// Mac decides what comes next (`ConnectModel`).
struct AppWelcomeView: View {
    @Environment(RootModel.self) private var root
    @Environment(\.openURL) private var openURL
    @Environment(\.scenePhase) private var scenePhase
    @State private var cameraDenied = false

    static let siteURL = URL(string: "https://apassy.wyderka.cc")!

    var body: some View {
        PairingScreen {
            VStack(spacing: 24) {
                Image("CoverIcon")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 96)
                    .clipShape(.rect(cornerRadius: 22, style: .continuous))
                    .accessibilityHidden(true)
                VStack(spacing: 12) {
                    Text("Approve your agents from anywhere")
                        .font(.largeTitle.bold())
                        .multilineTextAlignment(.center)
                    Text("On your Mac, open Apassy > Settings > Devices > Add a device. Then scan the code.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                }
                if cameraDenied {
                    VStack(spacing: 10) {
                        CalloutView(
                            symbol: "camera.fill", text: "Apassy needs the camera to scan the code. Or paste the link.")
                        Button("Open Settings") {
                            if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                        }
                        .buttonStyle(.bordered)
                    }
                }
            }
        } actions: {
            Button {
                root.connect(.scan)
            } label: {
                Label("Connect to your Mac", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            Button {
                root.connect(.paste)
            } label: {
                Text("Paste a link instead").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
            Link(destination: Self.siteURL) {
                Text("No Mac yet? Learn about Apassy")
                    .font(.footnote)
            }
            .padding(.top, 2)
        }
        .task(id: scenePhase) { cameraDenied = Self.cameraIsDenied() }
        #if targetEnvironment(simulator)
            // Development aids: `-ApassyJoinLink <link>` or `-ApassyConnectLink <link>` goes on into
            // the connect flow as if the code had been scanned; `-ApassyOpen connect|connect:paste`
            // opens it.
            .task {
                let defaults = UserDefaults.standard
                if defaults.string(forKey: "ApassyConnectLink") != nil || defaults.string(forKey: "ApassyJoinLink") != nil
                {
                    root.connect(.scan)
                } else if let route = defaults.string(forKey: "ApassyOpen"), route.hasPrefix("connect") {
                    root.connect(route == "connect:paste" ? .paste : .scan)
                }
            }
        #endif
    }

    /// The owner said no to the camera, or a profile forbids it.
    static func cameraIsDenied() -> Bool {
        #if targetEnvironment(simulator)
            // A development aid: `-ApassyPreviewCamera denied` shows the state of a refused camera.
            if UserDefaults.standard.string(forKey: "ApassyPreviewCamera") == "denied" { return true }
        #endif
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        return status == .denied || status == .restricted
    }
}
