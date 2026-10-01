import AVFoundation
import SwiftUI
import VisionKit

/// "Scan the code": the camera, or the reason why the camera cannot be used.
struct ScanView: View {
    let model: PairingModel
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.openURL) private var openURL
    @State private var availability = Availability.checking

    enum Availability: Equatable {
        case checking
        case ready
        /// No scanner: the device has no camera, or it is the Simulator.
        case unsupported
        case denied
        case restricted
        /// Supported and allowed, but not usable now.
        case unavailable
    }

    var body: some View {
        PairingScreen {
            VStack(spacing: 20) {
                PairingHero(
                    symbol: "qrcode.viewfinder", title: "Scan the code",
                    message: "Point the camera at the QR code that Apassy shows on your Mac.")
                scanner
                if let note = model.scanNote {
                    CalloutView(symbol: "exclamationmark.triangle.fill", text: note)
                }
            }
        } actions: {
            Button {
                model.backToWelcome()
            } label: {
                Text("Back").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
        }
        .task { await check() }
        .onChange(of: scenePhase) { _, phase in
            // The owner may come back from Settings with the camera allowed.
            if phase == .active { Task { await check() } }
        }
    }

    @ViewBuilder
    private var scanner: some View {
        switch availability {
        case .checking:
            ProgressView()
                .frame(maxWidth: .infinity, minHeight: 200)
        case .ready:
            QRScannerView(
                onCode: { model.handleScan($0) },
                onFailure: { availability = .unavailable }
            )
            .aspectRatio(1, contentMode: .fit)
            .clipShape(.rect(cornerRadius: 28, style: .continuous))
            .accessibilityLabel("Camera for the pairing code")
        case .unsupported:
            unavailableView(
                "The scanner is not available",
                "Apassy needs the camera to read the code from your Mac. This device has no camera that Apassy can use. The iOS Simulator has none.")
        case .denied:
            unavailableView(
                "Camera access is off",
                "Apassy uses the camera only to read the pairing code. Allow the camera for Apassy in Settings.",
                showsSettings: true)
        case .restricted:
            unavailableView(
                "The camera is restricted",
                "Camera access is restricted on this iPhone, for example by Screen Time or a profile. Apassy cannot read the code.")
        case .unavailable:
            unavailableView(
                "The camera is not available now",
                "Close other apps that use the camera, then come back to this screen.")
        }
    }

    private func unavailableView(_ title: String, _ message: String, showsSettings: Bool = false) -> some View {
        ContentUnavailableView {
            Label(title, systemImage: "camera.metering.unknown")
        } description: {
            Text(message)
        } actions: {
            if showsSettings {
                Button("Open Settings") {
                    if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private func check() async {
        guard DataScannerViewController.isSupported else {
            availability = .unsupported
            return
        }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .notDetermined:
            // The permission dialog makes the app inactive. It needs the screen behind it, so the
            // privacy cover waits until it is gone.
            PrivacyCover.shared.beginSystemPrompt()
            let allowed = await AVCaptureDevice.requestAccess(for: .video)
            PrivacyCover.shared.endSystemPrompt()
            availability = allowed ? (DataScannerViewController.isAvailable ? .ready : .unavailable) : .denied
        case .denied:
            availability = .denied
        case .restricted:
            availability = .restricted
        case .authorized:
            availability = DataScannerViewController.isAvailable ? .ready : .unavailable
        @unknown default:
            availability = .unavailable
        }
    }
}
