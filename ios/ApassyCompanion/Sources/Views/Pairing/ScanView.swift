import SwiftUI

/// "Scan the code": the camera, or the reason why the camera cannot be used.
struct ScanView: View {
    let model: PairingModel

    var body: some View {
        PairingScreen {
            VStack(spacing: 20) {
                PairingHero(
                    symbol: "qrcode.viewfinder", title: "Scan the code",
                    message: "Point the camera at the QR code that Apassy shows on your Mac.")
                CodeScannerPanel(accessibilityLabel: "Camera for the pairing code", use: "to read the pairing code") {
                    model.handleScan($0)
                }
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
    }
}
