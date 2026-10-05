import ApassyCompanionKit
import SwiftUI

/// What the app does, that it never receives a secret, and the name of this iPhone.
struct WelcomeView: View {
    @Bindable var model: PairingModel

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
                    Text("Apassy")
                        .font(.largeTitle.bold())
                    Text(
                        "Approve the runs that wait for you on your Mac, with Face ID, from your iPhone. Apassy on your iPhone never receives a secret: it shows what an agent wants to run and sends your decision."
                    )
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                }
                if let notice = model.notice {
                    CalloutView(symbol: "info.circle.fill", tint: .accentColor, text: notice)
                }
                if !model.usesSecureEnclave {
                    CalloutView(
                        symbol: "exclamationmark.triangle.fill",
                        text: "Simulator: keys are not in the Secure Enclave. This build is for development only.")
                }
                deviceName
                Text(
                    "On your Mac, open Apassy, select Settings > iPhone companion, and select \"Pair an iPhone\". A code shows on the Mac."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            }
        } actions: {
            Button {
                model.startScanning()
            } label: {
                Label("Scan the code", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .disabled(model.deviceNameProblem != nil)
        }
    }

    private var deviceName: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Name of this iPhone")
                .font(.subheadline.weight(.semibold))
            TextField("Name of this iPhone", text: $model.deviceName)
                .textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(.words)
                .submitLabel(.done)
            if let problem = model.deviceNameProblem {
                Text(problem)
                    .font(.footnote)
                    .foregroundStyle(.red)
            } else {
                Text(
                    "Your Mac lists this iPhone under this name. iOS may give apps a generic name, so change it if you have more than one iPhone."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
        }
    }
}

#if DEBUG
    #Preview("Welcome") {
        WelcomeView(model: PairingModel(store: InMemoryPairingStore(), notice: nil, deviceName: "Test iPhone") { _, _ in })
    }

    #Preview("Welcome, with a notice") {
        WelcomeView(
            model: PairingModel(
                store: InMemoryPairingStore(),
                notice: "This iPhone is no longer paired with the Mac. Pair it again.",
                deviceName: "Test iPhone"
            ) { _, _ in })
    }
#endif
