import ApassyVaultKit
import SwiftUI

/// No vault and no pairing yet: add the vault of the Mac, or only approve agent runs.
struct AppWelcomeView: View {
    @Environment(RootModel.self) private var root

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
                    Text("Apassy on your iPhone")
                        .font(.largeTitle.bold())
                        .multilineTextAlignment(.center)
                    Text(
                        "Your logins, API keys, SSH keys, and one-time passwords from the vault on your Mac, synced through the Apassy relay. Each secret shows only after Face ID."
                    )
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 14) {
                    WelcomePoint(
                        symbol: "lock.iphone", text: "The vault is encrypted on this iPhone with your passphrase.")
                    WelcomePoint(symbol: "key.fill", text: "Fill passwords in Safari and in apps with AutoFill.")
                    WelcomePoint(
                        symbol: "checkmark.seal.fill", text: "Approve the runs that wait for you on your Mac.")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } actions: {
            Button {
                root.addVault()
            } label: {
                Label("Add your vault", systemImage: "plus").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            Button {
                root.approveOnly()
            } label: {
                Text("Only approve agent runs").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
        }
        #if targetEnvironment(simulator)
            // A development aid: `-ApassyJoinLink <link>` goes on into the join flow.
            .task {
                if UserDefaults.standard.string(forKey: "ApassyJoinLink") != nil { root.addVault() }
            }
        #endif
    }
}

private struct WelcomePoint: View {
    let symbol: String
    let text: String

    var body: some View {
        Label {
            Text(text)
                .font(.callout)
        } icon: {
            Image(systemName: symbol)
                .foregroundStyle(.tint)
        }
    }
}
