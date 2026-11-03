import ApassyVaultKit
import SwiftUI

/// No vault and no pairing yet: add the vault of the Mac, only approve agent runs, or try the demo.
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
                        "Your vault holds logins, API keys, SSH keys, and one-time passwords. Sync it with your Mac through iCloud for free, or through the Apassy relay."
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
                root.addICloudVault()
            } label: {
                Label("iCloud · Free", systemImage: "icloud").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            Button {
                root.addVault()
                root.joinTeam()
            } label: {
                Label("From your Mac · Apassy relay", systemImage: "macbook.and.iphone").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
            Button {
                root.approveOnly()
            } label: {
                Text("Only approve agent runs").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
            // Try the app without a Mac: a vault of sample data in memory (`AppShell`).
            Button {
                root.tryDemo()
            } label: {
                Label("Try the Demo", systemImage: "theatermasks").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
            .accessibilityHint("Opens a vault of sample data. Nothing is saved.")
            .accessibilityIdentifier("welcome.tryDemo")
        }
        #if targetEnvironment(simulator)
            // A development aid: `-ApassyJoinLink <link>` goes on into the join flow.
            .task {
                if UserDefaults.standard.string(forKey: "ApassyJoinLink") != nil { root.addVault(); root.joinTeam() }
            }
        #endif
    }
}

private struct WelcomePoint: View {
    let symbol: String
    let text: String
    /// One width for every symbol, so the three texts start at the same x.
    @ScaledMetric(relativeTo: .callout) private var iconWidth: CGFloat = 28

    var body: some View {
        Label {
            Text(text)
                .font(.callout)
        } icon: {
            Image(systemName: symbol)
                .foregroundStyle(.tint)
                .frame(width: iconWidth)
        }
    }
}
