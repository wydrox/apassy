import SwiftUI

/// Settings > Advanced: the version of the app and of the vault core, the licenses, and the demo.
struct AdvancedSettingsView: View {
    @Environment(RootModel.self) private var root

    var body: some View {
        Form {
            Section {
                LabeledContent("Apassy", value: appVersion)
                if let info = root.vault?.info {
                    LabeledContent("Vault core", value: "\(info.version), schema \(info.schema)")
                }
                NavigationLink("Licenses") { LicensesView() }
            } header: {
                Text("About")
            } footer: {
                Text(
                    "The vault is encrypted on this iPhone with your passphrase. Apassy keeps no copy of the passphrase except behind Face ID, if you turn it on."
                )
            }
            Section {
                if root.isDemo {
                    Button("Leave Demo", systemImage: "xmark.circle") { root.leaveDemo() }
                } else {
                    Button("Try the Demo", systemImage: "theatermasks") { root.tryDemo() }
                        .accessibilityIdentifier("settings.tryDemo")
                }
            } footer: {
                Text(
                    root.isDemo
                        ? "You are in the demo. Leave it to go back; nothing of it is kept."
                        : "The demo opens a vault of sample data in memory. Your vaults stay as they are, and nothing of the demo is kept."
                )
            }
        }
        .navigationTitle("Advanced")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var appVersion: String {
        let short = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(short) (\(build))"
    }
}
