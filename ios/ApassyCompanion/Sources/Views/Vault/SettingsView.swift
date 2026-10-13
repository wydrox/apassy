import ApassyVaultKit
import SwiftUI

/// Settings: General, Devices, Security, and Advanced, the four groups of the Mac Settings window
/// (ADR 0026 §3 and §8). Each group is a page of its own; the root shows the groups and the state
/// of the devices.
struct SettingsView: View {
    /// A group page of Settings.
    enum Page: String, Hashable {
        case general
        case devices
        case security
        case advanced
    }

    @Environment(RootModel.self) private var root
    @Environment(\.dismiss) private var dismiss
    @State private var path: [Page] = []

    var body: some View {
        NavigationStack(path: $path) {
            Form {
                Section {
                    NavigationLink(value: Page.general) {
                        SettingsGroupRow(
                            title: "General", detail: "Vault, import, AutoFill", symbol: "gearshape.fill", tint: .gray)
                    }
                    NavigationLink(value: Page.devices) {
                        SettingsGroupRow(
                            title: "Devices", detail: "Questions go to every device", symbol: "laptopcomputer",
                            tint: .blue)
                    }
                    NavigationLink(value: Page.security) {
                        SettingsGroupRow(
                            title: "Security", detail: "Face ID, auto-lock, clipboard", symbol: "lock.fill",
                            tint: .green)
                    }
                    NavigationLink(value: Page.advanced) {
                        SettingsGroupRow(
                            title: "Advanced", detail: "Version, licenses", symbol: "slider.horizontal.3",
                            tint: .indigo)
                    }
                }
                Section {
                    ThisIPhoneRow()
                    VaultSyncRow()
                    if let vault = root.vault, vault.hasVault, vault.isUnlocked, vault.vault?.syncs == true {
                        LabeledContent("Sync") {
                            Text(vault.syncStatus?.message ?? "Not synced yet")
                                .multilineTextAlignment(.trailing)
                        }
                    }
                } header: {
                    Text("Devices")
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .navigationDestination(for: Page.self) { group in
                switch group {
                case .general: GeneralSettingsView(close: dismiss)
                case .devices: DevicesSettingsView(close: dismiss)
                case .security: SecuritySettingsView(close: dismiss)
                case .advanced: AdvancedSettingsView()
                }
            }
        }
        #if targetEnvironment(simulator)
            .task { openFromLaunchArgument() }
        #endif
    }

    #if targetEnvironment(simulator)
        /// `-ApassyOpen settings:general|devices|security|advanced`: a group page of Settings.
        private func openFromLaunchArgument() {
            guard let route = UserDefaults.standard.string(forKey: "ApassyOpen"),
                route.hasPrefix("settings:"),
                let name = route.dropFirst("settings:".count).split(separator: ":").first,
                let group = Page(rawValue: String(name))
            else { return }
            path = [group]
        }
    #endif
}

/// A group on the Settings root: its symbol in a colored square, its name, and what it holds.
private struct SettingsGroupRow: View {
    let title: String
    let detail: String
    let symbol: String
    let tint: Color
    @ScaledMetric(relativeTo: .body) private var side: CGFloat = 30

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: side * 0.52, weight: .medium))
                .foregroundStyle(.white)
                .frame(width: side, height: side)
                .background(tint.gradient, in: .rect(cornerRadius: side * 0.27, style: .continuous))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// The devices of the relay team of the vault.
struct DevicesView: View {
    let vault: VaultModel
    @State private var devices: [RelayDevice]?
    @State private var error: String?

    var body: some View {
        Group {
            if let devices {
                List(devices) { device in
                    HStack(spacing: 12) {
                        Image(systemName: device.this ? "iphone" : "desktopcomputer")
                            .foregroundStyle(.tint)
                            .frame(width: 28)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(device.name)
                            if device.this {
                                Text("This iPhone")
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                            } else if let date = VaultText.date(device.lastSeenAt) {
                                Text("Seen \(date, format: .relative(presentation: .named))")
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
            } else if let error {
                ContentUnavailableView {
                    Label("The relay did not answer", systemImage: "wifi.exclamationmark")
                } description: {
                    Text(error)
                } actions: {
                    Button("Try again") { Task { await load() } }
                        .buttonStyle(.bordered)
                }
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Devices")
        .task { await load() }
        .refreshable { await load() }
    }

    private func load() async {
        do {
            devices = try await vault.devices()
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }
}
