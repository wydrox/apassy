import ApassyVaultKit
import SwiftUI

/// W: what this watch is connected to, and its removal (the one irreversible local action, so it
/// has a warning and a Cancel).
struct ThisWatchView: View {
    let model: WatchAppModel
    /// "Notifications on this watch" (push-gateway-v1 section 11); nil in previews.
    @Environment(WatchNotificationsModel.self) private var notifications: WatchNotificationsModel?
    @State private var confirmingRemove = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(verbatim: connected)
                }
                Section("Macs that can ask") {
                    if model.macs.isEmpty {
                        Text("None")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(model.macs.indices, id: \.self) { index in
                            Text(verbatim: model.macs[index])
                        }
                    }
                }
                Section {
                    Text("Allow once needs this watch unlocked on your wrist.")
                        .font(.footnote)
                }
                if let notifications {
                    Section {
                        Toggle(
                            "Notifications on this watch",
                            isOn: Binding(
                                get: { notifications.enabled },
                                set: { on in Task { await notifications.setEnabled(on) } })
                        )
                    } footer: {
                        if let footnote = notifications.footnote {
                            Text(verbatim: footnote)
                        }
                    }
                }
                Section {
                    Button("Remove This Watch", role: .destructive) { confirmingRemove = true }
                }
            }
            .navigationTitle("This watch")
            .confirmationDialog("Remove this watch?", isPresented: $confirmingRemove, titleVisibility: .visible) {
                Button("Remove", role: .destructive) { model.forget() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("It stops answering access requests. Also remove it on your Mac in Settings › Devices.")
            }
        }
        .task {
            await model.reloadStatus()
            await notifications?.refresh()
        }
    }

    private var connected: String {
        model.vaultName.map { "Connected to “\($0)”" } ?? "Connected"
    }
}

#Preview {
    WatchRootView(model: WatchPreview.model(.settings))
}
