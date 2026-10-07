import ApassyVaultKit
import SwiftUI

/// The sheet of the extension. Plain SwiftUI, no images: an extension has little memory.
struct AutoFillRootView: View {
    @Bindable var model: AutoFillModel

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Apassy")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    if model.screen != .configuration {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { model.cancel() }
                        }
                    }
                }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch model.screen {
        case .loading:
            ProgressView()
        case .message(let text):
            MessageView(text: text) { model.cancel() }
        case .unlock:
            UnlockView(model: model)
        case .list:
            CandidateListView(model: model)
        case .configuration:
            ConfigurationView { model.configured() }
        }
    }
}

/// No vault, or the vault did not open.
private struct MessageView: View {
    let text: String
    let close: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Text(text)
                .multilineTextAlignment(.center)
            Button("Close", action: close)
                .buttonStyle(.glassProminent)
        }
        .padding(32)
    }
}

/// The owner check: Face ID, or the passphrase.
private struct UnlockView: View {
    @Bindable var model: AutoFillModel
    @FocusState private var passphraseFocused: Bool

    var body: some View {
        Form {
            if model.canUseBiometry {
                Section {
                    Button {
                        Task { await model.unlockWithBiometry() }
                    } label: {
                        Label("Unlock with \(model.biometry.name)", systemImage: model.biometry.symbol)
                    }
                    .disabled(model.busy)
                }
            }
            Section {
                SecureField("Passphrase", text: $model.passphrase)
                    .focused($passphraseFocused)
                    .submitLabel(.go)
                    .onSubmit { Task { await model.unlockWithPassphrase() } }
                Button {
                    Task { await model.unlockWithPassphrase() }
                } label: {
                    HStack {
                        Text("Unlock")
                        if model.busy {
                            Spacer()
                            ProgressView()
                        }
                    }
                }
                .disabled(model.busy || model.passphrase.isEmpty)
            } header: {
                Text("Type the passphrase of “\(model.vaultName)”.")
                    .textCase(nil)
            } footer: {
                if let message = model.unlockMessage {
                    Text(message)
                        .foregroundStyle(.red)
                }
            }
        }
        .task {
            await model.autoUnlock()
            if model.screen == .unlock { passphraseFocused = true }
        }
    }
}

/// The logins of the vault: those of the website first.
private struct CandidateListView: View {
    @Bindable var model: AutoFillModel

    var body: some View {
        let matches = model.filtered(model.matches)
        let others = model.filtered(model.others)
        List {
            if let message = model.listMessage {
                Text(message)
                    .foregroundStyle(.red)
            }
            if let host = model.host {
                Section("Logins for \(host)") {
                    if matches.isEmpty {
                        Text("No login for this website.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(matches) { row($0) }
                }
            }
            Section("All logins") {
                if others.isEmpty {
                    Text(model.search.isEmpty ? emptyText : "No login matches.")
                        .foregroundStyle(.secondary)
                }
                ForEach(others) { row($0) }
            }
        }
        .searchable(text: $model.search, placement: .navigationBarDrawer(displayMode: .always))
        .disabled(model.busy)
    }

    private var emptyText: String {
        switch model.kind {
        case .password: "No other login in “\(model.vaultName)”."
        case .oneTimeCode: "No other login with a one-time password in “\(model.vaultName)”."
        }
    }

    private func row(_ candidate: FillCandidate) -> some View {
        Button {
            Task { await model.choose(candidate) }
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text(candidate.title)
                    .foregroundStyle(.primary)
                if !candidate.username.isEmpty {
                    Text(candidate.username)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                if let website = candidate.website {
                    Text(website)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityHint(model.kind == .oneTimeCode ? "Fills the one-time code." : "Fills this login.")
    }
}

/// After the owner turns Apassy on in Settings.
private struct ConfigurationView: View {
    let done: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Text("Apassy can now fill your logins. Open Apassy and unlock your vault once, so iPhone can suggest them.")
                .multilineTextAlignment(.center)
            Button("Done", action: done)
                .buttonStyle(.glassProminent)
        }
        .padding(32)
    }
}
