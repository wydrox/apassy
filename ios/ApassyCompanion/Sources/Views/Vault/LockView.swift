import ApassyVaultKit
import SwiftUI

/// The locked vault: Face ID when the passphrase is stored behind it, else the passphrase.
struct LockView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(\.scenePhase) private var scenePhase
    @State private var passphrase = ""
    @State private var prompted = false
    @FocusState private var focused: Bool

    private var offersFaceID: Bool { vault.faceIDUnlockOn && vault.hasStoredPassphrase }

    var body: some View {
        PairingScreen {
            VStack(spacing: 24) {
                Image("CoverIcon")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 88)
                    .clipShape(.rect(cornerRadius: 20, style: .continuous))
                    .accessibilityHidden(true)
                VStack(spacing: 6) {
                    Text(vault.vault?.name ?? "Apassy")
                        .font(.largeTitle.bold())
                        .multilineTextAlignment(.center)
                    Label("Locked", systemImage: "lock.fill")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                if vault.vaults.count > 1 { vaultPicker }
                VStack(alignment: .leading, spacing: 8) {
                    SecureField("Passphrase", text: $passphrase)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.go)
                        .focused($focused)
                        .onSubmit(unlock)
                        .disabled(vault.isUnlocking)
                    if let message = vault.unlockMessage {
                        Text(message)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    } else {
                        Text("Type the passphrase of “\(vault.vault?.name ?? "")”.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        } actions: {
            if offersFaceID {
                Button {
                    Task { await vault.unlockWithFaceID() }
                } label: {
                    Label("Unlock with \(vault.gate.biometry.name)", systemImage: vault.gate.biometry.symbol)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .disabled(vault.isUnlocking)
            }
            Button(action: unlock) {
                Group {
                    if vault.isUnlocking { ProgressView() } else { Text("Unlock") }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(offersFaceID ? AnyPrimitiveButtonStyle(.glass) : AnyPrimitiveButtonStyle(.glassProminent))
            .disabled(vault.isUnlocking || passphrase.isEmpty)
        }
        // Face ID once when the screen shows and the app is active (a prompt cannot show in the
        // background). A cancel leaves the passphrase field.
        .task(id: scenePhase == .active) {
            guard scenePhase == .active, !prompted, offersFaceID else { return }
            prompted = true
            await vault.unlockWithFaceID()
        }
        .onChange(of: vault.isUnlocked) { _, unlocked in
            if !unlocked { passphrase = "" }
        }
        #if targetEnvironment(simulator)
            // A development aid: `-ApassyUnlockPassphrase <synthetic passphrase>` unlocks once
            // at launch, where nobody types.
            .task {
                guard !prompted, let typed = UserDefaults.standard.string(forKey: "ApassyUnlockPassphrase")
                else { return }
                prompted = true
                await vault.unlock(passphrase: typed)
            }
        #endif
    }

    private var vaultPicker: some View {
        Picker(
            "Vault",
            selection: Binding(
                get: { vault.vault?.id ?? "" },
                set: { id in Task { await vault.select(vaultID: id) } })
        ) {
            ForEach(vault.vaults) { entry in
                Text(entry.name).tag(entry.id)
            }
        }
        .pickerStyle(.menu)
        .onChange(of: vault.vault?.id) { prompted = false }
    }

    private func unlock() {
        let typed = passphrase
        guard !typed.isEmpty else { return }
        passphrase = ""
        Task { await vault.unlock(passphrase: typed) }
    }
}

/// A button style chosen at run time.
struct AnyPrimitiveButtonStyle: PrimitiveButtonStyle {
    private let make: (Configuration) -> AnyView

    init<Style: PrimitiveButtonStyle>(_ style: Style) {
        make = { AnyView(style.makeBody(configuration: $0)) }
    }

    func makeBody(configuration: Configuration) -> some View {
        make(configuration)
    }
}
