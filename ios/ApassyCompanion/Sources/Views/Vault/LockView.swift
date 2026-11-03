import ApassyVaultKit
import SwiftUI

/// The locked vault. With the passphrase stored behind Face ID, Face ID asks first, over the cover
/// of the app (the picture of the app switcher), so a return to the app shows no other screen
/// before the vault opens. The passphrase field shows only when Face ID did not open the vault, or
/// when Face ID unlock is off.
struct LockView: View {
    @Environment(VaultModel.self) private var vault
    @Environment(RootModel.self) private var root: RootModel?
    @Environment(\.scenePhase) private var scenePhase
    @State private var passphrase = ""
    @State private var prompted = false
    @FocusState private var focused: Bool

    private var offersFaceID: Bool { vault.faceIDUnlockOn && vault.hasStoredPassphrase }

    /// When the lock screen starts the Face ID try.
    private struct FaceIDTry: Equatable {
        let active: Bool
        let waits: Bool
    }

    var body: some View {
        ZStack {
            if vault.showsPassphraseField {
                passphraseScreen
                    .transition(.opacity)
            } else {
                LockCover(isUnlocking: vault.isUnlocking)
                    .transition(.opacity)
            }
        }
        .animation(.easeOut(duration: 0.2), value: vault.showsPassphraseField)
        // Face ID once each time the lock screen shows while the app is active (a prompt cannot
        // show in the background), and again after each return to the app.
        .onChange(of: FaceIDTry(active: scenePhase == .active, waits: vault.waitsForFaceIDTry), initial: true) {
            _, key in
            guard key.active, key.waits else { return }
            Task { await vault.unlockWithFaceIDFirst() }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { passphrase = "" }
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

    /// The passphrase, with "Unlock with Face ID" to try again.
    private var passphraseScreen: some View {
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
                    } else if root?.isDemo == true {
                        // The demo vault has a known passphrase: nothing in it is real.
                        Text("The passphrase of the demo is “\(DemoData.passphrase)”.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .accessibilityIdentifier("demo.passphraseHint")
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
        // The field shows because the passphrase is needed: the keyboard comes up with it, and
        // again when the app comes back to it.
        .task(id: scenePhase == .active) {
            if scenePhase == .active { focused = true }
        }
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
    }

    private func unlock() {
        let typed = passphrase
        guard !typed.isEmpty else { return }
        passphrase = ""
        Task { await vault.unlock(passphrase: typed) }
    }
}

/// The lock screen while Face ID asks by itself: the privacy cover, so the return to the app shows
/// the same picture as the app switcher until the vault opens, and a spinner while it opens.
private struct LockCover: View {
    let isUnlocking: Bool

    var body: some View {
        PrivacyCoverView()
            .overlay {
                if isUnlocking {
                    ProgressView()
                        .offset(y: 110)
                        .accessibilityLabel("Unlocking")
                }
            }
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
