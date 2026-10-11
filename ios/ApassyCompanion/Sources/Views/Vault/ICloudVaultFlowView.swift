import ApassyVaultKit
import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct AddVaultChoiceView: View {
    @Environment(RootModel.self) private var root

    var body: some View {
        PairingScreen {
            PairingHero(symbol: "externaldrive.badge.plus", title: "Add a vault",
                        message: "Use iCloud for your personal vault. Use the Apassy relay for a team vault.")
        } actions: {
            Button { root.addICloudVault() } label: {
                Label("iCloud · Personal · Free", systemImage: "icloud").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            Button { root.joinTeam() } label: {
                Label("Join a team · Apassy relay", systemImage: "person.2").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
            Button("Cancel") { root.cancelAddVault() }
                .buttonStyle(.glass)
        }
    }
}

struct ICloudVaultFlowView: View {
    @Bindable var model: ICloudVaultModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var showsPicker = false
    @State private var passphrase = ""

    var body: some View {
        PairingScreen {
            VStack(spacing: 24) {
                switch model.step {
                case .instructions:
                    PairingHero(symbol: "icloud", title: "Your personal vault in iCloud",
                        message: "Personal sync with iCloud is free. On your Mac, select iCloud Drive in Settings > General > Sync.")
                    Text("In Files, select iCloud Drive > Apassy > Personal.apassy. If you changed the filename, select that .apassy file.")
                        .multilineTextAlignment(.center)
                case .passphrase(let url):
                    PairingHero(symbol: "key.fill", title: "Open “\(url.deletingPathExtension().lastPathComponent)”",
                                message: "Type the passphrase that opens this vault on your Mac.")
                    SecureField("Passphrase", text: $passphrase)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .disabled(model.isWorking)
                        .onSubmit(open)
                case .faceID:
                    PairingHero(symbol: model.biometry.symbol, title: "Unlock with \(model.biometry.name)?",
                        message: "Apassy keeps the passphrase in the keychain of this iPhone. \(model.biometry.name) protects it. You can change this in Settings.")
                case .done(let entry):
                    PairingHero(symbol: "checkmark.seal.fill", tint: .green, title: "“\(entry.name)” is on this iPhone",
                                message: "Apassy syncs this vault through iCloud Drive.")
                case .cancelled:
                    ProgressView()
                }
                if let message = model.message {
                    CalloutView(symbol: "exclamationmark.triangle.fill", text: message)
                }
            }
        } actions: {
            switch model.step {
            case .instructions:
                Button("Select the iCloud vault file") { showsPicker = true }
                    .buttonStyle(.glassProminent)
                cancel
            case .passphrase:
                Button(action: open) {
                    if model.isWorking { ProgressView() } else { Text("Open the vault") }
                }
                .buttonStyle(.glassProminent)
                .disabled(model.isWorking || passphrase.isEmpty)
                Button("Select another file") {
                    passphrase = ""
                    model.chooseAnotherFile()
                    showsPicker = true
                }
                .buttonStyle(.glass)
                .disabled(model.isWorking)
                cancel
            case .faceID:
                Button("Unlock with \(model.biometry.name)") { model.turnOnFaceID() }
                    .buttonStyle(.glassProminent)
                Button("Not now") { model.notNow() }.buttonStyle(.glass)
                cancel
            case .done:
                Button("Continue") { model.complete() }.buttonStyle(.glassProminent)
                cancel
            case .cancelled:
                EmptyView()
            }
        }
        .sheet(isPresented: $showsPicker) {
            ICloudVaultFilePicker { url in
                showsPicker = false
                if let url { model.selectFile(url) }
            }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background {
                passphrase = ""
                showsPicker = false
            }
        }
        .onDisappear { passphrase = "" }
    }

    private var cancel: some View {
        Button("Cancel") {
            passphrase = ""
            Task { await model.cancel() }
        }
        .buttonStyle(.glass)
    }

    private func open() {
        let typed = passphrase
        passphrase = ""
        Task { await model.open(passphrase: typed) }
    }
}

/// Open the original provider file. SwiftUI's importer does not expose `asCopy`.
struct ICloudVaultFilePicker: UIViewControllerRepresentable {
    let onSelected: @MainActor (URL?) -> Void

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let type = UTType(exportedAs: "com.wydrox.apassy.vault", conformingTo: .data)
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [type], asCopy: false)
        picker.allowsMultipleSelection = false
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ controller: UIDocumentPickerViewController, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator(onSelected: onSelected) }

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onSelected: @MainActor (URL?) -> Void
        init(onSelected: @escaping @MainActor (URL?) -> Void) { self.onSelected = onSelected }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            onSelected(urls.first)
        }
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { onSelected(nil) }
    }
}
