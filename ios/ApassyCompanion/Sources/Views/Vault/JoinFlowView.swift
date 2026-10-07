import ApassyCompanionKit
import ApassyVaultKit
import SwiftUI

/// Adding the vault of the Mac to this iPhone (`JoinModel`): one screen per step.
struct JoinFlowView: View {
    @Bindable var model: JoinModel
    @State private var passphrase = ""
    @FocusState private var focused: Bool

    var body: some View {
        ZStack {
            switch model.step {
            case .instructions: instructions
            case .scan: scan
            case .name: name
            case .starting: starting
            case .waiting(let join): waiting(join)
            case .passphrase(let team): passphraseStep(team)
            case .faceID: faceID
            case .done(let vault): done(vault)
            case .failed(let title, let message): failed(title, message)
            }
        }
        .animation(.snappy, value: model.step)
        #if targetEnvironment(simulator)
            .task { await startFromLaunchArgument() }
        #endif
    }

    // MARK: Steps

    private var instructions: some View {
        PairingScreen {
            VStack(spacing: 20) {
                PairingHero(
                    symbol: "macbook.and.iphone", title: "Add your vault",
                    message:
                        "On your Mac, open Apassy > Settings > General > Sync, and select “Add a device…”. The Mac shows a QR code.")
                if let note = model.scanNote {
                    CalloutView(symbol: "exclamationmark.triangle.fill", text: note)
                }
            }
        } actions: {
            Button {
                model.showScanner()
            } label: {
                Label("Scan the QR code", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            paste
            cancelButton
        }
    }

    private var scan: some View {
        PairingScreen {
            VStack(spacing: 20) {
                PairingHero(
                    symbol: "qrcode.viewfinder", title: "Scan the code",
                    message: "Point the camera at the QR code that Apassy shows on your Mac.")
                CodeScannerPanel(accessibilityLabel: "Camera for the code of the Mac", use: "to read the code of the Mac") {
                    model.handleCode($0)
                }
                if let note = model.scanNote {
                    CalloutView(symbol: "exclamationmark.triangle.fill", text: note)
                }
            }
        } actions: {
            paste
            Button {
                model.step = .instructions
            } label: {
                Text("Back").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
        }
    }

    private var name: some View {
        PairingScreen {
            VStack(spacing: 24) {
                PairingHero(
                    symbol: "iphone", title: "Name this iPhone",
                    message: "Your Mac and the relay list this iPhone under this name.")
                VStack(alignment: .leading, spacing: 6) {
                    TextField("Name of this iPhone", text: $model.deviceName)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.words)
                        .submitLabel(.continue)
                        .onSubmit { Task { await model.start() } }
                    if let problem = model.deviceNameProblem {
                        Text(problem)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    } else {
                        Text("iOS may give apps a generic name such as “iPhone”. Change it if you have more than one.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        } actions: {
            Button {
                Task { await model.start() }
            } label: {
                Text("Continue").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .disabled(model.deviceNameProblem != nil)
            cancelButton
        }
    }

    private var starting: some View {
        PairingScreen {
            VStack(spacing: 24) {
                ProgressView()
                    .controlSize(.extraLarge)
                PairingHero(symbol: "network", title: "Sending the code to the relay")
            }
        } actions: {
            cancelButton
        }
    }

    private func waiting(_ join: JoinInfo) -> some View {
        PairingScreen {
            VStack(spacing: 24) {
                Text("Check the two words")
                    .font(.title2.bold())
                    .multilineTextAlignment(.center)
                SafetyWords(words: join.words)
                Text(
                    "Your Mac shows the same two words. Confirm “\(model.trimmedDeviceName)” on the Mac only if they match."
                )
                .multilineTextAlignment(.center)
                VStack(spacing: 8) {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Waiting for your Mac")
                            .foregroundStyle(.secondary)
                    }
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text("The code works for \(WaitClock.text(model.secondsLeft(join, at: context.date))) more")
                            .font(.footnote.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    if let note = model.waitNote {
                        CalloutView(symbol: "wifi.exclamationmark", text: note)
                    }
                }
                Text("If the words differ, select Cancel here and on the Mac. Another device may have read the code.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        } actions: {
            cancelButton
        }
    }

    private func passphraseStep(_ team: String) -> some View {
        PairingScreen {
            VStack(spacing: 24) {
                PairingHero(
                    symbol: "key.fill", title: "Type the passphrase of “\(team)”",
                    message: "Your Mac added this iPhone. The passphrase opens the copy of the vault on this iPhone.")
                VStack(alignment: .leading, spacing: 6) {
                    SecureField("Passphrase", text: $passphrase)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.go)
                        .focused($focused)
                        .onSubmit(finish)
                        .disabled(model.isWorking)
                    if let message = model.passphraseMessage {
                        Text(message)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
        } actions: {
            Button(action: finish) {
                Group {
                    if model.isWorking { ProgressView() } else { Text("Open the vault") }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .disabled(model.isWorking || passphrase.isEmpty)
            cancelButton
        }
        .onAppear { focused = true }
    }

    private var faceID: some View {
        PairingScreen {
            PairingHero(
                symbol: model.biometry.symbol, title: "Unlock with \(model.biometry.name)?",
                message:
                    "Apassy keeps the passphrase in the keychain of this iPhone, behind \(model.biometry.name). Without it, you type the passphrase at each unlock. You can change this in Settings.")
        } actions: {
            Button {
                model.turnOnFaceID()
            } label: {
                Label("Unlock with \(model.biometry.name)", systemImage: model.biometry.symbol)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            Button {
                model.notNow()
            } label: {
                Text("Not now").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
        }
    }

    private func done(_ vault: VaultEntry) -> some View {
        PairingScreen {
            VStack(spacing: 20) {
                PairingHero(
                    symbol: "checkmark.seal.fill", tint: .green, title: "“\(vault.name)” is on this iPhone",
                    message: "Apassy syncs it with your Mac through the relay.")
                if let message = model.passphraseMessage {
                    CalloutView(symbol: "exclamationmark.triangle.fill", text: message)
                }
            }
        } actions: {
            Button {
                model.complete()
            } label: {
                Text("Continue").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
        }
        .sensoryFeedback(.success, trigger: vault.id)
    }

    private func failed(_ title: String, _ message: String) -> some View {
        PairingScreen {
            PairingHero(symbol: "exclamationmark.triangle.fill", tint: .orange, title: title, message: message)
        } actions: {
            Button {
                model.startAgain()
            } label: {
                Text("Scan a new code").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            cancelButton
        }
    }

    // MARK: Parts

    private var paste: some View {
        PasteButton(payloadType: String.self) { strings in
            model.handleCode(strings.first ?? "")
        }
        .buttonBorderShape(.capsule)
        .labelStyle(.titleAndIcon)
        .accessibilityHint("Pastes the link that the Mac shows under the QR code")
    }

    private var cancelButton: some View {
        Button {
            Task { await model.cancel() }
        } label: {
            Text("Cancel").frame(maxWidth: .infinity)
        }
        .buttonStyle(.glass)
    }

    private func finish() {
        let typed = passphrase
        guard !typed.isEmpty else { return }
        passphrase = ""
        Task { await model.finish(passphrase: typed) }
    }

    #if targetEnvironment(simulator)
        /// A development aid of the Simulator, which has no camera: launch with
        /// `-ApassyJoinLink <link>` and the flow goes on as if the code had been scanned.
        private func startFromLaunchArgument() async {
            guard case .instructions = model.step,
                let text = UserDefaults.standard.string(forKey: "ApassyJoinLink")
            else { return }
            model.handleCode(text)
            await model.start()
        }
    #endif
}

/// The two safety words, large.
struct SafetyWords: View {
    let words: [String]
    @ScaledMetric(relativeTo: .largeTitle) private var size: CGFloat = 40

    var body: some View {
        VStack(spacing: 4) {
            ForEach(Array(words.enumerated()), id: \.offset) { _, word in
                Text(word)
                    .font(.system(size: size, weight: .bold, design: .rounded))
                    .minimumScaleFactor(0.5)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 20)
        .frame(maxWidth: .infinity)
        .background(.tint.opacity(0.12), in: .rect(cornerRadius: 24, style: .continuous))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("The words: \(words.joined(separator: ", "))")
    }
}
