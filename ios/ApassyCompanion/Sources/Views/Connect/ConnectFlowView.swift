import ApassyCompanionKit
import ApassyVaultKit
import SwiftUI

/// "Connect to your Mac" (`ConnectModel`, flow spec I1 and I2): one screen per step. The relay
/// join, the iCloud file, and the pairing on this Wi-Fi show their own screens.
struct ConnectFlowView: View {
    @Bindable var model: ConnectModel
    @Environment(RootModel.self) private var root
    @Environment(\.scenePhase) private var scenePhase
    @State private var pasted = ""
    @State private var showsPicker = false
    @State private var celebrated = false
    @FocusState private var nameFocused: Bool

    var body: some View {
        ZStack {
            switch model.step {
            case .scan: scan
            case .paste: paste
            case .openVault: openVault
            case .iCloud(let iCloud): ICloudVaultFlowView(model: iCloud)
            case .name: name
            case .words: words
            case .connected(let vaultName): connected(vaultName)
            case .join(let join): JoinFlowView(model: join)
            case .pairHelp: pairHelp
            case .pairing(let pairing):
                PairingFlowView(model: pairing)
                    .onChange(of: pairing.step) { _, step in
                        if step == .welcome { model.pairingLeft() }
                    }
            case .failed(let title, let message): failed(title, message)
            }
        }
        .animation(.snappy, value: model.step.id)
        .sheet(isPresented: $showsPicker) {
            ICloudVaultFilePicker { url in
                showsPicker = false
                if let url { model.openFile(url) }
            }
        }
        // The pairing ended with Continue: the companion is paired now.
        .onChange(of: root.companionIsPaired) { _, paired in
            if paired { model.pairingFinished() }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background {
                pasted = ""
                showsPicker = false
            }
        }
        #if targetEnvironment(simulator)
            .task { startFromLaunchArgument() }
            .task(id: launchStepKey) { await goOnFromLaunchArgument() }
        #endif
    }

    // MARK: The code

    private var scan: some View {
        PairingScreen {
            VStack(spacing: 20) {
                PairingHero(
                    symbol: "qrcode.viewfinder", title: "Scan the code",
                    message: "On your Mac, open Apassy > Settings > Devices > Add a device. Point the camera at the code.")
                CodeScannerPanel(accessibilityLabel: "Camera for the code of your Mac", use: "to read the code of your Mac")
                {
                    model.handle($0)
                }
                if let note = model.note {
                    CalloutView(symbol: "exclamationmark.triangle.fill", text: note)
                }
            }
        } actions: {
            Button {
                model.showPaste()
            } label: {
                Text("Paste a link instead").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
            cancelButton
        }
    }

    private var paste: some View {
        PairingScreen {
            VStack(spacing: 20) {
                PairingHero(
                    symbol: "link", title: "Paste the link",
                    message: "On your Mac, open Apassy > Settings > Devices > Add a device, and select Copy link under the code.")
                VStack(alignment: .leading, spacing: 10) {
                    TextField("The link of your Mac", text: $pasted, axis: .vertical)
                        .font(.callout.monospaced())
                        .lineLimit(2...5)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.continue)
                        .onSubmit { model.handle(pasted) }
                    PasteButton(payloadType: String.self) { strings in
                        let text = strings.first ?? ""
                        pasted = text
                        model.handle(text)
                    }
                    .buttonBorderShape(.capsule)
                    .labelStyle(.titleAndIcon)
                    .accessibilityHint("Pastes the link that the Mac shows under the code")
                }
                if let note = model.note {
                    CalloutView(symbol: "exclamationmark.triangle.fill", text: note)
                }
            }
        } actions: {
            Button {
                model.handle(pasted)
            } label: {
                Text("Continue").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            Button {
                pasted = ""
                model.showScanner()
            } label: {
                Text("Scan the code instead").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
            cancelButton
        }
    }

    // MARK: A Free Mac (I2)

    private var openVault: some View {
        PairingScreen {
            VStack(spacing: 20) {
                if model.link == nil {
                    PairingHero(
                        symbol: "icloud", title: "Open your vault from iCloud Drive",
                        message: "Select the file of your vault, then type its passphrase.")
                } else {
                    PairingHero(
                        symbol: "macbook.and.iphone", title: "Connect to your Mac",
                        message:
                            "One more step: open your vault from iCloud Drive, so this iPhone can approve away from your Wi-Fi.")
                    codeFromLine
                }
                CalloutView(
                    symbol: "folder.fill", tint: .accentColor,
                    text: "In Files, select iCloud Drive > Apassy, then the .apassy file of your vault.")
                if model.link != nil {
                    Text(
                        "Only on this Wi-Fi: this iPhone approves while it is on the same Wi-Fi as your Mac. Open the vault later in Settings > Devices."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                }
            }
        } actions: {
            Button {
                showsPicker = true
            } label: {
                Label("Open from iCloud Drive", systemImage: "icloud").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            if model.link != nil {
                Button {
                    model.onlyOnThisWiFi()
                } label: {
                    Label("Only on this Wi-Fi", systemImage: "wifi").frame(maxWidth: .infinity)
                }
                .buttonStyle(.glass)
            }
            cancelButton
        }
    }

    private var pairHelp: some View {
        PairingScreen {
            PairingHero(
                symbol: "wifi", title: "Pair on this network",
                message:
                    "This iPhone approves while it is on the same Wi-Fi as your Mac. On your Mac, open Apassy > Settings > Devices > Pair on this network. Then scan the code.")
        } actions: {
            Button {
                model.scanPairingCode()
            } label: {
                Label("Scan the code", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            Button {
                model.backToChoice()
            } label: {
                Text("Back").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
        }
    }

    // MARK: The name and the words

    private var name: some View {
        PairingScreen {
            VStack(spacing: 24) {
                PairingHero(
                    symbol: "iphone", title: "Name this iPhone",
                    message: "The Mac that made the code lists this iPhone under this name.")
                codeFromLine
                VStack(alignment: .leading, spacing: 6) {
                    TextField("Name of this iPhone", text: $model.deviceName)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.words)
                        .submitLabel(.continue)
                        .focused($nameFocused)
                        .onSubmit { Task { await model.connect() } }
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
                Task { await model.connect() }
            } label: {
                Text("Continue").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            .disabled(model.deviceNameProblem != nil)
            cancelButton
        }
    }

    @ViewBuilder
    private var words: some View {
        if case .waiting(let info)? = model.attach {
            PairingScreen {
                VStack(spacing: 24) {
                    Text("Check the two words")
                        .font(.title2.bold())
                        .multilineTextAlignment(.center)
                    SafetyWords(words: info.words)
                    Text("The Mac that made this code shows the same two words. Confirm there only if they match.")
                        .multilineTextAlignment(.center)
                    codeFromLine
                    VStack(spacing: 8) {
                        HStack(spacing: 10) {
                            ProgressView()
                            Text("Waiting for your Mac")
                                .foregroundStyle(.secondary)
                        }
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            Text("The code works for \(WaitClock.text(model.secondsLeft(info, at: context.date))) more")
                                .font(.footnote.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                    }
                    Text(
                        model.openedVault == nil
                            ? "If the words differ, select Cancel here and on the Mac. Another device may have read the code."
                            : "If the words differ, select Cancel here and on the Mac. Your vault stays on this iPhone."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                }
            } actions: {
                cancelButton
            }
        } else {
            PairingScreen {
                VStack(spacing: 24) {
                    ProgressView()
                        .controlSize(.extraLarge)
                    PairingHero(symbol: "network", title: "Connecting…")
                    codeFromLine
                }
            } actions: {
                cancelButton
            }
        }
    }

    private func connected(_ vaultName: String) -> some View {
        PairingScreen {
            VStack(spacing: 20) {
                PairingHero(
                    symbol: "checkmark.seal.fill", tint: .green, title: "Connected. Questions of “\(vaultName)” come here",
                    message:
                        "This iPhone approves with \(model.biometry == .none ? "Face ID" : model.biometry.name), also away from your Wi-Fi. Each question goes to your Macs and to this iPhone. The first answer counts.")
                codeFromLine
            }
        } actions: {
            Button {
                model.complete()
            } label: {
                Text("Done").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
        }
        .onAppear { celebrated = true }
        .sensoryFeedback(.success, trigger: celebrated)
    }

    private func failed(_ title: String, _ message: String) -> some View {
        PairingScreen {
            PairingHero(symbol: "exclamationmark.triangle.fill", tint: .orange, title: title, message: message)
        } actions: {
            Button {
                model.scanAgain()
            } label: {
                Text("Scan a new code").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            cancelButton
        }
    }

    // MARK: Parts

    /// "Code from “n”": the name in the code, as secondary text only. Anyone can make a code.
    @ViewBuilder
    private var codeFromLine: some View {
        if let codeFrom = model.codeFrom {
            Text(codeFrom)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
    }

    private var cancelButton: some View {
        Button {
            pasted = ""
            Task { await model.cancel() }
        } label: {
            Text("Cancel").frame(maxWidth: .infinity)
        }
        .buttonStyle(.glass)
    }

    #if targetEnvironment(simulator)
        /// The step and the step inside it, so the launch aids run again when either changes.
        private var launchStepKey: String {
            switch model.step {
            case .iCloud(let iCloud): "iCloud-\(iCloud.step)"
            case .join(let join): "join-\(join.step)"
            case .pairing(let pairing): "pairing-\(pairing.step)"
            default: model.step.id
            }
        }

        /// A development aid of the Simulator, which has no camera: `-ApassyConnectLink <link>`
        /// (or `-ApassyJoinLink <link>`) goes on as if the code had been scanned.
        private func startFromLaunchArgument() {
            guard case .scan = model.step,
                let text = UserDefaults.standard.string(forKey: "ApassyConnectLink")
                    ?? UserDefaults.standard.string(forKey: "ApassyJoinLink")
            else { return }
            model.handle(text)
        }

        /// The steps go on by themselves, for screenshots and for a join with a test relay:
        ///
        /// - a relay join skips its name step, and `-ApassyJoinPassphrase` types the passphrase;
        /// - `-ApassyConnectStep wifi` selects "Only on this Wi-Fi";
        /// - `-ApassyConnectStep vault` opens a synthetic file of the preview vault with
        ///   `-ApassyJoinPassphrase`, skips Face ID, and sends the name: the words show;
        /// - `-ApassyPreviewPairing code` shows a synthetic 6-digit code of the pairing.
        private func goOnFromLaunchArgument() async {
            let defaults = UserDefaults.standard
            let connectStep = defaults.string(forKey: "ApassyConnectStep")
            let passphrase = defaults.string(forKey: "ApassyJoinPassphrase")
            switch model.step {
            case .join(let join):
                if case .name = join.step { await join.start() }
            case .openVault where connectStep == "wifi":
                model.onlyOnThisWiFi()
            case .openVault where connectStep == "vault":
                model.openFile(URL(fileURLWithPath: "/private/tmp/Personal.apassy"))
            case .iCloud(let iCloud) where connectStep == "vault":
                switch iCloud.step {
                case .passphrase: if let passphrase { await iCloud.open(passphrase: passphrase) }
                case .faceID: iCloud.notNow()
                default: break
                }
            case .name where connectStep == "vault":
                await model.connect()
            case .pairHelp where defaults.string(forKey: "ApassyPreviewPairing") == "code":
                model.scanPairingCode()
            case .pairing(let pairing) where defaults.string(forKey: "ApassyPreviewPairing") == "code":
                if case .scan = pairing.step {
                    pairing.step = .code(macName: model.macName, code: "348 942", expiresAt: Date().addingTimeInterval(272))
                }
            default:
                break
            }
        }
    #endif
}

/// "Connect to your Mac" for the vault that is open, in a sheet (Decisions, Settings > Devices):
/// the vault joins the notifications team of the Mac.
struct ConnectSheet: View {
    @Environment(RootModel.self) private var root
    @Environment(\.dismiss) private var dismiss
    @State private var model: ConnectModel?

    var body: some View {
        Group {
            if let model {
                ConnectFlowView(model: model)
            } else {
                ProgressView()
            }
        }
        .task {
            guard model == nil else { return }
            let close = dismiss
            model = root.connectSelectedVault(onEnd: { close() })
            if model == nil { dismiss() }
        }
    }
}
