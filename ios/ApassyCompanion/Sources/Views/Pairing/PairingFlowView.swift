import SwiftUI

/// The pairing flow. It shows one screen for each step of `PairingModel`.
struct PairingFlowView: View {
    let model: PairingModel

    var body: some View {
        ZStack {
            switch model.step {
            case .welcome:
                WelcomeView(model: model)
            case .scan:
                ScanView(model: model)
            case .connecting(let macName):
                ConnectingView(model: model, macName: macName)
            case .code(let macName, let code, let expiresAt):
                CodeView(model: model, macName: macName, code: code, expiresAt: expiresAt)
            case .paired(let macName):
                PairedView(model: model, macName: macName)
            case .denied:
                PairingResultView(
                    symbol: "xmark.circle.fill", tint: .red, title: "Pairing was closed",
                    message:
                        "Apassy on your Mac closed the pairing: it was cancelled, or the code was typed wrong three times. Nothing is paired.",
                    model: model)
            case .expired:
                PairingResultView(
                    symbol: "clock.badge.exclamationmark.fill", tint: .orange, title: "The code has expired",
                    message:
                        "The pairing window of your Mac ended. Select \"Pair an iPhone\" in Apassy on your Mac to make a new code. Nothing is paired.",
                    model: model)
            case .failed(let title, let message):
                PairingResultView(
                    symbol: "exclamationmark.triangle.fill", tint: .orange, title: title, message: message,
                    model: model)
            }
        }
        .animation(.snappy, value: model.step)
        #if targetEnvironment(simulator)
            .task { model.startFromLaunchArgument() }
        #endif
    }
}

/// The frame of a pairing screen: content that scrolls, and actions that float above it.
struct PairingScreen<Content: View, Actions: View>: View {
    @ViewBuilder let content: Content
    @ViewBuilder let actions: Actions

    var body: some View {
        ScrollView {
            content
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 24)
                .padding(.vertical, 32)
        }
        .scrollBounceBehavior(.basedOnSize)
        .safeAreaInset(edge: .bottom) {
            GlassEffectContainer(spacing: 12) {
                VStack(spacing: 12) {
                    actions
                }
                .controlSize(.large)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 8)
        }
    }
}

/// A big symbol, a title, and a message. The screens of the pairing flow start with it.
struct PairingHero: View {
    let symbol: String
    var tint: Color = .accentColor
    let title: String
    var message: String?

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: symbol)
                .font(.system(size: 56))
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            Text(title)
                .font(.title.bold())
                .multilineTextAlignment(.center)
            if let message {
                Text(message)
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
    }
}

/// The end of a pairing that did not work, with a way to start again.
struct PairingResultView: View {
    let symbol: String
    let tint: Color
    let title: String
    let message: String
    let model: PairingModel

    var body: some View {
        PairingScreen {
            PairingHero(symbol: symbol, tint: tint, title: title, message: message)
        } actions: {
            Button {
                model.startAgain()
            } label: {
                Text("Scan a new code").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glassProminent)
            Button {
                model.backToWelcome()
            } label: {
                Text("Back").frame(maxWidth: .infinity)
            }
            .buttonStyle(.glass)
        }
    }
}

/// A note in a tinted box: a notice, or the warning of the Simulator.
struct CalloutView: View {
    let symbol: String
    var tint: Color = .orange
    let text: String

    var body: some View {
        Label {
            Text(text)
                .font(.callout)
                .frame(maxWidth: .infinity, alignment: .leading)
        } icon: {
            Image(systemName: symbol)
                .foregroundStyle(tint)
        }
        .padding(12)
        .background(tint.opacity(0.14), in: .rect(cornerRadius: 14, style: .continuous))
    }
}
