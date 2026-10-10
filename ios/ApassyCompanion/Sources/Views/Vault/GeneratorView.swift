import ApassyVaultKit
import SwiftUI

/// The password generator. From the "+" menu it copies; from a password field it also offers
/// "Use this password". A generated value is not in the vault, so it needs no owner check.
struct GeneratorView: View {
    @State private var model: GeneratorModel
    let onUse: ((String) -> Void)?
    @Environment(VaultModel.self) private var vault
    @Environment(\.dismiss) private var dismiss

    init(model: GeneratorModel, onUse: ((String) -> Void)?) {
        _model = State(initialValue: model)
        self.onUse = onUse
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 14) {
                        Text(SecretText.attributed(model.value))
                            .font(.title3.monospaced())
                            .frame(maxWidth: .infinity, minHeight: 64, alignment: .leading)
                            .textSelection(.disabled)
                            .contentTransition(.opacity)
                            .accessibilityLabel(model.value)
                        StrengthBar(strength: model.strength, bits: model.bits)
                        HStack(spacing: 12) {
                            Button {
                                Task { await model.regenerate() }
                            } label: {
                                Label("Regenerate", systemImage: "arrow.clockwise").frame(maxWidth: .infinity)
                            }
                            Button {
                                vault.copyGenerated(model.value)
                            } label: {
                                Label("Copy", systemImage: "doc.on.doc").frame(maxWidth: .infinity)
                            }
                            .disabled(model.value.isEmpty)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.large)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                    }
                    .padding(.vertical, 6)
                }
                if let error = model.error {
                    Section {
                        Text(error).foregroundStyle(.red)
                    }
                }
                Section {
                    Picker("Style", selection: Binding(get: { model.options.style }, set: { model.setStyle($0) })) {
                        ForEach(GeneratorOptions.Style.allCases) { style in
                            Text(style.label).tag(style)
                        }
                    }
                    .pickerStyle(.segmented)
                    options
                }
            }
            .navigationTitle("Password generator")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(role: .close) { dismiss() }
                }
                if let onUse {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Use this password") {
                            onUse(model.value)
                            dismiss()
                        }
                        .disabled(model.value.isEmpty)
                    }
                }
            }
            .task(id: model.options) { await model.regenerate() }
            .sensoryFeedback(.selection, trigger: model.generation)
            .onDisappear { model.clear() }
        }
    }

    @ViewBuilder
    private var options: some View {
        switch model.options.style {
        case .random:
            lengthSlider
            Toggle("Digits", isOn: $model.options.digits)
            Toggle("Symbols", isOn: $model.options.symbols)
        case .memorable:
            Stepper("Words: \(model.options.words)", value: $model.options.words, in: 3...10)
            Picker("Separator", selection: $model.options.separator) {
                ForEach(GeneratorOptions.separators, id: \.self) { separator in
                    Text(Self.separatorName(separator)).tag(separator)
                }
            }
            Toggle("Capitalize", isOn: $model.options.capitalize)
        case .pin:
            lengthSlider
        }
    }

    private var lengthSlider: some View {
        let range = GeneratorOptions.lengths(model.options.style)
        return VStack(alignment: .leading) {
            LabeledContent("Length", value: "\(model.options.length)")
            Slider(
                value: $model.length, in: Double(range.lowerBound)...Double(range.upperBound), step: 1
            ) {
                Text("Length")
            } minimumValueLabel: {
                Text("\(range.lowerBound)").font(.caption)
            } maximumValueLabel: {
                Text("\(range.upperBound)").font(.caption)
            }
        }
    }

    static func separatorName(_ separator: String) -> String {
        switch separator {
        case "-": "Hyphen (-)"
        case ".": "Period (.)"
        case "_": "Underscore (_)"
        case " ": "Space"
        case ",": "Comma (,)"
        default: separator
        }
    }
}

/// The strength of a value as five segments and words: "Very strong, 118 bits".
struct StrengthBar: View {
    let strength: Strength?
    let bits: Double

    var body: some View {
        let score = strength?.score ?? -1
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 4) {
                ForEach(0..<5) { index in
                    Capsule()
                        .fill(index <= score ? color(score) : Color.secondary.opacity(0.2))
                        .frame(height: 6)
                }
            }
            if let strength {
                Text("\(strength.label), \(Int(bits.rounded())) bits")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(strength.map { "Strength: \($0.label), \(Int(bits.rounded())) bits" } ?? "Strength unknown")
    }

    private func color(_ score: Int) -> Color {
        switch score {
        case ..<1: .red
        case 1: .orange
        case 2: .yellow
        default: .green
        }
    }
}
