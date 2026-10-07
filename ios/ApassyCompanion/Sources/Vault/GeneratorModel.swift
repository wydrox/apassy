import ApassyVaultKit
import Foundation
import Observation

/// The password generator (contract ios-core-v1, 5.4). The value is made by the core and is not
/// in the vault until the owner uses it in an item.
@MainActor
@Observable
final class GeneratorModel {
    var options: GeneratorOptions
    private(set) var value = ""
    private(set) var bits: Double = 0
    private(set) var strength: Strength?
    private(set) var error: String?
    /// Bumped on each new value, for the haptic.
    private(set) var generation = 0

    @ObservationIgnored private let service: any VaultService

    init(service: any VaultService, options: GeneratorOptions = GeneratorOptions()) {
        self.service = service
        self.options = options
    }

    /// Change the style. The length goes to the default of the new style.
    func setStyle(_ style: GeneratorOptions.Style) {
        guard style != options.style else { return }
        options.style = style
        options.length = style == .pin ? 6 : 24
    }

    /// The length as the slider shows it, kept in the range of the style.
    var length: Double {
        get { Double(options.length) }
        set {
            let range = GeneratorOptions.lengths(options.style)
            options.length = min(max(Int(newValue.rounded()), range.lowerBound), range.upperBound)
        }
    }

    /// A new value with the options.
    func regenerate() async {
        let asked = options
        do {
            let generated = try await service.generate(asked)
            let rated = try? await service.strength(generated.value)
            // The options may have changed while the core worked; the newer call wins.
            guard asked == options else { return }
            value = generated.value
            bits = generated.bits
            strength = rated.map { Strength(bits: generated.bits, score: Self.score(bits: generated.bits, fallback: $0.score)) }
            error = nil
            generation += 1
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// The score of a generated value from its exact entropy (contract section 9); the core's
    /// estimate only when the bits are unknown.
    static func score(bits: Double, fallback: Int) -> Int {
        guard bits > 0 else { return fallback }
        switch bits {
        case ..<28: return 0
        case ..<36: return 1
        case ..<60: return 2
        case ..<80: return 3
        default: return 4
        }
    }

    /// Drop the value: the sheet closed.
    func clear() {
        value = ""
        bits = 0
        strength = nil
    }
}
