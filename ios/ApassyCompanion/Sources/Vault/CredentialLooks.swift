import ApassyVaultKit
import Foundation

/// What the tile of a credential shows, as the Mac's `credential_tile`: the tile of its provider
/// when the provider or the title names a known one, else the tile of its kind.
struct ProviderTileStyle: Equatable, Sendable {
    enum Mark: Equatable, Sendable {
        /// The first letter of the provider, in white.
        case letter(String)
        /// A database symbol (PostgreSQL).
        case database
        /// The symbol of the kind on the color of the kind.
        case kind(ItemKind)
    }

    let mark: Mark
    /// The color of the tile as 0xRRGGBB; nil for a kind tile (the color of the kind).
    let rgb: UInt32?

    /// The providers of the Mac, in its order: a word to look for, the label, the color.
    private static let providers: [(needle: String, label: String, rgb: UInt32)] = [
        ("anthropic", "Anthropic", 0xCC785C),
        ("github", "GitHub", 0x1F2328),
        ("stripe", "Stripe", 0x635BFF),
        ("cloudflare", "Cloudflare", 0xF48120),
        ("fly.io", "Fly.io", 0x7B3FE4),
        ("openai", "OpenAI", 0x10A37F),
        ("aws", "AWS", 0x232F3E),
        ("amazon", "AWS", 0x232F3E),
        ("slack", "Slack", 0x4A154B),
        ("sentry", "Sentry", 0x362D59),
        ("resend", "Resend", 0x111111),
        ("netflix", "Netflix", 0xE50914),
    ]

    static let postgres: UInt32 = 0x336791

    static func of(provider: String?, title: String, kind: ItemKind) -> ProviderTileStyle {
        let words = "\(provider ?? "") \(title)".lowercased()
        if words.contains("postgres") { return ProviderTileStyle(mark: .database, rgb: postgres) }
        if let known = providers.first(where: { words.contains($0.needle) }) {
            return ProviderTileStyle(mark: .letter(letter(known.label)), rgb: known.rgb)
        }
        return ProviderTileStyle(mark: .kind(kind), rgb: nil)
    }

    static func of(_ row: ItemRow) -> ProviderTileStyle {
        of(provider: row.provider, title: row.title, kind: row.kind)
    }

    /// The first letter or digit, upper case; "?" when there is none.
    static func letter(_ name: String) -> String {
        name.first(where: { $0.isLetter || $0.isNumber }).map { String($0).uppercased() } ?? "?"
    }
}

/// The lines and the marks of a credential in lists and in its header (ADR 0026 §1).
enum CredentialLooks {
    /// The line under the title in a list, as on the Mac: the username of a login or a database,
    /// else the kind.
    static func detailLine(_ row: ItemRow) -> String {
        if row.kind == .login || row.kind == .database, !row.subtitle.isEmpty { return row.subtitle }
        return row.kind.label
    }

    /// "Stripe · API key" under the name in the header; the kind alone without a provider.
    static func headerLine(_ row: ItemRow) -> String {
        [row.provider, row.kind.label].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
    }

    /// A small tag of the header.
    struct Cap: Equatable, Sendable, Identifiable {
        let label: String
        /// The one red mark: production.
        let red: Bool

        var id: String { label }
    }

    /// The environment cap of the header, as the Mac's: a red "Production", or the environment in
    /// gray, when the owner or a signal set it. A default or a value from usage shows none.
    static func environmentCap(_ detail: ItemDetail) -> Cap? {
        guard let environment = detail.environment, detail.environmentSource?.isConfirmed == true else {
            // An older core has no environment: the row still says production.
            return detail.environment == nil && detail.row.production == true ? Cap(label: "Production", red: true) : nil
        }
        return Cap(label: environment.label, red: environment == .production)
    }
}

/// "Always ask me" and the environment of a credential (ADR 0025 §3b, contract section 5.11). The
/// core does not check the owner: a change that makes the bouncer less careful needs the owner
/// check in the app first; a stricter change does not.
enum CredentialOptions {
    /// What the environment picker shows: the environment that the owner or a signal set, or nil
    /// ("Not set" without a declaration, "Not confirmed" for a default or a value from usage).
    static func shownEnvironment(_ detail: ItemDetail) -> CredentialEnvironment? {
        guard detail.environmentSource?.isConfirmed == true else { return nil }
        return detail.environment
    }

    /// The text of the picker when no environment is shown.
    static func unsetLabel(_ detail: ItemDetail) -> String {
        detail.environment == nil ? "Not set" : "Not confirmed"
    }

    /// How careful the bouncer is with an environment: production most.
    static func strictness(_ environment: CredentialEnvironment) -> Int {
        switch environment {
        case .production: 3
        case .staging: 2
        case .development: 1
        case .local: 0
        }
    }

    /// Turning "Always ask me" off makes each use wait less: the owner check first. On is stricter.
    static func alwaysAskNeedsOwner(from current: Bool, to new: Bool) -> Bool {
        current && !new
    }

    /// Whether choosing `new` makes the bouncer less careful than now. Without a declaration, or
    /// with an environment that is not confirmed, the bouncer treats the credential as production,
    /// so anything but production loosens it. Production never needs the check.
    static func environmentNeedsOwner(_ detail: ItemDetail, to new: CredentialEnvironment) -> Bool {
        guard new != .production else { return false }
        let current = shownEnvironment(detail) ?? .production
        return strictness(new) < strictness(current)
    }
}
