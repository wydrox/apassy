import Foundation

/// The words of the watch screens for an access request (flow spec, Apple Watch, section 4), in one
/// place. Every text that an agent or a Mac supplies is escaped first, as on the iPhone.
public enum WatchRequestText {
    public static let scopeSource = "Requested scope; checked against Mac policy."
    public static let allowFootnote =
        "Allows one scoped use attempt. The bouncer still checks the command and may ask you."
    public static let checkingWrist = "Checking your wrist…"
    public static let sending = "Sending…"
    public static let expired = "Expired. Nothing was allowed."
    public static let unavailable = "This access request is no longer available"
    public static let notSpecified = "Not specified"

    /// Agent and Mac text as plain text: a backslash doubled, and control and format characters
    /// (bidirectional overrides among them) shown as `\u{…}`, so nothing can hide or reorder text.
    public static func escaped(_ text: String) -> String {
        text.unicodeScalars.map { scalar in
            if scalar.value == 92 { return "\\\\" }
            if CharacterSet.controlCharacters.contains(scalar)
                || scalar.properties.generalCategory == .format
            {
                return "\\u{\(String(scalar.value, radix: 16))}"
            }
            return String(scalar)
        }.joined()
    }

    /// "<agent> asks for <credential>".
    public static func title(_ card: RelayAccessCard) -> String {
        "\(escaped(card.agent.name)) asks for \(escaped(card.item.name))"
    }

    /// The name of the asking Mac.
    public static func mac(_ card: RelayAccessCard) -> String { escaped(card.asker.name) }

    /// "on <Mac>" (a row of Requests).
    public static func onMac(_ card: RelayAccessCard) -> String { "on \(mac(card))" }

    /// "Asked on <Mac> · <vault>".
    public static func askedOn(_ card: RelayAccessCard) -> String {
        "Asked on \(mac(card)) · \(escaped(card.vault_name))"
    }

    public static func isProduction(_ card: RelayAccessCard) -> Bool { card.item.environment == "production" }

    /// The environment of the credential as text, never as a color alone.
    public static func environment(_ card: RelayAccessCard) -> String {
        switch card.item.environment {
        case "production": "Production"
        case "development": "Development"
        case "staging": "Staging"
        case "unconfirmed": "Environment not confirmed"
        default: escaped(card.item.environment)
        }
    }

    /// What reaches the process.
    public static func delivery(_ card: RelayAccessCard) -> String {
        card.item.delivery == "real_value" ? "Real value reaches the process" : "Placeholder for these hosts only"
    }

    /// Where the host of the agent comes from.
    public static func hostProvenance(_ card: RelayAccessCard) -> String {
        guard let host = card.agent.host else { return "Agent host: unknown" }
        if card.agent.host_source == "agent_claimed" {
            return "Agent-reported host (not verified): \(escaped(host))"
        }
        return "Connection label (not executable attestation): \(escaped(host))"
    }

    /// A time of day, static (no countdown).
    public static func time(_ seconds: UInt64) -> String {
        Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(date: .omitted, time: .shortened)
    }

    /// "Until <time>".
    public static func until(_ card: RelayAccessCard) -> String { "Until \(time(card.expires_at))" }

    public static func sent(_ card: RelayAccessCard) -> String { "Sent. Waiting for \(mac(card)) to confirm." }

    public static func notConfirmed(_ card: RelayAccessCard) -> String {
        "Not confirmed. \(mac(card)) may be offline. Check on \(mac(card))."
    }

    /// The request ended without a receipt that this watch can check.
    public static func ended(_ card: RelayAccessCard) -> String { "Not confirmed. Check on \(mac(card))." }

    /// "a", "a or b", "a, b, or c".
    public static func list(_ items: [String], conjunction: String = "or") -> String {
        switch items.count {
        case 0: ""
        case 1: items[0]
        case 2: "\(items[0]) \(conjunction) \(items[1])"
        default: items.dropLast().joined(separator: ", ") + ", \(conjunction) " + items[items.count - 1]
        }
    }

    /// The status of a row of Requests: "Until <time>", or how it ended.
    public static func rowStatus(_ request: RelayAccessRequest, at date: Date) -> String {
        if let receipt = request.receipt {
            switch receipt.outcome {
            case "allowed_once": return "Allowed once"
            case "denied": return "Denied"
            case "expired": return "Expired"
            case "granted_on_mac": return "Granted on the Mac"
            default: return "Invalidated"
            }
        }
        if WatchRequestRules.isExpired(request, at: date) { return "Expired" }
        if request.state != "open" { return "Not confirmed" }
        return until(request.card)
    }

    /// One VoiceOver sentence for a row: "Claude Code asks for GitHub token on Studio Mac, until 9:48".
    public static func rowAccessibility(_ request: RelayAccessRequest, at date: Date) -> String {
        let card = request.card
        let status = rowStatus(request, at: date)
        let lowered = status.prefix(1).lowercased() + status.dropFirst()
        let production = isProduction(card) ? ", Production" : ""
        return "\(title(card)) \(onMac(card))\(production), \(lowered)"
    }
}
