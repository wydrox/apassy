import ApassyVaultKit
import Foundation

/// Presentation keeps selected authority, delivery, and authoritative confirmation distinct.
enum RequestHistoryPresentation {
    enum Filter: String, CaseIterable, Identifiable {
        case all = "All", allowed = "Allowed", denied = "Denied"
        var id: Self { self }
    }

    static func status(_ entry: RequestHistoryEntry) -> String {
        switch entry.outcome {
        case "approved": entry.confirmedKind == "approve_once" ? "Allowed once" : "Allowed"
        case "denied": "Denied"
        case "timed_out": "Request expired"
        case "replaced": "Request changed"
        case .some: "Ended · outcome not reported"
        case nil:
            if entry.sentAt != nil || entry.attemptedAt != nil { "Not confirmed" }
            else { "No decision confirmed" }
        }
    }

    static func symbol(_ entry: RequestHistoryEntry) -> String {
        switch entry.outcome {
        case "approved": "checkmark.circle"
        case "denied": "xmark.circle"
        case "replaced": "arrow.triangle.2.circlepath"
        default: "clock"
        }
    }

    static func scope(_ kind: String?) -> String {
        switch kind {
        case "approve_once": "This request only"
        case "approve_in_project": "All agents in this project"
        case "allow_production": "All agents in this project, production included"
        case "deny": "Denied this request"
        case "never_for_agent": "Not for this agent"
        case "always_ask_for_agent": "Always ask for this agent"
        case "correct_environment": "Credential environment correction"
        case "disconnect": "Disconnect"
        default: "Not reported"
        }
    }

    static func dayTitle(_ date: Date) -> String {
        if Calendar.current.isDateInToday(date) { return "Today" }
        if Calendar.current.isDateInYesterday(date) { return "Yesterday" }
        return date.formatted(date: .abbreviated, time: .omitted)
    }
}
