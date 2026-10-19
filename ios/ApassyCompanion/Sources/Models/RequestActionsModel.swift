import ApassyVaultKit
import Foundation

/// Visible list actions never increase scope beyond one validated Read request.
struct RequestListActions: Equatable {
    let canDeny: Bool
    let canAllowOnce: Bool
    var reviewOnly: Bool { !canAllowOnce }

    static func make(for question: RemoteQuestion, current: Bool) -> Self {
        guard current, question.problem == nil, let card = question.card else {
            return Self(canDeny: false, canAllowOnce: false)
        }
        let info = card.question
        let meaningful: (String) -> Bool = { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        let readable = question.vaultID.map(meaningful) == true
            && question.vaultName.map(meaningful) == true
            && !card.digest.isEmpty && meaningful(card.askerDevice)
            && meaningful(card.run.agent) && meaningful(card.run.id)
            && card.run.command.count >= 2 && card.run.command.allSatisfy(meaningful)
            && routineReadCommand(card.run.command)
            && !info.items.isEmpty && info.items.allSatisfy { meaningful($0.itemID) && meaningful($0.name) }
            && info.project.map { meaningful($0.key) && meaningful($0.label) } == true
        // Unknown and arbitrary agent risk strings are not a safety signal. Read action and
        // confirmed non-production credential facts are necessary; any reported risk adds Review.
        let eligible = readable && info.action == .read && !info.production
            && !info.items.contains { $0.production || $0.unconfirmed }
            && card.run.risk.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && info.validAnswers.contains("once")
        return Self(canDeny: true, canAllowOnce: eligible)
    }

    /// Unknown executables and shells require full review even if the action is classified Read.
    private static func routineReadCommand(_ command: [String]) -> Bool {
        guard let first = command.first else { return false }
        let executable = first.split(separator: "/").last.map(String.init) ?? first
        switch executable {
        case "git":
            return command.count >= 2 && ["status", "log", "show", "diff"].contains(command[1])
                && !command.contains(where: { $0 == "--ext-diff" || $0 == "--textconv" || $0.hasPrefix("--output") })
        case "ls", "cat", "head", "tail", "wc": return command.count >= 2
        default: return false
        }
    }
}

extension RemoteQuestion {
    /// Length framing prevents ambiguous delimiters; legacy selected-vault questions are isolated.
    var requestIdentity: String {
        let scope = vaultID ?? "legacy-selected-vault"
        return "question:\(scope.utf8.count):\(scope):\(qid.utf8.count):\(qid)"
    }
}
