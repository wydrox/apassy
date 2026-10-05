// How the app shows a command, a folder, and the time that a run has left.
//
// These functions are pure, so `swift test` can check them. The owner decides from what the
// screen shows, so the text must not hide a character: an argument with a line break, an invisible
// character, or a look-alike space is written with escapes, never as it is.

import Foundation

/// The text of a command as the owner reads it.
public enum CommandDisplay {
    /// Characters that a shell reads as themselves anywhere in a word.
    private static let safe = Set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_@%+=:,./-".unicodeScalars)

    /// The command as one line: the arguments joined with spaces, each quoted when a shell would
    /// read it as more than one word or as something else than text.
    public static func line(_ argv: [String]) -> String {
        argv.map(quote).joined(separator: " ")
    }

    /// One argument, quoted for a POSIX shell. `npm` stays `npm`, `my file` becomes `'my file'`,
    /// and an argument with a control or invisible character becomes `$'...'` with escapes.
    public static func quote(_ argument: String) -> String {
        if argument.isEmpty { return "''" }
        if argument.unicodeScalars.allSatisfy({ safe.contains($0) }) { return argument }
        if argument.unicodeScalars.contains(where: needsEscape) {
            return "$'" + argument.unicodeScalars.map(escaped).joined() + "'"
        }
        return "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// A character that a reader cannot see or cannot tell from another: control characters,
    /// format characters (zero width, bidirectional marks), line and paragraph separators, and
    /// any space other than U+0020.
    private static func needsEscape(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator: return true
        case .spaceSeparator: return scalar != " "
        default: return false
        }
    }

    /// One character inside `$'...'`.
    private static func escaped(_ scalar: Unicode.Scalar) -> String {
        switch scalar {
        case "\n": return "\\n"
        case "\t": return "\\t"
        case "\r": return "\\r"
        case "\u{1B}": return "\\e"
        case "\\": return "\\\\"
        case "'": return "\\'"
        default: break
        }
        guard needsEscape(scalar) else { return String(scalar) }
        if scalar.value <= 0xFF && scalar.properties.generalCategory == .control {
            return String(format: "\\x%02X", scalar.value)
        }
        return scalar.value <= 0xFFFF
            ? String(format: "\\u%04X", scalar.value) : String(format: "\\U%08X", scalar.value)
    }

    /// The end of a folder path for a row: the last two components, with `.../` in front when
    /// there are more. `nil` for no folder.
    public static func folderTail(_ cwd: String?, components count: Int = 2) -> String? {
        guard let cwd, !cwd.isEmpty else { return nil }
        let parts = cwd.split(separator: "/", omittingEmptySubsequences: true)
        if parts.isEmpty { return "/" }
        if parts.count <= count { return (cwd.hasPrefix("/") ? "/" : "") + parts.joined(separator: "/") }
        return "\u{2026}/" + parts.suffix(count).joined(separator: "/")
    }
}

/// The time that a waiting run has left before the Mac ends it.
public enum WaitClock {
    /// Seconds left: the timeout, less the time the run waited when the inbox was fetched, less the
    /// time since. Nil when the Mac did not say how long the run waited. Never below 0 and never
    /// above the timeout.
    public static func secondsLeft(waitingSeconds: Int?, timeoutSeconds: Int, fetchedAt: Date, now: Date) -> Int? {
        guard let waitingSeconds else { return nil }
        let since = max(0, Int(now.timeIntervalSince(fetchedAt).rounded(.down)))
        return min(timeoutSeconds, max(0, timeoutSeconds - max(0, waitingSeconds) - since))
    }

    /// Seconds as `m:ss`, for example `1:48`.
    public static func text(_ seconds: Int) -> String {
        let clamped = max(0, seconds)
        return "\(clamped / 60):" + String(format: "%02d", clamped % 60)
    }
}
