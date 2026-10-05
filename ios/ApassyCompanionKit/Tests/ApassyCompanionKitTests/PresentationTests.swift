import Foundation
import Testing

@testable import ApassyCompanionKit

@Suite("Presentation")
struct PresentationTests {
    @Test("plain arguments are written as they are")
    func plain() {
        #expect(CommandDisplay.line(["npm", "run", "migrate"]) == "npm run migrate")
        #expect(CommandDisplay.line(["curl", "-H", "a=b", "https://example.test/x?y=1"]) == "curl -H a=b 'https://example.test/x?y=1'")
        #expect(CommandDisplay.line([]) == "")
    }

    @Test("an argument with a space, a quote, or a shell character is quoted")
    func quoted() {
        #expect(CommandDisplay.quote("my file.txt") == "'my file.txt'")
        #expect(CommandDisplay.quote("") == "''")
        #expect(CommandDisplay.quote("it's") == "'it'\\''s'")
        #expect(CommandDisplay.quote("$HOME") == "'$HOME'")
        #expect(CommandDisplay.quote("a;b") == "'a;b'")
        #expect(CommandDisplay.quote("~") == "'~'")
        #expect(CommandDisplay.line(["echo", "two words", "x"]) == "echo 'two words' x")
    }

    @Test("a line break, a control character, and a carriage return are escaped")
    func controls() {
        #expect(CommandDisplay.quote("a\nb") == "$'a\\nb'")
        #expect(CommandDisplay.quote("a\tb") == "$'a\\tb'")
        #expect(CommandDisplay.quote("ok\rrm") == "$'ok\\rrm'")
        #expect(CommandDisplay.quote("\u{1B}[2J") == "$'\\e[2J'")
        #expect(CommandDisplay.quote("a\u{01}b") == "$'a\\x01b'")
        #expect(CommandDisplay.quote("it's\nx") == "$'it\\'s\\nx'")
        #expect(CommandDisplay.quote("a\\\nb") == "$'a\\\\\\nb'")
    }

    @Test("invisible and look-alike characters are escaped")
    func invisible() {
        #expect(CommandDisplay.quote("rm\u{202E}fdp") == "$'rm\\u202Efdp'")
        #expect(CommandDisplay.quote("a\u{200B}b") == "$'a\\u200Bb'")
        #expect(CommandDisplay.quote("a\u{00A0}b") == "$'a\\u00A0b'")
        #expect(CommandDisplay.quote("a\u{2028}b") == "$'a\\u2028b'")
        #expect(CommandDisplay.quote("a\u{E0041}b") == "$'a\\U000E0041b'")
    }

    @Test("a visible non-ASCII letter is quoted but not escaped")
    func letters() {
        #expect(CommandDisplay.quote("caf\u{00E9}") == "'caf\u{00E9}'")
    }

    @Test("a folder shows its last two components")
    func folder() {
        #expect(CommandDisplay.folderTail("/Users/me/Dev/shop") == "\u{2026}/Dev/shop")
        #expect(CommandDisplay.folderTail("/Users/me") == "/Users/me")
        #expect(CommandDisplay.folderTail("/tmp") == "/tmp")
        #expect(CommandDisplay.folderTail("/") == "/")
        #expect(CommandDisplay.folderTail("/a/b/c/", components: 1) == "\u{2026}/c")
        #expect(CommandDisplay.folderTail(nil) == nil)
        #expect(CommandDisplay.folderTail("") == nil)
    }

    @Test("the time left counts down from the timeout and stays in range")
    func timeLeft() {
        let fetched = Date(timeIntervalSince1970: 1_790_000_000)
        func left(_ waiting: Int?, after seconds: Double, timeout: Int = 120) -> Int? {
            WaitClock.secondsLeft(
                waitingSeconds: waiting, timeoutSeconds: timeout, fetchedAt: fetched,
                now: fetched.addingTimeInterval(seconds))
        }
        #expect(left(12, after: 0) == 108)
        #expect(left(12, after: 5.9) == 103)
        #expect(left(0, after: 0) == 120)
        #expect(left(119, after: 30) == 0)
        #expect(left(500, after: 0) == 0)
        #expect(left(12, after: -10) == 108)
        #expect(left(-5, after: 0) == 120)
        #expect(left(nil, after: 0) == nil)
    }

    @Test("the time is written as minutes and seconds")
    func timeText() {
        #expect(WaitClock.text(108) == "1:48")
        #expect(WaitClock.text(9) == "0:09")
        #expect(WaitClock.text(120) == "2:00")
        #expect(WaitClock.text(-3) == "0:00")
    }
}
