import Foundation
import Testing
@testable import ApassyCompanionKit

struct FaceIDWindowTests {
    private final class Context { var invalidated = false }
    private final class Clock { var now: TimeInterval = 0 }
    private func state(_ clock: Clock) -> FaceIDWindowState<Context> {
        FaceIDWindowState(now: { clock.now }, factory: { Context() }, invalidate: { $0.invalidated = true })
    }

    @Test func reusesWithoutExtendingDeadline() {
        let clock = Clock()
        var window = state(clock)
        window.configure(.oneMinute)
        let (first, reused, generation) = window.acquire()
        #expect(!reused)
        #expect(window.authenticated(first, generation: generation))
        clock.now = 59
        let (second, reusedAgain, _) = window.acquire()
        #expect(first === second && reusedAgain)
        #expect(window.authenticated(second, generation: generation))
        clock.now = 60
        let (third, reusedExpired, _) = window.acquire()
        #expect(third !== first && !reusedExpired && first.invalidated)
    }

    @Test func everyTimeNeverRetains() {
        let clock = Clock()
        var window = state(clock)
        let (first, _, generation) = window.acquire()
        #expect(window.authenticated(first, generation: generation))
        let (second, reused, _) = window.acquire()
        #expect(first !== second && !reused)
    }

    @Test func lockAndSettingChangeInvalidateAndFencePendingEvaluation() {
        let clock = Clock()
        var window = state(clock)
        window.configure(.untilLock)
        let (first, _, generation) = window.acquire()
        #expect(window.authenticated(first, generation: generation))
        window.end() // Runtime's protected-data / termination / vault-lock event.
        #expect(first.invalidated)
        #expect(!window.authenticated(first, generation: generation))
        let (next, _, nextGeneration) = window.acquire()
        #expect(window.authenticated(next, generation: nextGeneration))
        window.configure(.fiveMinutes)
        #expect(next.invalidated)
        #expect(!window.authenticated(next, generation: nextGeneration))
    }

    @Test func failedOrUnfinishedEvaluationDoesNotOpenWindow() {
        let clock = Clock()
        var window = state(clock)
        window.configure(.oneHour)
        let (first, _, _) = window.acquire()
        let (next, reused, _) = window.acquire()
        #expect(first !== next && !reused)
    }

    @Test func labelsMatchOwnerDecision() {
        #expect(FaceIDFrequency.allCases.map(\.label) == ["Every time", "1 minute", "5 minutes", "15 minutes", "1 hour", "Until the iPhone locks"])
    }

    @Test func untilLockSurvivesElapsedTimeAndBackgroundWithoutAnEndEvent() {
        let clock = Clock()
        var window = state(clock)
        window.configure(.untilLock)
        let (first, _, generation) = window.acquire()
        #expect(window.authenticated(first, generation: generation))
        clock.now = 100_000
        // Background is deliberately not a state-machine event.
        let (again, reused, _) = window.acquire()
        #expect(again === first && reused && !first.invalidated)
        window.end() // Enrollment change also uses the same invalidating transition.
        #expect(first.invalidated)
    }
}
