import ApassyCompanionKit
import Foundation
import Testing

@testable import AppModels

@Suite("RunSnapshot")
struct RunSnapshotTests {
    static let first = PreviewData.migrateRun

    /// The same run with other content and another digest, as the Mac would show it after a change.
    static func changed(_ run: PendingRun = first, digest: String = String(repeating: "ef", count: 32)) -> PendingRun {
        PendingRun(
            id: run.id, agent: run.agent, command: run.command + ["--force"], cwd: run.cwd, envNames: run.envNames,
            purpose: run.purpose, risk: run.risk, userRequest: run.userRequest, requestSource: run.requestSource,
            agentRequest: run.agentRequest, remember: run.remember, digest: digest,
            waitingSeconds: run.waitingSeconds)
    }

    @Test("a run that the Mac still shows the same can be approved and denied")
    func current() {
        var snapshot = RunSnapshot(Self.first)
        #expect(snapshot.availability(live: Self.first) == .current)
        #expect(snapshot.canApprove(live: Self.first))
        #expect(snapshot.canDeny(live: Self.first))
        // Only the time left differs: it is not part of the digest, so nothing changes.
        let later = PendingRun(
            id: Self.first.id, agent: Self.first.agent, command: Self.first.command, cwd: Self.first.cwd,
            envNames: Self.first.envNames, purpose: Self.first.purpose, risk: Self.first.risk,
            userRequest: Self.first.userRequest, requestSource: Self.first.requestSource,
            agentRequest: Self.first.agentRequest, remember: Self.first.remember, digest: Self.first.digest,
            waitingSeconds: 90)
        let took1 = snapshot.observe(later)
        #expect(!took1)
        #expect(!snapshot.needsReview)
        #expect(snapshot.canApprove(live: later))
        #expect(snapshot.run == Self.first)
    }

    @Test("another digest for the same run shows the new run and stops Approve until the owner confirms")
    func changedRun() {
        var snapshot = RunSnapshot(Self.first)
        let new = Self.changed()
        // Before the view took the new run, the buttons are off already.
        #expect(snapshot.availability(live: new) == .changed)
        #expect(!snapshot.canApprove(live: new))

        let took2 = snapshot.observe(new)

        #expect(took2)
        #expect(snapshot.run == new)
        #expect(snapshot.needsReview)
        // The screen shows the new run and the Mac shows it too, but the owner has not read it.
        #expect(snapshot.availability(live: new) == .current)
        #expect(!snapshot.canApprove(live: new))
        // A denial gives nothing away, so it needs no second look.
        #expect(snapshot.canDeny(live: new))

        snapshot.confirmReading()
        #expect(!snapshot.needsReview)
        #expect(snapshot.canApprove(live: new))
        // The digest that is signed is the one of the new run.
        #expect(snapshot.run.digest == new.digest)
    }

    @Test("a sheet that opens with a stale run takes the new digest at first appearance and needs a review before Approve")
    func openedStale() {
        // The row passed in the run from the last inbox render, and a poll changed its digest before
        // the sheet appeared. The digest then stays the same, so the view has no later change to
        // react to: the first observation, at first appearance, has to take the new run.
        var snapshot = RunSnapshot(Self.first)
        let live = Self.changed()
        // Before that observation the sheet is stuck: the old run, the changed banner, no way out.
        #expect(snapshot.availability(live: live) == .changed)
        #expect(!snapshot.needsReview)
        #expect(!snapshot.canApprove(live: live))

        let tookAtAppearance = snapshot.observe(live)

        // The new run is on the screen, and the owner has to confirm before Approve turns on.
        #expect(tookAtAppearance)
        #expect(snapshot.run == live)
        #expect(snapshot.run.digest == live.digest)
        #expect(snapshot.needsReview)
        #expect(snapshot.availability(live: live) == .current)
        #expect(!snapshot.canApprove(live: live))
        #expect(snapshot.canDeny(live: live))

        // A second observation of the same digest (the next poll) is not a change: the view does
        // not scroll or announce again, and the review stays as it is.
        let tookAgain = snapshot.observe(live)
        #expect(!tookAgain)
        #expect(snapshot.needsReview)
        #expect(!snapshot.canApprove(live: live))

        snapshot.confirmReading()
        #expect(snapshot.canApprove(live: live))
        #expect(snapshot.run.digest == live.digest)
    }

    @Test("a sheet that opens with the current run takes nothing at first appearance")
    func openedCurrent() {
        var snapshot = RunSnapshot(Self.first)
        let tookAtAppearance = snapshot.observe(Self.first)
        // No change: no scroll, no announcement, no review, and Approve works at once.
        #expect(!tookAtAppearance)
        #expect(!snapshot.needsReview)
        #expect(snapshot.canApprove(live: Self.first))
    }

    @Test("a run that goes back to its first version is still a change that the owner did not read")
    func backAndForth() {
        var snapshot = RunSnapshot(Self.first)
        let other = Self.changed()
        let took3 = snapshot.observe(other)
        #expect(took3)
        let took4 = snapshot.observe(Self.first)
        #expect(took4)
        #expect(snapshot.needsReview)
        #expect(snapshot.run == Self.first)
        #expect(!snapshot.canApprove(live: Self.first))
        snapshot.confirmReading()
        #expect(snapshot.canApprove(live: Self.first))
    }

    @Test("a second change after the confirmation asks again")
    func changedTwice() {
        var snapshot = RunSnapshot(Self.first)
        let took5 = snapshot.observe(Self.changed())
        #expect(took5)
        snapshot.confirmReading()
        let third = Self.changed(digest: String(repeating: "12", count: 32))
        let took6 = snapshot.observe(third)
        #expect(took6)
        #expect(snapshot.needsReview)
        #expect(!snapshot.canApprove(live: third))
    }

    @Test("a run that is gone from the inbox cannot be decided, and gone is not a change")
    func gone() {
        var snapshot = RunSnapshot(Self.first)
        #expect(snapshot.availability(live: nil) == .gone)
        #expect(!snapshot.canApprove(live: nil))
        #expect(!snapshot.canDeny(live: nil))
        let took7 = snapshot.observe(nil)
        #expect(!took7)
        #expect(!snapshot.needsReview)
        #expect(snapshot.run == Self.first)
    }

    @Test("the view keeps the run with the digest it showed until the owner has read a new one")
    func approvalUsesShownDigest() {
        var snapshot = RunSnapshot(Self.first)
        #expect(snapshot.run.digest == Self.first.digest)
        let new = Self.changed()
        snapshot.observe(new)
        // The digest that the view would send is the new run's, and only after the confirmation.
        #expect(snapshot.run.digest == new.digest)
        #expect(!snapshot.canApprove(live: new))
        snapshot.confirmReading()
        #expect(snapshot.canApprove(live: new))
    }
}

@Suite("CoverPolicy")
struct CoverPolicyTests {
    @Test("the app is covered when inactive or in the background, and not when active")
    func plain() {
        #expect(!CoverPolicy.isCovered(phase: .active, systemPromptDepth: 0))
        #expect(CoverPolicy.isCovered(phase: .inactive, systemPromptDepth: 0))
        #expect(CoverPolicy.isCovered(phase: .background, systemPromptDepth: 0))
    }

    @Test("a system prompt of the app excuses the inactive phase only")
    func prompt() {
        #expect(!CoverPolicy.isCovered(phase: .inactive, systemPromptDepth: 1))
        #expect(!CoverPolicy.isCovered(phase: .inactive, systemPromptDepth: 2))
        #expect(!CoverPolicy.isCovered(phase: .active, systemPromptDepth: 1))
        // In the background the app switcher can show the app, prompt or not.
        #expect(CoverPolicy.isCovered(phase: .background, systemPromptDepth: 1))
        // A prompt that ended puts the cover back.
        #expect(CoverPolicy.isCovered(phase: .inactive, systemPromptDepth: 0))
    }

    @Test("polling stops in the background only")
    func polling() {
        #expect(CoverPolicy.polls(in: .active))
        #expect(CoverPolicy.polls(in: .inactive))
        #expect(!CoverPolicy.polls(in: .background))
    }
}
