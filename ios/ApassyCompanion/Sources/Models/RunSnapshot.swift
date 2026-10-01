import ApassyCompanionKit

/// The run as the owner reads it in the sheet, and what the owner may do with it.
///
/// The phone signs the digest of this run, the one on the screen (contract section 7). When the
/// inbox later shows another digest for the same run ID, the snapshot takes the new run and asks
/// the owner to read it again before Approve is possible. The Mac's `409 changed` is only the
/// backstop.
struct RunSnapshot: Equatable {
    /// How the run on the screen compares with the run on the Mac now.
    enum Availability: Equatable {
        /// The Mac shows the same run.
        case current
        /// The Mac shows the run with other content, and the snapshot has not taken it yet.
        case changed
        /// The run no longer waits.
        case gone
    }

    /// The run on the screen, and the source of the digest that Approve signs.
    private(set) var run: PendingRun
    /// True from the moment the snapshot took a new version until the owner confirms that they read it.
    private(set) var needsReview = false

    init(_ run: PendingRun) {
        self.run = run
    }

    /// Take a new version of the run. `live` is the run that the inbox has now for this ID, or nil.
    /// It returns true when the snapshot changed, so the screen can show the new version at the top.
    @discardableResult
    mutating func observe(_ live: PendingRun?) -> Bool {
        guard let live, live.digest != run.digest else { return false }
        run = live
        // A version that comes back (A, then B, then A again) is still a change that the owner did
        // not read, so the flag stays until the owner confirms.
        needsReview = true
        return true
    }

    /// The owner read the new version.
    mutating func confirmReading() {
        needsReview = false
    }

    func availability(live: PendingRun?) -> Availability {
        guard let live else { return .gone }
        return live.digest == run.digest ? .current : .changed
    }

    /// Approve and Approve and remember need the run to be current and read.
    func canApprove(live: PendingRun?) -> Bool {
        !needsReview && availability(live: live) == .current
    }

    /// Deny needs a run that still waits. A denial gives nothing away, so it needs no second look.
    func canDeny(live: PendingRun?) -> Bool {
        availability(live: live) != .gone
    }
}
