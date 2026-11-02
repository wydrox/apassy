import Foundation

/// Pure state machine. The runtime serializes access and supplies monotonic time.
struct FaceIDWindowState<Context: AnyObject> {
    var frequency: FaceIDFrequency = .everyTime
    var generation = UUID()
    private var context: Context?
    private var began: TimeInterval = 0
    private let now: () -> TimeInterval
    private let factory: () -> Context
    private let invalidate: (Context) -> Void

    init(now: @escaping () -> TimeInterval, factory: @escaping () -> Context,
         invalidate: @escaping (Context) -> Void) {
        self.now = now
        self.factory = factory
        self.invalidate = invalidate
    }

    mutating func acquire() -> (Context, Bool, UUID) {
        expire()
        if let context { return (context, true, generation) }
        return (factory(), false, generation)
    }

    mutating func authenticated(_ candidate: Context, generation expected: UUID) -> Bool {
        guard expected == generation else { invalidate(candidate); return false }
        if frequency != .everyTime, context == nil {
            context = candidate
            began = now()
        }
        return true
    }

    mutating func expire() {
        if context != nil, let seconds = frequency.seconds, now() - began >= seconds { end() }
    }

    mutating func configure(_ value: FaceIDFrequency) { end(); frequency = value }
    mutating func end() {
        generation = UUID()
        if let context { invalidate(context) }
        context = nil
    }
}
