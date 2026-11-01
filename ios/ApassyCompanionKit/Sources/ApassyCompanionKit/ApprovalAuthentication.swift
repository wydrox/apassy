import Foundation
import LocalAuthentication

/// One signing attempt owns one context. Cancellation invalidates the actual OS prompt.
public final class ApprovalAuthentication: @unchecked Sendable {
  let context = LAContext()
  private let lock = NSLock()
  private var ended = false
  public init() {
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.localizedFallbackTitle = ""
  }
  public var isCancelled: Bool { lock.withLock { ended } }
  public func cancel() {
    lock.withLock {
      ended = true
      context.invalidate()
    }
  }
  public static var faceIDAvailable: Bool {
    let context = LAContext()
    defer { context.invalidate() }
    return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
      && context.biometryType == .faceID
  }
  func requireFaceID(reason: String) throws {
    guard !isCancelled else { throw CompanionKeyError.cancelled }
    context.localizedReason = reason
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil),
      context.biometryType == .faceID
    else { throw CompanionKeyError.biometryUnavailable }
  }
  deinit { context.invalidate() }
}
