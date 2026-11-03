import Foundation
import LocalAuthentication

/// One signing attempt leases the app context, or owns a fresh context without a provider.
public final class ApprovalAuthentication: @unchecked Sendable {
  private var storedContext = LAContext()
  var context: LAContext { lock.withLock { storedContext } }
  private let window: FaceIDWindow?
  private var lease: FaceIDLease?
  private let lock = NSLock()
  private var ended = false
  private var finished = false
  public init(window: FaceIDWindow? = nil) {
    self.window = window
    #if !os(watchOS)
    context.touchIDAuthenticationAllowableReuseDuration = 0
    context.localizedFallbackTitle = ""
    #endif
  }
  public var isCancelled: Bool { lock.withLock { ended || lease?.isValid == false } }
  public func cancel() {
    lock.withLock {
      ended = true
      guard !finished else { return }
      if let lease { lease.end(failed: true) } else {
        window?.end()
        storedContext.invalidate()
      }
    }
  }
  func prepare(reason: String) async throws {
    guard let window else { return }
    let acquired = try await window.authenticate(reason: reason)
    try lock.withLock {
      guard !ended else { acquired.end(failed: true); throw CompanionKeyError.cancelled }
      storedContext.invalidate()
      storedContext = acquired.context
      lease = acquired
    }
  }
  func finish() {
    lock.withLock {
      finished = true
      if let lease { lease.end() } else { storedContext.invalidate() }
    }
  }
  public static var faceIDAvailable: Bool {
    #if os(watchOS)
    // watchOS has no Face ID (ADR 0039).
    return false
    #else
    let context = LAContext()
    defer { context.invalidate() }
    return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
      && context.biometryType == .faceID
    #endif
  }
  func requireFaceID(reason: String) throws {
    guard !isCancelled else { throw CompanionKeyError.cancelled }
    #if os(watchOS)
    throw CompanionKeyError.biometryUnavailable
    #else
    context.localizedReason = reason
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil),
      context.biometryType == .faceID
    else { throw CompanionKeyError.biometryUnavailable }
    #endif
  }
  deinit { finish() }
}
