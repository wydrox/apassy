import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Observation

@MainActor @Observable
final class AccessRequestsModel {
  private(set) var history: [RelayAccessRequest] = []
  private(set) var requests: [RelayAccessRequest] = []
  private(set) var messages: [String: String] = [:]
  private(set) var busy: String?
  private(set) var unavailable: String?
  @ObservationIgnored private let service: any VaultService
  @ObservationIgnored private let signers: any AnswerSigners
  @ObservationIgnored private var authentication: ApprovalAuthentication?
  @ObservationIgnored private var generation = 0
  @ObservationIgnored private var sent: Set<String> = []
  @ObservationIgnored private var sentDates: [String: Date] = [:]

  init(service: any VaultService, signers: any AnswerSigners) {
    self.service = service
    self.signers = signers
  }
  func refresh() async {
    let current = generation
    do {
      let snapshot = try await service.accessRequestsList()
      guard current == generation else { return }
      guard snapshot.protocolName == "apassy-access-request", snapshot.version == 1 else {
        throw VaultError(.notAllowed, "Update Apassy to read access requests.")
      }
      let updated = snapshot.requests
      if let busy,
        !updated.contains(where: { $0.id == busy && $0.state == "open" && $0.receipt == nil })
      {
        cancel(clear: false)
      }
      requests = updated
      if let saved = try? await service.accessRequestsHistory(), current == generation {
        history = saved.requests
      }
      unavailable = nil
      for row in updated where row.receipt != nil { messages[row.id] = nil }
    } catch {
      guard current == generation else { return }
      cancel(clear: false)
      unavailable = "Review access on the Mac. \(error.localizedDescription)"
    }
  }
  func cancel(clear: Bool = true) {
    generation += 1
    authentication?.cancel()
    authentication = nil
    if let busy { messages[busy] = "The check was cancelled. Nothing was sent." }
    busy = nil
    if clear {
      requests = []
      history = []
      messages = [:]
    }
  }
  func canAllow(_ request: RelayAccessRequest) -> Bool {
    guard request.card.valid_answers.contains(.allow_once),
      let key = request.answer_key.flatMap(Base64URL.decode),
      let signer = signers.signer(team: request.card.team_id, registered: key)
    else { return false }
    return signer.canSignAccess
  }
  func actionable(_ request: RelayAccessRequest, at date: Date = .now) -> Bool {
    unavailable == nil
      && requests.contains { $0.id == request.id && $0.state == "open" && $0.receipt == nil }
      && date.timeIntervalSince1970 < Double(request.card.expires_at)
      && !sent.contains(request.id) && busy != request.id
  }
  func statusText(_ request: RelayAccessRequest, at date: Date) -> String? {
    if let sent = sentDates[request.id],
      date.timeIntervalSince(sent) >= 60
        || date.timeIntervalSince1970 >= Double(request.card.expires_at)
    {
      return "Not confirmed. Check on \(request.card.asker.name)."
    }
    return messages[request.id]
  }
  func answer(_ request: RelayAccessRequest, choice: AccessChoice) async {
    // Deny can cancel a pending match; it never uses the answer signer.
    if choice == .deny, busy != nil { cancel(clear: false) }
    guard busy == nil, actionable(request), request.card.valid_answers.contains(choice) else {
      return
    }
    if choice == .allow_once, !canAllow(request) {
      messages[request.id] = "Allow once needs Face ID on this iPhone. Deny or review on the Mac."
      return
    }
    generation += 1
    let current = generation
    busy = request.id
    messages[request.id] = choice == .allow_once ? "Preparing Face ID…" : "Sending Deny…"
    let auth = ApprovalAuthentication()
    authentication = auth
    defer {
      auth.cancel()
      if current == generation {
        busy = nil
        authentication = nil
      }
    }
    do {
      await service.accessRequestCancelPrepared()
      guard current == generation else { return }
      let prepared = try await service.accessRequestPrepare(request, choice: choice)
      guard current == generation, prepared.digest == request.digest,
        prepared.needs_face_id == (choice == .allow_once),
        let bytes = Base64URL.decode(prepared.bytes)
      else { return }
      let started = ContinuousClock.now
      let wall = Date.now
      let signature: Data?
      if choice == .allow_once {
        guard let key = request.answer_key.flatMap(Base64URL.decode),
          let signer = signers.signer(team: request.card.team_id, registered: key),
          try signer.publicKey() == key
        else { throw CompanionKeyError.biometryChanged }
        messages[request.id] = "Face ID — allow one scoped use attempt"
        signature = try await signer.signAccess(
          bytes,
          reason:
            "allow one scoped use attempt by \(ApprovalPrompt.shortName(request.card.agent.name))",
          authentication: auth)
      } else {
        signature = nil
      }
      // Cancelled/background/switched/expired/changed-card results can never POST.
      guard current == generation, !Task.isCancelled,
        requests.contains(where: { $0.id == request.id && $0.state == "open" && $0.receipt == nil })
      else { return }
      let elapsed = started.duration(to: .now)
      guard elapsed < .seconds(50),
        abs(Date.now.timeIntervalSince(wall) - Double(elapsed.components.seconds)) < 2
      else {
        throw VaultError(
          .notAllowed, "The signing time changed. Nothing was sent. Choose the answer again.")
      }
      for attempt in 0..<3 {
        guard current == generation, Date.now.timeIntervalSince1970 < Double(prepared.retry_before),
          Date.now.timeIntervalSince1970 < Double(request.card.expires_at)
        else { throw VaultError(.notAllowed, "The answer expired. Review on the Mac.") }
        do {
          let result = try await service.accessRequestAnswer(
            request, choice: choice, prepared: prepared, signature: signature)
          guard current == generation, result.sent else { return }
          sent.insert(request.id)
          sentDates[request.id] = .now
          messages[request.id] = "Sent. Waiting for \(request.card.asker.name) to confirm."
          await refresh()
          return
        } catch let error as VaultError where error.code == .relayUnreachable && attempt < 2 {
          // Same bytes/signature only. Core reserves every uncertain POST durably.
          try await Task.sleep(for: .seconds(attempt == 0 ? 2 : 4))
        }
      }
    } catch {
      guard current == generation else { return }
      messages[request.id] =
        "Not confirmed. Check on \(request.card.asker.name). \(error.localizedDescription)"
    }
  }
}
