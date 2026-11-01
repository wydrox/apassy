import ApassyVaultKit
import SwiftUI

struct AccessRequestDetailView: View {
  let model: AccessRequestsModel
  let identity: String
  var history = false
  @Environment(\.scenePhase) private var scenePhase
  private var request: RelayAccessRequest? {
    (history ? model.history : model.requests).first { $0.id == identity }
  }
  var body: some View {
    TimelineView(.periodic(from: .now, by: 1)) { time in
      if let request {
        detail(request, at: time.date)
      } else {
        ContentUnavailableView("This access request is unavailable", systemImage: "clock")
      }
    }
    .navigationTitle(history ? "Access consent history" : "Access request")
    .navigationBarTitleDisplayMode(.inline)
    .onDisappear { model.cancel(clear: false) }
    .onChange(of: scenePhase) { _, phase in
      if phase == .background { model.cancel(clear: true) }
    }
  }
  private func detail(_ r: RelayAccessRequest, at date: Date) -> some View {
    let c = r.card
    return List {
      Section {
        Text("\(escaped(c.agent.name)) (id \(c.agent.id)) asks for \(escaped(c.item.name))")
          .font(.headline)
        Text("\(escaped(c.vault_name)) · Asked on \(escaped(c.asker.name))")
        if c.agent.host == nil { Text("Agent host: unknown") }
        if let host = c.agent.host {
          Text(
            "\(c.agent.host_source == "agent_claimed" ? "Agent-reported host (not verified)" : "Connection label (not executable attestation)"): \(escaped(host))"
          )
        }
      }
      Section("Mac-verified fields") {
        fact("Environment", c.item.environment)
        if c.item.delivery == "real_value" {
          Text(
            "Real value reaches the process. Reviewed destinations do not confine its networking.")
        } else {
          Text("Placeholder restricted to these exact hosts and ports before expiry.")
        }
        fact("Project", c.project?.label ?? "Incomplete")
        fact("Project identity", c.project?.key ?? "Incomplete")
        fact("Full folder", c.cwd)
        Text("Requested scope; checked against Mac policy").font(.subheadline)
        fact("Action", c.action ?? "Incomplete")
        ForEach(c.hosts, id: \.self) { host in
          Text(verbatim: host).font(.body.monospaced()).textSelection(.enabled)
        }
      }
      Section("The agent says") { Text(verbatim: escaped(c.reason)) }
      Section {
        LabeledContent(
          "Expires",
          value: Date(timeIntervalSince1970: TimeInterval(c.expires_at)).formatted(
            date: .omitted, time: .standard))
        Text("Allows one scoped use attempt. The bouncer still checks the command and may ask you.")
        Text(
          "One attempt can make multiple network calls. No durable grant, remembered answer, production allowance or evaluation permission is saved."
        )
        .font(.footnote).foregroundStyle(.secondary)
        if let reason = c.local_review_reason {
          Text("Review access on \(escaped(c.asker.name)): \(escaped(reason))")
        }
        if !history, !model.canAllow(r), c.valid_answers.contains(.allow_once) {
          Text("Allow once needs Face ID and the registered answer key. Deny or review on the Mac.")
        }
        if let receipt = r.receipt {
          if let device = receipt.device_name {
            Text("Answered on \(escaped(device))").font(.headline)
          }
          switch receipt.outcome {
          case "allowed_once":
            Text(
              "Consent recorded for one attempt before \(Date(timeIntervalSince1970: TimeInterval(receipt.expires_at)).formatted(date: .omitted, time: .shortened))"
            )
          case "denied": Text("Denied")
          case "granted_on_mac": Text("Access granted on the Mac")
          case "expired": Text("Access expired")
          default: Text("Access request invalidated. Review on the Mac.")
          }
          Text("Check on \(escaped(c.asker.name)) for remaining availability.")
          if date.timeIntervalSince1970 >= Double(c.expires_at) { Text("Access expired") }
        } else if let message = model.statusText(r, at: date) {
          Text(message).accessibilityIdentifier("access.answer.status")
        } else if history || r.state != "open" || date.timeIntervalSince1970 >= Double(c.expires_at)
        {
          Text("Not confirmed. Check on \(escaped(c.asker.name)).")
        }
      }
      if !history, r.receipt == nil {
        Section {
          if model.busy == r.id {
            Button("Cancel Face ID") { model.cancel(clear: false) }.frame(minHeight: 44)
          }
          if c.valid_answers.contains(.allow_once), model.canAllow(r) {
            Button("Allow once") { Task { await model.answer(r, choice: .allow_once) } }
              .frame(minHeight: 44).disabled(!model.actionable(r, at: date) || model.busy != nil)
              .accessibilityIdentifier("access.allow-once")
          }
          Button("Deny", role: .destructive) { Task { await model.answer(r, choice: .deny) } }
            .frame(minHeight: 44).disabled(!model.actionable(r, at: date) && model.busy != r.id)
            .accessibilityIdentifier("access.deny")
        }
      }
      Section("Exact identities") {
        fact("Agent id", c.agent.id)
        fact("Mac id", c.asker.device)
        fact("Vault id", c.vault_id)
        fact("Credential id", "\(c.item.local_id) / \(c.item.uuid)")
        fact("Revision", c.item.revision)
        fact("Request id", c.request_id)
      }
    }
  }
  private func fact(_ name: String, _ value: String) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      Text(name).font(.caption).foregroundStyle(.secondary)
      Text(verbatim: escaped(value)).textSelection(.enabled)
    }
    .accessibilityElement(children: .combine)
  }
  private func escaped(_ text: String) -> String {
    text.unicodeScalars.map { scalar in
      if scalar.value == 92 { return "\\\\" }
      if CharacterSet.controlCharacters.contains(scalar)
        || scalar.properties.generalCategory == .format
      {
        return "\\u{\(String(scalar.value, radix: 16))}"
      }
      return String(scalar)
    }.joined()
  }
}
