import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

@MainActor
@Suite("OwnerGate")
struct OwnerGateTests {
    private func makeGate(answer: Bool, biometry: Biometry = .faceID) -> (OwnerGate, ScriptedOwnerCheck) {
        let check = ScriptedOwnerCheck(answer: answer, biometry: biometry)
        return (OwnerGate(check: check, service: PreviewVaultService(unlocked: true)), check)
    }

    /// Start a confirm that waits for the passphrase prompt.
    private func confirmWithPrompt(_ gate: OwnerGate, reason: String = "Show the password") async -> Task<Bool, Never> {
        let task = Task { await gate.confirm(reason: reason) }
        #expect(await waitUntil { gate.prompt != nil })
        return task
    }

    @Test("a Face ID match allows the action and shows no prompt")
    func match() async {
        let (gate, check) = makeGate(answer: true)
        #expect(await gate.confirm(reason: "Show the password"))
        #expect(gate.prompt == nil)
        #expect(!gate.isChecking)
        #expect(check.calls == 1)
        #expect(check.reasons == ["Show the password"])
    }

    @Test("without a match the passphrase prompt shows the reason")
    func noMatch() async {
        let (gate, _) = makeGate(answer: false)
        let task = await confirmWithPrompt(gate, reason: "Copy the password")
        #expect(gate.prompt?.reason == "Copy the password")
        #expect(gate.prompt?.message == nil)
        gate.cancel()
        #expect(await task.value == false)
    }

    @Test("the biometry of the check is the biometry of the gate")
    func biometry() {
        let (gate, _) = makeGate(answer: true, biometry: .touchID)
        #expect(gate.biometry == .touchID)
    }

    @Test("a wrong passphrase keeps the prompt with a message, and the right one allows the action")
    func wrongThenRight() async {
        let (gate, _) = makeGate(answer: false)
        let task = await confirmWithPrompt(gate)

        await gate.submit("wrong")
        #expect(gate.prompt?.message == "The passphrase does not open this vault.")
        #expect(gate.prompt?.isChecking == false)

        await gate.submit(PreviewVaultService.passphrase)
        #expect(await task.value == true)
        #expect(gate.prompt == nil)
        #expect(!gate.isChecking)
    }

    @Test("cancel refuses the action")
    func cancel() async {
        let (gate, _) = makeGate(answer: false)
        let task = await confirmWithPrompt(gate)
        gate.cancel()
        #expect(await task.value == false)
        #expect(gate.prompt == nil)
        #expect(!gate.isChecking)
    }

    @Test("an empty passphrase asks for one and keeps the prompt")
    func emptyPassphrase() async {
        let (gate, _) = makeGate(answer: false)
        let task = await confirmWithPrompt(gate)
        await gate.submit("")
        #expect(gate.prompt?.message == "Type the passphrase.")
        gate.cancel()
        #expect(await task.value == false)
    }

    @Test("a second confirm while the first waits answers false at once")
    func secondConfirm() async {
        let (gate, check) = makeGate(answer: false)
        let first = await confirmWithPrompt(gate)
        #expect(await gate.confirm(reason: "Another action") == false)
        #expect(check.calls == 1)
        #expect(gate.prompt != nil)
        gate.cancel()
        #expect(await first.value == false)
    }

    @Test("submit without a prompt does nothing")
    func submitWithoutPrompt() async {
        let (gate, _) = makeGate(answer: true)
        await gate.submit(PreviewVaultService.passphrase)
        #expect(gate.prompt == nil)
    }
}
