import Foundation
import Testing

@testable import ApassyVaultKit

/// The agents of the Macs (ios-core-v1 section 5.12): the models of the feed and the preview
/// service that keeps them in memory. Synthetic values of the contract's examples.
@Suite struct FeedModelTests {
    private func decode<Value: Decodable>(_ type: Value.Type, _ json: String) throws -> Value {
        try JSONDecoder().decode(type, from: Data(json.utf8))
    }

    /// The code of the error that a call throws, or nil when it does not throw.
    private func failure(_ body: () async throws -> Void) async -> VaultError.Code? {
        do {
            try await body()
            return nil
        } catch let error as VaultError {
            return error.code
        } catch {
            return nil
        }
    }

    @Test func theListOfTheContractDecodes() throws {
        let json = """
            {"vaults": [
              {"vault_id": "4f1c0a2b-9d8e-4f6a-8b4c-3d2e1f0a9b8c", "vault_name": "Personal", "team_id": "t_7k2m5q4x3c",
               "registered": true, "answer_key": true, "error": null,
               "macs": [
                 {"device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", "relay_device_id": 2, "name": "MacBook Pro",
                  "seq": 1790000040, "generated_at": 1790000040, "stale": false, "truncated": false,
                  "problem": null, "week": {"by_you": 3, "automatic": 128},
                  "agents": [
                    {"id": "4", "name": "Claude Code", "host": "claude", "where": "mac", "revoked": false,
                     "token_expires_at": 1797776000, "last_use_at": 1790000010, "uses_this_week": 12,
                     "projects": ["synthetic-shop"], "note": "Deploys only from the main branch.",
                     "restricted": false,
                     "actions": [{"action": "deploy", "allowed": 2, "not_allowed": 1, "projects": ["synthetic-shop"]}],
                     "exceptions": [{"item": "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c", "item_title": "Shop database",
                                     "title": null, "here": false, "kind": "never", "created_at": 1789990000}],
                     "recent": [{"at": 1790000010, "item": "8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e",
                                 "item_title": "API token", "title": "API token", "here": true,
                                 "action": "deploy", "project": "synthetic-shop",
                                 "command": "npm run deploy -- --token [apassy:secret]",
                                 "outcome": "allowed", "decided_by": "owner", "answered_on": "Test iPhone"}]}]}]}]}
            """
        let list = try decode(FeedList.self, json)
        let vault = try #require(list.vaults.first)
        #expect(list.vaults.count == 1)
        #expect(vault.vaultID == "4f1c0a2b-9d8e-4f6a-8b4c-3d2e1f0a9b8c")
        #expect(vault.vaultName == "Personal")
        #expect(vault.teamID == "t_7k2m5q4x3c")
        #expect(vault.registered)
        #expect(vault.answerKey)
        #expect(vault.error == nil)

        let mac = try #require(vault.macs.first)
        #expect(mac.device == "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d")
        #expect(mac.relayDeviceID == 2)
        #expect(mac.name == "MacBook Pro")
        #expect(mac.seq == 1_790_000_040)
        #expect(mac.generatedAt == 1_790_000_040)
        #expect(mac.stale == false)
        #expect(mac.truncated == false)
        #expect(mac.problem == nil)
        #expect(mac.week == FeedWeek(byYou: 3, automatic: 128))

        let agent = try #require(mac.agents.first)
        #expect(agent.id == "4")
        #expect(agent.name == "Claude Code")
        #expect(agent.host == .claude)
        #expect(agent.place == "mac")
        #expect(agent.revoked == false)
        #expect(agent.usesThisWeek == 12)
        #expect(agent.lastUseAt == 1_790_000_010)
        #expect(agent.tokenExpiresAt == 1_797_776_000)
        #expect(agent.projects == ["synthetic-shop"])
        #expect(agent.note == "Deploys only from the main branch.")
        #expect(agent.restricted == false)

        let action = try #require(agent.actions.first)
        #expect(action.action == .deploy)
        #expect(action.allowed == 2)
        #expect(action.notAllowed == 1)
        #expect(action.projects == ["synthetic-shop"])

        let exception = try #require(agent.exceptions.first)
        #expect(exception.item == "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c")
        #expect(exception.itemTitle == "Shop database")
        #expect(exception.title == nil)
        #expect(exception.here == false)
        #expect(exception.kind == .never)
        #expect(exception.createdAt == 1_789_990_000)

        let use = try #require(agent.recent.first)
        #expect(use.at == 1_790_000_010)
        #expect(use.item == "8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e")
        #expect(use.title == "API token")
        #expect(use.here == true)
        #expect(use.action == .deploy)
        #expect(use.project == "synthetic-shop")
        #expect(use.command.contains("[apassy:secret]"))
        #expect(use.outcome == .allowed)
        #expect(use.decidedBy == .owner)
        #expect(use.answeredOn == "Test iPhone")
    }

    @Test func aNewerCoreNeverEmptiesTheList() throws {
        let json = """
            {"vaults": [
              {"vault_id": "4f1c0a2b-9d8e-4f6a-8b4c-3d2e1f0a9b8c", "vault_name": "Personal", "team_id": "t_7k2m5q4x3c",
               "future": {"a": 1},
               "macs": [
                 {"device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", "name": "MacBook Pro", "seq": 5,
                  "generated_at": 5, "colour": "grey",
                  "week": {"by_you": 1, "automatic": 2, "extra": true},
                  "agents": [
                    {"name": "No id", "host": "claude"},
                    {"id": "6", "name": "Cursor", "host": "cursor", "where": "mac", "uses_this_week": "12",
                     "icon": "x",
                     "actions": [
                       {"action": "launch", "allowed": 4},
                       {"action": "read", "allowed": 3, "later": 1}],
                     "exceptions": [
                       {"item": "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c", "item_title": "Sometimes", "kind": "sometimes",
                        "created_at": 1789990000},
                       {"item": "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a3d", "item_title": "Kept", "kind": "always_ask",
                        "created_at": 1789990001, "tag": 1}],
                     "recent": [{"at": 1790000010, "item": null, "item_title": "", "action": "read", "extra": []}]},
                    {"id": "7", "name": "Codex", "host": "codex"}]},
                 {"device": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "name": "Mac mini",
                  "seq": null, "generated_at": null, "week": null}]}]}
            """
        let list = try decode(FeedList.self, json)
        let vault = try #require(list.vaults.first)
        #expect(vault.macs.count == 2)

        let first = vault.macs[0]
        #expect(first.week == FeedWeek(byYou: 1, automatic: 2))
        // The agent without an id is left out; the second one stays.
        #expect(first.agents.map(\.id) == ["6", "7"])

        let cursor = first.agents[0]
        #expect(cursor.host == .other)
        #expect(cursor.usesThisWeek == 0)
        #expect(cursor.actions.map(\.action) == [.read])
        #expect(cursor.exceptions.count == 1)
        #expect(cursor.exceptions.first?.itemTitle == "Kept")
        #expect(cursor.exceptions.first?.kind == .alwaysAsk)
        #expect(cursor.recent.count == 1)

        let empty = vault.macs[1]
        #expect(empty.agents.isEmpty)
        #expect(empty.seq == nil)
        #expect(empty.generatedAt == nil)
        #expect(empty.week == nil)
    }

    @Test func aDeletedCredentialHasNoItem() throws {
        let json = """
            {"vaults": [
              {"vault_id": "4f1c0a2b-9d8e-4f6a-8b4c-3d2e1f0a9b8c", "vault_name": "Personal", "team_id": "t_7k2m5q4x3c",
               "macs": [
                 {"device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", "name": "MacBook Pro",
                  "agents": [
                    {"id": "4", "name": "Claude Code", "host": "claude",
                     "exceptions": [{"item": null, "item_title": "", "title": null, "here": null,
                                     "kind": "never", "created_at": 1789990000}],
                     "recent": [{"at": 1790000010, "item": null, "item_title": "", "title": null, "here": null,
                                 "action": "read", "outcome": "refused", "decided_by": "bouncer"}]}]}]}]}
            """
        let list = try decode(FeedList.self, json)
        let agent = try #require(list.vaults.first?.macs.first?.agents.first)
        let exception = try #require(agent.exceptions.first)
        #expect(exception.item == nil)
        #expect(exception.itemTitle == "")
        #expect(exception.here == nil)
        let use = try #require(agent.recent.first)
        #expect(use.item == nil)
        #expect(use.itemTitle == "")
        #expect(use.outcome == .refused)
    }

    @Test func thePreparedActionDecodes() throws {
        let json = #"""
            {"vault_id": "4f1c0a2b-9d8e-4f6a-8b4c-3d2e1f0a9b8c", "team_id": "t_7k2m5q4x3c",
             "action_id": "sLGys7S1tre4ubq7vL2-vw", "time": 1790000060, "feed_seq": 1790000040,
             "action_string": "apassy-feed-action-v1\nsynthetic", "needs_face_id": true,
             "face_id_reason": "remove an exception of agent \"Claude Code\""}
            """#
        let prepared = try decode(PreparedFeedAction.self, json)
        #expect(prepared.vaultID == "4f1c0a2b-9d8e-4f6a-8b4c-3d2e1f0a9b8c")
        #expect(prepared.teamID == "t_7k2m5q4x3c")
        #expect(prepared.actionID == "sLGys7S1tre4ubq7vL2-vw")
        #expect(prepared.time == 1_790_000_060)
        #expect(prepared.feedSeq == 1_790_000_040)
        #expect(prepared.actionString == "apassy-feed-action-v1\nsynthetic")
        #expect(prepared.needsFaceID)
        #expect(prepared.faceIDReason == "remove an exception of agent \"Claude Code\"")
    }

    @Test func aPreparedActionWithoutTheFlagAsksForFaceID() throws {
        let json = """
            {"vault_id": "4f1c0a2b-9d8e-4f6a-8b4c-3d2e1f0a9b8c", "team_id": "t_7k2m5q4x3c",
             "action_id": "sLGys7S1tre4ubq7vL2-vw", "time": 1790000060, "action_string": "s"}
            """
        let prepared = try decode(PreparedFeedAction.self, json)
        #expect(prepared.needsFaceID)
        #expect(prepared.feedSeq == nil)
        #expect(prepared.faceIDReason == "")
    }

    @Test func theOutcomesDecode() throws {
        let applied = try decode(
            FeedActionOutcome.self,
            """
            {"action_id": "sLGys7S1tre4ubq7vL2-vw", "outcome": "applied", "verified": true, "reason": null,
             "feed_seq": 1790000070, "at": 1790000061}
            """)
        #expect(applied.actionID == "sLGys7S1tre4ubq7vL2-vw")
        #expect(applied.outcome == .applied)
        #expect(applied.verified)
        #expect(applied.reason == nil)
        #expect(applied.feedSeq == 1_790_000_070)
        #expect(applied.at == 1_790_000_061)

        let refused = try decode(
            FeedActionOutcome.self,
            """
            {"action_id": "a", "outcome": "refused", "verified": true, "reason": "The owner changed it."}
            """)
        #expect(refused.outcome == .refused)
        #expect(refused.reason == "The owner changed it.")

        for (word, expected) in [("stale", FeedActionOutcome.Outcome.stale), ("expired", .expired), ("pending", .pending)] {
            let outcome = try decode(
                FeedActionOutcome.self, """
                {"action_id": "a", "outcome": "\(word)", "verified": true}
                """)
            #expect(outcome.outcome == expected)
        }

        // An outcome of a later version is still open, as far as this app knows.
        let later = try decode(
            FeedActionOutcome.self, """
            {"action_id": "a", "outcome": "postponed"}
            """)
        #expect(later.outcome == .pending)
        // Without `verified` the outcome is the relay's word only.
        #expect(later.verified == false)
    }

    @Test func theSentActionDecodes() throws {
        let sent = try decode(
            SentFeedAction.self,
            """
            {"action_id": "sLGys7S1tre4ubq7vL2-vw", "seq": 9, "created_at": 1790000060, "expires_at": 1790000360}
            """)
        #expect(sent.actionID == "sLGys7S1tre4ubq7vL2-vw")
        #expect(sent.seq == 9)
        #expect(sent.createdAt == 1_790_000_060)
        #expect(sent.expiresAt == 1_790_000_360)

        // The relay had the action already (a retry).
        let retry = try decode(
            SentFeedAction.self,
            """
            {"action_id": "sLGys7S1tre4ubq7vL2-vw", "seq": null, "created_at": null, "expires_at": null}
            """)
        #expect(retry.actionID == "sLGys7S1tre4ubq7vL2-vw")
        #expect(retry.seq == nil)
        #expect(retry.createdAt == nil)
        #expect(retry.expiresAt == nil)
    }

    @Test func theRemovalHasTheParametersOfTheCore() {
        let removal = FeedRemoval(
            vaultID: "4f1c0a2b-9d8e-4f6a-8b4c-3d2e1f0a9b8c", macDevice: "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d",
            agent: "4", item: "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c", kind: .alwaysAsk, createdAt: 1_789_990_000)
        let parameters = removal.parameters
        #expect(Set(parameters.keys) == ["vault_id", "mac_device", "agent", "item", "kind", "created_at"])
        #expect(parameters["vault_id"] as? String == "4f1c0a2b-9d8e-4f6a-8b4c-3d2e1f0a9b8c")
        #expect(parameters["mac_device"] as? String == "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d")
        #expect(parameters["agent"] as? String == "4")
        #expect(parameters["item"] as? String == "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c")
        #expect(parameters["kind"] as? String == "always_ask")
        #expect(parameters["created_at"] as? Int64 == 1_789_990_000)
    }

    @Test func onlyTheFaceIDKindsNeedFaceID() {
        #expect(FeedExceptionKind.never.needsFaceID)
        #expect(FeedExceptionKind.alwaysAsk.needsFaceID)
        #expect(FeedExceptionKind.only.needsFaceID == false)
    }

    // MARK: The preview service

    /// The removal of the first exception of the agent, as the feed shows it.
    private func removal(
        _ vaults: [FeedVault], vault vaultName: String, mac device: String, agent name: String, agentID: String,
        kind: FeedExceptionKind? = nil
    ) throws -> FeedRemoval {
        let vault = try #require(vaults.first { $0.vaultName == vaultName })
        let mac = try #require(vault.macs.first { $0.device == device })
        let agent = try #require(mac.agents.first { $0.id == agentID && $0.name == name })
        let exception = try #require(agent.exceptions.first { kind == nil || $0.kind == kind })
        return FeedRemoval(
            vaultID: vault.vaultID, macDevice: mac.device, agent: agent.id, item: try #require(exception.item),
            kind: exception.kind, createdAt: exception.createdAt)
    }

    private func previewService() async -> (PreviewVaultService, [FeedVault]) {
        let service = PreviewVaultService()
        let vaults = PreviewVaultService.sampleFeed()
        await service.setFeed(vaults)
        return (service, vaults)
    }

    @Test func thePreviewSignsOnlyTheFaceIDKinds() async throws {
        let (service, vaults) = await previewService()

        // "Always ask" of Claude Code on the Mac mini of Personal: Face ID and the key of its team.
        let alwaysAsk = try removal(
            vaults, vault: "Personal", mac: PreviewVaultService.PreviewMacs.macMini, agent: "Claude Code",
            agentID: "4", kind: .alwaysAsk)
        let prepared = try await service.feedActionString(alwaysAsk, actionID: nil, time: nil)
        #expect(prepared.needsFaceID)
        #expect(prepared.teamID == "t_7k2m5q4x3c")
        #expect(
            await failure {
                _ = try await service.feedAction(
                    alwaysAsk, actionID: prepared.actionID, time: prepared.time, signature: nil)
            } == .invalidInput)
        _ = try await service.feedAction(
            alwaysAsk, actionID: prepared.actionID, time: prepared.time, signature: Data("sig".utf8))
        #expect(await service.sentFeedActions().count == 1)

        // "Only" of Claude Code on the Mac of Work: the core signs it, so a signature is refused.
        let only = try removal(
            vaults, vault: "Work", mac: PreviewVaultService.PreviewMacs.workMacBookPro, agent: "Claude Code",
            agentID: "3", kind: .only)
        let preparedOnly = try await service.feedActionString(only, actionID: nil, time: nil)
        #expect(preparedOnly.needsFaceID == false)
        #expect(preparedOnly.teamID == "t_wq3k7m2p5x")
        #expect(
            await failure {
                _ = try await service.feedAction(
                    only, actionID: preparedOnly.actionID, time: preparedOnly.time, signature: Data("sig".utf8))
            } == .invalidInput)
        _ = try await service.feedAction(
            only, actionID: preparedOnly.actionID, time: preparedOnly.time, signature: nil)
        #expect(await service.sentFeedActions().count == 2)
        #expect(await service.preparedFeedActions().count == 2)
    }

    @Test func anAppliedRemovalLeavesTheList() async throws {
        let (service, vaults) = await previewService()
        let target = try removal(
            vaults, vault: "Personal", mac: PreviewVaultService.PreviewMacs.macMini, agent: "Claude Code",
            agentID: "4", kind: .alwaysAsk)
        func listed() async throws -> Bool {
            let list = try await service.feedList()
            let agents = list.vaults.flatMap(\.macs).flatMap(\.agents)
            return agents.contains { $0.exceptions.contains { $0.item == target.item && $0.kind == target.kind } }
        }
        #expect(try await listed())

        let prepared = try await service.feedActionString(target, actionID: nil, time: nil)
        let sent = try await service.feedAction(
            target, actionID: prepared.actionID, time: prepared.time, signature: Data("sig".utf8))
        #expect(sent.actionID == prepared.actionID)
        let outcome = try await service.feedActionWait(actionID: prepared.actionID, vaultID: target.vaultID, timeout: 1)
        #expect(outcome.outcome == .applied)
        #expect(outcome.verified)
        // Claude Code keeps no other exception on this Mac: the one that was removed is gone.
        let list = try await service.feedList()
        let agent = try #require(list.vaults.first { $0.vaultID == target.vaultID }?.macs.first {
            $0.device == target.macDevice
        }?.agents.first { $0.id == target.agent })
        #expect(agent.exceptions.isEmpty)
    }

    @Test func aScriptedRefusalKeepsTheException() async throws {
        let (service, vaults) = await previewService()
        let target = try removal(
            vaults, vault: "Personal", mac: PreviewVaultService.PreviewMacs.macMini, agent: "Claude Code",
            agentID: "4", kind: .alwaysAsk)
        await service.scriptFeedOutcomes([.init(.refused, reason: "The owner changed it.")])

        let prepared = try await service.feedActionString(target, actionID: nil, time: nil)
        _ = try await service.feedAction(
            target, actionID: prepared.actionID, time: prepared.time, signature: Data("sig".utf8))
        let outcome = try await service.feedActionWait(actionID: prepared.actionID, vaultID: target.vaultID, timeout: 1)
        #expect(outcome.outcome == .refused)
        #expect(outcome.reason == "The owner changed it.")

        let list = try await service.feedList()
        let agent = try #require(list.vaults.first { $0.vaultID == target.vaultID }?.macs.first {
            $0.device == target.macDevice
        }?.agents.first { $0.id == target.agent })
        #expect(agent.exceptions.contains { $0.item == target.item && $0.kind == target.kind })
    }

    @Test func aStaleMacTakesNoAction() async throws {
        let (service, vaults) = await previewService()
        let target = try removal(
            vaults, vault: "Personal", mac: PreviewVaultService.PreviewMacs.macBookPro, agent: "CI on GitHub",
            agentID: "2")
        let prepared = try await service.feedActionString(target, actionID: nil, time: nil)
        #expect(
            await failure {
                _ = try await service.feedAction(
                    target, actionID: prepared.actionID, time: prepared.time, signature: Data("sig".utf8))
            } == .staleFeed)
        #expect(await service.sentFeedActions().isEmpty)
    }

    @Test func aMacSaysWhetherThisIPhoneCanActOnItsFeed() throws {
        let mac = { (member: String) in
            """
            {"device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", "name": "Mac mini"\(member)}
            """
        }
        #expect(try decode(FeedMac.self, mac("")).canAct)  // an older core
        #expect(try decode(FeedMac.self, mac(", \"can_act\": true")).canAct)
        #expect(try decode(FeedMac.self, mac(", \"can_act\": false")).canAct == false)
        #expect(try decode(FeedMac.self, mac(", \"can_act\": \"no\"")).canAct)
    }

    @Test func thePreviewSendsThePreparedStringAfterANewerFeed() async throws {
        let (service, vaults) = await previewService()
        let target = try removal(
            vaults, vault: "Personal", mac: PreviewVaultService.PreviewMacs.macMini, agent: "Codex",
            agentID: "7", kind: .never)
        let prepared = try await service.feedActionString(target, actionID: nil, time: nil)
        // A newer feed of the Mac lands during Face ID, with the exception still in it.
        var newer = vaults
        newer[0].macs[0].seq = (newer[0].macs[0].seq ?? 0) + 5
        await service.setFeed(newer)
        _ = try await service.feedAction(
            target, actionID: prepared.actionID, time: prepared.time, signature: Data("sig".utf8))
        let sent = try #require(await service.sentFeedActions().first)
        #expect(sent.feedSeq == prepared.feedSeq)
        #expect(sent.actionString == prepared.actionString)

        // The next one lands without it: the list changed, nothing is sent.
        let again = try await service.feedActionString(target, actionID: nil, time: nil)
        newer[0].macs[0].agents[1].exceptions = []
        await service.setFeed(newer)
        #expect(
            await failure {
                _ = try await service.feedAction(
                    target, actionID: again.actionID, time: again.time, signature: Data("sig".utf8))
            } == .notFound)
        #expect(await service.sentFeedActions().count == 1)
    }

    @Test func aLockDropsTheFeed() async throws {
        let (service, _) = await previewService()
        let list = try await service.feedList()
        #expect(list.vaults.count == 2)

        try await service.lock()
        #expect(
            await failure {
                _ = try await service.feedList()
            } == .locked)
    }

    @Test func anOlderServiceIsUnsupported() {
        #expect(VaultError.feedUnsupported.code == .unsupported)
    }
}
