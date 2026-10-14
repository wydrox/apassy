import ApassyVaultKit
import SwiftUI

#if DEBUG && targetEnvironment(simulator)

    extension View {
        /// A development aid of the Simulator: with `-ApassyPreviewVault -ApassyPreviewAgents
        /// list|detail|confirm|stale|restricted|unverified|othervault`, the preview vault gets the
        /// synthetic feeds of two Macs and two vaults (`PreviewVaultService.sampleFeed`). `detail`
        /// opens Claude Code on the Mac mini, `confirm` opens Codex and asks to remove its exception,
        /// `stale` opens the agent of the MacBook Pro that has not reported for three days,
        /// `restricted` opens the "only these items" agent of Work, `unverified` removes one of its
        /// rows with a settle that does not open, and `othervault` opens that agent of Work, a vault
        /// that is not selected, with a feed that came after its keys were read (`can_act: false`);
        /// its passphrase counts as stored behind Face ID (`RootModel.agentKeys`). No value is real.
        func agentsPreviewSeed(_ model: AgentsModel?, path: Binding<[String]>) -> some View {
            modifier(AgentsPreviewSeed(model: model, path: path))
        }

        /// With `-ApassyPreviewAgents confirm`, the page of Codex asks to remove its exception.
        func agentsConfirmSeed(_ entry: AgentEntry, ask: @escaping (FeedException) -> Void) -> some View {
            task {
                guard UserDefaults.standard.string(forKey: "ApassyPreviewAgents") == "confirm",
                    entry.agent.name == "Codex", let exception = entry.agent.exceptions.first
                else { return }
                try? await Task.sleep(for: .milliseconds(600))
                ask(exception)
            }
        }
    }

    extension View {
        /// With `-ApassyPreviewAgentsScroll exceptions|sees`, an agent's page scrolls to that section.
        func agentsScrollSeed(_ scroll: @escaping (String) -> Void) -> some View {
            task {
                guard let target = UserDefaults.standard.string(forKey: "ApassyPreviewAgentsScroll"),
                    ["exceptions", "sees"].contains(target)
                else { return }
                try? await Task.sleep(for: .milliseconds(500))
                scroll(target)
            }
        }
    }

    private struct AgentsPreviewSeed: ViewModifier {
        let model: AgentsModel?
        @Binding var path: [String]
        @Environment(VaultModel.self) private var vault: VaultModel?
        @Environment(RootModel.self) private var root: RootModel?

        func body(content: Content) -> some View {
            content.task {
                guard let mode = UserDefaults.standard.string(forKey: "ApassyPreviewAgents"), let model,
                    let service = vault?.service as? PreviewVaultService
                else { return }
                var feed = PreviewVaultService.sampleFeed()
                if mode == "othervault", let work = feed.firstIndex(where: { $0.vaultName == "Work" }) {
                    for mac in feed[work].macs.indices { feed[work].macs[mac].canAct = false }
                    await service.addQuestionsVault(
                        id: feed[work].vaultID, name: feed[work].vaultName, team: feed[work].teamID, onPhone: true)
                }
                // The rows of this iPhone hold the answer key of each team (software keys in the
                // Simulator), as after a confirmed connection.
                for team in Set(feed.map(\.teamID)) { _ = try? root?.answerSigners.joinKey(team: team) }
                await service.setFeed(feed)
                await model.refresh()
                let open: (vault: String, mac: String, agent: String)? =
                    switch mode {
                    case "detail": ("Personal", "Mac mini", "Claude Code")
                    case "confirm": ("Personal", "Mac mini", "Codex")
                    case "stale": ("Personal", "MacBook Pro", "CI on GitHub")
                    case "restricted", "unverified", "othervault": ("Work", "MacBook Pro", "Claude Code")
                    default: nil
                    }
                guard let open,
                    let entry = model.sections.first(where: { $0.vaultName == open.vault && $0.mac.name == open.mac })?
                        .agents.first(where: { $0.agent.name == open.agent })
                else { return }
                path = [entry.id]
                // `unverified`: the relay answers the removal of an "only" row with a settle that
                // this iPhone cannot open.
                if mode == "unverified", let only = entry.agent.exceptions.first(where: { $0.kind == .only }) {
                    await service.scriptFeedOutcomes([.init(.applied, verified: false)])
                    try? await Task.sleep(for: .milliseconds(800))
                    await model.remove(only, in: entry)
                }
            }
        }
    }

#endif
