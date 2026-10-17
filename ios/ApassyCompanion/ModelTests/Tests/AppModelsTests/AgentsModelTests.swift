import ApassyCompanionKit
import ApassyVaultKit
import Foundation
import Testing

@testable import AppModels

/// The Agents tab on the relay feed (contract relay-feed-v1; ios-core-v1 section 5.12), with the
/// synthetic feeds of the preview service: two Macs and two vaults. No value is real.
@MainActor
@Suite("AgentsModel")
struct AgentsModelTests {
    static let personalTeam = "t_7k2m5q4x3c"
    static let workTeam = "t_wq3k7m2p5x"

    @MainActor
    final class Fixture {
        let service = PreviewVaultService()
        let keys = ScriptedKeyStore()
        let now = Date()
        let model: AgentsModel

        init(feed: [FeedVault]? = nil, registered: [String: Data] = [:], signers: (any AnswerSigners)? = nil) async {
            keys.add(service: TeamAnswerSigners.service(team: AgentsModelTests.personalTeam))
            keys.add(service: TeamAnswerSigners.service(team: AgentsModelTests.workTeam))
            model = AgentsModel(
                service: service, signers: signers ?? TeamAnswerSigners(store: keys),
                registeredKey: { _, team in registered[team] }, retryInterval: .milliseconds(10), actionWait: 0)
            await service.setFeed(feed ?? PreviewVaultService.sampleFeed(now: now))
        }

        func entry(vault: String, mac: String, agent: String) throws -> AgentEntry {
            try #require(
                model.sections.first { $0.vaultName == vault && $0.mac.name == mac }?.agents.first {
                    $0.agent.name == agent
                })
        }

        func exception(_ entry: AgentEntry, _ kind: FeedExceptionKind) throws -> FeedException {
            try #require(entry.agent.exceptions.first { $0.kind == kind })
        }
    }

    // MARK: States

    @Test func theListStartsLoadingThenShowsTheFeeds() async throws {
        let fixture = await Fixture()
        #expect(fixture.model.phase == .loading)
        await fixture.model.refresh()
        #expect(fixture.model.phase == .ready)
        #expect(fixture.model.screen == .list)
        #expect(fixture.model.vaults.count == 2)
        #expect(fixture.model.agentCount == 6)
        #expect(fixture.model.agentCount == fixture.model.sections.flatMap(\.agents).count)
    }

    @Test func withoutAFeedTheTabSaysWhereTheAgentsAre() async throws {
        let fixture = await Fixture(feed: [])
        #expect(fixture.model.screen == .loading)
        await fixture.model.refresh()
        #expect(fixture.model.phase == .noFeed)
        #expect(fixture.model.screen == .reach)

        // A vault whose Macs publish nothing yet is no feed either.
        await fixture.service.setFeed([
            FeedVault(vaultID: "v1", vaultName: "Personal", teamID: Self.personalTeam, macs: [])
        ])
        await fixture.model.refresh()
        #expect(fixture.model.phase == .noFeed)

        // A relay without feeds.
        await fixture.service.failNextFeedList(VaultError(.feedUnavailable, "The relay does not show agents yet."))
        await fixture.model.refresh()
        #expect(fixture.model.phase == .noFeed)
    }

    @Test func anOlderCoreKeepsTheHonestScreen() async throws {
        let model = AgentsModel(service: SpyVaultService(), signers: TeamAnswerSigners(store: ScriptedKeyStore()))
        await model.refresh()
        #expect(model.phase == .noFeed)
        #expect(model.vaults.isEmpty)
    }

    @Test func aFailureShowsAnErrorOrANoticeOverTheList() async throws {
        let fixture = await Fixture()
        await fixture.service.failNextFeedList(VaultError(.relayUnreachable, "The relay does not answer."))
        await fixture.model.refresh()
        #expect(fixture.model.phase == .failed("The relay does not answer."))

        await fixture.model.refresh()
        #expect(fixture.model.phase == .ready)
        await fixture.service.failNextFeedList(VaultError(.relayUnreachable, "The relay does not answer."))
        await fixture.model.refresh()
        // The list stays, with the problem under it.
        #expect(fixture.model.phase == .ready)
        #expect(fixture.model.notice == "The relay does not answer.")
        #expect(!fixture.model.sections.isEmpty)
    }

    @Test func aMacWithAProblemIsListedWithItsText() async throws {
        let problem = FeedMac(
            device: PreviewVaultService.PreviewMacs.macMini, name: "Mac mini",
            problem: "Sync this vault to see the agents of Mac mini.")
        let fixture = await Fixture(feed: [
            FeedVault(vaultID: "v1", vaultName: "Personal", teamID: Self.personalTeam, macs: [problem])
        ])
        await fixture.model.refresh()
        #expect(fixture.model.phase == .ready)
        #expect(fixture.model.sections.first?.mac.problem == "Sync this vault to see the agents of Mac mini.")
        #expect(fixture.model.sections.first?.agents.isEmpty == true)
    }

    @Test func theWatchReadsTheListAgainAfterAChange() async throws {
        let fixture = await Fixture()
        await fixture.service.scriptFeedWaits([true])
        let watch = Task { await fixture.model.watch() }
        defer { watch.cancel() }
        #expect(await waitUntil { fixture.model.phase == .ready })
        var calls = 0
        for _ in 0..<200 {
            calls = await fixture.service.feedListCalls()
            if calls >= 2 { break }
            try await Task.sleep(for: .milliseconds(10))
        }
        #expect(calls >= 2)
    }

    // MARK: Grouping

    @Test func agentsAreGroupedByMacAndByVault() async throws {
        let fixture = await Fixture()
        await fixture.model.refresh()
        let sections = fixture.model.sections
        #expect(fixture.model.namesVaults)
        #expect(
            sections.map(\.title) == [
                "Personal · Mac mini", "Personal · MacBook Pro", "Work · MacBook Pro",
            ])
        #expect(sections[0].agents.map(\.agent.name) == ["Claude Code", "Codex", "T3 Code"])
        #expect(sections[2].agents.map(\.agent.name) == ["Claude Code", "Release bot"])
        // The same agent name on two Macs are two rows.
        let ids = sections.flatMap(\.agents).map(\.id)
        #expect(Set(ids).count == ids.count)
        let claude = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Claude Code")
        #expect(fixture.model.entry(claude.id) == claude)
        #expect(AgentsText.subtitle(claude) == "Mac mini · 54 uses this week")
        let bot = try fixture.entry(vault: "Work", mac: "MacBook Pro", agent: "Release bot")
        #expect(AgentsText.subtitle(bot) == "MacBook Pro · Disconnected")
    }

    @Test func oneVaultNamesOnlyTheMacs() async throws {
        let personal = PreviewVaultService.sampleFeed().filter { $0.vaultName == "Personal" }
        let fixture = await Fixture(feed: personal)
        await fixture.model.refresh()
        #expect(!fixture.model.namesVaults)
        #expect(fixture.model.sections.map(\.title) == ["Mac mini", "MacBook Pro"])
    }

    @Test func theTextsOfAnAgent() {
        let now = Date(timeIntervalSince1970: 1_790_000_000)
        #expect(AgentsText.uses(0) == "No uses this week")
        #expect(AgentsText.uses(1) == "1 use this week")
        #expect(AgentsText.uses(5) == "5 uses this week")
        #expect(AgentsText.ago(1_790_000_030, now: now) == "now")
        #expect(AgentsText.ago(1_790_000_600, now: now) == "now")  // ahead of this iPhone's clock
        #expect(AgentsText.ago(1_789_999_700, now: now) == "5m")
        #expect(AgentsText.ago(1_789_992_800, now: now) == "2h")
        #expect(AgentsText.ago(1_789_827_200, now: now) == "2d")
        let mac = FeedMac(device: "d", name: "Mac mini", generatedAt: 1_789_999_880)
        #expect(AgentsText.from(mac, now: now) == "From Mac mini, 2 min ago")
        let gone = FeedException(item: nil, itemTitle: "", kind: .never, createdAt: 1)
        #expect(AgentsText.exception(gone) == "Never: A deleted credential")
        let away = FeedException(item: "i", itemTitle: "Cloudflare API", here: false, kind: .only, createdAt: 1)
        #expect(AgentsText.exception(away) == "Only: Cloudflare API (not on this iPhone)")
        let here = FeedException(
            item: "i", itemTitle: "Old name", title: "Stripe live key", here: true, kind: .alwaysAsk,
            createdAt: 1)
        #expect(AgentsText.exception(here) == "Always ask: Stripe live key")
        #expect(
            AgentsText.confirmTitle(here, agent: "Codex", mac: "Mac mini")
                == "Remove “Always ask” for Stripe live key from Codex on Mac mini?")
        #expect(AgentsText.confirmMessage(here, agent: "Codex", mac: "Mac mini").contains("Face ID"))
        #expect(!AgentsText.confirmMessage(away, agent: "Codex", mac: "Mac mini").contains("Face ID"))
        let byYou = FeedUse(
            at: 1, item: "i", itemTitle: "t", outcome: .allowed, decidedBy: .owner, answeredOn: "iPhone")
        #expect(AgentsText.mark(byYou) == .allowedByYou)
        #expect(AgentsText.outcome(byYou) == "You allowed it on iPhone")
        #expect(AgentsText.mark(FeedUse(at: 1, item: nil, itemTitle: "", outcome: .refused)) == .denied)
        #expect(AgentsText.mark(FeedUse(at: 1, item: nil, itemTitle: "", outcome: .timedOut)) == .timedOut)
        #expect(AgentsText.outcome(FeedUse(at: 1, item: "i", itemTitle: "t", decidedBy: .rule)) == "Allowed by a rule")
    }

    // MARK: Stale

    @Test func aStaleMacIsDimmedAndTakesNoAction() async throws {
        let fixture = await Fixture()
        await fixture.model.refresh()
        let stale = try #require(fixture.model.sections.first { $0.title == "Personal · MacBook Pro" })
        #expect(stale.mac.stale)
        #expect(AgentsText.from(stale.mac, now: fixture.now) == "From MacBook Pro, 3 days ago")
        #expect(AgentsText.staleNote(stale.mac).hasPrefix("MacBook Pro has not reported since "))
        let ci = try fixture.entry(vault: "Personal", mac: "MacBook Pro", agent: "CI on GitHub")
        let never = try fixture.exception(ci, .never)
        #expect(fixture.model.removalBlock(of: never, in: ci) == "Remove it when MacBook Pro reports again.")

        // Remove does nothing on a stale Mac: no Face ID, nothing sent.
        await fixture.model.remove(never, in: ci)
        #expect(await fixture.service.preparedFeedActions().isEmpty)
        #expect(await fixture.service.sentFeedActions().isEmpty)
        #expect(fixture.model.removals.isEmpty)

        let fresh = try #require(fixture.model.sections.first { $0.title == "Personal · Mac mini" })
        #expect(!fresh.mac.stale)
    }

    @Test func actionsAreOfferedOnlyWhenThisIPhoneCanSendThem() async throws {
        var feed = PreviewVaultService.sampleFeed()
        feed[0].answerKey = false
        feed[1].registered = false
        let fixture = await Fixture(feed: feed)
        await fixture.model.refresh()
        let claude = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Claude Code")
        #expect(
            fixture.model.removalBlock(of: try fixture.exception(claude, .alwaysAsk), in: claude)
                == "Connect this iPhone again on a Mac to use Face ID here.")
        let work = try fixture.entry(vault: "Work", mac: "MacBook Pro", agent: "Claude Code")
        #expect(
            fixture.model.removalBlock(of: try fixture.exception(work, .only), in: work)?.contains("synced") == true)
        let deleted = FeedException(item: nil, itemTitle: "", kind: .never, createdAt: 1)
        #expect(fixture.model.removal(of: deleted, in: claude) == nil)
    }

    // MARK: Removing an exception

    @Test func aNeverRemovalSignsWithTheKeyOfTheVaultsTeamAfterFaceID() async throws {
        let fixture = await Fixture()
        await fixture.model.refresh()
        let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        let never = try fixture.exception(codex, .never)

        await fixture.model.remove(never, in: codex)

        let removal = try #require(fixture.model.removal(of: never, in: codex))
        #expect(fixture.model.removals[removal] == .removed("Removed on Mac mini."))
        let sent = try #require(await fixture.service.sentFeedActions().first)
        #expect(sent.removal == removal)
        #expect(sent.signature == Data("signed by \(TeamAnswerSigners.service(team: Self.personalTeam))".utf8))
        let prepared = try #require(await fixture.service.preparedFeedActions().first)
        #expect(prepared.teamID == Self.personalTeam)
        #expect(sent.actionID == prepared.actionID)
        #expect(sent.time == prepared.time)
        // The row goes away.
        let after = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        #expect(after.agent.exceptions.isEmpty)
    }

    @Test func anAlwaysAskRemovalAsksFaceIDWithTheReasonOfTheCore() async throws {
        let signer = ScriptedSigner()
        let fixture = await Fixture(signers: SharedAnswerSigners(signer: signer))
        await fixture.model.refresh()
        let claude = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Claude Code")
        await fixture.model.remove(try fixture.exception(claude, .alwaysAsk), in: claude)
        #expect(signer.reasons == ["remove an exception of agent \"Claude Code\""])
        #expect(await fixture.service.sentFeedActions().first?.signature == Data("signature".utf8))
    }

    @Test func eachVaultSignsWithItsOwnTeamKey() async throws {
        var feed = PreviewVaultService.sampleFeed()
        let at = Int64(Date().timeIntervalSince1970)
        feed[1].macs[0].agents[0].exceptions.append(
            FeedException(
                item: "5e6f7a8b9c0d4e1f8a2b3c4d5e6f7a8b", itemTitle: "Sentry", kind: .never,
                createdAt: at - 100))
        let fixture = await Fixture(feed: feed)
        await fixture.model.refresh()
        let work = try fixture.entry(vault: "Work", mac: "MacBook Pro", agent: "Claude Code")
        await fixture.model.remove(try fixture.exception(work, .never), in: work)
        let sent = try #require(await fixture.service.sentFeedActions().first)
        #expect(sent.signature == Data("signed by \(TeamAnswerSigners.service(team: Self.workTeam))".utf8))
        #expect(sent.removal.vaultID == work.vaultID)
    }

    @Test func anOnlyRemovalNeedsNoFaceID() async throws {
        let signer = ScriptedSigner()
        let fixture = await Fixture(signers: SharedAnswerSigners(signer: signer))
        await fixture.model.refresh()
        let work = try fixture.entry(vault: "Work", mac: "MacBook Pro", agent: "Claude Code")
        let only = try fixture.exception(work, .only)
        await fixture.model.remove(only, in: work)
        #expect(signer.reasons.isEmpty)
        let sent = try #require(await fixture.service.sentFeedActions().first)
        #expect(sent.signature == nil)
        let removal = try #require(fixture.model.removal(of: only, in: work))
        #expect(fixture.model.removals[removal] == .removed("Removed on MacBook Pro."))
    }

    @Test func refusedStaleAndExpiredSayWhatHappened() async throws {
        let cases: [(PreviewFeed.Scripted, String)] = [
            (.init(.refused, reason: "The exception is in use."), "Mac mini refused it: The exception is in use."),
            (.init(.refused), "Mac mini refused it."),
            (.init(.stale), "Mac mini did not accept it: the exception changed. Pull to refresh."),
            (.init(.expired, verified: false), "Mac mini did not answer. It may be asleep or locked."),
            // A settle that this iPhone cannot open is never "removed" nor "changed".
            (.init(.applied, verified: false), "Not applied, or unknown. Check the list on Mac mini."),
            (.init(.stale, verified: false), "Not applied, or unknown. Check the list on Mac mini."),
            (.init(.refused, verified: false), "Not applied, or unknown. Check the list on Mac mini."),
        ]
        for (scripted, text) in cases {
            let fixture = await Fixture()
            await fixture.service.scriptFeedOutcomes([.init(.pending), scripted])
            await fixture.model.refresh()
            let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
            let never = try fixture.exception(codex, .never)
            await fixture.model.remove(never, in: codex)
            let removal = try #require(fixture.model.removal(of: never, in: codex))
            #expect(fixture.model.removals[removal] == .failed(text))
            // The exception stays.
            #expect(try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex").agent.exceptions == [never])
        }
    }

    /// A signer whose "Face ID" runs `during` before it signs: a new feed lands meanwhile.
    final class SlowFaceID: AnswerSigner {
        let during: @Sendable () async -> Void

        init(during: @escaping @Sendable () async -> Void) { self.during = during }

        func publicKey() throws -> Data { Data([4] + [UInt8](repeating: 1, count: 64)) }

        func sign(_ message: Data, reason: String) async throws -> Data {
            await during()
            return Data("signature".utf8)
        }

        func renew() throws -> Data { try publicKey() }
    }

    @Test func aFeedThatLandsDuringFaceIDStillSendsThePreparedAction() async throws {
        let service = PreviewVaultService()
        let now = Date()
        var newer = PreviewVaultService.sampleFeed(now: now)
        let shown = try #require(newer[0].macs[0].seq)
        newer[0].macs[0].seq = shown + 5
        newer[0].macs[0].generatedAt = Int64(now.timeIntervalSince1970)
        let landed = newer
        let signer = SlowFaceID { await service.setFeed(landed) }
        let model = AgentsModel(
            service: service, signers: SharedAnswerSigners(signer: signer), retryInterval: .milliseconds(10),
            actionWait: 0)
        await service.setFeed(PreviewVaultService.sampleFeed(now: now))
        await model.refresh()
        let codex = try #require(model.sections.first?.agents.first { $0.agent.name == "Codex" })
        let never = try #require(codex.agent.exceptions.first { $0.kind == .never })

        await model.remove(never, in: codex)

        let removal = try #require(model.removal(of: never, in: codex))
        #expect(model.removals[removal] == .removed("Removed on Mac mini."))
        let prepared = try #require(await service.preparedFeedActions().first)
        let sent = try #require(await service.sentFeedActions().first)
        // The string that Face ID signed went out, with the `feed_seq` of the feed shown then.
        #expect(sent.actionString == prepared.actionString)
        #expect(sent.feedSeq == shown)
        #expect(model.sections.first?.mac.seq == shown + 5)
    }

    @Test func anExceptionGoneDuringFaceIDSaysTheListChanged() async throws {
        let service = PreviewVaultService()
        let now = Date()
        var newer = PreviewVaultService.sampleFeed(now: now)
        newer[0].macs[0].seq = (newer[0].macs[0].seq ?? 0) + 5
        newer[0].macs[0].agents[1].exceptions = []
        let landed = newer
        let signer = SlowFaceID { await service.setFeed(landed) }
        let model = AgentsModel(
            service: service, signers: SharedAnswerSigners(signer: signer), retryInterval: .milliseconds(10),
            actionWait: 0)
        await service.setFeed(PreviewVaultService.sampleFeed(now: now))
        await model.refresh()
        let codex = try #require(model.sections.first?.agents.first { $0.agent.name == "Codex" })
        let never = try #require(codex.agent.exceptions.first { $0.kind == .never })

        await model.remove(never, in: codex)

        let removal = try #require(model.removal(of: never, in: codex))
        #expect(model.removals[removal] == .failed("The list on Mac mini changed. Look at it again."))
        #expect(await service.sentFeedActions().isEmpty)
    }

    /// The alert keeps the list as the tap saw it. A feed that lands while it is up (a relay can
    /// swap one in) does not change what is removed: the core refuses the list of another feed,
    /// and nothing is sent.
    @Test func aNewFeedWhileTheAlertIsUpSendsNothing() async throws {
        let fixture = await Fixture()
        await fixture.model.refresh()
        let tapped = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        let never = try fixture.exception(tapped, .never)
        let removal = try #require(fixture.model.removal(of: never, in: tapped))
        #expect(removal.feedSeq == tapped.mac.seq)
        var newer = PreviewVaultService.sampleFeed(now: fixture.now)
        newer[0].macs[0].seq = (newer[0].macs[0].seq ?? 0) + 1
        newer[0].macs[0].agents[1].name = "Scratch Bot"
        await fixture.service.setFeed(newer)
        await fixture.model.refresh()

        await fixture.model.remove(never, in: tapped)

        #expect(fixture.model.removals[removal] == .failed("The list on Mac mini changed. Look at it again."))
        #expect(await fixture.service.sentFeedActions().isEmpty)
    }

    /// The names that the action signs must be those that the alert showed, byte for byte.
    @Test func namesThatDifferFromTheAlertSendNothing() async throws {
        let fixture = await Fixture()
        await fixture.model.refresh()
        let tapped = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        let never = try fixture.exception(tapped, .never)
        // The same feed `seq` with another name for the agent: the core's string names it.
        var renamed = PreviewVaultService.sampleFeed(now: fixture.now)
        renamed[0].macs[0].agents[1].name = "Scratch Bot"
        await fixture.service.setFeed(renamed)

        await fixture.model.remove(never, in: tapped)

        let removal = try #require(fixture.model.removal(of: never, in: tapped))
        #expect(fixture.model.removals[removal] == .failed("The list on Mac mini changed. Look at it again."))
        #expect(await fixture.service.sentFeedActions().isEmpty)
        #expect(try #require(await fixture.service.preparedFeedActions().first).agentName == "Scratch Bot")
    }

    /// A Mac whose feed lacks the mark (Apassy 0.5.2) takes no removal that gives authority back:
    /// the app says to update it instead of offering "Remove". "Only" is still offered, and the
    /// old Mac's "bad form" answer says the same.
    @Test func anOlderMacAsksForAnUpdate() async throws {
        var feed = PreviewVaultService.sampleFeed()
        feed[0].macs[0].checksNames = false
        let fixture = await Fixture(feed: feed)
        await fixture.model.refresh()
        let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        let never = try fixture.exception(codex, .never)
        #expect(
            fixture.model.removalBlock(of: never, in: codex)
                == "Update Apassy on Mac mini to remove this from the iPhone.")
        await fixture.model.remove(never, in: codex)
        #expect(await fixture.service.sentFeedActions().isEmpty)

        let only = FeedException(
            item: "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a09", itemTitle: "Sentry", kind: .only, createdAt: 1_789_990_100)
        #expect(fixture.model.removalBlock(of: only, in: codex) == nil)
    }

    @Test func theAnswerOfAnOlderMacSaysToUpdateIt() async throws {
        let fixture = await Fixture()
        await fixture.service.scriptFeedOutcomes([.init(.refused, reason: "it has a bad form")])
        await fixture.model.refresh()
        let work = try fixture.entry(vault: "Work", mac: "MacBook Pro", agent: "Claude Code")
        let only = try fixture.exception(work, .only)
        await fixture.model.remove(only, in: work)
        let removal = try #require(fixture.model.removal(of: only, in: work))
        #expect(
            fixture.model.removals[removal] == .failed("Update Apassy on MacBook Pro to remove this from the iPhone."))
    }

    @Test func aVaultThatIsNotSelectedAsksToSelectItFirst() async throws {
        var feed = PreviewVaultService.sampleFeed()
        feed[1].macs[0].canAct = false
        let fixture = await Fixture(feed: feed)
        await fixture.model.refresh()
        let work = try fixture.entry(vault: "Work", mac: "MacBook Pro", agent: "Claude Code")
        let only = try fixture.exception(work, .only)
        #expect(
            fixture.model.removalBlock(of: only, in: work)
                == "Select Work on this iPhone to remove exceptions of its agents.")
        await fixture.model.remove(only, in: work)
        #expect(await fixture.service.preparedFeedActions().isEmpty)
        #expect(await fixture.service.sentFeedActions().isEmpty)
        // The selected vault's Macs still can.
        let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        #expect(fixture.model.removalBlock(of: try fixture.exception(codex, .never), in: codex) == nil)
    }

    @Test func seesSaysThatTheMacListsOnlyItsRows() {
        #expect(
            AgentsText.seesFooter(mac: "MacBook Pro")
                == "Listed for this agent on MacBook Pro. Access granted on the Mac is not shown here.")
    }

    @Test func aCancelledFaceIDSendsNothing() async throws {
        let signer = ScriptedSigner()
        signer.fail(with: .cancelled)
        let fixture = await Fixture(signers: SharedAnswerSigners(signer: signer))
        await fixture.model.refresh()
        let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        await fixture.model.remove(try fixture.exception(codex, .never), in: codex)
        #expect(fixture.model.removals.isEmpty)
        #expect(await fixture.service.sentFeedActions().isEmpty)
    }

    @Test func aKeyOfAnotherTeamNeverSigns() async throws {
        let fixture = await Fixture()
        await fixture.model.refresh()
        let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        let never = try fixture.exception(codex, .never)
        // The core now names another team for this vault than the list did.
        var feed = PreviewVaultService.sampleFeed(now: fixture.now)
        feed[0].teamID = Self.workTeam
        await fixture.service.setFeed(feed)

        await fixture.model.remove(never, in: codex)

        let removal = try #require(fixture.model.removal(of: never, in: codex))
        #expect(
            fixture.model.removals[removal]
                == .failed("This action is not for the team of this vault, so nothing was sent."))
        #expect(await fixture.service.sentFeedActions().isEmpty)
    }

    @Test func aRowWithAnotherKeyIsNotSigned() async throws {
        let signer = ScriptedSigner()
        let other = Data([4] + [UInt8](repeating: 9, count: 64))
        let fixture = await Fixture(
            registered: [Self.personalTeam: other], signers: SharedAnswerSigners(signer: signer))
        await fixture.model.refresh()
        let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        let never = try fixture.exception(codex, .never)
        await fixture.model.remove(never, in: codex)
        let removal = try #require(fixture.model.removal(of: never, in: codex))
        #expect(fixture.model.removals[removal] == .failed(QuestionsModel.keyChangedText))
        #expect(signer.reasons.isEmpty)
        #expect(await fixture.service.sentFeedActions().isEmpty)
    }

    @Test func errorsOfTheCoreAreSaidPlainly() async throws {
        let fixture = await Fixture()
        await fixture.model.refresh()
        let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        let never = try fixture.exception(codex, .never)
        let removal = try #require(fixture.model.removal(of: never, in: codex))

        await fixture.service.failNextFeedActionString(VaultError(.notFound, "This list of the Mac changed."))
        await fixture.model.remove(never, in: codex)
        #expect(fixture.model.removals[removal] == .failed("The list on Mac mini changed. Look at it again."))

        await fixture.service.failNextFeedAction(VaultError(.staleAction, "Too old."))
        await fixture.model.remove(never, in: codex)
        #expect(fixture.model.removals[removal] == .failed("This took too long, so nothing was sent. Remove it again."))

        await fixture.service.failNextFeedAction(VaultError(.tooManyActions, "Too many actions in a short time."))
        await fixture.model.remove(never, in: codex)
        #expect(fixture.model.removals[removal] == .failed("Too many actions in a short time."))
        #expect(await fixture.service.sentFeedActions().isEmpty)

        fixture.model.dismissResult(removal)
        #expect(fixture.model.removals[removal] == nil)
    }

    // MARK: The lock

    @Test func aLockClearsEverything() async throws {
        let fixture = await Fixture()
        await fixture.model.refresh()
        let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        await fixture.model.remove(try fixture.exception(codex, .never), in: codex)
        #expect(!fixture.model.removals.isEmpty)

        try await fixture.service.lock()
        fixture.model.vaultDidLock()
        #expect(fixture.model.phase == .locked)
        #expect(fixture.model.screen == .reach)
        #expect(fixture.model.vaults.isEmpty)
        #expect(fixture.model.sections.isEmpty)
        #expect(fixture.model.removals.isEmpty)

        // The core answers `locked` too, until the vault opens again.
        await fixture.model.refresh()
        #expect(fixture.model.phase == .locked)
        try await fixture.service.unlock(passphrase: PreviewVaultService.passphrase, keep: false)
        await fixture.model.refresh()
        #expect(fixture.model.phase == .ready)
    }

    @Test func aLeaveEndsARemovalThatWaitsHonestly() async throws {
        let fixture = await Fixture()
        // The Mac does not settle: the action stays open.
        await fixture.service.scriptFeedOutcomes(Array(repeating: .init(.pending), count: 500))
        await fixture.model.refresh()
        let codex = try fixture.entry(vault: "Personal", mac: "Mac mini", agent: "Codex")
        let never = try fixture.exception(codex, .never)
        let removal = try #require(fixture.model.removal(of: never, in: codex))
        let task = Task { await fixture.model.remove(never, in: codex) }
        #expect(await waitUntil { fixture.model.removals[removal] == .working("Waiting for Mac mini…") })
        fixture.model.vaultWillLeave()
        await task.value
        guard case .failed(let text) = fixture.model.removals[removal] else {
            Issue.record("the removal did not end: \(String(describing: fixture.model.removals[removal]))")
            return
        }
        #expect(text.contains("Pull to refresh"))
    }
}
