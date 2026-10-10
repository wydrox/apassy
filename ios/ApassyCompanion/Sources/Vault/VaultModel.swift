import ApassyVaultKit
import Foundation
import Observation

/// The vault on this iPhone: which vault is selected, the lock, the items, the relay sync, and the
/// actions on items. Everything goes through `VaultService`; secrets are never kept here, only
/// the rows (titles, usernames, websites) while the vault is unlocked.
@MainActor
@Observable
final class VaultModel {
    /// What the app does around the model, without UIKit, so tests can pass their own.
    struct Hooks {
        /// Put a value on the pasteboard: `SecureClipboard.copy` with the setting.
        var copy: @MainActor (_ value: String, _ secret: Bool) -> Void = { _, _ in }
        /// Replace the AutoFill identities of a vault: logins, passkeys, and one-time passwords
        /// (`CredentialIdentitySync.replace`).
        var replaceIdentities: @MainActor (IdentitySet, String) async -> Void = { _, _ in }
        /// Remove every QuickType identity (`CredentialIdentitySync.removeAll`).
        var removeAllIdentities: @MainActor () async -> Void = {}
        /// Ask iOS for time to finish a vault write in the background; returns the end of it.
        var beginBackgroundWork: @MainActor (String) -> @MainActor () -> Void = { _ in {} }

        init() {}
    }

    /// The times of the sync loop and of a save; tests make them short.
    struct Timing {
        var waitTimeout = 25
        var firstBackoff = Duration.seconds(5)
        var maxBackoff = Duration.seconds(60)
        var saveDebounce = Duration.seconds(2)
        /// The clock of the auto-lock: continuous, so it counts while the iPhone sleeps and does
        /// not move when the owner sets the clock of the iPhone back.
        var now: @MainActor () -> ContinuousClock.Instant = { ContinuousClock.now }
    }

    // MARK: State

    private(set) var info: CoreInfo?
    /// Why `info` could not be read, for the error screen.
    private(set) var startError: String?
    private(set) var isUnlocked = false
    /// The app is away and the vault is closed with the passphrase kept (`suspend`). The screens
    /// stay unlocked behind the privacy cover until the app is back.
    private(set) var isSuspended = false
    /// Every item of the selected vault, archived ones too, while it is unlocked.
    private(set) var items: [ItemRow] = []
    /// Bumped after each reload, so open item screens load their item again.
    private(set) var itemsVersion = 0
    private(set) var syncStatus: SyncStatus?
    private(set) var isSyncing = false
    private(set) var watchtower: WatchtowerReport?
    /// Bumped when revealed values must go: the app left the screen, or the vault locked.
    private(set) var revealEpoch = 0

    // The lock screen.
    private(set) var isUnlocking = false
    var unlockMessage: String?
    /// iOS dropped the stored passphrase (a new Face ID enrollment). The next unlock stores it again.
    private(set) var faceIDNeedsRepair = false

    /// A message for an alert after a failed action.
    var alert: String?

    /// Show the error of an action. A vault that the core closed (`locked`) shows the lock screen.
    func report(_ error: any Error) {
        if (error as? VaultError)?.code == .locked {
            Task { await closedByCore() }
            return
        }
        alert = error.localizedDescription
    }

    /// The core answered `locked`. While the app is away or the vault is suspended that is
    /// expected, and a lock would erase the kept passphrase; else the lock screen shows.
    private func closedByCore() async {
        guard !isSuspended, !isInBackground else { return }
        await lock()
    }

    let settings: VaultSettings
    let gate: OwnerGate
    let service: any VaultService
    @ObservationIgnored let passphraseStore: any PassphraseStore
    @ObservationIgnored private let hooks: Hooks
    @ObservationIgnored private let timing: Timing
    @ObservationIgnored private var syncTask: Task<Void, Never>?
    @ObservationIgnored private var syncGeneration = 0
    @ObservationIgnored private var debounceTask: Task<Void, Never>?
    @ObservationIgnored private var leftAt: ContinuousClock.Instant?
    /// The app is in the background: set at once when the phase changes, before any await.
    @ObservationIgnored private(set) var isInBackground = false
    /// The last background or foreground transition. Each one waits for the one before, so a
    /// return never runs while the vault is still being closed.
    @ObservationIgnored private var transition: Task<Void, Never>?

    init(
        service: any VaultService, settings: VaultSettings, gate: OwnerGate, passphraseStore: any PassphraseStore,
        hooks: Hooks = Hooks(), timing: Timing = Timing()
    ) {
        self.service = service
        self.settings = settings
        self.gate = gate
        self.passphraseStore = passphraseStore
        self.hooks = hooks
        self.timing = timing
    }

    var vaults: [VaultEntry] { info?.vaults ?? [] }
    var vault: VaultEntry? { info?.selectedVault }
    var hasVault: Bool { !vaults.isEmpty }
    var activeItems: [ItemRow] { VaultQuery.active(items) }

    func item(_ id: UInt64) -> ItemRow? { items.first { $0.id == id } }

    // MARK: Start and the lock

    /// Read which vaults are on this iPhone. Selects the first one when none is selected.
    func start() async {
        do {
            var fresh = try await service.info()
            if fresh.selected == nil, let first = fresh.vaults.first {
                try await service.select(vaultID: first.id)
                fresh = try await service.info()
            }
            info = fresh
            startError = nil
            if fresh.unlocked, fresh.selectedVault != nil {
                await didUnlock()
            } else {
                isUnlocked = false
            }
        } catch {
            startError = error.localizedDescription
        }
    }

    /// Read `info` again, for example after a join or a removal.
    func refreshInfo() async {
        if let fresh = try? await service.info() { info = fresh }
    }

    /// Whether the lock screen offers Face ID for the selected vault.
    var faceIDUnlockOn: Bool {
        guard let vault else { return false }
        return settings.faceIDUnlock(vaultID: vault.id) && gate.biometry != .none
    }

    /// Whether a passphrase is stored behind Face ID for the selected vault. Never prompts.
    var hasStoredPassphrase: Bool {
        guard let vault else { return false }
        return passphraseStore.hasPassphrase(vaultID: vault.id)
    }

    func unlock(passphrase: String) async {
        guard let vault, !isUnlocking else { return }
        guard !passphrase.isEmpty else {
            unlockMessage = "Type the passphrase."
            return
        }
        isUnlocking = true
        defer { isUnlocking = false }
        do {
            // The core keeps the passphrase in memory only when the vault may stay unlocked while
            // the app is away; then `resume` opens it again on return.
            try await service.unlock(passphrase: passphrase, keep: settings.lockAfter != .immediately)
        } catch let error as VaultError where error.code == .locked {
            // The app went away during the key derivation and the core closed the vault first.
            unlockMessage = nil
            return
        } catch {
            unlockMessage = error.localizedDescription
            return
        }
        unlockMessage = nil
        // Face ID changed since the passphrase was stored: store it again for the new enrollment.
        if faceIDNeedsRepair || (settings.faceIDUnlock(vaultID: vault.id) && !passphraseStore.hasPassphrase(vaultID: vault.id)) {
            faceIDNeedsRepair = false
            do {
                try passphraseStore.save(passphrase, vaultID: vault.id)
            } catch {
                alert = error.localizedDescription
            }
        }
        if isInBackground {
            // The app went away while the core opened the vault: close it again at once.
            await closeOpenedWhileAway()
            return
        }
        await didUnlock()
    }

    /// The vault opened (an unlock or a resume) after the app went to the background. Close it
    /// inside a background task: "Immediately" locks; else it is suspended, and the return
    /// resumes it as after any other time away.
    private func closeOpenedWhileAway() async {
        let end = hooks.beginBackgroundWork("Close the vault")
        defer { end() }
        if settings.lockAfter == .immediately {
            await lock()
            return
        }
        do {
            try await service.suspend()
            isUnlocked = true
            isSuspended = true
            leftAt = timing.now()
        } catch {
            await lock()
        }
    }

    /// Read the stored passphrase with Face ID and unlock. Cancelled: the field stays.
    func unlockWithFaceID() async {
        guard let vault, !isUnlocking else { return }
        let passphrase: String
        do {
            passphrase = try await passphraseStore.read(vaultID: vault.id, reason: "Unlock “\(vault.name)”")
        } catch let error as VaultError where error.code == .locked {
            faceIDNeedsRepair = true
            unlockMessage = error.message
            return
        } catch let error as VaultError where error.code == .cancelled {
            return
        } catch {
            unlockMessage = error.localizedDescription
            return
        }
        await unlock(passphrase: passphrase)
    }

    func select(vaultID: String) async {
        guard vaultID != vault?.id else { return }
        await lock()
        do {
            try await service.select(vaultID: vaultID)
        } catch {
            alert = error.localizedDescription
        }
        faceIDNeedsRepair = false
        unlockMessage = nil
        await refreshInfo()
    }

    private func didUnlock() async {
        isUnlocked = true
        isSuspended = false
        leftAt = nil
        syncStatus = try? await service.syncStatus()
        await reloadAndPublish()
        startSync()
    }

    /// Lock the vault and drop everything read from it.
    func lock() async {
        stopSync()
        debounceTask?.cancel()
        debounceTask = nil
        gate.cancel()
        revealEpoch += 1
        isUnlocked = false
        isSuspended = false
        leftAt = nil
        items = []
        watchtower = nil
        itemsVersion += 1
        try? await service.lock()
        await refreshInfo()
    }

    // MARK: The app leaves and comes back

    /// The app goes to the background. Called at once on the phase change: the flag is set and
    /// revealed values go before anything awaits; the vault closes in a transition after the
    /// one before it.
    func enterBackground() {
        isInBackground = true
        gate.cancel()
        revealEpoch += 1
        stopSync()
        debounceTask?.cancel()
        debounceTask = nil
        let previous = transition
        transition = Task { [weak self] in
            await previous?.value
            await self?.closeForBackground()
        }
    }

    /// The app is active again. Waits for a background transition that still runs.
    func enterForeground() {
        isInBackground = false
        let previous = transition
        transition = Task { [weak self] in
            await previous?.value
            await self?.reopen()
        }
    }

    /// `enterBackground`, and wait until the vault is closed.
    func didEnterBackground() async {
        enterBackground()
        await transition?.value
    }

    /// `enterForeground`, and wait until the vault is open again or locked.
    func didBecomeActive() async {
        enterForeground()
        await transition?.value
    }

    /// Wait for the last transition (tests).
    func settle() async {
        await transition?.value
    }

    /// Close the vault for the background. The vault holds a file lock in the App Group
    /// container while it is open, and iOS kills a suspended app that holds one, so it closes
    /// inside a background task: "Immediately" locks, any other setting suspends (the core keeps
    /// the passphrase until the time is up). When the screens are not unlocked, an unlock or a
    /// join may be opening the vault right now: the core's lock closes whatever is open (it does
    /// nothing when nothing is). A suspended vault is never locked here: that would erase the
    /// kept passphrase.
    private func closeForBackground() async {
        guard isInBackground, !isSuspended else { return }
        let end = hooks.beginBackgroundWork("Close the vault")
        defer { end() }
        guard isUnlocked else {
            try? await service.lock()
            return
        }
        leftAt = timing.now()
        if settings.lockAfter == .immediately {
            await lock()
            return
        }
        do {
            try await service.suspend()
            isSuspended = true
        } catch {
            await lock()
        }
    }

    /// Lock when the app was away longer than the setting, else open the vault again with the
    /// kept passphrase and sync.
    private func reopen() async {
        guard !isInBackground, isUnlocked else { return }
        guard isSuspended else {
            startSync()
            return
        }
        if settings.lockAfter == .immediately || settings.lockAfter.locks(leftAt: leftAt, now: timing.now()) {
            await lock()
            return
        }
        guard (try? await service.resume()) == true else {
            await lock()
            return
        }
        if isInBackground {
            // The app went away again while the core opened the vault.
            isSuspended = false
            await closeOpenedWhileAway()
            return
        }
        isSuspended = false
        leftAt = nil
        await reload()
        startSync()
    }

    /// The app left the screen for a moment (inactive): revealed values go.
    func dropRevealed() {
        revealEpoch += 1
    }

    // MARK: Items

    /// Read the rows again, then Watchtower.
    func reload() async {
        guard isUnlocked else { return }
        do {
            items = try await service.items(archived: .all)
            itemsVersion += 1
        } catch let error as VaultError where error.code == .locked {
            await closedByCore()
            return
        } catch {
            report(error)
        }
        await refreshWatchtower()
    }

    /// Reload the rows and give iOS the logins for the QuickType bar.
    func reloadAndPublish() async {
        await reload()
        await publishIdentities()
    }

    private func publishIdentities() async {
        guard isUnlocked, let vault else { return }
        if let identities = try? await service.identitySet() {
            await hooks.replaceIdentities(identities, vault.id)
        }
    }

    func refreshWatchtower() async {
        guard isUnlocked else { return }
        if let report = try? await service.watchtower() { watchtower = report }
    }

    /// Save a new or an edited item, then reload, publish, and sync in 2 s. Throws the core's
    /// message (a validation, a conflict).
    @discardableResult
    func save(id: UInt64?, revision: UInt64?, draft: ItemDraft) async throws -> SavedItem {
        let end = hooks.beginBackgroundWork("Save the item")
        defer { end() }
        let saved = try await service.save(id: id, revision: revision, draft: draft)
        await didChangeItems()
        return saved
    }

    func setArchived(_ item: ItemRow, _ archived: Bool) async {
        let end = hooks.beginBackgroundWork("Archive the item")
        defer { end() }
        do {
            try await service.archive(id: item.id, archived: archived)
        } catch {
            report(error)
            return
        }
        await didChangeItems()
    }

    /// Delete with the revision that the owner saw. A changed item answers `conflict`.
    func delete(_ item: ItemRow) async -> Bool {
        let end = hooks.beginBackgroundWork("Delete the item")
        defer { end() }
        do {
            try await service.delete(id: item.id, revision: item.revision)
        } catch {
            report(error)
            await reload()
            return false
        }
        if let vault, settings.isFavorite(item.id, vaultID: vault.id) {
            settings.toggleFavorite(item.id, vaultID: vault.id)
        }
        await didChangeItems()
        return true
    }

    private func didChangeItems() async {
        await reloadAndPublish()
        scheduleSync()
    }

    /// Remove the passkey of a login after the owner check, on the revision that `plan` was made
    /// for. With a password the login stays with its other fields. Without one, the core deletes
    /// the whole item (`plan.deletesLogin`), so the owner check names that. True when the call
    /// succeeded.
    func removePasskey(_ plan: PasskeyRemovalPlan) async -> Bool {
        guard await gate.confirm(reason: plan.ownerReason) else { return false }
        let end = hooks.beginBackgroundWork(plan.deletesLogin ? "Delete the login" : "Remove the passkey")
        defer { end() }
        do {
            try await service.passkeyRemove(id: plan.itemID, revision: plan.revision)
        } catch {
            report(error)
            await reload()
            return false
        }
        if plan.deletesLogin, let vault, settings.isFavorite(plan.itemID, vaultID: vault.id) {
            settings.toggleFavorite(plan.itemID, vaultID: vault.id)
        }
        await didChangeItems()
        return true
    }

    /// After an import from another app: reload, publish, and sync.
    func didImport() async {
        await didChangeItems()
    }

    // MARK: Favorites

    var favoriteIDs: [UInt64] {
        guard let vault else { return [] }
        return settings.favorites(vaultID: vault.id)
    }

    func isFavorite(_ id: UInt64) -> Bool { favoriteIDs.contains(id) }

    func toggleFavorite(_ id: UInt64) {
        guard let vault else { return }
        settings.toggleFavorite(id, vaultID: vault.id)
    }

    // MARK: Secrets for a human

    /// The value of a secret field, after the owner check. nil when the owner did not confirm or
    /// the core refused; the core's message goes to `alert`.
    func releaseSecret(itemID: UInt64, field: String, reason: String) async -> String? {
        guard await gate.confirm(reason: reason) else { return nil }
        do {
            return try await service.reveal(id: itemID, field: field)
        } catch {
            report(error)
            return nil
        }
    }

    /// Copy a field. A plain one at once; a secret one after the owner check.
    func copy(_ field: FieldView, of title: String, itemID: UInt64) async {
        guard field.secret else {
            hooks.copy(field.value ?? "", false)
            return
        }
        let reason = "Copy the \(VaultText.phrase(field.label)) of “\(title)”"
        guard let value = await releaseSecret(itemID: itemID, field: field.name, reason: reason) else { return }
        hooks.copy(value, true)
    }

    /// Copy a value that is not in the vault, for example a generated password. It is marked
    /// secret, so it expires, but it needs no owner check: nothing leaves the vault.
    func copyGenerated(_ value: String) {
        hooks.copy(value, true)
    }

    /// Copy the username of a row (plain).
    func copyUsername(_ item: ItemRow) {
        guard !item.subtitle.isEmpty else { return }
        hooks.copy(item.subtitle, false)
    }

    /// Copy the main secret of an item (its password, token, or key), after the owner check.
    func copyMainSecret(_ item: ItemRow) async {
        let detail: ItemDetail
        do {
            detail = try await service.item(id: item.id)
        } catch {
            report(error)
            return
        }
        guard let field = Self.mainSecret(of: detail) else { return }
        await copy(field, of: item.title, itemID: item.id)
    }

    /// The secret that a swipe or a context menu copies.
    static func mainSecret(of detail: ItemDetail) -> FieldView? {
        let roles: [FieldRole] = [.password, .token, .privateKey]
        return detail.fields.first { $0.secret && roles.contains($0.role) }
            ?? detail.fields.first { $0.secret && $0.role != .totp }
    }

    /// The label of the main secret of a kind, for the swipe button.
    static func mainSecretLabel(_ kind: ItemKind) -> String {
        switch kind {
        case .login, .database: "Password"
        case .apiKey: "Token"
        case .sshKey: "Private key"
        case .custom: "Secret"
        }
    }

    // MARK: Sync

    /// Start the sync loop: a sync now, then a long poll while the vault is unlocked and the app
    /// active. A local vault does not sync.
    func startSync() {
        guard isUnlocked, !isSuspended, !isInBackground, vault?.syncs == true, syncTask == nil else { return }
        syncGeneration += 1
        let generation = syncGeneration
        syncTask = Task { [weak self] in
            await self?.syncLoop()
            guard let self, self.syncGeneration == generation else { return }
            self.syncTask = nil
        }
    }

    func stopSync() {
        syncGeneration += 1
        syncTask?.cancel()
        syncTask = nil
    }

    var isSyncLoopRunning: Bool { syncTask != nil }

    private func syncLoop() async {
        var backoff = timing.firstBackoff
        var needsSync = true
        while !Task.isCancelled, isUnlocked {
            do {
                if needsSync {
                    try await runSync()
                    needsSync = false
                    if let state = syncStatus?.state, Self.waitsForOwner(state) { return }
                }
                if Task.isCancelled { return }
                needsSync = try await service.syncWait(timeout: timing.waitTimeout)
                backoff = timing.firstBackoff
            } catch {
                if Task.isCancelled { return }
                if let error = error as? VaultError {
                    if error.code == .locked { return }
                    if error.code == .busy {
                        needsSync = true
                        try? await Task.sleep(for: timing.firstBackoff)
                        continue
                    }
                }
                if let status = try? await service.syncStatus(), !Task.isCancelled { syncStatus = status }
                if Task.isCancelled { return }
                if let state = syncStatus?.state, Self.waitsForOwner(state) { return }
                try? await Task.sleep(for: backoff)
                backoff = min(backoff * 2, timing.maxBackoff)
                needsSync = true
            }
        }
    }

    /// A state that a sync cannot leave on its own: the owner acts in Settings.
    static func waitsForOwner(_ state: SyncStatus.State) -> Bool {
        switch state {
        case .needsPassphrase, .removed, .damaged, .staleCopy, .forkedCopy, .off: true
        case .never, .ok, .offline, .busy, .pending, .error: false
        }
    }

    /// One sync, wrapped so iOS does not suspend the app inside the vault write. Reloads and
    /// publishes when the merge changed something.
    private func runSync() async throws {
        guard let target = vault, isUnlocked, !isSuspended, !isInBackground else { return }
        let targetID = target.id
        let epoch = revealEpoch
        let end = hooks.beginBackgroundWork("Sync the vault")
        isSyncing = true
        defer {
            isSyncing = false
            end()
        }
        let before = syncStatus
        let status: SyncStatus
        do {
            status = try await service.sync()
        } catch {
            guard isCurrentSession(vaultID: targetID, epoch: epoch), !Task.isCancelled else { throw error }
            let code = (error as? VaultError)?.code
            if code != .busy, let fresh = try? await service.syncStatus(),
                isCurrentSession(vaultID: targetID, epoch: epoch) {
                syncStatus = fresh
            }
            // The iCloud merge can commit locally before the provider rejects publication.
            // Its error status need not include a merge count. Refresh the local rows and
            // AutoFill identities, but never after a lock, cancellation, or selection change.
            if target.isICloud, code != .busy, code != .locked, code != .cancelled, !Task.isCancelled,
                isCurrentSession(vaultID: targetID, epoch: epoch) {
                await reloadAndPublish(vaultID: targetID, epoch: epoch)
            }
            throw error
        }
        guard isCurrentSession(vaultID: targetID, epoch: epoch), !Task.isCancelled else { return }
        syncStatus = status
        if Self.merged(status, since: before) { await reloadAndPublish(vaultID: targetID, epoch: epoch) }
    }

    /// Whether a sync brought changes: the merge or the version moved.
    static func merged(_ status: SyncStatus, since before: SyncStatus?) -> Bool {
        guard let merged = status.merged else { return false }
        guard let before else { return true }
        return status.version != before.version || merged != before.merged
    }

    /// "Sync now" in Settings and on the status capsule.
    func syncNow() async {
        guard isUnlocked, vault?.syncs == true else { return }
        do {
            try await runSync()
        } catch let error as VaultError where error.code == .busy {
        } catch {
            if syncStatus == nil { alert = error.localizedDescription }
        }
        if syncTask == nil, let state = syncStatus?.state, !Self.waitsForOwner(state) { startSync() }
    }

    /// A sync 2 s after the last change, so several edits go in one push.
    func scheduleSync() {
        guard vault?.syncs == true else { return }
        debounceTask?.cancel()
        let delay = timing.saveDebounce
        debounceTask = Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled, let self, self.isUnlocked, !self.isSuspended else { return }
            try? await self.runSync()
        }
    }

    // MARK: Sync problems the owner solves

    /// The passphrase changed on a Mac: take the new one, and store it again for Face ID.
    func takeNewPassphrase(_ passphrase: String) async throws {
        guard let target = vault, isUnlocked, !isSuspended, !isInBackground else {
            throw VaultError(.locked, "Unlock the vault before you change its passphrase.")
        }
        let targetID = target.id
        let epoch = revealEpoch
        let end = hooks.beginBackgroundWork("Take the new passphrase")
        defer { end() }
        let change = try await service.takeNewPassphrase(passphrase)
        // A rekey can finish before publication is cancelled by a selection change. Store the
        // new passphrase for its original vault, even when another vault is selected now.
        // Read the registry again so a removed vault cannot get a new keychain entry.
        if change.rekeyed, let fresh = try? await service.info(),
            fresh.vaults.contains(where: { $0.id == targetID }), settings.faceIDUnlock(vaultID: targetID) {
            try? passphraseStore.save(passphrase, vaultID: targetID)
        }
        guard isCurrentSession(vaultID: targetID, epoch: epoch) else { return }
        syncStatus = change.status
        await reloadAndPublish(vaultID: targetID, epoch: epoch)
        guard isCurrentSession(vaultID: targetID, epoch: epoch) else { return }
        startSync()
    }

    private func isCurrentSession(vaultID: String, epoch: Int) -> Bool {
        vault?.id == vaultID && revealEpoch == epoch && isUnlocked && !isSuspended && !isInBackground && !Task.isCancelled
    }

    /// Each read belongs to the captured vault session.
    private func reloadAndPublish(vaultID: String, epoch: Int) async {
        do {
            let rows = try await service.items(archived: .all)
            guard isCurrentSession(vaultID: vaultID, epoch: epoch) else { return }
            items = rows
            itemsVersion += 1
        } catch {
            guard isCurrentSession(vaultID: vaultID, epoch: epoch) else { return }
            report(error)
            return
        }
        let report = try? await service.watchtower()
        guard isCurrentSession(vaultID: vaultID, epoch: epoch) else { return }
        if let report { watchtower = report }
        let identities = try? await service.identitySet()
        guard isCurrentSession(vaultID: vaultID, epoch: epoch) else { return }
        if let identities { await hooks.replaceIdentities(identities, vaultID) }
    }

    /// Keep the relay copy after a stale or forked copy.
    func useRelayCopy() async throws {
        let end = hooks.beginBackgroundWork("Use the relay copy")
        defer { end() }
        syncStatus = try await service.useRelayCopy()
        await reloadAndPublish()
        startSync()
    }

    func devices() async throws -> [RelayDevice] {
        try await service.devices()
    }

    // MARK: Face ID unlock

    /// Turn on "Unlock with Face ID": check the passphrase, then store it behind Face ID.
    func enableFaceIDUnlock(passphrase: String) async throws {
        guard let vault else { return }
        guard try await service.checkPassphrase(passphrase) else {
            throw VaultError(.wrongPassphrase, "The passphrase does not open this vault.")
        }
        try passphraseStore.save(passphrase, vaultID: vault.id)
        settings.setFaceIDUnlock(true, vaultID: vault.id)
        faceIDNeedsRepair = false
    }

    func disableFaceIDUnlock() {
        guard let vault else { return }
        passphraseStore.remove(vaultID: vault.id)
        settings.setFaceIDUnlock(false, vaultID: vault.id)
    }

    // MARK: Removing the vault

    /// Remove the selected vault from this iPhone. Throws the core's error (`relay_unreachable`,
    /// `locked`) so the screen can offer "Remove anyway".
    func removeVault(force: Bool) async throws {
        guard let vault else { return }
        let end = hooks.beginBackgroundWork("Remove the vault")
        defer { end() }
        stopSync()
        _ = try await service.removeVault(id: vault.id, force: force)
        passphraseStore.remove(vaultID: vault.id)
        settings.forget(vaultID: vault.id)
        await hooks.removeAllIdentities()
        isUnlocked = false
        items = []
        watchtower = nil
        syncStatus = nil
        revealEpoch += 1
        itemsVersion += 1
        await start()
    }

    /// A join finished: the new vault is selected and unlocked.
    func didJoin() async {
        stopSync()
        await start()
    }
}
