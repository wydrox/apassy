# ADR 0026 — A simple app: three columns, folders, shared vaults

Date: 2026-10-12.
Status: ACCEPTED by the owner on 2026-10-12 ("jest już ok. działaj z implementacją"). Shipped in 0.5.0: the Mac app (§1–§5, §7) and the iPhone app (§8). Shared vaults (§6) are not built yet. On the iPhone, the agents, agent use, rules, requests, and suggestions wait for the feed from the Mac ([stage 5 plan](../design/stage5-plan.md), section D), and questions through the relay need the relay's team schema 5, which is not deployed yet. The approved mockup is [docs/design/app-v2-mockup.html](../design/app-v2-mockup.html). It goes with [ADR 0025](0025-low-friction-access.md).

## Context

On 2026-10-12 the owner said that the app has "many hidden corners" and that its navigation is not clear. A survey of the code found:

- 5 views (Credentials, Agents, Activity, Learning, Settings), about 24 sheets, and 5 settings tabs with about 13 groups.
- 3 separate onboarding flows. 4 of the 5 "Get started" steps are agent setup.
- The same task in several places: access is given in 4 places, the history of requests is in 4 places, and the declaration and the variable are in 3 places.
- Settings that need 3 or 4 clicks through disclosures.

Most of that UI configures access, which ADR 0025 removes. The owner also asked for folders and for vaults that the owner can share with other people.

The owner rejected two mockups: the first looked like a web page and the Decisions screen had no hierarchy. The owner approved the third ("v2"), with a sidebar that can expand and a standard gear icon.

## Decision

### 1. The window

The app follows the layout of Mail and 1Password: sidebar, list, detail.

- **Sidebar.**
  - *Personal*: "All credentials" and the folders, nested.
  - *Shared*: the shared vaults.
  - *Agents*: Decisions (with a red count of what blocks agents) and Agents.
  - At the bottom: the owner, the lock state and the Settings button.
  - The sidebar can be hidden with a toolbar button and ⌃⌘S. In a narrow window it collapses to icons. When opened, it floats over the list and closes after a choice. A shared vault shows its first letter and its name as a tooltip.
- **List.** A title, a count, a search field and one "+" button. A row shows the provider tile, the name and one line of detail. The selected row has the accent color. Group headers stay at the top while the list scrolls.
- **Detail.** Grouped rows in the style of System Settings: label on the left, value on the right. A header shows the provider tile, the name, the kind and small tags (Production, shared vaults). Rare actions are in a "⋯" menu in the toolbar.
- **Look.** System font at 13 pt, controls 28 px high, thin separators, no colored chips except the red Production tag. Provider tiles (Stripe, GitHub, Postgres…) instead of kind icons.

### 2. The views

| View | List | Detail |
| --- | --- | --- |
| Credentials (all, a folder, a shared vault) | credentials, grouped by folder | secret, variable, host; folder and shared vaults; agent use; rules from the owner's answers; "Always ask me", environment, "Hosts and risk" |
| Decisions | Waiting (with a timer), Requests, Suggestions | the question, its facts, the command, why the owner is asked; a bottom bar: Deny · Allow Once · Allow ACTION in PROJECT |
| Agents | connected agents | uses, projects, an optional note for the bouncer, exceptions, Disconnect |

The "⋯" menu of a question has the stricter answers of ADR 0025 §3f ("Not for this agent", "Always ask for this agent"). The app labels them "Never for AGENT" and "Always Ask for AGENT", with the name of the agent.

The old views go away:

- **Activity** and **Learning** become Decisions. The weekly counts move into a single line under the Decisions title.
- **Agents** loses grants, modes, folders and the "see all" switch (ADR 0025 §3f).
- **Rules** (demo build) moves to Settings, as its only section there.

### 3. Settings is a view

Owner decision of 2026-10-13: "napraw ekran ustawień (otwieraj go jak każdy inny (nie jak osobne okno), wyczyść zbędne ustawienia oraz popraw grupowanie ustawień bo aktualnie nie jest czytelny" (fix the settings screen: open it like any other view, not as a separate window; clean out unneeded settings; and fix the grouping, because it is not readable now). It replaces the first version of this section, "Settings is a window" with four tabs.

Settings is a view of the main window, as Decisions and Agents are. The gear at the bottom of the sidebar and ⌘, open it; the gear then shows selected and no sidebar row does. The list column lists the sections, each with a tile, its name, and one short status line, as macOS System Settings does. The detail column shows the selected section as groups of rows. A click on a sidebar row (or ⌘1 to ⌘3) leaves Settings. Sheets and owner checks show over the window, as all others. A lock leaves Settings.

- **Vault**: the open vault (where it lives, its "⋯" actions), Sync (off, a folder such as iCloud Drive, or the relay; its state; "Open a synced vault…"), Backup ("Back up now…", "Restore…"), and Import (1Password).
- **Security**: the Touch ID switch, whose note says whether owner checks use Touch ID, and "Change passphrase…". There is no auto-lock setting yet.
- **Devices**: This Mac (its notifications; the buttons and the reason only when they do not work), the iPhone (the listener, the paired iPhones, "Pair…"), the other Macs while the vault syncs, and the relay switch for the questions. Questions reach every device (ADR 0025 §3e).
- **Bouncer**: the model with its state and its actions, "Start the model", "Stop after", and Calibration and learning. A broker that does not take agent requests shows a warning row.
- **Tools**: the command line (install, and the open sessions with "End all") and the browser extension.
- **Updates**: the updater with the version, and the keyboard shortcuts.

A status that needs nothing from the owner does not show: the broker address, its socket, "Accepts agent requests", the weekly "Asked you" count (Decisions has it), and the contract version left Settings. Each group has at most one short note.

### 4. Adding

"+" opens "New Credential": paste, then Add (ADR 0025 §4). A `.env` file gives one row for each line. The folder is the selected folder.

### 5. Folders

- A personal vault has folders, nested to any depth. A credential is in at most one folder.
- Moving a credential changes nothing else: sharing, rules and history stay.
- The folder path is shown to agents in the catalog. The bouncer reads it as context: an item in the folder "Acme" fits the project `acme-billing`.
- Deleting a folder moves its credentials to the parent folder. It never deletes a credential.

### 6. Shared vaults

- A shared vault is a vault that the owner shares with people. It is built on a relay team (ADR 0019): one team, one vault.
- **One home, many shares.** A credential has exactly one home vault, personal or shared, and can be in many shared vaults. The item is shared, not copied: there is one value, and a change reaches everyone. Removing it from a shared vault does not delete it.
- **Roles.** Members use the items through their agents. Managers and owners can also see values. Only the item's owner edits it.
- **Decisions.** A production use of a shared item needs an owner or a manager of the shared vault (ADR 0025 §3e).
- The list of a shared vault shows "From you" and "From others".

### 7. Onboarding

Two steps: paste the first credential, and connect an agent. The "Get started" panel and the agent onboarding go away.

### 8. The iPhone app

The owner approved the iPhone mockup on 2026-10-12 ([docs/design/ios-v1-mockup.html](../design/ios-v1-mockup.html)). The iPhone follows the same model as the Mac:

- **Tabs:** Vault, Decisions, Agents, and search, with the iOS 26 tab bar. Watchtower is a card at the top of Vault, not a tab (owner decision: "Tak").
- **Vault:** "All credentials", the folders, and the shared vaults, as in the Mac sidebar. A folder lists its credentials with provider tiles; a red dot marks production.
- **Adding:** "+" opens New Credential: paste (or scan a QR code), then Add. Detection runs on the iPhone.
- **Editing:** the full editor stays (owner decision: "Pełen zakres").
- **Credential:** the same groups as on the Mac: secret, variable, folder, agent use, rules from the owner's answers, options.
- **Decisions:** Waiting, Requests, and Suggestions, with a fixed bottom bar: Allow ACTION in PROJECT, Deny, Allow Once. Allowing asks for Face ID; stricter answers do not. Questions arrive through the relay (ADR 0025 §3e), not only on the local network.
- **Agents:** read only, with exceptions; removing an exception asks for Face ID.
- **Settings:** the groups of the 2026-10-12 mockup (General, Devices, Security, Advanced). The Mac regrouped its Settings on 2026-10-13 (§3); the iPhone follows when it changes next.

## Implementation

The work is split into parallel streams with disjoint files, after one foundation step for the schema. The plan and the review gates are in the PRs. There is no release until the owner asks.

## What this does not protect

- The folder path and the names of the shared vaults are shown to agents and to their model providers, like the item names (ADR 0012).
- A shared item that a member's agent misuses is the owner's credential. The bouncer of the member decides. Production uses still need an owner or a manager of the shared vault.

## Relation to other records

- ADR 0012: the "see all" setting leaves the UI; ADR 0025 §3f turns old settings into exceptions.
- ADR 0013: several vaults stay; a shared vault is one of them.
- ADR 0019: a shared vault is a relay team with one vault. An item can be in several teams.
- ADR 0020: the iPhone answers Decisions (ADR 0025 §3d).
- ADR 0024: the first-use card becomes a Decision.
- ADR 0025: this record is the UI of that decision.
