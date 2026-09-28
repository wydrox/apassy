# Desktop UI

Date: 2026-09-27.
Scope: the layout and the design system of the desktop app (`src/desktop/ui.rs`, `src/desktop/ui/`, `src/desktop/learning_ui.rs`). The security rules of the fields and the owner check did not change. See [native app](native-app.md), sections A4 and F1 to F10.

## 1. Design

The app follows SwiftUI on macOS, drawn with eframe/egui 0.36.2 (ADR 0001). It is not a SwiftUI app.

- The window has a transparent title bar. The sidebar runs under it, as in a `NavigationSplitView`. A drag on the top strip moves the window. A double click zooms it.
- Text uses SF Pro and SF Mono from `/System/Library/Fonts`. The app loads them at start and does not bundle them. Without them, the egui fonts stay.
- Colors are the macOS light system colors: a white group on a near-white window, the system blue for actions, and green, orange, and red for state. A state color always has a label or an icon.
- Settings are grouped sections, as in `Form` with `.formStyle(.grouped)`: a label on the left, the value or the control on the right, a hairline between rows.
- A change opens a sheet. A result shows in a toast at the bottom for 4.5 s. An error stays until you close it.
- Each screen shows the common path first. Rare or advanced controls are behind a disclosure ("Notes", "Location", "Rule", "Why these values?", "Show as a table", "Advanced: calibration and models").

The tokens and the controls are in `src/desktop/ui/kit.rs`. Each control reports its label to AccessKit.

## 2. Screens

Without a vault file, or with a locked vault, the window shows a start screen only:

- Welcome: "Your vaults" (the vault list, when it has a vault), "Create a new vault", "Open an existing vault", "Restore from a backup…". A vault whose file is missing shows a notice with "Remove from list".
- Create: the name of the vault and the passphrase two times. "Location" opens the file path. The default is `~/Library/Application Support/Apassy/vaults/<name>.db`. Apassy creates a missing folder with mode `0700`. The first vault is "Personal" when you type no name. After the create, the vault is unlocked.
- Open and Restore: the file, and a name for the vault list. An empty name takes the name of the file.
- Unlock: the name of the vault, a picker of the other vaults, the passphrase, and "Unlock with Touch ID" when Touch ID unlock is set up for this file. "New vault…", "Open vault file…", and "Restore…" are below. At start, Apassy opens the last used vault, locked, so the window starts here.

Several vaults, one open at a time: [several vaults](multiple-vaults.md). The name of the open vault is at the top of the sidebar. Its menu has the other vaults, "New vault…", and "Open vault file…". A switch locks the open vault first.

With an unlocked vault, the sidebar has these views:

| View | What it has |
| --- | --- |
| Credentials | The list with search, a filter, and an order. By name, the list groups by kind. Each row shows its agent state: "Needs review", "No declaration", the variable name, or the environment. A recency order shows the time instead. "Add" opens a sheet: first the kind, then the name, the secret, the service, the project, and optional custom details. |
| Credential page | The secret (masked, "Show" needs the owner check), the details, the custom details, and "Agent access": Declaration, Environment variable, and Connector (API keys). Then "History" (the changes) and "Agent requests" (the access log). "Edit", "Archive credential…", and "Delete credential…" are here too. |
| Agents | The list with the token state. "Register" opens a sheet, then the token sheet shows the token and the MCP configuration one time. The agent page has the token expiry, "Rotate token…", "What it can see" (switch "All credentials, without values"), "Process access" for each credential with a variable and "Give access to several credentials…", "API operations" as switches, "Recent requests" (the access log of the agent), and "Revoke agent…". A process grant works in "This folder" or "Any folder" ([ADR 0012](../adr/0012-agent-visibility-and-access-requests.md)). |
| Activity | "Access requests" of agents with "Give access…" and "Deny", then "Waiting for you" with an approval card for each waiting run, then "Inbox" and "All requests". The sidebar count has the waiting runs and the open requests. |
| Learning | Three figures for the last 7 days, the ask rate chart for 14 days with the 10% goal line, the automatic decisions, and the remembered patterns. "Advanced" has the calibration and the candidate model. |
| Settings | Vault file and "Lock now", "Vaults" (each vault with its file, "Open", "Rename…", "Remove from list…", "New vault…", "Open vault file…", and Sync: the folder of each vault (Off, iCloud Drive, the detected folders, "Choose folder…"), its status, "Sync now", "Turn off…", and "Open a synced vault…"; [sync](sync.md)), "Change passphrase", the unlock method, backup and restore, the token lifetime, notifications, the broker and bouncer state, and Updates ([updates](updates.md)). |

A run that waits for you shows a banner on each view but Activity. A new version that is ready shows the banner "Apassy X is ready." with "Restart now" and "Later" on each view but Settings. A sync note (both versions of a credential kept, a damaged synced copy, a taken variable name) and a passphrase that changed on another Mac show a banner on each view ([sync](sync.md)). The Create screen has the Sync choice, off by default; the welcome and unlock screens have "Open a synced vault…". "Review" opens its approval card in a sheet. Each approval, reveal, and change of agent authority opens the owner check sheet "Confirm that it is you". A sheet with a change closes only when the check passes.

A lock returns the window to the unlock screen. It closes each sheet, erases each typed secret, and hides a token that you did not dismiss. A switch to another vault does the same, and also clears the selection, the forms, the inbox marks, and the learning view of the vault that was open.

The demo build (`--features desktop` without `vault`) has Credentials, Rules, Agents, and Activity on the in-memory demo model. The sidebar says "Demo".

### Filter and order

- Filter: all credentials, one kind, "Needs setup" (no declaration, or a review after a restore), or "Archived".
- Order: name, recently changed, recently used by agents, or date added. "Changed" ignores a reveal. "Used" is the newest request that Apassy allowed.

### Archive

"Archive credential…" asks once, then archives. An archived credential stays in the vault with its history. The list hides it: a search finds it, and the "Archived" filter shows it. The broker refuses each request with it (`item_archived`), and `apassy_list_access` does not list it. An archive only takes authority away, so it needs no passphrase. "Restore from archive" gives the authority back, so it needs the owner check.

### Environment variable: placeholder or real value

The "Environment variable" sheet has "What the program gets": "Placeholder" or "Real value" ([ADR 0011](../adr/0011-run-proxy-placeholders.md)). A placeholder needs hosts. The sheet fills them from the known hosts of the provider, and a new variable starts in placeholder mode when there are such hosts. The footer of the section says what each mode allows. The credential page shows `NAME · placeholder` for a variable in placeholder mode. "Save" needs the owner check. Apassy refuses placeholder mode for a value with less than 64 random bits.

### Custom details

A credential can have up to 10 custom details: a label (31 bytes or fewer, any language) and a value. A hidden detail is masked like the secret. "Show" needs the owner check, and a hidden detail can back an environment variable. In the edit sheet, a blank hidden value keeps the stored value, also after a rename. The switch "Hidden" moves a typed value between the visible field and the secret field.

### Timelines

- History (credential page): each change, newest first: added, edited (the names of the changed fields), shown by you, declaration, variable, connector, process access, rule, API operation, archive, restore, and review. It never keeps a value. It keeps 200 events for each credential.
- Agent requests (credential page) and Recent requests (agent page): each agent request with its result. A run with several credentials shows on each of them. The log keeps the last 500 requests of all agents.

Each timeline shows 5 rows and "Show all".

### Keyboard

| Keys | Action |
| --- | --- |
| ⌘N | New credential |
| ⌘F | Search credentials |
| ⌘S | The default action of the open sheet: Save, Add, Register, Archive, and so on |
| ⌘⇧H | Show or hide the secret values of the open credential (the owner check first) |
| Tab, ⇧Tab | Move the focus to the next or the previous control. A focused row or control has a blue ring. |
| Space | Press the focused control. On a segmented picker, select the next option. |
| ← → | On a focused segmented picker, select the previous or the next option. |
| Return | Confirm a passphrase field |
| Esc | Close the sheet |

⌘H is not used. In macOS it is "Hide Apassy" in the app menu, and the menu takes the key before the window. Settings > Keyboard shortcuts lists the same keys.

## 3. Where the old controls are

| Old label | Now |
| --- | --- |
| Vault file card: "Create vault file", "Open vault file", "Unlock vault" | Start screens: "Create a new vault", "Open an existing vault", "Unlock" |
| "Vault file, passphrase, unlock method, and backup" | Settings |
| Item details | The page of a credential: click it in Credentials |
| "Reveal values" / "Hide values" | "Show" / "Hide" next to the secret |
| Declaration card, "Save declaration" | Agent access > Declaration, "Save" |
| "Environment variable for agent processes", "Save variable" | Agent access > Environment variable, "Save" |
| "Agent connector", "Save connector" | Agent access > Connector, "Save" |
| "Delete item" / "Confirm delete" | "Delete credential…", then "Delete" |
| "Register an agent" card | Agents > "Register" |
| "Token lifetime" card | Settings > Agents |
| "Manage grants" | Click the agent |
| "Allow, ask each time" / "Let the bouncer decide" | Process access sheet: "Ask me each time" / "Bouncer decides", then "Save" |
| Grant checkboxes | API operations switches |
| Approval card on every view | Banner on every view, and the card in Activity |
| Inbox card: channel and buttons | Settings > Notifications |
| Broker card | Settings > Broker and bouncer |
| Rules view (vault build) | Removed. It was a fixture demo. Rules of a process grant are in its sheet. The demo build keeps the view. |
| Demo request card (vault build) | Removed. It was a fixture simulation. The demo build keeps it. |

## 4. Checks

The headless tests draw each view with `egui::Context::run_ui` and read the painted text. They cover the start screens, each view at 1180 × 800 and 900 × 600, the owner check before each guarded action, sheets that erase their secrets on close, a sheet that closes only after a passed check, the lock, and the toast. They do not prove pixel layout.

On 2026-09-27 the agent also drew each screen in a real window with synthetic data (a separate `HOME` under `/tmp`) and looked at a capture of that window only.
