# Desktop UI

Date: 2026-09-27; the window of ADR 0026 on 2026-10-12.
Scope: the layout and the design system of the desktop app (`src/desktop/ui.rs`, `src/desktop/ui/`, `src/desktop/learning_ui.rs`). The security rules of the fields and the owner check did not change. See [native app](native-app.md), sections A4 and F1 to F10.

## 1. Design

The app follows SwiftUI on macOS, drawn with eframe/egui 0.36.2 (ADR 0001). It is not a SwiftUI app.

- The window has a transparent title bar and three columns, as Mail and 1Password ([ADR 0026](../adr/0026-simple-app.md), the approved [mockup](../design/app-v2-mockup.html)): the sidebar, the list, and the detail. The toolbars of the list and the detail (52 points) hold the title bar. A drag on them moves the window. A double click zooms it.
- Text is 13 pt, controls are 28 points high. The list is white, the detail light gray (`#f6f6f7`) behind white groups, the sidebar `#ececef`. The selected row of a list has the accent fill. A credential shows the tile of its provider (Stripe, GitHub, Postgres…) or of its kind. The one red mark is Production.
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

Several vaults, one open at a time: [several vaults](multiple-vaults.md). The open vault is at the top of the sidebar: a tile with its initial, its name, and a status line ("On this Mac", "Synced 2 minutes ago · iCloud Drive", "Synced 2 minutes ago · Apassy relay", or a sync problem in orange). The lock button is next to it. Its menu has every vault, the open one checked and a vault with a missing file marked, then "New vault…", "Open vault file…", and "Lock". A switch locks the open vault first.

The sidebar (216 points) has three sections. **Personal**: "All credentials" with its count, then the folders, nested, each with the count of its credentials and its subfolders; a triangle opens and closes a folder with subfolders (also ← and → on the focused row), and `ui.json` keeps the open folders. "+" on the Personal header (it shows on hover) is New Folder; a secondary click on a folder has New Folder…, Rename…, and Delete…. **Shared**: each shared vault with a square of its color and its first letter (empty until shared vaults land). **Agents**: Decisions, with a red count of the runs that wait and the open access requests, and Agents, with the count of the active agents (or the expired tokens in orange). At the bottom: the open vault with its sync status, its lock, and its menu, and the Settings gear. Each row shows its shortcut on hover.

The button at the right of the top row of the sidebar, or ⌃⌘S, collapses the sidebar to a rail of icons (56 points; shared vaults show their square, the name in a tooltip) and expands it again; `ui.json` keeps the choice. Below 1000 points of window width the sidebar is always a rail: the button then opens the full sidebar over the list, and a choice, a click outside it, or Esc closes it. That choice is not kept. Below 1040 points the list is 236 points wide, else 300.

With an unlocked vault, the places of the sidebar show:

| View | What it has |
| --- | --- |
| All credentials, a folder | The list: the title (the folder name), the count, "+" (New Credential), the search field, the filter, and the order. A folder shows its credentials and those of its subfolders. By name, the rows group by folder path ("Personal" for the top level, "Work › Acme"); the header of the group at the top stays there while its rows scroll. Each row: the tile, the name, the project and service (or the kind), and at the right its agent state ("Needs review", "No declaration", the variable name, the environment, "Archived") or, in a recency order, the time. A production credential has a red dot. With nothing selected, the detail has the banners, "Use this vault on this Mac" for a vault from another Mac, "Get started" until each step is done ("Hide" hides it for this vault, kept in `ui.json`), the review and conflict notices, and "No credential selected" (or "No credentials yet" with "Add credential"). New Credential is a stub for now: "Choose Kind…" opens the add sheet (the kind, then the name, the secret, the service, the project, and optional custom details). |
| A credential (detail) | The toolbar: Share (a stub until shared vaults), Edit, and "⋯" with Move to Folder…, Share…, Archive…, and Delete…. The tile, the name, the kind, and the project stay above the scrolling body. Each field has its label above a left-aligned value. The secret is masked; Show needs the owner check. Agent access, History and requests, More actions, and Import data open on demand. Each credential keeps its own scroll position. |
| A shared vault | The list "From you" and "From others". Empty until shared vaults land. |
| Agents | The list of the active agents with their token state, "+" (Connect agent), and the revoked agents, folded. "Register" opens a sheet, then the token sheet shows the token and the MCP configuration one time. The detail of an agent has the token expiry, "Rotate token…", "What it can see" (switch "All credentials, without values"), "Process access" for each credential with a variable and "Give access to several credentials…", "API operations" as switches, "Recent requests" (the access log of the agent), and "Revoke agent…". A process grant works in "This folder" or "Any folder" ([ADR 0012](../adr/0012-agent-visibility-and-access-requests.md)). |
| Decisions | For now (until the Decisions view of ADR 0026): the list has "Waiting" (each run that waits), "Requests" (each open access request), and "History" with two rows, Activity and Learning, which the detail shows. Activity: "Access requests" of agents with "Give access…" and "Deny", then "Waiting for you" with an approval card for each waiting run, then "Inbox" and "All requests". |
| Decisions > Learning | Three figures for the last 7 days, the ask rate chart for 14 days with the 10% goal line, the remembered patterns, and the automatic decisions (8, then "Show all"). "Advanced" has the calibration and the candidate model. Before the first decision, the view shows one empty state instead. |
| Settings (its own window, ⌘, or the gear) | A toolbar of four tabs ([ADR 0026](../adr/0026-simple-app.md) §3): an icon above each label, the selected tab with a gray fill and the accent color. The toolbar stays; the grouped rows of the tab scroll below it. **General**: "Vaults" (each vault with its file, where it syncs, "Open", "Rename…", "Remove from list…", "New vault…", "Open vault file…", and "Lock now"), Import ("Import from 1Password…"), and the browser extension. **Devices**: "Questions go to every device" (This Mac with its notification state, Other Macs with the way the open vault syncs and "Devices…" for the relay, the count of paired iPhones, and the switch "Send questions through the relay", off and disabled with "Coming soon" until the relay carries the questions, [ADR 0025](../adr/0025-low-friction-access.md) §3e), "Add a Device…" (Another Mac…: the relay "Add a device…" sheet, only for a vault on the relay; iPhone…: the iPhone listener goes on and the pairing code shows), then Sync (where each vault syncs: Off, iCloud Drive, the detected folders, "Apassy relay", "Choose folder…"; its status, "Sync now", "Turn off…", and "Open a synced vault…"; for the relay also "Add a device…" with the link (as text and as a QR code for an iPhone) and the safety words, and "Devices…"; "Apassy relay" opens a sheet with the relay address, the team code, and the name of this Mac, or a link from another Mac; a folder for a relay vault opens the "Turn off" sheet first, with "Switch"; each relay call runs in the background, with its progress in the sheet or the row and its button dimmed; [sync](sync.md), section 17), macOS notifications, and the iPhone companion (the setting, the pairing QR code, the paired iPhones, and "Reset pairing"; see [companion](companion.md)). **Security**: Unlock ("Change passphrase" and the unlock method with Touch ID), and backup and restore. **Advanced**: the broker and bouncer ("Asked you" this week, "Start the model", "Stop after", the model server status, "Start now" or "Stop", and "Open log"; see [bouncer](bouncer.md), "Start from Apassy"; "Install the model" with its step and "Cancel install" while the Laya environment is missing, or "Install uv first: brew install uv"; a note with the remove commands for a LaunchAgent that runs `start.sh` with a missing model or in a mode where Apassy starts the server, see "Install from Apassy"), "Calibration and learning" (the runs without you and the remembered patterns of the week, and "Calibration and models": the threshold calibration and the candidate model), the command line, Updates ([updates](updates.md)), the keyboard shortcuts, and the contract version. Settings has no setting of an agent and no token lifetime ([ADR 0025](../adr/0025-low-friction-access.md) §3f); `apassy agent lifetime` reads and sets the lifetime. There is no auto-lock setting yet. |

A run that waits for you shows a banner on top of each detail but Decisions. A new version that is ready shows the banner "Apassy X is ready." with "Restart now" and "Later" on top of each detail, but not while Settings shows Advanced. A sync note (both versions of a credential kept, a damaged synced copy or relay copy with "Replace with this Mac's vault…", a taken variable name) and a passphrase that changed on another Mac show a banner on top of each detail ([sync](sync.md)). The Create screen has the Sync choice, off by default; the welcome and unlock screens have "Use a vault from another Mac", with two sources: "Synced folder" and "Apassy relay" (paste the link, compare the safety words, then type the passphrase). "Review" opens its approval card in a sheet. Each approval, reveal, change of agent authority, and new Mac for relay sync opens the owner check sheet "Confirm that it is you". A sheet with a change closes only when the check passes.

A lock returns the window to the unlock screen. It closes each sheet, erases each typed secret, and hides a token that you did not dismiss. A switch to another vault does the same, and also clears the selection, the forms, the inbox marks, and the learning view of the vault that was open.

Settings is its own window (an egui viewport, 720 × 640 points, at least 560 × 420; each tab draws at the minimum size): ⌘, and the gear open it or bring it to the front, ⌘W, Esc, and its close button close it, and a lock closes it. Esc closes a sheet, a menu, an error message, or leaves a text field first. A sheet or an owner check that opens in it shows in it; the others show in the main window. Where egui has no second window (the headless tests), Settings shows in place of the main window, with "Done".

The demo build (`--features desktop` without `vault`) has All credentials, Decisions (the fixture Activity), and Agents on the in-memory demo model, and the fixture Rules in its Settings window. The sidebar says "Demo".

### Filter and order

- Filter: all credentials, one kind, "Needs setup" (no declaration, or a review after a restore), or "Archived".
- Order: name, recently changed, recently used by agents, or date added. "Changed" ignores a reveal. "Used" is the newest request that Apassy allowed.

### Archive

"Archive credential…" asks once, then archives. An archived credential stays in the vault with its history. The list hides it: a search finds it, and the "Archived" filter shows it. The broker refuses each request with it (`item_archived`), and `apassy_list_access` does not list it. An archive only takes authority away, so it needs no passphrase. "Restore from archive" gives the authority back, so it needs the owner check.

### Environment variable: placeholder or real value

The "Environment variable" sheet has "What the program gets": "Placeholder" or "Real value" ([ADR 0011](../adr/0011-run-proxy-placeholders.md)). A placeholder needs hosts. The sheet fills them from the known hosts of the provider, and a new variable starts in placeholder mode when there are such hosts. The footer of the section says what each mode allows. The credential page shows `NAME · placeholder` for a variable in placeholder mode. "Save" needs the owner check. Apassy refuses placeholder mode for a value with less than 64 random bits.

### Custom details

A credential can have up to 10 custom details: a label (31 bytes or fewer, any language) and a value. A hidden detail is masked like the secret. "Show" needs the owner check, and a hidden detail can back an environment variable. In the edit sheet, a blank hidden value keeps the stored value, also after a rename. The switch "Hidden" moves a typed value between the visible field and the secret field.

### Credential navigation and values

The header stays visible when the body scrolls. A long credential name wraps within the header. The list stays beside the credential; ⌘[ leaves the credential. Opening a different credential starts its body at the top.

Field values use dark monospaced text below their labels. Show and Hide stay beside the label. A long revealed value has its own scroll area, at most 180 points high. The owner check and the clipboard rules stay the same.

Agent access, History and requests, More actions, and Import data start closed. More actions contains Archive and Delete. Import data contains the source item ID and source JSON from a 1Password transfer. Review, archive, and sync conflict notices stay visible.

### Timelines

- History (credential page): each change, newest first: added, edited (the names of the changed fields), shown by you, declaration, variable, connector, process access, rule, API operation, archive, restore, and review. It never keeps a value. It keeps 200 events for each credential.
- Agent requests (credential page) and Recent requests (agent page): each agent request with its result. A run with several credentials shows on each of them. The log keeps the last 500 requests of all agents.

Each timeline shows 5 rows and "Show all".

### Keyboard

Every control can be reached and used without a pointer (keyboard review, 2026-10-01).

| Keys | Action |
| --- | --- |
| ⌘1, ⌘2, ⌘3 | All credentials, Decisions, Agents. The focus goes to the first control of the list. In place of the main window, Settings gives way. |
| ⌘, | The Settings window. ⌘W or Esc closes it. |
| ⌘[ | Leave the credential or the agent: nothing is selected |
| ⌘N | New Credential (also "+" in the list) |
| ⌘F | Search credentials |
| ⌘L | Lock the vault, also with a sheet open (not during an owner check) |
| ⌃⌘S | Collapse the sidebar to its icons or expand it; in a narrow window, open or close it over the list |
| Return, ⌘Return, ⌘S | The default action of the open sheet: Save, Add, Register, Archive, and so on. A focused button takes Return itself, and a multi-line field takes it as a new line. In a destructive alert (Delete, Revoke, Reset pairing, Discard changes, and Remove or Turn off for the relay), Return and Space press Cancel (Keep editing in Discard changes), also when the alert was opened with the pointer and no control has the focus. |
| ⌘⇧H | Show or hide the secret values of the open credential (the owner check first) |
| Tab, ⇧Tab | Move the focus to the next or the previous control. The page scrolls to it. |
| ← → ↑ ↓ | Move the focus to the nearest control. In a sheet, the focus stays in the sheet. |
| Space | Press the focused control. On a segmented picker, select the next option. |
| ← → on a segmented picker | Select the previous or the next option. The focus stays on the picker. |
| Space on a menu, then Tab and Return | Open the menu, move through its options, and choose one. The menu closes, and the focus goes back to the menu button. |
| Page Up, Page Down, Home, End | Scroll the page or the sheet, when no text field has the focus |
| Esc | Close the sheet, a menu, or an error message |

The focus follows the owner:

- A sheet that opens takes the focus: its first control, or Cancel in a destructive alert. When it closes, the focus goes back to the control that opened it.
- A sheet that opens over another sheet, such as the owner check over "Add a device…", is drawn on top of it, also after a quick click (press and release in one frame, as a tap on a trackpad).
- After a navigation with the keyboard, or when the focused control goes away (for example "Mark as seen"), the first control of the page takes the focus. The next Tab does not start again at the sidebar.
- After picking a kind in the add sheet, the Name field takes the focus. A new start screen focuses its first field. On the Create screen, Return moves from Name to Passphrase to Repeat, and Return in Repeat creates the vault.
- The focus ring is 2 points of solid accent on every control, including rows, the sidebar, switches, pickers, kind cards, and code blocks. It passes 3:1 (WCAG 1.4.11).
- The window moves the focus only for a keyboard user. After a click, no focus ring appears that the owner did not ask for. One exception, as in macOS: the first text field of a new sheet, of a start screen, and of the credential form after the pick of a kind takes the focus for a pointer user too, so the owner can type at once.

VoiceOver gets a name for every control: icon-only buttons ("Close the message", "Remove detail …"), rows, tags, a sidebar item with its count ("Activity, 3 waiting", "Agents, 1 token expired"), the open vault with its status, a navigation row with its status, a segmented picker with its value, a disclosure with its state, and the fields of a custom detail.

⌘H is not used. In macOS it is "Hide Apassy" in the app menu, and the menu takes the key before the window. Settings > Advanced > Keyboard shortcuts lists the same keys.

### Command line

Settings > Advanced > Command line shows the owner socket of the `apassy` command line and the open sessions, with "End all sessions" ([command line](cli.md), [ADR 0017](../adr/0017-owner-command-line.md)). An owner check that the command line asked for says so in the dialog, and a change from the command line shows a message that starts with "Command line:".

## 3. Where the old controls are

| Old label | Now |
| --- | --- |
| Vault file card: "Create vault file", "Open vault file", "Unlock vault" | Start screens: "Create a new vault", "Open an existing vault", "Unlock" |
| "Vault file, passphrase, unlock method, and backup" | Settings > General (vaults, "Lock now") and Settings > Security |
| Item details | The page of a credential: click it in Credentials |
| "Reveal values" / "Hide values" | "Show" / "Hide" next to the secret |
| Declaration card, "Save declaration" | Agent access > Declaration, "Save" |
| "Environment variable for agent processes", "Save variable" | Agent access > Environment variable, "Save" |
| "Agent connector", "Save connector" | Agent access > Connector, "Save" |
| "Delete item" / "Confirm delete" | "Delete credential…", then "Delete" |
| "Register an agent" card | Agents > "Register" |
| "Token lifetime" card | Removed from the app (ADR 0025 §3f). `apassy agent lifetime` |
| "Manage grants" | Click the agent |
| "Allow, ask each time" / "Let the bouncer decide" | Process access sheet: "Ask me each time" / "Bouncer decides", then "Save" |
| Grant checkboxes | API operations switches |
| Approval card on every view | Banner on every view, and the card in Activity |
| Inbox card: channel and buttons | Settings > Devices > Notifications |
| iPhone companion, pairing, and paired iPhones | Settings > Devices > iPhone companion, Pair an iPhone, Paired iPhones; also "Add a Device…" > iPhone… |
| Broker card | Settings > Advanced > Broker and bouncer |
| Settings > General > Sync | Settings > Devices > Sync; General shows where each vault syncs |
| Settings > Agents, Notifications, About | Settings > Advanced (bouncer, command line, updates, shortcuts) and Settings > Devices (notifications, iPhone companion) |
| Learning: calibration and candidate model | Settings > Advanced > Calibration and learning |
| Rules view (vault build) | Removed. It was a fixture demo. Rules of a process grant are in its sheet. The demo build keeps the view, in its Settings window under Advanced. |
| Demo request card (vault build) | Removed. It was a fixture simulation. The demo build keeps it. |

## 4. Checks

The headless tests draw each place with `egui::Context::run_ui` and read the painted text. They cover the start screens, each place (All credentials, a folder, a shared vault, Decisions, Agents) at 1180 × 800 and 900 × 600 with the sidebar full, collapsed, and floating, the Settings window (each of its four tabs at a tall size and at the minimum size of 560 × 420 with no text past the edge, a click on a tab, the disabled relay switch in the AccessKit tree, and Esc and ⌘W; `src/desktop/ui/settings_tests.rs`), the folder sheets (a nested folder, a taken name, rename, move, and delete with the credentials going to the parent), the owner check before each guarded action, sheets that erase their secrets on close, a sheet that closes only after a passed check, the lock, and the toast. They do not prove pixel layout.

The keyboard tests (`src/desktop/ui/keyboard_tests.rs`) keep one context across frames and read the AccessKit tree: Tab to "Edit", Return opens the sheet and its first field takes the focus, Esc gives the focus back; Return in a field registers an agent; a delete alert starts on Cancel, and Return or Space in a delete or discard alert opened with the pointer presses Cancel or Keep editing; the arrows change a picker without moving the focus; ⌘1 to ⌘3, ⌘, and ⌘W, ⌘[ and ⌘L; ⌃⌘S collapses the sidebar, and in a narrow window floats it until a choice or a click outside; each focused control on Settings > Advanced is on screen, and Page Up, Page Down, Home, and End scroll it; a menu choice with the keyboard closes the menu; the focus survives a control that goes away; Esc closes an error message. The command-line tests (`src/desktop/ui/cli_tests.rs`) drive the app through the owner socket.

On 2026-09-27 the agent also drew each screen in a real window with synthetic data (a separate `HOME` under `/tmp`) and looked at a capture of that window only.
