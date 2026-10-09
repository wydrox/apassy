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

Several vaults, one open at a time: [several vaults](multiple-vaults.md). The open vault is at the top of the sidebar: a tile with its initial, its name, and a status line ("On this Mac", "Synced 2 minutes ago · iCloud Drive", "Synced 2 minutes ago · Apassy relay", or a sync problem in orange). The lock button is next to it. Its menu has every vault, the open one checked and a vault with a missing file marked, then "New vault…", "Open vault file…", and "Lock". A switch locks the open vault first.

The sidebar lists Credentials (the count), Agents (the number of expired tokens, in orange), Activity (what waits for you, in orange), and Learning; Settings is at the bottom. Each row shows its shortcut on hover. The button right of the window buttons, or ⌃⌘S, hides and shows the sidebar; the shortcuts work without it. The app remembers the choice across restarts in `ui.json` in the data folder.

With an unlocked vault, the sidebar has these views:

| View | What it has |
| --- | --- |
| Credentials | "Get started" on top until each step is done: add a credential, let agents use it (variable and declaration), register an agent, give it access, and connect the host for a first request. Each step reads the vault; only the next open step has a button, and "Hide" hides the list for this vault, also after a restart (`ui.json` in the data folder keeps it per vault). With no credential, the list replaces the empty state. A vault from another Mac shows "Use this vault on this Mac" there instead (Claude Code, Codex, CLI, or Skip), because its agents stay on the other Mac. Then the list with search, a filter, and an order. By name, the list groups by kind. Each row shows its agent state: "Needs review", "No declaration", the variable name, or the environment. A recency order shows the time instead. "Add" opens a sheet: first the kind, then the name, the secret, the service, the project, and optional custom details. |
| Credential page | Back, the credential name, its kind, and Edit stay above the scrolling body. Each field has its label above a left-aligned value. The secret is masked; Show needs the owner check. Agent access, History and requests, More actions, and Import data open on demand. Each credential keeps its own scroll position. |
| Agents | The list with the token state. "Register" opens a sheet, then the token sheet shows the token and the MCP configuration one time. The agent page has the token expiry, "Rotate token…", "What it can see" (switch "All credentials, without values"), "Process access" for each credential with a variable and "Give access to several credentials…", "API operations" as switches, "Recent requests" (the access log of the agent), and "Revoke agent…". A process grant works in "This folder" or "Any folder" ([ADR 0012](../adr/0012-agent-visibility-and-access-requests.md)). |
| Activity | "Access requests" of agents with "Give access…" and "Deny", then "Waiting for you" with an approval card for each waiting run, then "Inbox" and "All requests". The sidebar count has the waiting runs and the open requests. |
| Learning | Three figures for the last 7 days, the ask rate chart for 14 days with the 10% goal line, the remembered patterns, and the automatic decisions (8, then "Show all"). "Advanced" has the calibration and the candidate model. Before the first decision, the view shows one empty state instead. |
| Settings | Five tabs. General: "Vaults" (each vault with its file, "Open", "Rename…", "Remove from list…", "New vault…", "Open vault file…", and "Lock now"), Sync (where each vault syncs: Off, iCloud Drive, the detected folders, "Apassy relay", "Choose folder…"; its status, "Sync now", "Turn off…", and "Open a synced vault…"; for the relay also "Add a Mac…" with the link and the safety words, and "Devices…"; "Apassy relay" opens a sheet with the relay address, the team code, and the name of this Mac, or a link from another Mac; a folder for a relay vault opens the "Turn off" sheet first, with "Switch"; each relay call runs in the background, with its progress in the sheet or the row and its button dimmed; [sync](sync.md), section 17), and import. Security: "Change passphrase", the unlock method, and backup and restore. Agents: the token lifetime, the broker and bouncer state ("Start the model", "Stop after", the model server status, "Start now" or "Stop", and "Open log"; see [bouncer](bouncer.md), "Start from Apassy"; "Install the model" with its step and "Cancel install" while the Laya environment is missing, or "Install uv first: brew install uv"; a note with the remove commands for a LaunchAgent that runs `start.sh` with a missing model or in a mode where Apassy starts the server, see "Install from Apassy"), and the command line. Notifications: macOS notifications and the iPhone companion (the setting, the pairing QR code, the paired iPhones, and "Reset pairing"; see [companion](companion.md)). About: Updates ([updates](updates.md)), the keyboard shortcuts, and the contract version. |

A run that waits for you shows a banner on each view but Activity. A new version that is ready shows the banner "Apassy X is ready." with "Restart now" and "Later" on each view but Settings > About. A sync note (both versions of a credential kept, a damaged synced copy or relay copy with "Replace with this Mac's vault…", a taken variable name) and a passphrase that changed on another Mac show a banner on each view ([sync](sync.md)). The Create screen has the Sync choice, off by default; the welcome and unlock screens have "Use a vault from another Mac", with two sources: "Synced folder" and "Apassy relay" (paste the link, compare the safety words, then type the passphrase). "Review" opens its approval card in a sheet. Each approval, reveal, change of agent authority, and new Mac for relay sync opens the owner check sheet "Confirm that it is you". A sheet with a change closes only when the check passes.

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

### Credential navigation and values

The header stays visible when the body scrolls. A long credential name wraps within the header, with room for Edit. Back returns to the credential list. Opening a different credential starts its body at the top.

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
| ⌘1, ⌘2, ⌘3, ⌘4 | Credentials, Agents, Activity, Learning. The focus goes to the first control of the page. |
| ⌘, | Settings |
| ⌘[ | Back from a credential or an agent to its list |
| ⌘N | New credential |
| ⌘F | Search credentials |
| ⌘L | Lock the vault, also with a sheet open (not during an owner check) |
| ⌃⌘S | Hide or show the sidebar |
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
- A sheet that opens over another sheet, such as the owner check over "Add a Mac…", is drawn on top of it, also after a quick click (press and release in one frame, as a tap on a trackpad).
- After a navigation with the keyboard, or when the focused control goes away (for example "Mark as seen"), the first control of the page takes the focus. The next Tab does not start again at the sidebar.
- After picking a kind in the add sheet, the Name field takes the focus. A new start screen focuses its first field. On the Create screen, Return moves from Name to Passphrase to Repeat, and Return in Repeat creates the vault.
- The focus ring is 2 points of solid accent on every control, including rows, the sidebar, switches, pickers, kind cards, and code blocks. It passes 3:1 (WCAG 1.4.11).
- The window moves the focus only for a keyboard user. After a click, no focus ring appears that the owner did not ask for. One exception, as in macOS: the first text field of a new sheet, of a start screen, and of the credential form after the pick of a kind takes the focus for a pointer user too, so the owner can type at once.

VoiceOver gets a name for every control: icon-only buttons ("Close the message", "Remove detail …"), rows, tags, a sidebar item with its count ("Activity, 3 waiting", "Agents, 1 token expired"), the open vault with its status, a navigation row with its status, a segmented picker with its value, a disclosure with its state, and the fields of a custom detail.

⌘H is not used. In macOS it is "Hide Apassy" in the app menu, and the menu takes the key before the window. Settings > About > Keyboard shortcuts lists the same keys.

### Command line

Settings > Agents > Command line shows the owner socket of the `apassy` command line and the open sessions, with "End all sessions" ([command line](cli.md), [ADR 0017](../adr/0017-owner-command-line.md)). An owner check that the command line asked for says so in the dialog, and a change from the command line shows a message that starts with "Command line:".

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
| "Token lifetime" card | Settings > Agents > Agents |
| "Manage grants" | Click the agent |
| "Allow, ask each time" / "Let the bouncer decide" | Process access sheet: "Ask me each time" / "Bouncer decides", then "Save" |
| Grant checkboxes | API operations switches |
| Approval card on every view | Banner on every view, and the card in Activity |
| Inbox card: channel and buttons | Settings > Notifications > Notifications |
| iPhone companion, pairing, and paired iPhones | Settings > Notifications > iPhone companion, Pair an iPhone, Paired iPhones |
| Broker card | Settings > Agents > Broker and bouncer |
| Rules view (vault build) | Removed. It was a fixture demo. Rules of a process grant are in its sheet. The demo build keeps the view. |
| Demo request card (vault build) | Removed. It was a fixture simulation. The demo build keeps it. |

## 4. Checks

The headless tests draw each view with `egui::Context::run_ui` and read the painted text. They cover the start screens, each view at 1180 × 800 and 900 × 600, the owner check before each guarded action, sheets that erase their secrets on close, a sheet that closes only after a passed check, the lock, and the toast. They do not prove pixel layout.

The keyboard tests (`src/desktop/ui/keyboard_tests.rs`) keep one context across frames and read the AccessKit tree: Tab to "Edit", Return opens the sheet and its first field takes the focus, Esc gives the focus back; Return in a field registers an agent; a delete alert starts on Cancel, and Return or Space in a delete or discard alert opened with the pointer presses Cancel or Keep editing; the arrows change a picker without moving the focus; ⌘1 to ⌘4, ⌘, ⌘[ and ⌘L; each focused control on Settings > Agents is on screen, and Page Up, Page Down, Home, and End scroll Settings > About; a menu choice with the keyboard closes the menu; the focus survives a control that goes away; Esc closes an error message. The command-line tests (`src/desktop/ui/cli_tests.rs`) drive the app through the owner socket.

On 2026-09-27 the agent also drew each screen in a real window with synthetic data (a separate `HOME` under `/tmp`) and looked at a capture of that window only.
