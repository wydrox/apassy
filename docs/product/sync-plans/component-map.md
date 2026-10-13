# Component map (Stage 2, native)

Written by the architect on 2026-10-13 from flow-spec.md (approved at Gate A). The app has no shadcn: each element maps to the Mac kit (egui) or to SwiftUI.

Root `/Users/rafalw/Dev/apassy-integration`. Abbreviations: `kit` = `src/desktop/ui/kit.rs`, `rows` = `src/desktop/ui/settings_rows.rs`, `ST` = `src/desktop/ui/settings.rs`, `S` = `src/desktop/ui/sync.rs`, `R` = `src/desktop/ui/sync/relay.rs`, `Q` = `src/desktop/ui/sync/questions.rs`, `iOS` = `ios/ApassyCompanion/Sources`. Rule: compose from the kit first. New helpers justified: `kit::pop_menu` (promote `src/desktop/ui/detail_rows.rs:332`), `Icon::Phone` (`kit:2811`), two new modules `src/desktop/ui/devices.rs` (hub + its sheets) and `src/desktop/ui/plan.rs` (M4, M5, E), and `src/plan/` (provider, §2c).

## M1 Settings > Devices (hub)

| Element | Use | Missing / compose |
|---|---|---|
| Section, header, status | `SettingsSection::Devices` `settings_view.rs:19`; `header` `:210`; `status_line` `ST:72` | status "N devices · approvals on all" from the merged list |
| Device rows | `rows::section` `rows:77`, `g.row` `rows:134`; `kit::Tile::icon` `kit:1586` + `tile` `:1627`; `row_title` `:164`; "what it does" from `device_words` `Q:178` + `method_words` `S:330`; last seen `relative_time` `kit:196` | one `DeviceRow` (extend `Q:197`) merging `TrustedDevice` (`src/vault/trusted_device.rs:81`), `DeviceView.last_seen_at` (`src/sync/relay/devices.rs:53`, polled 30 s like `Q:824`), `CompanionDevice` (`src/vault/companion.rs:84`, Wi-Fi pairing). No skeleton: the list is local; "last seen" shows "—" until polled |
| Row "⋯" | `pop_menu` `detail_rows.rs:332` → `kit::pop_menu` | "Stop approvals here" only on this Mac's row (= today's switch `ST:166` → `questions_turn_off` `Q:287`); an iPhone stops on itself (I3). Spec clarification |
| Remove… | `questions::remove_device_sheet` `Q:1171` → `questions_remove_device` `Q:889` (rotates the key, relay `DELETE /v1/devices/{id}`) | absorb the relay confirm alert `R:3384` |
| Add a device… + trust line | `kit::button(Prominent)` `kit:810` in `rows::line` controls `rows:150`; `rows::footnote` `rows:55` | opens `DevicesSheet::AddDevice` (M2) |
| Note, empty, error, toast | section footer; `kit::empty_state` `kit:2343`; `kit::notice(Warning)` `kit:2303` + "Pair on this network" → `companion::pairing_section` `companion.rs:161` inline (L3); `kit::toast` `kit:2758` | — |

Removed/merged: `this_mac_group` `ST:225` → one row; `companion::iphone_group` `companion.rs:36` → L3 disclosure (`kit::disclosure` `kit:1326`); `other_macs_group` `ST:329`, `relay_group` `ST:358` with `RELAY_QUESTIONS` `ST:166`, `ADD_IPHONE` `ST:180`, "Add a Mac…"/"Devices…" (`ST:344`, `S:1660`, `S:1666`), `relay::devices_sheet` "Macs that sync" `R:3283` all go.

## M2 "Add a device" sheet

| Element | Use | Missing / compose |
|---|---|---|
| Frame | `kit::sheet/sheet_title/sheet_body/sheet_buttons` `kit:2527/2648/2660/2744` | title "Add a device"; one sheet, drop the `iphone` flag of `add_mac_sheet` `R:3088`; `AddMac.via` `R:261` picks the client |
| QR, link, Copy | `link_qr` `R:3079` + `draw_qr` `companion.rs:322`; `code_block` `kit:1032`; "Copy link" | link text becomes the payload of §2d |
| Waiting | `kit::text` TERTIARY + `egui::Spinner` | — |
| Device asks: words, Confirm with Touch ID, Refuse | poll `relay_add_mac_poll` `R:1958`; `safety_lines` `R:2816`; `relay_ask_confirm` `R:1991` → `OwnerRequest::ConfirmSyncDevice/ConfirmQuestionsDevice` `src/desktop/owner_check.rs:498/510`; `relay_confirmed` → `register_linked_device` `R:2133` → `src/relay/membership.rs:345`; refuse `R:2170` | relabel only |
| Expired, unreachable, success | "New link" (R); `kit::notice` + "Try again" / "Pair on this network instead"; result + "Done" (R) | — |
| First add on a vault with no team | — | §2a codeless creation replaces `questions::team_sheet` `Q:989` (Relay address + Team code → L3 "Use another relay…") |
| A5 test question | nothing exists on any side | needs a card flag (relay-questions-v1 §7.1 → card v2); until then end on "iPhone 17 is connected." |

## M3 Vault > Sync

| Element | Use | Missing / compose |
|---|---|---|
| Choice | `kit::segmented` `kit:1104` over `Pick` `S:1431` {iCloud folder, Relay, Off}; "Other folder…" `kit::menu` `kit:1262` → `choose_folder_sheet` `S:1778` | replaces `sync_picker` `S:1480`; "Personal" `kit::tag(Accent)` `kit:1372` when Free |
| Line, status, Sync now | `rows::note_row` `rows:290`; `S:1592-1618`; `S:1652` → `sync_now` `S:926` | relay words `R:569` → "Apassy" vocabulary |
| iCloud off | `kit::notice` | detect: `picker_choices` `S:1461` has no iCloud folder |
| Pick::Relay | Free → `Sheet::Upgrade{Sync}`; paid → alert (`kit::sheet` + `alert_default_button` `kit:2483`, `alert_cancel` `:2474`) → `RelaySync::enable_on_membership` (§2b) | `RelaySetup` `R:2899` (address, team code, NewCopy/Join) → L3 "Use another relay…" |
| Paid → iCloud | `relay::turn_off_sheet` variant "Sync with {label} instead…" `R:3425` → `relay_switch_to_folder` `R:1749` | — |

## M4 Upgrade sheet (`plan.rs`, `Sheet::Upgrade{from: Sync|Shared|Plan}`)

| Element | Use | Missing |
|---|---|---|
| Headline, 3 lines, price | `sheet_title`; `paint_icon_in(Icon::Check)` `kit:2876` + `paragraph` `kit:169`; `text(Font::Title)` `kit:142`; PRICE from `PlanProvider::offer()` | — |
| Continue to checkout | `button(Prominent)` → `checkout_url()` + browser opener | which helper opens URLs is not verified (check Updates) |
| Not now, Compare plans, reassurance | `button(Style::Link)` `kit:773`; `kit::note` `kit:174` | Compare: three `rows::group` in `ui.columns(3)` |
| Waiting / not confirmed / C3 | `kit::notice(Neutral)` + "Check again" (`refresh()`) / "Cancel"; C3 alert → M3 Pick::Relay path | — |

## M5 Settings > Plan

| Element | Use |
|---|---|
| Section | `SettingsSection::Plan` (`settings_view.rs:19`, `ALL :48` → 7, `label :59`, `tile :79`); `status_line ST:72` |
| Free | `g.labeled` `rows:178`; `g.note_row`; `g.link` "Compare plans" `rows:283` |
| Paid | `g.labeled` renews, email; `g.line` + `button(Bordered)` "Manage subscription" (portal URL); `button(Destructive)` "Sign out of this Mac" + alert |
| States | `g.note_row` offline; `g.tone_row` `rows:298` + "Update payment" |

## I1 iPhone Welcome

| Element | Use | Missing / compose |
|---|---|---|
| Headline, supporting | `PairingHero` `iOS/Views/Pairing/PairingFlowView.swift:72-95` | `AppWelcomeView.swift` rewritten; doors `:41/:48/:54` go |
| Connect to your Mac | `.glassProminent` → new `Views/Connect/ConnectFlowView.swift` with `QRScannerView` | new `Vault/ConnectModel.swift` routes by payload (§2d): `sync` → `JoinModel` steps; `connect` → `QuestionsModel.AttachStep` (`joinAttach…`); fallback → `PairingModel` |
| Paste a link | `JoinFlowView` link step; `VaultText.joinLink` `Vault/VaultText.swift:67` | accept the new payload |
| Camera denied | `CalloutView` `PairingFlowView.swift:126-143` + "Open Settings" | — |
| Routing | `RootModel.Screen` `Models/RootModel.swift:13-26`: `addVault/join/companion` → `connect` (keep `iCloud`); `route() :78` unchanged | — |

Removed: `ConnectQuestionsView` `Views/Main/QuestionsView.swift:6-72`; `AddVaultChoiceView` `Views/Vault/ICloudVaultFlowView.swift:6-26`; pairing door `Views/Pairing/WelcomeView.swift` stays only as L3. Hint texts rewritten: `WelcomeView.swift:37`, `PairingFlowView.swift:24,30`, `PairingModel.swift:239`, `CodeViews.swift:66`, `QuestionsView.swift:33`.

## I2 After connecting

| Element | Use | Missing |
|---|---|---|
| Waiting + words | `PairingScreen` `PairingFlowView.swift:46-69`; `SafetyWords` `Views/Vault/JoinFlowView.swift:308-327` | — |
| Free card | `CalloutView` + `.glassProminent` "Open from iCloud Drive" → `ICloudVaultFlowView` picker | picker has no `directoryURL`; the iCloud Drive > Apassy URL on iOS is unverified |
| Paid | `JoinModel` passphrase → faceID | — |
| Test question, Done | `QuestionsView` row + Face ID; `SymbolTile` `Views/Vault/VaultComponents.swift:162` + haptic | card flag (M2) |

## I3 iPhone Settings > Devices

| Element | Use |
|---|---|
| This iPhone | `QuestionsStateRow` `Views/Settings/DevicesSettingsView.swift:39-54` |
| Vault sync | "Sync service" row `:105` |
| Plan | `SettingsGroupRow` `Views/Vault/SettingsView.swift:90` (make internal); source: `PlanSummary` synced by the Mac (§2c); no purchase |
| L2 list, L3 | "Team devices" `:130` → `DevicesView` `SettingsView.swift:117-172`; `MacPairingRow :57-68` → "Pair on this network" |

## Flow sheets B–E

- **B** confirm "Switch to Apassy?": alert pattern (`kit::sheet` + `alert_default_button`).
- **D** `shared_section` `src/desktop/ui/sidebar.rs:411-454`: label `:418` becomes clickable → `Place::Shared` list column `kit::empty_state` "Share a vault with people. Part of Personal and Team." action "See plans" → `Sheet::Upgrade{Shared}`; paid: "New shared vault…" disabled until V3.
- **E** `Sheet::PlanEnded` (`plan.rs`): alert "Move sync to iCloud Drive" (Prominent → `relay_switch_to_folder` `R:1749`) / "Turn sync off" (`relay_turn_off` `R:1627`); raised when the provider reports `Ended` for a vault whose membership has purpose `sync`. "Manage subscription" → portal URL.
