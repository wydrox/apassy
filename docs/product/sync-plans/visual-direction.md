# Visual direction: Connect devices, sync, and plans

The theme is established: the approved mockups `docs/design/app-v2-mockup.html` (Mac) and `docs/design/ios-v1-mockup.html` (iPhone). This flow changes no tokens, colors, fonts, or radii. It uses the existing parts:

- the grouped rows of Settings;
- the tiles;
- the sheets;
- on the iPhone, `Form` and `List`.

It designs only the hero, the peak, and the ending, with the parts it already has. Gate B does not apply, because the theme is established.

## Rules

- **One accent per screen.** The system blue is for the one primary action. Green is only for "connected" and the check of the test answer. Red is only for "Remove…" and errors. Never use a color alone: each state also has a word or an icon.
- **No plan color.** "Personal" and "Team" are small gray tags, like the "Production" tag of a credential. A paid plan is not a reward color, and Free is not a lesser gray.
- **Devices look like the Agents list.** A round tile with the device glyph, the name, and one line of what it does. Same row height, same "⋯".
- **The relay is invisible.** No address, no code, no server words in L1 or L2.

## Hero: Settings > Devices, empty (only this Mac)

```
┌─ Devices ─────────────────────────────── [Add a device…] ┐
│                                                           │
│        (iPhone glyph, 48 pt, secondary color)             │
│        Approve your agents from your iPhone               │
│        Add a device to get each question there too.       │
│                   [ Add a device… ]                       │
│        A new device needs your Touch ID here.             │
└───────────────────────────────────────────────────────────┘
```

## Peak: the test question (A5), Mac sheet after Confirm

```
┌─ Add a device ────────────────────────────────────────────┐
│  ✓ iPhone 17 is connected                    (green check) │
│                                                            │
│  Try it: approve the test on your iPhone.                  │
│  ◌ Waiting for iPhone 17…            [Skip]               │
│                                                            │
│  → after the answer:                                       │
│  ✓ Your iPhone answered in 3 seconds.                      │
│    Each question now goes to both devices.                 │
│                       [Add another device]   [ Done ]      │
└────────────────────────────────────────────────────────────┘
```

- "Done" is the primary button. "Add another device" is plain.
- The waiting line uses the existing progress dot of the sync status, not a new spinner.
- On the iPhone, the test arrives as a normal notification titled "Test from MacBook Pro". It opens a question card with the "Test" tag, and one button, "Approve with Face ID". The success is a check with a light haptic (`.success`). Reduce Motion drops the animation.

## Ending: the new device row

```
│ (iPhone tile)  iPhone 17                               ⋯ │
│                Approves with Face ID · Syncs through     │
│                iCloud Drive · now                         │
```

For one second after the add, the row is selected, then it settles. The status line of the section changes to "2 devices · approvals on all".

## Upgrade sheet (M4)

```
┌─ Sync through Apassy ─────────────────────────────────────┐
│  ✓ Changes on every device in seconds                      │
│  ✓ Works without iCloud                                    │
│  ✓ End-to-end encrypted. Apassy can't read your vault.     │
│                                                            │
│  Personal · PRICE a month, or PRICE a year                 │
│  Includes shared vaults with a few people.                 │
│                                                            │
│  Cancel any time in Settings > Plan.                       │
│  Your vault stays on your devices.                         │
│                                                            │
│  Compare plans          [Not now]  [Continue to checkout]  │
└────────────────────────────────────────────────────────────┘
```

- The checks are secondary-gray, not green: this is a list, not a success.
- "Not now" is a bordered button of the same size as the primary button (symmetry).
- The price line is body text, not a large number (no anchoring theater).

## Plan section (M5)

These are the same grouped rows as the other sections. The header tile is gray for every plan.

- **Free:** "Free" with the line "iCloud Drive sync · approvals on all your devices", and "Compare plans".
- **Paid:** "Personal" with "renews DATE", "Manage subscription", and the email.

## Accessibility

- The QR code always has its link as text and "Copy link".
- The safety words are text at 22 pt, so VoiceOver reads them.
- Targets are at least 28 pt on the Mac and 44 pt on the iPhone.
- The test question works with VoiceOver: the notification action is labelled "Approve test with Face ID".
