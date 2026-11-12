# The node of the Mac

Date: 2026-11-03. Plan: [implementation plan S2–S3](../design/implementation-plan-s2-s3.md), decisions D1, D6, D9, units N4 (the node over the tailnet) and N7 (Settings > Devices). Mockup: [devices-settings-mockup.html](../design/devices-settings-mockup.html). Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) stage 2. Contract: [node-pairing-v1](../contracts/node-pairing-v1.md). Linux: [linux-node.md](linux-node.md).

The Mac app has its own **node**: the relay of the questions, the feed, and the access requests, inside the app. With **Reachable on Your Tailnet** on, your iPhone and your other Macs reach it straight over Tailscale, at `https://<Tailscale IPv4 of this Mac>:8444`, behind a self-signed certificate that they pin. The approvals then never go to `apassy-relay.wyderka.cc`. Without Tailscale, the approvals go through Apassy relay, as before.

## Settings > Devices

| Group | What it shows |
| --- | --- |
| This Mac | "Reachable on Your Tailnet" (the route switch), Address (the Tailscale IPv4 and the port, with Copy for the whole origin), Node Words, one line for each problem, "Move to This Mac…" when it applies, and Notifications |
| Devices | One line for each device of each team: name, the route word, the last contact, and Revoke… (Details… for a Linux node); `<Kind> · <Role>` is the hover text and the VoiceOver description of the name. The count and the ⓘ are by the title |
| (button) | **Add an iPhone or a Mac…**: through the node when the route is on, else through Apassy relay (hosted Connect, ADR 0032) |
| Wi-Fi Pairing | Only while a Wi-Fi iPhone is paired ([companion](companion.md)) |

The route words: **via your Mac** (straight to this Mac over your tailnet, green), **via Apassy relay** (through `apassy-relay.wyderka.cc`, end-to-end encrypted, grey), **Tailnet** (your own Linux node, blue), **Wi-Fi** (the old pairing, orange).

The last contact reads "Now" under a minute, then "4 min ago", "3 h ago", "Yesterday", "12 Sep".

Only one button is blue at a time: "Add an iPhone or a Mac…", or "Move to This Mac…" while that row shows.

## Turn the route on

1. Install Tailscale on the Mac and sign in. Settings shows "Tailscale is not installed." with **Get Tailscale…** (tailscale.com/download), or "Tailscale is not connected." with **Check Again**. The app also looks again every 10 s while Devices shows.
2. Turn on **Reachable on Your Tailnet**. The owner check (Touch ID or the passphrase) comes first; the switch moves only after it. Off asks too.
3. "Starting…" shows until the node listens on the tailnet address. Then Address (with the port) and Node Words show.
4. Install Tailscale on the iPhone too, and turn it on there.

The route runs while the vault is unlocked. A lock, a quit, and the end of the waiting runs stop it: Settings says "Stopped while the vault is locked." The setting stays, and the route starts again at the next unlock.

Only devices on your tailnet can connect, and nothing opens to the internet. Each device still signs in with its own key.

## Pair a device

Select **Add an iPhone or a Mac…**.

- **An iPhone**: scan the code with the Apassy app. The iPhone shows two safety words; confirm on the Mac only if they are the same, then pass the owner check. With the route on, the link names this Mac's node, its pin, and its other addresses; the iPhone needs Tailscale on to reach the Mac.
- **A Mac**: paste the link on the other Mac instead.
- **An Apple Watch** pairs from its iPhone.

**Node Words** are six words from this Mac's certificate. Your iPhone shows the same words in its Settings > Devices. Other words there mean another certificate: revoke that iPhone and pair again.

## Move the approvals to this Mac

A vault whose approvals still go through Apassy relay shows the row "Approvals go through Apassy relay" with **Move to This Mac…** while the route is on. The move makes an approvals team on this Mac (the owner check first), shows the pairing code for the iPhone (a new key and a new confirmation: identity is per team), and after the confirmed join takes the old devices off Apassy relay. The Apple Watch has its own key: pair it again from the iPhone. The move takes the iPhone and the watch; other Macs that read this Mac's feed stay where they are.

## Revoke a device

Select **Revoke…** on its row. The sheet says what changes: "It can no longer see or answer questions." for an iPhone or a watch, "It stops syncing VAULT and seeing approvals." for another Mac. Revoking an iPhone offers "Also revoke WATCH" for its Apple Watch, on by default; the Mac revokes the watch's key directly, without the iPhone. Revoke is the red button; Return presses Cancel. Then the owner check, then:

- a device of this Mac's node: its tokens stop at once and its push handle goes; its row of the vault goes, with a new question key, so it cannot read the next questions;
- a device of Apassy relay: today's removal (the row stays deleted, a new question key, and the relay removes the device when this Mac can).

The row leaves at once and "NAME revoked" shows. A failed node revoke keeps the row with "Not revoked. Try Again". This Mac itself has no Revoke….

A **Linux node** row has **Details…**: its kind, route, and address, and **Revoke…**: after the owner check, this Mac stops syncing that vault through the node (its copy stays there).

## The port

The node listens on port **8444** of the Tailscale address. The port is shown, not edited.

- "Another app uses port 8444." with **Use Port 8445** shows only before the first pairing: the origin changes with the port, so a paired device would need to pair again.
- After the first pairing the line is "Another app uses port 8444. Quit it." with no button.
- "The address changed. Paired devices must pair again." with **Pair Again…** shows when Tailscale gave this Mac another address than the paired devices know. Pair Again… opens the pairing of a new team on the new address.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| The switch does not move | Tailscale is not installed or not connected, or the vault is locked. |
| "Starting…" stays | After 15 s the line says why. Check Again tries again. |
| The iPhone shows "Turn on Tailscale on this iPhone to reach MAC" | Turn Tailscale on in the iPhone. The approvals wait on the Mac meanwhile. |
| The iPhone shows other Node Words | Another certificate answers. Revoke that iPhone on the Mac and pair it again. |

## Development

The demo build (`cargo run --features desktop`, no vault) shows every frame of the mockup in Settings > Devices: the menu at the top picks one, and `APASSY_DEMO_DEVICES` (1, 3a, 3b, 3c, 3d, 3f, 3g, 3h, 4, 5a, 5b, 5c, 6a, 6b, 6d, 7, 9a, 9b, 9c, 9d, 9d+, 9e) opens it at start. 3e and 6c are frame 1 with the ⓘ open. The pairing and move sheets (frames 2 and 4b–4d) are those of the vault build.

The section never runs the Tailscale command line in a frame: a worker thread reads `Node::status` at most every 10 s while Devices shows and at once after a change (`NodeCache` in `src/desktop/ui/devices.rs`).
