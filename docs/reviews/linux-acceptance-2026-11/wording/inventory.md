# L7 wording inventory: every text that names a Mac thing, by platform

Generated from the source of `feat/linux-wording` (unit L7, 2026-11-10) by evaluating
each `concat!` that uses a macro of `src/wording.rs` once with the macOS values and once
with the Linux values. The macOS column is the text before L7, byte for byte (checked
by comparing every string literal of the 89 changed Rust files with the base commit
`d7f192af`, macros folded to their macOS values: the only differences are three format
strings whose named argument became positional, the owner-client error with the same
output, and the Linux-only note of Settings › Updates).

Classes: **a** names this computer or its owner check (now platform wording);
**b** names a feature that Linux does not have (Linux text says what Linux uses);
**shortcut** a shortcut hint (Linux modifier names). Rows from tests are not listed.
About 20 class-a rows (`owner_check!`, `touch_id!`) come from the earlier pass
(`470b5809`); the rest are L7.

<!-- generated: 425 source texts, 170 test expectations -->
| File:line | Class | macOS (unchanged) | Linux |
| --- | --- | --- | --- |
| `src/agent/mcp.rs:372` | a | …tual command. Scoped requests appear in Mac Decisions and iPhone Requests. Query apassy_access_reque… | …tual command. Scoped requests appear in Apassy Decisions and iPhone Requests. Query apassy_access_re… |
| `src/agent/mcp.rs:1271` | a | …uery its access status or review on the Mac. | …uery its access status or review on the computer. |
| `src/agent/mcp.rs:1279` | a | The conservative Mac-local access-request budget is exhausted. Review on the Mac. | The conservative computer-local access-request budget is exhausted. Review on the computer. |
| `src/broker/access_once.rs:167` | a | this Mac | this computer |
| `src/broker/access_once.rs:203` | a | Review on this Mac. Another scope is active or the conservative local request budget is exhausted. | Review on this computer. Another scope is active or the conservative local request budget is exhaust… |
| `src/broker/access_once.rs:212` | a | …available to this agent. Review on this Mac. | …available to this agent. Review on this computer. |
| `src/broker/approvals/owner_auth.rs:566` | a | on this Mac | on this computer |
| `src/broker/approvals/owner_auth.rs:731` | a | Reach this Mac on your tailnet | Reach this computer on your tailnet |
| `src/broker/approvals/owner_auth.rs:757` | a | change how often Apassy asks for Touch ID | change how often Apassy asks for the passphrase or system authentication |
| `src/broker/approvals/owner_auth.rs:967` | a | let your iPhone and Macs reach this Mac directly on your tailnet | let your iPhone and computers reach this computer directly on your tailnet |
| `src/broker/approvals/owner_auth.rs:975` | a | stop the tailnet route of this Mac; approvals go through Apassy relay | stop the tailnet route of this computer; approvals go through Apassy relay |
| `src/broker/approvals/owner_auth.rs:999` | a | …"{}\", which returns to {back}, to this Mac | …"{}\", which returns to {back}, to this computer |
| `src/broker/approvals/owner_auth.rs:1011` | a | let remote agents reach this Mac through Tailscale Funnel | let remote agents reach this computer through Tailscale Funnel |
| `src/broker/approvals/owner_auth.rs:1423` | a | …is not connected or not paired, or this Mac has no Touch ID sensor. | …is not connected or not paired, or this computer has no Touch ID sensor. |
| `src/broker/approvals/owner_auth.rs:1431` | a | …ocked after failed attempts. Unlock the Mac with its password to reset it. | …ocked after failed attempts. Unlock the computer with its password to reset it. |
| `src/broker/approvals/owner_auth.rs:2603` | a | run the bouncer brain on this Mac | run the bouncer brain on this computer |
| `src/broker/approvals/owner_auth.rs:2806` | a | … which returns to grok.example, to this Mac | … which returns to grok.example, to this computer |
| `src/broker/approvals/owner_auth.rs:2814` | a | …\", which returns to localhost, to this Mac | …\", which returns to localhost, to this computer |
| `src/broker/approvals/owner_window.rs:33` | a | Until the Mac locks | Until the computer locks |
| `src/broker/brain_host.rs:32` | a | …ave yet. The bouncer brain runs on this Mac. | …ave yet. The bouncer brain runs on this computer. |
| `src/broker/decide.rs:619` | a | …t could not be withdrawn. Review on the Mac. | …t could not be withdrawn. Review on the computer. |
| `src/broker/decide.rs:1081` | a | this Mac | this computer |
| `src/broker/heads_place.rs:46` | a | The bouncer brain on this Mac runs outside Apassy without APASSY_BOUNCER_KEY, so it takes no head se… | The bouncer brain on this computer runs outside Apassy without APASSY_BOUNCER_KEY, so it takes no he… |
| `src/broker/heads_place.rs:55` | a | the bouncer brain on this Mac | the bouncer brain on this computer |
| `src/broker/heads_place.rs:111` | a | The head set on this Mac cannot go up: {text}. | The head set on this computer cannot go up: {text}. |
| `src/broker/heads_place.rs:312` | a | the head file is not on this Mac | the head file is not on this computer |
| `src/broker/heads_place.rs:320` | a | its manifest.json is not on this Mac | its manifest.json is not on this computer |
| `src/broker/heads_place.rs:363` | a | …ts manifest.json names a folder on this Mac | …ts manifest.json names a folder on this computer |
| `src/broker/operations.rs:307` | a | …t be withdrawn. Check its status on the Mac. | …t be withdrawn. Check its status on the computer. |
| `src/broker/run.rs:190` | a | (the cloud agent, not on this Mac) | (the cloud agent, not on this computer) |
| `src/broker/run.rs:1165` | a | …s cannot be established. Review on this Mac. | …s cannot be established. Review on this computer. |
| `src/broker/shadow.rs:239` | a | the bouncer brain on this Mac | the bouncer brain on this computer |
| `src/cli/commands.rs:67` | a | … declaration of each credential on this Mac, and adds all of them at once. It prints one line for ea… | … declaration of each credential on this computer, and adds all of them at once. It prints one line f… |
| `src/cli/commands.rs:109` | a | … N] Owner check. A remote agent of this Mac (remote access on) for a client without the MCP authoriz… | … N] Owner check. A remote agent of this computer (remote access on) for a client without the MCP aut… |
| `src/cli/commands.rs:1452` | a | {} (ID {}) is a remote agent of this Mac. Save the token now. Apassy does not show it again: | {} (ID {}) is a remote agent of this computer. Save the token now. Apassy does not show it again: |
| `src/cli/doctor.rs:76` | b | … path. If Apassy is closed, open Apassy.app. | … path. If Apassy is closed, open Apassy. |
| `src/cli/doctor.rs:103` | b | Use the apassy program inside the running Apassy.app. | Use the apassy program of the same package version as the running window. |
| `src/cli/doctor.rs:221` | b | Reinstall Apassy.app. For a source build, build all programs with cargo build --locked --features de… | Reinstall Apassy. For a source build, build all programs with cargo build --locked --features deskto… |
| `src/cli/setup.rs:21` | a+b | …en trust the hook in Codex with /hooks. Apassy.app includes the MCP server, prompt hook, and sandbox… | …en trust the hook in Codex with /hooks. The Apassy package includes the MCP server and the prompt ho… |
| `src/cli/setup.rs:266` | b | …to this program. Use the apassy program inside Apassy.app. | …to this program. Use the apassy program of the Apassy package (/usr/bin/apassy). |
| `src/cli/setup.rs:292` | b | …s missing. Reinstall the complete Apassy.app package, then try setup again. | …s missing. Reinstall the complete Apassy package, then try setup again. |
| `src/cli/setup.rs:492` | b | Keep Apassy.app open and the vault unlocked. Restart the host. Check Apassy with /mcp. | Keep Apassy open and the vault unlocked. Restart the host. Check Apassy with /mcp. |
| `src/companion/control.rs:75` | a | …passy found no network address for this Mac. Connect the Mac to Wi-Fi or Ethernet. Nothing was paire… | …passy found no network address for this computer. Connect the computer to Wi-Fi or Ethernet. Nothing… |
| `src/desktop/auto_lock.rs:41` | a | When the Mac locks or sleeps | When the computer locks or sleeps |
| `src/desktop/brain_host.rs:51` | a | The bouncer brain runs on this Mac again. | The bouncer brain runs on this computer again. |
| `src/desktop/brain_host.rs:58` | a | … The bouncer gate still decides on this Mac. | … The bouncer gate still decides on this computer. |
| `src/desktop/brain_host.rs:66` | a | … The bouncer gate still decides on this Mac. | … The bouncer gate still decides on this computer. |
| `src/desktop/brain_host.rs:73` | a | The bouncer brain trains on this Mac again. | The bouncer brain trains on this computer again. |
| `src/desktop/brain_host.rs:109` | a | The TLS settings of this Mac did not load ({error}). | The TLS settings of this computer did not load ({error}). |
| `src/desktop/brain_host.rs:154` | a | …thing changed. The TLS settings of this Mac did not load ({error}). | …thing changed. The TLS settings of this computer did not load ({error}). |
| `src/desktop/brain_host.rs:175` | a | …ved, but the bouncer brain runs on this Mac: {problem} | …ved, but the bouncer brain runs on this computer: {problem} |
| `src/desktop/brain_hosting_ui.rs:47` | a | The bouncer gate still decides on this Mac. | The bouncer gate still decides on this computer. |
| `src/desktop/brain_hosting_ui.rs:55` | a | …used, so the bouncer brain runs on this Mac. | …used, so the bouncer brain runs on this computer. |
| `src/desktop/brain_hosting_ui.rs:62` | a | This Mac: nothing leaves this Mac. | This computer: nothing leaves this computer. |
| `src/desktop/brain_hosting_ui.rs:71` | a | The bouncer gate on this Mac decides every run. No answer means Apassy asks you. | The bouncer gate on this computer decides every run. No answer means Apassy asks you. |
| `src/desktop/brain_hosting_ui.rs:80` | a | … The bouncer gate still decides on this Mac. | … The bouncer gate still decides on this computer. |
| `src/desktop/brain_hosting_ui.rs:93` | a | …e. Apassy keeps it in the vault on this Mac. | …e. Apassy keeps it in the vault on this computer. |
| `src/desktop/brain_hosting_ui.rs:107` | a | What Leaves This Mac | What Leaves This computer |
| `src/desktop/brain_hosting_ui.rs:252` | a | This Mac | This computer |
| `src/desktop/brain_hosting_ui.rs:274` | a | The bouncer brain runs on this Mac. | The bouncer brain runs on this computer. |
| `src/desktop/brain_hosting_ui.rs:635` | a | Consent version {}. Each change needs Touch ID. | Consent version {}. Each change needs the passphrase or system authentication. |
| `src/desktop/companion.rs:288` | a | …ort {}. Paired Wi-Fi iPhones reach this Mac. | …ort {}. Paired Wi-Fi iPhones reach this computer. |
| `src/desktop/companion.rs:422` | a | …ame}\" is removed. It cannot reach this Mac any more. | …ame}\" is removed. It cannot reach this computer any more. |
| `src/desktop/companion.rs:440` | a | …eset. Every iPhone is removed, and this Mac has a new certificate. Pair each iPhone again. | …eset. Every iPhone is removed, and this computer has a new certificate. Pair each iPhone again. |
| `src/desktop/node.rs:566` | a | {} is connected to this Mac. It sees no credential until you choose some in Agents. | {} is connected to this computer. It sees no credential until you choose some in Agents. |
| `src/desktop/node.rs:623` | a | …ss is off. No remote agent reaches this Mac. | …ss is off. No remote agent reaches this computer. |
| `src/desktop/owner_check.rs:1224` | a | Change how often Apassy asks for Touch ID to {} on this Mac? | Change how often Apassy asks for the passphrase or system authentication to {} on this computer? |
| `src/desktop/owner_check.rs:1583` | a | Add the Mac \"{name}\" to the questions of this vault through the Apassy relay. It can then see the … | Add the computer \"{name}\" to the questions of this vault through the Apassy relay. It can then see… |
| `src/desktop/owner_check.rs:1605` | a | another Mac | another computer |
| `src/desktop/owner_check.rs:1608` | a | …y signs the answer with the key of this Mac and sends it, end-to-end encrypted, through the relay. | …y signs the answer with the key of this computer and sends it, end-to-end encrypted, through the rel… |
| `src/desktop/owner_check.rs:1626` | a | …and signs out. Your vaults stay on this Mac. | …and signs out. Your vaults stay on this computer. |
| `src/desktop/owner_check.rs:1660` | a | Make this Mac reachable on your tailnet. Your iPhone and Macs then reach it directly over Tailscale.… | Make this computer reachable on your tailnet. Your iPhone and computers then reach it directly over … |
| `src/desktop/owner_check.rs:1661` | a | Stop the tailnet route of this Mac. Approvals then go through Apassy relay. | Stop the tailnet route of this computer. Approvals then go through Apassy relay. |
| `src/desktop/owner_check.rs:1663` | a | Revoke \"{}\". This Mac stops syncing through it. Its copy stays there. | Revoke \"{}\". This computer stops syncing through it. Its copy stays there. |
| `src/desktop/owner_check.rs:1681` | a | Connect {} to this Mac as a new agent? {}.{} Allow only if the page in your browser shows this code:… | Connect {} to this computer as a new agent? {}.{} Allow only if the page in your browser shows this … |
| `src/desktop/owner_check.rs:1696` | a | …cess? Remote agents can then reach this Mac through Tailscale Funnel while it is awake and the vault… | …cess? Remote agents can then reach this computer through Tailscale Funnel while it is awake and the … |
| `src/desktop/owner_check.rs:1717` | a | …your project or home folder leaves this Mac, and the bouncer gate still decides on this Mac. | …your project or home folder leaves this computer, and the bouncer gate still decides on this compute… |
| `src/desktop/owner_check.rs:1726` | a | Run the bouncer brain on this Mac again. Bouncer requests stay on this Mac. | Run the bouncer brain on this computer again. Bouncer requests stay on this computer. |
| `src/desktop/owner_check.rs:1782` | a | Train the bouncer brain on this Mac again. Training examples stay on this Mac. | Train the bouncer brain on this computer again. Training examples stay on this computer. |
| `src/desktop/owner_check.rs:2350` | a | Instance trusted on this Mac. | Instance trusted on this computer. |
| `src/desktop/owner_check.rs:3696` | a | Connect Grok Bot to this Mac as a new agent? Returns to grok.example. Allow only | Connect Grok Bot to this computer as a new agent? Returns to grok.example. Allow only |
| `src/desktop/owner_check.rs:3705` | a | A program on this Mac | A program on this computer |
| `src/desktop/owner_check.rs:3723` | a | A program on this Mac can start this request. | A program on this computer can start this request. |
| `src/desktop/owner_frequency.rs:80` | a | Saved for this Mac. | Saved for this computer. |
| `src/desktop/owner_store.rs:692` | a | The Mac session changed during unlock. Confirm again. | The computer session changed during unlock. Confirm again. |
| `src/desktop/owner_store/decisions.rs:485` | a | …akes the bouncer less careful. It needs Touch ID or the passphrase. | …akes the bouncer less careful. It needs the passphrase or system authentication. |
| `src/desktop/remote_feeds.rs:218` | a | Another Mac | Another computer |
| `src/desktop/ui/agent_onboarding.rs:221` | a | You confirm once with Touch ID or the passphrase. Then the bouncer decides each use, and a question … | You confirm once with the passphrase or system authentication. Then the bouncer decides each use, an… |
| `src/desktop/ui/agent_onboarding.rs:251` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/agent_onboarding.rs:355` | b | Configuration saved. Start {} in the Apassy sandbox on macOS with the command below. Keep Apassy ope… | Configuration saved. Start {} with the command below. On Linux it runs as your user: the Apassy sand… |
| `src/desktop/ui/agent_setup.rs:184` | b | …ot find the app tools. Reinstall Apassy.app. | …ot find the app tools. Reinstall Apassy. |
| `src/desktop/ui/agent_setup.rs:192` | b | … needs {}. Reinstall the complete Apassy.app package. | … needs {}. Reinstall the complete Apassy package. |
| `src/desktop/ui/agent_setup.rs:313` | b | …passy-mcp. Reinstall the complete Apassy.app package. | …passy-mcp. Reinstall the complete Apassy package. |
| `src/desktop/ui/agent_setup.rs:320` | b | …assy-hook. Reinstall the complete Apassy.app package. | …assy-hook. Reinstall the complete Apassy package. |
| `src/desktop/ui/agents.rs:689` | a | Adding credentials asks for Touch ID. | Adding credentials asks for the passphrase or system authentication. |
| `src/desktop/ui/agents.rs:806` | a | … active credential is available on this Mac. | … active credential is available on this computer. |
| `src/desktop/ui/agents.rs:814` | a | …ctive credentials are available on this Mac. | …ctive credentials are available on this computer. |
| `src/desktop/ui/agents.rs:830` | a | Use this vault on this Mac | Use this vault on this computer |
| `src/desktop/ui/agents.rs:836` | a | Agents stay on this Mac. Connect them here before an agent can use a credential. | Agents stay on this computer. Connect them here before an agent can use a credential. |
| `src/desktop/ui/agents_page.rs:85` | a | Port 443 of this Mac is public through Funnel. | Port 443 of this computer is public through Funnel. |
| `src/desktop/ui/agents_page.rs:177` | a | Credential values stay on this Mac. | Credential values stay on this computer. |
| `src/desktop/ui/agents_page.rs:182` | a | Switching on needs Touch ID. Keep this Mac unlocked and awake. | Switching on needs Touch ID. Keep this computer unlocked and awake. |
| `src/desktop/ui/agents_page.rs:615` | a | Cloud agents can reach this Mac | Cloud agents can reach this computer |
| `src/desktop/ui/agents_page.rs:742` | a | Connect agents on that Mac. | Connect agents on that computer. |
| `src/desktop/ui/agents_page.rs:757` | a | …Show agents on my other devices on that Mac. | …Show agents on my other devices on that computer. |
| `src/desktop/ui/agents_page.rs:772` | a | On that Mac, open Apassy. | On that computer, open Apassy. |
| `src/desktop/ui/agents_page.rs:949` | a | This Mac | This computer |
| `src/desktop/ui/agents_page.rs:994` | a |  with Touch ID |  with the passphrase or system authentication |
| `src/desktop/ui/agents_page.rs:1140` | a | Connect it again on its Mac. | Connect it again on its computer. |
| `src/desktop/ui/bouncer.rs:125` | a | This Mac | This computer |
| `src/desktop/ui/bouncer.rs:154` | a | This Mac | This computer |
| `src/desktop/ui/bouncer_load.rs:106` | a | This Mac | This computer |
| `src/desktop/ui/browser_settings.rs:93` | a | Fills ask for Touch ID as set in Security › How often to ask. Agents never get the password. | Fills ask for the passphrase or system authentication as set in Security › How often to ask. Agents … |
| `src/desktop/ui/cli_tools.rs:50` | b | …issing {}. Reinstall the complete Apassy.app package. | …issing {}. Reinstall the complete Apassy package. |
| `src/desktop/ui/cli_tools.rs:62` | b | …xecutable. Reinstall the complete Apassy.app package. | …xecutable. Reinstall the complete Apassy package. |
| `src/desktop/ui/decisions.rs:1121` | a | {} · Mac review | {} · Computer review |
| `src/desktop/ui/decisions.rs:1330` | a | This Mac | This computer |
| `src/desktop/ui/decisions.rs:1380` | a | …could not be dispatched. Review on this Mac. | …could not be dispatched. Review on this computer. |
| `src/desktop/ui/decisions.rs:2287` | a | … can read these secrets. An allow needs Touch ID or the passphrase now. A notification is not an app… | … can read these secrets. An allow needs the passphrase or system authentication now. A notification … |
| `src/desktop/ui/decisions.rs:3096` | a | {} needs Touch ID or the passphrase. | {} needs the passphrase or system authentication. |
| `src/desktop/ui/decisions.rs:3098` | a | {} and {} need Touch ID or the passphrase. | {} and {} need the passphrase or system authentication. |
| `src/desktop/ui/decisions.rs:3185` | a | Review on this Mac. Remote publication is unavailable: {p} | Review on this computer. Remote publication is unavailable: {p} |
| `src/desktop/ui/decisions.rs:3196` | a | Review on this Mac. The relay connection is not ready. | Review on this computer. The relay connection is not ready. |
| `src/desktop/ui/decisions.rs:3209` | a | Review on this Mac. Connect an iPhone before creating a request to send there. | Review on this computer. Connect an iPhone before creating a request to send there. |
| `src/desktop/ui/decisions.rs:3220` | a | Mac-verified fields | Computer-verified fields |
| `src/desktop/ui/decisions.rs:3226` | a | Mac {} · Vault {} | Computer {} · Vault {} |
| `src/desktop/ui/decisions.rs:3265` | a | Requested scope; checked against Mac policy | Requested scope; checked against computer policy |
| `src/desktop/ui/decisions.rs:3340` | a | Grant access on this Mac… | Grant access on this computer… |
| `src/desktop/ui/decisions.rs:3510` | a | {} · on this Mac · 1 of {count} | {} · on this computer · 1 of {count} |
| `src/desktop/ui/decisions_activity.rs:29` | a | This Mac | This computer |
| `src/desktop/ui/decisions_activity.rs:215` | a | another Mac | another computer |
| `src/desktop/ui/decisions_bouncer.rs:29` | a | A program on this Mac can start this request. | A program on this computer can start this request. |
| `src/desktop/ui/decisions_bouncer.rs:821` | a | Asks for Touch ID or the passphrase. | Asks for the passphrase or system authentication. |
| `src/desktop/ui/devices.rs:39` | a | Your iPhone and Macs reach this Mac directly. | Your iPhone and computers reach this computer directly. |
| `src/desktop/ui/devices.rs:51` | a | Add an iPhone or a Mac… | Add an iPhone or a computer… |
| `src/desktop/ui/devices.rs:53` | a | Move Approvals to This Mac… | Move Approvals to This computer… |
| `src/desktop/ui/devices.rs:69` | a | Your iPhone and Macs reach this Mac over Tailscale. | Your iPhone and computers reach this computer over Tailscale. |
| `src/desktop/ui/devices.rs:78` | a | Switching needs Touch ID. It stops when the vault locks. | Switching needs the passphrase or system authentication. It stops when the vault locks. |
| `src/desktop/ui/devices.rs:86` | a | …y words to compare: six words from this Mac's certificate. | …y words to compare: six words from this computer's certificate. |
| `src/desktop/ui/devices.rs:93` | a | The same words are not proof of this Mac. The iPhone checks the whole certificate. | The same words are not proof of this computer. The iPhone checks the whole certificate. |
| `src/desktop/ui/devices.rs:101` | a | via your Mac: straight to this Mac over your tailnet. | via your computer: straight to this computer over your tailnet. |
| `src/desktop/ui/devices.rs:135` | a | This Mac was removed. Turning it on needs a new link. | This computer was removed. Turning it on needs a new link. |
| `src/desktop/ui/devices.rs:140` | a | This Mac was removed from the questions of this vault. | This computer was removed from the questions of this vault. |
| `src/desktop/ui/devices.rs:146` | a | … then join the vault again from another Mac. | … then join the vault again from another computer. |
| `src/desktop/ui/devices.rs:156` | a | Only this Mac changes them. | Only this computer changes them. |
| `src/desktop/ui/devices.rs:158` | a | Other Macs | Other computers |
| `src/desktop/ui/devices.rs:161` | a | Add a Mac… | Add a computer… |
| `src/desktop/ui/devices.rs:169` | a | Turning it on needs Touch ID. Off needs none. | Turning it on needs the passphrase or system authentication. Off needs none. |
| `src/desktop/ui/devices.rs:178` | a | Your iPhone and your other Macs of this vault show this Mac's agents. | Your iPhone and your other computers of this vault show this computer's agents. |
| `src/desktop/ui/devices.rs:185` | a | Only this Mac changes them. | Only this computer changes them. |
| `src/desktop/ui/devices.rs:186` | a | Off: Apassy deletes this Mac's feed from the relay. | Off: Apassy deletes this computer's feed from the relay. |
| `src/desktop/ui/devices.rs:194` | a | The Macs that sync this vault. | The computers that sync this vault. |
| `src/desktop/ui/devices.rs:195` | a | Devices… lists them; Add a Mac… links one more. | Devices… lists them; Add a computer… links one more. |
| `src/desktop/ui/devices.rs:203` | a | Approvals already go through this Mac. | Approvals already go through this computer. |
| `src/desktop/ui/devices.rs:229` | a | via your Mac | via your computer |
| `src/desktop/ui/devices.rs:259` | a | Mac | Computer |
| `src/desktop/ui/devices.rs:500` | a | Tailnet on · This Mac only | Tailnet on · This computer only |
| `src/desktop/ui/devices.rs:502` | a | This Mac only | This computer only |
| `src/desktop/ui/devices.rs:710` | a | This Mac | This computer |
| `src/desktop/ui/devices.rs:1017` | a | This Mac | This computer |
| `src/desktop/ui/devices.rs:1120` | a | Keep them free over Tailscale with this Mac as the node. | Keep them free over Tailscale with this computer as the node. |
| `src/desktop/ui/devices.rs:1264` | a | Its copy of the vault stays on that Mac. | Its copy of the vault stays on that computer. |
| `src/desktop/ui/devices.rs:1331` | a | Revoke: this Mac stops syncing {vault} through it. Its copy stays there. | Revoke: this computer stops syncing {vault} through it. Its copy stays there. |
| `src/desktop/ui/devices.rs:1367` | a | The iPhone app now reaches this Mac through your tailnet. | The iPhone app now reaches this computer through your tailnet. |
| `src/desktop/ui/devices.rs:1373` | a | The iPhone app now reaches this Mac through Apassy relay. | The iPhone app now reaches this computer through Apassy relay. |
| `src/desktop/ui/devices.rs:1415` | a | On a Mac, paste the link instead. | On a computer, paste the link instead. |
| `src/desktop/ui/devices.rs:1419` | a | It approves runs through this Mac. | It approves runs through this computer. |
| `src/desktop/ui/devices.rs:1422` | a | …iPhone needs Tailscale on to reach this Mac. | …iPhone needs Tailscale on to reach this computer. |
| `src/desktop/ui/devices.rs:1427` | a | Move Approvals to This Mac | Move Approvals to This computer |
| `src/desktop/ui/devices.rs:1428` | a | Your iPhone pairs again, with this Mac. | Your iPhone pairs again, with this computer. |
| `src/desktop/ui/devices.rs:1438` | a | Questions now go through this Mac. | Questions now go through this computer. |
| `src/desktop/ui/devices.rs:1442` | a | Approvals already use this Mac. | Approvals already use this computer. |
| `src/desktop/ui/devices.rs:1454` | a | Mac | computer |
| `src/desktop/ui/devices.rs:1994` | a | on the tailnet address of this Mac is taken | on the tailnet address of this computer is taken |
| `src/desktop/ui/devices.rs:2122` | a | This Mac is reachable on your tailnet. | This computer is reachable on your tailnet. |
| `src/desktop/ui/devices.rs:2129` | a | This Mac is off your tailnet. Approvals go through Apassy relay. | This computer is off your tailnet. Approvals go through Apassy relay. |
| `src/desktop/ui/devices.rs:2668` | a | The node of this Mac uses port {port} now. | The node of this computer uses port {port} now. |
| `src/desktop/ui/devices.rs:2682` | a | The address of this Mac is copied. | The address of this computer is copied. |
| `src/desktop/ui/folders.rs:190` | a | The folder is gone. Another Mac may have deleted it. | The folder is gone. Another computer may have deleted it. |
| `src/desktop/ui/import.rs:157` | b | …y may not delete the file. Delete it in Finder. | …y may not delete the file. Delete it in your file manager. |
| `src/desktop/ui/import.rs:163` | b | …could not delete the file. Delete it in Finder. | …could not delete the file. Delete it in your file manager. |
| `src/desktop/ui/import.rs:316` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/import.rs:380` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/items.rs:258` | shortcut | New credential ⌘N | New credential Ctrl+N |
| `src/desktop/ui/items.rs:313` | shortcut | Move selected credentials ⇧⌘M | Move selected credentials Ctrl+Shift+M |
| `src/desktop/ui/items.rs:330` | shortcut | ⌘Z | Ctrl+Z |
| `src/desktop/ui/items.rs:666` | shortcut | …bsite, host, project, service, or notes ⌘F | …bsite, host, project, service, or notes Ctrl+F |
| `src/desktop/ui/items.rs:1340` | a | …s the same credential, not a copy. This Mac has no shared vault yet. | …s the same credential, not a copy. This computer has no shared vault yet. |
| `src/desktop/ui/items.rs:1551` | shortcut | Show or hide secret values ⌘⇧H | Show or hide secret values Ctrl+Shift+H |
| `src/desktop/ui/items.rs:3418` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/items.rs:3610` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/items.rs:3769` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/items.rs:4493` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/items.rs:4843` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/items.rs:4961` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/kit.rs:2661` | a | This Mac | This computer |
| `src/desktop/ui/new_credential.rs:306` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/new_credential.rs:371` | shortcut | ⌘V | Ctrl+V |
| `src/desktop/ui/overview.rs:334` | a | Across Macs the median is each Mac's median, weighted by its answers. | Across computers the median is each computer's median, weighted by its answers. |
| `src/desktop/ui/overview.rs:341` | a | Other Macs count from their reports; allowed runs are approximate. | Other computers count from their reports; allowed runs are approximate. |
| `src/desktop/ui/overview.rs:348` | a | A Mac on an older Apassy reports no numbers: it counts as —. | A computer on an older Apassy reports no numbers: it counts as —. |
| `src/desktop/ui/overview.rs:541` | a | This Mac | This computer |
| `src/desktop/ui/scope_bar.rs:41` | a | Other Macs appear when they use this vault. | Other computers appear when they use this vault. |
| `src/desktop/ui/settings.rs:332` | a | …s time is up. The window ends when your Mac locks or sleeps. | …s time is up. The window ends when your computer locks or sleeps. |
| `src/desktop/ui/settings.rs:527` | shortcut | ⌘1 to ⌘5 | Ctrl+1 to Ctrl+5 |
| `src/desktop/ui/settings.rs:530` | shortcut | ⌘, | Ctrl+, |
| `src/desktop/ui/settings.rs:531` | shortcut | ⌘[ | Alt+Left |
| `src/desktop/ui/settings.rs:532` | shortcut | ⌘N | Ctrl+N |
| `src/desktop/ui/settings.rs:533` | shortcut | ⌘F | Ctrl+F |
| `src/desktop/ui/settings.rs:534` | shortcut | ⌘L | Ctrl+L |
| `src/desktop/ui/settings.rs:535` | shortcut | ⌃⌘S | F9 |
| `src/desktop/ui/settings.rs:537` | shortcut | Return, ⌘S | Return, Ctrl+S |
| `src/desktop/ui/settings.rs:541` | shortcut | ⌘⇧H | Ctrl+Shift+H |
| `src/desktop/ui/settings.rs:545` | shortcut | ⌘W | Ctrl+W |
| `src/desktop/ui/settings.rs:547` | shortcut | ⌘Q | Ctrl+Q |
| `src/desktop/ui/settings.rs:549` | shortcut | Tab, ⇧Tab | Tab, Shift+Tab |
| `src/desktop/ui/settings.rs:1373` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/settings.rs:1489` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/settings.rs:1527` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/ui/sidebar.rs:87` | shortcut | Hide sidebar ⌃⌘S | Hide sidebar F9 |
| `src/desktop/ui/sidebar.rs:89` | shortcut | Show sidebar ⌃⌘S | Show sidebar F9 |
| `src/desktop/ui/sidebar.rs:257` | shortcut | All credentials, {count} ⌘1 | All credentials, {count} Ctrl+1 |
| `src/desktop/ui/sidebar.rs:327` | shortcut | All credentials ⌘1 | All credentials Ctrl+1 |
| `src/desktop/ui/sidebar.rs:544` | shortcut | ⌘2 | Ctrl+2 |
| `src/desktop/ui/sidebar.rs:552` | shortcut | ⌘3 | Ctrl+3 |
| `src/desktop/ui/sidebar.rs:560` | shortcut | ⌘4 | Ctrl+4 |
| `src/desktop/ui/sidebar.rs:568` | shortcut | ⌘5 | Ctrl+5 |
| `src/desktop/ui/sidebar.rs:616` | shortcut | Settings ⌘, | Settings Ctrl+, |
| `src/desktop/ui/sidebar.rs:635` | shortcut | Lock the vault ⌘L | Lock the vault Ctrl+L |
| `src/desktop/ui/start.rs:141` | a | …ach vault is one encrypted file on this Mac. Agents use the secrets through Apassy and never see the… | …ach vault is one encrypted file on this computer. Agents use the secrets through Apassy and never se… |
| `src/desktop/ui/start.rs:156` | a | Use a vault from another Mac | Use a vault from another computer |
| `src/desktop/ui/sync.rs:146` | a | This Mac matches the local file in the sync folder. Last folder sync {}. Receipt on another Mac is n… | This computer matches the local file in the sync folder. Last folder sync {}. Receipt on another com… |
| `src/desktop/ui/sync.rs:155` | a | This Mac matches the local file in the sync folder. Receipt on another Mac is not confirmed. | This computer matches the local file in the sync folder. Receipt on another computer is not confirme… |
| `src/desktop/ui/sync.rs:163` | a | Saved on this Mac. A change waits for the sync folder. | Saved on this computer. A change waits for the sync folder. |
| `src/desktop/ui/sync.rs:171` | a | The passphrase changed on another Mac. Type the new passphrase. | The passphrase changed on another computer. Type the new passphrase. |
| `src/desktop/ui/sync.rs:273` | a | {} changed on this Mac and on {} at the same time. Apassy kept the later change, and the other versi… | {} changed on this computer and on {} at the same time. Apassy kept the later change, and the other … |
| `src/desktop/ui/sync.rs:300` | a | On this Mac | On this computer |
| `src/desktop/ui/sync.rs:306` | a | On this Mac | On this computer |
| `src/desktop/ui/sync.rs:832` | a | … variable of “{vault}” is taken on this Mac | … variable of “{vault}” is taken on this computer |
| `src/desktop/ui/sync.rs:839` | a | Another credential on this Mac has the variable {}. The credential from the other device came withou… | Another credential on this computer has the variable {}. The credential from the other device came w… |
| `src/desktop/ui/sync.rs:858` | a | …did not merge it, and the vault on this Mac did not change. Apassy does not download that copy again… | …did not merge it, and the vault on this computer did not change. Apassy does not download that copy … |
| `src/desktop/ui/sync.rs:866` | a | …ssy did not merge it. The vault on this Mac did not change. If no other Mac can repair it, replace i… | …ssy did not merge it. The vault on this computer did not change. If no other computer can repair it,… |
| `src/desktop/ui/sync.rs:983` | a | The passphrase changed on another Mac: type the new one to sync. | The passphrase changed on another computer: type the new one to sync. |
| `src/desktop/ui/sync.rs:1016` | a | …r sync: {} credential{} changed on this Mac. | …r sync: {} credential{} changed on this computer. |
| `src/desktop/ui/sync.rs:1029` | a | Saved to the sync folder on this Mac. | Saved to the sync folder on this computer. |
| `src/desktop/ui/sync.rs:1032` | a | Saved to the sync folder on this Mac. | Saved to the sync folder on this computer. |
| `src/desktop/ui/sync.rs:1101` | a | …syncs with {label} as {}. On your other Mac, select “Use a vault from another Mac”. | …syncs with {label} as {}. On your other computer, select “Use a vault from another computer”. |
| `src/desktop/ui/sync.rs:1150` | a | …opy on the Apassy relay stays, and this Mac stays in its relay team: remove it in “Devices…” on anot… | …opy on the Apassy relay stays, and this computer stays in its relay team: remove it in “Devices…” on… |
| `src/desktop/ui/sync.rs:1340` | a | “{name}” is on this Mac. Folder sync is on for {}. | “{name}” is on this computer. Folder sync is on for {}. |
| `src/desktop/ui/sync.rs:1421` | a | Sync: the passphrase changed on another Mac. Unlock the vault, then type the new passphrase. | Sync: the passphrase changed on another computer. Unlock the vault, then type the new passphrase. |
| `src/desktop/ui/sync.rs:1427` | a | …not available. The changes stay on this Mac and sync when it is back. | …not available. The changes stay on this computer and sync when it is back. |
| `src/desktop/ui/sync.rs:1433` | a | …nced file yet. The changes stay on this Mac. | …nced file yet. The changes stay on this computer. |
| `src/desktop/ui/sync.rs:1440` | a | Sync: {other}. The changes stay on this Mac. | Sync: {other}. The changes stay on this computer. |
| `src/desktop/ui/sync.rs:1453` | a | … this name is in iCloud but not on this Mac yet. Apassy asked iCloud for it. Try again when the down… | … this name is in iCloud but not on this computer yet. Apassy asked iCloud for it. Try again when the… |
| `src/desktop/ui/sync.rs:1463` | a | …ile is damaged. Nothing changed on this Mac. | …ile is damaged. Nothing changed on this computer. |
| `src/desktop/ui/sync.rs:1464` | a | The file is not on this Mac yet. Apassy asked iCloud for it. Try again when the download ends. | The file is not on this computer yet. Apassy asked iCloud for it. Try again when the download ends. |
| `src/desktop/ui/sync.rs:1494` | a | Replace with this Mac's vault… | Replace with this computer's vault… |
| `src/desktop/ui/sync.rs:1549` | a | …e passphrase of “{}” changed on another Mac | …e passphrase of “{}” changed on another computer |
| `src/desktop/ui/sync.rs:1555` | a | …on syncing. Apassy then uses it on this Mac too. | …on syncing. Apassy then uses it on this computer too. |
| `src/desktop/ui/sync.rs:1674` | a | …s. Agents and your answers stay on each Mac. | …s. Agents and your answers stay on each computer. |
| `src/desktop/ui/sync.rs:1928` | a | …at a sync service keeps in step on each Mac: Dropbox, Google Drive, OneDrive, Syncthing, or a networ… | …at a sync service keeps in step on each computer: Dropbox, Google Drive, OneDrive, Syncthing, or a n… |
| `src/desktop/ui/sync.rs:1988` | a | … merges the copy into the vault on this Mac, and uploads the result under the passphrase of this Mac… | … merges the copy into the vault on this computer, and uploads the result under the passphrase of thi… |
| `src/desktop/ui/sync.rs:2000` | a | …e passphrase of “{}” changed on another Mac | …e passphrase of “{}” changed on another computer |
| `src/desktop/ui/sync.rs:2009` | a | …opy, then uses it for the vault on this Mac too, and syncs. Touch ID unlock on this Mac then needs t… | …opy, then uses it for the vault on this computer too, and syncs. Touch ID unlock on this computer th… |
| `src/desktop/ui/sync.rs:2099` | a | …s merging this vault. The vault on this Mac stays. The synced copy {file} stays in {folder}, and you… | …s merging this vault. The vault on this computer stays. The synced copy {file} stays in {folder}, an… |
| `src/desktop/ui/sync.rs:2145` | a | … “{}” on the relay fails a check, so no Mac can merge it. Apassy can upload the vault of this Mac as… | … “{}” on the relay fails a check, so no computer can merge it. Apassy can upload the vault of this c… |
| `src/desktop/ui/sync.rs:2167` | a | …ynced copy of “{}” fails a check, so no Mac can merge it. Apassy can write the vault of this Mac in … | …ynced copy of “{}” fails a check, so no computer can merge it. Apassy can write the vault of this co… |
| `src/desktop/ui/sync.rs:2202` | a | The synced copy has the vault of this Mac now. | The synced copy has the vault of this computer now. |
| `src/desktop/ui/sync.rs:2244` | a | Use a vault from another Mac… | Use a vault from another computer… |
| `src/desktop/ui/sync.rs:2263` | a | …rypted copy in a folder that your other Macs, or your team, keep in step. | …rypted copy in a folder that your other computers, or your team, keep in step. |
| `src/desktop/ui/sync.rs:2447` | a | Use a vault from another Mac | Use a vault from another computer |
| `src/desktop/ui/sync.rs:2473` | a | …e same vault passphrase as on the other Mac. Apassy keeps a local copy on this Mac. | …e same vault passphrase as on the other computer. Apassy keeps a local copy on this computer. |
| `src/desktop/ui/sync.rs:2543` | b | …and name stay in this form. Check for a macOS permission request or a file download. Then try again. | …and name stay in this form. Check for a stopped sync service or a file download. Then try again. |
| `src/desktop/ui/sync.rs:2687` | a | Name on this Mac | Name on this computer |
| `src/desktop/ui/sync.rs:2746` | a | {} You can unlock the vault on this Mac now. | {} You can unlock the vault on this computer now. |
| `src/desktop/ui/sync/questions.rs:85` | a | This Mac was removed from the questions of this vault. To answer and ask through the relay again, tu… | This computer was removed from the questions of this vault. To answer and ask through the relay agai… |
| `src/desktop/ui/sync/questions.rs:103` | a | …Keep them free over Tailscale with this Mac as the node, or use Apassy Connect (paid). | …Keep them free over Tailscale with this computer as the node, or use Apassy Connect (paid). |
| `src/desktop/ui/sync/questions.rs:275` | a | This Mac | This computer |
| `src/desktop/ui/sync/questions.rs:276` | a | Mac · answers after Touch ID | Computer · answers after the passphrase or system authentication |
| `src/desktop/ui/sync/questions.rs:326` | a | this Mac | this computer |
| `src/desktop/ui/sync/questions.rs:331` | a | …lso removes it from the relay when this Mac can, so it gets no more notifications. To answer again i… | …lso removes it from the relay when this computer can, so it gets no more notifications. To answer ag… |
| `src/desktop/ui/sync/questions.rs:433` | a | …provals of this vault then move to this Mac. | …provals of this vault then move to this computer. |
| `src/desktop/ui/sync/questions.rs:649` | a | Approvals now go through this Mac on your tailnet. Scan the pairing code with Apassy on your iPhone. | Approvals now go through this computer on your tailnet. Scan the pairing code with Apassy on your iP… |
| `src/desktop/ui/sync/questions.rs:689` | a | …your iPhone. The approvals move to this Mac when you confirm it here. | …your iPhone. The approvals move to this computer when you confirm it here. |
| `src/desktop/ui/sync/questions.rs:728` | a | Approvals now go through this Mac on your tailnet. The old devices left the Apassy relay. | Approvals now go through this computer on your tailnet. The old devices left the Apassy relay. |
| `src/desktop/ui/sync/questions.rs:734` | a | Approvals now go through this Mac on your tailnet. | Approvals now go through this computer on your tailnet. |
| `src/desktop/ui/sync/questions.rs:780` | a | Questions stay on this Mac and the paired iPhones on this network. | Questions stay on this computer and the paired iPhones on this network. |
| `src/desktop/ui/sync/questions.rs:914` | a | Paste the link from a Mac that has the questions on. | Paste the link from a computer that has the questions on. |
| `src/desktop/ui/sync/questions.rs:924` | a | … is of another team. Make the link on a Mac that has the questions of this vault on. | … is of another team. Make the link on a computer that has the questions of this vault on. |
| `src/desktop/ui/sync/questions.rs:1058` | a | The other Mac refused this Mac, or the link expired. Nothing changed. | The other computer refused this computer, or the link expired. Nothing changed. |
| `src/desktop/ui/sync/questions.rs:1131` | a | The other Mac confirmed this Mac, but the vault did not keep the key: {} | The other computer confirmed this computer, but the vault did not keep the key: {} |
| `src/desktop/ui/sync/questions.rs:1482` | a | To stop this Mac, turn “Send questions through the relay” off. | To stop this computer, turn “Send questions through the relay” off. |
| `src/desktop/ui/sync/questions.rs:1597` | a | …pare the safety words. Connecting needs Touch ID or the passphrase. | …pare the safety words. Connecting needs the passphrase or system authentication. |
| `src/desktop/ui/sync/questions.rs:1611` | a | Name of this Mac | Name of this computer |
| `src/desktop/ui/sync/questions.rs:1699` | a | …ns through a team on the relay, so this Mac joins that team. On a Mac that has “Send questions throu… | …ns through a team on the relay, so this computer joins that team. On a computer that has “Send quest… |
| `src/desktop/ui/sync/questions.rs:1721` | a | Waiting for the other Mac… Both Macs show: | Waiting for the other computer… Both computers show: |
| `src/desktop/ui/sync/questions.rs:1729` | a | Confirm on the other Mac only if it shows the same words. | Confirm on the other computer only if it shows the same words. |
| `src/desktop/ui/sync/relay.rs:83` | a | The relay did not hear that this Mac cancelled. The link ends on its own within 10 minutes. If the o… | The relay did not hear that this computer cancelled. The link ends on its own within 10 minutes. If … |
| `src/desktop/ui/sync/relay.rs:93` | a | Apassy could not remove this Mac from the relay. The other Mac shows it in “Devices…”: remove it the… | Apassy could not remove this computer from the relay. The other computer shows it in “Devices…”: rem… |
| `src/desktop/ui/sync/relay.rs:173` | a | Apassy asks the relay for the Macs that wait… | Apassy asks the relay for the computers that wait… |
| `src/desktop/ui/sync/relay.rs:178` | a | Apassy adds the other Mac… | Apassy adds the other computer… |
| `src/desktop/ui/sync/relay.rs:179` | a | Apassy refuses the other Mac… | Apassy refuses the other computer… |
| `src/desktop/ui/sync/relay.rs:180` | a | Apassy asks the relay for the Macs… | Apassy asks the relay for the computers… |
| `src/desktop/ui/sync/relay.rs:181` | a | Apassy removes the Mac… | Apassy removes the computer… |
| `src/desktop/ui/sync/relay.rs:182` | a | Apassy asks the relay for the Macs of the team… | Apassy asks the relay for the computers of the team… |
| `src/desktop/ui/sync/relay.rs:188` | a | Apassy asks the relay which Macs have the vault… | Apassy asks the relay which computers have the vault… |
| `src/desktop/ui/sync/relay.rs:193` | a | Apassy removes this Mac from the relay team… | Apassy removes this computer from the relay team… |
| `src/desktop/ui/sync/relay.rs:198` | a | Apassy uploads the vault of this Mac to the relay… | Apassy uploads the vault of this computer to the relay… |
| `src/desktop/ui/sync/relay.rs:649` | a | another Mac | another computer |
| `src/desktop/ui/sync/relay.rs:659` | a | Saved on this Mac. A change waits for the relay. | Saved on this computer. A change waits for the relay. |
| `src/desktop/ui/sync/relay.rs:661` | a | The passphrase changed on another Mac. Type the new passphrase. | The passphrase changed on another computer. Type the new passphrase. |
| `src/desktop/ui/sync/relay.rs:671` | a | …for this hour. The changes stay on this Mac and sync later. | …for this hour. The changes stay on this computer and sync later. |
| `src/desktop/ui/sync/relay.rs:693` | a | …ore is part of Apassy Connect; your own Mac or Linux node can be the sync home (free). | …ore is part of Apassy Connect; your own computer or Linux node can be the sync home (free). |
| `src/desktop/ui/sync/relay.rs:715` | a | …ode needed. Apassy makes a key for this Mac, keeps it in the vault, and uploads the encrypted copy. … | …ode needed. Apassy makes a key for this computer, keeps it in the vault, and uploads the encrypted c… |
| `src/desktop/ui/sync/relay.rs:738` | a | This is a link from another Mac. Choose “Join from another Mac” and paste it there. | This is a link from another computer. Choose “Join from another computer” and paste it there. |
| `src/desktop/ui/sync/relay.rs:751` | a | … matches the link, makes a key for this Mac, and keeps it in the vault. | … matches the link, makes a key for this computer, and keeps it in the vault. |
| `src/desktop/ui/sync/relay.rs:775` | a | The other Mac refused, or the link expired. Make a new link on the other Mac. | The other computer refused, or the link expired. Make a new link on the other computer. |
| `src/desktop/ui/sync/relay.rs:783` | a | …pen this vault. Nothing changed on this Mac. Type it again. | …pen this vault. Nothing changed on this computer. Type it again. |
| `src/desktop/ui/sync/relay.rs:808` | a | …it runs (“apassy status”) and that this Mac is on the same tailnet, then try again. {stays} | …it runs (“apassy status”) and that this computer is on the same tailnet, then try again. {stays} |
| `src/desktop/ui/sync/relay.rs:1221` | a | …c: {count} credential{} changed on this Mac. | …c: {count} credential{} changed on this computer. |
| `src/desktop/ui/sync/relay.rs:1255` | a | The relay has the vault of this Mac now. Your other Macs merge it at their next sync. | The relay has the vault of this computer now. Your other computers merge it at their next sync. |
| `src/desktop/ui/sync/relay.rs:1286` | a | …e}”, which keeps the passphrase of this Mac. | …e}”, which keeps the passphrase of this computer. |
| `src/desktop/ui/sync/relay.rs:1449` | a | …se of the relay copy now, as your other Macs, and merged with the copy. It syncs through the Apassy … | …se of the relay copy now, as your other computers, and merged with the copy. It syncs through the Ap… |
| `src/desktop/ui/sync/relay.rs:1462` | a | …s through your own node. To add another Mac or an iPhone, select “Add a device…”. | …s through your own node. To add another computer or an iPhone, select “Add a device…”. |
| `src/desktop/ui/sync/relay.rs:1471` | a | …hrough the Apassy relay. To add another Mac or an iPhone, select “Add a device…”. | …hrough the Apassy relay. To add another computer or an iPhone, select “Add a device…”. |
| `src/desktop/ui/sync/relay.rs:1856` | a | …time. The relay team stays; remove this Mac in “Devices…” on another Mac, or ask the operator of the… | …time. The relay team stays; remove this computer in “Devices…” on another computer, or ask the opera… |
| `src/desktop/ui/sync/relay.rs:2141` | a | …the relay is deleted. The vault on this Mac stays. | …the relay is deleted. The vault on this computer stays. |
| `src/desktop/ui/sync/relay.rs:2151` | a | {off} The copy on the relay stays. This Mac was no longer in the relay team. If the relay was paused… | {off} The copy on the relay stays. This computer was no longer in the relay team. If the relay was p… |
| `src/desktop/ui/sync/relay.rs:2163` | a | {off} The copy on the relay stays. This Mac was the last Mac of the relay team, so only the operator… | {off} The copy on the relay stays. This computer was the last computer of the relay team, so only th… |
| `src/desktop/ui/sync/relay.rs:2173` | a | {off} The copy on the relay stays. This Mac is still in the relay team ({reason}): remove it in “Dev… | {off} The copy on the relay stays. This computer is still in the relay team ({reason}): remove it in… |
| `src/desktop/ui/sync/relay.rs:2697` | a | The relay's record of this Mac does not match. Nothing was added. | The relay's record of this computer does not match. Nothing was added. |
| `src/desktop/ui/sync/relay.rs:2862` | a | Paste the link from the other Mac. | Paste the link from the other computer. |
| `src/desktop/ui/sync/relay.rs:3314` | a | “{name}” is on this Mac. Relay sync is on. | “{name}” is on this computer. Relay sync is on. |
| `src/desktop/ui/sync/relay.rs:3447` | a | Waiting for the other Mac… Both Macs show: | Waiting for the other computer… Both computers show: |
| `src/desktop/ui/sync/relay.rs:3455` | a | Confirm on the other Mac if it shows the same words. | Confirm on the other computer if it shows the same words. |
| `src/desktop/ui/sync/relay.rs:3464` | a | The other Mac confirmed this Mac. Apassy downloads “{team}” from the relay… | The other computer confirmed this computer. Apassy downloads “{team}” from the relay… |
| `src/desktop/ui/sync/relay.rs:3478` | a | “{team}” is on this Mac, still encrypted. | “{team}” is on this computer, still encrypted. |
| `src/desktop/ui/sync/relay.rs:3495` | a | The other Mac confirmed this Mac. The relay copy of “{team}” uses another passphrase than this vault… | The other computer confirmed this computer. The relay copy of “{team}” uses another passphrase than … |
| `src/desktop/ui/sync/relay.rs:3534` | a | Name of this Mac | Name of this computer |
| `src/desktop/ui/sync/relay.rs:3561` | a | …is vault and passes the changes of each Mac to the others within seconds. It never gets the passphra… | …is vault and passes the changes of each computer to the others within seconds. It never gets the pas… |
| `src/desktop/ui/sync/relay.rs:3578` | a | Join from another Mac | Join from another computer |
| `src/desktop/ui/sync/relay.rs:3593` | a | …y copy. “{}” takes it, as on your other Macs, and Apassy merges the copy into it. From then on you u… | …y copy. “{}” takes it, as on your other computers, and Apassy merges the copy into it. From then on … |
| `src/desktop/ui/sync/relay.rs:3622` | a | …works once. Apassy makes a key for this Mac and keeps it in the vault. | …works once. Apassy makes a key for this computer and keeps it in the vault. |
| `src/desktop/ui/sync/relay.rs:3654` | a | Name of this Mac | Name of this computer |
| `src/desktop/ui/sync/relay.rs:3675` | a | Name of this Mac | Name of this computer |
| `src/desktop/ui/sync/relay.rs:3689` | a | …lt that is on the relay already. On the Mac that syncs it, select “Add a device…” and copy the link.… | …lt that is on the relay already. On the computer that syncs it, select “Add a device…” and copy the … |
| `src/desktop/ui/sync/relay.rs:3861` | a | … vault”, and scan this code. On another Mac, open Apassy, select “Use a vault from another Mac”, the… | … vault”, and scan this code. On another computer, open Apassy, select “Use a vault from another comp… |
| `src/desktop/ui/sync/relay.rs:4388` | a | Macs that sync “{}” | Computers that sync “{}” |
| `src/desktop/ui/sync/relay.rs:4391` | a | Each Mac has its own key on the relay. A removed Mac keeps its copy of the vault and the passphrase:… | Each computer has its own key on the relay. A removed computer keeps its copy of the vault and the p… |
| `src/desktop/ui/sync/relay.rs:4417` | a | This Mac | This computer |
| `src/desktop/ui/sync/relay.rs:4543` | a | The key of this Mac for the relay is in the vault. Open and unlock the vault to turn relay sync off:… | The key of this computer for the relay is in the vault. Open and unlock the vault to turn relay sync… |
| `src/desktop/ui/sync/relay.rs:4546` | a | …lay leaves the vault. The vault on this Mac stays. This Mac is the last Mac of the relay team: the c… | …lay leaves the vault. The vault on this computer stays. This computer is the last computer of the re… |
| `src/desktop/ui/sync/relay.rs:4549` | a | …assy stops merging this vault, and this Mac leaves the relay team. The vault on this Mac stays. The … | …assy stops merging this vault, and this computer leaves the relay team. The vault on this computer s… |
| `src/desktop/ui/sync/relay.rs:4570` | a | …he copy on the relay. The vault on this Mac stays. | …he copy on the relay. The vault on this computer stays. |
| `src/desktop/ui/sync/relay.rs:4629` | a | On the Mac that has the vault, open Settings > Vault > Sync, select “Add a device…”, and copy the li… | On the computer that has the vault, open Settings > Vault > Sync, select “Add a device…”, and copy t… |
| `src/desktop/ui/sync/relay.rs:4676` | a | …he passphrase of the vault on the other Mac. Apassy keeps a local copy on this Mac. | …he passphrase of the vault on the other computer. Apassy keeps a local copy on this computer. |
| `src/desktop/ui/sync/relay.rs:4700` | a | Name on this Mac | Name on this computer |
| `src/desktop/ui/sync/relay.rs:4751` | a | This Mac refuses the copy of “{}” on the relay: it is older than the copy that this Mac saw last, or… | This computer refuses the copy of “{}” on the relay: it is older than the copy that this computer sa… |
| `src/desktop/ui/vaults.rs:526` | shortcut | Lock “{name}” ⌘L | Lock “{name}” Ctrl+L |
| `src/desktop/ui/vaults.rs:695` | a | On this Mac | On this computer |
| `src/desktop/ui/vaults.rs:930` | shortcut | ⌘S | Ctrl+S |
| `src/desktop/unlock.rs:45` | a | The fingerprints on this Mac changed after you turned on Touch ID unlock. Apassy removed the old unl… | The fingerprints on this computer changed after you turned on Touch ID unlock. Apassy removed the ol… |
| `src/node/funnel.rs:210` | a | Port {NEVER_PORT} of this Mac is public through Tailscale Funnel. Apassy adds no route while it is: … | Port {NEVER_PORT} of this computer is public through Tailscale Funnel. Apassy adds no route while it… |
| `src/node/mod.rs:1049` | a | The node certificate of this Mac is new, so its pin changed. Pair your iPhone again. | The node certificate of this computer is new, so its pin changed. Pair your iPhone again. |
| `src/node/mod.rs:1089` | a | The address of this Mac on the tailnet changed from {last} to {}. Pair your iPhone again. | The address of this computer on the tailnet changed from {last} to {}. Pair your iPhone again. |
| `src/node/mod.rs:1295` | a | The name of this Mac is in public certificate logs while the route is on. The Mac must stay awake an… | The name of this computer is in public certificate logs while the route is on. The computer must sta… |
| `src/node/mod.rs:1524` | a | The node of this Mac is not on the tailnet. Turn on “Reachable on your tailnet”. | The node of this computer is not on the tailnet. Turn on “Reachable on your tailnet”. |
| `src/node/mod.rs:1534` | a | The node of this Mac is not on the tailnet. Turn on “Reachable on your tailnet”. | The node of this computer is not on the tailnet. Turn on “Reachable on your tailnet”. |
| `src/node/mod.rs:1635` | a | …hrough another relay. Move them to this Mac first. | …hrough another relay. Move them to this computer first. |
| `src/node/mod.rs:1645` | a | This vault has its approvals on another Mac. Join them from that Mac with “Add an iPhone or a Mac…”. | This vault has its approvals on another computer. Join them from that computer with “Add an iPhone o… |
| `src/node/mod.rs:1700` | a | This vault has no approvals on this Mac yet. Turn them on first. | This vault has no approvals on this computer yet. Turn them on first. |
| `src/node/mod.rs:1740` | a | This vault has no approvals on this Mac. | This vault has no approvals on this computer. |
| `src/node/mod.rs:1750` | a | This Mac holds the approvals of the vault. Turn them off instead. | This computer holds the approvals of the vault. Turn them off instead. |
| `src/node/mod.rs:1975` | a | …ess is on: remote agents can reach this Mac through Tailscale Funnel while it is awake and the vault… | …ess is on: remote agents can reach this computer through Tailscale Funnel while it is awake and the … |
| `src/node/mod.rs:1977` | a | …ss is off: no remote agent reaches this Mac. | …ss is off: no remote agent reaches this computer. |
| `src/node/mod.rs:2059` | a | Allowed with Touch ID on this Mac. | Allowed with Touch ID on this computer. |
| `src/node/tailnet.rs:131` | a | Tailscale is not installed on this Mac. Install it from tailscale.com, then sign in. | Tailscale is not installed on this computer. Install it from tailscale.com, then sign in. |
| `src/node/tailnet.rs:167` | a | Tailscale gives this Mac no IPv4 address. | Tailscale gives this computer no IPv4 address. |
| `src/node/tailnet.rs:275` | a | …t {port} on the tailnet address of this Mac is taken: {error}. Choose another port before the first … | …t {port} on the tailnet address of this computer is taken: {error}. Choose another port before the f… |
| `src/node/tailnet.rs:424` | a | …in cannot be routed to the node on this Mac. | …in cannot be routed to the node on this computer. |
| `src/owner/client.rs:45` | b | …t path. If Apassy is closed, open Apassy.app, then try again. | …t path. If Apassy is closed, open Apassy, then try again. |
| `src/questions/access_worker.rs:84` | a | Review on this Mac. Relay capacity is reserved for execution questions and iPhone connection. | Review on this computer. Relay capacity is reserved for execution questions and iPhone connection. |
| `src/questions/access_worker.rs:113` | a | Review this access request on this Mac. It could not be sent to your other devices. | Review this access request on this computer. It could not be sent to your other devices. |
| `src/questions/access_worker.rs:134` | a | Review on this Mac. A prior relay publication still reserves the access slot until settlement or exp… | Review on this computer. A prior relay publication still reserves the access slot until settlement o… |
| `src/questions/access_worker.rs:172` | a | Review this access request on this Mac. Remote publication failed: {e:?} | Review this access request on this computer. Remote publication failed: {e:?} |
| `src/questions/answer.rs:175` | a | Confirm with Touch ID to send this answer. | Confirm with the passphrase or system authentication to send this answer. |
| `src/questions/answer.rs:182` | a | This question no longer waits on this Mac. | This question no longer waits on this computer. |
| `src/questions/connect.rs:52` | a | …on your iPhone. Answer this one on this Mac. | …on your iPhone. Answer this one on this computer. |
| `src/questions/connect.rs:57` | a | …o your other devices. Answer it on this Mac. | …o your other devices. Answer it on this computer. |
| `src/questions/connect.rs:62` | a | …yet. Answer the connect request on this Mac. | …yet. Answer the connect request on this computer. |
| `src/questions/envelope.rs:584` | a | A program on this Mac can start this request. | A program on this computer can start this request. |
| `src/questions/feed.rs:626` | a | …move this from it, or remove it on this Mac | …move this from it, or remove it on this computer |
| `src/questions/feed.rs:1151` | a | it is for another Mac | it is for another computer |
| `src/questions/feed.rs:1154` | a | … agent or the credential is not on this Mac | … agent or the credential is not on this computer |
| `src/questions/feed.rs:1159` | a | the list on this Mac changed | the list on this computer changed |
| `src/questions/feed.rs:1160` | a | … names on the iPhone did not match this Mac | … names on the iPhone did not match this computer |
| `src/questions/worker.rs:96` | a | Requests from other Macs could not be refreshed. Apassy will try again. | Requests from other computers could not be refreshed. Apassy will try again. |
| `src/questions/worker.rs:101` | a | …is vault to read a request from another Mac. | …is vault to read a request from another computer. |
| `src/questions/worker.rs:106` | a | A request from another Mac could not be read. Sync this vault or update Apassy. | A request from another computer could not be read. Sync this vault or update Apassy. |
| `src/questions/worker.rs:114` | a | This Mac is not a device of the questions of this vault. Turn “Send questions through the relay” off… | This computer is not a device of the questions of this vault. Turn “Send questions through the relay… |
| `src/questions/worker.rs:126` | a | Sent. The Mac checks it; if the run does not continue within a minute, the answer was refused. | Sent. The computer checks it; if the run does not continue within a minute, the answer was refused. |
| `src/questions/worker.rs:133` | a | …come with shared vaults; answer on this Mac. | …come with shared vaults; answer on this computer. |
| `src/questions/worker.rs:151` | a | another Mac | another computer |
| `src/questions/worker.rs:1258` | a | …r your other devices. Answer it on this Mac. | …r your other devices. Answer it on this computer. |
| `src/questions/worker.rs:1352` | a | …does not answer. Questions wait on this Mac. | …does not answer. Questions wait on this computer. |
| `src/questions/worker.rs:1366` | a | …lay has too many open questions of this Mac or this vault. Answer it on this Mac. | …lay has too many open questions of this computer or this vault. Answer it on this computer. |
| `src/questions/worker.rs:1375` | a | …r your other devices. Answer it on this Mac. | …r your other devices. Answer it on this computer. |
| `src/questions/worker.rs:1382` | a | The relay refused this Mac. Answer the question on this Mac. | The relay refused this computer. Answer the question on this computer. |
| `src/questions/worker.rs:1390` | a | …t take this question. Answer it on this Mac. | …t take this question. Answer it on this computer. |
| `src/relay/connect.rs:52` | a | …ready has a relay connection on another Mac. On that Mac, turn on relay sync for this vault, then se… | …ready has a relay connection on another computer. On that computer, turn on relay sync for this vaul… |
| `src/sync/mod.rs:370` | a | …e used it. Make a new link on the other Mac | …e used it. Make a new link on the other computer |
| `src/sync/mod.rs:373` | a | the other Mac has not confirmed this Mac yet | the other computer has not confirmed this computer yet |
| `src/sync/mod.rs:374` | a | the other Mac refused, or the link expired | the other computer refused, or the link expired |
| `src/sync/mod.rs:382` | a | the relay's record of this Mac does not match. Nothing was added | the relay's record of this computer does not match. Nothing was added |
| `src/sync/mod.rs:398` | a | the synced file is not on this Mac yet; wait for the download | the synced file is not on this computer yet; wait for the download |
| `src/sync/mod.rs:401` | a | …rase: the passphrase changed on another Mac | …rase: the passphrase changed on another computer |
| `src/sync/mod.rs:413` | a | another Mac pushed to the relay first | another computer pushed to the relay first |
| `src/sync/mod.rs:415` | a | the relay is busy with another Mac. Apassy tries again | the relay is busy with another computer. Apassy tries again |
| `src/sync/mod.rs:421` | a | removed from the relay. This Mac keeps its vault. Turn relay sync off, then join again with a link f… | removed from the relay. This computer keeps its vault. Turn relay sync off, then join again with a l… |
| `src/sync/mod.rs:424` | a | the relay has an older copy than this Mac saw. To go on, select “Use the relay copy…” in Settings > … | the relay has an older copy than this computer saw. To go on, select “Use the relay copy…” in Settin… |
| `src/sync/mod.rs:427` | a | …erved a copy that does not include this Mac's last change. To go on, select “Use the relay copy…” in… | …erved a copy that does not include this computer's last change. To go on, select “Use the relay copy… |
| `src/sync/mod.rs:438` | a | …lt yet. Turn on relay sync on the other Mac first | …lt yet. Turn on relay sync on the other computer first |
| `src/sync/mod.rs:441` | a | the relay's words differ from this Mac's. Cancel and make a new link | the relay's words differ from this computer's. Cancel and make a new link |
| `src/vault/bouncer_host.rs:96` | a | This Mac | This computer |
| `src/vault/bouncer_host.rs:241` | a | This Mac. | This computer. |
