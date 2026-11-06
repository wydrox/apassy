# Changelog

All notable changes to Apassy. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions follow [Semantic Versioning](https://semver.org/). The site shows this file at <https://apassy.wyderka.cc/changelog>.

## [Unreleased]

### Fixed

- **The same question came back after you answered it:** a run with two or more credentials without a label offered only **Allow**, which saves nothing, so it asked at each run. It now also offers **Allow as dev** and **Allow as prod**, on the Mac and on the iPhone. They label the first of those credentials, the card says which, and the others ask next time. **Allow once** stays and labels nothing.
- **Remember for this project on a production write:** the card offered it, Apassy saved it, and the next run asked anyway. Production with write or admin scope asks at each run, so the card no longer offers it.
- **A host that the shell builds:** `https://$P.api.github.com` looked like a known host because its text ends like one, although the request can go to another server. A command like this that sends a secret now asks you.
- **The bouncer decision log was empty:** the Mac app did not write `~/Library/Logs/Apassy/bouncer-decisions.log`, so `apassy decisions log` had nothing to show. It writes it now.

## [0.5.18] - 2026-11-04

### Fixed

- **iPhone crash when connecting to a Mac:** the iPhone app of 0.5.17 crashed each time it joined or synced a vault after the update. The build of the iPhone core stripped local symbols, and the linker then merged two different Rust functions; the app called one with the arguments of the other. The core now goes into the app unstripped. The same build flaw was in 0.5.16, where fewer paths reached it.
- **Add Apple Watch did nothing after scanning:** for a vault that syncs through the relay, the Mac's **Add an iPhone or a Mac…** showed a sync-only code without the handoff that a watch needs, so the scan had no effect. The Mac now shows the code with the handoff, and the iPhone says why a scanned code cannot be used. A handoff also keeps the node's certificate pin.

### Upgrade notes

- Coordinated release: macOS, iOS (TestFlight, with the watch app), browser extension, relay, Linux CLI and website move to 0.5.18 together. The extension, the relay and the Linux node have no functional change since 0.5.17. No schema changes.

## [0.5.17] - 2026-11-04

### Added

- **Your Mac as the node on your tailnet:** Settings › Devices on the Mac has **Reachable on Your Tailnet**. It is off by default, and turning it on asks for Touch ID. Your iPhone, Apple Watch and other Macs then reach this Mac directly over Tailscale at `https://<Tailscale address>:8444`. Nothing opens to the internet, and each device still signs in with its own key. A TLS front binds only the Tailscale addresses and serves the Mac's own certificate. Every device pins that certificate: no system trust and no fallback. The section shows the address, the port and the **Node Words**: six safety words to compare with the iPhone. They are not proof of the Mac, because the device checks the whole certificate. One line names each problem (no Tailscale, not connected, starting, locked, port in use, address changed). The route stops while the vault is locked. When Tailscale cannot give peer addresses to the Serve fallback, Devices says "Tailscale Serve without peer addresses: update Tailscale".
- **Approvals through your node:** while the Mac is reachable on the tailnet, "Get approvals on your iPhone" makes the approvals team on the Mac's node. **Add an iPhone or a Mac…** shows a pinned link and QR code "via your Mac", then the safety words with the kind and route of the device, then Added. The Devices list shows every device of every team with its kind, roles, route (via your Mac, via Apassy relay, Tailnet, Wi-Fi) and last contact. **Revoke…** asks for Touch ID and also removes the watch of an iPhone. A Linux node has **Details…**. The **Relay** group keeps **Send Questions Through the Relay**, **Show Agents on My Other Devices** and **Other Macs**.
- **Move Approvals to This Mac…:** while the approvals go through Apassy relay, this row moves them to the Mac's node in three steps: pair each iPhone (and its watch) with the node, move the questions there, and take the old devices off the hosted relay. **Approvals Moved** lists each device and its route. If the hosted relay keeps an old entry, **Later** leaves the row "Old entry still on Apassy relay".
- **iPhone and Apple Watch on a node:** the iPhone joins a node with its pinned link and shows "via your Mac" when it joins, in Settings › Devices and in Requests, with "Node words to compare: …". When the node does not answer, the iPhone shows one quiet line, "Turn on Tailscale on this iPhone to reach <Mac>.", never a card. The watch reaches the node's Tailscale address with the same pin.
- **Linux node:** on Linux, `apassy` runs the node without a window. It serves the questions, the feed, the access requests and relay sync of your devices, and hosts teams. It needs no vault and no unlock. `apassy up` checks Tailscale, installs and starts the systemd user service `apassy-node.service`, and prints a pairing link. `apassy serve` runs the node in the foreground (`apassy serve --stop` stops it). `apassy pair` prints a one-use link and QR code that work for 1 to 10 minutes. `apassy status` and `apassy doctor` (both with `--json`) show the state and the next step. `apassy uninstall` removes the service and keeps the node's files. With systemd 256 or later, the node key is an encrypted systemd credential; `apassy up --no-encrypt` keeps a plain file. `apassy doctor` warns when it finds coding-agent folders in the home of the node's user: run the node as its own user. `apassy team` is the team command line, and `apassy-team` stays for one release as an alias that prints a deprecation line ([guide](docs/operations/linux-node.md)).
- **Linux packages:** `apassy-<version>-linux-x86_64.tar.gz` and `apassy-<version>-linux-aarch64.tar.gz` (glibc 2.31 or later: Debian 11, Ubuntu 20.04 and later), and `apassy_<version>_amd64.deb` and `apassy_<version>_arm64.deb`. The `.deb` starts nothing; each user who runs a node runs `apassy up`. `install.sh` checks the SHA-256 of the tarball against `SHA256SUMS` and installs `apassy` and `apassy-team` into `~/.local/bin`.
- **Your own node as the sync home (Mac):** Settings › Vault › Sync has a third way for Apassy relay, **Your own node**. Paste the link of `apassy pair`. The Mac makes the team on the node through the pin and keeps the pin with the vault, and a Mac that joins later uses the same pin. A wrong pin stops before any request: "This node's certificate changed. Pair again."
- **Push gateway:** a node sends notifications through a push gateway, a Cloudflare Worker (`https://push.apassy.wyderka.cc` by default). The gateway seals each APNs token into a handle, and the node keeps only handles. The iPhone and the watch register handles for the teams on a node. Two notification extensions open the sealed summary of a question; the watch shows a run question as "Answer on your iPhone or Mac". The watch has **Notifications on this watch**. Limits: 60 pushes an hour for each handle, 600 pushes an hour for each node address, 30 new handles an hour for each address, and for each APNs token 10 new handles a day and 30 pushes an hour. The hosted gateway is live at `push.apassy.wyderka.cc`. Questions through Apassy relay push as before.
- **Bouncer brain on your own server:** Settings › Bouncer has **Runs on**: This Mac (the default), **My Server…**, and Apassy Connect, which is disabled ("Coming with Connect"). **Use My Server** takes an https address with a public certificate (for example from Tailscale Serve) and a token. Apassy can generate the token and shows the commands that start the server; the token never goes on a command line. **What Leaves This Mac** lists what is sent: the user request and the purpose, and the shell command, with item values masked and project and home paths shortened, and the bouncer heads trained on your decisions (numbers, no text). Secret values, the vault and the full paths of your project and home folder never leave. Touch ID then confirms the change, and its text names the host. The bouncer gate on the Mac still decides every run. When the server cannot be used, the brain runs on this Mac again. A trained head set goes to the chosen server before it answers in shadow mode; the Learning card offers **Upload the head sets** while it is not there. The self-host images (CPU for arm64 and x86_64, CUDA for x86_64) and the runbook are in `docs/operations/bouncer-hosting.md`.
- **WebSocket in the run proxy:** a WebSocket to a host of the run goes through the swap rules. The upgrade gets the real header, a real value in a frame of the service becomes its placeholder (also across fragments), and a placeholder in a frame of the program closes the WebSocket with 1008. Compressed frames and frames over 1 MiB are refused.
- **Linux sandbox for proxied runs:** on Linux, a proxied run runs in a bubblewrap sandbox with its own network namespace, and its only route is the run proxy. The sandbox hides the home folder, the Apassy data, the vault files, the keys, the keyrings, the browser profiles, `/run/user/<uid>`, and `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.config/gh`, `~/.docker`, `~/.kube` and `~/.netrc`. A run refuses a working folder in `/tmp`, `/var/tmp`, `/run`, `/dev/shm` or the home folder itself, and names the folder to use. Without bubblewrap or user namespaces, the run starts without the rule, and its answer says why and how to fix it. The run answer names the network rule: `seatbelt`, `netns` or `none`.
- **Temporary credentials (groundwork):** the vault can keep an AWS key pair, a GitHub App key, a Google service-account key or an OAuth refresh token as a source of short-lived credentials (vault schema 32), and the code that makes AWS STS, GitHub installation, Google and OAuth tokens is in. **Runs do not use it yet:** they get the static key until temporary credentials in runs ship. A source keeps them off, and an item with them on would fail its runs with `lease_failed` instead of giving the long-lived key. A pasted AWS key id with its secret, or a whole Google service-account key JSON, now becomes one Custom item. A run of an AWS pair gets `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`; a Google key keeps `GOOGLE_API_KEY`.
- **Apassy Connect (groundwork):** the account, billing and tunnel contracts and the Mac's Connect account code, with fresh Touch ID checks for every account change. The app has no Connect sign-in yet: Apassy Connect shows only as "Coming with Connect" under Runs on and in the notices below. The website has **Pricing** (`/pricing`): everything self-hosted is free, and the Connect plans show as "Coming", with no buy button. The Connect terms, imprint and privacy update are drafts: not in force and not linked.
- **Release attestations:** the Mac disk image, `latest.json`, the relay image, both team CLIs, the Linux node packages, the extension zip and the iPhone build record get GitHub build attestations, most with an SPDX SBOM. Check a file with `gh attestation verify` (`docs/operations/release.md`).

### Changed

- **New relay copy without a team code:** on apassy-relay.wyderka.cc, **New relay copy** asks for no team code. Apassy makes a key for this Mac, keeps it in the vault and uploads the encrypted copy. **Relay with a team code** is the second choice. A vault whose approvals team was made before this release sees "the relay does not keep vault copies for this connection yet" until the relay operator raises its size.
- **The free hosted relay paths end with 0.5.19:** a vault on apassy-relay.wyderka.cc shows the notice "Free approvals through Apassy relay end with Apassy 0.5.19." in Settings › Devices and "Get approvals on your iPhone" on the Mac, and under "Questions through the relay" on the iPhone. The relay row of Settings › Vault › Sync and "Sync service" on the iPhone say "Relay sync on apassy-relay.wyderka.cc is free until Apassy 0.5.19." Both name the free way, your own Mac or Linux node over Tailscale, and Apassy Connect. A relay that you run shows no notice.
- **Wi-Fi pairing is ending:** the Wi-Fi companion is now **Wi-Fi Pairing** with **Listen on This Network**, and shows only while a Wi-Fi iPhone is paired. A new iPhone cannot pair over Wi-Fi. Paired iPhones keep working. A once-only alert, "Wi-Fi Pairing Is Ending", says that it ends in two versions.
- **Bouncer brain paths:** the shell command of each bouncer state names the project folder as `.` and the home folder as `~`, for the brain on this Mac too, and for replay and fine-tuning. The decision export can take the project folder, so training states match.
- **Shadow mode:** a candidate head set now answers in the request of the active model, on the host that has its head file. The separate candidate server on port 8775 is gone. A promotion pins the head set by its hash.
- **Mac colors:** every color of the Mac window has a role in one palette. Nothing looks different; this prepares a dark appearance.

### Fixed

- **A Mac refused by the relay for a moment:** two sign-ins of one session could run at once. Then the sync status could disappear for a while, or "Removed from the relay" could come back after every sync. A session now signs in once at a time.
- **The save-login banner of the extension could show twice:** after a sign-in or sign-up page loaded, the second banner replaced the first, and a click on the first was lost. The offer shows once for each page, and again only for a page back from the back/forward cache.

### Security

- **Encoded echoes of a secret (Mac proxy, present in 0.5.16):** in 0.5.16 the Mac's run proxy replaced only the plain value. A service that echoed a value percent-encoded, JSON-escaped or HTML-escaped (for example a key sent in a query parameter) gave it to the agent. The Mac proxy now replaces those forms too, in headers, bodies, chunked bodies and WebSocket frames, also across reads, and keeps the length. Run output masks the same forms. The relay proxy shares the code.
- **A remote bouncer brain never allows production:** with My Server, every production credential, read-only too, is a hard rule: you decide, and the brain is not asked. A hard check, secret output and another host always ask you, with any brain. A local brain keeps deciding read-only production as before.
- **One tailnet peer cannot lock out the node:** failed sign-ins count for each tailnet peer, as the TLS front saw it, not for the whole listener. The Mac's own questions worker uses a separate local route with its own count. The Serve fallback asks Tailscale for each peer's address (PROXY protocol), and gives each peer at most 16 connections.
- **The run proxy:** a request on an intercepted connection needs an origin-form target and one `Host` header that names the CONNECT host, else 400 before any swap. After a real value went out, a compressed answer is 502. The Base64 of Basic credentials and the `\/` form of a value are replaced. A value that the service splits over two WebSocket messages closes the WebSocket with 1008. The listener takes at most 256 connections and gives 10 seconds for the first request head. Teredo and IPv4-translated IPv6 addresses are not public.
- **Temporary-credential settings need Touch ID:** a change of the role, policy, permissions, repositories, scopes or URLs of a source needs a fresh owner check on the Mac, and so does turning temporary credentials on or off. A revoke URL must be on the host of the token URL. Only Google's own token endpoint is called for a service-account key. A rotated refresh token is stored before a failed run, and one item refreshes once at a time.
- **Connect account changes:** each change of a Connect account or vault store needs a fresh owner check on the Mac. A codeless relay copy sends the names "Vault" and "Mac" to the hosted relay, never your names.
- **Secret-handling programs:** every program that handles secrets turns off core dumps, and on Linux it is not dumpable.

### Upgrade notes

- Vault schema 28 (node trust): `relay_membership` gets `pin` and `alt`, and the local table `cloud_node` gets `tailnet_on`, `tailnet_port`, `node_origin` and `push_gateway`.
- Vault schema 29 (bouncer brain host): the local table `bouncer_host` and the candidate columns of shadow mode. They never sync.
- Vault schema 32 (temporary credentials): the synced tables `short_lived` and `member_key`.
- Vault schema 34 (Connect account): `relay_membership.key_source` (`vault` for every existing row).
- A vault moves from 27 to 34 at its next unlock. Apps of 0.5.16 (schema 27) refuse a copy of schema 28 or later, so update every Mac and iPhone that shares the vault together. A vault of schema 28 or later cannot go back to an older app.
- Relay team schema 8: each team file gets the table `push_handle`, after a copy `<team>.db.pre-v8`. `apassy-relay downgrade-schema-7` is the way back. The hosted relay keeps the table empty and answers 409 `push_unavailable` on `/v1/push/handle` (relay `docs/OPERATIONS.md` section 25).
- Relay directory 1005: `team_code.kind` (`operator` for every existing code) and node pairing codes (`apassy-relay admin node-code`). The image of directory 1004 refuses a 1005 file; `apassy-relay downgrade-directory-1004` is the way back.
- `APASSY_RELAY_CONNECT_SYNC_BYTES` (default `0`) sets the sync size of each new Connect team. The hosted relay sets it to 64 MiB for the codeless relay copy and deploys before the apps. Teams made before it get the size by hand (`admin limits <id> --sync-bytes`). Check the disk first (relay `docs/OPERATIONS.md` section 20.6).
- Connect team limits: a Connect team pushes at most 30 snapshots and 512 MiB of snapshots an hour (403 `team_limit`, 429 `rate_limited`).
- Push gateway: a new Worker in `crates/apassy-relay/deploy/push-gateway`, with a Durable Object counter for its limits (class `LimitCounter`, migration `v1-limits`). It needs its DNS name, its gateway key and the APNs secrets before it deploys (`docs/operations/push-gateway.md`).
- iPhone and watch: `ITSAppUsesNonExemptEncryption` stays NO (standard encryption outside France). The two notification extensions (`ApassyNotifications`, `ApassyWatchNotifications`) need their own App IDs and profiles: `scripts/ios-testflight.sh` takes them in `APASSY_IOS_NOTIFICATIONS_PROFILE` and `APASSY_IOS_WATCH_NOTIFICATIONS_PROFILE`.
- Coordinated release: macOS, iOS (TestFlight, with the watch app), browser extension (Chrome Web Store), relay, Linux CLI and website move to 0.5.17 together. Every component changes: the Linux CLI is now the Linux node; the extension changes only for the save-banner fix. The hosted relay gets the two migrations (team schema 8, directory 1005), the codeless relay copy and the Connect limits; the tailnet listener and the push handles run only on a node.

## [0.5.16] - 2026-11-03

### Added

- **Bouncer section (Mac):** the sidebar has a **Bouncer** section with **Overview** (⌘2), **Decisions** (⌘3), **Agents** (⌘4) and **Logs** (⌘5). A scope bar, **Showing [All Environments] in [All Projects]**, filters every page: this Mac, each other Mac of the vault with the age of its report, and Macs that never reported. Overview shows the runs of the last 7 days, **Allowed by bouncer**, **Asked you**, **Denied**, the **Median answer**, **Runs per day**, **Needs attention** (what waits for you comes first), a table of the agents, and the environments. Logs lists the events of every environment by day, with the filters **All**, **Runs**, **Connections** and **Denied**, an agent, and text, and **Load More**. For a cloud run it lists the requests that the proxy sent (method, host, status; never a path). Agents is one page with a table for each environment. A row opens the agent page: its figures, its last runs, **Can See** with **Choose Credentials…**, and **Disconnect…**. Decisions has **History** with the same filters. The pages compute their numbers at most every 2 seconds, not for each frame.
- **Remote agents (cloud agents):** a hosted agent such as Grok Bot can use the credentials that you choose for it, without their values. Turn on **Remote Access** in Bouncer › Agents (Tailscale Funnel to your own Mac, port 8443, off by default). Turning it on asks for Touch ID; turning it off does not. The agent gets only the MCP address. It connects by itself with the MCP authorization flow (OAuth 2.1 with PKCE). Its browser page shows a code, and you allow the request in Decisions on the Mac (with Touch ID) or in Requests on the iPhone (with Face ID). Both show the code and where it returns ("Returns to grok.com"). Every allowed connect makes a new agent with no credential, also for a client that already has one ("Grok Bot 2"). You then choose its items in **Choose Credentials…**. You allow every run on the Mac or the iPhone: the card says **Not verified** and offers **Allow Once** only. The agent gets placeholders and base URLs, and your Mac puts the real value into the API request. Disconnect the agent, lock the vault, or quit Apassy, and the route stops. While remote access runs, closing the window minimizes it ([contract](docs/contracts/cloud-agents-v1.md), [plugin](deploy/plugins/apassy-cloud/README.md)).
- **`apassy agent add-remote NAME [--days N]`:** for a client without the authorization flow. It always asks for a new owner check, even inside an open Touch ID window. It prints a bearer token once, with the MCP address. The token lives 30 to 365 days (90 by default) and cannot be renewed.
- **Remote access problems:** the Remote Access block names the problem with a button: **Get Tailscale…**, **Check Again**, **Open Admin Console…** when the tailnet policy blocks Funnel, and **Use Port 10000** when another program has port 8443. While a problem lasts and remote access is off, the switch is off and disabled, and the problem's button is the way on; remote access that is on can always be turned off. Apassy never touches port 443. At start, and after a failed start, Apassy turns off a Funnel route that a crash left behind.
- **Remote agent limits:** at most 20 remote agents for each Mac, counting every agent that is not disconnected. At most 120 runs an hour, 10 waiting runs, and one waiting question for each agent. A run waits 300 seconds for your answer. An access token lives 24 hours and is refreshed. A refresh token lives 90 days from its last use.
- **Why the bouncer asked you:** a past decision of this Mac in Decisions › History has a **Why** section: the reason that the question showed, **Asked you**, the **Task** that the bouncer compared the command with and where it came from (the prompt hook or the agent), the **Rule flags**, and the answers of the **Bouncer brain**. Each use of a run now names its decision log entry. A click on a past decision shows its **Why** also while a question or request waits; **N Waiting** goes back to them, and a new question does not replace the decision that you opened.
- **Decision log file for debugging:** the window writes one JSON line for each agent request to `~/Library/Logs/Apassy/bouncer-decisions.log` (mode 0600, 2 MiB, then `.1`): the agent, the credentials, the project, the route, the reason kind and its reason, the rule flags, the task source, the bouncer brain answers, the hosts, the outcome, and the time to the decision. It has no command, user request, purpose, or secret value. `apassy decisions log [--asked] [--limit N]` reads it with no session: the questions of the last 7 days by reason, with what to change so that the next run does not ask, and the last decisions.
- **Apple Watch:** a watch app that answers access requests only (ADR 0039). It can **Allow once** while the watch is unlocked on your wrist, or **Deny**. Connect it in Settings › Devices › Add Apple Watch on the iPhone, with the code from the Mac's Add an iPhone or a Mac…, and confirm the safety words with Touch ID on the Mac. The watch never shows run questions, connect requests or vault items. Macs refuse every run answer from a watch. Apple Watch Series 9 or later, or Ultra 2 or later (arm64), with watchOS 27 or later. Settings › Devices on the iPhone shows the state of the watch (Apassy not installed, Not connected, or Connected to the vault), and the watch's Requests screen shows its vault.
- **Try the Demo (iPhone) and See a Sample (Apple Watch):** the welcome screen and Settings › Advanced have **Try the Demo**. It opens the app with a sample vault in memory only: items, a passkey, a duplicate, a waiting run question and access request from "Mac mini (demo)", past decisions and agents. A banner "Demo — sample data only" with **Leave Demo** stays on top. The demo never touches your vaults, the relay, AutoFill or notifications; pairing, import and export say "Not available in the demo". **Allow Once** in the demo still asks for Face ID. A watch with no vault shows **See a Sample**: one sample access request with Allow once and Deny.
- **Mac Agents and Decisions show the whole vault:** each Mac reads the agent feeds of the other Macs of the vault through the relay (relay-feed-v1, a Mac as a read-only reader). Agents lists the agents of every Mac, and the agents of another Mac are read-only ("Change on <Mac>."). Decisions counts and lists the decisions of all Macs. "Show agents on the iPhone" is now **Show agents on my other devices**: a Mac publishes its feed when the vault has another Mac or an iPhone. The feed now also carries the 7-day figures and the remote access state of each Mac (feed v2).
- **Import everything from another app (iPhone):** an import through Credential Exchange (Passwords, 1Password) now keeps every item. Cards, Wi-Fi networks, passports, driver's licenses, ID documents, addresses, names, notes, lone one-time codes, generated passwords and custom fields become Custom items with their values hidden and a type tag (`card`, `wifi`, `identity`, `note`). API keys and SSH keys keep their kinds. An imported passkey goes on the login that the vault already has for the same website and username, instead of making a second login. The summary gives counts only.
- **More passkeys:** imported passkeys can be ES384 (P-384), EdDSA (Ed25519) or RS256 (RSA 2048–4096) as well as ES256. Apassy keeps their PRF secrets and large blob (iOS 26.4 and later give them), answers PRF and large blob requests at sign-in on the iPhone, in the Mac passkey sheet and in the browser extension, and gives them back in an export to another app. New passkeys are still ES256.
- **Find duplicates (Mac and iPhone):** Settings › Vault › Import › Find duplicates… on the Mac, and Settings › General › Find duplicates on the iPhone, list items that hold the same account (same website and username, or the same secret values) and merge a group into one item. The kept item gets the fields it was missing; a different value stays as "Previous <label>"; the others go to the archive, where you can restore them. "Merge all identical" merges every group with the same values. A merge refuses two different passkeys, agent settings that cannot move safely, and items over the vault limits. The 1Password import result and the iPhone import offer it when the import made duplicates.
- **1Password import (Mac):** credit cards, identities, bank accounts, licences, memberships, passports, reward programs, social security numbers, medical records and crypto wallets import as Custom items, not selected first. Their values are hidden except the type, country or state, bank name and expiry. Addresses import as hidden details. A login with a passkey says that the passkey is not in the export (import it on the iPhone). Documents (files) are still not imported: Apassy does not store files.

### Changed

- **"Allow as dev" means development:** a development or local label now also gives a default risk and reversibility the development defaults (medium risk, reversible), also for labels made before 0.5.16. Before, "Allow as dev" set only the environment, so the bouncer kept treating the credential as high risk and asked for ordinary development commands. Values that you set, or that a strong signal set, do not change. Staging and production give the careful defaults back. The declaration sheet shows the development defaults when you pick development.
- **"Allow as dev" and "Allow as prod" label one item:** the Mac and the iPhone offer them only when exactly one item of the run is unconfirmed, and they label only that item. A run with two or more unconfirmed items asks as any other run and labels nothing.
- **Decisions:** the **Activity** button and timeline are gone; their rows are in Logs. A notification of an activity line opens Logs with that row selected. A new vault's Decisions says "No decisions yet".
- **Decisions with nothing waiting** shows the recent decisions of all devices and the week of each device, not an empty page. An agent page with no use or no exception is shorter, and its dates read like the rest of the app.
- **Who answered:** an answer that comes through the relay is logged with its device ("iPhone", or the name of the other Mac), not as this Mac. The log keeps the time to your answer and the kind of request (a run or a browser fill).
- **iPhone Requests:** Requests no longer shows "<Mac> is unavailable". The Wi-Fi state of a Mac shows only in Settings › Devices, with **Retry <Mac> on Wi-Fi**. Runs and access requests that come over Wi-Fi still show.
- **Mac credential page:** a one-time password is a row of the login card, with Copy and Show like the password. Copy needs no Show first. The username has Copy. The website row shows its host, with Open for http and https addresses. A login without a website offers **Add website…**. The header names the provider and the kind, and Service and Project are labeled rows. The details of a 1Password import move to the footer, under **Import details…**.
- **Agent Access:** a line under the title says what happens when an agent asks for the credential, also while the part is closed. "Always ask me" and "Environment" say what their state means, and "Hosts and risk" names the hosts that the bouncer knows.
- **Mac credential list:** the selection bar appears for two or more selected credentials. Credentials with the same kind and name show their host or folder. **Possible duplicates (N)** lists together what Find duplicates finds (the same website and username, or the same secret), with **Merge…** to open that sheet. Credentials in no folder are under **No folder** (the top level was called "Personal"). A selected row keeps a white edge around its tile.
- Dates older than a week read "9 Oct 2026".
- **iPhone lock screen:** with Face ID unlock on, opening or returning to the app shows only the Apassy icon while Face ID asks, and then the vault. The passphrase field shows only when Face ID does not open the vault (Cancel, a face that does not match, a changed Face ID enrollment), with the keyboard up. Each return to the app tries Face ID first again, and so does a vault picked on the lock screen. The launch shows the icon instead of a spinner.
- **iPhone and site:** The text describes the Apassy relay as sync with your Mac, not as the way for teams: the welcome and Add a vault screens offer **From your Mac · Apassy relay**, and the hosted relay no longer serves team vaults. Plans: everything self-hosted is free; only the hosted Apassy Connect is paid (`docs/product/plans.md`). The relay guide (`/guide`) describes what the hosted relay still serves and how to run your own relay.
- **iPhone and watch app for the App Store:** the app, the AutoFill extension and the watch app have privacy manifests (`PrivacyInfo.xcprivacy`) for the file and time APIs of the vault core and for UserDefaults. The export compliance answers name the app's own standard encryption (SQLCipher, rustls and the sealing of the relay data), outside France. App Store Connect needs no documentation for that, so `ITSAppUsesNonExemptEncryption` stays NO. The listing, the App Privacy answers, the export compliance answers and the review notes are in `docs/store/app-store/`. Nothing is submitted.
- **Privacy page (website):** `/privacy` now says what the iPhone, the Apple Watch and the relay send and keep: relay sync of encrypted vault copies, sealed requests and answers, push through the Worker and APNs, what the relay can see and for how long, and the self-hosted relay. It no longer says that the iPhone talks to the Mac on the local network only.

### Fixed

- **The bouncer asked for almost every run after a background task:** Claude Code 2.1.3xx runs the prompt hook also for turns that it injects (task notifications, peer messages, auto-continuation, `/loop` and scheduled wakeups). `apassy-hook` sent each one as your request, so a finished background task replaced your task, and the transcript check failed with `hook_unverified` and asked you. The hook now sends only your turns (`source` `user` or `sdk`), and the transcript check skips injected records.
- **The Mac app used CPU while idle:** the window drew about ten frames a second with nothing to show. It no longer polls the browser extension wait, the approvals or the remote access state on each frame, keeps the results of its last vault searches, and redraws a shown one-time code once a second. An idle window asks for no frame.
- **A stale feed of another Mac looked current:** when a later feed of another Mac does not open, Agents and Decisions keep the last good feed with "Sync this vault to see …" or "Update Apassy to see …" until a newer good feed comes.
- **Pairing an iPhone on 0.5.15 with a vault that has an Apple Watch:** the handoff no longer contains the watch, which the older iPhone could not read, so it waited until the link expired.
- **Linux builds:** a file capture no longer follows a last symbolic link on arm64 Linux (`O_NOFOLLOW` had the x86_64 value). The owner-check window and the auto-lock idle time now count time in suspend.

### Security

- **A connect never takes over an agent:** a client id is public, so a stranger could keep a connect request open and have the owner allow it for the real client's agent. Now a new request of a client ends its waiting one, and every allowed connect makes a new agent with no credential. The Touch ID prompt and the iPhone card say "Allow only if the page in your browser shows this code: <code>."
- **Where the code goes:** the Mac and the iPhone show the host that a connect request returns its code to, and the answer is bound to it. For a loopback address the Mac adds "A program on this Mac can start this request.", because any program on the Mac can reach the node.
- **No open redirect:** an authorize error of a client that you never allowed shows the page "This connection link is not valid." instead of a redirect to an address that anyone can register.
- **Strangers cannot block the connect flow:** only clients that you allowed at least once count toward the limits of 10 registrations in 10 minutes and 100 clients; a client that you never allowed goes after an hour. Bad codes and refresh tokens count only for their client (20 a minute).
- **Failed sign-ins count per source:** on `/mcp` and `/p/`, bad tokens count by the address that Funnel forwards (IPv6 by /64; 20 a minute, then 429), so a stranger holds only their own address. The authorization flow has its own count.
- **Names on the public page:** the public connect page says "your Mac", never the name of the computer. Connect names lose every control, format and tag character, with one rule on the relay, the Mac and the iPhone.
- **No operator socket on the Mac's node:** the node serves no `admin.sock`, because the coding agents of the Mac run as the same user. A socket that an older build left is removed.
- **A cloud run card shows no folder:** the folder that a cloud agent sent could put a false line on the card. The card shows only the fixed label.
- **Escaped values are scrubbed:** the relay proxy now also replaces a value that the upstream echoes JSON-escaped, HTML-escaped or percent-encoded (`\/`, `\u003c`, `\"`, `&amp;`, `&#x2F;`, `%2F` and others), also across reads, and keeps the length of the answer.
- **Prompt sources:** the transcript check takes only `typed`, `user`, `sdk` or no `promptSource` as your prompt; any other value counts as injected. An Agent SDK turn still counts as your request, but the card and the log name it "Agent SDK turn".
- **Decision log file:** it is set to mode 0600 at every write and after rotation, and it never follows a symbolic link at the log or at `.1`.

### Upgrade notes

- Relay team schema 7: each team file gets the column `agent.items`, after a copy `<team>.db.pre-v7`. Existing agents keep every item of their grants. `apassy-relay downgrade-schema-6` is the way back (relay `docs/OPERATIONS.md` section 23).
- Relay directory 1004: `relay.db` gets the tables of the MCP authorization flow, in one transaction. The hosted relay migrates too, keeps them empty, and answers 404 on every path of the flow. The image of directory 1003 refuses a 1004 file; `apassy-relay downgrade-directory-1003` is the way back, with the relay stopped (relay `docs/OPERATIONS.md` section 24).
- Vault schema 24: `trusted_device` accepts the device kind `watch`. Apps at schema 23 or older refuse schema-24 copies until they update.
- Vault schema 25: passkeys can have the formats `es384-pkcs8-v1`, `ed25519-pkcs8-v1` and `rs256-pkcs8-v1`, and the optional fields `passkey_prf_uv`, `passkey_prf_no_uv`, `passkey_large_blob` and `passkey_large_blob_size`. No table changes. Apps at schema 24 or older refuse schema-25 copies until they update, so update every Mac and iPhone that shares the vault.
- Vault schema 26 (remote agents): the vault gets the local tables `cloud_agent`, `cloud_item`, and `cloud_node` and the column `agent.kind`, for the Mac's own node. Remote agents stay on the Mac that made them and do not sync.
- Vault schema 27 (Bouncer figures): `decision_log` gets the columns `request` and `wait_ms`, `cloud_agent` gets `client_id` and `connected_with`, and the local table `cloud_run` is new. All of it is local. A vault of schema 26 or earlier moves to 27 at its next unlock, and its synced content does not change. Apps of schema 26 or earlier refuse a copy of schema 27, so update the Mac and iPhone apps together. A vault of schema 25 or later cannot go back to an older app.
- Feed v2: a Mac of 0.5.16 publishes feed v2. An iPhone or a Mac of 0.5.15 or earlier shows "Update Apassy to see the agents of <Mac>" until it updates. A 0.5.16 reader takes v1 and v2.
- Connect card v2: an iPhone of 0.5.15 or earlier cannot answer a connect request; allow it on the Mac. Run cards stay card v1.
- Wire additions: `passkey_assert` (iPhone core), the Mac credential bridge and the browser host take optional `prf` and `large_blob` inputs and answer `algorithm`, `prf` and `large_blob`; the bridge request frame grows to 128 KiB. iPhone core: `passkey_import` takes `prf`, `large_blob` and `attach_id`; new calls `duplicates` and `duplicates_merge` (app role only), connect cards in the question list and their answers `allow_connect` and `deny`, and the feed v2 fields of `feed_list`. Broker: `submit_user_request` takes an optional `source`.
- Building from source: the Mac app's binary now comes from the workspace crate `crates/apassy-app` (binary `apassy-app`, copied into the bundle as `apassy`), which links the embedded relay. `scripts/build-app.sh` builds it.
- Coordinated release: macOS, iOS (TestFlight, with the watch app), browser extension (Chrome Web Store), relay, Linux CLI and website move to 0.5.16 together. The relay, the Linux CLI and the extension go from 0.5.14 straight to 0.5.16, because 0.5.15 went out only on the Mac and the website. The extension changes only for passkey PRF and large blob. The Linux CLI has no functional change. On the hosted relay only the two migrations (team schema 7, directory 1004) change; the other new relay code (the public listener, the failed-auth limiter, the authorization flow) runs in the node of a Mac.

## [0.5.15] - 2026-11-03

### Fixed

- Touch ID vault unlock now shows the Apassy panel. In 0.5.14 the keychain helper (an `LSUIElement` app) fell back to the macOS dialog, because macOS refuses to set the accessory policy that the app already has.

### Upgrade notes

- No vault schema change: schema stays at 23. The Touch ID helper protocol stays at version 1.
- Coordinated release: macOS, iOS (TestFlight), browser extension (Chrome Web Store), relay, Linux CLI and website move to 0.5.15 together. iOS, the extension, the relay and the Linux CLI have no functional change. Relay team schema 6 and directory schema 1003 do not change.

## [0.5.14] - 2026-11-02

### Changed

- Touch ID prompts appear in an Apassy panel instead of the macOS dialog.
- **Relay:** The relay is open source under Apache-2.0 and is part of this repository (`crates/apassy-relay`). Its image and the Linux team CLI build here.
- **Relay:** The hosted relay no longer serves shared team vaults. It refuses the proxy, MCP, access requests, runs, the host lane and new team-vault content with `410 team_vaults_retired`. Relay sync, questions, the feed and push keep working. A relay that you run yourself keeps team vaults on by default (`APASSY_RELAY_TEAM_VAULTS=1`).

### Fixed

- Release uses the verified successful `release-binaries` artifact after a partial CI rerun, even when that job ran in an earlier attempt.

### Upgrade notes

- No vault schema change: schema stays at 23. The Touch ID helper protocol stays at version 1.
- Coordinated release: macOS, iOS (TestFlight), browser extension (Chrome Web Store), relay, Linux CLI and website move to 0.5.14 together. This is the first relay built from this repository. Relay team schema 6 and directory schema 1003 do not change.

## [0.5.13] - 2026-11-02

### Added

- Add `apassy_fill_in_browser` for agent website logins, with broker authorization, saved-site binding, and status-only responses.
- **Browser extension:** Deliver agent fills to one matching focused tab, require device-local trust for the exact remote-debugging instance, disclose agent page access in owner questions, and clear agent-filled passwords when a show-password toggle makes them visible.
- **Browser extension:** Request permission in Apassy to allow passkeys and codes once or for five minutes in an exactly identified remote-debugging profile. Show remaining time and End now in the popup.
- Protected, device-local browser profile trust list for agent fills, with owner approval to add and removal in Browser settings. A grant for one debugging port never covers another.

### Changed

- **iPhone:** Match Mac owner choices for known and unknown environments, with signed dismissal comments returned to the agent.
- **iPhone:** Add a device-local “Ask for Face ID” setting shared by approvals and vault actions in the app. Every time remains the default; AutoFill still authenticates every fill.
- The app names the two parts of the bouncer. The bouncer brain is the model: it answers questions about a command and decides nothing by itself. The bouncer gate is the fixed checks and the decision. Settings > Bouncer, Learning, and the owner checks use these names.
- The lock screen shows the Apassy logo and asks for Touch ID first when Touch ID unlock is on.
- Staged updates install when the vault locks, or right away with Restart to update.
- Make the Touch ID frequency global for all owner actions, including revealing secrets, production approvals, settings and pairing. Replace heartbeat-gap revocation with synchronous lifecycle-helper state checks; lock, sleep, session changes and helper loss still end the window.
- Let the bouncer brain use agent-stated tasks when no verified hook task is available, with visible provenance.
- Permit declared read-only production credentials after the bouncer gate checks the brain's answers and its policy; production write/admin still asks the owner.
- Simplify owner questions to allow or dismiss, add guarded environment-and-allow actions and refusal comments, and show a floating question queue.
- Keep v1 remote question cards so old iPhones keep working; accept new signed allow/classify/dismiss answer choices, including bounded refusal comments, alongside legacy kinds. Card v2 publication stays off.

### Upgrade notes

- No vault schema change: schema stays at 23. iPhones on TestFlight 0.5.10 keep receiving the same question cards and answers; TestFlight 0.5.13 adds the new answer buttons and the Face ID window.
- Coordinated release: macOS, iOS (TestFlight), browser extension (Chrome Web Store), relay, Linux CLI and website move to 0.5.13 together. The extension reaches browsers after Chrome Web Store review. The relay and Linux CLI have no protocol or schema change.

### Fixed

- The bouncer brain, the local model, uses about half the memory on Apple Silicon: 1.8 GB idle, before 3.4 GB and more. Its answers do not change.

## [0.5.12] - 2026-11-02

### Fixed

- Agent questions show why the owner must answer. Unconfirmed classification stays secondary.
- Show privacy-safe bouncer route counts and top reasons since app start. Log route outcomes without request data.

### Upgrade notes

- No vault schema change: schema stays at 23. Macs on 0.5.11 and the iPhone on TestFlight 0.5.10 keep syncing; no TestFlight update is needed.
- The Mac download and in-app auto-update publish with this release. The Chrome Web Store extension update follows separately (0.5.10 is in review). Relay stays at 0.5.9.

## [0.5.11] - 2026-11-02

### Fixed

- Development on agent questions follows the owner check window after each local click. Other sensitive and durable actions still ask.
- Display sleep keeps the window open. Mac lock and system sleep still end it. Keep lifecycle heartbeats active and check Touch ID availability again for each fresh check.
- Add privacy-safe owner window diagnostics.
- **Browser extension:** Explain passkey and code refusals when the browser was started with remote debugging or a test extension.

### Upgrade notes

- No vault schema change: schema stays at 23. Macs on 0.5.10 and the iPhone on TestFlight 0.5.10 keep syncing; no TestFlight update is needed.
- The Mac download and in-app auto-update publish with this release. The Chrome Web Store extension update follows separately (0.5.10 is in review). Relay stays at 0.5.9.

## [0.5.10] - 2026-11-01

### Added

- Owner CLI `apassy code` shows the current one-time code and expiry. Each request requires fresh Touch ID. Use `--copy` for the app clipboard or `--json` for structured output.
- Agent runs can get one-time codes only with owner approval. Password answers never cover codes.
- Answer access requests in iPhone Requests: Deny, or Allow once with Face ID (ADR 0033).
- After pairing a new iPhone, offer to remove an older paired iPhone with a fresh Mac owner check.

### Fixed

- **Browser extension:** Never for this site waits until the exclusion is saved before closing the banner. Show an error if saving fails (PR #45).

### Upgrade notes

- A 0.5.10 Mac converts the vault to schema 23 at unlock. Older apps (0.5.9 and earlier, Mac or iPhone) cannot read it. Keep an encrypted pre-upgrade backup and shared-vault clients closed. Update every Mac to 0.5.10 and the iPhone to TestFlight 0.5.10 before resuming sync.
- TestFlight and the Chrome Web Store update follow separately. The Mac download and in-app auto-update publish with this release. Relay needs no change and stays at 0.5.9.

## [0.5.9] - 2026-11-01

### Added

- **MCP:** bounded concurrent calls with a reserved catalog/status slot, cancellation that withdraws pending questions, and 15-second progress. Broker operation receipts support reconnect recovery and optional idempotency keys without blind mutation replay. Receipts retain metadata only for 15 minutes after completion; executing commands are not undone by cancellation.
- Free and Personal vaults can connect an iPhone for approvals and push without an account or operator code. Connect saves its key before contacting the relay, reuses it after failures, and confirms each iPhone with safety words.
- **Browser extension:** offer to save a typed login or update an existing account after a sign-in/sign-up submission and same-origin navigation or form transition. Username-first flows retain short-lived metadata. A trusted Save/Update click uses the existing app owner check; pending passwords stay only in memory for at most three minutes. Never for this site shares the toolbar's reversible hostname exclusion.
- Transactional staged host-file repair, connection identity metadata, and Settings host health with owner-checked reconnect.
- Opt-in isolated synthetic broker/MCP/hook diagnostic through `doctor --live`.

### Fixed

- **Inline login menu:** align directly below the field, or above when the menu would cover Submit and room permits. Clamp to the viewport and reposition on scrolling and resizing; never detach beside the form.
- Preserve existing catalog restrictions during reconnect; align helper help/version/usage handling and bound fixture inputs.

### Upgrade notes

- A 0.5.9 Mac converts the vault to schema 21 at unlock. Keep shared-vault clients locked/closed and keep an encrypted pre-upgrade backup. Update every Mac to 0.5.9 and the iPhone to TestFlight 0.5.9 before resuming sync; older apps cannot read schema 21.
- TestFlight and the Chrome Web Store update follow separately. The Mac download and in-app auto-update publish with this release; relay 0.5.9 is already live.

## [0.5.8] - 2026-10-31

### Added

- Add optional per-Mac Lock after inactivity in Security, defaulting to Never to preserve unattended agent access.

- **Mac owner checks:** Settings > Security now offers How often to ask for Touch ID. Every time stays the default. Protected per-device windows cover browser and macOS AutoFill password/code actions, passkey sign-ins and explicitly clicked Allow once. Lock, sleep, user switch, vault lifecycle changes and failed/cancelled checks revoke them. Sensitive and durable actions still require fresh checks. Encrypted backup, CLI decision export and CLI token issuance now also take fresh checks. iPhone is unchanged.

### Changed

- **Browser extension:** suggest site-matched account metadata on all granted HTTPS sites and localhost by default, including existing broad passkey grants. One permission button, one global switch and per-site exclusions replace per-host activation. Compact account rows, site-local search, account details, approval context and paired light/dark styling keep settings behind a small link.

### Fixed

- Refuse agent command execution with secrets shorter than four bytes before starting the process; preserve ordinary words in the standalone token masker.
- Preserve CLI CSV Website metadata and exact passwords; reject malformed quotes before import.
- Start configured desktop agents through the Apassy sandbox launcher.
- Bound MCP input while reading, terminating oversized streams.
- Retain deletion tombstones indefinitely to block stale-replica resurrection.
- Stop marking imported accounts as duplicates based only on their name and kind.

- **CLI setup and diagnostics:** setup verifies runnable host commands and reports JSON state consistently. Doctor diagnoses malformed host configuration; MCP refusals return sanitized errors.

- **Mac, bouncer decides by default:** first use, staging, unconfirmed production and default-source classifications reach the model without evaluation setup (ADR 0031). Defaults require 80% task match even for safe commands or reads; calibration cannot lower this check. Confirmed production, Always ask, foreign projects/DB hosts, missing context and unfit owner answers keep their vetoes. A model allow permits one run and remembers nothing.
- **Mac, bouncer visibility:** Settings > Bouncer shows inference readiness and counts for the owner's local day for model decisions, owner questions and failures. Decisions hides the obsolete evaluation setup offer. Stored schema-20 scopes and compatibility APIs remain; routing no longer requires or reads them.
- **Evaluation safety and coverage:** the scratch project matches fixture declarations. A non-executing broker evaluator replaces stale grant revocation and stops before credential delivery or process creation. Missing intended inference and unsafe allowances fail the harness. A frozen routing smoke set reports model calls and latency.
- **Bouncer review:** foreign destinations ask even without a literal secret reference. Encoded hosts, IDNs and IPv6 zones stay visible to this check. Missing request/declaration veto remembered execution. Model-field spoofing in command text asks, and oversized model inputs are rejected before truncation can hide the command. Evaluation coverage counts valid scored responses, not failed HTTP attempts.
- **Model diagnostics:** temperature warnings name each affected bucket and whether it affects the bouncer's yes/no questions. Model weights and calibration are unchanged.
- **Browser suggestions:** query already-focused fields on injection, enablement and reload; recognize conservative label-only username fields while excluding search, OTP, newsletters and text-displayed passwords. Distinguish username filter misses from no site logins and missing Website guidance. Support same-origin blank/srcdoc frames, explain cross-origin refusals, and measure inline placement to avoid page actions. Fill and save triggers refuse untrusted events and retain app approval.
- **Browser matching:** canonicalize IDNs on both sides and reject ICANN/private public-suffix Websites with the existing pinned PSL. Preserve exact ports, HTTPS and host/subdomain boundaries. Add IDNA redistribution notices and regression coverage.

- **Model readiness:** a healthy HTTP endpoint alone no longer marks a failed warm-up ready. Readiness requires valid inference with the active model pin when configured; external mode never launches a process.
- **Model deadlines:** each real inference attempt has an absolute 10-second deadline and at most one timeout retry (20 seconds by default). HTTP errors, invalid answers, and model-version mismatches ask the owner without retrying. Only inference repeats, never command execution.
- **Automatic-use summaries:** both totals include allowed requests without an owner question from the model, patterns, and remembered execution answers. Denials and unanswered/manual requests do not count as successful automation.

- **Extension compatibility:** negotiate trusted-gesture support from native app status; older apps receive legacy requests with fresh owner checks. New-app window reuse still requires trusted gestures and signed-host provenance.

### Upgrade notes

- A 0.5.8 Mac converts the vault to schema 20 at unlock; sync can also write schema 20 without an edit. Every iPhone and Mac sharing the vault must update to 0.5.8 before reopening it. Older apps cannot read schema 20.
- Keep shared-vault clients locked/closed and preserve an encrypted pre-upgrade backup. Install TestFlight 0.5.8 on the iPhone first, then update every Mac before resuming unlock/sync; upload the extension to the Chrome Web Store after the Mac update.
- Relay and Linux CLI are intentionally unchanged for this app release; this is not a completed coordinated six-component release.

## [0.5.7] - 2026-10-20

The coordinated 0.5.7 release updates the iPhone app, Mac app, Linux CLI, browser extension, relay, and website together.

### Fixed

- **iPhone, Requests History:** an unlocked vault that does not send its requests through the relay is no longer shown as locked. History says that requests are off for it. A vault whose requests are really locked has an Unlock button, as in Waiting.
- **iPhone, notifications:** when no vault on the iPhone sends its requests through the relay, the notification status says so, instead of "Waiting for Apple to register this iPhone". Requests over Wi-Fi never notify.

### Security

- **All apps:** rustls-webpki 0.103.16 and webpki-root-certs 1.0.10, for RUSTSEC-2026-0382 and RUSTSEC-2026-0383 (distrusted emSign intermediates could be accepted).

### Upgrade notes

- Push notifications need a vault that sends its questions through the relay: on the Mac, turn on Send questions through the relay in Settings > Devices, then connect the iPhone.
- The Mac app, extension, relay, and Linux CLI receive the coordinated version bump without changing the request wire protocol.

## [0.5.6] - 2026-10-19

The coordinated 0.5.6 release updates the iPhone app, Mac app, Linux CLI, browser extension, relay, and website together.

### Changed

- **iPhone, Requests:** Waiting and History share the same native list presentation. Review, Allow Once and Deny stay close to the waiting request; completed and unconfirmed attempts remain available in encrypted local history, with search and filters.
- **iPhone, navigation:** Requests uses compact actions and the Waiting / History picker. Vault shows the active vault name and selector. Search uses its search field; folders, details and forms use compact contextual navigation titles.

### Fixed

- **Mac, receiving Requests:** a question that arrives before its key or trusted-device record now becomes visible after vault sync without reopening the vault. Receiving failures show a contextual message instead of an all-clear state. Expired and settled questions stay removed, and approvals still require a fresh owner check.
- **iPhone, durable request history:** device-local history keys keep history readable across question-key rotation. Atomic migration preserves older history when its key is available; storage failures preserve encrypted data and block unsafe retries. Unconfirmed answers remain guarded against accidental duplicate sends.

### Upgrade notes

- Macs must be explicitly joined under Settings → Devices to receive each other's requests; opening the same synced vault alone does not enroll a device.
- Updating from an earlier Requests test build migrates readable history forward. Older Requests test builds cannot read the new history format. If a required legacy key was already lost, encrypted history is preserved and reported as unavailable.
- Extension, relay and Linux CLI receive the coordinated version bump without changing the request wire protocol.

## [0.5.5] - 2026-10-17

The coordinated 0.5.5 release updates the iPhone app, Mac app, Linux CLI, browser extension, relay, and website together. The UX changes below require this version bump so installed 0.5.4 apps can receive them; rebuilding 0.5.4 is not an upgrade.

### Added

- **Mac, native menus:** File, Edit, Item and Folder menus expose credential/folder creation, text editing, bulk Move/Undo and folder reparenting, with current-session and focus guards.

- **Mac, Copy a secret:** each supported secret field has Copy, with a fresh Touch ID or vault-passphrase check for that item, field, and revision. No reveal is needed first. Apassy requests clipboard clearing after 30 seconds and on lock, vault switch, or quit while its write still matches. Other local apps can read or retain a copied value; clipboard privacy markers are advisory. Passkey keys and one-time-password setup keys are excluded ([ADR 0027](docs/adr/0027-owner-desktop-copy.md)).
- **Browser, account suggestions and password updates:** optional site access enables an account chooser at login fields. Focus retrieves matching account metadata; selecting an account still needs its own owner check before fill. Update Login changes only the selected login's password after a fresh check. The extension retains the result across the app handoff and explains recovery for changed pages, unsupported frames, a locked app, or a missing host.

### Changed

- **iPhone, daily destinations:** Vault opens the credential list directly, alongside Requests and Search. Agent Access is in Settings and credential context. Healthy sync and organization tools are secondary; sync and security problems retain direct recovery. iCloud setup offers optional AutoFill with Later.
- **Mac and iPhone, adding credentials:** Login, Paste, and Other entry points keep the chosen folder. Save reports the actual saved item and destination; failed saves retain the draft. iPhone editors protect unsaved changes and freeze the submitted input while saving.
- **Mac, finding and organizing:** search includes visible account identities and websites, with an explicit folder or all-credentials scope. Command-click and Shift-click select credentials for one bulk Move; Undo Move restores their original folders. Folder menus include Move Folder with cycle and name-collision checks. Saved credentials become visible after creation, and connecting an agent is optional during setup.

### Fixed

- **Requests and notifications:** a generic iPhone push opens a refreshed Requests list without choosing a newer question or starting an unlock. A sent answer stays waiting or unconfirmed until the Mac confirms it. Notification settings report current iOS permission and registration, with recovery actions. Mac notifications carry an opaque local route that is revalidated before opening an exact request; stale routes open the list. Settled alerts are reconciled conservatively, and suggestions use quieter attention than blocked work.

## [0.5.4] - 2026-10-17

### Added

- **Sync log:** each failed folder or relay sync writes one line to `~/Library/Logs/Apassy/sync.log`: the time, the list ID of the vault, the kind of sync, the error, the status of the synced file, and the first digits of its hashes. The same error writes at most one line every 10 minutes, with a count; the first sync that works after failures writes one line too. No vault name, credential, value, or passphrase goes into the log. The file has mode `0600` and stays under 256 KiB (one older file, `sync.log.1`) ([sync](docs/operations/sync.md) §7.2).
- **Mac, notification when sync stops:** when the open vault keeps failing to sync for 5 minutes (10 minutes while iCloud downloads), Apassy posts one notification: "Personal" has not synced for 5 minutes, with a short reason, and "Open Settings > Vault > Sync". One for each streak of failures; a folder or relay that is not reachable causes none ([sync](docs/operations/sync.md) §7.3).

### Changed

- Development: the integration tests are one test program, `tests/it.rs`, with one module for each `tests/<name>.rs` file (`cargo test --all-features --test it companion::`), and the aliases in `.cargo/config.toml` (`cargo t`, `cargo clippy-all`) use one feature set. `target/` keeps one copy of the crate and its dependencies instead of one per test file and feature set. CI still runs four serial test groups, now by module.

### Fixed

- **Mac, iCloud Drive sync:** a synced file that is on the Mac but older than the version in iCloud (iCloud says "not downloaded" or "downloaded", not "current") no longer shows "Up to date". Apassy shows "Waiting for iCloud…", asks iCloud for the newest version, and waits for it before it merges or pushes, so it does not take the old copy as the newest one or write over the newer one. Before, Apassy asked iCloud only for a file that was not on the Mac at all, and a change from the iPhone could stay unsynced on a Mac that showed "synced" ([sync](docs/operations/sync.md) §7.1).

## [0.5.3] - 2026-10-15

### Upgrade notes

- Update the Mac and the iPhone together. An iPhone on 0.5.3 removes an exception only on a Mac with 0.5.3; for a Mac on 0.5.2 it says "Update Apassy on <Mac>". A Mac on 0.5.3 no longer takes the removal of a "Never" or "Always ask" exception from an iPhone on 0.5.2.

### Security

- **TLS library:** rustls is updated from 0.23.45 to 0.23.46 for RUSTSEC-2026-0346, -0347, -0348, and -0349 (published on 2026-10-14). The Mac and the iPhone use it for their connections to the relay.
- **What you confirm is what is removed:** removing an exception from the iPhone now signs the names it showed (agent, credential, Mac) and the list they came from. The Mac checks those names against its own vault, again at the moment it removes the row, and removes nothing when they differ. A feed with false names on real exceptions no longer gets an exception removed ([relay feed v1](docs/contracts/relay-feed-v1.md) §9.3, §15).

### Fixed

- **Mac, Settings > Devices:** the summary counts an iPhone linked through the relay ("1 iPhone"), not only one paired on this network.
- **Mac, Settings > Devices > Relay:** "Remove…" lines up with the switches above it.
- **iPhone, Agents:** on a vault that is not selected, "Remove" is offered when its passphrase is kept behind Face ID. Face ID reads that vault's keys again first, then the confirmation shows.

## [0.5.2] - 2026-10-14

### Added

- **Agents on the iPhone:** the Agents tab lists the agents of every Mac of your vaults, grouped by vault and Mac. Each agent shows its uses this week, its recent uses, and its exceptions. Commands show `[apassy:secret]` in place of the values of the vault's credentials. You can remove an exception from the iPhone. Removing one that limits the agent ("Never" or "Always ask") asks for Face ID, and the Mac checks the signature before it applies it. The Macs publish this list end-to-end encrypted through the relay team of the vault's questions ([relay feed v1](docs/contracts/relay-feed-v1.md)). The relay needs team schema 6; with an older relay, the tab says where the agents are.
- **Mac setting "Show agents on the iPhone"** (Settings > Devices > Relay), on by default. Turning it off removes this Mac's list from the relay.

### Fixed

- **Questions of every vault on one iPhone:** an iPhone with several vaults (for example Personal and Work, each with its own Macs) gets and answers the questions of each vault. Each answer is signed with the answer key of that vault's team. After the app returns from the background, Decisions shows one "Unlock with Face ID" row for the locked vaults; it no longer prompts by itself.
- **Notifications off** removes the push token from the team of every vault and unregisters the iPhone from notifications. Removing a vault also removes its token from that vault's team.
- **iPhone battery:** no busy loop when this iPhone was removed from the team of every vault.
- **iPhone background:** the app no longer holds a vault file lock in the background while it opens the questions of another vault.
- **iPhone search:** only the Search tab has the search field.

### Security

- **Masked commands:** use rows and the Activity text of a run mask the values of every credential of the run before the text is cut. A value of another credential in the same command, or the start of a value at the cut, is no longer stored in clear.

## [0.5.1] - 2026-10-14

### Fixed

- **iPhone pairing:** a companion QR scanned in a device connection flow opens companion pairing with the usual owner confirmation, instead of being rejected as an invalid relay link. A late response from a cancelled relay connection cannot interrupt the new pairing flow.
- **iCloud sync:** connected vaults merge authenticated conflicting file versions, retain encrypted recovery copies, and check for intervening changes before resolving the captured versions. Unreadable or incompatible copies remain unresolved.
- **Older iCloud copies:** sync accepts verified schema-16 snapshots from earlier releases and preserves their fields and variable bindings during migration. Unsupported or inconsistent copies identify whether the current iCloud file or a conflict copy stopped sync.
- **iPhone sync status:** long errors wrap fully; tapping a problem opens Settings > Devices.

## [0.5.0] - 2026-10-13

One version, 0.5.0, for the Mac app, the iPhone app, and the browser extension. Agents need no setup for each credential: a connected agent sees the names of your credentials, and the bouncer decides each use from the first one or asks you ([ADR 0025](docs/adr/0025-low-friction-access.md)). The Mac app has a new window with folders, Decisions, and Agents, you add a credential by pasting it, and the iPhone app follows the same model ([ADR 0026](docs/adr/0026-simple-app.md)).

### Upgrade notes

- Make an encrypted backup first. Then update every Mac and iPhone that shares the vault through a folder, iCloud Drive, or the relay, at the same time.
- The first unlock migrates the vault from schema 17 to schema 19. Apassy 0.4.1 and older cannot open the upgraded vault or read its copies. A 0.5.0 build still merges a copy of schema 17 or 18 from a device that has not updated yet.
- The agent settings of 0.4.1 become exceptions, so no agent gets more than before without you ([ADR 0025](docs/adr/0025-low-friction-access.md) §3f):
  - An agent that did not see all credentials gets the exception "only these items": the credentials of its grants that still work (not expired) and of its connector grants. It does not see the other credentials, and the bouncer treats them as "Not for this agent". Such an agent without grants gets no credential.
  - A grant in "Ask me each time" becomes "Always ask for this agent". So does a grant with a command prefix, a forbidden word, a run limit, an expiry, or an instruction, a rule that does not read, and an "any folder" grant with the real value.
  - Any other grant in "Bouncer decides" becomes nothing: the bouncer decides by default now. An agent that saw all credentials gets no "only these items".
  - Revoked agents and grants of deleted credentials get nothing. Grants, rules, requests, and remembered patterns stay as history. You remove an exception on the page of the agent, after the owner check.
- A question waits 5 minutes, so the host of an agent needs a longer tool time-out: `MCP_TOOL_TIMEOUT=330000` for Claude Code, `tool_timeout_sec = 330` for Codex. "Connect an Agent" and `apassy setup` write these values. Set them for a host that you connected by hand.
- Questions through the relay need a relay with team schema 5, which is not deployed yet. With the current relay, Settings > Devices says "The relay does not support questions yet — update the relay.", and each question stays on the Mac that asks and on an iPhone paired on the local network.

### Not done yet

- Shared vaults ([ADR 0026](docs/adr/0026-simple-app.md) §6) are not built. You cannot share a vault yet.
- The Mac does not send its agents, agent use, rules, requests, and suggestions to the iPhone yet. The Agents tab, "Agent use" and "Rules from your answers" of a credential, and Requests and Suggestions in Decisions on the iPhone show "Available when the Mac is connected".
- Push notifications on the iPhone are in TestFlight without Time Sensitive delivery.
- Acceptance on physical Macs and iPhones is open.

### Added

- **The bouncer decides from the first use** ([ADR 0025](docs/adr/0025-low-friction-access.md) §3). It reads the agent, the user request, the project (a git repository with all its worktrees, or a folder without git), the kind of action (read, change, deploy, delete or irreversible), the command, the hosts that the secret goes to, the provider and declaration of the credential, and the history. It asks you when the credential has no history in the project, when a secret goes to a host that is not a host of its provider, when a hard rule applies, or when it is not sure.
- **Decisions** lists what waits for you: Waiting (with the time left of the 5-minute wait), Requests, and Suggestions. A question has Deny, Allow Once, and "Allow ACTION in PROJECT". Apassy remembers that answer for the credential, the project, and the kind of action, for all agents. The "⋯" menu has the stricter answers "Not for this agent", "Always ask for this agent", and "Disconnect the agent". An answer that allows needs Touch ID or the passphrase; a stricter answer does not.
- You can allow production for one project and one kind of action: "Allow production: ACTION in PROJECT", after the owner check. It covers only a command whose kind a rule identifies, and only the hosts of that run. The credential page lists your answers and allowances, and removes one with one click. A credential that is production only by the careful default asks once in each project and kind of action, with "Development" and "Production" as answers.
- Each credential page shows its agent use. From that use, Apassy suggests corrections in Decisions > Suggestions, for example "Mark it as production?" or "Limit it to this project?". Until you answer, the bouncer uses the more careful value.
- The line under the Decisions title counts how often Apassy asked you this week.
- Agent tools that add credentials, without the agent getting a value ([ADR 0025](docs/adr/0025-low-friction-access.md) §6):
  - `apassy_capture_credential` saves the output of a command or a file. A fixed list of token commands, such as `gh auth token` or `op read op://…`, runs at once; any other command, and a file outside the project, waits for you.
  - `apassy_generate_credential` makes a password or a token, and `apassy_save_credential` saves a value that the agent already has.
  - `apassy_ask_owner_for_credential` opens a request in Decisions > Requests: you paste the credential, and the agent gets the item.
  - `apassy_update_credential` and `apassy_describe_credential` change only credentials that the agent created. An update keeps the previous value hidden for up to 7 days, and you can restore it.
  - An agent creates or updates at most 10 credentials and opens at most 5 requests each hour.
- **Questions through the relay** (Settings > Devices > "Questions through the relay", off by default, after the owner check). Each waiting question goes end-to-end encrypted to every device of the vault, and the first valid answer counts. The relay sees the routing only. The iPhone gets a push notification without content and answers with Face ID; another Mac answers after Touch ID. A vault in iCloud Drive gets a team for questions only. "Add an iPhone or a Mac…" adds a device with a QR code and safety words. This needs the relay update (see Upgrade notes).
- **The Mac window** has three columns ([ADR 0026](docs/adr/0026-simple-app.md)): a sidebar with "All credentials", the folders, Decisions with a red count, Agents, the lock state, and Settings; a list; and a detail. ⌃⌘S collapses the sidebar, and ⌘1 to ⌘3 switch places.
- Folders, nested to any depth. Deleting a folder moves its credentials to the parent folder. Agents see the folder path in their catalog, and the bouncer reads it as context.
- **New Credential** ("+"): paste a secret, a `KEY=value` line, a `.env` file, a URL with a password, or an `otpauth://` link, then Add. Apassy finds the kind, the provider, the name, the variable, the hosts, and the declaration on this Mac, without sending the value anywhere. A `.env` file gives one row for each line. "More kinds…" opens the full form. `apassy add [--folder PATH]` does the same from a terminal.
- The credential page shows the provider, the secret, the variable, the host, the folder, the agent use, the rules from your answers, "Always ask me", the environment, and "Hosts and risk". While the environment is only a default, it asks "Is this a development key?".
- "Connect an Agent" in Agents: pick Claude Code, Codex, T3 Code, or Other, and confirm once. Apassy saves the host settings; for Other it shows the token and the MCP configuration one time. The page of an agent shows its uses, the actions it used this week (read, change, deploy, delete) with their counts and projects, its newest uses with their result, its projects, an optional note for the bouncer, its exceptions, and Disconnect. Uses that were not allowed show in red.
- **The iPhone app** follows the Mac ([ADR 0026](docs/adr/0026-simple-app.md) §8): the tabs Vault, Decisions, Agents, and Search; the Vault with the Watchtower card, "All credentials", "Favorites", "Archive", "Password generator", and nested folders; New Credential by paste or QR code, with the detection on the iPhone and masked previews only; a credential with its variable, folder, "Always ask me", and environment; and the editor with a Folder row.
- The iPhone Decisions tab shows the relay questions and the runs of the Mac paired on Wi-Fi in one Waiting list, with a fixed bar: "Allow ACTION in PROJECT", Deny, and Allow Once. A production answer is red. An answer that allows needs Face ID.

### Changed

- The Mac disk image has the version in its name (`Apassy-0.5.0.dmg`), and <https://apassy.wyderka.cc/download> redirects to it. `latest.json` and `/download/Apassy.dmg` stay as before, so apps from 0.3.0 still update. From 0.5.0, the app also accepts the versioned name in `latest.json`.
- A new vault shows two steps instead of the "Get started" list: paste your first credential, and connect an agent. A step shows done when it is; the list goes away when both are done.
- An agent needs no grant. Connecting it is the only setup. Every agent gets the catalog of credential names without values, with folder paths, less the credentials that its exceptions hide. This replaces "a first use always waits for the owner" of [ADR 0024](docs/adr/0024-access-at-first-use.md).
- Without a running bouncer, each run and each connector use waits for you. An agent still has at most one waiting question.
- New credentials of AWS, Google Cloud, GitHub, Stripe, Supabase, and PlanetScale get the real value, because the command-line tools of these providers do not accept a placeholder. Apassy keeps their hosts for the bouncer. Cloudflare keeps the placeholder.
- Settings is a view of the main window, like Decisions and Agents: the gear at the bottom of the sidebar or ⌘, opens it, and any sidebar row leaves it. It has six sections, each with a one-line status: Vault (the vault, sync, backup, import), Security (Touch ID, passphrase), Devices (notifications of this Mac, iPhones, other Macs, the relay), Bouncer (the model, calibration and learning), Tools (command line, browser extension), and Updates.
- Settings no longer shows developer details (the broker address, the socket, the contract version) or status rows that need nothing from you. A warning shows only when something is wrong.
- The vault schema is 19 (it was 17). Schema 18 adds folders, the policy of an item, the use log, your answers, exceptions, requests, and suggestions. Schema 19 adds the devices that may answer questions and one relay membership for each team; the relay sync key moves there.
- On the iPhone, Home, Items, Watchtower, and Approvals become Vault, Decisions, Agents, and Search. Watchtower is a card in Vault. The companion of the Mac on Wi-Fi is "Mac on Wi-Fi" in the "⋯" menu of Decisions. Settings has the groups General, Devices, Security, and Advanced.

### Removed

- From the Mac app: grants, decision modes, the folders of an agent, and the "see all" switch; the process access and access request sheets; and the first-use card, which is a question in Decisions now.
- The Activity and Learning views. Decisions shows what waits and the counts of the week; the calibration and the candidate model are in Settings > Bouncer > Calibration and learning.
- The "Needs setup" filter and the agent column of the credential list.
- The token lifetime setting of the app. `apassy agent lifetime` reads and sets it.

### Fixed

- Sync through iCloud Drive runs on its own again on the Mac. Apassy asks iCloud again every 30 seconds for a synced file that stays in iCloud, and a question that waits for you no longer stops sync. A run whose credential changed while it waited (your edit, or a sync from another Mac) is refused after your answer. The same request after such a change does not join the old question: that question ends and a new one shows, so your answer always covers the credential as it was when the question showed.
- On the iPhone, a vault in iCloud Drive syncs on its own while the app is open and unlocked. Changes from the Mac show without "Sync now", and a push of an iPhone change that failed is tried again.

### Security

- The bouncer never counts `printenv`, `echo $NAME`, an environment read of `jq` or `yq`, `/proc/PID/environ`, or `heroku config` as a read. An environment read of `jq` or `yq` and `/proc/PID/environ` raise the secret output flag, which always asks you.
- A database host on the command line that one of the credentials of the run does not know asks you.
- A `.git` file makes a folder part of a project only with a link back from its repository. A `.git` symlink is never followed.
- The iPhone app refuses third-party keyboards, which would see a pasted secret or a passphrase.

## [0.4.1] - 2026-10-12

One version, 0.4.1, for the Mac app, the iPhone app, and the browser extension. Signed and notarized Mac packaging, optimized iPhone packaging, and native Mac passkey registration and sign-in have passed. Newly created Mac passkeys are immediately available to sign in without an AutoFill refresh. Acceptance on a physical iPhone and of the browser extension from the Chrome Web Store is still open ([status and checks](docs/operations/passkeys-and-codes.md#1-status)).

### Upgrade notes

- Make an encrypted backup first. Then update every Mac and iPhone that shares the vault through a folder, iCloud Drive, or the relay.
- The new apps migrate schema 16 to schema 17 when you unlock the vault. Older apps cannot open or sync the upgraded vault.

### Added

- An agent that can see credentials can ask for process access at its first use ([ADR 0024](docs/adr/0024-access-at-first-use.md)). The owner sees the folder, effective secret delivery, and declaration, then chooses "Allow once" or access in that folder and its subfolders. Production credentials still ask at each run.

- The iPhone app adds the free personal iCloud Drive sync path beside team relay sync. It opens the Mac's encrypted `.apassy` file, keeps an offline local vault, and merges changes in both directions through coordinated snapshots. Sync settings identify the source and can restore file access. Companion approval pairing remains separate.

- The Apassy app for the iPhone holds your vault, like a second Mac ([ADR 0023](docs/adr/0023-iphone-vault.md)). Add the iPhone with "Add a device…" on the Mac: scan the QR code, compare the two safety words, confirm on the Mac with Touch ID, and type the passphrase on the iPhone. The vault syncs both ways through the Apassy relay. The app has Home (favorites, recently changed, kinds), Items, Search, item details, new and edited items, the password generator (random, memorable, PIN), Watchtower (weak, reused, and old passwords, conflict copies), Face ID unlock, auto-lock, and Settings. Each reveal, copy, one-time code, or large type of a secret needs Face ID or the passphrase; a copy stays on the iPhone and expires after 60 seconds. Password AutoFill fills logins and one-time codes in Safari and apps after Face ID. The companion of ADR 0020 is the Approvals tab. The app is in TestFlight.
- The vault core of the iPhone app (`ios/ApassyCore`) runs the same vault and relay sync code as the Mac (contract `docs/contracts/ios-core-v1.md`). `scripts/build-ios-core.sh` builds it, and `scripts/ios-testflight.sh` archives and uploads the app.
- Passkeys (WebAuthn, ES256) and one-time codes (RFC 6238 TOTP) in the vault, the iPhone core, the Mac app, and the browser extension. Acceptance on a physical iPhone and with the store build of the extension is open ([guide](docs/operations/passkeys-and-codes.md), [iPhone core contract](docs/contracts/ios-core-v1.md)).
  - A login can hold one passkey. The iPhone core has the calls `passkey_list`, `passkey_assert`, `passkey_register`, `passkey_import`, and `passkey_remove`. Sign-in and registration need a fresh owner check. The key never appears in an item, a reveal, a list, or an agent read.
  - Codes accept SHA-1, SHA-256, and SHA-512, 6 to 8 digits, and a period of 15 to 120 seconds. HOTP and Steam codes are not supported. A field with a custom title counts as a code when its value is an `otpauth://totp` link.
  - The iPhone AutoFill suggests passkeys and codes beside passwords. A login that has only a passkey offers no password.
  - Credential Exchange on iOS 26 moves logins, TOTP, and ES256 passkeys to and from other apps. Each import and export needs its own owner check. A paused export continues only in the vault where it started. The history says "prepared", which does not prove that the other app finished.
  - The Mac item page shows the passkey without its key and offers "Remove passkey". The browser extension can sign in with a passkey and fill a code after a separate permission. The browser guard verifies Helium and Google Chrome stable. It refuses extension-loader and remote-debugging switches. Acceptance with the signed app in a normal browser is open.
  - `docs/operations/passkeys-and-codes.md` has an acceptance checklist that keeps local tests, signed builds, and real devices apart.

### Changed

- "Add a Mac…" in Settings > General > Sync is "Add a device…". It shows the device link as a QR code for the iPhone, and as text for another Mac.
- The vault schema is 17 (it was 16). Update every Mac and iPhone that shares a vault. A build of schema 17 migrates a vault of schema 16 and reads a copy of schema 16. A build of schema 16 cannot open a vault of schema 17 or read a copy of it. Make a backup before you upgrade. Local tests cover schema 17 uploads over a copy of schema 16 on the relay, in the iCloud core, and in a folder. Device acceptance remains open.
- A login with a passkey needs no password. Removing the passkey keeps the login only when it has a non-empty password. Otherwise it deletes the whole login, and the screen says so first.
- A Mac build without both provisioning profiles has no AutoFill extension. With both valid profiles and `APASSY_REQUIRE_PROVIDER=1`, the build script can include passwords, codes, and passkeys. The signed Mac CI build of source `82c641d` passed its provider tests and notarization. Native Helium registration and sign-in passed with the same provider in an isolated signed test app.
- The Mac editor hides a visible detail that has an OTP label or looks like a setup key, also when you save it without a change.

### Fixed

- Passkey registration and sign-in set both backup flags required by Apple's credential provider API. The Mac provider validates the attestation data and required flags before returning a credential to macOS. These flags do not confirm that a backup of the vault exists.

### Security

- Automatic process bindings refuse OTP setup-key labels and `otpauth://totp` values. An owner can explicitly bind a setup key after the field-specific warning and check.
- First-use access cannot be saved for the filesystem root, HOME, its ancestors, or their filesystem aliases. These folders offer "Allow once" only. Displayed paths remove invisible format characters, and the Touch ID consent fits the native prompt limit.
- A passkey key stays in the encrypted vault. Generic reads, item details, and agent reads do not return it. Only the owner-approved Credential Exchange export returns it, straight to the system.
- Each passkey sign-in, registration, import, removal, and export asks for a fresh owner check. The seed of a one-time code never appears in a row, a list, an identity, or an error.
- The agent catalog hides legacy visible TOTP setup keys, and the decision log masks their stored values. An explicit setup-key variable grant names the field and warns that programs can make codes. Its owner proof names the field, variable, delivery mode, and setup-key status. Automatic batch binding refuses setup keys.
- The iPhone core writes each answer into one buffer of exact size and erases it when it is freed. A serializer that changes size gives an error and no grown copy of a secret.

## [0.3.6] - 2026-10-09

### Changed

- The credential header keeps Back, the name, and Edit visible when the page scrolls. Each credential keeps its own scroll position.
- Field labels are above dark monospaced values. Long secret values have a separate scroll area after the owner confirms Show.
- Agent access, History and requests, More actions, and 1Password import data open on demand.
- The agent token page offers host connection first. Advanced setup shows the token and manual configuration.
- The browser extension is in the Chrome Web Store: <https://chromewebstore.google.com/detail/apassy/bbnpgnjnfjlbgggmpnhejpmfjhmmhiih>. "Connect" in Settings > General > Browser extension opens its page in the browser, so the install is "Add to Chrome" in place of Developer mode. `apassy setup browser` and the site point there too. Settings no longer shows the extension folder: the folder in Apassy.app still works with Developer mode, and `apassy setup browser` prints its path.

### Security

- Updated the website build dependencies. The dependency audit reports no known vulnerabilities.

## [0.3.5] - 2026-10-09

### Added

- A browser extension for Helium, Chrome, Chromium, Brave, Edge, Arc, and Vivaldi. It fills the username and the password of a login on its website. Each fill asks for Touch ID or the passphrase in Apassy. Agents never get the password ([ADR 0021](docs/adr/0021-browser-extension.md), [browser](docs/operations/browser.md)).
- "Save this login" in the extension saves the login that you typed on a page, after Touch ID or the passphrase.
- "New password" in the extension makes a login with a new password from Apassy and fills it into a sign-up form. The password is in the vault before the page gets it, and never on the pasteboard.
- Settings > General > Browser extension connects a browser with one click: it writes the host manifest, opens the extensions page, and shows the extension folder. `apassy setup browser` does the same from a terminal.
- Logins have a Website field. The 1Password import puts the first address of a login there.
- The item history shows each fill in the browser, with the site.

### Security

- The agent profile denies a write to every `NativeMessagingHosts` folder. A browser starts the program of such a manifest outside the sandbox, so a planted manifest could replace the host of an installed extension.
- The agent profile denies a change of `Preferences`, `Secure Preferences`, and `Local State` of the Chromium browsers, and a new or renamed profile folder, so an agent cannot point an installed extension at its own code.

### Changed

- CI runs test groups and release builds in parallel. Release uses the verified binaries from the same successful CI run.

## [0.3.4] - 2026-10-07

Vault sync through the Apassy relay, a background sync worker, bouncer start modes in Settings, and fixes in the window and the owner command line.

### Added

- Settings > Agents > Broker and bouncer can start the local model: with Apassy, when a run needs it (it stops after 10, 30, or 60 idle minutes), managed outside Apassy (the default), or off. It shows the state, the model version, and what is missing, with "Start now", "Stop", and "Open log". The setting is `bouncer.json` in the data folder.
- Settings > Agents > Broker and bouncer has "Install the model" while the Laya environment is missing. It runs the `uv` commands of the bouncer guide on a background thread, shows the step, can stop, and writes `~/Library/Logs/Apassy/bouncer-install.log`. Without `uv` it says "Install uv first: brew install uv".
- "Install the model" also downloads the pinned Laya base weights ("Downloading the model weights", `tools/basemodel/fetch_weights.py`); without them a first start says "Starting (downloading the model weights, first start only)" and a run waits up to 45 seconds, then waits for you with the reason. A failed weights download keeps the installed environment, starts the server in "With Apassy", and offers the download again; the Python steps write no `__pycache__` into the app bundle. "Start now" is hidden while a start would fail, and `apassy decisions export` lines have an optional `model_version`.
- Settings shows a note with the remove commands for a LaunchAgent that runs `tools/basemodel/start.sh` with a missing `APASSY_BASE_MODEL`, or while Apassy starts the model itself. Apassy does not change the LaunchAgent.
- `scripts/build-app.sh` without `APASSY_BASE_MODEL` ships the checkpoint in `$APASSY_LAYA_DIR/models` when it exists and matches the manifest, and prints which model it ships. A checkpoint that does not match gives a warning and an app without a model, so `scripts/install.sh` does not fail. GitHub Actions does not use this checkpoint.
- Vault sync through the Apassy relay, stage 1. In Settings > General > Sync, the menu of a vault has "Apassy relay" after the detected folders. Its sheet takes the relay address, the team code from the operator, and the name of this Mac, or a link from another Mac for a vault that is on the relay already. A vault on the relay has "Add a Mac…" (a link that works once for 10 minutes, the same two safety words on both Macs, and Confirm behind Touch ID or the passphrase), "Devices…" (list and remove), and "Sync now", and statuses such as "Saved to the relay." and "Relay not reachable. Apassy syncs when it is back." "Use a vault from another Mac" has the source "Apassy relay": paste the link, compare the words, then type the passphrase. Turning relay sync off keeps the copy on the relay; the last Mac can also delete it. Every relay call that you start runs in the background, so the window stays responsive and shows what runs. "Cancel" or a quit on a Mac that joins cancels its link on the relay. Picking a folder for a relay vault asks first, and this Mac leaves the relay team; the message says what stays on the relay. A damaged relay copy has "Replace with this Mac's vault…", behind a sheet. Settings shows "Received by <Mac>" from the receipts that the other Macs send. A relay copy that this Mac refuses (an older copy after the relay came back from a backup, or a history without this Mac's last change) has "Use the relay copy…", which merges it and keeps the device, also for the last Mac of a team; a copy under another passphrase then asks for that passphrase only to open the copy: the vault keeps the passphrase of this Mac, and the merged vault goes up under it. A failed pull is tried again 5 seconds later, then 10, 20, 40, and 60. A lock, "Turn off", and a quit end every relay call at once, also while it connects. The window does not wait for a relay call, except at a lock with a change that waits: the push before the lock waits at most 10 seconds. "Turn off" needs the vault unlocked, since the key of this Mac for the relay is in the vault. A folder sync stays on until relay sync is on. See `docs/operations/sync.md`, section 17, [ADR 0022](docs/adr/0022-relay-sync.md) (accepted for stage 1), and the wire contract `docs/contracts/relay-sync-v1.md`.
- `apassy completions zsh|bash|fish` prints a shell completion script for the commands, subcommands, and main options. It is made from the tables of `apassy help`. Where no subcommand fits, as for the file of `apassy import`, the shell completes file names.
- `apassy import FILE --bind` binds the variables of the added credentials with one owner check: the key of a `.env` line, or a 1Password or Bitwarden title that is a variable name already. The window lists each credential and its variable with the count, and Touch ID names the count. Invalid names, names that another credential uses, and credentials without a secret value are refused, and a line under the table says why for each credential. With `--json`, the answer is one document, also when a variable is not bound. A cancel binds nothing. Without `--bind`, nothing changes.

### Changed

- Vault schema 16 adds the local table `relay_device` (the key of this Mac for the relay). It is never part of a sync copy. A vault that 0.3.3 opened no longer opens in 0.3.2. See Upgrade notes.
- Folder sync runs on a background thread. It merges and pushes also while the window is hidden, minimized, or covered.
- Settings has five tabs: General, Security, Agents, Notifications, and About.
- The sidebar shows the open vault with its sync state and a lock button, the shortcuts on hover, and expired agent tokens. ⌃⌘S hides it.
- Credentials of a new vault show "Get started", the steps to the first agent request.
- The page column keeps its reading width in a wide window, and lists show relative times.
- The app remembers a hidden sidebar and "Hide" of the Get started list (per vault) across restarts, in `ui.json` in the data folder.
- Relay sync: "Remove" in "Devices…" asks first ("Remove <Mac> from the relay?"), and Cancel is the default for the keyboard.
- Relay sync: after Confirm, "Add a Mac…" shows only the result and "Done", not the used link.
- Relay sync: the team code field is masked, and its text goes after each try.
- Relay sync: "Join from another Mac" for a vault whose relay copy has another passphrase asks for the passphrase of the copy, and the vault takes it, as on your other Macs; the step stays on the screen while the merge runs.

### Fixed

- Return on the Create screen moves to the next field instead of to "Back".
- A path typed in "Use a vault from another Mac" is picked when it is complete, not after the first character.
- The first text field of a new sheet takes the focus after a click.
- Relay sync: a Mac that another Mac removed shows "Removed from the relay" at once and signs in to the relay only once every 15 minutes, so it syncs again by itself after the relay was suspended; to sync again after a removal, turn relay sync off, then join again with a link from another Mac.
- Relay sync: "Turn off" on a Mac that the relay refused asks the relay to remove its device instead of trusting the earlier refusal.
- Relay sync: a failed sign-in token no longer shows "Removed from the relay".
- Relay sync: "Devices…" shows a current "last seen" for each Mac that syncs (the relay writes it at most once a minute per device).
- Return or Space in a destructive alert that was opened with the pointer pressed its destructive button: Delete, Revoke, Reset pairing, Discard, and Remove or Turn off for the relay. They press Cancel (Keep editing in Discard changes) now, as in an alert opened with the keyboard.
- A quick click on "Confirm…" (press and release in one frame, as a tap on a trackpad) could open the owner check behind "Add a Mac…": the window dimmed, the typed passphrase went nowhere, and Return closed the check with "Type the passphrase.". A sheet that opens over another sheet is now on top.
- "Confirm" with an empty passphrase field in an owner check closed the check, and the action that waited for it was lost. The check now stays open and says "Type the passphrase.", as after a wrong passphrase.
- Relay sync: a Mac that another Mac removed still showed "Sync now", "Add a Mac…", and "Devices…", and their sheets offered "Check again", "New link", and "Refresh", which all failed at once. Settings now shows only the sync menu for that vault, with the line that says to turn relay sync off, and the sheets show why without those buttons.
- In "Use a vault from another Mac", a click on a file did not give the focus to the passphrase field, and a click on "Apassy relay" did not give it to the link field, so the owner had to click the field first. egui gave the focus up at that click; the field now takes it in the next frame.
- The demo build without the vault feature (`cargo check --features desktop --bin apassy`) compiles again, and CI checks it.

### Security

- A run that names a host session no longer takes the hook prompt of another session without a flag. Such a prompt now has `hook_ambiguous`, so the owner decides.
- Relay edge: the Worker refuses a request body with a malformed or too large declared length before the relay reads it (400 `invalid_request`, 413 `payload_too_large`; snapshot pushes up to 64 MiB, the agent proxy up to 8 MiB, every other route up to 128 KiB), and limits snapshot pushes to 60 a minute per IP address. This needs a Worker deploy (see `docs/operations/release.md`, "Relay first").

### Upgrade notes

- **Vault schema 16.** The first unlock in 0.3.3 migrates the vault, and 0.3.2 refuses it afterwards (`verify_user_version` in `src/vault/mod.rs`). Back up the vault before the first unlock if you may go back. Macs that sync one vault through a folder or through the relay must all update: a merge needs the same schema on both sides (`src/vault/merge.rs`, the check of an attached copy), so a Mac on 0.3.2 refuses a copy that a 0.3.3 Mac wrote, and the reverse.
- **Relay sync needs a relay with SPEC section 24 deployed** (schema 4 team files, the sync endpoints, and the Worker of the same release). The first start of that relay migrates each team file and keeps `teams/<id>.db.pre-v4`; an older relay image cannot open them. Deploy the relay before you publish the app: `docs/operations/release.md`, "Relay first".

## [0.3.2] - 2026-10-05

Clearer setup on a second Mac, sync recovery, and complete command-line tools in the app bundle.

### Added

- A guided flow to find and open an existing vault from iCloud Drive or another sync folder.
- Setup choices for Claude Code, Codex, and the CLI after a synced vault opens. Agents and grants stay local to each Mac.
- A persistent conflict review with links between retained copies and the current credential.
- Native file panels for vault, import, backup, and sync paths.
- The iPhone companion source, with QR pairing, device removal, and owner approval for runs. Its listener is off by default. Device trust stays local to each Mac.
- Source files for the promotional videos.
- Design records for the local bouncer, shared-vault relay, and relay accounts.

### Fixed

- A wrong vault passphrase preserves the selected file and returns focus to the passphrase field.
- Anonymous cloud snapshots use private file permissions on macOS and Linux.
- Cloud folder checks have bounded waits. Retry detects newly available folders and preserves the selected file.
- Sync status distinguishes a local folder write from receipt on another Mac.
- CLI setup distinguishes configuration from a verified connection. The tool installer checks executable files.
- The app bundle includes `apassy-hook`, `apassy-sandbox`, and the agent profile. Build checks verify those files.
- Keyboard actions, edit cancellation, CLI help, and error output are clearer.

### Changed

- Vault schema 15 adds local companion settings, certificates, and paired devices. Migration keeps schemas 13 and 14. A restore or adoption clears device trust.
- Updated site build dependencies. The dependency audit reports no known vulnerabilities.

### Release status

- This release publishes source code. A signed and notarized download still requires the Apple and Cloudflare release credentials.

## [0.3.1] - 2026-10-01

The owner command line, keyboard use, and the install from source.

### Added

- **Install from source with one command.** `/bin/bash -c "$(curl -fsSL https://apassy.wyderka.cc/install.sh)"` checks the Mac, clones the newest release, builds, signs, and checks it with `scripts/build-app.sh`, and installs it in Applications. It asks before it replaces an app and never uses sudo; `--check` only checks the Mac. On the site, "Coming soon for macOS" opens a note with the command until the signed download is published ([`scripts/install.sh`](scripts/install.sh)).
- **Owner command line.** `apassy` with a command talks to the running window over a new owner socket: credentials (list, show, add, edit, archive, delete, history, agent settings), import of `.env` files and of 1Password and Bitwarden CSV exports, agents (register, rotate, revoke, see all, token lifetime), grants and rules, access requests, runs that wait, remembered patterns, activity, the decision export, backup, and the passphrase change. `apassy login` opens a session after Touch ID or the passphrase in the window; it ends after 30 idle minutes, at a lock, and when another vault opens. Every grant, approval, token, and agent setting still asks for its own owner check in the window, which says that the command line asked. The command line never shows a secret value, never takes one as an argument, and never unlocks or restores ([command line](docs/operations/cli.md), [ADR 0017](docs/adr/0017-owner-command-line.md), [wire](docs/contracts/owner-cli-v1.md)).
- **`apassy setup claude|codex`.** Registers an agent and writes the MCP server and the prompt hook. The token is in two wrapper scripts with mode 0700, not in a host file.
- **`apassy doctor`.** Checks the window, the vault, the broker, the session, the programs, the data directory, and the agent hosts, with a fix for each problem.
- **Settings > Command line.** The owner socket and the open sessions, with "End all sessions".
- **Keyboard use.** The focus follows the owner: a sheet takes the focus when it opens and gives it back when it closes; a destructive alert starts on Cancel; the page scrolls to the focused control; after a navigation or a control that goes away, the first control of the page takes the focus. Return does the default action of a sheet. New shortcuts: ⌘1 to ⌘4 and ⌘, for the views, ⌘[ for back, ⌘L to lock, Page Up, Page Down, Home, and End to scroll, and Esc to close an error message. A menu choice with the keyboard closes the menu. The arrows of a segmented picker no longer move the focus. The focus ring is 2 points of solid accent on every control. VoiceOver gets a name for every icon-only button, row, tag, picker, and custom detail field.

### Fixed

- A copy without a Developer ID signature, such as a build from source, no longer downloads new versions every 6 hours only to refuse them. It shows the version and the download page, and the installer updates it ([updates](docs/operations/updates.md)).

### Security

- **The agent profile denies the Unix sockets of the data directory.** The file rule did not stop a `connect()` to a socket there. Now only the broker socket is open to agents, and the owner socket is closed. `apassy-sandbox` removes `APASSY_SESSION` from the agent environment.

## [0.3.0] - 2026-09-28

Several vaults, sync between your Macs, import from 1Password, and automatic updates.

### Added

- **Several vaults.** Each vault is its own encrypted file with its own passphrase, credentials, agents, rules, and learning data. One vault is open at a time, and agents reach only the open vault. The name of the open vault at the top of the sidebar switches to another vault. A switch locks the open vault and ends each run that waits for you. Settings > Vaults renames a vault or removes it from the list; the file stays ([several vaults](docs/operations/multiple-vaults.md), [ADR 0013](docs/adr/0013-multiple-vaults.md)).
- **Sync through a folder.** As with an Obsidian vault, a vault can sync through iCloud Drive or through any folder that Dropbox, Google Drive, OneDrive, or Syncthing keeps in step. Settings > Vaults > Sync, or the Create screen, turns it on; it is off by default. Your other Macs add the vault with "Open a synced vault…".
  - Changes merge one credential at a time, after each unlock, every 30 seconds, a few seconds after a change, and before each lock and quit. You type no passphrase for it.
  - When the same credential changed on two Macs, the newer version wins, and the other stays as an archived conflict copy. An old copy changes nothing.
  - The credentials and their settings sync. Agents, tokens, grants, rules, activity, and learning data stay on each Mac and are never in the synced file: each Mac registers its own agents.
  - The vault that Apassy works on stays a local file, and SQLite never writes in the synced folder. The synced file is encrypted with the vault passphrase ([sync](docs/operations/sync.md), [ADR 0014](docs/adr/0014-icloud-sync.md)).
- **Import from 1Password.** Settings > Import reads a 1PUX or CSV export and shows each item before anything is added. API credentials, SSH keys, databases, and servers are selected first; logins, passwords, and notes are not. A secret never goes into a title, notes, or tags. No agent gets access to an imported credential. After the import, Apassy offers to delete the export file ([import from 1Password](docs/operations/import-1password.md)).
- **Rule pack validator.** `apassy-packs validate` loads a rule pack or a provider file as the broker does, and names the reason when it does not load. JSON Schemas in `packs/schema/` describe both formats, and CI checks each file with both ([rule packs](docs/operations/rule-packs.md), [CONTRIBUTING.md](CONTRIBUTING.md)).
- **Licenses and policies.** The code and the documents are Apache-2.0. The rule packs, the provider files, and their schemas are CC0-1.0. [SECURITY.md](SECURITY.md) says how to report a vulnerability.
- **Automatic updates.** The app checks for a new version shortly after the start and every 6 hours, downloads it, and installs it at "Restart now" or at the next quit. Only a higher version number updates the app: another build of the same version does not. It installs only an app with the size and SHA-256 of `latest.json`, signed with a Developer ID of the same team, and notarized by Apple. Settings > Updates turns the check and the automatic install off ([updates](docs/operations/updates.md), [ADR 0015](docs/adr/0015-automatic-updates.md)).

### Changed

- The vault schema is version 14: a vault ID, and an ID, a change count, and deletion marks for each synced record. A vault of an earlier version migrates at unlock.
- `apassy-sandbox` denies agents each vault in the vault list, the iCloud Drive folder of Apassy, the synced file of each vault in another folder, and the list itself. It refuses to start when the vault list is damaged, because a damaged list can hide a vault outside the data folder.
- An agent with a token of another vault gets a message that says the owner may have another vault open. The message names no vault.
- The result of a run, a connector call, and a local training goes only to the vault where it started, also when you switch vaults during it.
- An edit of a credential keeps its tags.
- Release builds record their commit and build time in the program and in `Info.plist`.

### Security

- The updater checks the new app again just before it replaces the installed app, and puts the old app back when the replacement fails.
- A synced copy is read only as a local copy, and it must pass the checks of a restore and a content digest before it merges. So a copy made of pages from different versions is refused.

## [0.2.1] - 2026-09-28

Apassy builds and passes its tests on Linux. The app for Linux is not published yet: the isolation of agents uses macOS Seatbelt, and Linux needs its own version first.

### Added

- **Linux build.** Apassy, the broker, the run proxy, and the desktop app build on Linux, and the tests pass there. On Linux, the files of Apassy are in `$XDG_DATA_HOME/apassy`, or `~/.local/share/apassy`. On macOS, they stay in `~/Library/Application Support/Apassy`.
- **Linux in CI.** CI runs Clippy, the tests, and the doc tests on Linux too.

### Changed

- On Linux, `apassy-sandbox` says that it runs only on macOS. The Seatbelt tests and the tests of the Swift helpers run only on macOS.
- The run proxy test uses Node only when it reads `HTTPS_PROXY`. Node before 22.21 ignores it and connects directly.
- CI runs once for each update of a pull request and once for each push to `main`, not for each push to another branch or a tag. A newer push to a pull request cancels its older run. A change only in `site/` or `design/` runs no CI.

## [0.2.0] - 2026-09-28

The first public release: a signed app for macOS, a website, and everything since the alpha.

### Added

- **Download.** A signed and notarized `Apassy.dmg` at [apassy.wyderka.cc](https://apassy.wyderka.cc). Each push to `main` that passes CI publishes a new build ([release](docs/operations/release.md)).
- **App icon.** The Apassy mark in the Dock, on notifications, and on the Touch ID prompt.
- **New desktop interface.** A sidebar with Credentials, Agents, Activity, Learning, and Settings. Each credential has a history and can be archived ([ADR 0011](docs/adr/0011-run-proxy-placeholders.md)).
- **Placeholders.** A variable can hold a placeholder instead of the value. The run then goes through a proxy of Apassy, which puts the real value into HTTPS requests to the hosts of that credential only. On macOS, the process can connect only to that proxy ([ADR 0011](docs/adr/0011-run-proxy-placeholders.md)).
- **Access requests.** An agent can see the names of all credentials, without values, and ask you for access. One grant can cover several credentials, in one folder or in any folder ([ADR 0012](docs/adr/0012-agent-visibility-and-access-requests.md)).
- **Base model.** The bouncer uses `apassy-base-v1`, a local Laya model with decision heads trained on synthetic commands. It starts at login ([base model](docs/operations/base-model.md)).
- **Learning.** A decision log, "Approve and remember" patterns, threshold calibration, and a Learning view with the ask rate of the last 14 days. A local fine-tune runs in shadow mode before it can replace the model ([learning](docs/operations/learning.md)).
- **Rule packs.** 64 packs describe tools as data: migrations and ORMs, clouds and platforms, databases, containers, Kubernetes, Terraform, and secret managers. A local pack can only add restrictions ([rule packs](docs/operations/rule-packs.md)).
- **Declarations.** Each credential can say its project, environment, risk, scope, and whether its actions can be undone. Apassy suggests a declaration and knows the hosts of common providers ([declarations](docs/operations/declarations.md)).
- **Host hooks.** `apassy-hook` gives the bouncer the real request of the user in Claude Code and Codex, and checks it against the transcript ([host hooks](docs/operations/host-hooks.md)).
- **Owner checks and notifications.** Each owner action needs a fresh Touch ID or passphrase check. Notifications come from `ApassyNotify.app`, and the inbox keeps each event ([native app](docs/operations/native-app.md), [notifications](docs/operations/notifications.md)).
- **Agent isolation.** `apassy-sandbox` starts Claude Code and Codex in a Seatbelt profile. The profile denies the vault, the backups, the model, the app bundle, and the ways to start a program outside the sandbox ([isolation](docs/operations/isolation.md)).
- **Vault lifecycle.** Passphrase change, agent token expiry and rotation, a settings review after a restore, and migration from each earlier schema.

### Changed

- A run with a production credential always waits for you.
- The bouncer policy is v7. On the blind held-out set v4 (226 cases, 3 runs), no violation and no critical case ran without the owner, and 91 of 120 normal cases (76%) ran without a prompt ([held-out v4](docs/evaluation/heldout-v4.md)).

### Security

- Key memory hardening: secrets and tokens are zeroized, SQLCipher memory security is on, core dumps are off, and each program has the hardened runtime without debug or injection entitlements ([key-memory review](docs/reviews/key-memory.md)).
- rustls 0.23.45 for RUSTSEC-2026-0285, and `cargo audit` in CI.

## [0.1.0] - 2026-09-25

The alpha. It was not published.

### Added

- The Rust foundation and an encrypted vault: one SQLCipher file with a master passphrase ([ADR 0003](docs/adr/0003-passphrase-vault.md)).
- The owner views of the desktop app.
- The agent path: a local broker, the MCP adapter `apassy-mcp`, and connectors over HTTPS ([ADR 0004](docs/adr/0004-agent-path-first.md), [ADR 0005](docs/adr/0005-connector-tls.md)).
- Secrets for agent processes with owner approval: the socket never returns a secret value ([ADR 0006](docs/adr/0006-process-secrets.md)).
- Plain-language rules and a local bouncer on Laya ([ADR 0007](docs/adr/0007-rules-and-local-bouncer.md)).

[Unreleased]: https://github.com/wydrox/apassy/compare/v0.5.14...HEAD
[0.5.14]: https://github.com/wydrox/apassy/compare/v0.5.13...v0.5.14
[0.5.13]: https://github.com/wydrox/apassy/compare/v0.5.12...v0.5.13
[0.5.12]: https://github.com/wydrox/apassy/compare/v0.5.11...v0.5.12
[0.5.0]: https://github.com/wydrox/apassy/releases/tag/v0.5.0
[0.4.1]: https://github.com/wydrox/apassy/releases/tag/v0.4.1
[0.3.6]: https://github.com/wydrox/apassy/releases/tag/v0.3.6
[0.3.5]: https://github.com/wydrox/apassy/releases/tag/v0.3.5
[0.3.4]: https://github.com/wydrox/apassy/releases/tag/v0.3.4
[0.3.2]: https://github.com/wydrox/apassy/releases/tag/0.3.2
[0.3.1]: https://github.com/wydrox/apassy/releases/tag/v0.3.1
[0.3.0]: https://github.com/wydrox/apassy/releases/tag/v0.3.0
[0.2.1]: https://github.com/wydrox/apassy/releases/tag/v0.2.1
[0.2.0]: https://github.com/wydrox/apassy/releases/tag/v0.2.0
[0.1.0]: https://github.com/wydrox/apassy/commits/a2f860a
