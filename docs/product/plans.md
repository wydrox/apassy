# Apassy plans

Date: 2026-11-03.
Status: accepted by the owner on 2026-11-03: three Connect plans, the size of Connect Family, free relay sync until Connect, and this page as the one source. Prices and the open decisions in section 6 are not decided.
Decisions: [ADR 0037](../adr/0037-own-relay-open-source.md) D2, D3, D7, D8, D14; [ADR 0035](../adr/0035-bouncer-hosting-and-training-choice.md) (bouncer brain hosting).

This page replaces the plan split of 2026-10-13: Free = iCloud and approvals through the relay, Personal (paid) = relay sync, Team (paid) = shared vaults. Relay sync and shared vaults are not what Apassy sells. Apassy sells the hosted service, Apassy Connect.

## 1. The rule

- Everything is free when you host it yourself. The code is open source (Apache-2.0).
- Paid: only **Apassy Connect**, the hosted service of the Apassy project, and support.
- Each function of Connect can also be self-hosted, for cost or for security.
- No Apassy-run server holds a key that opens a credential, a vault, a question, or an answer (ADR 0037 section 1). The hosted bouncer brain is the one Connect service that reads content: the command and the task that it judges, never a credential value. It is opt-in, with a consent screen (ADR 0035).

## 2. Free

| Function | How |
| --- | --- |
| The apps: Mac, iPhone, Apple Watch, browser extension, Linux CLI | Download, or build from source |
| Vaults, the bouncer gate, and the bouncer brain on your own hardware | On each Mac, or on a server of yours (ADR 0035) |
| Sync of your own devices | iCloud Drive or another sync folder. Later: your own node as the sync home (ADR 0037 stage 4). |
| iPhone and Apple Watch approvals away from the Mac | Over your tailnet or LAN to your own Mac node (ADR 0037 stage 2) |
| A shared vault for a family or a team | On your own team host node (ADR 0037 stage 4), or a synced file in a shared folder ([sync](../operations/sync.md) section 11) |
| Agents on other machines and in the cloud | Linked environments and the Funnel route to your own node (ADR 0037 stage 5) |
| Push notifications to the iPhone | The push gateway of the Apassy project, free for everyone, self-hosters included (D7). Push is not a paid feature. |

## 3. Apassy Connect (paid)

Connect is optional. It is for users who do not want to run a node that is always on, or who cannot use Tailscale (for example because of a work VPN on the iPhone).

| Function | What Connect sees |
| --- | --- |
| Reachability without Tailscale: a byte relay with TLS end to end between your devices | TLS records, sizes, times |
| An always-on sync home: a blind store for the encrypted vault copy | Ciphertext, sizes, times |
| The hosted bouncer brain and its training (opt-in, ADR 0035) | The command and the task of each question to the brain |
| Support | What you send |
| Later, enterprise track: the confidential team host in a TEE (ADR 0037 E1, E2) | Separate ADR |

Connect never does the way B swap on an Apassy server and never holds a team key, until the enterprise track E2.

### The three plans

| Plan | For | Billing | Adds |
| --- | --- | --- | --- |
| Connect Personal | One person and all of their devices | Per month | The Connect functions for one person |
| Connect Family | 4 people. Each further person costs extra. | One price per month for 4 people, plus a price per month for each further person | The Connect functions for each person, and shared family vaults in the blind sync store. One organizer adds and removes members. |
| Connect Team | A company or a group | Per member per month | The Connect functions for each member, roles, member management, and billing per seat. Later: the enterprise track. |

- Prices: not decided. Set them before stage 7, from the measured cost of each function. The hosted bouncer brain costs the most ([implementation plan 0035](../design/implementation-plan-0035.md), measured on `devbox-x86`).
- Account: the Connect account of ADR 0037 D3 and ADR 0035 decision 6. An account sign-in never adds a device. A new device is confirmed on an existing one with the safety words and Touch ID.
- Purchase: on the Mac, through a web checkout (Stripe) that returns to the app. The iPhone shows the plan only. There is no In-App Purchase. (Carried over from 2026-10-13.)
- Stripe today has the products of the old split: Personal (EUR 1 a month) and Team (EUR 2 a member a month), in the sandbox and the live account. Renaming them to Connect Personal and Connect Team, and adding Connect Family, changes the Stripe account: do it only with the owner's confirmation, before stage 7.

## 4. Until Connect exists

| What | Now | Ends |
| --- | --- | --- |
| Relay sync on the hosted relay (`apassy-relay.wyderka.cc`) | Free for everyone until stage 7 (owner decision, 2026-11-03). Today it still needs a team code from the operator (ADR 0022); the path without a code is in section 4.1. | Stage 7 makes the hosted store part of paid Connect. The apps say so two releases before, as for D14, and offer an own sync home (stage 4, free) or Connect. "Delete the copy on the relay" exists. |
| Approvals without a code (questions-only Connect, ADR 0032) | Free | Stage 7. The apps say so two releases before (D14) and offer Tailscale (free) or Connect. |
| Shared team vaults and way B on the hosted relay | Off since 0.5.14 (`410 team_vaults_retired`, D8) | A relay that you run yourself keeps them (`APASSY_RELAY_TEAM_VAULTS=1`). Stage 4 moves teams to their own host node. |
| Push | Free, through the hosted Worker | Stays free: it moves to the push gateway (D7) |

### 4.1 Relay sync without a code (to build)

1. Relay: a setting for the vault sync size of a new Connect team (today `TeamLimits::connect()` sets `sync_bytes` to 0, so a push gets `403 plan_required`). The hosted relay sets it above 0. Existing Connect teams get the same limit with `admin limits`. Check the Connect capacity limits (50 new teams a day, 100 in total) and the disk of the VPS against that size.
2. Mac app: "New relay copy" without a team code. Apassy makes a Connect team with the purpose `sync` and pushes the first copy. A vault that already has a Connect team for questions uses that team. The team code stays an option for a relay that needs one.
3. Text: the sheet says that relay sync is free until Apassy Connect starts. The notice two releases before stage 7 also covers relay sync.
4. One release of all six components. The relay goes first.

## 5. Rules for text in the apps, the site, and the docs

- Do not call relay sync or shared vaults the paid feature. The paid part is Apassy Connect.
- Do not say that the hosted relay is for teams. It no longer serves team vaults.
- Say "free" without a limit only for what is free when self-hosted. For the questions-only path of ADR 0032, do not promise that it stays free.
- Use the plan names Connect Personal, Connect Family, and Connect Team.

## 6. Open decisions

| # | Decision | Recommendation |
| --- | --- | --- |
| 1 | Prices of the three plans | Set before stage 7, from measured cost |
| 2 | Family: whether members have roles | One organizer, the others are equal members. (Decided 2026-11-03: 4 people, each further person costs extra.) |
| 3 | The vault sync size of a free Connect team (section 4.1) | Measure the vault sizes and the VPS disk first. (Decided 2026-11-03: relay sync is free for everyone until stage 7.) |

## 7. Follow-ups

- The relay guide (`crates/apassy-relay/docs/ONBOARDING.md`, served at `/guide`) describes a relay that you run yourself (2026-11-03). It goes live with the next Worker deploy.
- `docs/operations/relay.md` and the relay deployment notes describe Connect at stage 7 (ADR 0037, process changes).
