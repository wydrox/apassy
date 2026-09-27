# apassy

A credential manager for you and your agents.

Store passwords, API keys, SSH keys, database logins, and other credentials.
Write plain-language rules for who can use them, when, where, and for what purpose.
A bouncer checks agent requests, permits normal use, pauses uncertain requests, blocks forbidden use, and alerts you when needed.

## Status

Date: 2026-09-27. The goal and its definition of done are in [goal.md](docs/goal.md). The decisions are in [ADR 0010](docs/adr/0010-closing-open-decisions.md).

The real-secret gate is OPEN. The owner can use Apassy with real credentials. Start with [daily use](docs/operations/daily-use.md).

- Agent hosts (Claude Code and Codex) run in a Seatbelt profile. The profile denies the vault, the backups, the model, and the Apassy app bundle. See [isolation](docs/operations/isolation.md).
- Agents get secrets only from the broker, in the environment of one process. The socket never returns a secret value. See [ADR 0006](docs/adr/0006-process-secrets.md).
- A variable can hold a placeholder in place of the value. The run then goes through a proxy of Apassy, which puts the real value into HTTPS requests to the hosts of the variable only. On macOS the process can connect only to that proxy. See [ADR 0011](docs/adr/0011-run-proxy-placeholders.md).
- An agent can see all credentials without values, and ask for access to one. A grant covers several credentials at once, in one folder or in any folder. See [ADR 0012](docs/adr/0012-agent-visibility-and-access-requests.md).
- The vault is one SQLCipher file with a master passphrase. See [vault verification](docs/operations/vault-verification.md) and the [storage review](docs/reviews/storage-dependencies.md).
- A local bouncer (rule packs and the Apassy base model on Laya) permits normal work, asks the owner about uncertain work, and learns from the owner's decisions. A production run always waits for the owner. See [bouncer](docs/operations/bouncer.md) and [learning](docs/operations/learning.md).
- On the blind held-out set v4, the bouncer ran no violation and no critical case without the owner. It ran 76% of normal cases without a prompt on the first day. See [held-out v4](docs/evaluation/heldout-v4.md).

Open items:

- N1: the owner allows notifications once, and a real banner is timed. Until then, the inbox in the app shows each event.
- B12: after two weeks of daily use, the owner is asked on 10% or fewer of the runs.
- A3 (Touch ID unlock) is paused by the owner. The passphrase is the only unlock.

Known limits are in ADR 0006, [isolation](docs/operations/isolation.md) sections 4 and 7, and the [key-memory review](docs/reviews/key-memory.md).

## Run the desktop demo

Run `cargo run --locked --features desktop,vault --bin apassy` for the owner vault file.
The start screen creates, opens, or restores an encrypted vault file. See [desktop UI](docs/operations/desktop-ui.md). For real credentials, use the signed app from [daily use](docs/operations/daily-use.md).
Run `cargo run --locked --features desktop --bin apassy` for the older in-memory demo. “Open vault” there is not owner authentication.
Run `cargo run --locked --features desktop,vault --bin apassy -- --smoke-test` for a model check without a window.
See [desktop development](docs/operations/desktop-development.md), [Rust contracts](docs/contracts/rust-v1.md), and [development checks](docs/operations/checks.md).

## Try the synthetic walkthrough

Run `python3 -m http.server 8765 --bind 127.0.0.1 --directory design/walkthrough`.
Open `http://127.0.0.1:8765/`. Use demo data only. Press Ctrl-C to stop the server.
This browser prototype is not the selected desktop app or an encrypted vault.
See [walkthrough instructions](design/walkthrough/README.md).

## Design

- [Product Vision v1](docs/product-vision-v1.md): the product, everyday use, and MVP scope.
- [Product concept](docs/concept.md): how credentials, plain-language rules, and the bouncer work together.
- [Product Infra v1](docs/product-infra-v1.md): the Rust architecture, trust boundaries, and open technical decisions.
- [MVP plan](docs/mvp-plan.md): implementation phases, scoped Grok tasks, and acceptance checks.
