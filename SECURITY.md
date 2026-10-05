# Security policy

Apassy holds credentials and decides what an agent may do with them. A weakness in it matters more than in most programs. Thank you for reporting one.

## Report a vulnerability

Use GitHub private vulnerability reporting: <https://github.com/wydrox/apassy/security/advisories/new>. Do not open a public issue, and do not describe the weakness in a pull request.

Put in the report:

- The version (Apassy > About, or the `version` in `CHANGELOG.md` of the build) and the macOS version.
- The steps, or a test. Use synthetic values only. Never send a real secret, a real vault, or a real agent token.
- What an attacker gains: a secret value, a run without the owner, a file outside the sandbox, and so on.

What happens next:

- You get an acknowledgement within 3 working days.
- You get an assessment within 14 days: in scope or not, severity, and a plan.
- A fix ships in the next build of `main`. Each push to `main` that passes CI publishes a signed build ([release](docs/operations/release.md)). The `CHANGELOG.md` names the fix under "Security".
- Disclosure is coordinated: when the fix ships, or 90 days after the report, whichever comes first. You are credited if you want to be.

Apassy has one maintainer. The times above are targets, not guarantees. There is no bug bounty.

## Supported versions

The latest build of `main`, as published at <https://apassy.wyderka.cc>. Older builds get no fix. Update, then check again.

## What is in scope

Apassy makes these promises. A way to break one of them is a vulnerability.

| Promise | Where it is stated |
| --- | --- |
| The broker socket never returns a secret value to an agent. An agent gets a value only in the environment of one approved process, or a placeholder. | [ADR 0006](docs/adr/0006-process-secrets.md), [ADR 0011](docs/adr/0011-run-proxy-placeholders.md) |
| In placeholder mode, the real value goes only into an auth position of an HTTPS request to a host of the variable. Never into a body, a path, another header, or another host. | [ADR 0011](docs/adr/0011-run-proxy-placeholders.md) §3 |
| A process in the Seatbelt profile cannot read the vault, a backup, the model, or the Apassy app bundle, and cannot start a program outside the profile by a route the profile denies. | [Isolation](docs/operations/isolation.md) §1, §7 |
| A run with a production credential, a hard rule failure, or an unavailable bouncer always waits for the owner or is denied. The model cannot override this. | [Goal](docs/goal.md) P2, [ADR 0007](docs/adr/0007-rules-and-local-bouncer.md) |
| Reveal, approval of a run, grant and rule changes, "Approve and remember", and token rotation need a fresh owner check. | [Goal](docs/goal.md) A4 |
| Lock and restart deny waiting runs. An approval of an old or changed request fails. A notification is not an approval. | [Goal](docs/goal.md) V3, N4 |
| A local rule pack can only add a restriction. It cannot mark a command safe, remove a flag, or replace a built-in pack. | [Rule packs](docs/operations/rule-packs.md) §4 |
| A notification shows the agent name and the event type only. No command, request, or value. | [Goal](docs/goal.md) N2 |
| No secret value, placeholder, or proxy password appears in the activity log, the decision log, the run answer, or the MCP output. | [ADR 0011](docs/adr/0011-run-proxy-placeholders.md) §5 |
| The vault at rest is one SQLCipher file. Without the passphrase, its content is not readable. Key material is not left in a file. | [Vault verification](docs/operations/vault-verification.md), [Key memory](docs/reviews/key-memory.md) |
| The iPhone companion listener answers only paired devices. A request needs a valid signature, a fresh time, and a new nonce. Pairing needs a 6-digit code that only the iPhone shows and a fresh owner check on the Mac. An approval from the iPhone is a signature of its approval key, made with Face ID, over the run exactly as the Mac showed it. The listener refuses a connection from the Mac itself. It runs only while the setting is on and the vault is unlocked, and a lock stops it. | [ADR 0020](docs/adr/0020-iphone-companion.md), [Companion](docs/operations/companion.md) |
| The published `Apassy.dmg` and every program in it are signed with the Developer ID and notarized. | [Release](docs/operations/release.md) |

Also in scope: an injection through the purpose, the user request, a command, or a tool output that changes a decision the documents say cannot change, and a dependency or build step that does not match what the documents say.

## What is a known limit, not a vulnerability

These are recorded. A report that only restates one of them gets a pointer to the record.

- A process of the same user can read the environment of a running process (F11). In real value mode this exposes the value. In placeholder mode it exposes only placeholders and the proxy password for the time of the run. See [ADR 0006](docs/adr/0006-process-secrets.md) and [ADR 0011](docs/adr/0011-run-proxy-placeholders.md), "What this mode does not protect".
- Seatbelt does not protect memory, the clipboard, or processes outside the profile. Apple marks `sandbox-exec` as deprecated. A program that the owner starts later outside the profile, for example from a git hook or a Makefile that a sandboxed process wrote, is not confined. See [Isolation](docs/operations/isolation.md) §4.
- A program that needs the real value (a signed request such as AWS SigV4, a database protocol, HTTP/2 only, a value the program uses itself) gets it when the owner selects real value mode. The proxy does not protect that mode.
- The bouncer is a classifier. A miss on a command it has not seen is a quality problem, not a vulnerability, unless it breaks a promise above. Report it as a normal issue with the synthetic command and the expected decision. The evaluation sets are in [docs/evaluation](docs/evaluation).
- The iPhone companion adds a network surface while its setting is on and the vault is unlocked: it answers on every network the Mac joins. The iPhone shows commands to whoever holds it unlocked, and an unlocked iPhone can deny runs. There is no push notification and no access away from the local network. See [Companion](docs/operations/companion.md), section 8.
- An attacker who controls the owner account, the Mac, or the trusted agent host. See [Product vision](docs/product-vision-v1.md) §4.
- Linux has no network rule for the run proxy yet. The codebase does not build for Windows.

## Verify a download

The DMG is signed with a Developer ID and notarized. Check the image and the app after you open it:

```
spctl -a -vv -t open --context context:primary-signature Apassy.dmg
codesign -dv --verbose=2 /Volumes/Apassy/Apassy.app
```

The site publishes `latest.json` with the SHA-256 of the image and whether it is notarized. You can also build the app yourself with `scripts/build-app.sh`, which signs and checks every program and the sandbox profile. See [Release](docs/operations/release.md).

## How Apassy is built

- The Rust crate has `#![forbid(unsafe_code)]`. The native parts are small Swift helpers in `native/`.
- Every dependency is pinned to an exact version. CI runs `cargo audit`. The source and license review of the storage stack is in [storage dependencies](docs/reviews/storage-dependencies.md); the notices are in [licenses/THIRD-PARTY-NOTICES.md](licenses/THIRD-PARTY-NOTICES.md).
- No custom cipher or TLS implementation (ADR 0001). TLS is `rustls` with the system trust store.
- Each design decision is an ADR in [docs/adr](docs/adr). The security reviews are in [docs/reviews](docs/reviews). The blind evaluations of the bouncer are in [docs/evaluation](docs/evaluation).
