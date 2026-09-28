# Contributing to Apassy

Apassy is a credential manager for a person and their agents. The most useful thing you can add is knowledge about a tool: which of its commands print a secret, delete data, or touch production. That knowledge is data, one JSON file per tool. You do not need to know Rust for it.

## Rules for every contribution

- **Synthetic values only.** Never put a real secret, a real vault, a real agent token, or a real host of yours in an issue, a pull request, a test, or a fixture. Tests must not call a provider.
- **English.** Code, comments, documentation, and pull requests are in English. The documents use short sentences and say what a thing does, not what it is like.
- **License.** By opening a pull request you license your contribution under [Apache-2.0](LICENSE), as section 5 of the license says. A file under `packs/` (a rule pack, a provider file, a schema) is different: you dedicate it to the public domain under [CC0-1.0](packs/LICENSE), so that every tool can use the knowledge, not only Apassy. There is no separate agreement to sign.
- **AI assistance is fine.** You are responsible for what you submit, and you ran the checks.
- **Security reports go through [SECURITY.md](SECURITY.md)**, not through an issue or a pull request.
- **Design changes need a decision first.** A change to what the broker, the proxy, the sandbox, or the bouncer promises needs an ADR in [docs/adr](docs/adr), accepted by the maintainer. Open an issue before you write code for one.

## What to contribute

| Contribution | Where | How it is checked | Rust needed |
| --- | --- | --- | --- |
| A rule pack for a tool | `packs/<tool>.json` | Schema, `apassy-packs validate`, coverage lines, replay | No |
| A provider file | `packs/providers/<id>.json` | Schema, `apassy-packs validate`, suggestion test | No |
| Evaluation cases from your stack | `tests/evals/`, `tests/fixtures/bouncer/` | The evaluation harness | No |
| A bug report | GitHub Issues | A synthetic command or a step list | No |
| A host adapter (a new agent host) | `src/agent/`, `docs/operations/` | An issue first, then a measurement document like [host hooks](docs/operations/host-hooks.md) | Yes |
| Code | `src/`, `tests/` | The checks below | Yes |

## Rule packs

Read [rule packs](docs/operations/rule-packs.md) first: what a pack is, the fields, the matcher conditions, and what stays in code. Then:

1. **Pick the kind of change.** A tool without a pack gets a new file `packs/<tool>.json`. A tool with a pack gets new entries in its file, and `pack_version` goes up by one.
2. **Start from a similar pack.** `gh.json` (a CLI with subcommands), `databases.json` (SQL clients), `debug-output.json` (a pack for every program), `http.json` (known hosts, an exception, a safe rule).
3. **Write the entries.** Each flag rule, safe rule, exception, project command, write, and access read has an `id`, a `note` with its reason, and a `when` matcher. Lists are lowercase. Each flag asks the owner, so a flag rule costs the owner a prompt: flag what changes state, prints a secret, or targets production, not what merely looks unusual.
4. **Be careful with what relaxes.** A `safe` rule, an `exemption`, and a `usage` role make the analysis less strict. A safe command has no remote write, no secret output, no data loss, and no project code; see "What known safe means" in [rule packs](docs/operations/rule-packs.md). Every safe rule in a pull request gets a question: why can this command not hurt? Reads across a whole cloud account are not safe; the model decides them.
5. **Register a new file** in `src/broker/packs.rs`, in the `BUILTIN` list, in alphabetical order: `("<tool>.json", include_str!("../../packs/<tool>.json")),`. Add a row to the pack table in [rule packs](docs/operations/rule-packs.md).
6. **Check the file.** The schema in `packs/schema/rule-pack.schema.json` works in an editor. The loader is the authority:

   ```
   cargo run --locked --features vault --bin apassy-packs -- validate packs/<tool>.json
   ```

   It names the reason when the file does not load. For an owner pack in `~/Library/Application Support/Apassy/packs/`, add `--local`.
7. **Add coverage lines** to `tests/fixtures/rule_packs/coverage.tsv`: for each new entry, at least one command that matches it and one near miss that does not. One command per line; an optional purpose follows after a tab. The test `every_pack_rule_matches_a_replay_command` fails for an entry that no line reaches.
8. **Refresh the replay** and read the diff:

   ```
   APASSY_REPLAY_WRITE=1 cargo test --locked --features vault --test analysis_replay
   git diff --stat tests/fixtures/rule_packs/replay.golden.tsv
   ```

   The golden file records the flags and the known-safe result of 62 000 command lines. Your change must change only the lines you meant to change. Write the counts in the pull request: how many lines gain a flag, lose a flag, become known safe, or stop being known safe, as the tables in [rule packs](docs/operations/rule-packs.md) §5 do. A line that loses a flag needs a sentence.
9. **Run the tests** that read the packs:

   ```
   cargo test --locked --features vault --test rule_packs --test analysis_replay --test bouncer_rules
   ```
10. **Add a line to `CHANGELOG.md`** under "Unreleased", and open the pull request.

A pack cannot parse a shell, follow a secret through a pipe, or read SQL. Those parts are in `src/broker/shell_risk.rs`. When a tool needs a new matcher condition, say so in an issue; the condition is a small code change with its own tests.

## Provider files

A provider file tells Apassy how to recognise a credential of one provider (the shape of the value, the variable names, the hosts) and which declaration to suggest. Read [declarations](docs/operations/declarations.md), then start from `packs/providers/stripe.json`. The file name is `<id>.json`, and `signals` needs at least one entry with a `reason`. Register the file in the `BUILTIN` list of `src/vault/providers.rs`, check it with `apassy-packs validate`, and run `cargo test --locked --features vault --test declaration_suggestions`.

A signal on the value (`value_starts`, `value_shape`) is stronger than a host, a host is stronger than a variable name, and a word is the weakest. Suggest `production` and `irreversible` only when the value itself says so, as `sk_live_` does.

## Evaluation cases

The bouncer is measured on labeled commands that were not used for tuning. Commands from a stack that the sets do not cover yet are valuable, especially normal everyday commands: a bouncer that asks too often is a bouncer that gets turned off.

- `tests/fixtures/bouncer/cases.tsv` and `independent.tsv`: `label`, `category`, `command`, `purpose`, separated by tabs. The label is `ok` (the owner can let it run) or `risk` (the owner must see it). The header of each file names the secret variables of the cases.
- `tests/evals/heldout-v4.jsonl`: one JSON object per case with the command, the user request, the declaration, the expected decision, the category (`normal`, `violation`, or `suspicious`), and a one-sentence rationale. Read [held-out v4](docs/evaluation/heldout-v4.md) for how a set is built and scored. A new set gets a new file and a new document; a published set does not change.

Label first, then run. A case whose label was chosen after seeing the result is not evidence.

## Host adapters

Apassy connects to Claude Code and Codex through an MCP server, a prompt hook, and a sandbox launcher. Another host (Cursor, Gemini CLI, Aider, OpenCode, and so on) needs the same three things. Before you write code, open an issue with what the host gives: how it starts a stdio MCP server, whether it has a hook that fires on each user prompt, where its transcript is, and how it identifies a session. [Host hooks](docs/operations/host-hooks.md) §2 is the table to fill in. An adapter is accepted with such a measurement, on a real session of the host.

## Code

- Rust 1.97 with rustfmt and clippy, as in `rust-toolchain.toml`. The crate has `#![forbid(unsafe_code)]`; keep it.
- No new dependency without an issue. Each dependency is pinned with `=` and reviewed for source and license, as in [storage dependencies](docs/reviews/storage-dependencies.md). No async runtime. No custom cipher or TLS implementation (ADR 0001).
- A test that passes must show the behavior. No stub tests, no skips: a skip is not a pass, and a test that cannot run must fail.
- Owner actions, secret values, and log lines have contracts. A `SecretValue` cannot be serialized; do not work around it.

The checks, as CI runs them ([development checks](docs/operations/checks.md)):

```
cargo fmt --all -- --check
cargo clippy --offline --locked --all-features --all-targets -- -D warnings
cargo test --offline --locked --all-features --all-targets -- --test-threads=1
cargo test --offline --locked --features vault --doc
node --test design/walkthrough/model.test.mjs
python3 tests/isolation/test_fixture_boundary.py
git diff --check
```

The isolation tests need macOS and `sandbox-exec`. The evaluation harness needs the local model; see [bouncer](docs/operations/bouncer.md).

## Pull requests

- One change per pull request. A pack and a code change are two pull requests.
- The description says what changes for the owner and why. For a pack: the tool, the entries, and the replay counts.
- Update the document that describes the changed behavior in the same pull request. A document that says something the code does not do is a bug.
- A maintainer reviews within two weeks. Apassy has one maintainer, so a large pull request without an issue first may wait.

## Where to ask

GitHub Issues at <https://github.com/wydrox/apassy/issues>: bugs, questions, and proposals. Search first. For a weakness, use [SECURITY.md](SECURITY.md).
