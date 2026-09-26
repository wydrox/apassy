# Rule packs

Date: 2026-09-26. Decisions: [ADR 0009](../adr/0009-general-by-default-and-learning.md) ("Rule packs as data"), [ADR 0010](../adr/0010-closing-open-decisions.md) ("Rule packs"). Goal item: B7 in [goal.md](../goal.md).

## 1. What a rule pack is

The command analysis (`src/broker/shell_risk.rs`) decides the rule flags and the "known safe" result of each command. See [bouncer.md](bouncer.md) for the decision order.
Knowledge about single tools is in rule packs. A rule pack is a JSON file for one tool or for a group of small tools.

- Built-in packs are the files in `packs/`. The build embeds them in the binary (`include_str!` in `src/broker/packs.rs`). Only an app release changes them.
- Local packs are owner files. They can only add restrictions. See section 4.

A new stack needs a new pack, not a code change.

### Built-in packs

| Pack | Programs | Content |
| --- | --- | --- |
| `aws` | aws, eb, cdk, sam, amplify | S3 writes, resource changes, deployments |
| `cargo` | cargo | build and test commands, publishing |
| `cloud` | gcloud, az, fly, flyctl, railway, render, heroku, serverless, sls, ansible-playbook, firebase, wrangler, stripe, twilio | deployments and resource changes |
| `databases` | psql, pg_dump, dropdb, dropuser, mysql, sqlite3, mongo, mongosh, clickhouse-client, cockroach, redis-cli | SQL writes, drops, credential columns |
| `docker` | docker, podman, docker-compose | removal of containers, images, and volumes; read commands |
| `encoding` | base64, xxd, od, hexdump, openssl, gzip, zip, uuencode, rev | the `encoder` role |
| `file-tools` | ls, cat, grep, sed, awk, find, cp, rm, and 35 others | file removal, secret files, system files, read commands |
| `gh` | gh | releases, workflow runs, secrets, repository settings, gists, API writes |
| `git` | git | history changes, pushes to release branches, read commands |
| `go` | go | build and test commands |
| `http` | curl, wget, http, https, httpie | known provider hosts, broadcasts, local requests, read requests |
| `js-tools` | tsc, eslint, prettier, test runners, next, vite, astro, playwright, cypress, turbo | check and test commands |
| `kubernetes` | kubectl, helm | deletions and cluster changes |
| `macos` | security, defaults, pbcopy, launchctl, diskutil, brew | Keychain, preferences, clipboard, disks |
| `make` | make | development targets |
| `netlify` | netlify | production deployments |
| `node` | node, deno, bun, tsx, ts-node | inline code, scripts, version checks |
| `npm` | npm, pnpm, yarn, bun, npx, bunx | scripts, new dependencies, unknown packages, registry settings, publishing |
| `prisma` | prisma | resets and schema commands |
| `python` | python, python3, pip, pip3, pytest, ruff, mypy, black, flake8, pylint, isort, twine, poetry | inline code, pip installs, test tools, Django commands, publishing |
| `remote` | ssh, scp, sftp, rsync, ftp, telnet, nc, ncat, netcat, socat | remote access, secrets sent to another host |
| `scripting` | ruby, perl, php, gem | inline code, scripts, gem publishing |
| `shell` | sh, bash, zsh, echo, test, cd, for, and other keywords and builtins | shell control, text output |
| `supabase` | supabase | queries, resets, key listings, functions, secrets |
| `system` | sudo, doas, chmod, crontab, systemctl, dd, mkfs, and others | privilege, permissions, jobs, services, disks |
| `terraform` | terraform, tofu, pulumi | destroy and apply |
| `vercel` | vercel | deployments, aliases, environment variables, read commands |

The 27 packs have 83 flag rules, 46 safe rules, and 12 exceptions.

## 2. What stays in code

These parts are not about one tool. They stay in `src/broker/shell_risk.rs`:

| Part | Reason |
| --- | --- |
| Shell parser: quotes, pipes, `&&`, redirects, `$( )`, here-documents, `sh -c` | It is the base of every rule. A pack cannot parse a shell. |
| Wrappers: `sudo`, `doas`, `env`, `time`, `nohup`, `exec`, `npx`, `bunx`, `pnpm dlx`, `yarn dlx` | The parser removes them to find the program. The `sudo` flag and the unknown-package flag are in packs. |
| Secret references and secret files (`$KEY`, `.env`, SSH keys) | Secret flow. Every pack uses the same definition. |
| Environment dumps (`env`, `printenv`, `set`, `export`) and `set -x` | Secret flow in the shell itself. |
| Pipes of a secret to an encoder or the network, a secret in a redirect | Secret flow. Packs give the roles `encoder`, `network`, and `output`. |
| HTTP auth headers, uploads, and `@file` arguments | Secret flow for HTTP clients. Packs give the role `http_client` and the known hosts. |
| Here-documents as code or SQL | Secret flow and SQL analysis. Packs give the roles `heredoc_code`, `heredoc_sql`, and `file_writer`. |
| SQL analysis: the first keyword of each statement | General for all database clients. Packs choose the programs (`"sql": "writes"`). |
| "A dry run does not act" | General rule. A pack rule selects it with `dry_run`. |
| Production words, production assignments (`URL=$PROD_URL`), and build modes | General rule. Packs make exceptions, for example for text tools. |
| Script names such as `delete-users.js`, danger options such as `--accept-data-loss` | General rule for every program. Packs give the role `script_runner`. |
| Real recipients, mass messages, system paths, `--print-secrets` options | General rules for every program. |
| Injection phrases in the purpose | The purpose is not a command. |
| `git push` refspecs (`HEAD:main`) | A parser for one syntax. The `git` pack gives the protected branches (`push_target`). |

## 3. Pack format

A pack is one JSON object. The loader rejects unknown fields at every level.

| Field | Built-in | Local | Meaning |
| --- | --- | --- | --- |
| `schema_version` | yes | yes | The pack format. This version of Apassy reads version 1 only. |
| `pack_version` | yes | yes | The version of the pack content. It starts at 1. Increase it at each change. |
| `tool` | yes | yes | A unique name: lowercase letters, digits, `-`, `_`. A built-in pack file has the name `<tool>.json`. |
| `description` | yes | yes | One sentence. |
| `programs` | yes | yes | Program names in lowercase, or `["*"]` for every program. |
| `rules` | yes | yes | Flag rules. |
| `roles` | yes | no | Roles for the general rules: a map from a role to programs. |
| `known_hosts` | yes | no | Provider API hosts. A secret in an auth header to these hosts is normal use. |
| `exemptions` | yes | no | Exceptions to a general rule. |
| `safe` | yes | no | Known safe commands. |

### Flag rules

```json
{ "id": "push-force-or-delete", "flag": "data_loss", "dry_run": "skip_with_n",
  "note": "Optional text for people.", "when": { "subcommand": ["push"], "any_arg": ["-f"] } }
```

- `id`: unique in the pack.
- `flag`: one of `secret_output`, `data_loss`, `production`, `real_recipient`, `remote_code`, `remote_access`, `system_change`, `new_dependency`, `privilege`, `ask_owner`. Each flag asks the owner. `ask_owner` has no other meaning.
- `dry_run` (optional): `skip` means the rule does not apply with `--dry-run` or `--dryrun`. `skip_with_n` also counts `-n`, except for a program with the role `no_dry_run` (`rm`, `git`). Without `dry_run`, the rule applies to a dry run too.
- `when`: the matcher. A rule without `program` or `raw_program` applies to the programs of its pack.

### Matcher conditions

All conditions in one matcher must hold. A list means "one of the items". The analysis compares arguments in lowercase, so the loader rejects uppercase items in these lists.

| Condition | Holds when |
| --- | --- |
| `program` | The program after wrappers is in the list. |
| `raw_program` | The first word, before wrappers, is in the list. |
| `package_runner` | The command runs a package with `npx`, `bunx`, `pnpm dlx`, or `yarn dlx`. |
| `package` | The package name (the program before `@`) is in the list. |
| `program_word_contains` | The program word as written contains a text, for example `@latest`. |
| `subcommand`, `action` | The first or the second argument is in the list. A missing argument is `""`. |
| `script` | The package script (after `run` or `run-script`, else the first argument): `base` is the part before `:`, and the name contains no text of `not_contains`. |
| `arg_count` | The number of arguments. |
| `only_options` | Every argument starts with `-`. |
| `any_arg`, `any_arg_starts`, `any_arg_contains` | An argument is, starts with, or contains a text. |
| `args_start`, `args_contain` | The arguments joined with spaces start with or contain a text, for example `"db query"`. |
| `command_contains` | The program and the arguments contain a text. |
| `command_contains_exact` | As `command_contains`, as written. |
| `word_contains` | A word of the command as written, wrappers included, contains a text. |
| `option_value` | An option in `option` is followed by a value in `value`, or by a value not in `not_value`. |
| `short_option_letter` | A group of short options such as `-rf` contains the letter. |
| `option_letter` | An option word, short or long, contains the letter. |
| `operands` | Conditions on the arguments that do not start with `-`: `count`, `min`, `any`, `all`, `allow_none`, `at` (`index` with `in` or `not_in`), `trim_start`, `trim_end`, and `as_written`. `any` and `all` take text patterns: `equals`, `starts`, `ends`, `contains`, `max_len`, `temp_path`. |
| `push_target` | A branch that `git push` updates is in the list. |
| `url_hosts_in` | There is a URL, and every URL host is in the list. |
| `known_host_read` | A GET request without a body or an upload, to known hosts only. |
| `refs_secret` | A word refers to a secret, for example `$DATABASE_URL`. |
| `arg_refs_secret` | An argument after the program refers to a secret. |
| `secret_file_arg`, `secret_file_arg_as_written` | An argument is a secret file, such as `.env`. |
| `system_path_arg` | An argument is under `/etc/`, `/usr/`, `/Library/`, `/System/`, or `/private/etc/`. |
| `inline_code_leaks` | Code in the command reads the environment and prints, writes, or sends data. |
| `sql` | `"writes"` or `"reads"`: the SQL argument (`-c`, `--command`, `-e`, `--eval`, or the text after `query`). |
| `any_of` | One of the matchers in the list holds. |
| `not` | The matcher does not hold. |

### Roles, exceptions, and safe rules (built-in packs only)

| Role | Meaning for the general rules |
| --- | --- |
| `output` | A secret in an argument is printed. |
| `encoder` | A secret in a pipe to this program is secret output. |
| `network` | A secret in a pipe is sent. A pipe from this program to a shell is remote code. |
| `http_client` | The analysis checks auth headers, uploads, and recipients. |
| `heredoc_code`, `heredoc_sql` | A here-document is code or SQL. |
| `file_writer` | A here-document with a secret goes to a file. |
| `script_runner` | The first argument is a script. Its name can tell about data loss. |
| `usage` | `--help`, `--version`, `help`, or a lone `-h` only prints usage. |
| `no_dry_run` | The data-loss rules ignore dry-run options. |

An exception (`exemptions`) has an `id`, a `check`, and a matcher. The checks are `secret_file_argument` and `production_word`. A safe rule (`safe`) has an `id` and a matcher.

## 4. Local packs

### Location

Apassy reads each `*.json` file in `~/Library/Application Support/Apassy/packs/`, in name order, when the broker starts. `APASSY_PACKS_DIR` changes the directory. A missing directory means no local packs. A file must be 1 MiB or less.
The Seatbelt profile of the agent host denies access to the Apassy data directory (ADR 0010), so an agent cannot write a local pack.

### Example

This pack asks the owner before every `git push`, and before any command that names the main billing database:

```json
{
  "schema_version": 1,
  "pack_version": 1,
  "tool": "owner-rules",
  "description": "Pushes and the billing database need the owner.",
  "programs": ["*"],
  "rules": [
    { "id": "push", "flag": "ask_owner",
      "when": { "program": ["git"], "subcommand": ["push"] } },
    { "id": "billing-db", "flag": "production",
      "when": { "command_contains": ["billing-main-db"] } }
  ]
}
```

Write a local pack:

1. Select a tool name that no built-in pack has, for example `git-local` or `owner-rules`.
2. List the programs, or use `["*"]`.
3. Write one rule for each restriction. Use lowercase text in the lists.
4. Check the directory: `cargo test --features vault --test rule_packs owner_local_packs -- --ignored --nocapture`. The test names each loaded pack. It fails with the reason if a pack does not load.
5. Restart the broker.

### Guarantees

- A local pack can add a flag. Each flag asks the owner.
- A local pack cannot mark a command as safe, remove a flag, make an exception, give a role, or name a known host. Its schema has no `safe`, `exemptions`, `roles`, or `known_hosts`. The loader rejects these fields and every other unknown field.
- A local pack cannot replace a built-in pack. The loader rejects a local pack with the tool name of a built-in pack.
- The analysis joins the flags of all packs. A command is known safe only when it has no flag, so a local flag can only remove "known safe".
- `not` and `any_of` in a local rule change only when that rule adds its flag.
- If a local pack does not load, the broker keeps the built-in packs and adds the flag `rule_pack_error` to every analysis. Then every run waits for the owner until the owner fixes or removes the file.

Tests in `tests/rule_packs.rs`:

| Test | What it shows |
| --- | --- |
| `a_local_pack_adds_a_restriction` | `git push origin feature/x` goes from known safe to `ask_owner`. A pack for every program adds `production` to a known safe `npm test` that names the billing database. Built-in flags stay. |
| `a_local_pack_cannot_relax_a_restriction` | Seven attempts to relax: a safe rule, an exception, the `usage` role for `rm`, a known host, a replacement of the `git` pack, an `allow` flag, and an unknown field. Each is rejected. The rule set and the analysis of the target command do not change. |
| `local_rules_only_add_flags_on_the_replay_sets` | Broad local rules with `not` and `any_of` on 1517 replay commands: no built-in flag goes away, and no command becomes known safe. 1279 commands get more flags. |
| `a_rejected_local_directory_fails_closed` | A relaxing pack in the directory: the loader names the file, and `npm test` gets `rule_pack_error`. After the owner removes the file, the other local pack is active. |
| `every_built_in_pack_file_loads` | Each file in `packs/` is embedded, loads, has schema version 1, and has a unique tool name. |

## 5. Replay evidence

The move of the tool knowledge must not change a decision. The evidence:

1. Before the move, `tests/analysis_replay.rs` recorded the analysis output (flags and known safe) in `tests/fixtures/rule_packs/replay.golden.tsv`. The commit of the golden file came before any code change. A second commit added six coverage lines for `gem`, `poetry`, and `twine`. The old code also wrote their golden lines.
2. The replay covers 61517 commands:
   - 174 commands of `tests/fixtures/bouncer/cases.tsv` and 96 of `independent.tsv`,
   - 1247 commands of the synthetic coverage set `tests/fixtures/rule_packs/coverage.tsv`. It has the examples of the unit tests and the broker tests, and commands for each rule with near misses,
   - 60000 generated commands with a fixed seed. The golden file has their count, a digest, and the count of each flag.
3. After the move: 61517 commands, 0 different lines.
4. A unit test (`every_pack_rule_matches_a_replay_command`) shows that each of the 141 rules, safe rules, and exceptions matches at least one replay command.
5. I changed single entries in three packs by hand (the `release` branch, one known host, one build folder). The replay found each change. Then I removed the changes.
6. A temporary test compared the old code and the committed code on 22 million random commands (seeds 7, 11, 404, 505, 606, and 707). Half of the commands use a known program and its words. The other half use random words from the old code. Both halves have random case, wrappers, pipes, redirects, here-documents, and argument lists without a shell. There were 0 differences. The test used a copy of the old code. The repository does not keep it.

The replay compares the analysis, not the final decision. The decision (`src/broker/bouncer.rs`) uses the analysis, the declarations, and the model answers. The same analysis gives the same decision.

Run the replay: `cargo test --features vault --test analysis_replay -- --nocapture`.

## 6. Change a built-in pack

1. Change the JSON file in `packs/`. Increase `pack_version`.
2. Run `cargo test --features vault --test analysis_replay`. A difference is a changed decision.
3. For an intended change, write the golden file again with `APASSY_REPLAY_WRITE=1` and review each changed line. `APASSY_REPLAY_DUMP=path` writes the full output of the generated set, to compare two versions.
4. Add a command for a new rule to `coverage.tsv`. The unit test fails for a rule without a replay command.
5. A new pack file needs an `include_str!` line in `src/broker/packs.rs`. A test fails for a file that is not embedded.

## 7. Limits

- The rules are heuristics, as before the move. The move did not tune them.
- The owner does not see which local rule added a flag. The approval card shows the flag name only. Use `ask_owner` or a clear flag for each rule.
- A local pack that does not load makes every run wait for the owner. A process that can write to the local pack directory can do this.
- There is no signature on a local pack. Built-in packs are part of the signed app.

## 8. Checks

Results on 2026-09-26:

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS |
| `cargo test --locked --features desktop,vault` | PASS. `analysis_replay`: 1 test, 61517 commands, 0 differences. `rule_packs`: 5 tests, 1 ignored (`owner_local_packs_load` reads the owner's directory). Unit tests in `packs.rs` and `shell_risk.rs` pass. |
