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
| `airflow` | airflow | connections, variables, and configuration with secrets, metadata resets, DAG deletion, users, project commands (DAG and task runs), read commands |
| `alembic` | alembic | downgrades, upgrades and stamps (writes), read commands |
| `algolia` | algolia | index deletion, clearing, and overwrites, record deletion, API keys, read commands |
| `auth0` | auth0 | revealed client secrets, test tokens, deletions, user and role changes, read commands |
| `aws` | aws, eb, cdk, sam, amplify | S3 writes and removal, deletions, resource changes, secret reads, environment values of functions and tasks, remote shells, targeted reads, identity inventory (access reads) |
| `azure` | az | deletions, resource changes, keys and secrets, remote shells, blob listings in a named container, role and directory inventory (access reads) |
| `cargo` | cargo | build and test commands, new crates, publishing, SQLx drops, migrations (writes), and offline query data |
| `celery` | celery | queue purges, worker control, workers and task calls (project commands), worker inspection |
| `cloud` | railway, render, serverless, sls, ansible-playbook, ansible, ansible-vault, ansible-galaxy, ansible-inventory, twilio | deployments, the printed Serverless configuration, Ansible check mode and ad-hoc commands, vault plaintext, Railway variables, shells, and reads, Twilio reads |
| `databases` | psql, pg_dump, pg_restore, dropdb, dropuser, mysql, mysqladmin, sqlite3, duckdb, mongo, mongosh, mongorestore, clickhouse-client, cockroach, cqlsh, redis-cli, mysqldump, mariadb-dump | SQL writes, SQL as a plain argument, MongoDB writes, drops, restores over data, Redis and MySQL server changes, Redis passwords, Redis reads, credential columns, SQL and Redis changes (writes), schema reads, reads of local database files |
| `dbt` | dbt | full refreshes, project commands (`run-operation`), check and read commands |
| `digitalocean` | doctl | deletions, resource changes, credentials, remote shells |
| `django` | python, python3, manage.py, django-admin | flush, `migrate APP zero`, destructive `shell` code, `dbshell` writes, admin accounts, printed settings, development commands |
| `docker` | docker, podman, docker-compose, podman-compose | removal of containers, images, and volumes; host access from a container; the printed Compose configuration; image runs (project commands); pushes (writes); read and local commands; commands in a local container |
| `dotnet` | dotnet | Entity Framework drops and rollbacks, database updates (writes), publishing, new packages, user secrets, build and test |
| `encoding` | base64, xxd, od, hexdump, openssl, gzip, zip, uuencode, rev | the `encoder` role |
| `file-tools` | ls, cat, grep, sed, awk, find, cp, rm, and 35 others | file removal, secret files, system files, read commands |
| `firebase` | firebase | deployments, deletion of Firestore, database, function, and hosting data, remote writes, user and config exports |
| `fly` | fly, flyctl | deployments, secret and machine changes, destruction, remote shells, tokens, read commands |
| `gcloud` | gcloud, gsutil, bq | deletions, resource changes, storage writes, BigQuery writes and overwrites, tokens and secrets, environment values of services, remote shells, BigQuery schema reads and dry runs, IAM inventory (access reads) |
| `gh` | gh | releases, workflow runs, merges, secrets, repository settings, gists, API writes, write commands (writes), read commands |
| `git` | git | history changes, pushes to release branches, pushes (writes), read commands |
| `glab` | glab | merges, releases, pipeline runs, CI/CD variables, deletions, API writes, write commands (writes), read commands |
| `go` | go, gofmt, goimports, golangci-lint, staticcheck, govulncheck | new modules, Go settings, build, test, and lint commands |
| `heroku` | heroku | every command except known reads, destruction of apps, databases, and add-ons, config values, one-off dynos |
| `host-hooks` | every program | the host hook channel: `apassy-hook`, host settings, and transcripts (goal item B6) |
| `http` | curl, wget, http, https, httpie | known provider hosts, broadcasts, local requests, read requests |
| `huggingface` | huggingface-cli, hf | logins that store the token, token output, uploads of the project folder, repository deletion, read commands |
| `js-tools` | tsc, eslint, prettier, test runners, next, vite, astro, playwright, cypress, turbo | check and test commands |
| `jvm` | gradle, gradlew, mvn, mvnw | Flyway and Liquibase tasks, history changes, migrations (writes), publishing and deployment, build, test, and read tasks |
| `kafka` | kafka-topics, kafka-consumer-groups, kafka-configs, kafka-acls, and 8 others (with or without `.sh`), kcat | deletions, offset resets, cluster and access changes, list and describe commands |
| `kubernetes` | kubectl, helm | deletions, cluster changes, secret reads, raw and flattened configuration, copies from a pod, read commands |
| `laravel` | php, artisan, sail, composer, phpunit, pest, phpstan, psalm, php-cs-fixer, phpcs | fresh and reset migrations, database wipes, destructive tinker code, printed config, queue flushes and retries, the app key, new packages, development commands |
| `linters` | tflint, tfsec, checkov, kubeconform, hadolint, shellcheck, ansible-lint, sqlfluff, and 7 others | linters and scanners (known safe) |
| `macos` | security, defaults, pbcopy, launchctl, diskutil, brew | Keychain reads, preferences, clipboard, disks |
| `make` | make, just, task | development targets (every target on the line), task names |
| `migrations` | flyway, liquibase, knex, sequelize, typeorm, drizzle-kit, dbmate, goose, migrate, atlas, and 3 others | clean, drop, and rollback commands, history repairs, applied migrations (writes), read commands |
| `mix` | mix | Ecto drops, resets, and rollbacks, Hex publishing, build and test tasks |
| `mlflow` | mlflow | garbage collection and deletions, tracking database upgrades, project commands (`mlflow run`), read commands |
| `netlify` | netlify | production deployments, site deletion, environment variables, local builds |
| `node` | node, deno, bun, tsx, ts-node | inline code, scripts, version checks, Deno check, lint, format, test, and development tasks |
| `nomad` | nomad | job runs and changes, purges and garbage collection, variables, ACL tokens, shells in an allocation, node and operator changes, read commands |
| `npm` | npm, pnpm, yarn, bun, npx, bunx | scripts, task names, new dependencies, unknown packages, registry settings and access, publishing, publish dry runs |
| `planetscale` | pscale | deploy requests and promotions, deletions, new passwords and tokens, read commands |
| `prisma` | prisma | resets, migrations and database writes (writes), schema commands, migration reads |
| `python` | python, python3, pip, pip3, poetry, uv, pipenv, pdm, hatch, test and lint tools, twine | inline code, new packages, package sources, test tools, lock file installs, publishing |
| `rabbitmq` | rabbitmqctl, rabbitmqadmin, rabbitmq-diagnostics, rabbitmq-plugins, rabbitmq-queues, rabbitmq-upgrade | purges, deletions, node resets, users and permissions, definition exports, node stops, read commands |
| `rails` | rails, rake | database drops, resets, schema loads, rollbacks, destructive runner code, credentials, read and test tasks |
| `remote` | ssh, scp, sftp, rsync, ftp, telnet, nc, ncat, netcat, socat | remote access, secrets sent to another host |
| `ruby-tools` | bundle, bundler, rspec, rubocop, standardrb, brakeman, bundle-audit | new gems, gem sources, install, test, and lint commands |
| `scripting` | ruby, perl, php, gem | inline code, scripts, gem publishing |
| `secret-managers` | vault, op, doppler, infisical, sops, chamber, bw, pass, gopass, aws-vault, age, gpg, gpg2 | printed secret values, secret changes, names-only listings, command runners |
| `sentry` | sentry-cli | release deletion, release bookkeeping and events (writes), commands that it runs, read commands |
| `shell` | sh, bash, zsh, echo, test, cd, for, set, export, source, eval, and other keywords and builtins | shell control, text output |
| `sql-clients` | snowsql, snow, trino, presto, spark-sql, beeline, hive, impala-shell, sqlcmd, usql, mycli, pgcli, litecli, mariadb, vsql, clickhouse | SQL writes in an argument or an option value, SQL changes (writes), Snowflake object drops |
| `stripe` | stripe | deletions and cancellations, money movement, API keys, account changes and test events (writes), read commands |
| `supabase` | supabase | queries, resets, key listings, functions, secrets |
| `symfony` | php (`bin/console`), symfony | database drops, fixture loads, message retries, printed environment values and secrets, development commands |
| `system` | sudo, doas, chmod, crontab, systemctl, dd, mkfs, kill, pkill, dig, and others | privilege, permissions, jobs, services, disks, process environments, process and host information |
| `terraform` | terraform, tofu, pulumi | destroy, apply, state changes, secret outputs and outputs by name, read commands |
| `vercel` | vercel | deployments, aliases, environment variables, read commands |
| `wrangler` | wrangler | deployments, deletions, KV, R2, D1, and secret writes, local and read commands |

The 62 packs have 258 flag rules, 117 safe rules, 21 exceptions, 5 project command entries, 17 write entries, and 3 access read entries. Each has a `note` with its reason. The test `every_built_in_rule_has_a_note` checks this. Dev round 2 added 13 packs and more knowledge in 20 packs ([dev-round2.md](../evaluation/dev-round2.md)). Dev round 3 audited every safe rule, added the `glab` and `celery` packs, and changed 33 packs ([dev-round3.md](../evaluation/dev-round3.md)).

**What known safe means (dev round 3).** A known safe command has no remote write, no secret output, no data loss, and no project code. One exception is recorded: a command may run project code through a named contract of its tool whose purpose is local, namely a test, a build, a check, a format, an install from the lock file, a preview (`terraform plan`, `pulumi preview`), or a local development server (`npm run dev`, `rails server`, `mix phx.server`). A `run` verb that starts any program of the project (`cargo run`, `go run`, `dotnet run`, `deno run`, `gradle run`, `bootRun`, `spring-boot:run`) is never known safe. A command list is known safe only when every part is known safe, and the flags come from every part. The audit, pack by pack, is in [dev-round3.md](../evaluation/dev-round3.md).

Inventory reads across a whole cloud account (`aws ... describe-*`, `gcloud ... list`, `az ... list`, `doctl ... list`) are not known safe. The model decides them. Targeted reads, such as logs, the caller identity, and the local configuration, are known safe. Reads of the access configuration of a whole account (`aws iam`, `aws organizations`, `gcloud iam`, `get-iam-policy`, `az role`, `az ad`) are access reads (dev round 3): they are not known commands, so they always need `task_match`.

## 2. What stays in code

These parts are not about one tool. They stay in `src/broker/shell_risk.rs`:

| Part | Reason |
| --- | --- |
| Shell parser: quotes, pipes, `&&`, redirects, `$( )`, here-documents, `sh -c` | It is the base of every rule. A pack cannot parse a shell. |
| Wrappers: `sudo`, `doas`, `env`, `time`, `nohup`, `exec`, `npx`, `bunx`, `pnpm dlx`, `yarn dlx` | The parser removes them to find the program. The `sudo` flag and the unknown-package flag are in packs. |
| Environment runners: `bundle exec`, `poetry run`, `uv run`, `pipenv run`, `pdm run`, `hatch run`, `rye run` | The parser removes them and their options to find the program, as for the other wrappers. `poetry run alembic downgrade base` is an `alembic` command. |
| Commands in a local container: `docker exec`, `docker container exec`, `docker compose exec` and `run`, `docker-compose exec` and `run`, and the same for Podman | The parser adds the inner command as its own pipeline, with the here-document of the line. The packs check it as a command on the host. The line is known safe only when the inner command is known safe. |
| Secret references and secret files (`$KEY`, `.env`, SSH keys, `.pgpass`, `.git-credentials`, key stores, `*.tfstate`, service account keys, `~/.kube/config`, `~/.docker/config.json`) | Secret flow. Every pack uses the same definition. |
| Environment dumps (`env`, `printenv`, `set`, `export`) and `set -x` | Secret flow in the shell itself. |
| Pipes of a secret to an encoder or the network, a secret in a redirect | Secret flow. Packs give the roles `encoder`, `network`, and `output`. |
| HTTP auth headers, uploads, and `@file` arguments | Secret flow for HTTP clients. Packs give the role `http_client` and the known hosts. |
| Here-documents as code or SQL | Secret flow and SQL analysis. Packs give the roles `heredoc_code`, `heredoc_sql`, and `file_writer`. |
| SQL analysis: the first keyword of each statement | General for all database clients. Packs choose the programs (`"sql": "writes"`). |
| "A dry run does not act" | General rule. A pack rule selects it with `dry_run`. Use `skip`, not `skip_with_n`, for a program where `-n` has another meaning: a namespace (`kubectl`, `helm`), a database number (`redis-cli`), a name (`prisma`), or a count (`shred`). |
| Production words, production assignments (`URL=$PROD_URL`), and build modes | General rule. Packs make exceptions, for example for text tools. |
| Script names such as `delete-users.js`, danger options such as `--accept-data-loss` | General rule for every program. Packs give the role `script_runner`. |
| Task and package script names such as `db:reset` or `db-drop` | General rule. Packs give the role `task_runner` (npm, pnpm, yarn, bun, make, just, task). |
| A usage request (`--help`, `--version`) does not act | General rule for programs with the role `usage`. Through `npx`, `bunx`, or `dlx` the runner still downloads and runs the package, so the rules with `"package_runner": true` still apply. |
| Real recipients, mass messages, system paths, `--print-secrets` options | General rules for every program. |
| Injection phrases in the purpose and the user request | Text, not a command. The broker checks the user request in `run.rs` with `shell_risk::injection_flag`. |
| Known commands (`Analysis::known_command`) | Policy v5: only for a known command can a certain read replace `task_match` ([bouncer.md](bouncer.md), step 6). A known program is named by a built-in pack. Packs give the role `project_code` and the field `project_commands`. An HTTP write is not a known command. |
| The general secret lexicon | General for every program. A reveal verb (`get`, `show`, `view`, `export`, `decrypt`, `pull`, and others) with a secret or value noun (`secrets`, `vault`, `password`, `token`, `variables`, `vars`, `credentials`, `connections`, `dotenv`, `appsettings`), a listing of values, a value noun as the subcommand, a new secret (`password create`), or a reveal option (`--reveal`, `--show-secrets`, `--kv`, `--with-decryption`, `--format dotenv`). Packs make exceptions with the check `command_lexicon`. |
| A secret stored in another store | A login, a store or configuration entry, or a remote URL with a secret of the run after the verb, and `--add-to-git-credential`. |
| Public access | `allUsers`, `allAuthenticatedUsers`, `0.0.0.0/0`, `::/0`, and `public-read` give the flag `privilege`. |
| Programs that no pack knows | Verbs and options that delete or reset (`delete`, `drop`, `purge`, `gc`, `clear`, `reset`, `--reset-offsets`, `--full-refresh`, `--replace`) give `data_loss`. Verbs of an irreversible change (`repair`, `replay`, `revert`), a retry of all jobs, and confirmation options (`--force`, `--yes`, `--execute`) give `irreversible`. A destructive SQL statement in an argument gives `data_loss`. |
| Connection URLs with a written host | A bound secret and a `jdbc:`, `postgresql://`, `mongodb://`, `redis://`, or similar URL whose host is written in the command and is not this computer: `secret_output`. |
| HTTP methods, paths, and headers | A DELETE, or a write to a path with `delete`, `purge`, `flush`, or `reset`, is `data_loss`. A write to a marketing, campaign, newsletter, or broadcast path is `production`. A header name with `key`, `token`, `auth`, or `secret` is an auth header. A URL that starts with a bound variable with an endpoint name (`$ES_URL/...`) goes to the endpoint that the owner bound. A POST to a search path is a read. |
| Command runners | `doppler run --`, `op run --`, `railway run --`, and other programs with the role `command_runner`: the command after `--` is its own pipeline. |
| `git push` refspecs (`HEAD:main`) | A parser for one syntax. The `git` pack gives the protected branches (`push_target`). |
| Global options before the subcommand (dev round 3) | `git -C dir`, `kubectl -n ns`, `helm --kube-context`, `terraform -chdir=`, `docker --context`, the `docker compose` options, `npm --prefix`, `pnpm -C`, `aws --profile`, `cargo +nightly`, `make -C`, `just -f`, `task -t`, `supabase --workdir`, `stripe --api-key`, and `celery -A`. The matchers `subcommand`, `action`, `args_start`, `args_contain`, `arg_count`, `script`, and `operands` read the arguments from the subcommand on (`sub_args`). An option that is not in the list of the program ends the global options, as before. |
| More wrappers (dev round 3) | `xargs`, `timeout`, `nice`, `ionice`, `stdbuf`, `caffeinate`, `command` (not `command -v`), `builtin`, `watch`, `chronic`, and `unbuffer`, with their options. The command after them is the program. `pnpm exec`, `npm exec`, `yarn exec`, and `bun x` too; `npm exec` and `bun x` are package runners, as `npx`. |
| Shell scripts inside a segment (dev round 3) | `sh -c TEXT` after a wrapper or inside a script (`timeout 60 sh -c '...'`, `sh -c "bash -c '...'"`), the here-document of a shell without `-c`, the command of `trap`, and the arguments of `eval` are parsed as their own pipelines. |
| Every target of a task runner (dev round 3) | `make`, `just`, and `task` run every target on the command line, so each target counts for the data-loss names (`make test db-reset`). |
| Known writes (dev round 3) | Packs list write commands (`writes`). An HTTP write is a known write too. A write rule wins over a safe rule. |
| Verbose HTTP clients (dev round 3) | `curl -v`, `--verbose`, `--trace`, `--trace-ascii`, `--libcurl`, a short option group with `v` (`-sSv`), `wget -d`, and HTTPie `-v`, `--offline`, and `--print` with `H` or `B` print the request. With a secret reference, a user option, an auth header, or `.netrc` credentials, the command gets `secret_output`. |
| SQL changes, schema reads, and local file reads (dev round 3) | `sql_changes`: every statement that changes data, schema, or access, also `INSERT`, `CREATE`, `COPY ... FROM`, `CALL`, a `PRAGMA` with a value, and MongoDB inserts. `sql_schema_read`: `psql` meta commands, `EXPLAIN` of a read with read functions only, `SHOW TABLES`, `DESCRIBE`, `SELECT` without `FROM`, and MongoDB schema methods. `plain_sql_reads`: SQLite and DuckDB arguments that only read. SQL comments do not hide a statement, and every `-c` of `psql` counts. |
| Names-only options (dev round 3) | `--only-names`, `--names-only`, `--name-only`, `--only-keys`, `--keys-only`, and `--no-values` ask for names, not values. The secret lexicon does not flag such a command, and packs use the condition `names_only`. |
| Redirects to scratch folders (dev round 3) | A known safe command stays known safe when every output redirect goes to `/tmp/`, or to `tmp/`, `dist/`, `build/`, `out/`, `coverage/`, `target/`, or `.cache/` of the project, not to a secret file, and not through `..`. |

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
| `project_commands` | yes | no | Commands that run code of the project, such as `dbt run-operation`. They are not known commands (policy v5). |
| `writes` | yes | no | Commands that change state, such as `gh pr comment`, `git push`, or SQL `INSERT` (policy v7). They are known writes: never a certain read, and never known safe. |
| `access_reads` | yes | no | Reads of the access configuration of a whole account, such as `aws iam list-users` (dev round 3). They are not known commands. |

### Flag rules

```json
{ "id": "push-force-or-delete", "flag": "data_loss", "dry_run": "skip_with_n",
  "note": "Optional text for people.", "when": { "subcommand": ["push"], "any_arg": ["-f"] } }
```

- `id`: unique in the pack.
- `flag`: one of `secret_output`, `data_loss`, `irreversible`, `production`, `real_recipient`, `remote_code`, `remote_access`, `system_change`, `new_dependency`, `privilege`, `hook_channel`, `ask_owner`. Each flag asks the owner. `ask_owner` has no other meaning. `hook_channel` is for the host hook channel (goal item B6). `irreversible` is a change that cannot be undone and is not a deletion, for example `flyway repair` or `queue:retry all`.
- `note`: the reason for the rule, in one or two sentences. Each built-in rule has one.
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
| `segment_contains` | All text of the segment contains a text: the `NAME=value` prefixes, the words as written, the redirect targets, and the here-document, in lowercase. |
| `segment_word_ends` | A word of that text ends with a text. Words split at spaces, quotes, `=`, and shell operators. A trailing `/` does not count. |
| `option_value` | An option in `option` is followed by a value in `value`, or by a value not in `not_value`. |
| `short_option_letter` | A group of short options such as `-rf` contains the letter. |
| `option_letter` | An option word, short or long, contains the letter. |
| `operands` | Conditions on the arguments from the subcommand on that do not start with `-`: `count`, `min`, `any`, `all`, `allow_none`, `at` (`index` with `in`, `not_in`, or `starts`), `trim_start`, `trim_end`, `as_written`, and `skip` (options with a separate value, such as `-u URL`; the value is not an operand). `any` and `all` take text patterns: `equals`, `starts`, `ends`, `contains`, `max_len`, `temp_path`, and `only_chars` (every character is in the text, dev round 3). |
| `push_target` | A branch that `git push` updates is in the list. |
| `url_hosts_in` | There is a URL, and every URL host is in the list. |
| `known_host_read` | A GET request without a body or an upload, to known hosts only. |
| `refs_secret` | A word refers to a secret, for example `$DATABASE_URL`. |
| `arg_refs_secret` | An argument after the program refers to a secret. |
| `secret_file_arg`, `secret_file_arg_as_written` | An argument is a secret file, such as `.env`. |
| `system_path_arg` | An argument is under `/etc/`, `/usr/`, `/Library/`, `/System/`, or `/private/etc/`. |
| `inline_code_leaks` | Code in the command reads the environment and prints, writes, or sends data. |
| `sql` | `"writes"` or `"reads"`: the SQL argument (every `-c`, `--command`, `-e`, `--execute`, `--eval`, or the text after `query`). `"any_arg_writes"`: an argument that is not an option, or the value of a `--name=value` option, has a space and is SQL that writes, for clients that take SQL as an argument (`sqlite3 app.db "DELETE FROM users"`, `snowsql -q "DROP SCHEMA x"`). Dev round 3: `"changes"` and `"any_arg_changes"` (SQL that changes anything, for `writes`), `"schema_read"` (a read of the schema, a plan, or server information), and `"plain_args_read"` (SQLite and DuckDB arguments that only read). |
| `names_only` | An option asks for names only, such as `--only-names` (dev round 3). |
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
| `task_runner` | The argument after `run` or `run-script`, or else the first argument, is a task or a package script. Its name can tell about data loss. |
| `usage` | `--help`, `--version`, `help`, or a lone `-h` only prints usage. |
| `no_dry_run` | The data-loss rules ignore dry-run options. |
| `project_code` | The program runs code that the project defines: script files, package scripts, make targets, or custom framework subcommands. A command of it that is not known safe is not a known command (policy v5). |
| `command_runner` | The program runs another command after `--` with secrets in its environment. The analysis checks that command as its own pipeline. |

An exception (`exemptions`) has an `id`, a `check`, and a matcher. The checks are `secret_file_argument`, `production_word`, and `command_lexicon` (the general secret lexicon and the public access words, for programs whose arguments are text or file names, or for a subcommand that the pack knows better). A safe rule (`safe`) and a project command (`project_commands`) have an `id` and a matcher.

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
- A local pack cannot mark a command as safe, remove a flag, make an exception, give a role, name a known host, or list project commands, writes, or access reads. Its schema has no `safe`, `exemptions`, `roles`, `known_hosts`, `project_commands`, `writes`, or `access_reads`. The loader rejects these fields and every other unknown field. A local pack adds a restriction with a flag, for example `ask_owner`.
- A local pack cannot make a program known (policy v5). Only a built-in pack does. Test: `a_local_pack_does_not_make_a_program_known`.
- A local pack cannot replace a built-in pack. The loader rejects a local pack with the tool name of a built-in pack.
- The analysis joins the flags of all packs. A command is known safe only when it has no flag, so a local flag can only remove "known safe".
- `not` and `any_of` in a local rule change only when that rule adds its flag.
- If a local pack does not load, the broker keeps the built-in packs and adds the flag `rule_pack_error` to every analysis. Then every run waits for the owner until the owner fixes or removes the file.

Tests in `tests/rule_packs.rs`:

| Test | What it shows |
| --- | --- |
| `a_local_pack_adds_a_restriction` | `git push origin feature/x` (a known write, dev round 3) gets `ask_owner`. A pack for every program adds `production` to a known safe `npm test` that names the billing database. Built-in flags stay. |
| `a_local_pack_cannot_relax_a_restriction` | Eight attempts: a safe rule, an exception, the `usage` role for `rm`, a known host, a `writes` entry, a replacement of the `git` pack, an `allow` flag, and an unknown field. Each is rejected. The rule set and the analysis of the target command do not change. |
| `local_rules_only_add_flags_on_the_replay_sets` | Broad local rules with `not` and `any_of` on 2074 replay commands: no built-in flag goes away, and no command becomes known safe. 1823 commands change. |
| `a_rejected_local_directory_fails_closed` | A relaxing pack in the directory: the loader names the file, and `npm test` gets `rule_pack_error`. After the owner removes the file, the other local pack is active. |
| `every_built_in_pack_file_loads` | Each file in `packs/` is embedded, loads, has schema version 1, and has a unique tool name. |
| `every_built_in_rule_has_a_note` | Each flag rule, safe rule, exception, project command, write, and access read of a built-in pack has a `note` with its reason. |

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

### Intended changes after the move (goal items B2 and B7)

After the move, new tool knowledge changed the analysis on purpose. Each commit wrote the golden file again. The commit message lists the changed lines, and the table below sums them. The counts compare each commit with the commit before it. The replay now covers 62074 commands: 270 labeled commands, 1804 coverage commands (557 new), and 60000 generated commands.

| Commit | Knowledge | Changed lines of the labeled and coverage sets | New coverage lines | Changed generated lines |
| --- | --- | --- | --- | --- |
| Analysis | Environment runners, commands in a local container, task names, usage requests through a package runner, more secret files, new matcher conditions | 0 | 46 | 128: 122 get `new_dependency`, 5 get `data_loss`, 54 are no longer known safe |
| Host hooks | The `host-hooks` pack (the old check in `prompts.rs`) | 0 | 11 | 0 |
| Migrations and ORM | `rails`, `ruby-tools`, `django`, `alembic`, `migrations`, `dotnet`, `mix`, `laravel`, `jvm`, `linters`; more in `python`, `cargo`, `go`, `prisma` | 16 | 192 | 115: 38 get `new_dependency`, 5 get `data_loss`, 70 become known safe, 3 lose `production` |
| Clouds and platforms | `gcloud`, `azure`, `digitalocean`, `heroku`, `fly`, `firebase`, `wrangler`, `stripe` (from `cloud`); more in `aws`, `netlify`, `cloud` | 12 | 170 | 272: 102 get `data_loss`, 3 get `production`, 81 become known safe, 123 lose `production` |
| Data stores and infrastructure | `secret-managers`; more in `databases`, `docker`, `kubernetes`, `terraform`, `macos`, `file-tools` | 22 | 138 | 798: 676 get `data_loss`, 28 get `secret_output`, 2 get `production`, 88 become known safe, 9 lose a flag |
| Notes | A `note` for 71 older rules | 0 | 0 | 0 |
| Dev round 2 | General secret, store, irreversible, public access, connection URL, HTTP, and injection rules; known commands; 13 new packs; more knowledge in 20 packs | 8 of 2074 | 328 | 592 (see below) |
| Dev round 3, safety | Known safe audit, known writes, access reads, global options, wrappers, shells inside a segment, verbose HTTP clients, outputs by name, `glab` (commit `5b03c49`) | 43 of 2402 | 163 | 316 (see below) |
| Dev round 3, schema reads | Schema, plan, and server reads; every `-c`; SQL comments; backslash in double quotes (commit `fece794`) | 10 of 2565 | 11 | 16 |
| Dev round 3, v3 knowledge | Deno, `pnpm exec`, SQLite, MySQL, SQLx, Celery, names-only listings, command runners, redirects to scratch folders (commit `072d797`) | 10 of 2576 | 36 | 79 |
| Dev round 3, Ansible facts | `ansible -m setup` is not known safe (commit `ef835b8`) | 0 of 2612 | 1 | 0 |

On the 1517 lines of the golden file of the move, 41 lines changed:

- 12 get `data_loss`. `-n` is not a dry run for `kubectl` and `helm` (namespace), `psql`, `redis-cli` (database number), `prisma` (`--name`), `terraform`, and `shred` (passes): 5 lines. SQL as a plain argument for `sqlite3` and `clickhouse-client`: 3 lines. `python manage.py flush`, `aws s3 rm`, `aws dynamodb delete-table`, and `fly destroy`: 4 lines.
- 4 get `new_dependency`: `cargo install x`, `cargo add x`, `go get x`, `python -m pip install x`.
- 1 gets `secret_output`: `security find-generic-password -s x -w`.
- 1 gets `remote_access` and keeps `production`: `heroku run rails db:migrate -a odealo-production`.
- 23 become known safe. Examples: `terraform plan`, `kubectl get pods`, `helm list`, `docker compose down`, `aws sts get-caller-identity`, `npx prisma migrate status`, `twilio api:core:messages:list --limit 10`, `pip install -r requirements.txt`. One of them lost a flag: `heroku logs` had `production`, because the old rule flagged every `heroku` command.

The flags that went away in the generated set, all 135 lines:

- `production` on Heroku reads (78 lines, for example `heroku ps`) and on `fly secrets` without a write action (45 lines, for example `fly secrets` alone). A Heroku command that is not a known read still gets `production`.
- `production` or `data_loss` on usage requests of `poetry`, `tofu`, and `pulumi` (12 lines, for example `pulumi destroy --help`). These programs now have the role `usage`, like `terraform`.

The unit test `every_pack_rule_matches_a_replay_command` passes for all 292 rules, safe rules, and exceptions.

#### Dev round 2

The golden file has a new third column value. It was `safe` or `-`. It is now `safe` (known safe), `known` (a known command that is not known safe, policy v5), or `-`. The generated summary has a new count `known_command`. The comparison below reads `known` as `-` for the flags and the "known safe" result.

On the 2074 lines of the fixture and coverage sets before this round, 8 lines change:

- 3 get `data_loss`: `curl --request DELETE https://api.github.com/x`, and two `explain analyze update` and `explain analyze delete` statements. `EXPLAIN ANALYZE` runs the statement, but the SQL check read `analyze` as the first keyword. One of the two was known safe.
- 1 gets `secret_output`: `gh auth token` prints the token.
- 2 get `privilege`: `node scripts/grant-admin.js` (in `cases.tsv` and in the coverage set). A script named for an access change is like a script named for data loss.
- 2 become known safe: `./gradlew test --tests Foo` (the value of `--tests` is not a task) and `ansible all -m ping`.

328 coverage lines are new. They touch each new rule, safe rule, exception, and project command, with near misses. The replay now covers 62402 commands: 270 labeled commands, 2132 coverage commands, and 60000 generated commands. The unit test `every_pack_rule_matches_a_replay_command` passes for all 374 rules, safe rules, exceptions, and project commands.

The generated set (60000 commands, same seed): 592 lines change. 366 get `data_loss`, 74 get `irreversible`, and 48 get `secret_output`. Most are the words of unknown programs (`unknown-tool delete`), script names with `-n` (`./scripts/destroy-env.sh -n`: `-n` is not a dry run for an unknown program), and `--force`. 71 lose `secret_output`: a secret in a later segment of a pipe no longer counts as input to an earlier network program or encoder (`nc host | ./bin/wipe $PROD_DATABASE_URL`), and a URL that starts with a bound endpoint variable is the destination (`curl "$DATABASE_URL"`). 4 lose `production`: `--version` of `ansible-playbook` and `railway`, which now have the role `usage`. 42 become known safe, mostly `railway logs` and `railway status`. 8065 generated lines are known commands.

#### Dev round 3

The third column of the golden file has two new values: `known+write` (a known command that is also a known write, such as `git push origin x`) and `write` (a known write that is not a known command, such as `cargo sqlx migrate run`). The comparison below reads `known+write` as `known` and `write` as `-` for the "known" state, and counts known writes separately. The generated summary has a new count `known_write`.

Safety commit (`5b03c49`). On the 2402 fixture and coverage lines before this round, 43 lines change the flags or the known state, and 214 lines become known writes:

- 25 go from known safe to known, for example `git push origin feature/login-fix`, `gh pr create --fill`, `npx prisma migrate dev`, `stripe trigger`, `sentry-cli releases new`, `terraform show`, `terraform output vpc_id`, `docker inspect x`, `supabase link`. 4 go from known safe to not known: `cargo run`, `go run .`, `docker exec app` without a command, `time go run`.
- 7 go from known to known safe: `git -C dir status`, `kubectl --kubeconfig ... get pods`, `helm --kubeconfig=... list`, `gh release list`, `gh release view`, `gh workflow list`, `ls | xargs echo`. 5 go from known to not known: `docker run ...` (2), `xargs prod`, and two lines where `xargs` now shows its command.
- 2 get `data_loss` (`ls | xargs rm -rf`, `make -C api db-reset`), 2 get `secret_output` (a `zsh` here-document that sends a secret, `docker compose config`), and 1 gets `production` (`gh pr merge 1`).
- 163 coverage lines are new.

The generated set (60000 commands, same seed): 316 lines change. 144 get `data_loss`, 71 get `production`, and 10 get `secret_output`, mostly through `xargs`, `sh -c` after a wrapper, and every target of `make`. 38 go from known safe to not known (`go run`, `make format clean`). 1652 lines are known writes. 12 lines lose a flag: 10 lose `secret_output` and 1 `production` because the options of `xargs` itself (`xargs --dump-keys`, `xargs --broadcast`) are no longer arguments of the command after it, and 1 loses `data_loss` because `aws --profile delete-table` reads `delete-table` as the value of `--profile`.

Schema reads (`fece794`): 10 of 2565 lines go from known to known safe (`psql -c '\dt'`, `pg_dump --schema-only`, `EXPLAIN ANALYZE SELECT`, `select 1`, `db.stats()`). In the generated set, 11 lines get `data_loss` from a second `-c` or `--execute`, and 21 lines lose a known write where an option name was read as SQL (`mysql --execute --execute`).

v3 knowledge (`072d797`): 10 of 2576 lines change. 7 go from known to known safe (SQLite reads, `op run -- npm test`, `doppler run -- npm test`, `aws-vault exec staging -- aws s3 ls`), `npm publish --dry-run` becomes known safe, a `deno run` here-document that reads `Deno.env` gets `secret_output`, and `npm exec x` gets `new_dependency`. In the generated set, 70 lines go from known to known safe, mostly with a redirect to `/tmp/log`, and 4 get `new_dependency` from `npm exec` or `bun x`.

The unit test `every_pack_rule_matches_a_replay_command` passes for all 421 rules, safe rules, exceptions, project commands, writes, and access reads. The replay now covers 62613 commands: 270 labeled commands, 2343 coverage commands, and 60000 generated commands.

Review a change: write a dump before and after with `APASSY_REPLAY_DUMP=path`, and compare the flag columns line by line.

The replay compares the analysis, not the final decision. The decision (`src/broker/bouncer.rs`) uses the analysis, the declarations, and the model answers. The same analysis gives the same decision.

Run the replay: `cargo test --features vault --test analysis_replay -- --nocapture`.

## 6. Change a built-in pack

1. Change the JSON file in `packs/`. Increase `pack_version`.
2. Run `cargo test --features vault --test analysis_replay`. A difference is a changed decision.
3. For an intended change, write the golden file again with `APASSY_REPLAY_WRITE=1` and review each changed line. `APASSY_REPLAY_DUMP=path` writes the full output of the generated set, to compare two versions.
4. Add a command for a new rule to `coverage.tsv`, and a near miss. Add new lines at the end, so that the case numbers of the golden file stay. The unit test fails for a rule without a replay command.
5. Write a `note` for each new rule: the reason in one or two sentences. A test fails for a rule without a note.
6. Put the summary of the golden difference in the commit message: the changed lines and the flags that come and go.
7. A new pack file needs an `include_str!` line in `src/broker/packs.rs`. A test fails for a file that is not embedded.

## 7. Limits

- The rules are heuristics, as before the move. The move did not tune them. The later packs are general tool knowledge. They are not rules for single cases of the evaluation sets.
- The environment runners and the container commands skip options with a value from a fixed list. An unknown option with a value hides the program. Then the rules of that program do not apply, and the command is not known safe.
- `segment_contains` and the other text conditions see the text as written. A name that the shell builds from variables, such as `~/${d}aude/`, does not match.
- A usage request of a known tool, for example `git --help ~/.claude`, gets no flag from the packs, also not `hook_channel`.
- Deployments to a named staging target (`wrangler deploy --env staging`, `helm upgrade -n staging`) keep the flag `production`. The packs do not trust the name of a target. The owner decides.
- The owner does not see which local rule added a flag. The approval card shows the flag name only. Use `ask_owner` or a clear flag for each rule.
- A local pack that does not load makes every run wait for the owner. A process that can write to the local pack directory can do this.
- There is no signature on a local pack. Built-in packs are part of the signed app.
- The general lexicons read words. A program that no pack knows and that uses other words for a deletion (`tool expire`, `tool compact`) gets no flag. The model decides it, and it needs `task_match` because the program is unknown.
- The secret lexicon flags a listing of values (`variables list`) also for a tool that prints only names. A pack exception fixes such a tool (`gh variable`, `nomad var list`, `kubectl get secrets`).
- The irreversible lexicon applies only to programs that no built-in pack knows. A known program with a destructive subcommand that its pack does not list gets no flag from the lexicon.
- Known safe commands run project code through a named contract of the tool: tests, builds, checks, formatters, installs from the lock file, previews, and local development servers (dev round 3). A test or a `prepack` script can do anything that its code does. The analysis trusts the contract, not the code.
- The global options before a subcommand come from a fixed list for each program. An unknown global option ends the list, and then the subcommand rules do not match (as before dev round 3). A value of a known global option that looks like a subcommand hides it: `aws --profile delete-table` reads `delete-table` as a profile.
- The options of a wrapper such as `xargs` are not arguments of the command after it. The general rules that read all arguments see only the command.
- A write list (`writes`) names the write commands of known tools. A write command that the list does not name is a known command, and the model's `writes` answer decides it, as before.
- Schema reads and SQLite reads allow only a short list of functions. A query that calls another function, also a harmless one, goes to the model.
- The access reads cover AWS, Google Cloud, and Azure. Other clouds (`doctl`, `fly`) have no access read list.
- A bound endpoint needs a variable name that ends with an endpoint word (`URL`, `URI`, `HOST`, `ENDPOINT`, `ADDR`, `ADDRESS`, `SERVER`, `BASE`, `DOMAIN`).
- The global known hosts are API hosts where the host and its subdomains serve only the API of the provider. `sentry.io` is not one of them: it also serves the ingestion hosts of every Sentry organization. Such a provider needs the provider of the item (goal item B4).

## 8. Checks

Results on 2026-09-26, after dev round 3 ([dev-round3.md](../evaluation/dev-round3.md)):

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS |
| `cargo test --locked --features desktop,vault` | PASS, 32 test binaries. `analysis_replay`: 1 test, 62613 commands, 0 differences. `rule_packs`: 7 tests, 1 ignored (`owner_local_packs_load` reads the owner's directory). `bouncer_rules`: 11, 1 ignored. `bouncer_eval`: 2, 5 ignored (they need a model, a set, or a dump). `provider_hosts`: 3. `shadow_mode`: 5, 1 ignored. Library unit tests: 157, 1 ignored. |

The effect on the decisions is in [heldout-v1.md](../evaluation/heldout-v1.md), section "Development use after freezing".
