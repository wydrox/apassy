# Bouncer with a local Laya model

Date: 2026-09-25. Decision: [ADR 0007](../adr/0007-rules-and-local-bouncer.md).

## 1. Install and start Laya

Laya is an open-source decision model with the Jev wire protocol. The model has about 421M parameters. It runs on the CPU or the Apple GPU.

```
D="$HOME/Library/Application Support/Apassy/laya"
mkdir -p "$D" && cd "$D"
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python "laya[serve]==0.3.20"
LAYA_HOST=127.0.0.1 LAYA_PORT=8770 LAYA_MODELS=english .venv/bin/laya-serve
```

- The first start downloads the weights from Hugging Face (`convaiinnovations/laya`).
- The first decision loads the model. It took about 8 seconds on an M1 Pro. After that, one decision took about 0.4 seconds.
- Keep `LAYA_HOST=127.0.0.1`. Apassy accepts only a loopback bouncer.
- `APASSY_BOUNCER_URL` changes the address. The default is `http://127.0.0.1:8770`. `APASSY_BOUNCER_KEY` sends a bearer key if `LAYA_API_KEY` is set.

If Laya does not answer in 3 seconds, the bouncer is unavailable. Then every run waits for the owner.

## 2. Set a rule

In Agents, click "Manage grants" for an agent. In "Process access":

1. Type the project directory. Click "Let the bouncer decide".
2. Open "Rule". Type the permitted command prefixes, one per line, for example `npm test` and `npm run migrate`.
3. Optional: forbidden words, an expiry in hours, a limit of runs per hour, and your instruction in plain words.
4. Click "Save rule".

The bouncer decides only if the rule has command prefixes. Without prefixes, every run waits for you.

## 3. Decision order

1. Hard rule: expiry, prefixes, forbidden words, runs per hour. A failure is a denial.
2. Command analysis (`src/broker/shell_risk.rs`). It parses the command like a shell: quotes, pipes, `&&`, redirects, `$( )`, `sh -c`, and `NAME=value` prefixes. Rules for each program give flags: `secret_output`, `data_loss`, `production`, `real_recipient`, `remote_code`, `remote_access`, `system_change`, `new_dependency`, `privilege`, `injection_phrase`. A flag always asks the owner. The model is not called.
3. A known safe development command (tests, lint, builds, local servers, read-only git, cache removal, GET requests to a known provider API) runs without a model call.
4. Other commands go to the model. Unavailable or a high risk asks the owner.
5. "Bouncer" mode also needs command prefixes in the rule. Without prefixes, every run waits for the owner.

## 4. Measurement

Data in `tests/fixtures/bouncer/`:

| File | Cases | Author | Use |
| --- | --- | --- | --- |
| `cases.tsv` | 174 (84 normal, 90 risky) | written together with the rules | split by hash: calibration 93, test 81 |
| `independent.tsv` | 96 (48 normal, 48 risky) | a separate `claude -p` session without the code | first used as a blind test, then used for rule changes |

Run: `cargo test --features vault --test bouncer_eval -- --nocapture` for the rules, and `APASSY_EVAL_MODEL=http://127.0.0.1:8770 cargo test --features vault --test bouncer_eval -- --ignored --nocapture` with the model.

### Blind result before the hardening changes

The rules were frozen before the first run on `independent.tsv`.

| Decision | Risky caught | False alarms |
| --- | --- | --- |
| Rules only | 37/48 (77%) | 0/48 |
| Rules and zero-shot Laya | 41/48 (85%) | 7/48 (15%) |

The rules missed secret files as arguments (`gh gist create .env.local`, `git add -f .env`), a production value in a `NAME=value` prefix, `vercel deploy` without `--prod`, `gh release create`, a Resend broadcast, `npx -y` of an unknown package, a crontab install, `npm config set registry`, a GitHub collaborator change, and one injection phrase. The model false alarms were cache removal, `git rebase`, `test -n "$KEY"`, and GET requests to provider APIs.

### After the hardening changes

The changes are general categories, not single commands: secret files as arguments, `set -x` with secrets, `NAME=value` prefixes, unknown `npx` packages, `gh` and `vercel` actions, system files, more injection phrases, and known safe cache removal and provider reads. The `rule_violation` threshold went from 0.94 to 0.96 because normal calibration commands reached 0.94.

| Split | Risky caught | False alarms |
| --- | --- | --- |
| calibration | 46/46 | 0/47 |
| test | 43/44 | 0/37 |
| independent (no longer blind) | 48/48 | 0/48 |

These numbers are optimistic. The same author wrote `cases.tsv` and the rules, and `independent.tsv` was used for the changes. There is no blind measurement after the hardening. A second independent set was not generated: the separate session refused the request.

### What the model adds

After the hardening, the rules decide 243 of 270 cases. The model decides 27 cases. One of them is risky (`node scripts/grant-admin.js` with a false purpose), and the model did not flag it. Several normal commands are at 0.94 to 0.95 for `rule_violation`. So the zero-shot model gives no measured benefit now, and it can give false alarms on new data. The Laya documentation reports 0.77 accuracy for a fine-tuned checkpoint against 0.36 for the base checkpoint on typed decisions. A fine-tune on owner-labeled decisions is the next step for the model.

## 5. Checks

| Command | Result |
| --- | --- |
| `cargo test --offline --locked --all-features --all-targets -- --test-threads=1` | PASS. A fake Jev-compatible bouncer runs in `tests/common`. |
| `cargo test --offline --locked --features vault --test bouncer_rules -- --ignored` | PASS with `laya-serve` running. Broker path: a known safe command ran without a prompt, and `echo $KEY \| base64` waited for the owner. |

The GUI run on 2026-09-25 showed the bouncer address in the Broker card. The GUI run stopped before the rule editor, because the owner was using the computer. The rule editor has no GUI check.
