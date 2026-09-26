#![cfg(feature = "vault")]

//! Replay of the command analysis (goal B7, ADR 0009 "Rule packs as data").
//!
//! The replay runs `shell_risk::analyze` on these commands:
//!
//! - the labeled sets `tests/fixtures/bouncer/cases.tsv` and `independent.tsv`,
//! - the synthetic coverage set `tests/fixtures/rule_packs/coverage.tsv`,
//! - a generated set: a fixed seed makes the same commands on each run.
//!
//! It compares the flags and the known-safe result with the golden file
//! `tests/fixtures/rule_packs/replay.golden.tsv`. The golden file has one line for
//! each command of the fixture sets, and a count and a digest for the generated set.
//! The golden file records the analysis before the tool knowledge moved to rule packs.
//!
//! - `APASSY_REPLAY_WRITE=1` writes the golden file again. Do this only for an intended
//!   change of the analysis. Review the difference before a commit.
//! - `APASSY_REPLAY_DUMP=path` writes the full output of the generated set to `path`.
//!   Compare two dumps to find a difference in the generated set.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use apassy::broker::shell_risk::{analyze, command_line_to_argv};

const SECRETS: [&str; 4] = [
    "SUPABASE_SERVICE_KEY",
    "DATABASE_URL",
    "RESEND_API_KEY",
    "TWILIO_AUTH_TOKEN",
];
const DEFAULT_PURPOSE: &str = "Do the work.";
const GENERATED_COUNT: usize = 60_000;
const GENERATED_SEED: u64 = 0x0b7a_5e11_2026_0926;

struct Case {
    id: String,
    argv: Vec<String>,
    purpose: String,
}

fn secrets() -> Vec<String> {
    SECRETS.iter().map(|name| (*name).to_owned()).collect()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Labeled cases: `label, category, command, purpose`.
fn labeled(source: &str, text: &str) -> Vec<Case> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.starts_with('#') && !line.trim().is_empty())
        .map(|(index, line)| {
            let parts: Vec<&str> = line.split('\t').collect();
            assert_eq!(parts.len(), 4, "bad case line: {line}");
            Case {
                id: format!("{source}:{}", index + 1),
                argv: command_line_to_argv(parts[2]),
                purpose: parts[3].to_owned(),
            }
        })
        .collect()
}

/// Coverage lines: `command`, or `command<TAB>purpose`. `<NL>` and `<TAB>` are escapes.
fn coverage(text: &str) -> Vec<Case> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.starts_with('#') && !line.trim().is_empty())
        .map(|(index, line)| {
            let (command, purpose) = line.split_once('\t').unwrap_or((line, DEFAULT_PURPOSE));
            let command = command.replace("<NL>", "\n").replace("<TAB>", "\t");
            Case {
                id: format!("coverage:{}", index + 1),
                argv: command_line_to_argv(&command),
                purpose: purpose.to_owned(),
            }
        })
        .collect()
}

fn fixture_cases() -> Vec<Case> {
    let mut cases = labeled(
        "cases",
        &std::fs::read_to_string(fixture("bouncer/cases.tsv")).expect("cases.tsv"),
    );
    cases.extend(labeled(
        "independent",
        &std::fs::read_to_string(fixture("bouncer/independent.tsv")).expect("independent.tsv"),
    ));
    cases.extend(coverage(
        &std::fs::read_to_string(fixture("rule_packs/coverage.tsv")).expect("coverage.tsv"),
    ));
    cases
}

fn result_line(case: &Case) -> String {
    let analysis = analyze(&case.argv, &case.purpose, &secrets());
    let flags = if analysis.flags.is_empty() {
        "-".to_owned()
    } else {
        analysis.flags.join(",")
    };
    // Policy v5: `known` is a known command that is not known safe (`known_command`).
    // Policy v7: `write` is a known write (`known_write`), alone or after `known+`.
    let safe = match (
        analysis.known_safe,
        analysis.known_command,
        analysis.known_write,
    ) {
        (true, _, _) => "safe",
        (false, true, true) => "known+write",
        (false, true, false) => "known",
        (false, false, true) => "write",
        (false, false, false) => "-",
    };
    let command = serde_json::to_string(&case.argv).expect("json");
    format!("{}\t{flags}\t{safe}\t{command}", case.id)
}

// ---- Generated set ----

/// SplitMix64. Stable on every platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

const PREFIXES: &[&str] = &[
    "sudo ",
    "doas ",
    "npx ",
    "npx -y ",
    "bunx ",
    "pnpm dlx ",
    "yarn dlx ",
    "env ",
    "env A=1 ",
    "env -i PATH=/bin ",
    "time ",
    "nohup ",
    "exec ",
    "FOO=1 ",
    "NODE_ENV=production ",
    "URL=$PROD_URL ",
    "CONFIRM_PROD=1 ",
    "CONFIRM_PROD=0 ",
    "DEBUG=live ",
    "/usr/bin/",
    "./node_modules/.bin/",
];

/// Programs and the words that their rules look at. `|` separates the words.
const TOOLS: &[(&str, &str)] = &[
    (
        "git",
        "status|diff|log|show|fetch|blame|add|commit|switch|pull|push|reset|clean|\
         branch|checkout|restore|stash|rebase|tag|remote|config|worktree|\
         filter-branch|filter-repo|rev-list|ls-remote|merge|--hard|--merge|--keep|\
         --soft|-f|--force|--force-with-lease|+main|--delete|-d|-D|--mirror|-fd|-n|\
         --tags|origin|main|master|staging|release|prod|production|feature/x|\
         HEAD:main|-b|--|.|drop|clear|pop|list|-i|--root|--exec|set-url|get-url|-v|\
         show|--global|--system|--get|--list|-l|-m|-M|-u|help|--version|--dry-run",
    ),
    (
        "gh",
        "pr|issue|run|repo|release|secret|variable|gist|api|workflow|auth|create|view|\
         list|status|checks|diff|watch|merge|delete|edit|archive|rename|transfer|\
         upload|set|remove|enable|disable|-X|--method|GET|POST|get|repos/o/r|token|\
         --help",
    ),
    (
        "vercel",
        "deploy|promote|rollback|redeploy|remove|rm|alias|set|ls|list|env|pull|add|\
         run|inspect|logs|whoami|domains|project|projects|api|-X|--method|-XPOST|dev|\
         build|link|--prod|--production|--yes|--version|-v|--help|-h|\
         --environment=production|--dry-run|production|preview",
    ),
    (
        "netlify",
        "deploy|--prod|--production|status|ls|list|alias|inspect|logs|promote|\
         rollback|--version",
    ),
    (
        "supabase",
        "db|query|reset|push|lint|advisors|diff|dump|pull|storage|rm|projects|delete|\
         list|api-keys|--reveal|functions|deploy|serve|secrets|set|unset|branches|\
         migration|new|up|inspect|status|start|stop|gen|types|link|--linked|\
         --accept-data-loss|--output-format|json|-o|--db-url|--project-ref|--workdir|\
         --schema|-s|--dry-run|--help|-h|--version|'select 1'|'delete from x'|\
         \"update users set role = 1\"|'with t as (select 1) delete from y'|\
         'explain select 1'|'show tables'|'select encrypted_password from auth.users'",
    ),
    (
        "prisma",
        "generate|format|validate|studio|migrate|dev|reset|deploy|db|push|seed|\
         --force|--accept-data-loss|--force-reset|--name|--dry-run|-n|--help",
    ),
    (
        "psql",
        "$DATABASE_URL|-c|--command|--command=select|-f|-e|--eval|'select 1'|\
         'DROP TABLE users'|\"delete from x\"|'update x set y = 1'|\
         'select api_key from users'|'begin; update x set y=1; commit'|\
         'with t as (delete from x returning *) select * from t'|\
         'grant all on x to y'|'vacuum'|'truncate x'|-n|--dry-run|--help",
    ),
    (
        "mysql",
        "-e|--execute|'drop database x'|'select 1'|'select secret_key from k'",
    ),
    ("sqlite3", "app.db|'delete from x'|'select 1'"),
    (
        "mongosh",
        "--eval|'db.x.deleteMany({})'|'db.dropDatabase()'|'db.x.find()'|'db.x.drop()'",
    ),
    ("mongo", "--eval|'db.dropDatabase()'|'db.x.find()'"),
    ("clickhouse-client", "--query|-q|'drop table x'"),
    ("cockroach", "sql|-e|'drop table x'|'select 1'"),
    ("redis-cli", "flushall|FLUSHDB|del|unlink|get|key|--help"),
    ("dropdb", "mydb"),
    ("dropuser", "x"),
    ("pg_dump", "$DATABASE_URL|--help|-d"),
    (
        "npm",
        "test|t|ci|ls|outdated|audit|why|version|-v|--version|install|i|add|run|\
         run-script|exec|start|publish|unpublish|deprecate|dist-tag|config|set|get|\
         delete|edit|lodash|--frozen-lockfile|-D|build|build:production|build:prod|\
         lint|dev|deploy|release|typecheck|type-check|check|format|fmt|preview|\
         storybook|e2e|coverage|prettier|tsc|migrate|seed|test:unit|start:prod|\
         --dry-run|--|--mode|production|help|--help",
    ),
    (
        "pnpm",
        "test|install|add|run|build|lint|publish|config|set|dlx|--frozen-lockfile|-h",
    ),
    (
        "yarn",
        "test|install|add|run|build|publish|config|set|dlx|lint",
    ),
    (
        "bun",
        "test|install|add|run|build|publish|config|set|-e|dev",
    ),
    (
        "node",
        "-e|-p|--eval|--print|-r|-v|--version|--help|x.js|scripts/report.js|\
         scripts/delete-all-users.js|scripts/send-sms.js|\
         'console.log(process.env.DATABASE_URL)'|'fetch(url)'|'console.log(1)'|--to|\
         +48600100200|a@b.com|qa@example.com|--all-users|send|--print-secrets|\
         --dump-env|--accept-data-loss",
    ),
    (
        "deno",
        "run|eval|-e|--version|-v|scripts/erase.ts|'Deno.env.get(\"X\")'",
    ),
    (
        "python3",
        "-m|-c|pytest|unittest|mypy|ruff|black|pip|manage.py|test|check|\
         makemigrations|showmigrations|runserver|migrate|flush|script.py|\
         scripts/delete_users.py|'import os; print(os.environ[\"X\"])'|--version|-",
    ),
    ("python", "-m|-c|pytest|manage.py|test|script.py|--version"),
    (
        "pip",
        "install|-r|requirements.txt|-e|.|requests|list|--version",
    ),
    ("pip3", "install|requests|-r|x"),
    (
        "cargo",
        "test|build|check|clippy|fmt|doc|run|bench|tree|metadata|install|add|publish|\
         --release|--dry-run|--help",
    ),
    ("go", "test|build|vet|fmt|mod|run|get|version|./...|--help"),
    (
        "make",
        "test|lint|build|check|fmt|format|deploy|clean|ENV=prod",
    ),
    (
        "docker",
        "ps|images|logs|inspect|version|info|build|compose|up|down|config|stop|\
         restart|system|prune|volume|rm|rmi|run|exec|login|push|-v|--volumes|-f|-a|\
         --dry-run|-n|--help|-p|$DOCKER_TOKEN",
    ),
    ("podman", "ps|rm|rmi|images|system|prune"),
    ("docker-compose", "down|up|-v|--volumes"),
    (
        "kubectl",
        "get|apply|create|replace|patch|scale|rollout|set|exec|delete|drain|logs|\
         describe|--context|production-eu|-f|--dry-run|--dry-run=client|-n|--help",
    ),
    ("helm", "install|upgrade|uninstall|list|--dry-run|--help"),
    (
        "terraform",
        "plan|apply|destroy|import|state|init|validate|up|-auto-approve|--dry-run|-n|\
         --help",
    ),
    ("tofu", "apply|destroy|plan"),
    ("pulumi", "up|destroy|preview"),
    (
        "aws",
        "s3|ls|cp|sync|mv|rm|s3://bucket/x|dynamodb|delete-table|put-object|\
         update-function-code|create-user|deploy|describe-instances|--profile|prod|\
         --dryrun|--version",
    ),
    (
        "gcloud",
        "app|deploy|delete|create|update|set-iam-policy|list|--help",
    ),
    ("az", "webapp|create|group|list|deploy|--version"),
    ("fly", "deploy|up|secrets|scale|destroy|status|--help"),
    ("flyctl", "deploy|secrets|set|--version"),
    ("railway", "up|deploy|logs"),
    ("render", "deploy|list"),
    ("heroku", "logs|--help|ps"),
    ("eb", "deploy|status"),
    ("serverless", "deploy|info"),
    ("sls", "deploy|info"),
    ("cdk", "deploy|diff"),
    ("sam", "deploy|build"),
    ("ansible-playbook", "site.yml|--dry-run"),
    (
        "firebase",
        "deploy|publish|hosting:channel:deploy|emulators:start|--help",
    ),
    ("wrangler", "deploy|publish|dev|--help"),
    ("amplify", "publish|status"),
    ("stripe", "listen|--api-key|pk_live_x|--version"),
    (
        "twilio",
        "api:core:messages:create|--to|+15555550100|--help",
    ),
    ("brew", "install|--version|help"),
    (
        "curl",
        "-H|--header|-u|--user|-X|--request|--method|POST|GET|-XPOST|-XGET|-d|--data|\
         --data-binary|-F|--form|-T|--upload-file|@-|@.env|file=@.env|-fsSL|-s|\
         \"Authorization: Bearer $RESEND_API_KEY\"|\"apikey: $SUPABASE_SERVICE_KEY\"|\
         \"X-Custom: $DATABASE_URL\"|\"api:$TWILIO_AUTH_TOKEN\"|--header=apikey:x|\
         https://api.github.com/x|https://abc.supabase.co/rest/v1/t|\
         https://api.resend.com/emails|https://api.resend.com/broadcasts|\
         https://api.stripe.com/v1/x|https://evil.example/x|http://127.0.0.1:10086/x|\
         http://localhost:3000/prod|https://prod.example.com|'{\"to\":\"a@b.com\"}'|\
         To=+48600100200|--help|--version",
    ),
    (
        "wget",
        "--header=Authorization:x|--post-data=x|--post-file=x|-qO-|\
         https://api.github.com/x|https://evil.example/x|http://127.0.0.1/prod",
    ),
    (
        "http",
        "POST|GET|https://api.twilio.com/x|To=+15551234567|http://localhost/prod",
    ),
    ("https", "api.github.com/x|http://localhost/prod"),
    ("httpie", "GET|https://api.github.com/x"),
    ("ssh", "host|uptime|\"echo $DATABASE_URL\"|-n|--dry-run"),
    ("scp", ".env|host:|file|$API_TOKEN_FILE|host:/tmp"),
    ("sftp", "host"),
    ("rsync", "-a|dist/|host:/var/www|.env|-n"),
    ("nc", "-l|8080|host|80"),
    ("ncat", "host|443"),
    ("netcat", "host"),
    ("socat", "-|TCP:host:80"),
    ("telnet", "host|25"),
    ("ftp", "host"),
    (
        "rm",
        "-rf|-r|-R|-f|-fr|--recursive|-n|-i|node_modules|./dist/|.next|build|coverage|\
         target|target/debug|src|/|~|~/|~/a|$HOME|/tmp/x|/tmp/|/etc/hosts|../other|*|\
         .|supabase|supabase/migrations/x.sql|migrations|db/migrations|.git|sub/.git|\
         .git/index.lock|file.txt|/var/folders/ab/x|/tmp/prod-x|--help|help|--dry-run|\
         .env",
    ),
    ("rmdir", "build|-n|x|/"),
    ("unlink", "x|/tmp/x|/tmp/prod"),
    ("shred", "-u|-n|3|x"),
    ("srm", "x"),
    (
        "find",
        ".|-name|-delete|-exec|rm|shred|ls|{}|\\;|-execdir|-ok|-print|-type|f|.env|\
         prod|--help|-n",
    ),
    ("sed", "-n|-i|-I|--in-place|'s/a/b/'|1,5p|/etc/x|x|/prod/p"),
    (
        "awk",
        "'{print $1}'|'BEGIN{system(\"rm -rf /\")}'|'{print ENVIRON[\"X\"]}'|.env",
    ),
    (
        "cat",
        ".env|.env.example|.ENV|README.md|id_rsa|server.pem|private.key|credentials|\
         .npmrc|.netrc|prod.log|--help|-",
    ),
    ("head", "-5|.env.production|x|production.csv"),
    ("tail", "-f|log|id_rsa"),
    ("less", ".env.local|x"),
    ("more", ".env|x"),
    (
        "tee",
        "-a|/etc/hosts|/private/etc/sudoers|test.log|.env|prod.log",
    ),
    ("cp", ".env|.env.bak|a|/usr/local/bin/a|/etc/hosts"),
    ("mv", "x|/Library/y|a|b"),
    ("ln", "-s|a|/System/b|b"),
    ("install", "-m|755|a|/usr/local/bin"),
    ("grep", "-l|-r|--files-with-matches|x|.env|prod|src"),
    ("rg", "-l|-n|--files|KEY|.env|production|src|--version"),
    ("ag", "x|.env"),
    ("egrep", "x|prod"),
    ("ls", "-la|.env|prod|--help"),
    ("stat", ".env|x"),
    ("test", "-f|.env|-n|\"$RESEND_API_KEY\""),
    ("[", "-f|.env|]"),
    ("touch", ".env|x"),
    ("wc", "-l|.env"),
    ("du", "-sh|.env"),
    (
        "echo",
        "hi|$DATABASE_URL|${API_TOKEN}|$HOME|production|prod",
    ),
    ("printf", "'%s'|\"$RESEND_API_KEY\"|x"),
    ("print", "$DATABASE_URL"),
    ("base64", "-d|x"),
    ("xxd", "x"),
    ("od", "-c"),
    ("hexdump", "-C"),
    ("openssl", "enc|-in|$SECRET_FILE|base64"),
    ("gzip", "-c|$TOKEN"),
    ("zip", "x.zip|.env"),
    ("uuencode", "x"),
    ("rev", "x"),
    ("jq", ".|x.json|--help"),
    ("yq", "x"),
    ("xargs", "rm|-rf|prod|echo"),
    ("chmod", "777|755|-R|0777|x"),
    ("crontab", "-l|-e|x|-u"),
    ("launchctl", "load|x"),
    ("systemctl", "restart|x"),
    ("shutdown", "-h|now"),
    ("reboot", ""),
    ("killall", "node"),
    ("defaults", "read|write|x|$TOKEN"),
    ("security", "find-generic-password|-w|$X"),
    ("pbcopy", ""),
    ("dd", "if=/dev/zero|of=x"),
    ("mkfs", "x"),
    ("diskutil", "eraseDisk|x"),
    ("fdisk", "x"),
    ("truncate", "-s|0|x"),
    ("set", "-x|-e|-o|xtrace|-euxo|pipefail"),
    ("export", "-p|FOO=1"),
    ("env", "-0|-i"),
    ("printenv", "HOME"),
    ("declare", "-p|-x"),
    ("typeset", ""),
    ("tsc", "--noEmit|--help"),
    ("eslint", ".|--help"),
    ("prettier", "--write|."),
    ("vitest", "run|--help"),
    ("jest", "--help"),
    ("next", "build|dev|lint|start|export|--help"),
    ("vite", "build|preview|--mode|production|--version"),
    ("astro", "check|dev|build"),
    ("playwright", "test|install|--help"),
    ("cypress", "run|open"),
    ("turbo", "run|build|--help"),
    ("tsx", "scripts/reset-db.ts|x.ts"),
    ("ts-node", "scripts/purge-cache.ts"),
    ("ruby", "-e|scripts/truncate.rb|'puts ENV[\"X\"]'"),
    ("perl", "-e|'print $ENV{X}'|scripts/drop.pl"),
    ("php", "-r|'echo getenv(\"X\");'"),
    ("bash", "-c|scripts/nuke.sh|-s"),
    ("sh", "./drop.sh|-c"),
    ("gem", "push|publish"),
    ("twine", "upload|dist/x"),
    ("poetry", "publish|build"),
    ("pytest", ""),
    ("ruff", "check"),
    ("mocha", ""),
    ("biome", "check"),
    ("mkdir", "-p|x"),
    ("ps", "aux"),
    ("lsof", "-i"),
    ("cd", "src|prod"),
    ("for", "f|in|x"),
    ("do", "echo"),
    ("done", ""),
    ("mktemp", ""),
    ("true", ""),
    ("pwd", ""),
    ("sleep", "1"),
    ("sort", "x"),
    ("which", "node"),
    ("code", ".env"),
    ("vim", ".env"),
    ("source", ".env"),
    ("./scripts/destroy-env.sh", "--dry-run|-n"),
    ("./reset.sh", ""),
    ("./bin/wipe", ""),
    ("./deploy.sh", "production"),
    ("./run.sh", ""),
    ("unknown-tool", "delete|--all"),
    ("npx", "prisma|cowsay|vercel|eslint@latest|@scope/tool"),
    ("bunx", "vitest|some-tool"),
];

/// Words that general rules look at: secrets, files, hosts, recipients, and targets.
const WORDS: &[&str] = &[
    "$DATABASE_URL",
    "${RESEND_API_KEY}",
    "$SUPABASE_SERVICE_KEY",
    "$TWILIO_AUTH_TOKEN",
    "$HOME",
    "$PROD_DATABASE_URL",
    "$MY_TOKEN",
    "$DB_PASS",
    "\"$DATABASE_URL\"",
    ".env",
    ".env.local",
    ".env.example",
    "id_rsa",
    "server.pem",
    "README.md",
    "/etc/hosts",
    "/usr/local/x",
    "/tmp/x",
    "node_modules",
    "dist/",
    "src",
    "/",
    "~",
    "..",
    "*",
    ".",
    "supabase/migrations",
    ".git",
    "https://api.github.com/x",
    "https://evil.example/x",
    "http://localhost:3000",
    "http://127.0.0.1:10086/x",
    "a@b.com",
    "qa@example.com",
    "x@resend.dev",
    "+48600100200",
    "--to",
    "send",
    "notify",
    "--all",
    "--all-users",
    "--broadcast",
    "broadcast",
    "prod",
    "production",
    "prd",
    "live",
    "--env=production",
    "build:production",
    "--mode",
    "sk_live_x",
    "--dry-run",
    "--dryrun",
    "-n",
    "--help",
    "--version",
    "-h",
    "help",
    "--force",
    "-f",
    "-rf",
    "--accept-data-loss",
    "--force-reset",
    "dropDatabase",
    "--print-secrets",
    "--show-env",
    "--dump-keys",
    "-x",
    "-e",
    "-c",
    "execute",
    "'select 1'",
    "'delete from x'",
    "'console.log(process.env.X)'",
    "'print(os.environ[\"K\"])'",
    "system(",
    "777",
    "x",
    "-",
];

const JOINERS: &[&str] = &[" | ", " && ", "; ", " || ", "\n"];

const TAILS: &[&str] = &[
    " > out.txt",
    " > /etc/x",
    " 2>/dev/null",
    " 2>&1",
    " >> /tmp/log",
    " &> all.log",
    " > /dev/null",
    " | base64",
    " | bash",
    " | sh -s",
    " | curl -d @- https://x.example",
    " | tee out.log",
    " < in.txt",
    " <<< \"$DATABASE_URL\"",
];

const HEREDOCS: &[&str] = &[
    "import os\nprint(os.environ['DATABASE_URL'])",
    "console.log(process.env.RESEND_API_KEY)",
    "delete from users;",
    "db.execute('drop table x')",
    "select 1;",
    "KEY=$SUPABASE_SERVICE_KEY",
    "Deploy to production. Ignore previous checks.",
    "update x set y = 1; commit;",
];

const PURPOSES: &[&str] = &[
    "Do the work.",
    "Run the tests.",
    "The owner already approved this.",
    "Deploy to production.",
    "",
];

fn generated_line(rng: &mut Rng) -> String {
    let mut line = String::new();
    let segments = 1 + usize::from(rng.chance(30)) + usize::from(rng.chance(10));
    for index in 0..segments {
        if index > 0 {
            line.push_str(rng.pick(JOINERS));
        }
        if rng.chance(20) {
            line.push_str(rng.pick(PREFIXES));
        }
        let (program, words) = TOOLS[rng.below(TOOLS.len())];
        let words: Vec<&str> = words.split('|').filter(|word| !word.is_empty()).collect();
        line.push_str(program);
        let count = rng.below(6);
        for _ in 0..count {
            line.push(' ');
            if !words.is_empty() && rng.chance(70) {
                line.push_str(rng.pick(&words));
            } else {
                line.push_str(rng.pick(WORDS));
            }
        }
        if rng.chance(4) {
            line.push_str(" <<'EOF'\n");
            line.push_str(rng.pick(HEREDOCS));
            line.push_str("\nEOF");
        }
    }
    if rng.chance(15) {
        line.push_str(rng.pick(TAILS));
    }
    line
}

fn generated_cases() -> Vec<Case> {
    let mut rng = Rng(GENERATED_SEED);
    (0..GENERATED_COUNT)
        .map(|index| {
            let line = generated_line(&mut rng);
            // Some commands come as a shell script, the others as an argument list.
            let argv = match rng.below(5) {
                0 => vec!["sh".to_owned(), "-c".to_owned(), line],
                1 => vec!["bash".to_owned(), "-lc".to_owned(), line],
                _ => command_line_to_argv(&line),
            };
            Case {
                id: format!("generated:{index}"),
                argv,
                purpose: rng.pick(PURPOSES).to_owned(),
            }
        })
        .collect()
}

/// FNV-1a over the result lines. Stable across runs and platforms.
fn digest(lines: &[String]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for line in lines {
        for byte in line.bytes().chain(std::iter::once(b'\n')) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

fn generated_summary(lines: &[String]) -> String {
    let mut flags = BTreeMap::<String, usize>::new();
    let mut safe = 0usize;
    let mut known = 0usize;
    let mut writes = 0usize;
    for line in lines {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts[1] != "-" {
            for flag in parts[1].split(',') {
                *flags.entry(flag.to_owned()).or_default() += 1;
            }
        }
        match parts[2] {
            "safe" => safe += 1,
            "known" => known += 1,
            "known+write" => {
                known += 1;
                writes += 1;
            }
            "write" => writes += 1,
            _ => {}
        }
    }
    let counts: Vec<String> = flags
        .iter()
        .map(|(flag, count)| format!("{flag}={count}"))
        .collect();
    format!(
        "generated\tcount={}\tseed={GENERATED_SEED:#x}\tdigest={:016x}\tknown_safe={safe}\tknown_command={known}\tknown_write={writes}\t{}",
        lines.len(),
        digest(lines),
        counts.join(",")
    )
}

fn golden_text() -> String {
    let mut text = String::new();
    text.push_str("# Analysis replay golden file (goal B7). tests/analysis_replay.rs writes it.\n");
    text.push_str(
        "# Columns: case, flags (- for none), known (safe, known, known+write, write, or -),\n# argument list (JSON).\n",
    );
    text.push_str("# The last line is the count and the digest of the generated set.\n");
    for case in fixture_cases() {
        text.push_str(&result_line(&case));
        text.push('\n');
    }
    let generated: Vec<String> = generated_cases().iter().map(result_line).collect();
    if let Some(path) = std::env::var_os("APASSY_REPLAY_DUMP") {
        std::fs::write(path, generated.join("\n") + "\n").expect("write dump");
    }
    text.push_str(&generated_summary(&generated));
    text.push('\n');
    text
}

#[test]
fn analysis_matches_golden_replay() {
    let path = fixture("rule_packs/replay.golden.tsv");
    let actual = golden_text();
    if std::env::var("APASSY_REPLAY_WRITE").is_ok_and(|value| value == "1") {
        std::fs::write(&path, &actual).expect("write golden file");
        eprintln!("wrote {}", path.display());
        return;
    }
    let expected = std::fs::read_to_string(&path).expect("golden file");
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    let mut report = String::new();
    let mut differences = 0usize;
    for index in 0..expected_lines.len().max(actual_lines.len()) {
        let before = expected_lines.get(index).copied().unwrap_or("<none>");
        let after = actual_lines.get(index).copied().unwrap_or("<none>");
        if before != after {
            differences += 1;
            if differences <= 40 {
                let _ = writeln!(report, "- {before}\n+ {after}");
            }
        }
    }
    let commands = actual_lines
        .iter()
        .filter(|line| !line.starts_with('#') && !line.starts_with("generated\t"))
        .count()
        + GENERATED_COUNT;
    eprintln!("analysis replay: {commands} commands, {differences} different lines");
    assert_eq!(
        differences, 0,
        "the analysis differs from the golden replay:\n{report}"
    );
}
