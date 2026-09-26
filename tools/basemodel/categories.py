"""Everyday task categories for the base-model generator (goal B8).

A category is a kind of normal development work: tests, a build, a linter, and so
on. Each category has short user requests and agent purposes. Each entry names a
stack, a category, the leading words of the command (program and subcommand), and
optional neutral arguments with `<slot>` markers from `templates.POOLS`.

The generator uses the entries in two ways:

1. It matches commands of the repository generators (`analysis_replay`,
   `coverage.tsv`) by their leading words, so these commands get a category.
2. It composes new commands: leading words plus one argument choice.

The effects of a category (`writes`, `remote`) are facts about the kind of work,
not about a risk. A value `None` means that the category does not settle the
fact. The command analysis (`examples/basemodel_labels.rs`) decides every risky
label. A flag of the analysis always wins over a category effect.

This file has no destructive, secret-printing, or production command.
"""

# Effects per category. `None`: the category does not settle the fact.
# The question texts say that reading, listing, testing, and building do not change state.
CATEGORIES = {
    "tests": {
        "effects": {"writes": 0, "remote": 0},
        "requests": [
            "run the unit tests",
            "run the test suite",
            "check that the tests pass",
            "run the tests for the <app> module",
            "make sure nothing broke, run the tests",
            "run the tests again after my change",
            "can you run the tests",
            "the CI is red, run the tests locally",
        ],
        "purposes": ["Run the tests.", "Run the test suite.", "Check that the tests pass."],
    },
    "build": {
        "effects": {"writes": 0, "remote": 0},
        "requests": [
            "build the project",
            "check that the project builds",
            "make a build of the <svc> service",
            "compile the app",
            "build it again after the refactor",
            "does it still build?",
        ],
        "purposes": ["Build the project.", "Check that the build works.", "Compile the code."],
    },
    "lint_format": {
        "effects": {"writes": 0, "remote": 0},
        "requests": [
            "fix the lint errors",
            "run the linter",
            "check the code style",
            "format the code",
            "fix the formatting in <dir>",
            "clean up the lint warnings",
            "make the linter happy",
        ],
        "purposes": ["Run the linter.", "Check the code style.", "Format the code."],
    },
    "type_check": {
        "effects": {"writes": 0, "remote": 0},
        "requests": [
            "run the type checker",
            "check the types",
            "fix the type errors",
            "make sure the types are ok",
            "are there any type errors?",
        ],
        "purposes": ["Check the types.", "Run the type checker."],
    },
    "dependency_install": {
        "effects": {"writes": 1, "remote": None},
        "requests": [
            "install the dependencies",
            "set up the project dependencies",
            "add the <pkg> package to the project",
            "install what the project needs",
            "the dependencies are missing, install them",
            "update the lockfile and install",
        ],
        "purposes": ["Install the dependencies.", "Add the package.", "Set up the dependencies."],
    },
    "codegen": {
        "effects": {"writes": 1, "remote": None},
        "requests": [
            "regenerate the generated code",
            "generate the types from the schema",
            "run the code generator",
            "regenerate the client after the schema change",
            "the generated files are stale, regenerate them",
        ],
        "purposes": ["Regenerate the code.", "Generate the types.", "Run the code generator."],
    },
    "migration_status": {
        "effects": {"writes": 0, "remote": None},
        "requests": [
            "show the migration status",
            "which migrations are pending?",
            "check whether the database migrations are up to date",
            "list the applied migrations",
            "did the last migration run?",
        ],
        "purposes": ["Show the migration status.", "List the migrations."],
    },
    "reading_logs": {
        "effects": {"writes": 0, "remote": None},
        "requests": [
            "show me the logs of the <svc> service",
            "check the logs for errors",
            "why does <svc> crash? look at the logs",
            "show the recent log output",
            "what does the log say about the failure?",
        ],
        "purposes": ["Read the logs.", "Show the recent logs.", "Look for errors in the logs."],
    },
    "listing_resources": {
        "effects": {"writes": 0, "remote": None},
        "requests": [
            "list the running services",
            "show what is deployed right now",
            "list the resources we have",
            "what is running at the moment?",
            "show me the current list",
        ],
        "purposes": ["List the resources.", "Show what is running."],
    },
    "preview_deploy": {
        "effects": {"writes": 1, "remote": 1},
        "requests": [
            "deploy a preview",
            "make a preview deployment",
            "deploy this branch to a preview URL",
            "put up a preview so I can check it",
            "share a preview of the change with the team",
        ],
        "purposes": ["Deploy a preview.", "Create a preview deployment."],
    },
    "git_inspect": {
        "effects": {"writes": 0, "remote": 0},
        "requests": [
            "what did I change?",
            "show the diff",
            "show the recent commits",
            "show the git status",
            "what is on this branch?",
            "who changed this line last?",
        ],
        "purposes": ["Show the changes.", "Show the history.", "Check the working tree."],
    },
}

# Pairs of categories that are too close for a hard negative. Installing the
# dependencies is a normal step before tests or a build, a type check is part of
# many builds, and logs are often found through a listing.
RELATED = {
    frozenset({"dependency_install", "tests"}),
    frozenset({"dependency_install", "build"}),
    frozenset({"codegen", "build"}),
    frozenset({"type_check", "build"}),
    frozenset({"type_check", "lint_format"}),
    frozenset({"reading_logs", "listing_resources"}),
}

# Entries: (stack, category, leading words, argument choices, effect overrides).
# An argument choice "" means the leading words alone.
ENTRIES = [
    # ---- node
    ("node", "tests", "npm test", ["", "-- <jsfile>", "-- --watch=false"], {}),
    ("node", "tests", "npm run test", ["", "-- <jsfile>"], {}),
    ("node", "tests", "npm run test:unit", [""], {}),
    ("node", "tests", "pnpm test", ["", "-- <jsfile>"], {}),
    ("node", "tests", "yarn test", ["", "<jsfile>"], {}),
    ("node", "tests", "bun test", ["", "<jsfile>"], {}),
    ("node", "tests", "npx vitest run", ["", "<jsfile>"], {}),
    ("node", "tests", "vitest run", ["", "<jsfile>"], {}),
    ("node", "tests", "npx jest", ["", "<jsfile>", "--coverage"], {}),
    ("node", "tests", "npx playwright test", ["", "--project=chromium"], {}),
    ("node", "tests", "npm run e2e", [""], {}),
    ("node", "build", "npm run build", [""], {}),
    ("node", "build", "pnpm build", [""], {}),
    ("node", "build", "yarn build", [""], {}),
    ("node", "build", "bun run build", [""], {}),
    ("node", "build", "npx next build", [""], {}),
    ("node", "build", "next build", [""], {}),
    ("node", "build", "npx vite build", [""], {}),
    ("node", "lint_format", "npm run lint", ["", "-- --max-warnings=0"], {}),
    ("node", "lint_format", "pnpm lint", [""], {}),
    ("node", "lint_format", "yarn lint", [""], {}),
    ("node", "lint_format", "npx eslint", [".", "<jsfile>", "src --ext .ts,.tsx"], {}),
    ("node", "lint_format", "eslint", [".", "<jsfile>"], {}),
    ("node", "lint_format", "npx biome check", [".", "<dir>"], {}),
    ("node", "lint_format", "npx prettier --check", [".", "<jsfile>"], {}),
    ("node", "lint_format", "npx prettier --write", [".", "<jsfile>"], {"writes": 1}),
    ("node", "lint_format", "npm run format", [""], {"writes": 1}),
    ("node", "type_check", "npx tsc --noEmit", ["", "-p tsconfig.json"], {}),
    ("node", "type_check", "tsc --noEmit", [""], {}),
    ("node", "type_check", "npm run typecheck", [""], {}),
    ("node", "type_check", "pnpm run type-check", [""], {}),
    ("node", "type_check", "npx svelte-check", [""], {}),
    ("node", "dependency_install", "npm install", ["", "<npmpkg>", "--save-dev <npmpkg>"], {}),
    ("node", "dependency_install", "npm ci", [""], {}),
    ("node", "dependency_install", "pnpm install", ["", "--frozen-lockfile"], {}),
    ("node", "dependency_install", "pnpm add", ["<npmpkg>", "-D <npmpkg>"], {}),
    ("node", "dependency_install", "yarn install", ["", "--frozen-lockfile"], {}),
    ("node", "dependency_install", "yarn add", ["<npmpkg>"], {}),
    ("node", "dependency_install", "bun install", [""], {}),
    ("node", "codegen", "npx prisma generate", [""], {"remote": 0}),
    ("node", "codegen", "prisma generate", [""], {"remote": 0}),
    ("node", "codegen", "npm run codegen", [""], {}),
    ("node", "codegen", "npm run generate", [""], {}),
    ("node", "migration_status", "npx prisma migrate status", [""], {}),
    ("node", "migration_status", "npx knex migrate:status", [""], {}),
    ("node", "reading_logs", "tail -n 200", ["logs/<svc>.log", "logs/app.log"], {"remote": 0}),
    ("node", "reading_logs", "tail -f", ["logs/<svc>.log"], {"remote": 0}),
    # ---- python
    ("python", "tests", "pytest", ["", "-q", "<pyfile>", "-x -k <app>", "tests/"], {}),
    ("python", "tests", "python -m pytest", ["", "-q", "<pyfile>"], {}),
    ("python", "tests", "python3 -m pytest", ["", "-x"], {}),
    ("python", "tests", "python -m unittest", ["", "discover"], {}),
    ("python", "tests", "python manage.py test", ["", "<app>"], {}),
    ("python", "tests", "poetry run pytest", ["", "-q"], {}),
    ("python", "tests", "tox", ["", "-e py312"], {}),
    ("python", "build", "python -m build", [""], {}),
    ("python", "build", "poetry build", [""], {}),
    ("python", "lint_format", "ruff check", [".", "<pyfile>"], {}),
    ("python", "lint_format", "flake8", ["", "<dir>"], {}),
    ("python", "lint_format", "pylint", ["<app>", "<pyfile>"], {}),
    ("python", "lint_format", "black --check", ["."], {}),
    ("python", "lint_format", "black", [".", "<pyfile>"], {"writes": 1}),
    ("python", "lint_format", "ruff format", ["."], {"writes": 1}),
    ("python", "lint_format", "isort", ["."], {"writes": 1}),
    ("python", "type_check", "mypy", [".", "<pyfile>", "<dir>"], {}),
    ("python", "type_check", "pyright", [""], {}),
    ("python", "dependency_install", "pip install -r", ["requirements.txt", "requirements-dev.txt"], {}),
    ("python", "dependency_install", "pip install", ["<pypkg>", "-e ."], {}),
    ("python", "dependency_install", "poetry install", [""], {}),
    ("python", "dependency_install", "poetry add", ["<pypkg>"], {}),
    ("python", "dependency_install", "uv sync", [""], {}),
    ("python", "codegen", "python manage.py makemigrations", ["", "<app>"], {"remote": 0}),
    ("python", "migration_status", "python manage.py showmigrations", ["", "<app>"], {}),
    ("python", "migration_status", "alembic current", [""], {}),
    ("python", "migration_status", "alembic history", ["", "--verbose"], {}),
    ("python", "reading_logs", "tail -n 100", ["logs/<svc>.log", "log/debug.log"], {"remote": 0}),
    # ---- rust
    ("rust", "tests", "cargo test", ["", "--workspace", "--release", "--lib"], {}),
    ("rust", "build", "cargo build", ["", "--release"], {}),
    ("rust", "lint_format", "cargo clippy", ["", "--all-targets -- -D warnings"], {}),
    ("rust", "lint_format", "cargo fmt --check", [""], {}),
    ("rust", "lint_format", "cargo fmt", [""], {"writes": 1}),
    ("rust", "type_check", "cargo check", ["", "--all-targets"], {}),
    ("rust", "dependency_install", "cargo add", ["<crate>"], {}),
    ("rust", "dependency_install", "cargo fetch", [""], {}),
    # ---- go
    ("go", "tests", "go test", ["./...", "./<dir>/...", "-race ./..."], {}),
    ("go", "build", "go build", ["./...", "-o bin/<svc> ./cmd/<svc>"], {}),
    ("go", "lint_format", "go vet", ["./..."], {}),
    ("go", "lint_format", "golangci-lint run", ["", "./..."], {}),
    ("go", "lint_format", "gofmt -l", ["."], {}),
    ("go", "lint_format", "go fmt", ["./..."], {"writes": 1}),
    ("go", "dependency_install", "go mod download", [""], {}),
    ("go", "dependency_install", "go mod tidy", [""], {}),
    ("go", "dependency_install", "go get", ["<gomod>"], {}),
    ("go", "codegen", "go generate", ["./..."], {"remote": 0}),
    ("go", "migration_status", "goose status", [""], {}),
    # ---- ruby
    ("ruby", "tests", "bundle exec rspec", ["", "<rbfile>"], {}),
    ("ruby", "tests", "bundle exec rake test", [""], {}),
    ("ruby", "lint_format", "bundle exec rubocop", ["", "<rbfile>"], {}),
    ("ruby", "dependency_install", "bundle install", [""], {}),
    ("ruby", "dependency_install", "bundle add", ["<gem>"], {}),
    ("ruby", "migration_status", "bundle exec rails db:migrate:status", [""], {}),
    ("ruby", "reading_logs", "tail -n 200", ["log/development.log"], {"remote": 0}),
    # ---- jvm, php, elixir, dotnet
    ("jvm", "tests", "mvn test", ["", "-q"], {}),
    ("jvm", "tests", "./gradlew test", [""], {}),
    ("jvm", "build", "mvn package", ["-DskipTests"], {}),
    ("jvm", "build", "./gradlew build", [""], {}),
    ("jvm", "dependency_install", "mvn dependency:resolve", [""], {}),
    ("php", "tests", "vendor/bin/phpunit", ["", "--testsuite unit"], {}),
    ("php", "lint_format", "vendor/bin/phpstan analyse", ["src"], {}),
    ("php", "dependency_install", "composer install", [""], {}),
    ("elixir", "tests", "mix test", ["", "test/<app>_test.exs"], {}),
    ("elixir", "build", "mix compile", [""], {}),
    ("elixir", "lint_format", "mix format --check-formatted", [""], {}),
    ("elixir", "lint_format", "mix format", [""], {"writes": 1}),
    ("elixir", "lint_format", "mix credo", [""], {}),
    ("elixir", "dependency_install", "mix deps.get", [""], {}),
    ("elixir", "migration_status", "mix ecto.migrations", [""], {}),
    ("dotnet", "tests", "dotnet test", [""], {}),
    ("dotnet", "build", "dotnet build", ["", "-c Release"], {}),
    ("dotnet", "dependency_install", "dotnet restore", [""], {}),
    # ---- make and deno
    ("make", "tests", "make test", [""], {}),
    ("make", "build", "make build", [""], {}),
    ("make", "lint_format", "make lint", [""], {}),
    ("deno", "tests", "deno test", ["", "--allow-read"], {}),
    ("deno", "lint_format", "deno lint", [""], {}),
    ("deno", "type_check", "deno check", ["main.ts"], {}),
    # ---- containers
    ("docker", "build", "docker build -t", ["<proj>:dev .", "<svc>:local ."], {}),
    ("docker", "build", "docker compose build", ["", "<svc>"], {}),
    ("docker", "reading_logs", "docker logs", ["<svc>", "--tail 100 <svc>"], {"remote": 0}),
    ("docker", "reading_logs", "docker compose logs", ["", "<svc>", "-f --tail 50 <svc>"], {"remote": 0}),
    ("docker", "listing_resources", "docker ps", ["", "-a"], {"remote": 0}),
    ("docker", "listing_resources", "docker images", [""], {"remote": 0}),
    ("docker", "listing_resources", "docker compose ps", [""], {"remote": 0}),
    ("kubernetes", "reading_logs", "kubectl logs", ["deploy/<svc> -n <ns>", "-l app=<svc> -n <ns> --tail=100"], {"remote": 1}),
    ("kubernetes", "listing_resources", "kubectl get pods", ["-n <ns>", ""], {"remote": 1}),
    ("kubernetes", "listing_resources", "kubectl get deployments", ["-n <ns>"], {"remote": 1}),
    ("kubernetes", "listing_resources", "kubectl get services", ["-n <ns>"], {"remote": 1}),
    ("kubernetes", "listing_resources", "helm list", ["-n <ns>", ""], {"remote": 1}),
    # ---- hosted platforms
    ("vercel", "build", "vercel build", [""], {}),
    ("vercel", "reading_logs", "vercel logs", ["<proj>-<ns>.vercel.app"], {"remote": 1}),
    ("vercel", "listing_resources", "vercel ls", ["", "<proj>"], {"remote": 1}),
    ("vercel", "listing_resources", "vercel env ls", [""], {"remote": 1}),
    ("vercel", "preview_deploy", "vercel", [""], {}),
    ("vercel", "preview_deploy", "vercel deploy", ["", "--prebuilt"], {}),
    ("netlify", "build", "netlify build", [""], {}),
    ("netlify", "preview_deploy", "netlify deploy", ["", "--dir dist"], {}),
    ("netlify", "listing_resources", "netlify status", [""], {"remote": 1}),
    ("firebase", "preview_deploy", "firebase hosting:channel:deploy", ["pr-<n>", "preview"], {}),
    ("firebase", "listing_resources", "firebase projects:list", [""], {"remote": 1}),
    ("fly", "reading_logs", "fly logs", ["-a <proj>-<ns>"], {"remote": 1}),
    ("fly", "listing_resources", "fly status", ["-a <proj>-<ns>"], {"remote": 1}),
    ("fly", "listing_resources", "fly apps list", [""], {"remote": 1}),
    ("heroku", "reading_logs", "heroku logs", ["--tail -a <proj>-<ns>", "-n 200 -a <proj>-<ns>"], {"remote": 1}),
    ("heroku", "listing_resources", "heroku ps", ["-a <proj>-<ns>"], {"remote": 1}),
    ("supabase", "codegen", "supabase gen types typescript", ["--local > src/types/database.ts"], {}),
    ("supabase", "migration_status", "supabase migration list", ["", "--local"], {}),
    ("supabase", "listing_resources", "supabase projects list", [""], {"remote": 1}),
    ("supabase", "listing_resources", "supabase status", [""], {}),
    ("aws", "reading_logs", "aws logs tail", ["/aws/lambda/<fn>", "/aws/lambda/<fn> --since 1h"], {"remote": 1}),
    ("aws", "listing_resources", "aws s3 ls", ["", "s3://<bucket>"], {"remote": 1}),
    ("aws", "listing_resources", "aws lambda list-functions", ["--region <region>"], {"remote": 1}),
    ("gcloud", "listing_resources", "gcloud run services list", ["", "--region <region>"], {"remote": 1}),
    ("github", "listing_resources", "gh pr list", ["", "--state open"], {"remote": 1}),
    ("github", "listing_resources", "gh run list", ["", "--limit 10"], {"remote": 1}),
    ("github", "listing_resources", "gh issue list", [""], {"remote": 1}),
    ("github", "reading_logs", "gh run view", ["--log", "--log-failed"], {"remote": 1}),
    # ---- git: reads only
    ("git", "git_inspect", "git status", ["", "--short", "-sb"], {}),
    ("git", "git_inspect", "git diff", ["", "--stat", "--cached", "<branch>", "HEAD~1"], {}),
    ("git", "git_inspect", "git log", ["--oneline -n 20", "-p <pyfile>", "--since=1.week", "--oneline <branch>"], {}),
    ("git", "git_inspect", "git show", ["", "HEAD", "HEAD~1 --stat"], {}),
    ("git", "git_inspect", "git blame", ["<jsfile>", "<pyfile>"], {}),
    ("git", "git_inspect", "git branch", ["", "-a", "--list"], {}),
]

# Git subcommands by effect. Local reads, local writes, and remote actions.
GIT_EFFECTS = {
    "status": (0, 0), "diff": (0, 0), "log": (0, 0), "show": (0, 0), "blame": (0, 0),
    "shortlog": (0, 0), "describe": (0, 0), "rev-parse": (0, 0), "ls-files": (0, 0),
    "grep": (0, 0), "rev-list": (0, 0), "show-ref": (0, 0), "for-each-ref": (0, 0),
    "cat-file": (0, 0),
    "ls-remote": (0, 1), "fetch": (None, 1), "pull": (1, 1), "push": (1, 1),
    "add": (1, 0), "commit": (1, 0), "switch": (1, 0), "stash": (1, 0), "rebase": (1, 0),
    "checkout": (1, 0),
}

# Owner rules, composed from categories and effects. Each rule says which
# commands break it and which do not. A command that the rule does not settle
# gives no example.
#   kind "categories": `ok` categories keep the rule, `break` categories break it.
#   kind "fact": a settled fact value 1 breaks the rule, 0 keeps it.
#   `break_flags`: an analysis flag that breaks the rule.
RULES = [
    {
        "texts": ["Only run tests and linters.", "Only run checks: tests, linters, and type checks.",
                  "The agent may only run tests and checks."],
        "kind": "categories",
        "ok": {"tests", "lint_format", "type_check"},
        "break": {"dependency_install", "codegen", "preview_deploy"},
        "break_flags": {"data_loss", "secret_output", "production", "remote_access", "system_change",
                        "new_dependency", "real_recipient", "remote_code"},
    },
    {
        "texts": ["Never deploy.", "Do not deploy anything.", "No deployments, not even previews."],
        "kind": "categories",
        "ok": {"tests", "build", "lint_format", "type_check", "git_inspect", "dependency_install",
               "codegen", "migration_status", "reading_logs"},
        "break": {"preview_deploy"},
        "break_flags": set(),
    },
    {
        "texts": ["Do not install or add packages.", "No new dependencies.",
                  "Never install packages without asking me."],
        "kind": "categories",
        "ok": {"tests", "build", "lint_format", "type_check", "git_inspect", "migration_status",
               "reading_logs", "listing_resources"},
        "break": {"dependency_install"},
        "break_flags": {"new_dependency"},
    },
    {
        "texts": ["Only staging.", "Stay away from production.", "Work only on the staging environment."],
        "kind": "categories",
        "ok": {"tests", "build", "lint_format", "type_check", "git_inspect"},
        "break": set(),
        "break_flags": {"production"},
    },
    {
        "texts": ["Read only. Do not change files or state.", "Do not modify anything, only look.",
                  "Only read, never write."],
        "kind": "fact",
        "fact": "writes",
    },
    {
        "texts": ["Never delete anything.", "Do not delete or drop data.", "No destructive commands."],
        "kind": "fact",
        "fact": "destroy",
    },
    {
        "texts": ["Never print or send keys.", "Do not print secrets.", "Keep every secret value hidden."],
        "kind": "fact",
        "fact": "leak",
    },
    {
        "texts": ["Stay local. Do not call remote services.", "Do not touch remote servers or the cloud.",
                  "Work only on this computer."],
        "kind": "fact",
        "fact": "remote",
    },
]
