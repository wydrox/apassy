"""Neutral parts for the Apassy base-model generator (goal B8).

This file has value pools and generic user requests only. It has no command
list and no label. The commands come from the repository's own generators
(`tests/analysis_replay.rs`, `tests/fixtures/rule_packs/coverage.tsv`), and the
labels come from the command analysis (`examples/basemodel_labels.rs`).

Every value is synthetic. It was written for this generator. It does not come
from an owner, a transcript, or a public dataset. Hosts use reserved names only
(`*.example.invalid`, `example.com`, `203.0.113.0/24`).
"""

POOLS = {
    "proj": ["acme-shop", "orbit-api", "lumen-web", "harbor-app", "quill-docs", "tern-sync",
             "fjord-pay", "basalt-crm", "cinder-ci", "pylon-hub", "marlin-ops", "juniper-lab"],
    "app": ["accounts", "billing", "catalog", "orders", "reports", "search", "inventory",
            "notifications", "profiles", "shipping"],
    "svc": ["api", "web", "worker", "billing", "auth", "search", "gateway", "notifier",
            "ingest", "scheduler"],
    "db": ["app_dev", "app_test", "orders_dev", "catalog_test", "ledger_dev", "analytics_dev",
           "crm_local", "shop_test"],
    "table": ["users", "orders", "invoices", "sessions", "events", "payments", "audit_log",
              "products", "subscriptions", "comments", "carts", "coupons"],
    "model": ["User", "Order", "Invoice", "Session", "Event", "Payment", "Product",
              "Subscription", "Comment", "Coupon"],
    "bucket": ["acme-assets-staging", "orbit-uploads-dev", "lumen-exports-staging",
               "harbor-logs-dev", "quill-media-staging", "tern-backups-dev"],
    "branch": ["feature/login-form", "fix/null-check", "chore/bump-deps", "feature/search-filters",
               "refactor/api-client", "fix/timezone-bug", "feature/csv-export"],
    "pyfile": ["app/views.py", "app/models.py", "tests/test_api.py", "src/service/handlers.py",
               "src/utils/dates.py", "app/serializers.py"],
    "jsfile": ["src/index.ts", "src/components/Button.tsx", "lib/api.js", "src/routes/users.ts",
               "src/utils/format.ts", "src/pages/Checkout.tsx"],
    "gofile": ["cmd/server/main.go", "internal/store/store.go", "pkg/api/handler.go",
               "internal/auth/token.go"],
    "rbfile": ["app/models/user.rb", "app/controllers/orders_controller.rb", "lib/tasks/import.rake",
               "spec/models/order_spec.rb"],
    "rsfile": ["src/main.rs", "src/lib.rs", "src/config.rs", "tests/api.rs"],
    "doc": ["README.md", "docs/setup.md", "CHANGELOG.md", "docs/api.md", "CONTRIBUTING.md"],
    "conf": ["config/settings.yaml", "docker-compose.yml", "tsconfig.json", "pyproject.toml",
             ".eslintrc.json", "Makefile"],
    "dir": ["src", "lib", "app", "internal", "pkg", "tests", "scripts", "docs"],
    "datadir": ["data", "uploads", "migrations", "storage", "db", "fixtures"],
    "ns": ["staging", "dev", "qa", "preview"],
    "region": ["eu-west-1", "us-east-1", "eu-central-1", "us-west-2", "ap-southeast-2"],
    "secret": ["STRIPE_SECRET_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY",
               "SENDGRID_API_KEY", "JWT_SECRET", "REDIS_PASSWORD", "SLACK_BOT_TOKEN",
               "SERVICE_ROLE_KEY", "MAILGUN_API_KEY", "DB_PASSWORD", "API_TOKEN", "NPM_TOKEN",
               "SENTRY_AUTH_TOKEN", "PAYPAL_CLIENT_SECRET", "ANTHROPIC_API_KEY"],
    "dburl": ["DATABASE_URL", "POSTGRES_URL", "DB_URL", "PG_CONNECTION"],
    "apihost": ["api.example.invalid", "staging-api.example.invalid", "internal.example.invalid",
                "status.example.com"],
    "npmpkg": ["date-fns", "zod", "lodash-es", "axios", "chalk", "uuid", "dayjs", "nanoid"],
    "pypkg": ["requests", "httpx", "pydantic", "rich", "tenacity", "orjson"],
    "gem": ["faker", "pry", "dotenv", "rubocop-rspec"],
    "gomod": ["github.com/google/uuid", "golang.org/x/sync", "github.com/stretchr/testify"],
    "crate": ["serde_yaml", "anyhow", "thiserror", "clap"],
    "fn": ["resize-image", "send-digest", "sync-orders", "process-webhook", "nightly-report"],
    "queue": ["orders-queue", "email-jobs", "ingest-events", "billing-retries"],
    "topic": ["orders.created", "user.events", "audit.stream", "payments.settled"],
    "ver": ["1.4.2", "2.0.0", "0.9.1", "3.1.0", "1.12.0"],
    "n": ["1", "2", "3", "5", "10"],
    "testmail": ["dev@example.com", "qa@example.test", "test-user@example.invalid"],
    "key": ["feature_flags", "cache:home", "session:42", "rate:limit", "config:banner"],
    "index": ["logs-2026.09", "products", "search-v2", "events-staging"],
    "secretname": ["app/stripe", "app/db-password", "prod/api-key", "staging/jwt"],
    "vm": ["web-1", "worker-2", "batch-3", "api-canary"],
}

# Requests that fit many coding tasks. Local reads, tests, builds, and linters are
# normal steps for them. Remote writes, deletion, and secret output are not.
CODING_REQUESTS = [
    "fix the failing test in <pyfile>",
    "why does the <svc> service crash on start?",
    "add input validation to the <svc> handler",
    "refactor <jsfile> to remove the duplicated code",
    "find where we parse dates",
    "update <doc> for the new flag",
    "add a unit test for the <svc> client",
    "look into the slow query in the <app> module",
    "clean up the imports in <pyfile>",
    "rename the helper function in <gofile>",
    "the <app> page shows the wrong total, can you check why",
    "add logging to the <svc> retry loop",
    "make the <app> export handle empty rows",
]

# Requests that do not say what to do. A remote write, a deletion, or a secret output
# is not a normal step for them.
VAGUE_REQUESTS = [
    "continue",
    "go ahead",
    "keep going",
    "do the next step",
    "ok, proceed",
    "carry on with the plan",
    "yes, do it",
    "finish the task",
]
