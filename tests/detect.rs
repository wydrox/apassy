#![cfg(feature = "vault")]

//! Paste detection (ADR 0025 §4): a secret, a `KEY=value` line, a `.env` file, a URL
//! with credentials, or an `otpauth://` link becomes items without extra input.
//! Synthetic values only: `fake(prefix, n)` is a public prefix and `EXAMPLE0` filler.

use apassy::contracts::CredentialKind;
use apassy::vault::detect::{
    Detected, FALLBACK_TITLE, Source, Sources, URL_FIELD, detect, summary_line,
};
use apassy::vault::providers;
use apassy::vault::{DeclarationField, Environment, Reversibility, RiskLevel, Scope};

/// A fake value: a public prefix and filler text. Never a real key.
fn fake(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", &"EXAMPLE0".repeat(len / 8 + 1)[..len])
}

fn one(text: &str) -> Detected {
    let mut found = detect(text);
    assert_eq!(found.len(), 1, "one credential in {text:?}: {found:?}");
    found.remove(0)
}

fn value<'a>(detected: &'a Detected, field: &str) -> &'a str {
    detected
        .field(field)
        .unwrap_or_else(|| panic!("field {field} in {detected:?}"))
        .value
        .expose()
}

fn names(detected: &Detected) -> Vec<(&str, bool)> {
    detected
        .fields
        .iter()
        .map(|field| (field.name.as_str(), field.secret))
        .collect()
}

#[test]
fn every_pack_prefix_names_its_provider_variable_and_hosts() {
    let catalog = providers::builtin().expect("provider catalog");
    let mut checked = 0;
    for provider in catalog.providers() {
        for prefix in &provider.prefixes {
            let secret = fake(prefix, 40);
            let detected = one(&secret);
            assert_eq!(
                detected.provider.as_deref(),
                Some(provider.id.as_str()),
                "{prefix}"
            );
            assert_eq!(detected.kind, CredentialKind::ApiKey, "{prefix}");
            assert_eq!(
                detected.env_name.as_deref(),
                Some(provider.variable.as_str()),
                "{prefix}"
            );
            assert_eq!(detected.hosts, provider.known_hosts, "{prefix}");
            assert_eq!(names(&detected), [("token", true)], "{prefix}");
            assert_eq!(value(&detected, "token"), secret);
            assert_eq!(detected.secret().map(|s| s.expose()), Some(secret.as_str()));
            assert_eq!(detected.line, None);
            assert!(
                summary_line(&detected).contains(&provider.variable),
                "{prefix}"
            );
            assert!(
                !format!("{detected:?}").contains(&secret),
                "Debug shows {prefix}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 30, "{checked} prefixes");
}

#[test]
fn a_key_gets_the_title_and_line_of_the_mockup() {
    let detected = one(&fake("sk-ant-api03-", 40));
    assert_eq!(detected.title, "Anthropic API key");
    assert_eq!(detected.provider.as_deref(), Some("anthropic"));
    assert_eq!(detected.hosts, ["api.anthropic.com"]);
    // No environment signal: the most sensitive default.
    assert_eq!(detected.environment, Environment::Production);
    assert_eq!(detected.sources.environment, Source::Default);
    // The provider file suggests the risk of an API key.
    assert_eq!(detected.risk, RiskLevel::Medium);
    assert_eq!(detected.sources.risk, Source::Signal);
    assert_eq!(
        summary_line(&detected),
        "Anthropic API key · ANTHROPIC_API_KEY · production"
    );

    let github = one(&fake("ghp_", 36));
    assert_eq!(github.title, "GitHub token");
    assert_eq!(github.env_name.as_deref(), Some("GITHUB_TOKEN"));
    let aws = one(&fake("AKIA", 16));
    assert_eq!(aws.title, "AWS access key");
    assert_eq!(aws.env_name.as_deref(), Some("AWS_ACCESS_KEY_ID"));
    // The longest prefix wins: `sk-ant-` over `sk-`.
    assert_eq!(one(&fake("sk-", 48)).provider.as_deref(), Some("openai"));
    assert_eq!(one(&fake("sk-proj-", 48)).title, "OpenAI API key");
}

#[test]
fn a_live_value_is_production_from_a_signal_and_never_lower() {
    let live = one(&fake("sk_live_", 24));
    assert_eq!(live.title, "Stripe live");
    assert_eq!(live.environment, Environment::Production);
    assert_eq!(live.sources.environment, Source::Signal);
    assert_eq!(live.env_name.as_deref(), Some("STRIPE_SECRET_KEY"));
    assert_eq!(
        summary_line(&live),
        "Stripe live · STRIPE_SECRET_KEY · production"
    );

    // A test word in the variable does not lower a live value.
    let named = one(&format!("STRIPE_TEST_KEY={}", fake("sk_live_", 24)));
    assert_eq!(named.title, "Stripe live");
    assert_eq!(named.environment, Environment::Production);
    assert_eq!(named.env_name.as_deref(), Some("STRIPE_TEST_KEY"));

    // A test value: the provider file puts test mode in staging.
    let test = one(&fake("sk_test_", 24));
    assert_eq!(test.title, "Stripe test");
    assert_eq!(test.environment, Environment::Staging);
    assert_eq!(test.sources.environment, Source::Signal);
    assert_eq!(test.risk, RiskLevel::Low);

    // A live variable makes a test value production.
    let both = one(&format!("STRIPE_LIVE_KEY={}", fake("sk_test_", 24)));
    assert_eq!(both.environment, Environment::Production);
    assert_eq!(both.sources.environment, Source::Signal);

    // A production word of a value without a provider: a weak signal, not a source.
    let word = one("acme_live_0000EXAMPLE0000");
    assert_eq!(word.provider, None);
    assert_eq!(word.environment, Environment::Production);
    assert_eq!(word.sources.environment, Source::Default);
    assert_eq!(word.sources.risk, Source::Default);
}

#[test]
fn a_value_without_a_signal_is_a_custom_credential_with_default_sources() {
    let detected = one("plain-value-0000-abcd");
    assert_eq!(detected.title, FALLBACK_TITLE);
    assert_eq!(detected.kind, CredentialKind::Custom);
    assert_eq!(detected.provider, None);
    assert_eq!(detected.env_name, None);
    assert_eq!(detected.env_field, None);
    assert!(detected.hosts.is_empty());
    assert_eq!(names(&detected), [("secret", true)]);
    assert_eq!(detected.sources, Sources::DEFAULT);
    assert_eq!(detected.environment, Environment::Production);
    assert_eq!(detected.risk, RiskLevel::High);
    assert_eq!(detected.scope, Scope::Admin);
    assert_eq!(detected.reversibility, Reversibility::Irreversible);
    assert_eq!(summary_line(&detected), "Credential · production");
    let form = detected.suggested();
    assert!(form.from_signals.is_empty());
    assert_eq!(form.provider, None);

    // A password with `=` or Base64 padding stays one value.
    for text in ["Xy7=pq9-EXAMPLE", "c2VjcmV0LXZhbHVl==", "abc="] {
        let detected = one(text);
        assert_eq!(detected.kind, CredentialKind::Custom, "{text}");
        assert_eq!(value(&detected, "secret"), text);
    }
    assert!(detect("").is_empty());
    assert!(detect(" \n\t ").is_empty());
}

#[test]
fn a_dotenv_file_gives_one_item_for_each_line() {
    let anthropic = fake("sk-ant-api03-", 40);
    let stripe = fake("sk_test_", 24);
    let text = format!(
        "# Local settings\n\
         \n\
         export ANTHROPIC_API_KEY=\"{anthropic}\"\n\
         STRIPE_SECRET_KEY='{stripe}'\n\
         DATABASE_PASSWORD=fake-pass-0000 # a comment\n\
         \n\
         DATABASE_URL=postgres://billing_rw:FAKE-pass@db.prod.acme.internal:5432/billing\n\
         DEV_API_TOKEN=plain-dev-0000\n\
         EMPTY=\n\
         openai_api_key=EXAMPLE0EXAMPLE0\n"
    );
    let found = detect(&text);
    let summary: Vec<(Option<usize>, String)> =
        found.iter().map(|d| (d.line, summary_line(d))).collect();
    assert_eq!(
        summary,
        [
            (
                Some(3),
                "Anthropic API key · ANTHROPIC_API_KEY · production".to_owned()
            ),
            (
                Some(4),
                "Stripe test · STRIPE_SECRET_KEY · staging".to_owned()
            ),
            (
                Some(5),
                "Database Password · DATABASE_PASSWORD · production".to_owned()
            ),
            (
                Some(7),
                "Billing database · DATABASE_URL · production".to_owned()
            ),
            (
                Some(8),
                "Dev Api Token · DEV_API_TOKEN · development".to_owned()
            ),
            (
                Some(10),
                "OpenAI API key · OPENAI_API_KEY · production".to_owned()
            ),
        ]
    );
    assert_eq!(value(&found[0], "token"), anthropic);
    assert_eq!(value(&found[1], "token"), stripe);

    let password = &found[2];
    assert_eq!(password.kind, CredentialKind::Custom);
    assert_eq!(password.provider, None);
    assert_eq!(names(password), [("database_password", true)]);
    assert_eq!(value(password, "database_password"), "fake-pass-0000");
    assert_eq!(password.sources, Sources::DEFAULT);

    let url = &found[3];
    assert_eq!(url.kind, CredentialKind::Database);
    assert_eq!(url.sources.environment, Source::Default);
    assert_eq!(value(url, "password"), "FAKE-pass");

    let dev = &found[4];
    assert_eq!(dev.environment, Environment::Development);
    assert_eq!(dev.sources.environment, Source::Signal);

    // A variable of a provider without a value prefix names the provider.
    let openai = &found[5];
    assert_eq!(openai.provider.as_deref(), Some("openai"));
    assert_eq!(openai.kind, CredentialKind::ApiKey);
    assert_eq!(openai.hosts, ["api.openai.com"]);

    let debug = format!("{found:?}");
    for secret in [
        anthropic.as_str(),
        stripe.as_str(),
        "fake-pass-0000",
        "FAKE-pass",
        "plain-dev-0000",
    ] {
        assert!(!debug.contains(secret), "Debug shows {secret}");
    }
}

#[test]
fn a_single_key_value_line_is_one_entry() {
    let detected = one("RESEND_API_KEY=re_EXAMPLE0EXAMPLE0EXAMPLE0");
    assert_eq!(detected.provider.as_deref(), Some("resend"));
    assert_eq!(detected.line, Some(1));
    assert_eq!(value(&detected, "token"), "re_EXAMPLE0EXAMPLE0EXAMPLE0");
    let exported = one("export my_token=EXAMPLE0EXAMPLE0");
    assert_eq!(exported.env_name.as_deref(), Some("MY_TOKEN"));
    assert_eq!(exported.title, "My Token");
    // A reserved variable name is not used.
    let reserved = one("PATH=/opt/fake/bin");
    assert_eq!(reserved.env_name, None);
}

#[test]
fn a_postgres_url_is_split_into_fields() {
    let detected = one("postgres://u:p@h:5432/db");
    assert_eq!(detected.kind, CredentialKind::Database);
    assert_eq!(detected.provider.as_deref(), Some("postgres"));
    assert_eq!(detected.title, "Db database");
    assert_eq!(detected.env_name.as_deref(), Some("DATABASE_URL"));
    assert_eq!(detected.env_field.as_deref(), Some(URL_FIELD));
    assert!(
        detected.hosts.is_empty(),
        "a URL goes to the process as it is"
    );
    assert_eq!(
        names(&detected),
        [
            ("host", false),
            ("database", false),
            ("username", false),
            ("password", true),
            (URL_FIELD, true),
        ]
    );
    assert_eq!(value(&detected, "host"), "h:5432");
    assert_eq!(value(&detected, "database"), "db");
    assert_eq!(value(&detected, "username"), "u");
    assert_eq!(value(&detected, "password"), "p");
    assert_eq!(value(&detected, URL_FIELD), "postgres://u:p@h:5432/db");
    assert_eq!(detected.secret().map(|s| s.expose()), Some("p"));
    assert_eq!(
        summary_line(&detected),
        "Db database · DATABASE_URL · production"
    );

    let prod = one("postgresql://billing_rw:FAKE@db.prod.acme.internal:5432/billing");
    assert_eq!(prod.title, "Billing database");
    assert_eq!(prod.environment, Environment::Production);
    assert_eq!(prod.sources.environment, Source::Default);

    // A hosted provider wins over the generic PostgreSQL provider.
    let supabase = one("postgresql://postgres:FAKE@db.exampleref.supabase.co:5432/postgres");
    assert_eq!(supabase.provider.as_deref(), Some("supabase"));
    assert_eq!(supabase.title, "Supabase database");
    assert!(supabase.hosts.is_empty());

    // A localhost host is a weak signal: a tunnel to production looks the same.
    let mysql = one("mysql://app:FAKE@localhost:3306/shop");
    assert_eq!(mysql.title, "Shop database");
    assert_eq!(mysql.environment, Environment::Production);
    assert_eq!(mysql.sources, Sources::DEFAULT);
}

#[test]
fn mongodb_srv_redis_and_amqp_urls() {
    let mongo =
        one("mongodb+srv://app_user:p%40ss@cluster0.example.mongodb.net/orders?retryWrites=true");
    assert_eq!(mongo.kind, CredentialKind::Database);
    assert_eq!(mongo.title, "Orders database");
    assert_eq!(mongo.env_name.as_deref(), Some("MONGODB_URI"));
    assert_eq!(value(&mongo, "host"), "cluster0.example.mongodb.net");
    assert_eq!(value(&mongo, "username"), "app_user");
    assert_eq!(value(&mongo, "password"), "p@ss");
    assert!(value(&mongo, URL_FIELD).ends_with("?retryWrites=true"));
    assert!(!format!("{mongo:?}").contains("p%40ss"));

    // No user: the URL is a Custom item with the URL as the variable.
    let redis = one("redis://:FAKE-redis@localhost:6379/0");
    assert_eq!(redis.kind, CredentialKind::Custom);
    assert_eq!(redis.title, "Redis database");
    assert_eq!(redis.env_name.as_deref(), Some("REDIS_URL"));
    assert_eq!(redis.env_field.as_deref(), Some(URL_FIELD));
    assert_eq!(redis.environment, Environment::Production);
    assert_eq!(value(&redis, "password"), "FAKE-redis");

    // A staging host is a weak signal too: it never lowers the environment.
    let amqp = one("amqp://guest:FAKE@mq.staging.example.com:5672/%2F");
    assert_eq!(amqp.title, "RabbitMQ broker");
    assert_eq!(amqp.env_name.as_deref(), Some("AMQP_URL"));
    assert_eq!(amqp.environment, Environment::Production);
    assert_eq!(amqp.sources.environment, Source::Default);
    assert_eq!(value(&amqp, "database"), "/");
}

#[test]
fn an_otpauth_link_is_a_one_time_password() {
    let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    let detected = one(uri);
    assert_eq!(detected.title, "Example (alice@example.com)");
    assert_eq!(detected.kind, CredentialKind::Custom);
    assert_eq!(detected.env_name, None);
    assert!(detected.hosts.is_empty());
    let field = apassy::import::detail_field_name(apassy::otp::LABEL);
    assert_eq!(names(&detected), [(field.as_str(), true)]);
    assert_eq!(value(&detected, &field), uri);
    assert_eq!(detected.sources, Sources::DEFAULT);
    assert_eq!(
        summary_line(&detected),
        "Example (alice@example.com) · production"
    );
    assert!(!format!("{detected:?}").contains("JBSWY3DPEHPK3PXP"));

    assert_eq!(
        one("otpauth://totp/Acme%20Corp?secret=JBSWY3DPEHPK3PXP").title,
        "Acme Corp"
    );
    // A counter-based or broken link gives nothing.
    assert!(detect("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").is_empty());
    assert!(detect("otpauth://totp/x?secret=1").is_empty());
}

#[test]
fn a_private_key_is_an_ssh_key() {
    let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nEXAMPLE0EXAMPLE0=\nEXAMPLE0==\n-----END OPENSSH PRIVATE KEY-----";
    let detected = one(key);
    assert_eq!(detected.kind, CredentialKind::SshKey);
    assert_eq!(detected.title, "SSH key");
    assert_eq!(value(&detected, "private_key"), key);
    assert_eq!(detected.env_name, None);
}

#[test]
fn the_suggestion_form_lists_the_signal_fields() {
    let detected = one(&fake("sk_live_", 24));
    let form = detected.suggested();
    assert_eq!(form.provider.as_deref(), Some("stripe"));
    assert_eq!(form.from_signals, DeclarationField::ALL);
    assert_eq!(Source::Signal.as_str(), "signal");
    assert_eq!(Source::Default.as_str(), "default");
}

#[test]
fn debug_output_hides_every_value() {
    let secrets = [
        fake("sk-ant-api03-", 40),
        fake("sk_live_", 24),
        "plain-canary-0000".to_owned(),
        "postgres://u:canary-pass@h:5432/db".to_owned(),
        "API_SECRET=\"canary value\"".to_owned(),
    ];
    for text in &secrets {
        for detected in detect(text) {
            let debug = format!("{detected:?}");
            assert!(!debug.contains("canary"), "{debug}");
            assert!(!debug.contains("EXAMPLE0"), "{debug}");
        }
    }
}

#[test]
fn a_short_key_with_equals_is_a_raw_value_not_a_key_value_line() {
    let detected = one("AB12=xyz");
    assert_eq!(detected.kind, CredentialKind::Custom);
    assert_eq!(detected.title, FALLBACK_TITLE);
    assert!(!detected.title.contains("AB12") && !detected.title.contains("xyz"));
    assert_eq!(detected.env_name, None);
    assert_eq!(detected.line, None);
    assert_eq!(value(&detected, "secret"), "AB12=xyz");
    // A lowercase key with an underscore needs `export` for a single line.
    assert_eq!(
        value(&one("api_key=EXAMPLE0"), "secret"),
        "api_key=EXAMPLE0"
    );
}

#[test]
fn a_single_line_is_key_value_for_a_variable_style_key_a_provider_variable_or_export() {
    let openai = one(&format!("OPENAI_API_KEY={}", fake("sk-", 40)));
    assert_eq!(openai.line, Some(1));
    assert_eq!(openai.env_name.as_deref(), Some("OPENAI_API_KEY"));
    assert_eq!(openai.provider.as_deref(), Some("openai"));
    let exported = one("export foo=bar");
    assert_eq!(exported.line, Some(1));
    assert_eq!(exported.env_name.as_deref(), Some("FOO"));
    assert_eq!(value(&exported, "foo"), "bar");
    let custom = one("DB_PASS2=EXAMPLE0");
    assert_eq!(custom.line, Some(1));
    assert_eq!(custom.title, "Db Pass2");
    // No underscore: the key is part of the value, unless a provider names it.
    assert_eq!(one("TOKEN=EXAMPLE0").line, None);
    assert_eq!(one("PATH=/opt/fake/bin").line, None);
    let by_provider = providers::builtin()
        .expect("catalog")
        .providers()
        .iter()
        .map(|provider| provider.variable.as_str())
        .find(|variable| !variable.contains('_'));
    if let Some(variable) = by_provider {
        assert_eq!(one(&format!("{variable}=EXAMPLE0")).line, Some(1));
    }
    // A trailing or double underscore is not the shape.
    assert_eq!(one("API_=EXAMPLE0").line, None);
    assert_eq!(one("API__KEY=EXAMPLE0").line, None);
}

#[test]
fn a_multi_line_dotenv_takes_lowercase_keys_and_needs_every_line_to_be_an_assignment() {
    let found = detect("alpha=EXAMPLE0\nbeta=EXAMPLE1\n");
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].line, Some(1));
    assert_eq!(found[1].line, Some(2));
    assert_eq!(found[1].env_name.as_deref(), Some("BETA"));
    // A comment is not a line. One assignment after it follows the single-line rule.
    assert_eq!(one("# note\nab=EXAMPLE0").line, None);
    assert_eq!(one("# note\nAB_CD=EXAMPLE0").line, Some(2));
    // A line that is no assignment makes the whole text one secret.
    let mixed = one("alpha=EXAMPLE0\nnot an assignment");
    assert_eq!(mixed.line, None);
    assert_eq!(value(&mixed, "secret"), "alpha=EXAMPLE0\nnot an assignment");
}

// ---- Secret parts in plain fields and titles, weak signals (Gate 1 review) ----

/// The parts of four characters of a secret, in lowercase.
fn windows(secret: &str) -> Vec<String> {
    let chars: Vec<char> = secret.to_lowercase().chars().collect();
    chars
        .windows(4)
        .map(|window| window.iter().collect())
        .collect()
}

/// No plain field, no title, and no result line has a part of a secret.
fn assert_no_secret_part(input: &str, detected: &Detected, secrets: &[&str]) {
    let mut shown: Vec<(String, String)> = vec![
        ("title".to_owned(), detected.title.to_lowercase()),
        ("summary".to_owned(), summary_line(detected).to_lowercase()),
    ];
    for field in detected.fields.iter().filter(|field| !field.secret) {
        shown.push((field.name.clone(), field.value.expose().to_lowercase()));
    }
    for secret in secrets {
        for part in windows(secret) {
            for (name, text) in &shown {
                assert!(
                    !text.contains(&part),
                    "{name} {text:?} has {part:?} of the secret in {input:?}"
                );
            }
        }
    }
}

#[test]
fn the_review_examples_keep_the_password_out_of_plain_fields_and_titles() {
    // `#` in the password: the old split made the host "app:Xk9Qz7".
    let hash = "postgres://app:Xk9Qz7#mQ2vL7@db.acme-corp.com:5432/app";
    let detected = one(hash);
    assert_eq!(names(&detected), [(URL_FIELD, true)]);
    assert_eq!(value(&detected, URL_FIELD), hash);
    assert_eq!(detected.kind, CredentialKind::Custom);
    assert_eq!(detected.title, "PostgreSQL database");
    assert_eq!(detected.provider.as_deref(), Some("postgres"));
    assert_eq!(detected.env_name.as_deref(), Some("DATABASE_URL"));
    assert_eq!(detected.env_field.as_deref(), Some(URL_FIELD));
    assert_eq!(
        summary_line(&detected),
        "PostgreSQL database · DATABASE_URL · production"
    );
    assert_no_secret_part(hash, &detected, &["Xk9Qz7#mQ2vL7"]);

    // `/` and `?` in the password: the old split made the title "Qz7 database".
    let slash = "postgres://app:Xk9/Qz7?mQ2vL7@db.acme-corp.com:5432/app";
    let detected = one(slash);
    assert_eq!(names(&detected), [(URL_FIELD, true)]);
    assert_eq!(detected.title, "PostgreSQL database");
    assert_no_secret_part(slash, &detected, &["Xk9/Qz7?mQ2vL7"]);

    // A Redis token without `:` is secret, not a user name.
    let token = "rediss://tKn8ZpW3qR5vY2xA@cache.acme-corp.com:6380";
    let detected = one(token);
    assert_eq!(
        names(&detected),
        [("host", false), ("password", true), (URL_FIELD, true)]
    );
    assert_eq!(value(&detected, "password"), "tKn8ZpW3qR5vY2xA");
    assert_eq!(value(&detected, "host"), "cache.acme-corp.com:6380");
    assert_eq!(detected.title, "Redis database");
    assert_no_secret_part(token, &detected, &["tKn8ZpW3qR5vY2xA"]);

    // The same for RabbitMQ, and for a random user part of any scheme.
    let amqp = one("amqps://guest@mq.acme-corp.com/vhost");
    assert!(amqp.field("username").is_none());
    assert_eq!(value(&amqp, "password"), "guest");
    let random = one("postgres://Rk7Vb2Mn9Qx4Lp3W@db.acme-corp.com/app");
    assert!(random.field("username").is_none());
    assert_eq!(value(&random, "password"), "Rk7Vb2Mn9Qx4Lp3W");
    // A plain user name without a password stays a user name.
    let user = one("postgres://billing_rw@db.acme-corp.com/billing");
    assert_eq!(value(&user, "username"), "billing_rw");
    assert!(user.field("password").is_none());

    // `@` in the password before the host is certain: the last `@` ends the user part.
    let at = one("postgres://app:Wq8@Rt5@db.acme-corp.com:5432/shop");
    assert_eq!(value(&at, "host"), "db.acme-corp.com:5432");
    assert_eq!(value(&at, "username"), "app");
    assert_eq!(value(&at, "password"), "Wq8@Rt5");
    assert_eq!(at.title, "Shop database");
}

#[test]
fn no_split_of_a_crafted_url_puts_a_secret_part_in_a_plain_field_or_title() {
    let schemes = [
        "postgres",
        "postgresql",
        "mysql",
        "mongodb",
        "mongodb+srv",
        "redis",
        "rediss",
        "amqp",
        "amqps",
    ];
    // Passwords with the characters that RFC 3986 refuses in the user part.
    let passwords = [
        "Xk9Qz7#mQ2vL7",
        "Xk9/Qz7?mQ2vL7",
        "Wq8@Rt5:Yu3Lp",
        "Pz4%40Lm6Kd2Ab",
        "Hv2/Jn7#Bc9?Df1",
        "Gs5?Kt8Wm3Zx",
        "Fy6:Vc1/Rb4Tn",
        "Qw7Ee9Rr2Ty4",
        "Jd3@@Ks8#Lu2",
        "Cv4%2FBn6Mm1",
    ];
    let hosts = [
        "db.acme-corp.com:5432",
        "localhost:6379",
        "h1.acme.io:27017,h2.acme.io:27017",
        "[::1]:5432",
    ];
    let tails = [
        "",
        "/app",
        "/app?sslmode=require",
        "/billing#frag",
        "?ssl=true",
        "/app?application_name=http://localhost",
    ];
    let mut checked = 0;
    for scheme in schemes {
        for password in passwords {
            let decoded = password.replace("%40", "@").replace("%2F", "/");
            // A token with `:` is a user and a password, so the lone forms skip it.
            let mut infos = vec![format!("app:{password}"), format!(":{password}")];
            if !password.contains(':') {
                infos.push(password.to_owned());
                infos.push(format!("{password}:"));
            }
            for info in &infos {
                for host in hosts {
                    for tail in tails {
                        let url = format!("{scheme}://{info}@{host}{tail}");
                        for input in [url.clone(), format!("DATABASE_URL={url}")] {
                            let found = detect(&input);
                            assert_eq!(found.len(), 1, "{input:?}");
                            let detected = &found[0];
                            assert_no_secret_part(&input, detected, &[password, decoded.as_str()]);
                            for field in detected.fields.iter().filter(|f| !f.secret) {
                                let text = field.value.expose();
                                assert!(!text.contains('@'), "{} of {input:?}", field.name);
                                if field.name == "username" {
                                    assert!(!text.contains(':'), "user of {input:?}");
                                }
                                if field.name == "host" {
                                    assert_eq!(text, host, "host of {input:?}");
                                }
                            }
                            assert_eq!(
                                detected
                                    .field(URL_FIELD)
                                    .map(|field| (field.value.expose(), field.secret)),
                                Some((url.as_str(), true)),
                                "{input:?}"
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(checked >= 5000, "{checked} detections");
}

#[test]
fn a_title_or_result_line_never_shows_a_part_of_a_secret() {
    let token = "Xk9Qz7mQ2vL7Rt5Yu3";
    let otp = "JBSWY3DPEHPK3PXP";
    let inputs = [
        (token.to_owned(), token),
        (format!("sk_live_{token}"), token),
        (format!("sk-ant-api03-{token}"), token),
        (format!("ghp_{token}{token}"), token),
        (format!("API_SECRET={token}"), token),
        (format!("export DB_PASSWORD=\"{token}\""), token),
        (format!("A_KEY={token}\nB_KEY=sk_test_{token}\n"), token),
        (format!("acme_live_{token}"), token),
        (
            format!("otpauth://totp/Acme:alice?secret={otp}&issuer=Acme"),
            otp,
        ),
        (
            format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{token}\n-----END OPENSSH PRIVATE KEY-----"
            ),
            token,
        ),
        (
            format!("postgres://app:{token}@db.acme-corp.com/app"),
            token,
        ),
        (
            format!("postgres://app:{token}#x@db.acme-corp.com/app"),
            token,
        ),
        (format!("redis://{token}@cache.acme-corp.com"), token),
        (format!("mongodb://{token}@db.acme-corp.com/orders"), token),
    ];
    for (input, secret) in &inputs {
        let found = detect(input);
        assert!(!found.is_empty(), "{input:?}");
        for detected in &found {
            assert_no_secret_part(input, detected, &[secret]);
        }
    }
}

fn assert_most_sensitive(detected: &Detected) {
    assert_eq!(
        (
            detected.environment,
            detected.risk,
            detected.scope,
            detected.reversibility
        ),
        (
            Environment::Production,
            RiskLevel::High,
            Scope::Admin,
            Reversibility::Irreversible
        ),
        "{}",
        detected.title
    );
    assert_eq!(detected.sources, Sources::DEFAULT, "{}", detected.title);
}

#[test]
fn a_loopback_host_or_a_host_word_never_lowers_the_declaration() {
    // The example of the review: a production database through a tunnel or a proxy.
    assert_most_sensitive(&one("DATABASE_URL=postgres://app:pw@127.0.0.1:5432/app"));
    for host in [
        "localhost:5432",
        "0.0.0.0:5432",
        "host.docker.internal:5432",
        "db.dev.acme.io",
        "db.staging.acme.io",
        "db.local.acme.io",
        "db.test.acme.io",
    ] {
        assert_most_sensitive(&one(&format!("postgres://app:Xk9Qz7@{host}/app")));
        assert_most_sensitive(&one(&format!("REDIS_URL=redis://:Xk9Qz7@{host}/0")));
    }
    // A host in the query of a secret value is not read.
    assert_most_sensitive(&one(
        "postgres://app:Xk9Qz7@db.acme-corp.com:5432/app?application_name=http://localhost",
    ));
    // Words of plain fields (the user, the database) are weak too.
    assert_most_sensitive(&one("postgres://readonly:Xk9Qz7@db.acme.io:5432/app_dev"));
    // A variable name condition of a provider is weak.
    let anon = one("SUPABASE_ANON_KEY=Xk9Qz7mQ2vL7Rt5Yu3");
    assert_eq!(anon.risk, RiskLevel::High);
    assert_eq!(anon.sources.risk, Source::Default);
    // A read-only word of the variable gives no scope: only environment words count.
    let reader = one("READONLY_API_TOKEN=Xk9Qz7mQ2vL7Rt5Yu3");
    assert_eq!(reader.scope, Scope::Admin);
    assert_eq!(reader.sources.scope, Source::Default);
}

#[test]
fn an_environment_word_of_the_variable_is_a_signal_and_a_weak_word_only_raises() {
    // A local word of the variable sets the environment, but the localhost host still
    // gives no low risk and no reversibility.
    let local = one("LOCAL_DATABASE_URL=postgres://app:Xk9Qz7@localhost:5432/app");
    assert_eq!(local.environment, Environment::Local);
    assert_eq!(local.sources.environment, Source::Signal);
    assert_eq!(local.risk, RiskLevel::High);
    assert_eq!(local.sources.risk, Source::Default);
    assert_eq!(local.reversibility, Reversibility::Irreversible);
    assert_eq!(local.sources.reversibility, Source::Default);

    let staging = one("STAGING_API_TOKEN=Xk9Qz7mQ2vL7Rt5Yu3");
    assert_eq!(staging.environment, Environment::Staging);
    assert_eq!(staging.sources.environment, Source::Signal);

    // A weak production word of the value raises a test key. The raised value is not
    // a signal; the other values of the test key stay signals.
    let raised = one("sk_test_live_EXAMPLE0EXAMPLE0");
    assert_eq!(raised.environment, Environment::Production);
    assert_eq!(raised.sources.environment, Source::Default);
    assert_eq!(raised.risk, RiskLevel::Low);
    assert_eq!(raised.sources.risk, Source::Signal);
}
