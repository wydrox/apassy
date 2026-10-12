#![cfg(feature = "vault")]

//! The kind of action of a command (ADR 0025 §3a). Synthetic commands only.

use apassy::broker::action_kind::{ActionKind, classify};
use apassy::broker::shell_risk::{Analysis, analyze, command_line_to_argv};

use ActionKind::{Change, Delete, Deploy, Read};

fn kind(command: &[&str]) -> ActionKind {
    let command: Vec<String> = command.iter().map(|word| (*word).to_owned()).collect();
    classify(&command, &Analysis::default())
}

#[test]
fn commands_are_classified_by_hard_rules() {
    let table: &[(&[&str], ActionKind)] = &[
        // Read
        (&["stripe", "payouts", "list"], Read),
        (&["kubectl", "get", "pods"], Read),
        (&["git", "status"], Read),
        (&["gh", "pr", "view", "12"], Read),
        (&["aws", "sts", "get-caller-identity", "--version"], Read),
        (&["ls", "-la"], Read),
        (&["cat", "README.md"], Read),
        (&["whoami"], Read),
        (&["psql", "-c", "select 1"], Read),
        (&["psql", "-c", "SELECT * FROM users"], Read),
        (&["flyctl", "status"], Read),
        (&["terraform", "show"], Read),
        (&["docker", "image", "ls"], Read),
        (&["vercel", "--help"], Read),
        // Change
        (&["curl", "https://example.invalid"], Change),
        (&["mytool", "frobnicate"], Change),
        (&[], Change),
        (&["npm", "install"], Change),
        (&["psql", "-c", "INSERT INTO x VALUES (1)"], Change),
        (&["cat", "a", ">", "b"], Change),
        (&["kubectl", "get", "pods", "|", "sh"], Change),
        (&["bash", "-c", "ls | tee out"], Change),
        (
            &["kubectl", "get", "pods", "-o", "json", ">", "out.json"],
            Change,
        ),
        (&["stripe", "customers", "create"], Change),
        (&["git", "commit", "-m", "x"], Change),
        // Deploy
        (&["wrangler", "deploy"], Deploy),
        (&["npm", "publish"], Deploy),
        (&["terraform", "apply"], Deploy),
        (&["git", "push", "origin", "main"], Deploy),
        (&["gh", "release", "create", "v1"], Deploy),
        (&["kubectl", "rollout", "status", "deploy/web"], Deploy),
        (&["docker", "push", "img:1"], Deploy),
        // Delete
        (&["rm", "-rf", "build"], Delete),
        (&["/bin/rm", "file"], Delete),
        (&["rmdir", "x"], Delete),
        (&["psql", "-c", "DELETE FROM x"], Delete),
        (&["psql", "-c", "delete from x"], Delete),
        (&["psql", "-c", "SELECT 1; DROP TABLE x"], Delete),
        (&["psql", "-c", "TRUNCATE x"], Delete),
        (&["git", "push", "--force"], Delete),
        (&["git", "push", "-f", "origin", "main"], Delete),
        (&["git", "push", "--force-with-lease"], Delete),
        (&["git", "reset", "--hard", "HEAD~1"], Delete),
        (&["terraform", "destroy"], Delete),
        (&["docker", "system", "prune"], Delete),
        (&["kubectl", "delete", "pod", "x"], Delete),
        (&["aws", "s3", "rm", "s3://b/k"], Delete),
        (&["rsync", "-a", "--delete", "a/", "b/"], Delete),
        (&["npm", "install", "--force"], Delete),
        (&["sh", "-c", "kubectl get pods && rm -rf /tmp/x"], Delete),
        (&["wrangler", "deploy", "--force"], Delete),
    ];
    assert!(table.len() >= 25);
    for (command, expected) in table {
        assert_eq!(kind(command), *expected, "command {command:?}");
    }
}

#[test]
fn unknown_commands_are_never_read() {
    for command in [
        &["frobnicate"][..],
        &["./script.sh"],
        &["python", "main.py"],
        &["make", "all"],
        &["curl", "-X", "POST", "https://example.invalid"],
    ] {
        assert_ne!(kind(command), Read, "command {command:?}");
    }
}

#[test]
fn analysis_can_only_raise_the_kind() {
    let command: Vec<String> = ["stripe", "payouts", "list"].map(str::to_owned).to_vec();
    let write = Analysis {
        known_write: true,
        ..Analysis::default()
    };
    assert_eq!(classify(&command, &write), Change);
    let loss = Analysis {
        flags: vec!["data_loss".to_owned()],
        ..Analysis::default()
    };
    assert_eq!(classify(&command, &loss), Delete);
    let other = Analysis {
        flags: vec!["secret_output".to_owned()],
        ..Analysis::default()
    };
    assert_eq!(classify(&command, &other), Read);
}

#[test]
fn names_round_trip_and_the_more_dangerous_kind_wins() {
    let all = [Read, Change, Deploy, Delete];
    for kind in all {
        assert_eq!(ActionKind::parse(kind.as_str()), Some(kind));
    }
    assert_eq!(ActionKind::parse("Read"), None);
    assert_eq!(ActionKind::parse(""), None);
    assert_eq!(ActionKind::parse("production"), None);
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            assert_eq!(a.more_dangerous(*b), all[i.max(j)]);
        }
    }
}

/// The kind of `argv` with an empty analysis must be `expected`. With the real analysis
/// of the active packs, a read stays a read, and any other kind can only rise. The
/// text of a mismatch, or `None`.
fn check(argv: &[String], expected: ActionKind) -> Option<String> {
    let plain = classify(argv, &Analysis::default());
    let real = classify(argv, &analyze(argv, "Do the work.", &[]));
    let real_ok = if expected == Read {
        real == Read
    } else {
        real != Read && expected.more_dangerous(real) == real
    };
    (plain != expected || !real_ok)
        .then(|| format!("{argv:?}: expected {expected:?}, empty {plain:?}, real {real:?}"))
}

/// Gate 0 review (ADR 0025 §3a, §3b): a production allowance for *read* must never
/// let a destructive command through. *Read* only for a certain read; unclear is a
/// change; the most dangerous match wins. Lines as an agent sends them (`sh -c LINE`
/// for shell syntax).
#[test]
fn only_a_certain_read_is_a_read() {
    let lines: &[(&str, ActionKind)] = &[
        // Certain reads: known read-only programs and subcommands.
        ("ls -la", Read),
        ("cat README.md", Read),
        ("grep -o TODO src/main.rs", Read),
        ("ps -o pid,command", Read),
        ("kubectl get pods -n prod", Read),
        ("kubectl describe pod web", Read),
        ("kubectl get deploy web -o yaml", Read),
        ("kubectl get pods -ojson", Read),
        ("kubectl logs web -c app --tail 20", Read),
        ("stripe customers list --limit 3", Read),
        ("stripe charges retrieve ch_1", Read),
        ("stripe get /v1/balance", Read),
        ("gh pr view 12", Read),
        ("gh issue list --state open", Read),
        ("gh release view v1", Read),
        ("gh api repos/o/r/pulls", Read),
        ("git log --oneline -5", Read),
        ("git show HEAD", Read),
        ("git status --porcelain", Read),
        ("git diff HEAD~1 --stat", Read),
        ("git -C sub log", Read),
        ("git branch -a", Read),
        ("aws ec2 describe-instances --region eu-west-1", Read),
        ("aws s3 ls s3://bucket", Read),
        ("aws sts get-caller-identity --output json", Read),
        ("aws ssm get-parameter --name x", Read),
        ("helm list -n prod -o json", Read),
        ("docker ps", Read),
        ("docker compose -f prod.yml ps", Read),
        ("fly status -a web", Read),
        ("vercel ls --prod", Read),
        ("wrangler kv key list --namespace-id 1", Read),
        ("heroku config -a web", Read),
        ("psql -c 'select 1'", Read),
        (
            "psql -h db -U app -c 'SELECT id, name FROM users WHERE id IN (1, 2)'",
            Read,
        ),
        ("psql -c '\\dt'", Read),
        ("mysql -h db -u app -e 'SELECT id FROM users'", Read),
        ("sqlite3 app.db 'select * from users'", Read),
        ("terraform output", Read),
        ("node --version", Read),
        // Interpreters with inline code.
        ("python -c 'print(1)'", Change),
        ("python3 -c 'import os'", Change),
        ("ruby -e 'puts 1'", Change),
        ("node -e 'console.log(1)'", Change),
        ("node --eval 'console.log(1)'", Change),
        ("node -p '1 + 1'", Change),
        ("perl -e 'print 1'", Change),
        ("php -r 'echo 1;'", Change),
        ("bash -c 'ls'", Change),
        ("sh -c 'ls -la'", Change),
        ("zsh -c 'cat README.md'", Change),
        ("deno eval 'console.log(1)'", Change),
        ("osascript -e 'beep'", Change),
        ("eval ls", Change),
        // `git -c`, output files, redirects, pipes.
        ("git -c core.pager=less log", Change),
        ("git -c core.fsmonitor=./x status", Change),
        ("git diff --output=patch.diff", Change),
        ("git diff --output patch.diff", Change),
        ("git log --ext-diff -p", Change),
        ("git grep -Ovim TODO", Change),
        ("kubectl get pods --output=pods.txt", Change),
        ("kubectl get pods -o pods.txt", Change),
        ("kubectl get pods > pods.txt", Change),
        ("kubectl get pods | tee pods.txt", Change),
        ("ls | tee out.txt", Change),
        ("sort -o out.txt in.txt", Change),
        ("tree -o out.txt", Change),
        ("curl -o page.html https://example.invalid", Change),
        ("rg --pre ./x TODO", Change),
        ("cat a >> out.txt", Change),
        // SQL other than a plain SELECT.
        ("psql -c 'select count(*) from users'", Change),
        ("psql -c 'select now()'", Change),
        ("psql -c 'select pg_sleep(10)'", Change),
        ("psql -c 'select * from users for update'", Change),
        ("psql -c 'select * into backup from users'", Change),
        ("psql -c '\\o /tmp/out'", Change),
        ("psql -c '\\! ls'", Change),
        ("psql -c 'select 1' -o out.txt", Change),
        ("psql -c 'select 1 -- comment'", Change),
        ("psql -c 'select $$x$$'", Change),
        ("psql -c 'insert into t values (1)'", Change),
        ("psql -c 'update t set a = 1'", Change),
        ("psql -f migrate.sql", Change),
        ("psql", Change),
        ("psql -c 'COPY users TO STDOUT'", Change),
        ("mysql -e 'select * from t into outfile \"/tmp/x\"'", Change),
        ("mysql --pager=less -e 'select 1'", Change),
        ("sqlite3 app.db '.output x'", Change),
        ("sqlite3 app.db \"select writefile('x', 'y')\"", Change),
        ("sqlite3 app.db", Change),
        // A known program with a write or an unknown subcommand.
        ("kubectl exec web -- ls", Change),
        ("kubectl --kubeconfig ./k get pods", Change),
        ("kubectl scale deploy/web --replicas 0", Change),
        ("kubectl cluster-info dump --output-directory x", Change),
        ("docker --config ./d ps", Change),
        ("docker run alpine ls", Change),
        ("stripe customers create", Change),
        ("aws s3 cp s3://b/k ./k", Change),
        ("aws s3api get-object --bucket b --key k out", Change),
        ("aws lambda invoke --function-name f out.json", Change),
        ("gh api repos/o/r/pulls -f title=x", Change),
        ("gh api -X POST repos/o/r/issues", Change),
        ("gh myext list", Change),
        ("gh run download 1", Change),
        ("git branch new-feature", Change),
        ("git config user.name x", Change),
        ("git fetch", Change),
        ("vercel env pull", Change),
        ("terraform plan", Change),
        ("env PAGER=x git log", Change),
        ("sudo ls", Change),
        ("./ls", Change),
        ("/bin/ls", Change),
        ("curl https://example.invalid", Change),
        ("npm test", Change),
        ("make", Change),
        ("mkdir x", Change),
        ("op run -- ls", Change),
        ("xargs cat", Change),
        // A delete that the word rules do not see is still not a read.
        ("node -e 'require(\"fs\").unlinkSync(\"x\")'", Change),
        // Deploy.
        ("vercel", Deploy),
        ("vercel --prod", Deploy),
        ("vercel deploy", Deploy),
        ("vercel ./site --prod", Deploy),
        ("vercel promote https://x.vercel.app", Deploy),
        ("fly deploy", Deploy),
        ("flyctl deploy -a web", Deploy),
        ("wrangler deploy", Deploy),
        ("wrangler publish", Deploy),
        ("kubectl apply -f k8s.yaml", Deploy),
        ("kubectl rollout restart deploy/web", Deploy),
        ("helm install web ./chart", Deploy),
        ("helm upgrade --install web ./chart", Deploy),
        ("helm rollback web 1", Deploy),
        ("docker push ghcr.io/acme/api:1", Deploy),
        ("git push", Deploy),
        ("git push -u origin feature", Deploy),
        ("git push origin main", Deploy),
        ("git push origin HEAD:refs/heads/x --dry-run", Deploy),
        ("gh release create v1", Deploy),
        ("npm publish", Deploy),
        ("cargo publish", Deploy),
        ("pulumi up --yes", Deploy),
        ("sh -c 'npm test && git push origin main'", Deploy),
        ("timeout 60 git push", Deploy),
        // Delete.
        ("sh -c 'rm -rf x'", Delete),
        ("bash -c 'echo hi && rm -rf x'", Delete),
        ("sh -c \"sh -c 'rm -rf x'\"", Delete),
        ("bash -c 'git push origin :feature'", Delete),
        ("bash -c 'cd x; echo $(git push origin +main)'", Delete),
        ("python -c 'import shutil; shutil.rmtree(\"x\")'", Delete),
        ("python3 -c \"import os; os.remove('x')\"", Delete),
        ("git push origin :feature", Delete),
        ("git push origin +main", Delete),
        ("git push origin +main:main", Delete),
        ("git push -fu origin main", Delete),
        ("git push --force", Delete),
        ("git push --force-with-lease origin main", Delete),
        ("git push --mirror origin", Delete),
        ("git push --prune origin", Delete),
        ("git push origin --delete feature", Delete),
        ("git push -d origin feature", Delete),
        ("git reset --hard HEAD~1", Delete),
        ("git clean -fdx", Delete),
        ("git branch -D old", Delete),
        ("git tag -d v1", Delete),
        ("git stash clear", Delete),
        ("git stash drop", Delete),
        ("git filter-repo --path x --invert-paths", Delete),
        ("npm unpublish pkg@1.0.0", Delete),
        ("gh repo delete o/r --yes", Delete),
        ("gh api -X DELETE repos/o/r", Delete),
        ("gh api -XDELETE repos/o/r", Delete),
        ("gh api --method DELETE repos/o/r", Delete),
        ("gh api --method=DELETE repos/o/r", Delete),
        ("curl -X DELETE https://api.example.invalid/x", Delete),
        ("curl -XDELETE https://api.example.invalid/x", Delete),
        (
            "curl --request DELETE https://api.example.invalid/x",
            Delete,
        ),
        (
            "curl --request=DELETE https://api.example.invalid/x",
            Delete,
        ),
        ("aws s3api delete-bucket --bucket b", Delete),
        ("aws ec2 terminate-instances --instance-ids i-1", Delete),
        ("aws s3 rm s3://b/k", Delete),
        ("aws s3 rb s3://b --force", Delete),
        ("aws s3 rb s3://b", Delete),
        ("aws s3 sync . s3://b --delete", Delete),
        ("heroku apps:destroy -a web", Delete),
        ("heroku pg:reset DATABASE_URL", Delete),
        ("rails db:drop", Delete),
        ("rails db:reset", Delete),
        ("bin/rails db:reset", Delete),
        ("rails db:rollback", Delete),
        ("rails db:schema:load", Delete),
        ("rake db:drop", Delete),
        ("php artisan migrate:fresh", Delete),
        ("prisma migrate reset --force", Delete),
        ("kubectl delete pod web", Delete),
        ("helm uninstall web", Delete),
        ("terraform destroy", Delete),
        ("terraform apply -destroy", Delete),
        ("docker volume rm data", Delete),
        ("docker system prune -a", Delete),
        ("redis-cli flushall", Delete),
        ("dropdb app", Delete),
        ("find . -name '*.log' -delete", Delete),
        ("sudo rm -rf /tmp/x", Delete),
        ("timeout 5 rm x", Delete),
        ("psql -c 'DROP TABLE users'", Delete),
        ("psql -c 'drop table users'", Delete),
        ("psql -c 'TRUNCATE users'", Delete),
        ("psql -c 'delete from users'", Delete),
        ("psql -c 'select 1; DrOp TABLE users'", Delete),
        ("psql -c 'ALTER TABLE users DROP COLUMN email'", Delete),
        ("psql -c 'select pg_terminate_backend(123)'", Delete),
        ("psql -c 'select lo_unlink(1)'", Delete),
        ("psql -c 'select pg_drop_replication_slot(1)'", Delete),
        ("mysql -e 'DROP DATABASE app'", Delete),
        ("sqlite3 app.db 'delete from users'", Delete),
    ];
    assert!(lines.len() >= 200, "{}", lines.len());
    let mut failures: Vec<String> = lines
        .iter()
        .filter_map(|(line, expected)| check(&command_line_to_argv(line), *expected))
        .collect();

    // Argument lists that an agent sends without a shell.
    let argvs: &[(&[&str], ActionKind)] = &[
        (&["AWS_PROFILE=prod", "aws", "s3", "ls"], Read),
        (
            &["env", "AWS_REGION=eu-west-1", "kubectl", "get", "pods"],
            Read,
        ),
        (&["psql", "-c", "select 1 where 2 > 1"], Read),
        (&["PAGER=rm -rf x", "git", "log"], Delete),
        (&["GIT_EXTERNAL_DIFF=./x", "git", "diff"], Change),
        (&["KUBECONFIG=./k", "kubectl", "get", "pods"], Change),
        (&["find", ".", "-exec", "cat", "{}", ";"], Change),
        (&["psql", "-c", "select 1", "|", "sh"], Change),
        (&["cat", "a", "2>", "err.txt"], Change),
        (&["sh", "-c", "psql <<EOF\nselect 1;\nEOF"], Change),
        (&["sh", "-c", "psql <<EOF\nDROP TABLE x;\nEOF"], Delete),
        (
            &["bash", "-eo", "pipefail", "-c", "git push origin :main"],
            Delete,
        ),
        (&["bash", "script.sh"], Change),
        (&["xargs", "-I{}", "rm", "{}"], Delete),
        // Deeper than the parser follows: the words still count.
        (
            &[
                "sh",
                "-c",
                "sh -c \"sh -c 'sh -c \\\"sh -c sh\\ -c\\ rm\\\"'\"",
            ],
            Delete,
        ),
    ];
    for (command, expected) in argvs {
        let argv: Vec<String> = command.iter().map(|w| (*w).to_owned()).collect();
        failures.extend(check(&argv, *expected));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn neutral_flags_keep_a_read_and_other_flags_raise_it() {
    let command: Vec<String> = ["kubectl", "get", "pods"].map(str::to_owned).to_vec();
    let with_flag = |flag: &str| Analysis {
        flags: vec![flag.to_owned()],
        ..Analysis::default()
    };
    for flag in [
        "production",
        "secret_output",
        "injection_phrase",
        "foreign_host",
    ] {
        assert_eq!(classify(&command, &with_flag(flag)), Read, "{flag}");
    }
    for flag in [
        "system_change",
        "remote_code",
        "privilege",
        "new_dependency",
        "x",
    ] {
        assert_eq!(classify(&command, &with_flag(flag)), Change, "{flag}");
    }
    assert_eq!(classify(&command, &with_flag("irreversible")), Delete);
    // `known_safe` alone never makes a read: the packs mark local changes as safe.
    let safe = Analysis {
        known_safe: true,
        known_command: true,
        ..Analysis::default()
    };
    for line in [
        "mkdir x",
        "npm install",
        "git commit -m x",
        "op run -- psql",
    ] {
        assert_ne!(classify(&command_line_to_argv(line), &safe), Read, "{line}");
    }
}
