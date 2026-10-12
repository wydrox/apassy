#![cfg(feature = "vault")]

//! The kind of action of a command (ADR 0025 §3a). Synthetic commands only.

use apassy::broker::action_kind::{ActionKind, classify};
use apassy::broker::shell_risk::Analysis;

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
