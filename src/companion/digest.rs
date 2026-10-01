//! The digest of a waiting run (contract companion-v1, section 7).
//!
//! The digest names a run exactly as the Mac shows it: SHA-256 over a version tag and
//! every field of the [`PendingRun`], each with its length. A text is its length as an
//! 8-byte big-endian number and its bytes. A list is its count and its texts. The remember
//! offer is a marker byte, and for an offer its pattern and two counts. So no two
//! different runs give the same input, also when text moves from one field to the next
//! (`["ab", "c"]` and `["a", "bc"]` differ).
//!
//! The phone treats the digest as opaque and signs it in an approval. Only the Mac
//! computes it.

use ring::digest::{Context, SHA256};

use super::crypto::hex;
use crate::broker::approvals::PendingRun;

/// The version tag at the start of the digest input. A change of the encoding changes it.
const TAG: &str = "apassy-companion-run-v1";

/// The digest of `run` as 32 bytes.
pub fn run_digest(run: &PendingRun) -> [u8; 32] {
    let mut hash = Context::new(&SHA256);
    text(&mut hash, TAG);
    hash.update(&run.id.to_be_bytes());
    text(&mut hash, &run.agent);
    list(&mut hash, &run.command);
    text(&mut hash, &run.cwd);
    list(&mut hash, &run.env_names);
    text(&mut hash, &run.purpose);
    text(&mut hash, &run.risk);
    text(&mut hash, &run.user_request);
    text(&mut hash, &run.request_source);
    text(&mut hash, &run.agent_request);
    match &run.remember {
        None => hash.update(&[0]),
        Some(offer) => {
            hash.update(&[1]);
            text(&mut hash, &offer.pattern);
            hash.update(&offer.approvals.to_be_bytes());
            hash.update(&offer.needed.to_be_bytes());
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.finish().as_ref());
    out
}

/// The digest of `run` as 64 lowercase hex characters, as the wire has it.
pub fn run_digest_hex(run: &PendingRun) -> String {
    hex(&run_digest(run))
}

fn length(hash: &mut Context, len: usize) {
    hash.update(&(len as u64).to_be_bytes());
}

fn text(hash: &mut Context, value: &str) {
    length(hash, value.len());
    hash.update(value.as_bytes());
}

fn list(hash: &mut Context, values: &[String]) {
    length(hash, values.len());
    for value in values {
        text(hash, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::approvals::RememberOffer;

    fn base() -> PendingRun {
        PendingRun {
            id: 123_456_789_012_345,
            agent: "claude-code".to_owned(),
            command: vec!["npm".to_owned(), "run".to_owned(), "migrate".to_owned()],
            cwd: "/tmp/synthetic-shop".to_owned(),
            env_names: vec!["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()],
            purpose: "Apply the new migration.".to_owned(),
            risk: "production credential: always asks the owner".to_owned(),
            user_request: "Deploy the new schema to staging.".to_owned(),
            request_source: "from the host hook".to_owned(),
            agent_request: "Run the migration.".to_owned(),
            remember: Some(RememberOffer {
                pattern: "npm run migrate".to_owned(),
                approvals: 1,
                needed: 3,
            }),
        }
    }

    #[test]
    fn the_digest_is_stable_and_has_64_hex_characters() {
        let digest = run_digest_hex(&base());
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(digest, run_digest_hex(&base().clone()));
        assert_eq!(hex(&run_digest(&base())), digest);
    }

    #[test]
    fn every_field_changes_the_digest() {
        let original = run_digest(&base());
        let variants: Vec<(&str, PendingRun)> = vec![
            ("id", PendingRun { id: 1, ..base() }),
            (
                "agent",
                PendingRun {
                    agent: "codex".to_owned(),
                    ..base()
                },
            ),
            (
                "command",
                PendingRun {
                    command: vec!["npm".to_owned(), "run".to_owned()],
                    ..base()
                },
            ),
            (
                "cwd",
                PendingRun {
                    cwd: "/tmp/other".to_owned(),
                    ..base()
                },
            ),
            (
                "env_names",
                PendingRun {
                    env_names: vec!["DATABASE_URL".to_owned()],
                    ..base()
                },
            ),
            (
                "purpose",
                PendingRun {
                    purpose: "Apply.".to_owned(),
                    ..base()
                },
            ),
            (
                "risk",
                PendingRun {
                    risk: String::new(),
                    ..base()
                },
            ),
            (
                "user_request",
                PendingRun {
                    user_request: String::new(),
                    ..base()
                },
            ),
            (
                "request_source",
                PendingRun {
                    request_source: "from the agent".to_owned(),
                    ..base()
                },
            ),
            (
                "agent_request",
                PendingRun {
                    agent_request: String::new(),
                    ..base()
                },
            ),
            (
                "remember none",
                PendingRun {
                    remember: None,
                    ..base()
                },
            ),
            (
                "remember pattern",
                PendingRun {
                    remember: Some(RememberOffer {
                        pattern: "npm run <word>".to_owned(),
                        approvals: 1,
                        needed: 3,
                    }),
                    ..base()
                },
            ),
            (
                "remember approvals",
                PendingRun {
                    remember: Some(RememberOffer {
                        pattern: "npm run migrate".to_owned(),
                        approvals: 2,
                        needed: 3,
                    }),
                    ..base()
                },
            ),
            (
                "remember needed",
                PendingRun {
                    remember: Some(RememberOffer {
                        pattern: "npm run migrate".to_owned(),
                        approvals: 1,
                        needed: 4,
                    }),
                    ..base()
                },
            ),
        ];
        for (field, variant) in &variants {
            assert_ne!(run_digest(variant), original, "{field}");
        }
        // Each variant also differs from every other variant.
        for (i, (a, left)) in variants.iter().enumerate() {
            for (b, right) in &variants[i + 1..] {
                assert_ne!(run_digest(left), run_digest(right), "{a} and {b}");
            }
        }
    }

    #[test]
    fn a_shift_between_list_items_changes_the_digest() {
        let with = |command: &[&str]| PendingRun {
            command: command.iter().map(|part| (*part).to_owned()).collect(),
            ..base()
        };
        assert_ne!(
            run_digest(&with(&["ab", "c"])),
            run_digest(&with(&["a", "bc"]))
        );
        assert_ne!(
            run_digest(&with(&["ab", ""])),
            run_digest(&with(&["a", "b"]))
        );
        assert_ne!(run_digest(&with(&["a b"])), run_digest(&with(&["a", "b"])));
        assert_ne!(run_digest(&with(&[])), run_digest(&with(&[""])));
        assert_ne!(run_digest(&with(&["", ""])), run_digest(&with(&[""])));
        let env = |names: &[&str]| PendingRun {
            env_names: names.iter().map(|name| (*name).to_owned()).collect(),
            ..base()
        };
        assert_ne!(
            run_digest(&env(&["AB", "C"])),
            run_digest(&env(&["A", "BC"]))
        );
    }

    #[test]
    fn moving_text_between_adjacent_fields_changes_the_digest() {
        let pair = |first: &str, second: &str| {
            (
                PendingRun {
                    agent: first.to_owned(),
                    cwd: second.to_owned(),
                    ..base()
                },
                PendingRun {
                    purpose: first.to_owned(),
                    risk: second.to_owned(),
                    ..base()
                },
                PendingRun {
                    user_request: first.to_owned(),
                    request_source: second.to_owned(),
                    ..base()
                },
                PendingRun {
                    request_source: first.to_owned(),
                    agent_request: second.to_owned(),
                    ..base()
                },
            )
        };
        let (a1, b1, c1, d1) = pair("ab", "c");
        let (a2, b2, c2, d2) = pair("a", "bc");
        assert_ne!(run_digest(&a1), run_digest(&a2));
        assert_ne!(run_digest(&b1), run_digest(&b2));
        assert_ne!(run_digest(&c1), run_digest(&c2));
        assert_ne!(run_digest(&d1), run_digest(&d2));
        // The same text in two different fields is a different run.
        assert_ne!(run_digest(&a1), run_digest(&b1));
        assert_ne!(run_digest(&c1), run_digest(&d1));
        // A text that moves from the last text field to the remember pattern.
        let moved_out = PendingRun {
            agent_request: "npm run migrate".to_owned(),
            remember: None,
            ..base()
        };
        let moved_in = PendingRun {
            agent_request: String::new(),
            remember: Some(RememberOffer {
                pattern: "npm run migrate".to_owned(),
                approvals: 0,
                needed: 0,
            }),
            ..base()
        };
        assert_ne!(run_digest(&moved_out), run_digest(&moved_in));
    }

    #[test]
    fn an_empty_offer_pattern_differs_from_no_offer() {
        let none = PendingRun {
            remember: None,
            ..base()
        };
        let empty = PendingRun {
            remember: Some(RememberOffer {
                pattern: String::new(),
                approvals: 0,
                needed: 0,
            }),
            ..base()
        };
        assert_ne!(run_digest(&none), run_digest(&empty));
    }

    #[test]
    fn a_text_with_a_newline_or_a_length_look_alike_does_not_collide() {
        let a = PendingRun {
            purpose: "x\ny".to_owned(),
            ..base()
        };
        let b = PendingRun {
            purpose: "x".to_owned(),
            risk: "y".to_owned(),
            ..base()
        };
        assert_ne!(run_digest(&a), run_digest(&b));
        // A text that starts with the 8-byte length of the next field.
        let prefix = String::from_utf8(vec![0, 0, 0, 0, 0, 0, 0, 1]).expect("ascii");
        let c = PendingRun {
            agent: format!("a{prefix}b"),
            cwd: String::new(),
            ..base()
        };
        let d = PendingRun {
            agent: "a".to_owned(),
            cwd: "b".to_owned(),
            ..base()
        };
        assert_ne!(run_digest(&c), run_digest(&d));
    }
}
