//! The rows of a search follow each change of the vault, also while the session keeps
//! the rows of its last searches ([`SearchCache`]). Synthetic values only.

use super::*;

const PASS: &str = "search-cache-pass-1";

fn unlocked(dir: &tempfile::TempDir) -> OwnerSession {
    let mut session = OwnerSession::new();
    session
        .create_file(&dir.path().join("search.apassy"), PASS)
        .expect("create");
    session.unlock(PASS).expect("unlock");
    session
}

fn add(session: &mut OwnerSession, name: &str, service: &str) -> OwnerSummary {
    let mut secrets = SecretForm::default();
    secrets.token = "synthetic-search-token".to_owned();
    session
        .add(
            &ItemDraft {
                name: name.to_owned(),
                kind: CredentialKind::ApiKey,
                service: service.to_owned(),
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add")
}

fn names(rows: &[OwnerSummary]) -> Vec<&str> {
    let mut names: Vec<&str> = rows.iter().map(|row| row.name.as_str()).collect();
    names.sort_unstable();
    names
}

#[test]
fn a_search_follows_each_change_of_the_vault() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let mut session = unlocked(&dir);
    let alpha = add(&mut session, "Alpha", "billing");
    let first = session.search("").expect("search");
    assert_eq!(names(&first), ["Alpha"]);
    assert_eq!(first[0].service, "billing");
    // The same state: the same rows.
    assert_eq!(session.search("").expect("search"), first);

    // An add, an edit, and a typed query.
    add(&mut session, "Beta", "payments");
    assert_eq!(
        names(&session.search("").expect("search")),
        ["Alpha", "Beta"]
    );
    assert_eq!(names(&session.search("Alpha").expect("search")), ["Alpha"]);
    let details = session.details(alpha.id).expect("details");
    let mut draft = details.to_draft();
    draft.service = "invoices".to_owned();
    session
        .update(alpha.id, details.revision, &draft, &SecretForm::default())
        .expect("update");
    let rows = session.search("Alpha").expect("search");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].service, "invoices");

    // A write of another thread through the shared slot, as the broker and the sync
    // worker write.
    session
        .with_vault(|vault| {
            vault
                .add(crate::vault::ItemDraft {
                    title: "Alpha from the broker".to_owned(),
                    kind: CredentialKind::ApiKey,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![crate::vault::Field {
                        name: "token".to_owned(),
                        value: SecretValue::new("synthetic-broker-token".to_owned()),
                        secret: true,
                    }],
                })
                .expect("add")
        })
        .expect("open vault");
    assert_eq!(
        names(&session.search("Alpha").expect("search")),
        ["Alpha", "Alpha from the broker"]
    );
    assert_eq!(session.search("").expect("search").len(), 3);

    // A delete.
    let beta = session.search("Beta").expect("search").pop().expect("Beta");
    session.delete(beta.id, beta.revision).expect("delete");
    assert_eq!(
        names(&session.search("").expect("search")),
        ["Alpha", "Alpha from the broker"]
    );

    // A locked vault answers nothing, and keeps no row of a search.
    session.lock().expect("lock");
    assert!(session.search("").is_err());
    assert_eq!(
        format!("{:?}", session.searches()),
        "SearchCache { searches: 0 }"
    );
    session.unlock(PASS).expect("unlock");
    assert_eq!(session.search("").expect("search").len(), 2);
}

#[test]
fn the_cache_keeps_four_searches_of_one_vault_state() {
    let row = |name: &str| OwnerSummary {
        id: 1,
        name: name.to_owned(),
        kind: CredentialKind::ApiKey,
        service: String::new(),
        project: String::new(),
        revision: 1,
    };
    let now = ([7u8; 32], 10);
    let mut cache = SearchCache::default();
    cache.put(now, "", &[row("All")]);
    assert_eq!(cache.get(now, ""), Some(vec![row("All")]));
    assert_eq!(cache.get(now, "a"), None, "another query");
    assert_eq!(cache.get(([7u8; 32], 11), ""), None, "a write since");
    assert_eq!(cache.get(([8u8; 32], 10), ""), None, "another session");

    // Four queries at most: the oldest goes.
    for query in ["a", "b", "c", "d"] {
        cache.put(now, query, &[row(query)]);
    }
    assert_eq!(cache.get(now, ""), None);
    assert_eq!(cache.get(now, "d"), Some(vec![row("d")]));

    // Another state drops every row of the last one.
    let later = ([7u8; 32], 12);
    cache.put(later, "e", &[row("e")]);
    assert_eq!(cache.get(now, "d"), None);
    assert_eq!(cache.get(later, "e"), Some(vec![row("e")]));
    // No query and no row reaches a log.
    assert_eq!(format!("{cache:?}"), "SearchCache { searches: 1 }");
}
