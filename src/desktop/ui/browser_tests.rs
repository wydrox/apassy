//! Headless tests of the browser socket in the app (ADR 0021). Synthetic values only.

use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use eframe::egui;
use tempfile::TempDir;

use super::owner_tests::{PASS, WRONG, app_frame, finish_check, unlocked_app_with_item};
use crate::broker::approvals::{OwnerAction, OwnerCheck};
use crate::browser::site::Page;
use crate::browser::wire::{Command, Data, EXTENSION_ORIGIN, Response, VaultState};
use crate::contracts::CredentialKind;
use crate::desktop::DesktopApp;
use crate::desktop::browser::BROWSER_ORIGIN_NOTE;
use crate::desktop::model::{DetailDraft, ItemDraft};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_socket::Envelope;
use crate::desktop::owner_store::SecretForm;
use crate::vault::{FILL_DETAIL_PREFIX, ItemEventKind};

const PASSWORD: &str = "browser-fill-canary-0123456789";
const OTHER_PASSWORD: &str = "browser-other-canary-9876543210";

fn add_login(app: &mut DesktopApp, name: &str, username: &str, websites: &[&str]) -> u64 {
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    let details = websites
        .iter()
        .enumerate()
        .map(|(index, website)| DetailDraft {
            label: if index == 0 {
                "Website".to_owned()
            } else {
                format!("Website {}", index + 1)
            },
            value: (*website).to_owned(),
            hidden: false,
            stored: None,
        })
        .collect();
    app.owner_ui
        .session
        .add(
            &ItemDraft {
                name: name.to_owned(),
                kind: CredentialKind::Login,
                username: username.to_owned(),
                details,
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add login")
        .id
}

/// An API key with a website detail. It is not a login, so it never matches.
fn add_api_key_with_website(app: &mut DesktopApp) -> u64 {
    let mut secrets = SecretForm::default();
    secrets.token = OTHER_PASSWORD.to_owned();
    app.owner_ui
        .session
        .add(
            &ItemDraft {
                name: "GitHub token".to_owned(),
                kind: CredentialKind::ApiKey,
                details: vec![DetailDraft {
                    label: "Website".to_owned(),
                    value: "https://github.com".to_owned(),
                    hidden: false,
                    stored: None,
                }],
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add key")
        .id
}

fn ask(app: &mut DesktopApp, ctx: &egui::Context, command: Command) -> Receiver<Response> {
    let (reply, answer) = mpsc::channel();
    app.handle_browser(
        Envelope {
            request: command,
            reply,
        },
        ctx,
    );
    answer
}

fn now(answer: &Receiver<Response>) -> Response {
    answer.try_recv().expect("an answer without an owner check")
}

fn logins(app: &mut DesktopApp, ctx: &egui::Context, url: &str) -> Response {
    now(&ask(
        app,
        ctx,
        Command::Logins {
            url: url.to_owned(),
        },
    ))
}

fn fill(app: &mut DesktopApp, ctx: &egui::Context, url: &str, item: u64) -> Receiver<Response> {
    ask(
        app,
        ctx,
        Command::Fill {
            url: url.to_owned(),
            item,
        },
    )
}

fn json(response: &Response) -> String {
    serde_json::to_string(response).expect("json")
}

#[test]
fn logins_list_only_the_logins_of_the_page_and_no_value() {
    let dir = TempDir::new().unwrap();
    let (mut app, _key) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let github = add_login(&mut app, "GitHub", "rafal", &["https://github.com/login"]);
    let work = add_login(
        &mut app,
        "Work GitHub",
        "rafal-work",
        &["gitlab.com", "https://www.github.com"],
    );
    add_login(&mut app, "GitLab", "rafal", &["gitlab.com"]);
    add_login(&mut app, "No website", "rafal", &[]);
    let archived = add_login(&mut app, "Old GitHub", "old", &["github.com"]);
    app.owner_ui.session.archive(archived).unwrap();
    add_api_key_with_website(&mut app);

    let response = logins(&mut app, &ctx, "https://gist.github.com/rafal");
    assert!(response.ok, "{response:?}");
    let text = json(&response);
    assert!(!text.contains(PASSWORD), "{text}");
    assert!(!text.contains(OTHER_PASSWORD), "{text}");
    let Data::Logins {
        origin,
        host,
        logins: rows,
    } = response.data
    else {
        panic!("no logins: {text}");
    };
    assert_eq!(origin, "https://gist.github.com");
    assert_eq!(host, "gist.github.com");
    let found: Vec<(u64, &str, &str)> = rows
        .iter()
        .map(|login| (login.item, login.title.as_str(), login.username.as_str()))
        .collect();
    // "www.github.com" of the work login matches github.com, not gist.github.com.
    assert_eq!(found, vec![(github, "GitHub", "rafal")]);

    let response = logins(&mut app, &ctx, "https://github.com/login");
    let Data::Logins { logins: rows, .. } = response.data else {
        panic!("no logins");
    };
    let found: Vec<u64> = rows.iter().map(|login| login.item).collect();
    assert_eq!(found, vec![github, work]);

    let response = logins(&mut app, &ctx, "https://github.com.evil.example/login");
    assert!(response.ok);
    let Data::Logins { logins: rows, .. } = response.data else {
        panic!("no logins");
    };
    assert!(rows.is_empty(), "a look-alike host gets nothing");
}

#[test]
fn pages_that_are_not_https_get_nothing() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let github = add_login(&mut app, "GitHub", "rafal", &["github.com"]);
    for url in [
        "http://github.com/login",
        "chrome://settings",
        "file:///Users/x",
    ] {
        assert_eq!(
            logins(&mut app, &ctx, url).code,
            "unsupported_page",
            "{url}"
        );
        assert_eq!(
            now(&fill(&mut app, &ctx, url, github)).code,
            "unsupported_page"
        );
    }
    assert!(app.owner.check.is_none());
}

#[test]
fn status_follows_the_vault_and_a_locked_vault_lists_nothing() {
    let ctx = egui::Context::default();
    let mut empty = DesktopApp::new();
    let status = now(&ask(&mut empty, &ctx, Command::Status));
    assert!(matches!(
        status.data,
        Data::Status {
            vault: VaultState::None,
            ..
        }
    ));
    assert_eq!(
        logins(&mut empty, &ctx, "https://github.com/").code,
        "none_open"
    );

    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let github = add_login(&mut app, "GitHub", "rafal", &["github.com"]);
    let status = now(&ask(&mut app, &ctx, Command::Status));
    let Data::Status { vault, version } = status.data else {
        panic!("no status");
    };
    assert_eq!(vault, VaultState::Unlocked);
    assert_eq!(version, env!("CARGO_PKG_VERSION"));

    app.lock_vault(None);
    let status = now(&ask(&mut app, &ctx, Command::Status));
    assert!(matches!(
        status.data,
        Data::Status {
            vault: VaultState::Locked,
            ..
        }
    ));
    assert_eq!(
        logins(&mut app, &ctx, "https://github.com/").code,
        "vault_locked"
    );
    assert_eq!(
        now(&fill(&mut app, &ctx, "https://github.com/", github)).code,
        "vault_locked"
    );
    assert!(app.owner.check.is_none());
}

#[test]
fn each_fill_waits_for_its_own_owner_check() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let github = add_login(&mut app, "GitHub", "rafal", &["https://github.com/login"]);

    let answer = fill(&mut app, &ctx, "https://github.com/login?next=/", github);
    assert!(
        answer.try_recv().is_err(),
        "a fill waits for the owner check"
    );
    let dialog = app.owner.check.as_ref().expect("the owner check is open");
    assert!(
        dialog.browser.is_some(),
        "the dialog knows that the browser asked"
    );
    assert_eq!(
        dialog.request.action(),
        OwnerAction::FillLogin {
            item_id: github,
            login: "GitHub".to_owned(),
            origin: "https://github.com".to_owned()
        }
    );
    let text = app_frame(&ctx, &mut app);
    assert!(
        text.contains("Fill the login \"GitHub\" (rafal) on https://github.com"),
        "{text}"
    );
    assert!(text.contains(BROWSER_ORIGIN_NOTE), "{text}");
    assert!(!text.contains(PASSWORD));

    // A wrong passphrase keeps the dialog and the request open.
    if let Some(dialog) = app.owner.check.as_mut() {
        dialog.passphrase.push_str(WRONG);
    }
    app.start_passphrase_check(&ctx);
    finish_check(&mut app, &ctx);
    assert!(app.owner.check.is_some());
    assert!(answer.try_recv().is_err(), "nothing for a wrong passphrase");

    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let response = answer.try_recv().expect("the fill answer");
    assert!(response.ok, "{response:?}");
    let Data::Fill {
        item,
        origin,
        username,
        password,
    } = response.data
    else {
        panic!("no fill: {:?}", response.data);
    };
    assert_eq!(item, github);
    assert_eq!(origin, "https://github.com");
    assert_eq!(username, "rafal");
    assert_eq!(password.expose(), PASSWORD);
    assert!(!response.message.contains(PASSWORD));
    assert!(app.browser_filled_is_empty(), "the app keeps no copy");

    let events = app.owner_ui.session.item_events(github, 10).unwrap();
    assert!(
        events
            .iter()
            .any(|event| event.kind == ItemEventKind::Revealed
                && event.detail == format!("{FILL_DETAIL_PREFIX}https://github.com")),
        "{events:?}"
    );

    // The next fill asks again.
    let again = fill(&mut app, &ctx, "https://github.com/", github);
    assert!(again.try_recv().is_err(), "a second fill waits too");
    assert!(app.owner.check.is_some());
}

#[test]
fn a_login_of_another_site_is_refused_before_the_check() {
    let dir = TempDir::new().unwrap();
    let (mut app, key) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let gitlab = add_login(&mut app, "GitLab", "rafal", &["gitlab.com"]);
    let token = add_api_key_with_website(&mut app);
    for item in [gitlab, token, key, 9999] {
        let response = now(&fill(&mut app, &ctx, "https://github.com/", item));
        assert_eq!(response.code, "no_match", "{item}");
        assert!(!json(&response).contains(PASSWORD));
        assert!(!json(&response).contains(OTHER_PASSWORD));
    }
    assert!(app.owner.check.is_none(), "no owner check for a wrong site");
}

#[test]
fn a_closed_dialog_or_a_lock_fills_nothing() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let github = add_login(&mut app, "GitHub", "rafal", &["github.com"]);

    let answer = fill(&mut app, &ctx, "https://github.com/", github);
    app.close_owner_check(Some(&ctx));
    let response = answer.try_recv().expect("an answer after cancel");
    assert_eq!(response.code, "cancelled");
    assert!(!json(&response).contains(PASSWORD));

    let answer = fill(&mut app, &ctx, "https://github.com/", github);
    app.lock_vault(Some(&ctx));
    let response = answer.try_recv().expect("an answer after the lock");
    assert_eq!(response.code, "cancelled");
}

#[test]
fn a_fill_while_another_check_is_open_is_busy() {
    let dir = TempDir::new().unwrap();
    let (mut app, key) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let github = add_login(&mut app, "GitHub", "rafal", &["github.com"]);
    app.ask_owner(OwnerRequest::Reveal { item_id: key }, Some(&ctx));
    let response = now(&fill(&mut app, &ctx, "https://github.com/", github));
    assert_eq!(response.code, "busy");
    assert_eq!(
        app.owner.check.as_ref().map(|d| d.request.clone()),
        Some(OwnerRequest::Reveal { item_id: key }),
        "the open dialog stays"
    );
}

#[test]
fn a_login_archived_during_the_check_is_refused() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let github = add_login(&mut app, "GitHub", "rafal", &["github.com"]);
    let answer = fill(&mut app, &ctx, "https://github.com/", github);
    app.owner_ui.session.archive(github).unwrap();
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let response = answer.try_recv().expect("an answer");
    assert_eq!(response.code, "refused");
    assert!(!json(&response).contains(PASSWORD));
}

#[test]
fn a_proof_for_one_site_does_not_fill_another() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let github = add_login(&mut app, "GitHub", "rafal", &["github.com"]);
    let proof = app
        .owner_gate()
        .authorize(
            OwnerAction::FillLogin {
                item_id: github,
                login: "GitHub".to_owned(),
                origin: "https://github.com".to_owned(),
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("proof");
    let other = Page::parse("https://gist.github.com/").unwrap();
    let err = app
        .owner_ui
        .session
        .fill_login(github, &other, proof)
        .expect_err("the proof names another site");
    assert_eq!(err.code, "owner_check_required");
}

/// The whole path without the browser: the host relay, the socket, and the app.
#[test]
fn the_host_reaches_the_app_through_the_socket() {
    use std::ffi::OsString;
    use std::io::Cursor;

    use crate::browser::relay::{read_frame, run, write_frame};

    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let github = add_login(&mut app, "GitHub", "rafal", &["github.com"]);
    let socket = dir.path().join("s").join("browser.sock");
    app.start_browser(&socket, &ctx);
    assert_eq!(app.browser.socket_path(), Some(socket.as_path()));

    let mut input = Vec::new();
    write_frame(&mut input, br#"{"v":1,"cmd":"status"}"#).unwrap();
    write_frame(
        &mut input,
        br#"{"v":1,"cmd":"logins","url":"https://github.com/login"}"#,
    )
    .unwrap();
    let host_socket = socket.clone();
    let host = std::thread::spawn(move || {
        let mut out = Vec::new();
        let status = run(
            [
                OsString::from("apassy-browser-host"),
                OsString::from(EXTENSION_ORIGIN),
            ],
            Cursor::new(input),
            &mut out,
            &host_socket,
        );
        (status, out)
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    while !host.is_finished() {
        assert!(Instant::now() < deadline, "the host did not finish");
        app.poll_browser(&ctx);
        std::thread::sleep(Duration::from_millis(5));
    }
    let (status, out) = host.join().unwrap();
    assert_eq!(status, 0);
    let mut out = out.as_slice();
    let first: serde_json::Value =
        serde_json::from_slice(&read_frame(&mut out).unwrap().unwrap()).unwrap();
    assert_eq!(first["data"]["vault"], "unlocked", "{first}");
    let second: serde_json::Value =
        serde_json::from_slice(&read_frame(&mut out).unwrap().unwrap()).unwrap();
    assert_eq!(second["data"]["logins"][0]["item"], github, "{second}");
    app.browser.stop();
    assert!(!socket.exists(), "the socket file goes when the app stops");
}

#[test]
fn a_check_after_the_browser_stopped_waiting_fills_nothing() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let github = add_login(&mut app, "GitHub", "rafal", &["github.com"]);

    // The dialog closes at the deadline of the socket.
    let answer = fill(&mut app, &ctx, "https://github.com/", github);
    app.age_browser_check();
    app.poll_owner_flows(&ctx);
    assert!(
        app.owner.check.is_none(),
        "the dialog closed at the deadline"
    );
    assert_eq!(answer.try_recv().expect("an answer").code, "cancelled");

    // A browser that is gone gets nothing, and the history records no fill.
    let answer = fill(&mut app, &ctx, "https://github.com/", github);
    drop(answer);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    assert!(app.browser_filled_is_empty());
    assert!(
        app.status_text.contains("The browser stopped waiting"),
        "{}",
        app.status_text
    );
    let events = app.owner_ui.session.item_events(github, 10).unwrap();
    assert!(
        !events
            .iter()
            .any(|event| event.detail.starts_with(FILL_DETAIL_PREFIX)),
        "{events:?}"
    );
}

#[test]
fn the_touch_id_prompt_names_the_login_and_the_site() {
    let action = OwnerAction::FillLogin {
        item_id: 7,
        login: "GitHub \"work\"\n".to_owned(),
        origin: "https://github.com".to_owned(),
    };
    assert_eq!(action.reason(), "fill \"GitHub work\" on github.com");
}

#[test]
fn a_proof_for_a_renamed_login_is_refused() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let github = add_login(&mut app, "GitHub", "rafal", &["github.com"]);
    let proof = app
        .owner_gate()
        .authorize(
            OwnerAction::FillLogin {
                item_id: github,
                login: "Another title".to_owned(),
                origin: "https://github.com".to_owned(),
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("proof");
    let page = Page::parse("https://github.com/").unwrap();
    let err = app
        .owner_ui
        .session
        .fill_login(github, &page, proof)
        .expect_err("the proof names another title");
    assert_eq!(err.code, "owner_check_required");
}

fn save(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    url: &str,
    title: &str,
    username: &str,
    password: &str,
) -> Receiver<Response> {
    ask(
        app,
        ctx,
        Command::Save {
            url: url.to_owned(),
            title: title.to_owned(),
            username: username.to_owned(),
            password: crate::owner::wire::SecretText::new(password.to_owned()),
        },
    )
}

/// Fill login `item` on `url` with the passphrase check. Returns the password.
fn fill_now(app: &mut DesktopApp, ctx: &egui::Context, url: &str, item: u64) -> String {
    let answer = fill(app, ctx, url, item);
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let response = answer.try_recv().expect("the fill answer");
    let Data::Fill { password, .. } = response.data else {
        panic!("no fill: {}", response.message);
    };
    password.expose().to_owned()
}

#[test]
fn save_adds_the_typed_login_after_the_owner_check() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let typed = "typed-on-the-page-canary-42";

    let answer = save(
        &mut app,
        &ctx,
        "https://example.com/signin",
        "Example",
        "rafal",
        typed,
    );
    assert!(
        answer.try_recv().is_err(),
        "a save waits for the owner check"
    );
    let text = app_frame(&ctx, &mut app);
    assert!(
        text.contains(
            "For https://example.com: save the login \"Example\" (rafal). The password comes from the page."
        ),
        "{text}"
    );
    assert!(text.contains(BROWSER_ORIGIN_NOTE), "{text}");
    assert!(!text.contains(typed));
    assert_eq!(
        app.owner.check.as_ref().unwrap().request.action().reason(),
        "save the login \"Example\" for example.com"
    );

    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let response = answer.try_recv().expect("the save answer");
    assert!(response.ok, "{}", response.message);
    let Data::Saved { item } = response.data else {
        panic!("no saved data");
    };
    assert!(!json(&response).contains(typed));

    // The new login has the website of the page and the typed password.
    let details = app.owner_ui.session.details(item).unwrap();
    assert_eq!(details.kind, CredentialKind::Login);
    assert_eq!(details.username, "rafal");
    assert_eq!(details.website, "https://example.com");
    assert_eq!(
        fill_now(&mut app, &ctx, "https://example.com/", item),
        typed
    );

    // The same username again, without regard to case, is refused before a dialog.
    let again = now(&save(
        &mut app,
        &ctx,
        "https://example.com/",
        "Example 2",
        "RAFAL",
        "other",
    ));
    assert_eq!(again.code, "exists");
    assert!(again.message.contains("\"Example\""), "{}", again.message);
    assert!(app.owner.check.is_none());
}

#[test]
fn a_cancelled_save_adds_nothing() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let before = app.owner_ui.session.search("").unwrap().len();
    let answer = save(
        &mut app,
        &ctx,
        "https://example.com/",
        "Example",
        "rafal",
        "pw",
    );
    app.close_owner_check(Some(&ctx));
    assert_eq!(answer.try_recv().expect("an answer").code, "cancelled");
    assert_eq!(app.owner_ui.session.search("").unwrap().len(), before);
    assert!(app.browser_pending_is_empty());
}

#[test]
fn create_makes_a_password_and_fills_it() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let answer = ask(
        &mut app,
        &ctx,
        Command::Create {
            url: "https://example.com/join".to_owned(),
            title: "Example".to_owned(),
            username: "rafal@example.com".to_owned(),
            length: 24,
            symbols: false,
        },
    );
    assert!(
        answer.try_recv().is_err(),
        "a create waits for the owner check"
    );
    let text = app_frame(&ctx, &mut app);
    assert!(
        text.contains("For https://example.com: create the login \"Example\" (rafal@example.com) with a new 24-character password of letters and digits"),
        "{text}"
    );
    app.confirm_owner_now(OwnerCheck::passphrase(PASS))
        .expect("owner check");
    let response = answer.try_recv().expect("the create answer");
    assert!(response.ok, "{}", response.message);
    let Data::Fill {
        item,
        origin,
        username,
        password,
    } = response.data
    else {
        panic!("no fill data");
    };
    assert_eq!(origin, "https://example.com");
    assert_eq!(username, "rafal@example.com");
    assert_eq!(password.expose().len(), 24);
    assert!(password.expose().bytes().all(|b| b.is_ascii_alphanumeric()));
    let created = password.expose().to_owned();
    assert!(
        app.status_text
            .contains("The new login \"Example\" is in Apassy"),
        "{}",
        app.status_text
    );

    // The vault has the same password, and the history has the fill.
    assert_eq!(
        fill_now(&mut app, &ctx, "https://example.com/", item),
        created
    );
    let events = app.owner_ui.session.item_events(item, 10).unwrap();
    assert!(events.iter().any(|e| e.kind == ItemEventKind::Created));
    assert!(
        events
            .iter()
            .any(|e| e.detail == format!("{FILL_DETAIL_PREFIX}https://example.com"))
    );

    // A second create with the same username is refused before a dialog.
    let again = now(&ask(
        &mut app,
        &ctx,
        Command::Create {
            url: "https://example.com/join".to_owned(),
            title: "Example".to_owned(),
            username: "rafal@example.com".to_owned(),
            length: 20,
            symbols: true,
        },
    ));
    assert_eq!(again.code, "exists");
}

#[test]
fn the_website_field_of_a_login_matches_and_a_bad_one_is_refused() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    let draft = |website: &str| ItemDraft {
        name: "GitHub".to_owned(),
        kind: CredentialKind::Login,
        username: "rafal".to_owned(),
        website: website.to_owned(),
        ..ItemDraft::default()
    };
    let item = app
        .owner_ui
        .session
        .add(&draft("https://github.com/login"), &secrets)
        .unwrap()
        .id;
    assert_eq!(
        app.owner_ui.session.details(item).unwrap().website,
        "https://github.com/login"
    );
    let response = logins(&mut app, &ctx, "https://github.com/");
    let Data::Logins { logins: rows, .. } = response.data else {
        panic!("no logins");
    };
    assert_eq!(rows.iter().map(|r| r.item).collect::<Vec<_>>(), vec![item]);

    let err = app
        .owner_ui
        .session
        .add(&draft("not a web address"), &secrets)
        .expect_err("a bad website");
    assert_eq!(err.code, "invalid_input");
}

#[test]
fn settings_show_the_browser_extension_and_the_last_request() {
    let dir = TempDir::new().unwrap();
    let (mut app, _) = unlocked_app_with_item(&dir);
    let ctx = egui::Context::default();
    app.view = crate::desktop::OwnerView::Settings;
    let text = app_frame(&ctx, &mut app);
    assert!(text.contains("Browser extension"), "{text}");
    // A test program is not in an app bundle, so it connects no browser.
    assert!(
        text.contains(super::browser_settings::SOURCE_BUILD_NOTE),
        "{text}"
    );
    assert!(!text.contains("Connect\n"), "{text}");
    assert!(app.browser.last_seen.is_none());
    let _ = now(&ask(&mut app, &ctx, Command::Status));
    assert!(app.browser.last_seen.is_some(), "a request counts as seen");
}
