//! Headless tests of Settings › Connect › Shared Vaults (connect-account-v1 section 16):
//! each state of the section and each sheet shows its text, the model follows the share
//! status, and the texts name nothing of one platform. Synthetic values only.

use std::collections::BTreeMap;

use eframe::egui;
use zeroize::Zeroizing;

use super::*;
use crate::connect::share::{EndedMember, MemberStatus, StoreStatus};
use crate::connect::{LeftStore, ShareOffer, ShareStatus, VaultStoreView};
use crate::desktop::ui::owner_tests::{collect, input};

/// The painted text of three frames of `draw` (a new sheet is invisible in its first).
fn painted(mut add: impl FnMut(&egui::Context, &mut Ui)) -> String {
    let ctx = egui::Context::default();
    let mut text = String::new();
    for _ in 0..3 {
        let output = ctx.run_ui(input(0.0, Vec::new()), |ui| {
            let ctx = ui.ctx().clone();
            add(&ctx, ui);
        });
        text.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut text);
        }
        output.drop_without_applying_deltas();
    }
    text
}

fn store(team: &str, name: &str) -> VaultStoreView {
    VaultStoreView {
        team_id: team.to_owned(),
        vault_id: "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77".to_owned(),
        name: name.to_owned(),
        created_at: 1_790_000_000,
        shared: true,
        devices: Vec::new(),
        void: Vec::new(),
    }
}

/// A status of an account that shares "Family" with Ola (not joined yet) and Anna (who
/// reset her account), joined "Garden" of Piotr (who reset his account), joined "Car" of
/// Ewa (the share ended), and is offered "Travel" of Ola.
fn status() -> ShareStatus {
    let member = |id: &str, name: &str, joined: bool, suspended: bool| MemberStatus {
        account_id: id.to_owned(),
        name: name.to_owned(),
        joined,
        suspended,
        accepted: true,
    };
    let names: BTreeMap<String, String> = [
        ("acc_olaaaaaaaa", "Ola"),
        ("acc_annaaaaaaa", "Anna"),
        ("acc_piotraaaaa", "Piotr"),
        ("acc_ewaaaaaaaa", "Ewa"),
    ]
    .into_iter()
    .map(|(id, name)| (id.to_owned(), name.to_owned()))
    .collect();
    ShareStatus {
        offers: vec![ShareOffer {
            team_id: "t_travelaaaa".to_owned(),
            owner: "acc_olaaaaaaaa".to_owned(),
            owner_name: "Ola".to_owned(),
            vault_name: Some("Travel".to_owned()),
        }],
        stores: vec![
            StoreStatus {
                team_id: "t_familyaaaa".to_owned(),
                owner: None,
                owner_name: None,
                members: vec![
                    member("acc_olaaaaaaaa", "Ola", false, false),
                    member("acc_annaaaaaaa", "Anna", true, true),
                ],
                ended_members: vec![
                    EndedMember {
                        account_id: "acc_piotraaaaa".to_owned(),
                        name: "Piotr".to_owned(),
                        left: true,
                    },
                    EndedMember {
                        account_id: "acc_ewaaaaaaaa".to_owned(),
                        name: "Ewa".to_owned(),
                        left: false,
                    },
                ],
                accounts: vec!["acc_olaaaaaaaa".to_owned(), "acc_annaaaaaaa".to_owned()],
                ended: false,
                void: false,
                owner_suspended: false,
            },
            StoreStatus {
                team_id: "t_gardenaaaa".to_owned(),
                owner: Some("acc_piotraaaaa".to_owned()),
                owner_name: Some("Piotr".to_owned()),
                members: Vec::new(),
                ended_members: Vec::new(),
                accounts: vec!["acc_piotraaaaa".to_owned()],
                ended: false,
                void: false,
                owner_suspended: true,
            },
            StoreStatus {
                team_id: "t_caraaaaaaa".to_owned(),
                owner: Some("acc_ewaaaaaaaa".to_owned()),
                owner_name: Some("Ewa".to_owned()),
                members: Vec::new(),
                ended_members: Vec::new(),
                accounts: vec!["acc_ewaaaaaaaa".to_owned()],
                ended: true,
                void: false,
                owner_suspended: false,
            },
        ],
        suspended: vec!["acc_annaaaaaaa".to_owned(), "acc_piotraaaaa".to_owned()],
        names,
        ..ShareStatus::default()
    }
}

/// The vaults of this computer that sync a store: Garden and Car (joined), Family (own).
fn local() -> BTreeMap<String, String> {
    [
        ("t_familyaaaa", "Family"),
        ("t_gardenaaaa", "Garden"),
        ("t_caraaaaaaa", "Car"),
    ]
    .into_iter()
    .map(|(team, name)| (team.to_owned(), name.to_owned()))
    .collect()
}

fn stores() -> Vec<VaultStoreView> {
    vec![
        store("t_familyaaaa", "Family"),
        store("t_gardenaaaa", "Garden"),
        store("t_caraaaaaaa", "Car"),
        store("t_travelaaaa", "Travel"),
    ]
}

#[test]
fn the_section_shows_each_state_of_a_shared_vault() {
    let view = view_of(&status(), &stores(), &local(), true, &[]);
    let text = painted(|_, ui| {
        draw(ui, &view);
    });
    for expected in [
        SECTION,
        "Family",
        SHARE_WITH,
        &not_joined("Ola"),
        &reset_owner("Anna"),
        &stop("Ola"),
        &stop("Anna"),
        &shared_by("Garden", "Piotr"),
        &reset_member("Piotr"),
        &shared_by("Car", "Ewa"),
        &stopped("Ewa"),
        &shared_by(VAULT_OFFERED, "Ola"),
        &connect_calls("Travel"),
        &left_vault("Piotr"),
        &sharing_ended("Ewa"),
        &share_again("Piotr"),
        &share_again("Ewa"),
        JOIN,
        LEAVE,
        ACCEPT,
    ] {
        assert!(text.contains(expected), "{expected} in:\n{text}");
    }
    // A head of a key not verified yet: the joined store says so.
    let checking = view_of(
        &status(),
        &stores(),
        &local(),
        true,
        &["t_caraaaaaaa".to_owned()],
    );
    let joined = checking
        .others
        .iter()
        .find(|store| store.team_id == "t_caraaaaaaa")
        .unwrap();
    assert_eq!(
        joined.joined.as_deref(),
        Some(stopped("Ewa").as_str()),
        "the end comes first"
    );
    let mut alive = status();
    alive.stores[2].ended = false;
    let checking = view_of(
        &alive,
        &stores(),
        &local(),
        true,
        &["t_caraaaaaaa".to_owned()],
    );
    let joined = checking
        .others
        .iter()
        .find(|store| store.team_id == "t_caraaaaaaa")
        .unwrap();
    assert_eq!(joined.joined.as_deref(), Some(CHECKING));
    // Outside a family or team, there is nothing to share with or accept.
    let alone = view_of(&status(), &stores(), &local(), false, &[]);
    let text = painted(|_, ui| {
        draw(ui, &alone);
    });
    assert!(
        !text.contains(SHARE_WITH) && !text.contains(ACCEPT) && !text.contains(&share_again("Ewa")),
        "{text}"
    );
}

/// The lines of the section come from the lists: a store that this account left says on
/// which device (also after a restart), a void share says that it ended, and a joined
/// store that no vault here syncs offers the download.
#[test]
fn the_rows_of_left_void_and_absent_stores_come_from_the_status() {
    let mut status = status();
    status.left = vec![
        LeftStore {
            team_id: "t_oldaaaaaaa".to_owned(),
            owner: "acc_olaaaaaaaa".to_owned(),
            device: "Laptop".to_owned(),
            here: false,
        },
        LeftStore {
            team_id: "t_heraaaaaaa".to_owned(),
            owner: "acc_olaaaaaaaa".to_owned(),
            device: "This one".to_owned(),
            here: true,
        },
    ];
    status.stores[1].owner_suspended = false;
    status.stores[1].void = true;
    let mut away = local();
    away.remove("t_gardenaaaa");
    let view = view_of(&status, &stores(), &away, true, &[]);
    let text = painted(|_, ui| {
        draw(ui, &view);
    });
    for expected in [
        &left_on("Laptop"),
        LEFT_HERE,
        ENDED,
        &connect_calls("Garden"),
    ] {
        assert!(text.contains(expected), "{expected} in:\n{text}");
    }
    let left = view
        .others
        .iter()
        .find(|store| store.team_id == "t_oldaaaaaaa")
        .unwrap();
    assert!(left.left && left.joined.is_none());
    // A joined store that no vault here syncs, and that did not end: the download.
    status.stores[1].void = false;
    let view = view_of(&status, &stores(), &away, true, &[]);
    let garden = view
        .others
        .iter()
        .find(|store| store.team_id == "t_gardenaaaa")
        .unwrap();
    assert!(garden.download);
    let text = painted(|_, ui| {
        draw(ui, &view);
    });
    assert!(text.contains(DOWNLOAD), "{text}");
}

#[test]
fn the_model_puts_each_store_where_it_belongs() {
    let view = view_of(&status(), &stores(), &local(), true, &[]);
    assert_eq!(
        view.own
            .iter()
            .map(|store| store.vault.as_str())
            .collect::<Vec<_>>(),
        ["Family"]
    );
    assert_eq!(view.own[0].members.len(), 2);
    let offered: Vec<_> = view
        .others
        .iter()
        .filter(|store| store.joined.is_none())
        .map(|store| store.team_id.as_str())
        .collect();
    assert_eq!(offered, ["t_travelaaaa"]);
    let joined: Vec<_> = view
        .others
        .iter()
        .filter(|store| store.joined.is_some())
        .map(|store| store.team_id.as_str())
        .collect();
    assert_eq!(joined, ["t_gardenaaaa", "t_caraaaaaaa"]);
}

#[test]
fn each_sheet_shows_its_text() {
    let qr = |ui: &mut Ui, _: &str| {
        ui.label("[QR]");
    };
    let cases: Vec<(ShareSheet, Vec<String>)> = vec![
        (
            ShareSheet::Pick {
                team_id: "t_familyaaaa".into(),
                vault: "Family".into(),
                members: vec![("acc_olaaaaaaaa".into(), "Ola".into())],
                chosen: None,
            },
            vec![
                format!("{PICK_TITLE}: Family"),
                PICK_LEAD.into(),
                "Ola".into(),
            ],
        ),
        (
            ShareSheet::Pick {
                team_id: "t_familyaaaa".into(),
                vault: "Family".into(),
                members: Vec::new(),
                chosen: None,
            },
            vec![NO_MEMBERS.into()],
        ),
        (
            ShareSheet::Code {
                name: "Ola".into(),
                code: Zeroizing::new(format!(
                    "apassy_shr_acc_k7m2q4x3ca_{}_{}",
                    "cd".repeat(32),
                    "ab".repeat(16)
                )),
                expires_at: 600,
            },
            vec![
                CODE_TITLE.into(),
                send_to("Ola"),
                CODE_WAITING.into(),
                "[QR]".into(),
                "Copy".into(),
            ],
        ),
        (
            ShareSheet::Confirm {
                join_id: 4,
                name: "Ola".into(),
                device: "MacBook Air".into(),
                words: "audio coyote forest mint magnet apple".into(),
            },
            vec![
                asks("Ola", "MacBook Air"),
                CONFIRM_TAIL.into(),
                "coyote".into(),
                "Confirm…".into(),
                "Refuse".into(),
            ],
        ),
        (
            ShareSheet::Paste {
                code: Zeroizing::new(String::new()),
            },
            vec![ACCEPT_TITLE.into(), ACCEPT_LEAD.into()],
        ),
        (
            ShareSheet::Match {
                name: "Rafal".into(),
                device: "MacBook Pro".into(),
                words: "audio coyote forest mint magnet apple".into(),
            },
            vec![
                shares_with_you("Rafal", "MacBook Pro"),
                MATCH_TAIL.into(),
                format!("{WORDS_MATCH}…"),
                WORDS_DIFFER.into(),
            ],
        ),
        (
            ShareSheet::End {
                team_id: "t_familyaaaa".into(),
                account: "acc_olaaaaaaaa".into(),
                name: "Ola".into(),
                leave: false,
            },
            vec![
                "Stop Sharing with Ola?".into(),
                STOP_LEAD.into(),
                "Stop Sharing".into(),
            ],
        ),
        (
            ShareSheet::End {
                team_id: "t_gardenaaaa".into(),
                account: "acc_piotraaaaa".into(),
                name: "Piotr".into(),
                leave: true,
            },
            vec![
                "Leave This Shared Vault?".into(),
                LEAVE_LEAD.into(),
                "Leave".into(),
            ],
        ),
        (
            ShareSheet::Done {
                title: shared_with("Ola"),
                line: not_joined("Ola"),
            },
            vec![shared_with("Ola"), not_joined("Ola"), "Done".into()],
        ),
    ];
    for (mut shown, expected) in cases {
        let text = painted(|ctx, _| {
            sheet(ctx, &mut shown, false, Some(MISMATCH), 0, &qr);
        });
        for line in expected.iter().chain([&MISMATCH.to_owned()]) {
            assert!(text.contains(line.as_str()), "{line} in {shown:?}:\n{text}");
        }
    }
}

/// The texts are plain and the same on the Mac and Linux: they name no platform, no
/// purchase, and no Connect internals.
#[test]
fn the_texts_name_nothing_of_one_platform() {
    let made = [
        send_to("Ola"),
        asks("Ola", "Laptop"),
        shares_with_you("Ola", "Laptop"),
        not_joined("Ola"),
        reset_owner("Ola"),
        reset_member("Ola"),
        stop("Ola"),
        shared_by("Family", "Ola"),
        shared_with("Ola"),
        stopped("Ola"),
        left_vault("Ola"),
        sharing_ended("Ola"),
        share_again("Ola"),
        connect_calls("Family"),
        not_listed("Ola"),
        left_on("Laptop"),
    ];
    for text in TEXTS.iter().copied().chain(made.iter().map(String::as_str)) {
        for word in [
            "Touch ID",
            "Keychain",
            "macOS",
            "upgrade",
            "subscribe",
            "€",
            "root",
            "peer",
            "token",
        ] {
            assert!(!text.contains(word), "{word}: {text}");
        }
        assert!(
            !text
                .split(|c: char| !c.is_alphanumeric())
                .any(|word| word == "Mac"),
            "{text}"
        );
    }
    assert_eq!(
        MISMATCH,
        "The code does not match the account that answered."
    );
    assert_eq!(CHECKING, "Checking who shares this vault…");
    assert_eq!(
        WAITING_SHARED,
        "Waiting for a device that shares this vault"
    );
    assert_eq!(reset_owner("Ola"), "Ola reset the account. Share again.");
    assert_eq!(reset_member("Ola"), "Ola must verify this account again.");
    assert_eq!(not_joined("Ola"), "Ola: has not joined yet");
    assert_eq!(send_to("Ola"), "Send this to Ola.");
}

/// C7: the quiet time of a head whose signer is not verified yet runs once for that head:
/// a lock (which resets the section) does not start it again, and after 10 minutes the
/// line goes (the error shows). A new head of the store starts its own.
#[test]
fn the_check_of_a_head_keeps_its_start_across_a_lock() {
    let t0 = Instant::now();
    let head = "a".repeat(64);
    let mut share = ShareUi::default();
    assert!(share.checks.due("t_familyaaaa", &head, t0));
    share.reset();
    assert!(
        !share
            .checks
            .due("t_familyaaaa", &head, t0 + Duration::from_secs(5))
    );
    assert!(
        share
            .checks
            .quiet("t_familyaaaa", &head, t0 + Duration::from_secs(599))
    );
    assert!(!share.checks.quiet("t_familyaaaa", &head, t0 + CHECK_QUIET));
    let next = "b".repeat(64);
    assert!(share.checks.due("t_familyaaaa", &next, t0 + CHECK_QUIET));
    assert!(share.checks.quiet("t_familyaaaa", &next, t0 + CHECK_QUIET));
    share.checks.passed("t_familyaaaa");
    assert!(!share.checks.quiet("t_familyaaaa", &next, t0 + CHECK_QUIET));
}

/// C7: the lists are read again at once, after 30 s, then after twice the last wait, up
/// to 10 minutes.
#[test]
fn the_reads_of_a_head_not_verified_yet_back_off() {
    let t0 = Instant::now();
    let head = "a".repeat(64);
    let mut checks = HeadChecks::default();
    let mut reads = Vec::new();
    for second in 0..3000 {
        if checks.due("t_familyaaaa", &head, t0 + Duration::from_secs(second)) {
            reads.push(second);
        }
    }
    assert_eq!(reads[..7], [0, 30, 90, 210, 450, 930, 1530]);
    assert!(reads.windows(2).all(|pair| pair[1] - pair[0] <= 600));
}

/// F11: a shared store is decided only by lists asked after its refusal: the time of a
/// refresh counts for a store only when the lists of every account of it, and the own list,
/// were asked and verified; a read that failed or did not verify gives no time.
#[test]
fn a_store_is_decided_only_by_lists_that_verified() {
    let start = Instant::now();
    let later = start + Duration::from_secs(5);
    let mut status = status();
    assert_eq!(status.asked_for("t_familyaaaa"), None, "no read at all");
    status.own_read = Some(later);
    status.read.insert("acc_olaaaaaaaa".to_owned(), start);
    assert_eq!(
        status.asked_for("t_familyaaaa"),
        None,
        "Anna's list was not read"
    );
    status.read.insert("acc_annaaaaaaa".to_owned(), later);
    assert_eq!(
        status.asked_for("t_familyaaaa"),
        Some(start),
        "the oldest read"
    );
    status.own_read = None;
    assert_eq!(
        status.asked_for("t_familyaaaa"),
        None,
        "the own list was not read"
    );
    assert_eq!(status.asked_for("t_unknownaaa"), None);
}

/// Item A1 of the 0.5.20 review: every row of Shared Vaults stays inside its column, from
/// the width of Settings in the smallest window (`MIN_WINDOW`, about 340 points for the
/// section) to the 1100-point window. Long names and long button labels wrap or are cut
/// with "…" inside the row, each button stays whole, and the footer keeps "Accept a
/// Shared Vault…".
#[test]
fn every_row_fits_its_column_at_each_width() {
    let long = "\u{201c}Aleksandra's MacBook Air in the study upstairs\u{201d} (Aleksandra Nowak-Kowalska)";
    let view = ShareView {
        own: vec![OwnStore {
            team_id: "t_familyaaaa".to_owned(),
            vault: "Family photos, documents and the passwords of the household".to_owned(),
            members: vec![(
                long.to_owned(),
                "acc_olaaaaaaaa".to_owned(),
                not_accepted(long),
            )],
            ended: vec![(
                long.to_owned(),
                "acc_ewaaaaaaaa".to_owned(),
                sharing_ended(long),
            )],
        }],
        others: vec![OtherStore {
            team_id: "t_gardenaaaa".to_owned(),
            owner: "acc_piotraaaaa".to_owned(),
            title: shared_by("Garden and the summer house", long),
            joined: Some("Syncs.".to_owned()),
            note: None,
            download: true,
            left: false,
        }],
        in_group: true,
        busy: false,
        error: None,
        notes: Vec::new(),
    };
    for width in [300.0_f32, 340.0, 560.0] {
        let ctx = egui::Context::default();
        let left = 20.0;
        for frame in 0..3 {
            let output = ctx.run_ui(input(0.0, Vec::new()), |ui| {
                let rect =
                    egui::Rect::from_min_size(egui::pos2(left, 0.0), egui::vec2(width, 3000.0));
                ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
                    let _ = draw(ui, &view);
                });
            });
            if frame == 2 {
                let mut text = String::new();
                for clipped in &output.shapes {
                    collect(&clipped.shape, &mut text);
                    let right = clipped.shape.visual_bounding_rect().right();
                    assert!(
                        right <= left + width + 3.0,
                        "at {width}: a shape ends at {right}, past {}: {:?}",
                        left + width,
                        clipped.shape
                    );
                }
                for whole in [ACCEPT, SHARE_WITH, LEAVE, DOWNLOAD, SECTION] {
                    assert!(text.contains(whole), "at {width}: no {whole:?} in\n{text}");
                }
                // The person's button keeps its start, cut with "…" at most.
                assert!(text.contains("Stop Sharing with"), "at {width}:\n{text}");
                assert!(
                    text.contains("Each of you compares six words once."),
                    "at {width}:\n{text}"
                );
            }
            output.drop_without_applying_deltas();
        }
    }
}

/// The words sheets name the person once: the label of its verified list, without the
/// device name again and without a possessive after a parenthesis.
#[test]
fn the_words_name_the_person_once() {
    let name = "\u{201c}Ola's MacBook Air\u{201d} (Ola)";
    assert_eq!(
        asks(name, "Ola's MacBook Air"),
        "\u{201c}Ola's MacBook Air\u{201d} (Ola) asks to share vaults with you."
    );
    assert_eq!(
        shares_with_you(name, "Ola's iMac"),
        "\u{201c}Ola's MacBook Air\u{201d} (Ola) on \u{201c}Ola's iMac\u{201d} shares vaults with you."
    );
    for tail in [CONFIRM_TAIL, MATCH_TAIL] {
        assert!(!tail.contains(")'s"), "{tail}");
    }
}
