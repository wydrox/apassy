//! The demo build of Settings > Connect: every frame of `docs/design/connect-mockup.html`
//! from synthetic fixtures, drawn by the same functions as the vault build. The menu at
//! the top of the section picks a frame; `APASSY_DEMO_CONNECT` (1, 2a, 2b, 3, S, 4a, 4b,
//! 4c, 5a, 5b, 5c, 6a to 6h, 7a to 7d, 8a, 8b, 8c, 9, 9a to 9e, 10a, 10b, 10c, 11a, 11b)
//! opens it at start once Settings shows (`APASSY_DEMO_DEVICES=1` opens Settings). The
//! prices are those of `tests/fixtures/connect-billing-v1/plans.json`, read as Connect
//! would send them; no amount is written here.

use eframe::egui;
use zeroize::Zeroizing;

use super::{
    Account, Action, ConnectView, Device, Group, Member, Offer, Plan, Plans, Price, Sheet, Shown,
};
use crate::desktop::DesktopApp;

/// "Now" of the fixtures: Tue 10 Nov 2026, 14:20 UTC, as the mockup.
const NOW: u64 = 1_794_320_400;
const DAY: u64 = 86_400;
/// 21 Sep 2026: the account and this Mac.
const CREATED: u64 = 1_790_000_000;

/// The frames of the mockup: the code of `APASSY_DEMO_CONNECT` and the label of the menu.
const FRAMES: &[(&str, &str)] = &[
    ("1", "Frame 1: Not on Connect"),
    ("2a", "Frame 2a: Create the Account"),
    ("2b", "Frame 2b: Recovery Code"),
    ("3", "Frame 3: Account, No Plan"),
    ("S", "Frame S: Signed Out"),
    ("4a", "Frame 4a: Picker, Personal"),
    ("4b", "Frame 4b: Picker, Family Yearly"),
    ("4c", "Frame 4c: Picker, Team"),
    ("5a", "Frame 5a: Waiting"),
    ("5b", "Frame 5b: Confirmed"),
    ("5c", "Frame 5c: Stopped Waiting"),
    ("6a", "Frame 6a: Active"),
    ("6b", "Frame 6b: Ends"),
    ("6c", "Frame 6c: Past Due"),
    ("6d", "Frame 6d: Read-Only"),
    ("6e", "Frame 6e: Suspended"),
    ("6f", "Frame 6f: Waiting for Payment"),
    ("6g", "Frame 6g: Family, Organizer"),
    ("6h", "Frame 6h: Family, Member"),
    ("7a", "Frame 7a: Add a Device"),
    ("7b", "Frame 7b: Safety Words"),
    ("7c", "Frame 7c: Revoke"),
    ("7d", "Frame 7d: Forget This Mac"),
    ("8a", "Frame 8a: Join, the Code"),
    ("8b", "Frame 8b: Join, Waiting"),
    ("8c", "Frame 8c: Join, Added"),
    ("9", "Frame 9: Family Members"),
    ("9a", "Frame 9a: Invite"),
    ("9b", "Frame 9b: Invite to a Team"),
    ("9c", "Frame 9c: Remove a Member"),
    ("9d", "Frame 9d: Change the People"),
    ("9e", "Frame 9e: A Member's View"),
    ("10a", "Frame 10a: Join a Group"),
    ("10b", "Frame 10b: Request Sent"),
    ("10c", "Frame 10c: Join Refused"),
    ("11a", "Frame 11a: Delete"),
    ("11b", "Frame 11b: Members First"),
];

/// The frame that the section shows: an index into [`FRAMES`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Frame(usize);

impl Frame {
    fn code(self) -> &'static str {
        FRAMES[self.0].0
    }

    fn from_code(code: &str) -> Option<Self> {
        FRAMES
            .iter()
            .position(|(known, _)| *known == code)
            .map(Self)
    }
}

/// The plans of the fixture, as `GET /v1/plans` sends them.
pub(crate) fn fixture_plans() -> Plans {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/connect-billing-v1/plans.json"
    ))
    .unwrap_or_default();
    let text =
        |value: &serde_json::Value, key: &str| value[key].as_str().unwrap_or_default().to_owned();
    Plans {
        currency: text(&value, "currency"),
        offers: value["plans"]
            .as_array()
            .map(|offers| {
                offers
                    .iter()
                    .map(|offer| Offer {
                        plan: text(offer, "plan"),
                        name: text(offer, "name"),
                        included: offer["included"].as_u64().unwrap_or(1),
                        max: offer["max"].as_u64().unwrap_or(1),
                        prices: offer["prices"]
                            .as_array()
                            .map(|prices| {
                                prices
                                    .iter()
                                    .map(|price| Price {
                                        interval: text(price, "interval"),
                                        amount: price["amount"].as_u64().unwrap_or(0),
                                        extra: price["extra"].as_u64(),
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn devices() -> Vec<Device> {
    let device =
        |id: &str, name: &str, platform: &str, added: u64, seen: Option<u64>, this: bool| Device {
            id: id.to_owned(),
            name: name.to_owned(),
            platform: platform.to_owned(),
            created_at: added,
            last_seen_at: seen,
            this,
        };
    vec![
        device(
            "dev_mmmmmmmmma",
            "Mac mini (office)",
            "mac",
            CREATED,
            None,
            true,
        ),
        device(
            "dev_mmmmmmmmmb",
            "MacBook Pro",
            "mac",
            CREATED + DAY,
            Some(NOW - 7_200),
            false,
        ),
        device(
            "dev_mmmmmmmmmc",
            "Rafal's iPhone",
            "iphone",
            CREATED + DAY,
            Some(NOW - DAY - 600),
            false,
        ),
    ]
}

fn plan(status: &str, key: Option<&str>) -> Plan {
    Plan {
        plan: key.map(str::to_owned),
        status: status.to_owned(),
        entitled: matches!(status, "active" | "trialing" | "past_due"),
        interval: key.map(|_| "month".to_owned()),
        quantity: key.map(|_| 1),
        ..Plan::default()
    }
}

fn family(role: &str, state: &str) -> Group {
    let member = |id: &str, name: &str, role: &str, state: &str, at: u64| Member {
        account_id: id.to_owned(),
        name: name.to_owned(),
        role: role.to_owned(),
        state: state.to_owned(),
        joined_at: Some(at),
    };
    Group {
        id: "grp_f4m6n2p7qa".to_owned(),
        kind: "family".to_owned(),
        role: role.to_owned(),
        state: state.to_owned(),
        owner_name: "Rafal".to_owned(),
        quantity: 4,
        members: if role == "owner" {
            vec![
                member("acc_k7m2q4x3ca", "Rafal", "owner", "active", CREATED),
                member("acc_m3n5p7q2rb", "Ola", "member", "active", CREATED + DAY),
                member("acc_r5s7t2u4vc", "Jan", "member", "pending", NOW - 3_600),
            ]
        } else {
            Vec::new()
        },
    }
}

fn account(plan: Plan, group: Option<Group>) -> Account {
    Account {
        account_id: "acc_k7m2q4x3ca".to_owned(),
        name: if group.as_ref().is_some_and(|group| group.role != "owner") {
            "Ola".to_owned()
        } else {
            "Rafal".to_owned()
        },
        email: plan.entitled.then(|| "rafal@example.com".to_owned()),
        plan,
        devices: devices(),
        group,
    }
}

/// The view and the sheet of a frame. Synthetic data only.
#[allow(clippy::too_many_lines)]
fn frame(code: &str) -> (Shown, Option<Sheet>) {
    let renews = NOW + 30 * DAY;
    let year = NOW + 365 * DAY;
    let active = |key: &str, renews_at: u64| Plan {
        renews_at: Some(renews_at),
        ..plan("active", Some(key))
    };
    let none = || Shown::Account(account(plan("none", None), None));
    let family_owner = || {
        Shown::Account(account(
            Plan {
                interval: Some("year".to_owned()),
                quantity: Some(4),
                ..active("family", year)
            },
            Some(family("owner", "active")),
        ))
    };
    let personal = || Shown::Account(account(active("personal", renews), None));
    let words = "blaze cable flute board seal tiger";
    match code {
        "1" => (Shown::None, None),
        "2a" => (
            Shown::None,
            Some(Sheet::Create {
                name: "Rafal".to_owned(),
                device_name: "Mac mini (office)".to_owned(),
            }),
        ),
        "2b" => (
            Shown::None,
            Some(Sheet::Recovery {
                words: Zeroizing::new(
                    "blaze cable flute board seal tiger maple orbit cedar lemon quartz otter harbor mango piano river"
                        .to_owned(),
                ),
            }),
        ),
        "S" => (
            Shown::SignedOut {
                name: Some("Rafal".to_owned()),
                device_name: "Mac mini (office)".to_owned(),
            },
            None,
        ),
        "4a" | "4b" | "4c" => {
            let (key, interval, count) = match code {
                "4a" => ("personal", "month", 1),
                "4b" => ("family", "year", 6),
                _ => ("team", "month", 5),
            };
            (
                none(),
                Some(Sheet::Picker {
                    plan: key.to_owned(),
                    interval: interval.to_owned(),
                    count,
                }),
            )
        }
        "5a" | "5c" => (
            none(),
            Some(Sheet::Waiting {
                url: "https://checkout.stripe.com/c/pay/cs_test_SynthSession0001".to_owned(),
                stopped: code == "5c",
            }),
        ),
        "5b" => (
            family_owner(),
            Some(Sheet::Active {
                title: "Connect Family Is Active".to_owned(),
                line: "Renews 10 Nov 2027.".to_owned(),
            }),
        ),
        "6a" => (personal(), None),
        "6b" => (
            Shown::Account(account(
                Plan {
                    renews_at: None,
                    ends_at: Some(renews),
                    ..active("personal", renews)
                },
                None,
            )),
            None,
        ),
        "6c" => (
            Shown::Account(account(
                Plan {
                    grace_until: Some(NOW + 7 * DAY),
                    ..plan("past_due", Some("personal"))
                },
                None,
            )),
            None,
        ),
        "6d" => (
            Shown::Account(account(
                Plan {
                    read_only_until: Some(NOW + 55 * DAY),
                    delete_at: Some(NOW + 113 * DAY),
                    ..plan("read_only", Some("personal"))
                },
                None,
            )),
            None,
        ),
        "6e" => (
            Shown::Account(account(
                Plan {
                    delete_at: Some(NOW + 113 * DAY),
                    ..plan("suspended", Some("personal"))
                },
                None,
            )),
            None,
        ),
        "6f" => (
            Shown::Account(account(plan("pending", Some("personal")), None)),
            None,
        ),
        "6g" | "9" => (family_owner(), None),
        "6h" | "9e" => (
            Shown::Account(account(
                Plan {
                    quantity: Some(4),
                    ..active("family", year)
                },
                Some(family("member", "active")),
            )),
            None,
        ),
        "7a" => (
            personal(),
            Some(Sheet::AddDevice {
                code: Zeroizing::new(
                    "apassy_alk_acc_k7m2q4x3ca_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                ),
                expires_at: NOW + 581,
            }),
        ),
        "7b" => (
            personal(),
            Some(Sheet::Words {
                join_id: 4,
                device_name: "Rafal's iPhone".to_owned(),
                platform: "iphone".to_owned(),
                words: words.to_owned(),
            }),
        ),
        "7c" => (
            personal(),
            Some(Sheet::Revoke {
                index: 1,
                name: "MacBook Pro".to_owned(),
                this: false,
            }),
        ),
        "7d" => (
            personal(),
            Some(Sheet::Revoke {
                index: 0,
                name: "Mac mini (office)".to_owned(),
                this: true,
            }),
        ),
        "8a" => (
            Shown::None,
            Some(Sheet::JoinAccount {
                code: Zeroizing::new(String::new()),
            }),
        ),
        "8b" => (
            Shown::None,
            Some(Sheet::JoinWaiting {
                confirmer: "MacBook Pro".to_owned(),
                words: words.to_owned(),
            }),
        ),
        "8c" => (personal(), Some(Sheet::Joined)),
        "9a" => (
            family_owner(),
            Some(Sheet::Invite {
                kind: "family".to_owned(),
                choose_role: false,
                role: "member".to_owned(),
                link: Some((
                    "https://apassy.wyderka.cc/connect/join#apassy_gin_grp_f4m6n2p7qa_abababababababababababababababababababababababababababababababab".to_owned(),
                    NOW + 7 * DAY,
                )),
            }),
        ),
        "9b" => (
            family_owner(),
            Some(Sheet::Invite {
                kind: "team".to_owned(),
                choose_role: true,
                role: "member".to_owned(),
                link: None,
            }),
        ),
        "9c" => (
            family_owner(),
            Some(Sheet::RemoveMember {
                account_id: "acc_m3n5p7q2rb".to_owned(),
                name: "Ola".to_owned(),
                kind: "family".to_owned(),
                leave: false,
            }),
        ),
        "9d" => (
            family_owner(),
            Some(Sheet::Seats {
                kind: "family".to_owned(),
                quantity: 6,
            }),
        ),
        "10a" | "10c" => (
            none(),
            Some(Sheet::JoinGroup {
                link: if code == "10c" {
                    "https://apassy.wyderka.cc/connect/join#apassy_gin_grp_f4m6n2p7qa_abab…".to_owned()
                } else {
                    String::new()
                },
                refused: code == "10c",
            }),
        ),
        "10b" => (
            none(),
            Some(Sheet::JoinSent {
                owner_name: "Rafal".to_owned(),
            }),
        ),
        "11a" => (personal(), Some(Sheet::Delete)),
        "11b" => (family_owner(), Some(Sheet::MembersFirst)),
        // "3", and any other code.
        _ => (none(), None),
    }
}

fn view(app: &DesktopApp) -> ConnectView {
    ConnectView {
        shown: frame(app.ui.connect.demo.code()).0,
        plans: Some(fixture_plans()),
        locked: false,
        busy: false,
        error: None,
        now: NOW,
    }
}

/// The status line of the section in the list.
pub(crate) fn status_line(app: &DesktopApp) -> String {
    view(app).status_line()
}

/// Show `frame` and its sheet.
fn select(app: &mut DesktopApp, frame: Frame) {
    app.ui.connect.demo = frame;
    app.ui.connect.sheet = self::frame(frame.code()).1;
}

/// Open Settings > Connect at the frame of `APASSY_DEMO_CONNECT`, once.
pub(crate) fn from_env_once(app: &mut DesktopApp) {
    use std::sync::Once;
    static FROM_ENV: Once = Once::new();
    FROM_ENV.call_once(|| {
        if let Some(frame) = std::env::var("APASSY_DEMO_CONNECT")
            .ok()
            .and_then(|code| Frame::from_code(code.trim()))
        {
            app.ui.settings_section = crate::desktop::ui::settings_view::SettingsSection::Connect;
            select(app, frame);
        }
    });
}

/// The section: the frame menu, the view, and the sheet of the frame.
pub(crate) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    ui.add_space(8.0);
    let mut chosen = app.ui.connect.demo;
    let options: Vec<(Frame, String)> = (0..FRAMES.len())
        .map(|index| (Frame(index), FRAMES[index].1.to_owned()))
        .collect();
    let shown = FRAMES[chosen.0].1;
    super::super::kit::picker(
        ui,
        "demo-connect-frame",
        &mut chosen,
        &options,
        shown,
        260.0,
    );
    if chosen != app.ui.connect.demo {
        select(app, chosen);
    }
    let view = view(app);
    let next = match super::draw(ui, &view) {
        Some(Action::Create) => Some("2a"),
        Some(Action::AddThisMac) => Some("8a"),
        Some(Action::SignIn) => Some("6a"),
        Some(Action::ChoosePlan) => Some("4a"),
        Some(Action::AddDevice) => Some("7a"),
        Some(Action::Revoke(index)) => Some(if index == 0 { "7d" } else { "7c" }),
        Some(Action::Invite) => Some("9a"),
        Some(Action::RemoveMember(_)) => Some("9c"),
        Some(Action::ChangeSeats) => Some("9d"),
        Some(Action::JoinGroup) => Some("10a"),
        Some(Action::Delete) => Some("11a"),
        _ => None,
    };
    if let Some(frame) = next.and_then(Frame::from_code) {
        select(app, frame);
    }
    let plans = view.plans.clone();
    let choice = app.ui.connect.sheet.as_mut().and_then(|sheet| {
        super::sheet(&ctx, sheet, plans.as_ref(), false, None, NOW, &|ui, _| {
            // The demo build has no QR encoder; the mockup's code is decorative too.
            ui.add_space(4.0);
        })
    });
    if let Some(choice) = choice {
        if let super::SheetChoice::Copy(text) = choice {
            ctx.copy_text(text);
        } else {
            app.ui.connect.sheet = None;
        }
    }
}
