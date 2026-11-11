//! Settings > Connect (plan s7 unit M2; the mockup `docs/design/connect-mockup.html`):
//! the Apassy Connect account of this Mac, its plan, the checkout and the Customer
//! Portal in the default browser, the devices of the account, the family or team, and
//! the deletion of the account. The contracts are connect-account-v1 and
//! connect-billing-v1; the account calls are those of `crate::connect` (unit M1).
//!
//! The drawing is pure, as in Settings > Devices: [`draw`] takes a [`ConnectView`] and
//! returns the [`Action`] that the owner chose, and [`sheet`] draws one [`Sheet`] and
//! returns its [`SheetChoice`]. The vault build makes the view from the account on a
//! worker thread (`live`, every network call runs off the UI thread); the demo build
//! makes it from the fixtures of each mockup frame (`demo`, `APASSY_DEMO_CONNECT`).
//!
//! - Every price comes from `GET /v1/plans` ([`Plans`]); no amount is in this file.
//! - The Checkout and Portal URLs come from Connect and open in the default browser
//!   (`egui::Context::open_url`, which the tests record).
//! - While the waiting sheet is open the app asks `GET /v1/account` every 3 s
//!   ([`POLL_EVERY`]) and stops on an entitled plan, on Cancel, or after 30 minutes. The
//!   app bundle has no `apassy://` URL scheme and eframe has no open-URL event, so
//!   polling is the only way back from the browser (plan s7 "Not verified").
//! - The owner check (Touch ID or the passphrase) runs before confirming a device,
//!   revoking one, deleting the account, and every change of the group; none before the
//!   plan picker, a checkout, the portal, an invite link, or joining a group.
//! - The texts follow plans section 5: the paid part is Apassy Connect, the plan names
//!   are Connect Personal, Connect Family, and Connect Team, and "free" is said only of
//!   what is self-hosted ([`TEXTS`] is the list that the tests check).

// The demo build draws the fixtures only: the parts of the vault build stay unused there.
#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use eframe::egui::{self, Label, Rect, Sense, Stroke, Ui, Vec2};

use super::devices::rows;
use super::kit::{self, Font, Icon, Style, Tone};

/// `GET /v1/account` while the waiting sheet is open (connect-billing-v1 section 4).
pub(crate) const POLL_EVERY: std::time::Duration = std::time::Duration::from_secs(3);
/// The waiting sheet stops asking after this long.
pub(crate) const WAIT_AT_MOST: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// `GET /v1/account/devices/pending`, and the poll of this Mac's own join.
pub(crate) const JOIN_POLL_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

// ---- Texts (plans section 5). ----

pub(crate) const NOT_ON_CONNECT: &str = "Not on Connect";
pub(crate) const INTRO: &str = "Apassy Connect is the hosted service of the Apassy project: it reaches your devices without Tailscale, keeps the encrypted copy of your vaults always online, and hosts the bouncer brain.";
pub(crate) const SELF_HOST: &str = "Everything Connect does also runs on your own hardware, free.";
pub(crate) const CREATE: &str = "Create a Connect Account…";
pub(crate) const ADD_THIS_MAC: &str =
    concat!("Add This ", crate::computer_cap!(), " to an Account…");
pub(crate) const KEY_NOTE: &str = concat!(
    "No password and no email: the key of this ",
    crate::computer!(),
    ", ",
    crate::connect_key_place!(),
    ", signs in."
);
pub(crate) const GROUP_LABEL: &str = "Apassy Connect";
pub(crate) const SIGNED_OUT: &str = "Signed out";
pub(crate) const SIGNED_OUT_NOTE: &str = crate::connect_key_read!();
pub(crate) const SIGN_IN: &str = "Sign In…";
/// The row and the tag of this device.
pub(crate) const THIS_DEVICE: &str = concat!("This ", crate::computer_cap!());
/// Settings › Connect could not reach Connect after the account opened.
pub(crate) const UNREACHABLE: &str = "Connect unreachable";
/// "Try Again" of the unreachable state.
pub(crate) const ASK_AGAIN: &str = "Try Again";
/// This device revoked itself.
pub(crate) const LEFT: &str = concat!(
    "This ",
    crate::computer_cap!(),
    " left the Connect account."
);
/// This device forgot its account after a removal.
pub(crate) const FORGOT: &str = concat!(
    "This ",
    crate::computer_cap!(),
    " forgot the Connect account."
);
pub(crate) const NO_PLAN: &str = "No plan";
pub(crate) const CHOOSE_PLAN: &str = "Choose a Plan…";
pub(crate) const MANAGE_BILLING: &str = "Manage Billing…";
pub(crate) const PENDING_PAYMENT: &str = "Waiting for the payment";
pub(crate) const LOCKED: &str = "Unlock Apassy to change Connect.";
pub(crate) const ADD_DEVICE: &str = "Add a Device…";
pub(crate) const JOIN_GROUP: &str = "Join a Family or Team";
pub(crate) const JOIN_GROUP_NOTE: &str = "Paste the invite link that the organizer sent you.";
pub(crate) const INVITE: &str = "Invite…";
pub(crate) const DELETE: &str = "Delete Account…";
pub(crate) const DELETED: &str = "The Connect account is deleted.";

pub(crate) const CREATE_TITLE: &str = "Create a Connect Account";
pub(crate) const CREATE_LEAD: &str = concat!(
    "No password and no email: the key of this ",
    crate::computer!(),
    ", ",
    crate::connect_key_place!(),
    ", signs in. You choose a plan later."
);
pub(crate) const CREATE_NOTE: &str = "The name shows to the members of a family or team.";
pub(crate) const RECOVERY_TITLE: &str = "Save Your Recovery Code";
pub(crate) const RECOVERY_LEAD: &str = "Shown once. Save it in another password manager.";
pub(crate) const RECOVERY_NOTE: &str = concat!(
    "If every device of the account is lost, this code gives the account to a new ",
    crate::computer!(),
    ". The vault copies at Connect are deleted then; your vaults stay on your devices."
);
pub(crate) const SAVED_IT: &str = "I Saved It";

pub(crate) const PICKER_TITLE: &str = "Choose a Plan";
pub(crate) const PICKER_LEAD: &str = "Apassy Connect, the hosted service of the Apassy project.";
pub(crate) const PICKER_NOTE: &str =
    "VAT included. You pay in your browser, through Stripe; Apassy never sees your card.";
pub(crate) const LOADING_PRICES: &str = "Loading prices…";
/// The picker when `GET /v1/plans` failed: the error shows under the sheet.
pub(crate) const PRICES_FAILED: &str = "The prices did not load.";
pub(crate) const TRY_AGAIN: &str = "Try Again";
pub(crate) const CONTINUE_BROWSER: &str = "Continue in the Browser…";
pub(crate) const WAIT_TITLE: &str = "Finish in Your Browser";
pub(crate) const WAIT_LEAD: &str =
    "Stripe opened in your browser. This sheet closes by itself when Connect confirms the plan.";
pub(crate) const WAIT_LINE: &str = "Waiting for Connect…";
pub(crate) const WAIT_NOTE: &str = "Closing this sheet does not cancel a payment that you finish.";
pub(crate) const OPEN_AGAIN: &str = "Open the Page Again";
pub(crate) const WAIT_STOPPED: &str =
    "Apassy stopped waiting. If you paid, the plan shows here within a few minutes.";
pub(crate) const CHECK_AGAIN: &str = "Check Again";

pub(crate) const ADD_TITLE: &str = "Add a Device";
pub(crate) const ADD_LEAD: &str = concat!(
    "On the new device, choose Add This ",
    crate::computer_cap!(),
    " to an Account (on a ",
    crate::computer!(),
    ") or scan this code (on the iPhone)."
);
pub(crate) const ADD_WAITING: &str = "Waiting for the other device…";
pub(crate) const WORDS_TAIL: &str = "Confirm only if the other device shows the same words.";
pub(crate) const ADDED_LEAD: &str = "It is a device of your Connect account now.";
pub(crate) const REVOKE_LEAD: &str =
    "It leaves your Connect account and every vault copy at Connect. Its vaults stay on it.";
pub(crate) const FORGET_TITLE: &str = concat!("Forget This ", crate::computer_cap!(), "?");
pub(crate) const NOT_VERIFIED: &str = "Not verified";
pub(crate) const REMOVED: &str = "Removed from the account";
pub(crate) const REMOVED_NOTE: &str = concat!(
    "Apassy Connect says this ",
    crate::computer!(),
    " was removed from its account. Its Connect key and its account file stay on this ",
    crate::computer!(),
    " until you forget the account here."
);
pub(crate) const FORGET_THIS_MAC: &str = concat!("Forget This ", crate::computer_cap!(), "…");
pub(crate) const FORGET_REMOVED_LEAD: &str = concat!(
    "The Connect key and the account file of this ",
    crate::computer!(),
    " are deleted, and the vault copies of the account stop syncing on this ",
    crate::computer!(),
    ". To use the account here again, add this ",
    crate::computer!(),
    " from another device of the account."
);
pub(crate) const FORGET_LEAD: &str = concat!(
    "This ",
    crate::computer_cap!(),
    " leaves your Connect account, and its Connect key is deleted. To use the account here again, add this ",
    crate::computer!(),
    " from another device of the account."
);
pub(crate) const JOIN_ACCOUNT_TITLE: &str =
    concat!("Add This ", crate::computer_cap!(), " to an Account");
pub(crate) const JOIN_ACCOUNT_LEAD: &str =
    "On a device of the account, choose Add a Device…, then paste its code here.";
pub(crate) const JOINED_TITLE: &str = concat!("This ", crate::computer_cap!(), " Is Added");
pub(crate) const JOINED_LEAD: &str = "It is a device of the Connect account now.";

pub(crate) const INVITE_LEAD: &str = "Send this link to the person. It works once, for 7 days.";
pub(crate) const INVITE_NOTE: &str =
    "The person pastes it in Settings › Connect › Join a Family or Team. You confirm them here.";
pub(crate) const ADMIN_NOTE: &str =
    "An admin invites, confirms, and removes members. Only you change the seats and the billing.";
pub(crate) const CREATE_LINK: &str = "Create Link";
pub(crate) const SEATS_NOTE: &str =
    "Stripe charges or credits the difference for the rest of the period.";
pub(crate) const JOIN_GROUP_REFUSED: &str = "This account has its own plan, or is in another family or team. Cancel the plan or leave first.";
pub(crate) const DELETE_TITLE: &str = "Delete Your Connect Account?";
pub(crate) const DELETE_LEAD: &str = "The plan ends now, and every vault copy, device, and link of the account is deleted at Connect. Your vaults stay on your devices. Your invoices stay at Stripe.";
pub(crate) const MEMBERS_FIRST_TITLE: &str = "Remove the Members First";
pub(crate) const MEMBERS_FIRST_LEAD: &str =
    "Your family or team still has members. Remove them, then delete the account.";

/// Every fixed text of the section, for the checks of plans section 5.
#[cfg(all(test, feature = "vault"))]
pub(crate) const TEXTS: &[&str] = &[
    NOT_ON_CONNECT,
    INTRO,
    SELF_HOST,
    CREATE,
    ADD_THIS_MAC,
    KEY_NOTE,
    GROUP_LABEL,
    SIGNED_OUT,
    SIGNED_OUT_NOTE,
    SIGN_IN,
    THIS_DEVICE,
    UNREACHABLE,
    ASK_AGAIN,
    LEFT,
    FORGOT,
    NO_PLAN,
    CHOOSE_PLAN,
    MANAGE_BILLING,
    PENDING_PAYMENT,
    LOCKED,
    ADD_DEVICE,
    JOIN_GROUP,
    JOIN_GROUP_NOTE,
    INVITE,
    DELETE,
    DELETED,
    CREATE_TITLE,
    CREATE_LEAD,
    CREATE_NOTE,
    RECOVERY_TITLE,
    RECOVERY_LEAD,
    RECOVERY_NOTE,
    SAVED_IT,
    PICKER_TITLE,
    PICKER_LEAD,
    PICKER_NOTE,
    LOADING_PRICES,
    PRICES_FAILED,
    TRY_AGAIN,
    CONTINUE_BROWSER,
    WAIT_TITLE,
    WAIT_LEAD,
    WAIT_LINE,
    WAIT_NOTE,
    OPEN_AGAIN,
    WAIT_STOPPED,
    CHECK_AGAIN,
    ADD_TITLE,
    ADD_LEAD,
    ADD_WAITING,
    WORDS_TAIL,
    ADDED_LEAD,
    REVOKE_LEAD,
    FORGET_TITLE,
    FORGET_LEAD,
    NOT_VERIFIED,
    REMOVED,
    REMOVED_NOTE,
    FORGET_THIS_MAC,
    FORGET_REMOVED_LEAD,
    JOIN_ACCOUNT_TITLE,
    JOIN_ACCOUNT_LEAD,
    JOINED_TITLE,
    JOINED_LEAD,
    INVITE_LEAD,
    INVITE_NOTE,
    ADMIN_NOTE,
    CREATE_LINK,
    SEATS_NOTE,
    JOIN_GROUP_REFUSED,
    DELETE_TITLE,
    DELETE_LEAD,
    MEMBERS_FIRST_TITLE,
    MEMBERS_FIRST_LEAD,
];

/// The name of a plan when the plans are not loaded: the names of plans section 5.
/// Connect sends the same names in `GET /v1/plans`, which win.
pub(crate) fn fallback_name(plan: &str) -> &'static str {
    match plan {
        "family" => "Connect Family",
        "team" => "Connect Team",
        _ => "Connect Personal",
    }
}

/// What a plan is for, in the picker. No amount: the prices come from Connect.
fn plan_line(offer: &Offer, interval: &str, currency: &str) -> String {
    match offer.plan.as_str() {
        "family" => {
            let extra = offer
                .price(interval)
                .and_then(|price| price.extra)
                .map(|extra| {
                    format!(
                        "; each further person {} {}",
                        money(currency, extra),
                        per(interval)
                    )
                })
                .unwrap_or_default();
            format!("{} people{extra}", offer.included)
        }
        "team" => "Members, roles, and billing per seat".to_owned(),
        _ => "One person and all of their devices".to_owned(),
    }
}

/// "a month" or "a year".
fn per(interval: &str) -> &'static str {
    if interval == "year" {
        "a year"
    } else {
        "a month"
    }
}

/// An amount in cents: the sign and the whole amount, or the amount with two digits of
/// cents; another currency than euro, dollar, or pound shows its code ("CHF 3").
pub(crate) fn money(currency: &str, cents: u64) -> String {
    let sign = match currency.to_ascii_lowercase().as_str() {
        "eur" => "€".to_owned(),
        "usd" => "$".to_owned(),
        "gbp" => "£".to_owned(),
        other => format!("{} ", other.to_ascii_uppercase()),
    };
    if cents.is_multiple_of(100) {
        format!("{sign}{}", cents / 100)
    } else {
        format!("{sign}{}.{:02}", cents / 100, cents % 100)
    }
}

/// The UTC day of `at`: "10 Dec 2026".
pub(crate) fn day(at: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // H. Hinnant's days-to-civil, as `devices::day_month`.
    let days = (at / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{day} {} {year}", MONTHS[(month - 1) as usize])
}

// ---- The view. ----

/// One price of a plan, in cents with VAT included (connect-billing-v1 section 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Price {
    pub(crate) interval: String,
    pub(crate) amount: u64,
    pub(crate) extra: Option<u64>,
}

/// One plan of `GET /v1/plans`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Offer {
    pub(crate) plan: String,
    pub(crate) name: String,
    pub(crate) included: u64,
    pub(crate) max: u64,
    pub(crate) prices: Vec<Price>,
}

impl Offer {
    pub(crate) fn price(&self, interval: &str) -> Option<&Price> {
        self.prices.iter().find(|price| price.interval == interval)
    }

    /// The total in cents for `count` people or seats (Personal: 1) of `interval`:
    /// `amount + max(0, count − included) × extra`, for `1 ≤ count ≤ max`
    /// (connect-billing-v1 section 2). A Family of 2 pays the price of 4.
    pub(crate) fn total(&self, interval: &str, count: u64) -> Option<u64> {
        if count == 0 || count > self.max {
            return None;
        }
        let price = self.price(interval)?;
        match count.saturating_sub(self.included) {
            0 => Some(price.amount),
            further => price
                .extra?
                .checked_mul(further)
                .and_then(|extra| extra.checked_add(price.amount)),
        }
    }

    /// The plan counts people or seats.
    fn counted(&self) -> bool {
        self.max > 1
    }

    /// "People" or "Seats".
    fn unit_label(&self) -> &'static str {
        if self.plan == "family" {
            "People"
        } else {
            "Seats"
        }
    }
}

/// The plans and their prices, from Connect.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Plans {
    pub(crate) currency: String,
    pub(crate) offers: Vec<Offer>,
}

impl Plans {
    pub(crate) fn offer(&self, plan: &str) -> Option<&Offer> {
        self.offers.iter().find(|offer| offer.plan == plan)
    }
}

/// The plan of the account (the `PlanView` of connect-billing-v1 section 8).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Plan {
    pub(crate) plan: Option<String>,
    /// `none`, `pending`, `active`, `trialing`, `past_due`, `read_only`, `suspended`.
    pub(crate) status: String,
    pub(crate) entitled: bool,
    pub(crate) interval: Option<String>,
    pub(crate) quantity: Option<u64>,
    pub(crate) renews_at: Option<u64>,
    pub(crate) ends_at: Option<u64>,
    pub(crate) grace_until: Option<u64>,
    pub(crate) read_only_until: Option<u64>,
    pub(crate) delete_at: Option<u64>,
}

/// A device of the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Device {
    pub(crate) id: String,
    pub(crate) name: String,
    /// `mac`, `iphone`, or `linux`.
    pub(crate) platform: String,
    pub(crate) created_at: u64,
    pub(crate) last_seen_at: Option<u64>,
    /// This Mac.
    pub(crate) this: bool,
    /// The signed device list that this Mac verified holds the device's key. A device
    /// that is not verified shows "Not verified" and is no device of the account for any
    /// step.
    pub(crate) verified: bool,
}

impl Device {
    fn kind(&self) -> &'static str {
        match self.platform.as_str() {
            "iphone" => "iPhone",
            "linux" => "Linux",
            _ => "Mac",
        }
    }
}

/// A member of the family or team.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) account_id: String,
    pub(crate) name: String,
    /// `owner`, `admin`, or `member`.
    pub(crate) role: String,
    /// `pending` or `active`.
    pub(crate) state: String,
    pub(crate) joined_at: Option<u64>,
}

/// The family or team of the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Group {
    pub(crate) id: String,
    /// `family` or `team`.
    pub(crate) kind: String,
    /// The role of this account.
    pub(crate) role: String,
    /// The state of this account in the group: `pending` or `active`.
    pub(crate) state: String,
    pub(crate) owner_name: String,
    pub(crate) quantity: u64,
    /// Every member, for the owner and the admins; empty for a member.
    pub(crate) members: Vec<Member>,
}

impl Group {
    fn manages(&self) -> bool {
        self.state == "active" && matches!(self.role.as_str(), "owner" | "admin")
    }

    fn active(&self) -> usize {
        self.members
            .iter()
            .filter(|member| member.state == "active")
            .count()
    }

    /// "Family" or "Team".
    fn label(&self) -> &'static str {
        if self.kind == "team" {
            "Team"
        } else {
            "Family"
        }
    }

    /// "family" or "team", in a sentence.
    fn word(&self) -> &'static str {
        if self.kind == "team" {
            "team"
        } else {
            "family"
        }
    }
}

/// The account at Connect, as `GET /v1/account` and `GET /v1/account/group` showed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Account {
    pub(crate) account_id: String,
    pub(crate) name: String,
    pub(crate) email: Option<String>,
    pub(crate) plan: Plan,
    pub(crate) devices: Vec<Device>,
    pub(crate) group: Option<Group>,
}

impl Account {
    /// This account pays: it has no group, or owns it.
    fn pays(&self) -> bool {
        self.group
            .as_ref()
            .is_none_or(|group| group.role == "owner")
    }
}

/// What the section shows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // One value for each frame; a box buys nothing.
pub(crate) enum Shown {
    /// This Mac has no Connect account.
    None,
    /// The account file is there; the key is not in memory (after a lock or a start).
    SignedOut {
        name: Option<String>,
        device_name: String,
    },
    /// The account is open but Connect has not answered yet ("Asking Apassy Connect…").
    Loading {
        name: Option<String>,
    },
    /// The account is open, and Connect could not be reached for its first answer. The
    /// vault and its local work go on; the section asks again by itself.
    Unreachable {
        name: Option<String>,
        device_name: String,
        note: String,
    },
    /// Connect says this Mac was removed from its account, or the key of this Mac cannot
    /// be read any more. The account file and the key stay until the owner chooses
    /// "Forget This Mac…". `note` says why.
    Removed {
        name: Option<String>,
        device_name: String,
        note: String,
    },
    Account(Account),
}

/// Everything that Settings > Connect shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectView {
    pub(crate) shown: Shown,
    pub(crate) plans: Option<Plans>,
    /// The vault is locked: no owner check can run.
    pub(crate) locked: bool,
    /// A step runs: the buttons are off.
    pub(crate) busy: bool,
    pub(crate) error: Option<String>,
    pub(crate) now: u64,
}

impl ConnectView {
    fn plan_name(&self, plan: &str) -> String {
        self.plans
            .as_ref()
            .and_then(|plans| plans.offer(plan))
            .map_or_else(
                || fallback_name(plan).to_owned(),
                |offer| offer.name.clone(),
            )
    }

    /// The status line of the list row and the header.
    pub(crate) fn status_line(&self) -> String {
        let Shown::Account(account) = &self.shown else {
            return match &self.shown {
                Shown::None => NOT_ON_CONNECT.to_owned(),
                Shown::Removed { .. } => REMOVED.to_owned(),
                Shown::Unreachable { .. } => UNREACHABLE.to_owned(),
                _ => SIGNED_OUT.to_owned(),
            };
        };
        let plan = &account.plan;
        let name = plan
            .plan
            .as_deref()
            .map(|key| self.plan_name(key))
            .unwrap_or_default();
        match plan.status.as_str() {
            "active" | "trialing" => {
                if let Some(group) = account.group.as_ref().filter(|group| group.manages()) {
                    let unit = if group.kind == "team" {
                        "seats"
                    } else {
                        "people"
                    };
                    return format!("{name} · {} of {} {unit}", group.active(), group.quantity);
                }
                match (plan.ends_at, plan.renews_at) {
                    (Some(ends), _) => format!("{name} · Ends {}", day(ends)),
                    (None, Some(renews)) => format!("{name} · Renews {}", day(renews)),
                    (None, None) => name,
                }
            }
            "past_due" => format!("{name} · Past due"),
            "read_only" => plan.read_only_until.map_or_else(
                || "Read-only".to_owned(),
                |at| format!("Read-only until {}", day(at)),
            ),
            "suspended" => "Connect ended".to_owned(),
            "pending" => PENDING_PAYMENT.to_owned(),
            _ => NO_PLAN.to_owned(),
        }
    }

    /// The value of the Plan row and its tone.
    pub(crate) fn plan_value(&self, plan: &Plan) -> (String, Tone) {
        let name = plan
            .plan
            .as_deref()
            .map(|key| self.plan_name(key))
            .unwrap_or_default();
        match plan.status.as_str() {
            "active" | "trialing" => match (plan.ends_at, plan.renews_at) {
                (Some(ends), _) => (format!("{name} · Ends {}", day(ends)), Tone::Neutral),
                (None, Some(renews)) => (format!("{name} · Renews {}", day(renews)), Tone::Neutral),
                (None, None) => (name, Tone::Neutral),
            },
            "past_due" => (format!("{name} · Past due"), Tone::Warning),
            "read_only" => (
                plan.read_only_until.map_or_else(
                    || "Read-only".to_owned(),
                    |at| format!("Read-only until {}", day(at)),
                ),
                Tone::Warning,
            ),
            "suspended" => ("Ended".to_owned(), Tone::Critical),
            "pending" => (PENDING_PAYMENT.to_owned(), Tone::Neutral),
            _ => (NO_PLAN.to_owned(), Tone::Neutral),
        }
    }
}

/// The line under the Plan row of a plan that needs the owner, and its tone.
pub(crate) fn plan_note(plan: &Plan) -> Option<(String, Tone)> {
    match plan.status.as_str() {
        "past_due" => Some((
            plan.grace_until.map_or_else(
                || "The last payment failed. Update the payment method to keep Connect.".to_owned(),
                |at| {
                    format!(
                        "The last payment failed. Update the payment method by {} to keep Connect.",
                        day(at)
                    )
                },
            ),
            Tone::Warning,
        )),
        "read_only" => Some((
            format!(
                "Your devices can still download their copies from Connect; nothing new is uploaded.{}",
                plan.delete_at
                    .map(|at| format!(" The copies at Connect are deleted on {}.", day(at)))
                    .unwrap_or_default()
            ),
            Tone::Warning,
        )),
        "suspended" => Some((
            plan.delete_at.map_or_else(
                || "Choose a plan to use Connect again.".to_owned(),
                |at| {
                    format!(
                        "The copies at Connect are deleted on {}. Choose a plan before then to keep them.",
                        day(at)
                    )
                },
            ),
            Tone::Critical,
        )),
        _ => None,
    }
}

/// What the owner chose in the section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Create,
    AddThisMac,
    SignIn,
    ChoosePlan,
    ManageBilling,
    AddDevice,
    /// Revoke… or Forget… of the device with this index.
    Revoke(usize),
    /// "Forget This Mac…" of a Mac that Connect removed from its account.
    ForgetRemoved,
    Invite,
    /// Confirm… of the member with this index.
    ConfirmMember(usize),
    /// Remove… of the member with this index.
    RemoveMember(usize),
    ChangeSeats,
    /// Leave… of a member's own group.
    Leave,
    JoinGroup,
    Delete,
}

// ---- Drawing. ----

/// Draw the section.
pub(crate) fn draw(ui: &mut Ui, view: &ConnectView) -> Option<Action> {
    let mut action = None;
    if let Some(error) = &view.error {
        rows::footnote_colored(ui, error.as_str(), Tone::Critical.text());
    }
    ui.add_enabled_ui(!view.busy, |ui| match &view.shown {
        Shown::None => not_on_connect(ui, &mut action),
        Shown::SignedOut { name, device_name } => {
            rows::group(ui, Some(GROUP_LABEL), |g| {
                if let Some(name) = name {
                    g.labeled("Name", rows::value(name.as_str()));
                }
                g.labeled(THIS_DEVICE, rows::value(device_name.as_str()));
                g.line_note(SIGNED_OUT, None, Some(rows::note(SIGNED_OUT_NOTE)), |ui| {
                    if kit::small_button(ui, SIGN_IN, Style::Prominent).clicked() {
                        action = Some(Action::SignIn);
                    }
                });
            });
        }
        Shown::Loading { name } => {
            rows::group(ui, Some(GROUP_LABEL), |g| {
                if let Some(name) = name {
                    g.labeled("Name", rows::value(name.as_str()));
                }
                g.row(|ui| {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(12.0));
                        ui.label(rows::value("Asking Apassy Connect…"));
                    });
                });
            });
        }
        Shown::Unreachable {
            name,
            device_name,
            note,
        } => {
            rows::group(ui, Some(GROUP_LABEL), |g| {
                if let Some(name) = name {
                    g.labeled("Name", rows::value(name.as_str()));
                }
                g.labeled(THIS_DEVICE, rows::value(device_name.as_str()));
                g.line_note(UNREACHABLE, None, Some(rows::note(note)), |ui| {
                    if kit::small_button(ui, ASK_AGAIN, Style::Bordered).clicked() {
                        action = Some(Action::SignIn);
                    }
                });
            });
        }
        Shown::Removed {
            name,
            device_name,
            note,
        } => {
            rows::group(ui, Some(GROUP_LABEL), |g| {
                if let Some(name) = name {
                    g.labeled("Name", rows::value(name.as_str()));
                }
                g.labeled(THIS_DEVICE, rows::value(device_name.as_str()));
                g.line_note(REMOVED, None, Some(rows::note(note)), |ui| {
                    if ui
                        .add_enabled_ui(!view.locked, |ui| {
                            kit::small_button(ui, FORGET_THIS_MAC, Style::Bordered)
                        })
                        .inner
                        .clicked()
                    {
                        action = Some(Action::ForgetRemoved);
                    }
                });
            });
        }
        Shown::Account(account) => account_section(ui, view, account, &mut action),
    });
    action
}

fn not_on_connect(ui: &mut Ui, action: &mut Option<Action>) {
    rows::group(ui, Some(GROUP_LABEL), |g| {
        g.row(|ui| {
            ui.label(rows::label_text(NOT_ON_CONNECT));
            ui.add(Label::new(rows::note(INTRO)).wrap());
        });
        g.tone_row(SELF_HOST, Tone::Accent.text());
    });
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        if kit::button(ui, CREATE, Style::Prominent).clicked() {
            *action = Some(Action::Create);
        }
        if kit::button(ui, ADD_THIS_MAC, Style::Bordered).clicked() {
            *action = Some(Action::AddThisMac);
        }
    });
    rows::footnote(ui, KEY_NOTE);
}

fn account_section(
    ui: &mut Ui,
    view: &ConnectView,
    account: &Account,
    action: &mut Option<Action>,
) {
    let plan = &account.plan;
    let group = account.group.as_ref();
    let has_plan = plan.status != "none";
    let can_choose = account.pays()
        && matches!(plan.status.as_str(), "none" | "read_only" | "suspended")
        && group.is_none_or(|group| group.role == "owner");
    let billing = account.pays() && has_plan;
    rows::group(ui, Some(GROUP_LABEL), |g| {
        g.labeled("Name", rows::value(account.name.as_str()));
        if let Some(email) = &account.email {
            g.labeled("Email", rows::value(email.as_str()));
        }
        let (value, tone) = view.plan_value(plan);
        let color = match tone {
            Tone::Neutral => kit::palette().secondary,
            tone => tone.text(),
        };
        // The buttons stay on the line of the label, and the status goes under it in
        // full: "Connect Personal · Renews 10 Dec 2026" never ends in "…" at the width
        // of Settings (frame 6 of the mockup).
        g.line_note(
            "Plan",
            None,
            Some(kit::text(value, Font::Body).color(color)),
            |ui| {
                if billing && kit::small_button(ui, MANAGE_BILLING, Style::Bordered).clicked() {
                    *action = Some(Action::ManageBilling);
                }
                if can_choose && kit::small_button(ui, CHOOSE_PLAN, Style::Prominent).clicked() {
                    *action = Some(Action::ChoosePlan);
                }
            },
        );
        if let Some(group) = group.filter(|group| group.manages() && plan.entitled) {
            let label = if group.kind == "team" {
                "Seats"
            } else {
                "People"
            };
            let value = format!("{} of {}", group.active(), group.quantity);
            g.line(label, Some(rows::value(value)), |ui| {
                if group.role == "owner"
                    && ui
                        .add_enabled_ui(!view.locked, |ui| {
                            kit::small_button(ui, "Change…", Style::Bordered)
                        })
                        .inner
                        .clicked()
                {
                    *action = Some(Action::ChangeSeats);
                }
            });
        }
        if let Some(group) = group.filter(|group| !group.manages()) {
            let line = if group.state == "pending" {
                format!("Waiting for {} to confirm you.", group.owner_name)
            } else {
                format!("{} manages the plan and the billing.", group.owner_name)
            };
            g.tone_row(line, kit::palette().secondary);
        }
        if let Some((line, tone)) = plan_note(plan) {
            g.tone_row(line, tone.text());
        }
    });
    if view.locked {
        rows::footnote(ui, LOCKED);
    }
    devices_group(ui, view, account, action);
    match group {
        Some(group) => group_section(ui, view, account, group, action),
        None if !plan.entitled => {
            rows::group(ui, Some("Family or Team"), |g| {
                g.line_note(JOIN_GROUP, None, Some(rows::note(JOIN_GROUP_NOTE)), |ui| {
                    if kit::small_button(ui, "Join…", Style::Bordered).clicked() {
                        *action = Some(Action::JoinGroup);
                    }
                });
            });
        }
        None => {}
    }
    ui.add_space(6.0);
    rows::group(ui, None, |g| {
        ui_enabled_row(g, !view.locked, |g| {
            let response = g.clickable_row(DELETE, |ui| {
                ui.label(kit::text(DELETE, Font::Body).color(Tone::Critical.text()));
            });
            if response.clicked() {
                *action = Some(Action::Delete);
            }
        });
    });
}

/// Run `add` with the group's rows off when `enabled` is false.
fn ui_enabled_row(g: &mut rows::Group<'_>, enabled: bool, add: impl FnOnce(&mut rows::Group<'_>)) {
    if enabled {
        add(g);
    } else {
        g.row(|ui| {
            ui.label(kit::text(DELETE, Font::Body).color(kit::palette().tertiary));
        });
    }
}

/// A group label with a count on the right, as "Devices ⓘ 6" of Settings > Devices.
fn counted_label(ui: &mut Ui, title: &str, count: &str) {
    ui.add_space(18.0);
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        ui.add(
            Label::new(
                kit::text(title, Font::Callout)
                    .variation(b"wght", 600.0)
                    .color(kit::palette().secondary),
            )
            .selectable(false),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(2.0);
            ui.label(kit::text(count, Font::Callout).color(kit::palette().secondary));
        });
    });
    ui.add_space(6.0);
}

/// The small tile of a device: a gray rounded square with its glyph.
fn device_glyph(ui: &mut Ui, platform: &str) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(28.0), Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter();
    painter.rect_filled(rect, 7, kit::palette().fill_hover);
    let inner = Rect::from_center_size(rect.center(), Vec2::splat(17.0));
    match platform {
        "iphone" => {
            let body = Rect::from_center_size(inner.center(), Vec2::new(9.0, 15.0));
            painter.rect_stroke(
                body,
                2.5,
                Stroke::new(1.4, kit::palette().label),
                egui::StrokeKind::Middle,
            );
        }
        "linux" => kit::paint_icon(painter, inner, Icon::Terminal, kit::palette().label),
        _ => kit::paint_icon(painter, inner, Icon::Laptop, kit::palette().label),
    }
}

/// A row with a glyph, a title with an optional cap, a subline, and controls on the
/// right (the first is the rightmost).
fn entity_row(
    g: &mut rows::Group<'_>,
    glyph: impl FnOnce(&mut Ui),
    title: &str,
    cap: Option<(&str, Tone)>,
    subline: &str,
    controls: impl FnOnce(&mut Ui),
) {
    g.row(|ui| {
        egui::Sides::new()
            .shrink_left()
            .wrap_mode(egui::TextWrapMode::Truncate)
            .height(rows::LINE)
            .show(
                ui,
                |ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    glyph(ui);
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            ui.add(Label::new(rows::label_text(title)).truncate());
                            if let Some((cap, tone)) = cap {
                                kit::cap_toned(ui, cap, tone);
                            }
                        });
                        ui.add(Label::new(rows::note(subline)).truncate());
                    });
                },
                |ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    controls(ui);
                },
            );
    });
}

fn devices_group(ui: &mut Ui, view: &ConnectView, account: &Account, action: &mut Option<Action>) {
    counted_label(ui, "Devices", &account.devices.len().to_string());
    rows::group_box(ui, |g| {
        for (index, device) in account.devices.iter().enumerate() {
            let subline = format!("{} · Added {}", device.kind(), day(device.created_at));
            let cap = if device.this {
                Some((THIS_DEVICE, Tone::Neutral))
            } else if !device.verified {
                Some((NOT_VERIFIED, Tone::Warning))
            } else {
                None
            };
            entity_row(
                g,
                |ui| device_glyph(ui, &device.platform),
                &device.name,
                cap,
                &subline,
                |ui| {
                    let label = if device.this {
                        "Forget…"
                    } else {
                        "Revoke…"
                    };
                    let button = ui
                        .add_enabled_ui(!view.locked, |ui| {
                            kit::small_button(ui, label, Style::Bordered)
                        })
                        .inner;
                    let spoken = format!("{label} {}", device.name);
                    ui.ctx()
                        .accesskit_node_builder(button.id, |node| node.set_label(spoken));
                    if button.clicked() {
                        *action = Some(Action::Revoke(index));
                    }
                    let seen = if device.this {
                        Some(view.now)
                    } else {
                        device.last_seen_at
                    };
                    if let Some(at) = seen {
                        ui.label(
                            rows::value(super::devices::last_contact(at, view.now)).size(12.0),
                        );
                    }
                },
            );
        }
    });
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.add_enabled_ui(!view.locked, |ui| {
            if kit::button(ui, ADD_DEVICE, Style::Bordered).clicked() {
                *action = Some(Action::AddDevice);
            }
        });
    });
}

/// The role cap of a member: the owner of a family is its organizer.
fn role_cap(kind: &str, role: &str) -> Option<&'static str> {
    match (kind, role) {
        ("family", "owner") => Some("Organizer"),
        (_, "owner") => Some("Owner"),
        (_, "admin") => Some("Admin"),
        _ => None,
    }
}

fn group_section(
    ui: &mut Ui,
    view: &ConnectView,
    account: &Account,
    group: &Group,
    action: &mut Option<Action>,
) {
    if !group.manages() {
        rows::group(ui, Some(group.label()), |g| {
            let title = format!("{}'s {}", group.owner_name, group.word());
            let note = if group.state == "pending" {
                format!("Waiting for {} to confirm you.", group.owner_name)
            } else {
                format!("{} manages the plan and the members.", group.owner_name)
            };
            g.line_note(&title, None, Some(rows::note(&note)), |ui| {
                if ui
                    .add_enabled_ui(!view.locked, |ui| {
                        kit::small_button(ui, "Leave…", Style::Bordered)
                    })
                    .inner
                    .clicked()
                {
                    *action = Some(Action::Leave);
                }
            });
        });
        return;
    }
    counted_label(
        ui,
        group.label(),
        &format!("{} of {}", group.active(), group.quantity),
    );
    rows::group_box(ui, |g| {
        for (index, member) in group.members.iter().enumerate() {
            let pending = member.state == "pending";
            let subline = if pending {
                "Waits for your confirmation".to_owned()
            } else {
                member
                    .joined_at
                    .map_or_else(String::new, |at| format!("Since {}", day(at)))
            };
            let removable = member.role != "owner"
                && member.account_id != account.account_id
                && (group.role == "owner" || member.role == "member");
            entity_row(
                g,
                |ui| {
                    kit::avatar(ui, &member.name, 28.0);
                },
                &member.name,
                role_cap(&group.kind, &member.role).map(|cap| (cap, Tone::Neutral)),
                &subline,
                |ui| {
                    ui.add_enabled_ui(!view.locked, |ui| {
                        if pending && kit::small_button(ui, "Confirm…", Style::Prominent).clicked()
                        {
                            *action = Some(Action::ConfirmMember(index));
                        }
                        if removable && kit::small_button(ui, "Remove…", Style::Bordered).clicked()
                        {
                            *action = Some(Action::RemoveMember(index));
                        }
                    });
                },
            );
        }
    });
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        if kit::button(ui, INVITE, Style::Bordered).clicked() {
            *action = Some(Action::Invite);
        }
    });
}

// ---- Sheets. ----

/// A sheet of the section, over the window. Text that the owner types lives here.
pub(crate) enum Sheet {
    /// Frame 2a.
    Create { name: String, device_name: String },
    /// Frame 2b: the 16 words, once. They are erased with the sheet.
    Recovery { words: zeroize::Zeroizing<String> },
    /// Frame 4: the plan, `month` or `year`, and the people or seats.
    Picker {
        plan: String,
        interval: String,
        count: u64,
    },
    /// Frame 5a and 5c.
    Waiting { url: String, stopped: bool },
    /// Frame 5b.
    Active { title: String, line: String },
    /// Frame 7a: the link code, shown as text and as a QR code of the same text.
    AddDevice {
        code: zeroize::Zeroizing<String>,
        expires_at: u64,
    },
    /// Frame 7b.
    Words {
        join_id: u64,
        device_name: String,
        platform: String,
        words: String,
    },
    /// After a confirmed device.
    DeviceAdded { name: String },
    /// Frame 7c and 7d.
    Revoke {
        index: usize,
        name: String,
        this: bool,
    },
    /// "Forget This Mac…" after Connect removed this Mac: the confirmation.
    ForgetRemoved,
    /// Frame 8a.
    JoinAccount { code: zeroize::Zeroizing<String> },
    /// Frame 8b.
    JoinWaiting { confirmer: String, words: String },
    /// Frame 8c.
    Joined,
    /// Frame 9a and 9b: `link` after Create Link.
    Invite {
        kind: String,
        /// A Team owner chooses the role first.
        choose_role: bool,
        role: String,
        link: Option<(String, u64)>,
    },
    /// Frame 9c, and Leave… of a member (`leave`).
    RemoveMember {
        account_id: String,
        name: String,
        kind: String,
        leave: bool,
    },
    /// Frame 9d.
    Seats { kind: String, quantity: u64 },
    /// Frame 10a and 10c.
    JoinGroup { link: String, refused: bool },
    /// Frame 10b.
    JoinSent { owner_name: String },
    /// Frame 11a.
    Delete,
    /// Frame 11b.
    MembersFirst,
}

/// What the owner chose in a sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SheetChoice {
    Cancel,
    /// The main button of the sheet: Create Account, Continue…, Confirm…, Revoke…,
    /// Create Link, Join, Change…, Delete….
    Go,
    /// Refuse a device.
    Refuse,
    /// I Saved It, Done, OK, Close.
    Done,
    OpenAgain,
    CheckAgain,
    /// Ask Connect again after a failed step: the prices of the picker.
    TryAgain,
    Copy(String),
}

/// Sheet buttons with one leading and one trailing button, each giving a choice.
fn pair(
    ui: &mut Ui,
    leading: impl FnOnce(&mut Ui) -> Option<SheetChoice>,
    trailing: impl FnOnce(&mut Ui) -> Option<SheetChoice>,
) -> Option<SheetChoice> {
    let mut left = None;
    let mut right = None;
    kit::sheet_buttons(ui, |ui| left = leading(ui), |ui| right = trailing(ui));
    left.or(right)
}

/// A − n + stepper inside `1..=max`.
fn stepper(ui: &mut Ui, value: &mut u64, max: u64) {
    ui.spacing_mut().item_spacing.x = 4.0;
    if ui
        .add_enabled_ui(*value < max, |ui| {
            kit::small_button(ui, "+", Style::Bordered)
        })
        .inner
        .clicked()
    {
        *value += 1;
    }
    ui.label(kit::text(value.to_string(), Font::Body).color(kit::palette().label));
    if ui
        .add_enabled_ui(*value > 1, |ui| kit::small_button(ui, "−", Style::Bordered))
        .inner
        .clicked()
    {
        *value -= 1;
    }
}

/// The six safety words, large, in two rows of three.
fn big_words(ui: &mut Ui, words: &str) {
    let list: Vec<&str> = words.split_whitespace().collect();
    ui.add_space(6.0);
    for line in list.chunks(3) {
        ui.vertical_centered(|ui| {
            egui::Frame::new()
                .fill(kit::palette().window)
                .stroke(Stroke::new(0.5, kit::palette().border))
                .corner_radius(8)
                .inner_margin(egui::Margin::symmetric(14, 6))
                .show(ui, |ui| {
                    ui.label(
                        kit::text(line.join("  "), Font::Title)
                            .variation(b"wght", 600.0)
                            .color(kit::palette().label),
                    );
                });
        });
        ui.add_space(4.0);
    }
    ui.add_space(6.0);
}

/// The centred head of a result: a check, the title, and its lines.
fn result_head(ui: &mut Ui, title: &str, lines: &[&str]) {
    ui.vertical_centered(|ui| {
        ui.add_space(6.0);
        kit::paint_icon_in(ui, Icon::CheckCircle, 30.0, Tone::Good.mark());
        ui.add_space(6.0);
        ui.label(kit::text(title, Font::Title3).color(kit::palette().label));
        ui.add_space(4.0);
        for line in lines {
            kit::paragraph(ui, *line, Font::Callout, kit::palette().label);
        }
    });
    ui.add_space(10.0);
}

/// A destructive alert: the title, the lead, Cancel (the default) and the red button.
fn destructive(ui: &mut Ui, title: &str, lead: &str, button: &str) -> Option<SheetChoice> {
    let mut choice = None;
    kit::sheet_title(ui, title, Some(lead));
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            if kit::button(ui, button, Style::Destructive).clicked() {
                choice = Some(SheetChoice::Go);
            }
            if kit::alert_cancel(ui).clicked() {
                choice = Some(SheetChoice::Cancel);
            }
        },
    );
    choice
}

/// One result sheet with Done.
fn done_sheet(ui: &mut Ui, title: &str, lines: &[&str]) -> Option<SheetChoice> {
    let mut choice = None;
    result_head(ui, title, lines);
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            if kit::button(ui, "Done", Style::Prominent).clicked() {
                choice = Some(SheetChoice::Done);
            }
        },
    );
    choice
}

/// The plan picker (frame 4). The rows and the total come from `plans`. `failed`: the
/// prices did not load, and "Try Again" asks Connect again.
fn picker(
    ui: &mut Ui,
    plans: Option<&Plans>,
    plan: &mut String,
    interval: &mut String,
    count: &mut u64,
    busy: bool,
    failed: bool,
) -> Option<SheetChoice> {
    let mut choice = None;
    kit::sheet_title(ui, PICKER_TITLE, Some(PICKER_LEAD));
    let mut yearly = interval == "year";
    ui.vertical_centered(|ui| {
        kit::segmented(
            ui,
            "connect-interval",
            &mut yearly,
            &[(false, "Monthly"), (true, "Yearly")],
        );
    });
    *interval = if yearly { "year" } else { "month" }.to_owned();
    ui.add_space(10.0);
    let Some(plans) = plans else {
        rows::group(ui, None, |g| {
            g.row(|ui| {
                ui.horizontal(|ui| {
                    if failed {
                        ui.label(rows::value(PRICES_FAILED));
                    } else {
                        ui.add(egui::Spinner::new().size(12.0));
                        ui.label(rows::value(LOADING_PRICES));
                    }
                });
            });
        });
        ui.add_space(8.0);
        return pair(
            ui,
            |ui| {
                (failed && kit::button(ui, TRY_AGAIN, Style::Bordered).clicked())
                    .then_some(SheetChoice::TryAgain)
            },
            |ui| {
                ui.add_enabled_ui(false, |ui| {
                    kit::button(ui, CONTINUE_BROWSER, Style::Prominent)
                });
                kit::alert_cancel(ui)
                    .clicked()
                    .then_some(SheetChoice::Cancel)
            },
        )
        .or(choice);
    };
    rows::group_box(ui, |g| {
        for offer in &plans.offers {
            let Some(price) = offer.price(interval) else {
                continue;
            };
            let selected = *plan == offer.plan;
            let unit = if offer.plan == "team" {
                format!("a member {}", per(interval))
            } else {
                per(interval).to_owned()
            };
            let response = g.clickable_row(&offer.name, |ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                let (rect, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
                let painter = ui.painter();
                if selected {
                    painter.circle_filled(rect.center(), 8.0, kit::palette().accent);
                    painter.circle_filled(rect.center(), 3.0, kit::palette().surface);
                } else {
                    painter.circle_stroke(
                        rect.center(),
                        7.5,
                        Stroke::new(1.0, kit::palette().border),
                    );
                }
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.label(rows::label_text(&offer.name));
                    ui.add(
                        Label::new(rows::note(&plan_line(offer, interval, &plans.currency)))
                            .truncate(),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 1.0;
                        ui.label(
                            kit::text(money(&plans.currency, price.amount), Font::Body)
                                .color(kit::palette().label),
                        );
                        ui.label(rows::note(&unit));
                    });
                });
            });
            if response.clicked() && !selected {
                *plan = offer.plan.clone();
                *count = if offer.counted() {
                    offer.included.max(1)
                } else {
                    1
                };
            }
        }
    });
    let offer = plans.offer(plan);
    ui.add_space(10.0);
    rows::group_box(ui, |g| {
        if let Some(offer) = offer.filter(|offer| offer.counted()) {
            *count = (*count).clamp(1, offer.max);
            let max = offer.max;
            g.line(offer.unit_label(), None, |ui| stepper(ui, count, max));
        }
        let total = offer
            .and_then(|offer| offer.total(interval, *count))
            .map(|cents| format!("{} {}", money(&plans.currency, cents), per(interval)))
            .unwrap_or_default();
        g.line(
            "Total",
            Some(
                kit::text(total, Font::Body)
                    .variation(b"wght", 600.0)
                    .color(kit::palette().label),
            ),
            |_| {},
        );
    });
    ui.add_space(6.0);
    kit::note(ui, PICKER_NOTE);
    ui.add_space(8.0);
    let can_go = !busy && offer.is_some_and(|offer| offer.total(interval, *count).is_some());
    kit::sheet_buttons(
        ui,
        |ui| {
            if busy {
                ui.add(egui::Spinner::new().size(14.0));
            }
        },
        |ui| {
            if ui
                .add_enabled_ui(can_go, |ui| {
                    kit::button(ui, CONTINUE_BROWSER, Style::Prominent)
                })
                .inner
                .clicked()
            {
                choice = Some(SheetChoice::Go);
            }
            if kit::alert_cancel(ui).clicked() {
                choice = Some(SheetChoice::Cancel);
            }
        },
    );
    choice
}

/// Draw `sheet` over the window. `error` is the error of its last step; `qr` draws the
/// QR code of a text (the vault build). Escape is Cancel, except for the recovery code,
/// which has only "I Saved It".
pub(crate) fn sheet(
    ctx: &egui::Context,
    sheet: &mut Sheet,
    plans: Option<&Plans>,
    busy: bool,
    error: Option<&str>,
    now: u64,
    qr: &dyn Fn(&mut Ui, &str),
) -> Option<SheetChoice> {
    let mut choice = None;
    let recovery = matches!(sheet, Sheet::Recovery { .. });
    let width = if matches!(sheet, Sheet::Picker { .. }) {
        460.0
    } else {
        420.0
    };
    // A step that failed and does not run again: the picker offers "Try Again".
    let failed = error.is_some() && !busy;
    let response = kit::sheet(ctx, "connect-sheet", width, |ui| {
        choice = sheet_body(ui, sheet, plans, busy, failed, now, qr);
        if let Some(error) = error {
            ui.add_space(4.0);
            kit::paragraph(ui, error, Font::Callout, Tone::Critical.text());
        }
    });
    if response.escape && !recovery && choice.is_none() {
        choice = Some(SheetChoice::Cancel);
    }
    choice
}

fn cancel_and(ui: &mut Ui, label: &str, enabled: bool, busy: bool) -> Option<SheetChoice> {
    let mut choice = None;
    kit::sheet_buttons(
        ui,
        |ui| {
            if busy {
                ui.add(egui::Spinner::new().size(14.0));
            }
        },
        |ui| {
            if ui
                .add_enabled_ui(enabled && !busy, |ui| {
                    kit::button(ui, label, Style::Prominent)
                })
                .inner
                .clicked()
            {
                choice = Some(SheetChoice::Go);
            }
            if kit::alert_cancel(ui).clicked() {
                choice = Some(SheetChoice::Cancel);
            }
        },
    );
    choice
}

#[allow(clippy::too_many_lines)]
fn sheet_body(
    ui: &mut Ui,
    sheet: &mut Sheet,
    plans: Option<&Plans>,
    busy: bool,
    failed: bool,
    now: u64,
    qr: &dyn Fn(&mut Ui, &str),
) -> Option<SheetChoice> {
    match sheet {
        Sheet::Create { name, device_name } => {
            kit::sheet_title(ui, CREATE_TITLE, Some(CREATE_LEAD));
            rows::group_box(ui, |g| {
                g.field("Your Name", |ui| {
                    kit::text_input(ui, name, "connect-name", "Your name")
                });
                g.field(THIS_DEVICE, |ui| {
                    kit::text_input(ui, device_name, "connect-device", crate::computer_cap!())
                });
            });
            ui.add_space(6.0);
            kit::note(ui, CREATE_NOTE);
            ui.add_space(8.0);
            let ready = !name.trim().is_empty() && !device_name.trim().is_empty();
            cancel_and(ui, "Create Account", ready, busy)
        }
        Sheet::Recovery { words } => {
            let mut choice = None;
            kit::sheet_title(ui, RECOVERY_TITLE, Some(RECOVERY_LEAD));
            let list: Vec<&str> = words.split_whitespace().collect();
            egui::Frame::new()
                .fill(kit::palette().surface)
                .stroke(Stroke::new(0.5, kit::palette().border))
                .corner_radius(8)
                .inner_margin(egui::Margin::symmetric(14, 10))
                .show(ui, |ui| {
                    egui::Grid::new("connect-recovery")
                        .num_columns(4)
                        .spacing([14.0, 6.0])
                        .show(ui, |ui| {
                            for (index, word) in list.iter().enumerate() {
                                ui.label(
                                    kit::text(format!("{:>2} {word}", index + 1), Font::Mono)
                                        .color(kit::palette().label),
                                );
                                if index % 4 == 3 {
                                    ui.end_row();
                                }
                            }
                        });
                });
            ui.add_space(8.0);
            kit::note(ui, RECOVERY_NOTE);
            ui.add_space(8.0);
            choice = pair(
                ui,
                |ui| {
                    kit::button(ui, "Copy", Style::Bordered)
                        .clicked()
                        .then(|| SheetChoice::Copy(words.as_str().to_owned()))
                },
                |ui| {
                    kit::button(ui, SAVED_IT, Style::Prominent)
                        .clicked()
                        .then_some(SheetChoice::Done)
                },
            )
            .or(choice);
            choice
        }
        Sheet::Picker {
            plan,
            interval,
            count,
        } => picker(ui, plans, plan, interval, count, busy, failed),
        Sheet::Waiting { stopped, .. } => {
            let mut choice = None;
            if *stopped {
                kit::sheet_title(ui, WAIT_TITLE, Some(WAIT_STOPPED));
                choice = pair(
                    ui,
                    |ui| {
                        kit::button(ui, CHECK_AGAIN, Style::Bordered)
                            .clicked()
                            .then_some(SheetChoice::CheckAgain)
                    },
                    |ui| {
                        kit::button(ui, "Close", Style::Prominent)
                            .clicked()
                            .then_some(SheetChoice::Cancel)
                    },
                )
                .or(choice);
                return choice;
            }
            kit::sheet_title(ui, WAIT_TITLE, Some(WAIT_LEAD));
            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(14.0));
                    ui.label(rows::value(WAIT_LINE));
                });
            });
            ui.add_space(8.0);
            kit::note(ui, WAIT_NOTE);
            ui.add_space(8.0);
            choice = pair(
                ui,
                |ui| {
                    kit::button(ui, OPEN_AGAIN, Style::Bordered)
                        .clicked()
                        .then_some(SheetChoice::OpenAgain)
                },
                |ui| {
                    kit::alert_cancel(ui)
                        .clicked()
                        .then_some(SheetChoice::Cancel)
                },
            )
            .or(choice);
            choice
        }
        Sheet::Active { title, line } => done_sheet(ui, title, &[line.as_str()]),
        Sheet::AddDevice { code, expires_at } => {
            let mut choice = None;
            kit::sheet_title(ui, ADD_TITLE, Some(ADD_LEAD));
            ui.vertical_centered(|ui| qr(ui, code.as_str()));
            ui.add_space(8.0);
            rows::group_box(ui, |g| {
                let shown = format!("{}…", &code[..code.len().min(26)]);
                g.line(
                    "Code",
                    Some(kit::text(shown, Font::Mono).color(kit::palette().label)),
                    |ui| {
                        if kit::small_button(ui, "Copy", Style::Bordered).clicked() {
                            choice = Some(SheetChoice::Copy(code.as_str().to_owned()));
                        }
                    },
                );
                let left = expires_at.saturating_sub(now);
                g.labeled(
                    "Expires In",
                    rows::value(format!("{}:{:02}", left / 60, left % 60)),
                );
            });
            ui.add_space(8.0);
            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(12.0));
                    ui.label(rows::value(ADD_WAITING));
                });
            });
            ui.add_space(8.0);
            kit::sheet_buttons(
                ui,
                |_| {},
                |ui| {
                    if kit::alert_cancel(ui).clicked() {
                        choice = Some(SheetChoice::Cancel);
                    }
                },
            );
            choice
        }
        Sheet::Words {
            device_name,
            platform,
            words,
            ..
        } => {
            kit::sheet_title(
                ui,
                &format!("\"{device_name}\" Asks to Join"),
                Some(&format!(
                    "\"{device_name}\" asks to join your Apassy Connect account. {WORDS_TAIL}"
                )),
            );
            big_words(ui, words);
            let kind = Device {
                id: String::new(),
                name: String::new(),
                platform: platform.clone(),
                created_at: 0,
                last_seen_at: None,
                this: false,
                verified: false,
            }
            .kind();
            rows::group_box(ui, |g| g.labeled("Kind", rows::value(kind)));
            ui.add_space(8.0);
            ui.add_enabled_ui(!busy, |ui| {
                pair(
                    ui,
                    |ui| {
                        kit::button(ui, "Refuse", Style::Destructive)
                            .clicked()
                            .then_some(SheetChoice::Refuse)
                    },
                    |ui| {
                        kit::button(ui, "Confirm…", Style::Prominent)
                            .clicked()
                            .then_some(SheetChoice::Go)
                    },
                )
            })
            .inner
        }
        Sheet::DeviceAdded { name } => done_sheet(ui, &format!("{name} Added"), &[ADDED_LEAD]),
        Sheet::ForgetRemoved => destructive(ui, FORGET_TITLE, FORGET_REMOVED_LEAD, "Forget"),
        Sheet::Revoke { name, this, .. } => {
            if *this {
                destructive(ui, FORGET_TITLE, FORGET_LEAD, "Forget…")
            } else {
                destructive(ui, &format!("Revoke {name}?"), REVOKE_LEAD, "Revoke…")
            }
        }
        Sheet::JoinAccount { code } => {
            kit::sheet_title(ui, JOIN_ACCOUNT_TITLE, Some(JOIN_ACCOUNT_LEAD));
            kit::mono_input(ui, code, "connect-join-code", "apassy_alk_…");
            ui.add_space(8.0);
            let ready = !code.trim().is_empty();
            cancel_and(ui, "Continue", ready, busy)
        }
        Sheet::JoinWaiting { confirmer, words } => {
            let mut choice = None;
            kit::sheet_title(
                ui,
                &format!("Waiting for {confirmer}…"),
                Some(&format!(
                    "Both devices show these words. Confirm on {confirmer} only if they match."
                )),
            );
            big_words(ui, words);
            kit::sheet_buttons(
                ui,
                |ui| {
                    ui.add(egui::Spinner::new().size(14.0));
                },
                |ui| {
                    if kit::alert_cancel(ui).clicked() {
                        choice = Some(SheetChoice::Cancel);
                    }
                },
            );
            choice
        }
        Sheet::Joined => done_sheet(ui, JOINED_TITLE, &[JOINED_LEAD]),
        Sheet::Invite {
            kind,
            choose_role,
            role,
            link,
        } => {
            let title = if kind == "team" {
                "Invite to Your Team"
            } else {
                "Invite to Your Family"
            };
            kit::sheet_title(ui, title, Some(INVITE_LEAD));
            if let Some((url, expires_at)) = link {
                let mut choice = None;
                rows::group_box(ui, |g| {
                    let shown = match url.split_once('#') {
                        Some((page, _)) => format!("{page}#…"),
                        None => url.clone(),
                    };
                    g.line(
                        "Link",
                        Some(kit::text(shown, Font::Mono).color(kit::palette().label)),
                        |ui| {
                            if kit::small_button(ui, "Copy", Style::Bordered).clicked() {
                                choice = Some(SheetChoice::Copy(url.clone()));
                            }
                        },
                    );
                    g.labeled("Expires", rows::value(day(*expires_at)));
                });
                ui.add_space(6.0);
                kit::note(ui, INVITE_NOTE);
                ui.add_space(8.0);
                kit::sheet_buttons(
                    ui,
                    |_| {},
                    |ui| {
                        if kit::button(ui, "Done", Style::Prominent).clicked() {
                            choice = Some(SheetChoice::Done);
                        }
                    },
                );
                return choice;
            }
            if *choose_role {
                rows::group_box(ui, |g| {
                    g.line("Role", None, |ui| {
                        let mut admin = role == "admin";
                        kit::segmented(
                            ui,
                            "connect-role",
                            &mut admin,
                            &[(false, "Member"), (true, "Admin")],
                        );
                        *role = if admin { "admin" } else { "member" }.to_owned();
                    });
                });
                ui.add_space(6.0);
                kit::note(ui, ADMIN_NOTE);
                ui.add_space(8.0);
            }
            cancel_and(ui, CREATE_LINK, true, busy)
        }
        Sheet::RemoveMember {
            name, kind, leave, ..
        } => {
            let word = if kind == "team" { "team" } else { "family" };
            if *leave {
                destructive(
                    ui,
                    &format!("Leave the {word}?"),
                    &format!(
                        "You leave the {word} and its shared vaults. Your Connect account stays, without a plan."
                    ),
                    "Leave…",
                )
            } else {
                destructive(
                    ui,
                    &format!("Remove {name}?"),
                    &format!(
                        "{name} leaves your {word} and its shared vaults. {name} keeps an Apassy Connect account without a plan."
                    ),
                    "Remove…",
                )
            }
        }
        Sheet::Seats { kind, quantity } => {
            let team = kind == "team";
            let offer = plans.and_then(|plans| plans.offer(kind));
            let title = if team {
                "Seats in Your Team"
            } else {
                "People in Your Family"
            };
            let lead = offer
                .zip(plans)
                .and_then(|(offer, plans)| {
                    let price = offer.price("month")?;
                    let extra = price.extra?;
                    Some(if team {
                        format!("Each seat costs {} a month.", money(&plans.currency, extra))
                    } else {
                        format!(
                            "Each person after {} costs {} a month.",
                            offer.included,
                            money(&plans.currency, extra)
                        )
                    })
                })
                .unwrap_or_default();
            kit::sheet_title(ui, title, (!lead.is_empty()).then_some(lead.as_str()));
            let max = offer.map_or(u64::MAX, |offer| offer.max);
            rows::group_box(ui, |g| {
                let label = if team { "Seats" } else { "People" };
                g.line(label, None, |ui| stepper(ui, quantity, max));
            });
            ui.add_space(6.0);
            kit::note(ui, SEATS_NOTE);
            ui.add_space(8.0);
            cancel_and(ui, "Change…", *quantity > 0, busy)
        }
        Sheet::JoinGroup { link, refused } => {
            kit::sheet_title(ui, JOIN_GROUP, Some(JOIN_GROUP_NOTE));
            kit::mono_input(
                ui,
                link,
                "connect-join-group",
                "https://apassy.wyderka.cc/connect/join#…",
            );
            if *refused {
                ui.add_space(4.0);
                kit::paragraph(ui, JOIN_GROUP_REFUSED, Font::Callout, Tone::Critical.text());
            }
            ui.add_space(8.0);
            let ready = !link.trim().is_empty();
            cancel_and(ui, "Join", ready, busy)
        }
        Sheet::JoinSent { owner_name } => done_sheet(
            ui,
            &format!("Request Sent to {owner_name}"),
            &[&format!(
                concat!(
                    "{} confirms you on their ",
                    crate::computer!(),
                    ". Then the plan of the group covers you."
                ),
                owner_name
            )],
        ),
        Sheet::Delete => destructive(ui, DELETE_TITLE, DELETE_LEAD, "Delete…"),
        Sheet::MembersFirst => {
            let mut choice = None;
            kit::sheet_title(ui, MEMBERS_FIRST_TITLE, Some(MEMBERS_FIRST_LEAD));
            kit::sheet_buttons(
                ui,
                |_| {},
                |ui| {
                    if kit::button(ui, "OK", Style::Prominent).clicked() {
                        choice = Some(SheetChoice::Done);
                    }
                },
            );
            choice
        }
    }
}

// ---- The state of the section. ----

/// Settings > Connect: its sheet, and the account and its worker in the vault build.
#[derive(Default)]
pub(crate) struct State {
    pub(crate) sheet: Option<Sheet>,
    #[cfg(feature = "vault")]
    pub(crate) live: live::Live,
    /// The demo build: the mockup frame that the section shows.
    #[cfg(not(feature = "vault"))]
    pub(crate) demo: demo::Frame,
}

#[cfg(not(feature = "vault"))]
pub(super) use demo::{from_env_once as demo_from_env, section, status_line};
#[cfg(feature = "vault")]
pub(super) use live::{section, status_line};

#[cfg(feature = "vault")]
pub(crate) mod live;

#[cfg(not(feature = "vault"))]
mod demo;
