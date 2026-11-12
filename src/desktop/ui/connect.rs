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
pub(crate) const INTRO: &str = "Syncs your vaults and reaches your devices, without Tailscale.";
pub(crate) const SELF_HOST: &str = "Everything Connect does also runs on your own hardware, free.";
pub(crate) const CREATE: &str = "Create Account…";
pub(crate) const ADD_THIS_MAC: &str = concat!("Add This ", crate::computer_cap!(), "…");
pub(crate) const GROUP_LABEL: &str = "Apassy Connect";
pub(crate) const SIGNED_OUT: &str = "Signed out";
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
/// The lead of the sheet of "Join…".
pub(crate) const JOIN_GROUP_NOTE: &str = "Paste the invite link that the organizer sent you.";
pub(crate) const INVITE: &str = "Invite…";
pub(crate) const DELETE: &str = "Delete Account…";
pub(crate) const DELETED: &str = "The Connect account is deleted.";

pub(crate) const CREATE_TITLE: &str = "Create a Connect Account";
pub(crate) const CREATE_LEAD: &str = "No password or email needed. You choose a plan later.";
pub(crate) const CREATE_NOTE: &str = "Members of your family or team see this name.";
pub(crate) const RECOVERY_TITLE: &str = "Save Your Recovery Code";
pub(crate) const RECOVERY_LEAD: &str =
    "Shown once. Save it and the account ID in another password manager.";
pub(crate) const SAVED_IT: &str = "I Saved It";
/// A join whose key is in the account already (connect-account-v1 section 7.2).
pub(crate) const JOIN_FINISHING_TITLE: &str = "Finishing the Join…";
/// A join that made a new account key because the earlier one was used.
pub(crate) const JOIN_NEW_KEY: &str = concat!(
    "This ",
    crate::computer!(),
    " made a new device key. If the account still lists its earlier device, remove it from another device."
);
/// A join that made a new key while an account of an earlier join of this device still
/// lists the earlier key, which this device could not remove there (connect-account-v1
/// section 7.2): `confirmer` confirmed that earlier join, and `device` is this device's
/// name there.
pub(crate) fn join_left_behind(confirmer: &str, device: &str) -> String {
    format!(
        concat!(
            "Another Apassy Connect account still lists this ",
            crate::computer!(),
            " as “{device}”. On “{confirmer}”, open Settings › Connect and remove it."
        ),
        device = device,
        confirmer = confirmer,
    )
}

/// Settings › Connect: a new recovery code (connect-account-v1 section 9.1).
/// The title of the help of a new recovery code that another device made.
pub(crate) const RECOVERY_ROW: &str = "Recovery Code";
pub(crate) const NEW_RECOVERY: &str = "New Recovery Code…";
/// The button of the Recovery Code row (spoken [`NEW_RECOVERY`]).
pub(crate) const NEW_CODE: &str = "New Code…";
pub(crate) const RECOVERY_UNSEEN: &str = "You have not seen this account's recovery code.";
/// The sheet of a new recovery code that Connect took while the account file of this
/// device could not be written (section 9.1).
pub(crate) const RECOVERY_UNRECORDED: &str = concat!(
    "This ",
    crate::computer!(),
    " could not record the new code. It works: save it now."
);
/// The sheet that shows a recovery code once: the account id comes with it.
pub(crate) const ACCOUNT_ID: &str = "Account ID";
/// The help of the line of a new recovery code that another device made.
pub(crate) const RECOVERY_CHANGED_HELP: [&str; 2] = [
    "The old code no longer works.",
    "Not you? Revoke that device, then make a new code.",
];
pub(crate) const RECOVERY_CHANGED_OK: &str = "OK";
/// The Account row: the name and the email, and the menu of the rare account actions.
pub(crate) const ACCOUNT_ROW: &str = "Account";
pub(crate) const MORE_ACCOUNT: &str = "More account actions";
pub(crate) const COPY_ACCOUNT_ID: &str = "Copy Account ID";
/// A member's leave of its family or team.
pub(crate) const LEAVE_FAMILY: &str = "Leave Family…";
pub(crate) const LEAVE_TEAM: &str = "Leave Team…";
/// The row of an account without a family or team, with "Join…".
pub(crate) const JOIN_ROW: &str = "Family or Team";
/// The cap of a member that waits for the organizer's confirmation.
pub(crate) const PENDING_MEMBER: &str = "Pending";

/// The line of a new recovery code that another device made (section 9.1): `device`, the
/// signed name of that device when the device list holds it, and `at`, the time of the
/// change at Connect.
pub(crate) fn recovery_changed(device: Option<&str>, at: Option<u64>) -> String {
    let device = device.unwrap_or("another device");
    match at {
        Some(at) => format!(
            "Your recovery code was replaced on {device} on {}.",
            day(at)
        ),
        None => format!("Your recovery code was replaced on {device}."),
    }
}

/// Settings › Connect without an account: the recovery of an account that has no device
/// left (connect-account-v1 section 9).
pub(crate) const RECOVER: &str = "Recover an Account…";
pub(crate) const RECOVER_TITLE: &str = "Recover an Account";
/// The start screen's Apassy Connect path without an account file: the way of a person
/// who has no other device of the account.
pub(crate) const START_NO_DEVICE: &str = concat!(
    "No other device? Make a vault on this ",
    crate::computer!(),
    ", then recover the account in Settings › Connect."
);
pub(crate) const RECOVER_LEAD: &str = "Use this only if no device of the account is left.";
/// What a recovery deletes, under the lead of its sheet.
pub(crate) const RECOVER_WHAT: &str =
    "The vault copies at Connect are deleted; the vaults on your devices stay.";
pub(crate) const RECOVER_CODE: &str = "Recovery Code";
pub(crate) const RECOVER_CODE_HINT: &str = "The 16 words";
pub(crate) const RECOVER_ID_WRONG: &str = "An account ID is acc_ and 10 letters and digits.";
pub(crate) const RECOVER_GO: &str = "Recover…";
/// Connect's one refusal of a recovery: a wrong code, an unknown account id, and an
/// account that still has a device get the same answer (section 9).
pub(crate) const RECOVER_REFUSED: &str = concat!(
    "Apassy Connect did not recover the account. Check the account ID and the code, or add this ",
    crate::computer!(),
    " from a device that still works."
);
/// A recovery that finished after a restart or a lock, before its new code was shown.
pub(crate) const RECOVERED_UNSEEN: &str =
    "The account is recovered, but its new recovery code was not shown. Make one now.";

/// The word at `position` of a typed recovery code is not a word of the list.
pub(crate) fn recover_word_wrong(position: usize, word: &str) -> String {
    format!("Word {position}, \u{201c}{word}\u{201d}, is not a word of a recovery code.")
}

/// A typed recovery code of `count` words of the list, not 16.
pub(crate) fn recover_count_wrong(count: usize) -> String {
    format!("A recovery code has 16 words. This one has {count}.")
}

/// Too many tries of a recovery (`429`): when to try again.
pub(crate) fn recover_wait(seconds: u64) -> String {
    let minutes = seconds.div_ceil(60).max(1);
    if minutes == 1 {
        "Too many recovery tries. Try again in a minute.".to_owned()
    } else {
        format!("Too many recovery tries. Try again in {minutes} minutes.")
    }
}

/// The line of Settings › Connect after a recovery: what it deleted at Connect, and that
/// each vault can sync through Connect again. `deleted` is `None` when the recovery was
/// settled without Connect's count.
pub(crate) fn recovered_line(deleted: Option<u64>) -> String {
    let again = "Sync again in Vault › Sync.";
    match deleted {
        Some(0) => "The account is recovered.".to_owned(),
        Some(1) => format!("Recovered. Connect deleted 1 vault copy. {again}"),
        Some(count) => format!("Recovered. Connect deleted {count} vault copies. {again}"),
        None => format!("Recovered. Connect deleted the vault copies. {again}"),
    }
}

pub(crate) const PICKER_TITLE: &str = "Choose a Plan";
pub(crate) const PICKER_NOTE: &str = "VAT included. Apassy never sees your card.";
pub(crate) const LOADING_PRICES: &str = "Loading prices…";
/// The picker when `GET /v1/plans` failed: the error shows under the sheet.
pub(crate) const PRICES_FAILED: &str = "The prices did not load.";
pub(crate) const TRY_AGAIN: &str = "Try Again";
pub(crate) const CONTINUE_BROWSER: &str = "Continue to Payment…";
pub(crate) const WAIT_TITLE: &str = "Finish in Your Browser";
pub(crate) const WAIT_LEAD: &str =
    "Pay in your browser. This sheet closes when the plan is active.";
pub(crate) const WAIT_LINE: &str = "Waiting for Connect…";
pub(crate) const OPEN_AGAIN: &str = "Open Page Again";
pub(crate) const WAIT_STOPPED: &str = "Stopped waiting. If you paid, the plan shows here soon.";
pub(crate) const CHECK_AGAIN: &str = "Check Again";

pub(crate) const ADD_TITLE: &str = "Add a Device";
pub(crate) const ADD_LEAD: &str = concat!(
    "Scan this code with the iPhone, or paste it on the other ",
    crate::computer!(),
    "."
);
pub(crate) const ADD_WAITING: &str = "Waiting for the other device…";
pub(crate) const WORDS_TAIL: &str = "Confirm only if the other device shows the same words.";
pub(crate) const REVOKE_LEAD: &str =
    "It leaves your Connect account and every vault copy at Connect. Its vaults stay on it.";
pub(crate) const FORGET_TITLE: &str = concat!("Forget This ", crate::computer_cap!(), "?");
pub(crate) const NOT_VERIFIED: &str = "Not verified";
/// The device list that Connect sent did not verify on this device: every device shows
/// "Not verified", and this says why.
pub(crate) const LIST_NOT_VERIFIED: &str =
    "Apassy could not verify the device list from Connect. Nothing was changed.";
/// The device list of the account is nearly full (connect-account-v1 section 13).
pub(crate) const LIST_NEARLY_FULL: &str =
    "The device list of this account is nearly full. Removing a device always works.";
pub(crate) const REMOVED: &str = "Removed from the account";
pub(crate) const REMOVED_NOTE: &str = concat!(
    "Apassy Connect removed this ",
    crate::computer!(),
    " from its account. Forget this ",
    crate::computer!(),
    " here."
);
pub(crate) const FORGET_THIS_MAC: &str = concat!("Forget This ", crate::computer_cap!(), "…");
/// The title of an account file of an earlier version of Apassy.
pub(crate) const OLD_FILE_TITLE: &str = "Join the account again";
/// The account file is from an earlier version of Apassy.
pub(crate) const OLD_FILE: &str = concat!(
    "This ",
    crate::computer!(),
    "'s account file is from an earlier Apassy. Forget this ",
    crate::computer!(),
    ", then add it again from another device."
);
pub(crate) const FORGET_REMOVED_LEAD: &str = concat!(
    "The Connect key and the account file of this ",
    crate::computer!(),
    " are deleted, and the vault copies of the account stop syncing on this ",
    crate::computer!(),
    ". To come back, add it from another device."
);
pub(crate) const FORGET_LEAD: &str = concat!(
    "This ",
    crate::computer!(),
    " leaves your Connect account, and its Connect key is deleted. To come back, add it from another device."
);
pub(crate) const JOIN_ACCOUNT_TITLE: &str =
    concat!("Add This ", crate::computer_cap!(), " to an Account");
pub(crate) const JOIN_ACCOUNT_LEAD: &str =
    "Paste the code of Add a Device… from another device of the account.";
pub(crate) const JOINED_TITLE: &str = concat!("This ", crate::computer_cap!(), " Is Added");

pub(crate) const INVITE_LEAD: &str = "Send this link to the person. It works once.";
pub(crate) const ADMIN_NOTE: &str = "Admins manage members; only you change the seats and billing.";
pub(crate) const CREATE_LINK: &str = "Create Link";
pub(crate) const SEATS_NOTE: &str = "Stripe charges or credits the difference for this period.";
pub(crate) const JOIN_GROUP_REFUSED: &str =
    "This account has a plan or another family or team. Cancel or leave it first.";
pub(crate) const DELETE_TITLE: &str = "Delete Your Connect Account?";
pub(crate) const DELETE_LEAD: &str = "The plan ends now, and every vault copy, device, and link of the account is deleted at Connect. Your vaults stay on your devices.";
pub(crate) const ACTIVE_FAMILY: &str = "Invite your family in Settings › Connect.";
pub(crate) const ACTIVE_TEAM: &str = "Invite your team in Settings › Connect.";
pub(crate) const MEMBERS_FIRST_TITLE: &str = "Remove the Members First";
pub(crate) const MEMBERS_FIRST_LEAD: &str = "Your family or team still has members.";

/// Every fixed text of the section, for the checks of plans section 5.
#[cfg(all(test, feature = "vault"))]
pub(crate) const TEXTS: &[&str] = &[
    NOT_ON_CONNECT,
    INTRO,
    SELF_HOST,
    CREATE,
    ADD_THIS_MAC,
    GROUP_LABEL,
    SIGNED_OUT,
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
    RECOVERY_UNRECORDED,
    NEW_CODE,
    RECOVERY_CHANGED_HELP[0],
    RECOVERY_CHANGED_HELP[1],
    ACCOUNT_ROW,
    MORE_ACCOUNT,
    COPY_ACCOUNT_ID,
    LEAVE_FAMILY,
    LEAVE_TEAM,
    JOIN_ROW,
    PENDING_MEMBER,
    ACCOUNT_ID,
    RECOVER,
    RECOVER_TITLE,
    START_NO_DEVICE,
    RECOVER_LEAD,
    RECOVER_WHAT,
    RECOVER_CODE,
    RECOVER_CODE_HINT,
    RECOVER_ID_WRONG,
    RECOVER_GO,
    RECOVER_REFUSED,
    RECOVERED_UNSEEN,
    SAVED_IT,
    PICKER_TITLE,
    PICKER_NOTE,
    LOADING_PRICES,
    PRICES_FAILED,
    TRY_AGAIN,
    CONTINUE_BROWSER,
    WAIT_TITLE,
    WAIT_LEAD,
    WAIT_LINE,
    OPEN_AGAIN,
    WAIT_STOPPED,
    CHECK_AGAIN,
    ADD_TITLE,
    ADD_LEAD,
    ADD_WAITING,
    WORDS_TAIL,
    REVOKE_LEAD,
    FORGET_TITLE,
    FORGET_LEAD,
    NOT_VERIFIED,
    LIST_NOT_VERIFIED,
    LIST_NEARLY_FULL,
    REMOVED,
    REMOVED_NOTE,
    FORGET_THIS_MAC,
    OLD_FILE_TITLE,
    OLD_FILE,
    FORGET_REMOVED_LEAD,
    JOIN_ACCOUNT_TITLE,
    JOIN_ACCOUNT_LEAD,
    JOINED_TITLE,
    INVITE_LEAD,
    ADMIN_NOTE,
    CREATE_LINK,
    SEATS_NOTE,
    JOIN_GROUP_REFUSED,
    DELETE_TITLE,
    DELETE_LEAD,
    ACTIVE_FAMILY,
    ACTIVE_TEAM,
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
    /// that is not verified shows "Not verified", has no "Revoke…", and is no device of
    /// the account for any step.
    pub(crate) verified: bool,
    /// The short fingerprint of the device's key, as the owner check names it.
    pub(crate) fingerprint: String,
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

/// The facts of a device in one line, "Mac · Added 22 Sep 2026 · Key c815 2d6e a093": the
/// hover text of its row and the note of its Revoke alert.
pub(crate) fn device_detail(device: &Device) -> String {
    if device.fingerprint.is_empty() {
        format!("{} · Added {}", device.kind(), day(device.created_at))
    } else {
        format!(
            "{} · Added {} · Key {}",
            device.kind(),
            day(device.created_at),
            device.fingerprint
        )
    }
}

/// The line of a member of a family or team on the Account group: who manages it, or
/// that the owner did not confirm this account yet.
pub(crate) fn managed_by(group_state: &str, owner_name: &str) -> (String, Tone) {
    if group_state == "pending" {
        (
            format!("Waiting for {owner_name} to confirm you"),
            Tone::Warning,
        )
    } else {
        (format!("Managed by {owner_name}"), Tone::Neutral)
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
    /// The device list that Connect sent verified on this Mac.
    pub(crate) list_verified: bool,
    /// The list has [`crate::connect::trust::ADDS_LEFT_WARNING`] or fewer versions left
    /// for a new device.
    pub(crate) list_nearly_full: bool,
    /// The recovery code of the account was never shown on this device (the account file
    /// keeps the mark until a new code is made and its sheet is closed).
    pub(crate) recovery_unseen: bool,
    /// Another device made a new recovery code since this device saw the key: the line,
    /// and the key that "OK" pins.
    pub(crate) recovery_changed: Option<RecoveryLine>,
    /// This device recovered the account in this session: the number of vault copies that
    /// Connect deleted, when it named it ([`recovered_line`]).
    pub(crate) recovered: Option<Option<u64>>,
}

/// The line of a new recovery code that another device made, and the recovery key that
/// "OK" pins (`ConnectAccount::recovery_change_seen`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryLine {
    pub(crate) text: String,
    pub(crate) recovery_key: String,
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
    /// The account file is from an earlier version of Apassy: this Mac must join its
    /// account again, after "Forget This Mac…" (an owner check).
    OldFile,
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
                Shown::OldFile => OLD_FILE_TITLE.to_owned(),
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

/// The lines of the sheet of a plan that became active (frame 5b): its date, and for a
/// family or a team where to invite the others, one per line.
pub(crate) fn active_lines(plan: Option<&str>, date: &str) -> String {
    let invite = match plan {
        Some("family") => Some(ACTIVE_FAMILY),
        Some("team") => Some(ACTIVE_TEAM),
        _ => None,
    };
    [Some(date), invite]
        .into_iter()
        .flatten()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The line under the Plan row of a plan that needs the owner, and its tone.
pub(crate) fn plan_note(plan: &Plan) -> Option<(String, Tone)> {
    match plan.status.as_str() {
        "past_due" => Some((
            plan.grace_until.map_or_else(
                || "Payment failed. Update the payment method.".to_owned(),
                |at| format!("Payment failed. Update the payment method by {}.", day(at)),
            ),
            Tone::Warning,
        )),
        "read_only" => Some((
            format!(
                "Nothing is uploaded{}.",
                plan.delete_at
                    .map(|at| format!("; copies at Connect are deleted on {}", day(at)))
                    .unwrap_or_default()
            ),
            Tone::Warning,
        )),
        "suspended" => Some((
            plan.delete_at.map_or_else(
                || "Choose a plan to use Connect again.".to_owned(),
                |at| {
                    format!(
                        "Choose a plan before {} to keep your copies at Connect.",
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
    /// "Recover an Account…" (section 9).
    Recover,
    SignIn,
    ChoosePlan,
    ManageBilling,
    AddDevice,
    /// Revoke… or Forget… of the device with this index.
    Revoke(usize),
    /// "Forget This Mac…" of a Mac that Connect removed from its account.
    ForgetRemoved,
    /// "Forget This Mac…" of an account file of an earlier version.
    ForgetOld,
    Invite,
    /// Confirm… of the member with this index.
    ConfirmMember(usize),
    /// Remove… of the member with this index.
    RemoveMember(usize),
    ChangeSeats,
    /// Leave… of a member's own group.
    Leave,
    JoinGroup,
    /// "New Recovery Code…" (section 9.1).
    NewRecoveryCode,
    /// "OK" of the line of a new recovery code that another device made.
    RecoveryChangeSeen,
    /// "Copy" of the account id.
    CopyAccountId,
    /// "OK" of the line after a recovery.
    RecoveredSeen,
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
                g.line(SIGNED_OUT, None, |ui| {
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
                        kit::spinner(ui, 12.0);
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
                // The error in red, as frame 2c shows it.
                let note = kit::text(note.as_str(), Font::Callout).color(Tone::Critical.text());
                g.line_note(UNREACHABLE, None, Some(note), |ui| {
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
        Shown::OldFile => {
            rows::group(ui, Some(GROUP_LABEL), |g| {
                g.line_note(OLD_FILE_TITLE, None, Some(rows::note(OLD_FILE)), |ui| {
                    if ui
                        .add_enabled_ui(!view.locked, |ui| {
                            kit::small_button(ui, FORGET_THIS_MAC, Style::Bordered)
                        })
                        .inner
                        .clicked()
                    {
                        action = Some(Action::ForgetOld);
                    }
                });
            });
        }
        Shown::Account(account) => account_section(ui, view, account, &mut action),
    });
    action
}

/// Frame 1: what Connect does, the line on self-hosting, and the three ways in. The
/// header says "Not on Connect"; the recovery is the borderless third button.
fn not_on_connect(ui: &mut Ui, action: &mut Option<Action>) {
    rows::group(ui, Some(GROUP_LABEL), |g| {
        g.row(|ui| {
            ui.add(Label::new(rows::label_text(INTRO)).wrap());
        });
        g.tone_icon_row(SELF_HOST, Tone::Accent);
    });
    ui.add_space(12.0);
    // The buttons wrap onto two lines in a narrow window.
    ui.horizontal_wrapped(|ui| {
        if kit::button(ui, CREATE, Style::Prominent).clicked() {
            *action = Some(Action::Create);
        }
        if kit::button(ui, ADD_THIS_MAC, Style::Bordered).clicked() {
            *action = Some(Action::AddThisMac);
        }
        if kit::button(ui, RECOVER, Style::Link).clicked() {
            *action = Some(Action::Recover);
        }
    });
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
        // The problem lines first (frames 14h, 13a, 13d), each with its one button.
        if let Some(deleted) = account.recovered {
            g.row(|ui| {
                let line =
                    kit::text(recovered_line(deleted), Font::Callout).color(kit::palette().label);
                if rows::text_buttons(ui, line, &[("OK", Style::Bordered)]).is_some() {
                    *action = Some(Action::RecoveredSeen);
                }
            });
        }
        // The button of a code that nobody saw is the one of the Recovery Code row below.
        if account.recovery_unseen {
            super::devices::problem_line(g, RECOVERY_UNSEEN, Tone::Warning, None, None);
        }
        if let Some(changed) = &account.recovery_changed {
            let button = (!view.locked).then_some(RECOVERY_CHANGED_OK);
            if super::devices::problem_line(
                g,
                changed.text.as_str(),
                Tone::Warning,
                button,
                Some((RECOVERY_ROW, &RECOVERY_CHANGED_HELP)),
            ) {
                *action = Some(Action::RecoveryChangeSeen);
            }
        }
        // The account, and the rare account actions in one menu (the account id, forgetting
        // this Mac, the deletion).
        let who = match &account.email {
            Some(email) => format!("{} · {email}", account.name),
            None => account.name.clone(),
        };
        g.line(ACCOUNT_ROW, Some(rows::value(who)), |ui| {
            account_menu(ui, view, account, action);
        });
        // The recovery code: one visible place for a new one.
        g.line(RECOVERY_ROW, None, |ui| {
            let enabled = !view.locked && account.list_verified;
            if ui
                .add_enabled_ui(enabled, |ui| {
                    named_button(ui, NEW_CODE, NEW_RECOVERY, Style::Bordered)
                })
                .inner
                .clicked()
            {
                *action = Some(Action::NewRecoveryCode);
            }
        });
        let (value, tone) = view.plan_value(plan);
        let color = match tone {
            Tone::Neutral => kit::palette().secondary,
            tone => tone.text(),
        };
        // One line: the label, the status, and the buttons at the trailing edge. The
        // status wraps rather than ends in "…" ("Connect Personal · Renews 10 Dec 2026"
        // stays whole at the width of Settings), and the buttons go under it only when the
        // row is too narrow.
        g.row(|ui| {
            let mut line = egui::text::LayoutJob::default();
            rows::label_text("Plan").append_to(
                &mut line,
                ui.style(),
                egui::FontSelection::Default,
                egui::Align::Center,
            );
            kit::text(format!("   {value}"), Font::Body)
                .color(color)
                .append_to(
                    &mut line,
                    ui.style(),
                    egui::FontSelection::Default,
                    egui::Align::Center,
                );
            let mut buttons: Vec<(&str, &str, Style)> = Vec::new();
            if billing {
                buttons.push((MANAGE_BILLING, MANAGE_BILLING, Style::Bordered));
            }
            if can_choose {
                buttons.push((CHOOSE_PLAN, CHOOSE_PLAN, Style::Prominent));
            }
            if let Some(index) = rows::text_buttons_named(ui, line, &buttons) {
                *action = Some(if buttons[index].0 == MANAGE_BILLING {
                    Action::ManageBilling
                } else {
                    Action::ChoosePlan
                });
            }
        });
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
        // A member's family or team: who manages it, and Leave… (frames 6h, 9e).
        if let Some(group) = group.filter(|group| !group.manages()) {
            let (line, tone) = managed_by(&group.state, &group.owner_name);
            let color = match tone {
                Tone::Neutral => kit::palette().secondary,
                tone => tone.text(),
            };
            let spoken = if group.kind == "team" {
                LEAVE_TEAM
            } else {
                LEAVE_FAMILY
            };
            g.line(
                group.label(),
                Some(kit::text(line, Font::Body).color(color)),
                |ui| {
                    if ui
                        .add_enabled_ui(!view.locked, |ui| {
                            named_button(ui, "Leave…", spoken, Style::Bordered)
                        })
                        .inner
                        .clicked()
                    {
                        *action = Some(Action::Leave);
                    }
                },
            );
        }
        if group.is_none() && !plan.entitled {
            g.line(JOIN_ROW, None, |ui| {
                if named_button(ui, "Join…", JOIN_GROUP, Style::Bordered).clicked() {
                    *action = Some(Action::JoinGroup);
                }
            });
        }
        if let Some((line, tone)) = plan_note(plan) {
            g.tone_icon_row(line, tone);
        }
    });
    if view.locked {
        rows::footnote(ui, LOCKED);
    }
    // A family or team comes before the devices (frame 9).
    if let Some(group) = group.filter(|group| group.manages()) {
        group_section(ui, view, account, group, action);
    }
    devices_group(ui, view, account, action);
}

/// One item of the ⋯ menu of the Account row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MenuItem {
    pub(crate) label: &'static str,
    /// A secondary text at the trailing edge of the item (the account id).
    pub(crate) secondary: Option<String>,
    pub(crate) enabled: bool,
    /// A destructive item, in red.
    pub(crate) red: bool,
    /// A separator goes above the item.
    pub(crate) separated: bool,
    pub(crate) action: Action,
}

/// The items of the ⋯ menu of the Account row, in order: Copy Account ID (with the id),
/// forgetting this Mac (only while the list holds it), and the deletion in red. Every
/// item that needs an owner check is off while the vault is locked, and every item is off
/// while a step runs: an open menu is its own area and does not follow the disabled
/// pane.
pub(crate) fn account_menu_items(view: &ConnectView, account: &Account) -> Vec<MenuItem> {
    let free = !view.busy;
    let checked = free && !view.locked;
    let item = |label, enabled, action| MenuItem {
        label,
        secondary: None,
        enabled,
        red: false,
        separated: false,
        action,
    };
    let mut items = vec![MenuItem {
        secondary: Some(account.account_id.clone()),
        ..item(COPY_ACCOUNT_ID, free, Action::CopyAccountId)
    }];
    if let Some(index) = account.devices.iter().position(|device| device.this) {
        items.push(item(FORGET_THIS_MAC, checked, Action::Revoke(index)));
    }
    items.push(MenuItem {
        red: true,
        separated: true,
        ..item(DELETE, checked, Action::Delete)
    });
    items
}

/// The ⋯ menu of the Account row: [`account_menu_items`].
fn account_menu(ui: &mut Ui, view: &ConnectView, account: &Account, action: &mut Option<Action>) {
    let more = kit::icon_button(ui, Icon::More, MORE_ACCOUNT, kit::Size::Small);
    egui::Popup::menu(&more).show(|ui| {
        ui.set_min_width(260.0);
        for item in account_menu_items(view, account) {
            if item.separated {
                ui.separator();
            }
            let color = if item.red {
                Tone::Critical.text()
            } else {
                kit::palette().label
            };
            let label = kit::text(item.label, Font::Body).color(color);
            let mut button = egui::Button::selectable(false, label);
            if let Some(secondary) = &item.secondary {
                button = button.shortcut_text(
                    kit::text(secondary.as_str(), Font::Mono).color(kit::palette().secondary),
                );
            }
            if ui.add_enabled(item.enabled, button).clicked() {
                *action = Some(item.action);
            }
        }
    });
}

/// A small button whose spoken name says more than its label ("Revoke…" that VoiceOver
/// reads as "Revoke MacBook Pro").
fn named_button(ui: &mut Ui, label: &str, spoken: &str, style: Style) -> egui::Response {
    let button = kit::small_button(ui, label, style);
    ui.ctx()
        .accesskit_node_builder(button.id, |node| node.set_label(spoken));
    button
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
/// right (the first is the rightmost). An empty subline draws the row on one line.
/// `detail` is the hover text of the title and its description for VoiceOver.
fn entity_row(
    g: &mut rows::Group<'_>,
    glyph: impl FnOnce(&mut Ui),
    title: &str,
    caps: &[(&str, Tone)],
    subline: &str,
    detail: Option<&str>,
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
                    let head = |ui: &mut Ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            let name = ui.add(Label::new(rows::label_text(title)).truncate());
                            if let Some(detail) = detail {
                                ui.ctx().accesskit_node_builder(name.id, |node| {
                                    node.set_description(detail);
                                });
                                name.on_hover_text(detail);
                            }
                            for (cap, tone) in caps {
                                kit::cap_toned(ui, cap, *tone);
                            }
                        });
                    };
                    if subline.is_empty() {
                        head(ui);
                    } else {
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            head(ui);
                            ui.add(Label::new(rows::note(subline)).truncate());
                        });
                    }
                },
                |ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    controls(ui);
                },
            );
    });
}

fn devices_group(ui: &mut Ui, view: &ConnectView, account: &Account, action: &mut Option<Action>) {
    // The title says no count: the list shows them.
    rows::group_label(ui, "Devices");
    if account.list_nearly_full && account.list_verified {
        rows::footnote(ui, LIST_NEARLY_FULL);
    }
    rows::group_box(ui, |g| {
        for (index, device) in account.devices.iter().enumerate() {
            let detail = device_detail(device);
            let key =
                (!device.fingerprint.is_empty()).then(|| format!("Key {}", device.fingerprint));
            let caps: &[(&str, Tone)] = if device.this {
                &[(THIS_DEVICE, Tone::Neutral)]
            } else if !device.verified {
                &[(NOT_VERIFIED, Tone::Warning)]
            } else {
                &[]
            };
            entity_row(
                g,
                |ui| device_glyph(ui, &device.platform),
                &device.name,
                caps,
                "",
                Some(detail.as_str()),
                |ui| {
                    // This Mac shows its own key, which the Revoke owner check of another
                    // device names; "Forget This Mac…" is in the menu of the Account row.
                    // A device that this Mac did not verify is no device of the account
                    // for it: it has nothing to revoke, and its key stands in for the time.
                    if device.this || !device.verified {
                        if let Some(key) = &key {
                            ui.label(rows::value(key.as_str()).size(12.0));
                        }
                        return;
                    }
                    let spoken = format!("Revoke {}", device.name);
                    let button = ui
                        .add_enabled_ui(!view.locked, |ui| {
                            named_button(ui, "Revoke…", &spoken, Style::Bordered)
                        })
                        .inner;
                    if button.clicked() {
                        *action = Some(Action::Revoke(index));
                    }
                    if let Some(at) = device.last_seen_at {
                        ui.label(
                            rows::value(super::devices::last_contact(at, view.now)).size(12.0),
                        );
                    }
                },
            );
        }
    });
    if !account.list_verified {
        // An error of the device list: one red line with its icon under the group that
        // failed (the rule of every view of the mockup).
        ui.add_space(6.0);
        kit::tone_note_icon(ui, LIST_NOT_VERIFIED, Tone::Critical, Font::Callout);
    }
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
/// The facts of a member in one line: its role and the day it joined, "Admin · Since 22
/// Sep 2026", "Member · Pending". The hover text of its row and its VoiceOver description.
pub(crate) fn member_detail(kind: &str, member: &Member) -> String {
    let role = role_cap(kind, &member.role).unwrap_or("Member");
    match (member.state == "pending", member.joined_at) {
        (true, _) => format!("{role} · {PENDING_MEMBER}"),
        (false, Some(at)) => format!("{role} · Since {}", day(at)),
        (false, None) => role.to_owned(),
    }
}

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
    // The People or Seats row says "3 of 4"; the title does not say it again.
    rows::group_label(ui, group.label());
    rows::group_box(ui, |g| {
        for (index, member) in group.members.iter().enumerate() {
            let pending = member.state == "pending";
            // The role stays beside "Pending" (an organizer confirms an admin knowingly),
            // and is in the hover text with the day the member joined.
            let role = role_cap(&group.kind, &member.role);
            let mut caps: Vec<(&str, Tone)> =
                role.map(|cap| (cap, Tone::Neutral)).into_iter().collect();
            if pending {
                caps.push((PENDING_MEMBER, Tone::Warning));
            }
            let detail = member_detail(&group.kind, member);
            let removable = member.role != "owner"
                && member.account_id != account.account_id
                && (group.role == "owner" || member.role == "member");
            entity_row(
                g,
                |ui| {
                    kit::avatar(ui, &member.name, 28.0);
                },
                &member.name,
                &caps,
                "",
                Some(detail.as_str()),
                |ui| {
                    ui.add_enabled_ui(!view.locked, |ui| {
                        let confirm = format!("Confirm {}", member.name);
                        if pending
                            && named_button(ui, "Confirm…", &confirm, Style::Prominent).clicked()
                        {
                            *action = Some(Action::ConfirmMember(index));
                        }
                        let remove = format!("Remove {}", member.name);
                        if removable
                            && named_button(ui, "Remove…", &remove, Style::Bordered).clicked()
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
    /// Frame 2b: the 16 words, once, under the account id. They are erased with the
    /// sheet. `unrecorded`: Connect took a new code, and the account file of this device
    /// could not record it.
    Recovery {
        account_id: String,
        words: zeroize::Zeroizing<String>,
        unrecorded: bool,
    },
    /// Frame 14a: the recovery of an account (section 9): its id, its recovery code, and
    /// the name of this device.
    Recover {
        account_id: String,
        code: zeroize::Zeroizing<String>,
        device_name: String,
    },
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
        /// The facts of the device ([`device_detail`]), so it can be told apart.
        detail: String,
    },
    /// "Forget This Mac…" after Connect removed this Mac: the confirmation.
    ForgetRemoved,
    /// Frame 8a.
    JoinAccount { code: zeroize::Zeroizing<String> },
    /// Frame 8b.
    /// `words` is empty for a device whose key is in the account already (the join finishes
    /// from the device list); `note` says that this device made a new key for the join.
    JoinWaiting {
        confirmer: String,
        words: String,
        note: Option<String>,
    },
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
    ui.add_space(6.0);
    kit::word_chips(ui, words);
    ui.add_space(6.0);
}

/// The centred head of a result: a check, the title, and its lines.
fn result_head(ui: &mut Ui, title: &str, lines: &[&str]) {
    ui.vertical_centered(|ui| {
        ui.add_space(6.0);
        // A green disc with a white check (frames 5b, 8c, 10b).
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
        ui.painter()
            .circle_filled(rect.center(), 15.0, Tone::Good.mark());
        kit::paint_icon(
            ui.painter(),
            rect.shrink(8.0),
            Icon::Check,
            kit::palette().on_accent,
        );
        ui.add_space(6.0);
        ui.label(kit::text(title, Font::Title3).color(kit::palette().label));
        ui.add_space(4.0);
        for line in lines {
            kit::paragraph(ui, *line, Font::Callout, kit::palette().label);
        }
    });
    ui.add_space(10.0);
}

/// A destructive alert: the red warning tile, the title, the lead, Cancel (the default)
/// and the bordered button with the red label (frames 7c, 7d, 9c, 11a).
fn destructive(
    ui: &mut Ui,
    title: &str,
    lead: &str,
    note: Option<&str>,
    button: &str,
) -> Option<SheetChoice> {
    let mut choice = None;
    kit::alert_head(ui, Tone::Critical, title, Some(lead));
    if let Some(note) = note {
        kit::note(ui, note);
        ui.add_space(8.0);
    }
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            if kit::button(ui, button, Style::DestructiveBordered).clicked() {
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
    kit::sheet_title(ui, PICKER_TITLE, None);
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
                        kit::spinner(ui, 12.0);
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
                // The price at the trailing edge of the row, right-aligned, as in frame 4;
                // a long description is cut before it.
                egui::Sides::new()
                    .shrink_left()
                    .wrap_mode(egui::TextWrapMode::Truncate)
                    .height(rows::LINE)
                    .show(
                        ui,
                        |ui| {
                            ui.spacing_mut().item_spacing.x = 10.0;
                            let (rect, _) =
                                ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
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
                                    Label::new(rows::note(&plan_line(
                                        offer,
                                        interval,
                                        &plans.currency,
                                    )))
                                    .truncate(),
                                );
                            });
                        },
                        |ui| {
                            let amount =
                                kit::text(money(&plans.currency, price.amount), Font::Body)
                                    .variation(b"wght", 600.0)
                                    .color(kit::palette().label);
                            let unit = rows::note(&unit);
                            let width = kit::galley(ui, amount.clone())
                                .size()
                                .x
                                .max(kit::galley(ui, unit.clone()).size().x);
                            ui.allocate_ui_with_layout(
                                Vec2::new(width, rows::LINE),
                                egui::Layout::top_down(egui::Align::Max),
                                |ui| {
                                    ui.spacing_mut().item_spacing.y = 1.0;
                                    ui.label(amount);
                                    ui.label(unit);
                                },
                            );
                        },
                    );
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
        g.row(|ui| {
            rows::one_line(
                ui,
                kit::text("Total", Font::Body)
                    .variation(b"wght", 600.0)
                    .color(kit::palette().label)
                    .into(),
                Some(
                    kit::text(total, Font::Body)
                        .variation(b"wght", 600.0)
                        .color(kit::palette().label),
                ),
                |_| {},
            );
        });
    });
    ui.add_space(6.0);
    kit::note(ui, PICKER_NOTE);
    ui.add_space(8.0);
    let can_go = !busy && offer.is_some_and(|offer| offer.total(interval, *count).is_some());
    kit::sheet_buttons(
        ui,
        |ui| {
            if busy {
                kit::spinner(ui, 14.0);
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

/// What the Copy button of a recovery code copies: the account id and the words, which
/// a recovery needs together. The recovery sheet reads both back from it.
pub(crate) fn recovery_copy(account_id: &str, words: &str) -> String {
    format!("{ACCOUNT_ID}: {account_id}\n{RECOVER_CODE}: {words}")
}

/// What the recovery sheet reads in a typed recovery code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Typed {
    Empty,
    Ready,
    /// The word at this place (from 1) is not a word of the list.
    Unknown(usize, String),
    /// Every word is of the list, and there are this many, not 16.
    Count(usize),
}

/// The vault build reads a typed code with the word list of `crate::connect`.
#[cfg(feature = "vault")]
fn typed_code(code: &str) -> Typed {
    use crate::connect::{TypedRecovery, read_recovery};
    match read_recovery(code) {
        TypedRecovery::Empty => Typed::Empty,
        TypedRecovery::Ready(_) => Typed::Ready,
        TypedRecovery::UnknownWord { position, word } => Typed::Unknown(position, word),
        TypedRecovery::Count(count) => Typed::Count(count),
    }
}

/// The demo build has no word list: it reads the synthetic words of its frames.
#[cfg(not(feature = "vault"))]
fn typed_code(code: &str) -> Typed {
    demo::typed_code(code)
}

/// Whether `text` is an account id (`acc_` and 10 characters of `a-z2-7`).
#[cfg(feature = "vault")]
fn account_id_ok(text: &str) -> bool {
    crate::connect::words::valid_account_id(text)
}

#[cfg(not(feature = "vault"))]
fn account_id_ok(text: &str) -> bool {
    text.strip_prefix("acc_").is_some_and(|rest| {
        rest.len() == 10
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    })
}

/// The account id in a pasted text (the Copy button of a recovery code).
#[cfg(feature = "vault")]
fn pasted_account_id(text: &str) -> Option<String> {
    crate::connect::find_account_id(text)
}

#[cfg(not(feature = "vault"))]
fn pasted_account_id(_text: &str) -> Option<String> {
    None
}

/// What the recovery sheet says of what the owner typed: the problem with the account id,
/// the problem with the words, and whether "Recover…" may run.
pub(crate) fn recover_check(
    account_id: &str,
    code: &str,
    device_name: &str,
) -> (Option<&'static str>, Option<String>, bool) {
    let id = account_id.trim().to_ascii_lowercase();
    let id_ok = account_id_ok(&id);
    let id_note = (!id.is_empty() && !id_ok).then_some(RECOVER_ID_WRONG);
    let (code_note, code_ok) = match typed_code(code) {
        Typed::Empty => (None, false),
        Typed::Ready => (None, true),
        Typed::Unknown(position, word) => (Some(recover_word_wrong(position, &word)), false),
        Typed::Count(count) => (Some(recover_count_wrong(count)), false),
    };
    (
        id_note,
        code_note,
        id_ok && code_ok && !device_name.trim().is_empty(),
    )
}

/// Frame 14a: the account id, the recovery code, and the name of this device. A pasted
/// text that holds an account id (the Copy button of a recovery code) fills the id too.
fn recover_sheet(
    ui: &mut Ui,
    account_id: &mut String,
    code: &mut zeroize::Zeroizing<String>,
    device_name: &mut String,
    busy: bool,
) -> Option<SheetChoice> {
    kit::sheet_title(ui, RECOVER_TITLE, Some(RECOVER_LEAD));
    kit::note(ui, RECOVER_WHAT);
    ui.add_space(8.0);
    let (id_note, code_note, ready) = recover_check(account_id, code, device_name);
    rows::group_box(ui, |g| {
        g.row(|ui| {
            ui.label(rows::label_text(ACCOUNT_ID));
            kit::mono_input(ui, account_id, "connect-recover-id", "acc_…");
            if let Some(note) = id_note {
                ui.add(
                    Label::new(kit::text(note, Font::Callout).color(Tone::Critical.text())).wrap(),
                );
            }
        });
        g.row(|ui| {
            ui.label(rows::label_text(RECOVER_CODE));
            let response = kit::text_area(ui, code, "connect-recover-code", RECOVER_CODE_HINT, 3);
            if response.changed()
                && account_id.trim().is_empty()
                && let Some(id) = pasted_account_id(code)
            {
                *account_id = id;
            }
            if let Some(note) = &code_note {
                ui.add(
                    Label::new(kit::text(note, Font::Callout).color(Tone::Critical.text())).wrap(),
                );
            }
        });
        g.field(THIS_DEVICE, |ui| {
            kit::text_input(
                ui,
                device_name,
                "connect-recover-device",
                crate::computer_cap!(),
            )
        });
    });
    ui.add_space(8.0);
    cancel_and(ui, RECOVER_GO, ready, busy)
}

fn cancel_and(ui: &mut Ui, label: &str, enabled: bool, busy: bool) -> Option<SheetChoice> {
    let mut choice = None;
    kit::sheet_buttons(
        ui,
        |ui| {
            if busy {
                kit::spinner(ui, 14.0);
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
        Sheet::Recovery {
            account_id,
            words,
            unrecorded,
        } => {
            let mut choice = None;
            kit::sheet_title(ui, RECOVERY_TITLE, Some(RECOVERY_LEAD));
            if *unrecorded {
                ui.label(kit::text(RECOVERY_UNRECORDED, Font::Callout).color(Tone::Warning.text()));
                ui.add_space(6.0);
            }
            rows::group_box(ui, |g| {
                g.labeled(
                    ACCOUNT_ID,
                    kit::text(account_id.as_str(), Font::Mono).color(kit::palette().label),
                );
            });
            ui.add_space(6.0);
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
            choice = pair(
                ui,
                |ui| {
                    kit::button(ui, "Copy", Style::Bordered)
                        .clicked()
                        .then(|| SheetChoice::Copy(recovery_copy(account_id, words)))
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
                    kit::spinner(ui, 14.0);
                    ui.label(rows::value(WAIT_LINE));
                });
            });
            ui.add_space(8.0);
            choice = pair(
                ui,
                |ui| {
                    kit::button(ui, OPEN_AGAIN, Style::Bordered)
                        .clicked()
                        .then_some(SheetChoice::OpenAgain)
                },
                // "Close", not "Cancel": closing the sheet does not cancel a payment that
                // the owner finishes in the browser. Escape still closes it.
                |ui| {
                    kit::alert_default_button(ui, "Close")
                        .clicked()
                        .then_some(SheetChoice::Cancel)
                },
            )
            .or(choice);
            choice
        }
        Sheet::Active { title, line } => done_sheet(ui, title, &line.lines().collect::<Vec<_>>()),
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
                    kit::spinner(ui, 12.0);
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
                Some(WORDS_TAIL),
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
                fingerprint: String::new(),
            }
            .kind();
            rows::group_box(ui, |g| g.labeled("Kind", rows::value(kind)));
            ui.add_space(8.0);
            ui.add_enabled_ui(!busy, |ui| {
                pair(
                    ui,
                    |ui| {
                        kit::button(ui, "Refuse", Style::DestructiveBordered)
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
        Sheet::DeviceAdded { name } => done_sheet(ui, &format!("{name} Added"), &[]),
        Sheet::ForgetRemoved => destructive(ui, FORGET_TITLE, FORGET_REMOVED_LEAD, None, "Forget"),
        Sheet::Revoke {
            name, this, detail, ..
        } => {
            if *this {
                destructive(ui, FORGET_TITLE, FORGET_LEAD, None, "Forget…")
            } else {
                destructive(
                    ui,
                    &format!("Revoke {name}?"),
                    REVOKE_LEAD,
                    Some(detail.as_str()),
                    "Revoke…",
                )
            }
        }
        Sheet::Recover {
            account_id,
            code,
            device_name,
        } => recover_sheet(ui, account_id, code, device_name, busy),
        Sheet::JoinAccount { code } => {
            kit::sheet_title(ui, JOIN_ACCOUNT_TITLE, Some(JOIN_ACCOUNT_LEAD));
            kit::mono_input(ui, code, "connect-join-code", "apassy_alk_…");
            ui.add_space(8.0);
            let ready = !code.trim().is_empty();
            cancel_and(ui, "Continue", ready, busy)
        }
        Sheet::JoinWaiting {
            confirmer,
            words,
            note,
        } => {
            let mut choice = None;
            if words.is_empty() {
                kit::sheet_title(
                    ui,
                    JOIN_FINISHING_TITLE,
                    Some(&format!(
                        concat!(
                            "{} confirmed this ",
                            crate::computer!(),
                            " earlier. Apassy finishes the join."
                        ),
                        confirmer
                    )),
                );
            } else {
                kit::sheet_title(
                    ui,
                    &format!("Waiting for {confirmer}…"),
                    Some(&format!(
                        "Confirm on {confirmer} only if it shows these words."
                    )),
                );
                big_words(ui, words);
            }
            if let Some(note) = note {
                kit::note(ui, note.as_str());
            }
            kit::sheet_buttons(
                ui,
                |ui| {
                    // Frame 8b: the spinner and what it waits for.
                    kit::spinner(ui, 14.0);
                    ui.label(rows::value("Waiting…"));
                },
                |ui| {
                    if kit::alert_cancel(ui).clicked() {
                        choice = Some(SheetChoice::Cancel);
                    }
                },
            );
            choice
        }
        Sheet::Joined => done_sheet(ui, JOINED_TITLE, &[]),
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
            // The lead belongs to the link: before it, the sheet has the role only (9b).
            kit::sheet_title(ui, title, link.is_some().then_some(INVITE_LEAD));
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
                    None,
                    "Leave…",
                )
            } else {
                destructive(
                    ui,
                    &format!("Remove {name}?"),
                    &format!(
                        "{name} leaves your {word} and its shared vaults. {name} keeps an Apassy Connect account without a plan."
                    ),
                    None,
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
                "{owner_name} confirms you, then their plan covers you."
            )],
        ),
        Sheet::Delete => destructive(ui, DELETE_TITLE, DELETE_LEAD, None, "Delete…"),
        Sheet::MembersFirst => {
            let mut choice = None;
            kit::alert_head(
                ui,
                Tone::Warning,
                MEMBERS_FIRST_TITLE,
                Some(MEMBERS_FIRST_LEAD),
            );
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
    /// Settings › Connect › Shared Vaults (connect-account-v1 section 16).
    #[cfg(feature = "vault")]
    pub(crate) share: share::ShareUi,
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
#[cfg(feature = "vault")]
pub(crate) mod share;

#[cfg(feature = "vault")]
impl State {
    /// The account id of the account file of this device, for the owner checks of
    /// Shared Vaults.
    pub(crate) fn share_account_id(&self) -> Option<String> {
        self.live.account_id()
    }
}

#[cfg(not(feature = "vault"))]
mod demo;
