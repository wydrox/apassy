//! The plan of this Mac: Free, Personal, Team, or Operator (build plan §2c, ADR 0027).
//!
//! The app asks a [`PlanProvider`] for the [`Entitlement`] of this Mac and for the
//! [`Offer`] of an upgrade. Until the account service exists, the app uses
//! [`NoPlanProvider`]: Free, no offer, no link. With no offer the app shows no paid tag,
//! no Plan section, and no upgrade, so a real build shows nothing about plans yet.
//!
//! [`FakePlanProvider`] is for the tests and the screenshot tour only; the app never
//! makes one.
//!
//! An entitlement works offline for 14 days after its last check
//! ([`OFFLINE_GRACE_SECONDS`]). After that the app treats the plan as unknown, so Free,
//! and says so ([`Entitlement::standing`]). A plan never adds a device, never signs in,
//! and never opens a vault.

use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// A paid plan works this long after its last check without a new one.
pub const OFFLINE_GRACE_SECONDS: u64 = 14 * 24 * 60 * 60;
/// The app checks the plan at least this often. A check older than this means that
/// the account service did not answer: the plan works offline.
pub const CHECK_EVERY_SECONDS: u64 = 24 * 60 * 60;

/// A plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Plan {
    /// iCloud Drive sync and approvals on every device.
    Free,
    /// Sync through Apassy and shared vaults, for one person.
    Personal,
    /// Personal with roles, members, and billing per seat.
    Team,
    /// A vault in a team that a relay operator made with a team code. It keeps sync
    /// through the relay as before (grandfathered).
    Operator,
}

impl Plan {
    /// The name of the plan, as the app shows it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Free => "Free",
            Self::Personal => "Personal",
            Self::Team => "Team",
            Self::Operator => "Operator",
        }
    }

    /// Whether the plan syncs through Apassy and has shared vaults.
    pub fn is_paid(self) -> bool {
        self != Self::Free
    }
}

/// The state of a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanStatus {
    Active,
    /// The last payment failed. The plan still works; the app shows "Update payment".
    PastDue,
    /// The period ended. Sync through Apassy moves to iCloud Drive or stops
    /// (`Sheet::PlanEnded`).
    Ended,
}

/// The plan of this Mac, as the account service told it at `checked_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entitlement {
    pub plan: Plan,
    /// The email of the account. `None` on Free: Free has no account.
    pub email: Option<String>,
    /// Unix time of the next renewal, or of the end when the plan does not renew.
    pub renews_at: Option<u64>,
    pub status: PlanStatus,
    /// Unix time of the last check with the account service.
    pub checked_at: u64,
}

impl Entitlement {
    /// Free, checked at `now`.
    pub fn free(now: u64) -> Self {
        Self {
            plan: Plan::Free,
            email: None,
            renews_at: None,
            status: PlanStatus::Active,
            checked_at: now,
        }
    }

    /// When the plan stops working without a new check.
    pub fn grace_ends_at(&self) -> u64 {
        self.checked_at.saturating_add(OFFLINE_GRACE_SECONDS)
    }

    /// What the app acts on at `now`. A paid plan works for 14 days after its last
    /// check; then its status is unknown and the app acts as Free, with a note.
    pub fn standing(&self, now: u64) -> Standing {
        if !self.plan.is_paid() {
            return Standing {
                plan: Plan::Free,
                status: Some(self.status),
                note: None,
            };
        }
        if now >= self.grace_ends_at() {
            return Standing {
                plan: Plan::Free,
                status: None,
                note: Some(PlanNote::Unchecked {
                    plan: self.plan,
                    checked_at: self.checked_at,
                }),
            };
        }
        let offline = now >= self.checked_at.saturating_add(CHECK_EVERY_SECONDS);
        Standing {
            plan: self.plan,
            status: Some(self.status),
            note: offline.then_some(PlanNote::Offline {
                checked_at: self.checked_at,
                until: self.grace_ends_at(),
            }),
        }
    }
}

/// The plan that the app acts on now ([`Entitlement::standing`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Standing {
    pub plan: Plan,
    /// `None`: the plan was not checked for 14 days, so its status is unknown.
    pub status: Option<PlanStatus>,
    pub note: Option<PlanNote>,
}

impl Standing {
    /// Whether the paid features work now: a paid plan that did not end.
    pub fn paid(&self) -> bool {
        self.plan.is_paid() && matches!(self.status, Some(PlanStatus::Active | PlanStatus::PastDue))
    }
}

/// A line that Settings > Plan shows under the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanNote {
    /// "Plan checked DATE. Works offline for 14 days." The service did not answer for a
    /// day; the plan works until `until`.
    Offline { checked_at: u64, until: u64 },
    /// The paid plan `plan` was not checked for 14 days: the app acts as Free until a
    /// check works.
    Unchecked { plan: Plan, checked_at: u64 },
}

/// Where the owner picked a paid feature: it sets the headline of the Upgrade sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpgradeFrom {
    /// Vault > Sync > "Apassy".
    Sync,
    /// "Share a vault…" in the Shared section of the sidebar.
    Shared,
    /// Settings > Plan.
    Plan,
}

/// The plan that an upgrade buys, with its prices as the app shows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub plan: Plan,
    /// For example "€X a month".
    pub monthly: String,
    /// For example "€X a year". `None` when there is no yearly price.
    pub yearly: Option<String>,
}

/// Why the account service did not answer as asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// No network, or the service did not answer.
    Unreachable,
    /// The service answered with something that is not a valid entitlement.
    Invalid,
    /// The cached entitlement could not be read or written in the data folder.
    Storage,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unreachable => "the plan could not be checked. Apassy tries again later",
            Self::Invalid => "the answer about the plan is not valid",
            Self::Storage => "the plan could not be saved on this Mac",
        })
    }
}

impl std::error::Error for PlanError {}

/// The source of the plan of this Mac. The UI calls [`Self::current`] and
/// [`Self::offer`] in each frame, so they read only memory; [`Self::refresh`] and
/// [`Self::sign_out`] may call the network and run off the UI thread.
pub trait PlanProvider: Send + Sync {
    /// The entitlement as last checked.
    fn current(&self) -> Entitlement;
    /// Ask the account service again, and keep the answer.
    fn refresh(&self) -> Result<Entitlement, PlanError>;
    /// The upgrade to offer at `from`. `None`: there is nothing to buy, and the app
    /// hides every paid tag, the Plan section, and the upgrade.
    fn offer(&self, from: UpgradeFrom) -> Option<Offer>;
    /// The web checkout for an upgrade from `from`, for the browser.
    fn checkout_url(&self, from: UpgradeFrom) -> Option<String>;
    /// The web portal of the subscription ("Manage subscription").
    fn portal_url(&self) -> Option<String>;
    /// Forget the account on this Mac: the plan becomes Free here.
    fn sign_out(&self) -> Result<(), PlanError>;
}

/// The provider of the app until the account service exists: Free, no offer, no link.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPlanProvider;

impl PlanProvider for NoPlanProvider {
    fn current(&self) -> Entitlement {
        Entitlement::free(unix_now())
    }

    fn refresh(&self) -> Result<Entitlement, PlanError> {
        Ok(self.current())
    }

    fn offer(&self, _from: UpgradeFrom) -> Option<Offer> {
        None
    }

    fn checkout_url(&self, _from: UpgradeFrom) -> Option<String> {
        None
    }

    fn portal_url(&self) -> Option<String> {
        None
    }

    fn sign_out(&self) -> Result<(), PlanError> {
        Ok(())
    }
}

/// A provider with a fixed plan and synthetic data, for the tests and the screenshot
/// tour. It offers Personal at "€X a month". The app never makes one.
#[derive(Debug)]
pub struct FakePlanProvider {
    entitlement: Mutex<Entitlement>,
}

/// The synthetic account email of [`FakePlanProvider`].
const FAKE_EMAIL: &str = "owner@example.test";
/// The synthetic account service of [`FakePlanProvider`].
const FAKE_SERVICE: &str = "https://accounts.example.test";

impl FakePlanProvider {
    /// The provider of the screenshot tour (`examples/screenshots.rs`): `free`,
    /// `personal`, `team`, `operator`, `ended` (Personal that ended), `past-due`
    /// (Personal whose last payment failed), or `offline` (Personal last checked two
    /// days before `now`), checked at `now`. `None` for another name.
    #[doc(hidden)]
    pub fn for_screenshots(name: &str, now: u64) -> Option<Self> {
        let paid = |plan, status| Entitlement {
            plan,
            email: Some(FAKE_EMAIL.to_owned()),
            renews_at: Some(now.saturating_add(30 * 24 * 60 * 60)),
            status,
            checked_at: now,
        };
        let entitlement = match name {
            "free" => Entitlement::free(now),
            "personal" => paid(Plan::Personal, PlanStatus::Active),
            "team" => paid(Plan::Team, PlanStatus::Active),
            "operator" => Entitlement {
                email: None,
                renews_at: None,
                ..paid(Plan::Operator, PlanStatus::Active)
            },
            "ended" => paid(Plan::Personal, PlanStatus::Ended),
            "past-due" => paid(Plan::Personal, PlanStatus::PastDue),
            "offline" => Entitlement {
                checked_at: now.saturating_sub(2 * 24 * 60 * 60),
                ..paid(Plan::Personal, PlanStatus::Active)
            },
            _ => return None,
        };
        Some(Self::with(entitlement))
    }

    /// A provider with `entitlement`, for the tests.
    #[cfg(test)]
    pub(crate) fn new(entitlement: Entitlement) -> Self {
        Self::with(entitlement)
    }

    /// The account service answers with `entitlement` from now on, as after a checkout
    /// or the end of a period, for the tests.
    #[cfg(test)]
    pub(crate) fn set(&self, entitlement: Entitlement) {
        *self.held() = entitlement;
    }

    fn with(entitlement: Entitlement) -> Self {
        Self {
            entitlement: Mutex::new(entitlement),
        }
    }

    fn held(&self) -> MutexGuard<'_, Entitlement> {
        self.entitlement
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl PlanProvider for FakePlanProvider {
    fn current(&self) -> Entitlement {
        self.held().clone()
    }

    fn refresh(&self) -> Result<Entitlement, PlanError> {
        Ok(self.current())
    }

    fn offer(&self, _from: UpgradeFrom) -> Option<Offer> {
        Some(Offer {
            plan: Plan::Personal,
            monthly: "€X a month".to_owned(),
            yearly: Some("€X a year".to_owned()),
        })
    }

    fn checkout_url(&self, from: UpgradeFrom) -> Option<String> {
        let from = match from {
            UpgradeFrom::Sync => "sync",
            UpgradeFrom::Shared => "shared",
            UpgradeFrom::Plan => "plan",
        };
        Some(format!("{FAKE_SERVICE}/checkout?from={from}"))
    }

    fn portal_url(&self) -> Option<String> {
        self.held()
            .plan
            .is_paid()
            .then(|| format!("{FAKE_SERVICE}/portal"))
    }

    fn sign_out(&self) -> Result<(), PlanError> {
        let mut held = self.held();
        *held = Entitlement::free(held.checked_at);
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;
    const DAY: u64 = 24 * 60 * 60;

    fn personal(checked_at: u64, status: PlanStatus) -> Entitlement {
        Entitlement {
            plan: Plan::Personal,
            email: Some(FAKE_EMAIL.to_owned()),
            renews_at: Some(NOW + 30 * DAY),
            status,
            checked_at,
        }
    }

    #[test]
    fn no_plan_provider_is_free_with_no_offer_and_no_link() {
        let provider = NoPlanProvider;
        let current = provider.current();
        assert_eq!(current.plan, Plan::Free);
        assert_eq!((current.email, current.renews_at), (None, None));
        assert_eq!(provider.refresh().unwrap().plan, Plan::Free);
        for from in [UpgradeFrom::Sync, UpgradeFrom::Shared, UpgradeFrom::Plan] {
            assert_eq!(provider.offer(from), None);
            assert_eq!(provider.checkout_url(from), None);
        }
        assert_eq!(provider.portal_url(), None);
        assert_eq!(provider.sign_out(), Ok(()));
        assert!(!provider.current().standing(unix_now()).paid());
    }

    #[test]
    fn a_paid_plan_works_offline_for_fourteen_days() {
        let entitlement = personal(NOW, PlanStatus::Active);
        let fresh = entitlement.standing(NOW + 60);
        assert_eq!(fresh.plan, Plan::Personal);
        assert_eq!(fresh.status, Some(PlanStatus::Active));
        assert_eq!(fresh.note, None);
        assert!(fresh.paid());

        let offline = entitlement.standing(NOW + 2 * DAY);
        assert!(offline.paid());
        assert_eq!(
            offline.note,
            Some(PlanNote::Offline {
                checked_at: NOW,
                until: NOW + 14 * DAY
            })
        );
        let last_second = entitlement.standing(NOW + 14 * DAY - 1);
        assert!(last_second.paid());

        // Then the status is unknown: the app acts as Free and says why.
        let unchecked = entitlement.standing(NOW + 14 * DAY);
        assert_eq!(unchecked.plan, Plan::Free);
        assert_eq!(unchecked.status, None);
        assert!(!unchecked.paid());
        assert_eq!(
            unchecked.note,
            Some(PlanNote::Unchecked {
                plan: Plan::Personal,
                checked_at: NOW
            })
        );
        assert_eq!(entitlement.grace_ends_at(), NOW + OFFLINE_GRACE_SECONDS);
        // A clock before the check is not offline.
        assert_eq!(entitlement.standing(NOW - DAY).note, None);
        // A check at the end of time does not overflow.
        assert!(
            personal(u64::MAX, PlanStatus::Active)
                .standing(u64::MAX - 1)
                .paid()
        );
    }

    #[test]
    fn free_needs_no_check_and_an_ended_plan_is_not_paid() {
        let free = Entitlement::free(NOW).standing(NOW + 100 * DAY);
        assert_eq!(free.plan, Plan::Free);
        assert_eq!(free.note, None);
        assert!(!free.paid());

        let ended = personal(NOW, PlanStatus::Ended).standing(NOW + 60);
        assert_eq!(ended.plan, Plan::Personal);
        assert_eq!(ended.status, Some(PlanStatus::Ended));
        assert!(!ended.paid());

        let past_due = personal(NOW, PlanStatus::PastDue).standing(NOW + 60);
        assert!(past_due.paid());
    }

    #[test]
    fn the_operator_plan_is_paid_and_has_no_account() {
        let fake = FakePlanProvider::for_screenshots("operator", NOW).unwrap();
        let current = fake.current();
        assert_eq!(current.plan, Plan::Operator);
        assert_eq!(current.email, None);
        assert!(current.standing(NOW).paid());
        assert!(Plan::Operator.is_paid());
        assert!(!Plan::Free.is_paid());
    }

    #[test]
    fn the_fake_provider_picks_its_plan_by_name() {
        for (name, plan, status) in [
            ("free", Plan::Free, PlanStatus::Active),
            ("personal", Plan::Personal, PlanStatus::Active),
            ("team", Plan::Team, PlanStatus::Active),
            ("ended", Plan::Personal, PlanStatus::Ended),
            ("past-due", Plan::Personal, PlanStatus::PastDue),
            ("offline", Plan::Personal, PlanStatus::Active),
        ] {
            let fake = FakePlanProvider::for_screenshots(name, NOW).unwrap();
            let current = fake.current();
            assert_eq!((current.plan, current.status), (plan, status), "{name}");
            let checked = if name == "offline" {
                NOW - 2 * DAY
            } else {
                NOW
            };
            assert_eq!(current.checked_at, checked, "{name}");
            assert!(fake.offer(UpgradeFrom::Sync).is_some());
            assert_eq!(fake.refresh().unwrap(), current);
        }
        // Offline: the plan works, with the note of its last check.
        let offline = FakePlanProvider::for_screenshots("offline", NOW).unwrap();
        let standing = offline.current().standing(NOW);
        assert!(standing.paid());
        assert!(matches!(standing.note, Some(PlanNote::Offline { .. })));
        assert!(FakePlanProvider::for_screenshots("gold", NOW).is_none());
        assert!(FakePlanProvider::for_screenshots("", NOW).is_none());
    }

    #[test]
    fn the_fake_provider_has_synthetic_links_and_signs_out_to_free() {
        let fake = FakePlanProvider::new(personal(NOW, PlanStatus::Active));
        let offer = fake.offer(UpgradeFrom::Shared).unwrap();
        assert_eq!(offer.plan, Plan::Personal);
        assert_eq!(offer.monthly, "€X a month");
        assert_eq!(
            fake.checkout_url(UpgradeFrom::Sync).as_deref(),
            Some("https://accounts.example.test/checkout?from=sync")
        );
        assert_eq!(
            fake.portal_url().as_deref(),
            Some("https://accounts.example.test/portal")
        );
        fake.sign_out().unwrap();
        let current = fake.current();
        assert_eq!(current.plan, Plan::Free);
        assert_eq!(current.email, None);
        assert_eq!(fake.portal_url(), None);
    }

    #[test]
    fn plan_names_and_errors_read_as_the_app_shows_them() {
        let labels: Vec<_> = [Plan::Free, Plan::Personal, Plan::Team, Plan::Operator]
            .into_iter()
            .map(Plan::label)
            .collect();
        assert_eq!(labels, ["Free", "Personal", "Team", "Operator"]);
        assert!(
            PlanError::Unreachable
                .to_string()
                .contains("could not be checked")
        );
    }
}
