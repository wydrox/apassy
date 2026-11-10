//! Connect billing: plans and prices, Checkout and the Customer Portal, the Stripe
//! webhook, the plan state of an account, and the seats of a group
//! (docs/contracts/connect-billing-v1.md; docs/SPEC.md section "Billing").
//!
//! Rules this module keeps:
//!
//! - **State only from verified webhooks.** The only functions that change a stored
//!   subscription, customer, or group are the webhook handler (`Billing::webhook`, after
//!   the signature) and the maintenance pass (`Billing::mark_stores_deleted`, which only
//!   records that the stores of an ended plan were deleted). Checkout, the portal, and a
//!   seats change call Stripe and change nothing here; Stripe's webhook then does.
//! - **Idempotent by event id**: an event id is stored in the same transaction as its
//!   effect, and a repeat answers `duplicate: true` without an effect. Stripe does not
//!   keep the order of events, so an older subscription or invoice event than the last
//!   applied one is ignored.
//! - **Logs** name event ids, event types, Stripe object ids, and account ids. Never an
//!   email, a key, a secret, or a body.
//!
//! The handlers are plain functions from parsed input to an answer struct, written
//! against the storage trait `BillingStore`. `MemoryBillingStore` implements it for the
//! tests; the relay implements it on the directory tables `stripe_customer`,
//! `stripe_subscription`, `stripe_event`, `group`, and `group_member`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{RelayError, RelayResult, codes};
use crate::secret::SecretString;
use crate::server::stripe::{
    self, Form, LogSink, MAX_WEBHOOK_BODY, SignatureError, StripeClient, StripePrice,
    is_stripe_id,
};
use crate::sync_head::hex;

const DAY: u64 = 86_400;
/// How long an event id is kept (contract section 7).
pub const EVENT_RETENTION: u64 = 30 * DAY;
/// The default site of the checkout and portal return pages (`APASSY_CONNECT_SITE_URL`).
pub const DEFAULT_SITE_URL: &str = "https://apassy.wyderka.cc";

// ---------------------------------------------------------------------------------------
// Plans.

/// A Connect plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    Personal,
    Family,
    Team,
}

impl Plan {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Family => "family",
            Self::Team => "team",
        }
    }

    /// The fixed part of the plan (contract sections 2 and 6).
    pub fn spec(self) -> &'static PlanSpec {
        match self {
            Self::Personal => &CATALOG[0],
            Self::Family => &CATALOG[1],
            Self::Team => &CATALOG[2],
        }
    }

    /// The kind of group the plan makes, if any.
    pub fn group_kind(self) -> Option<GroupKind> {
        match self {
            Self::Personal => None,
            Self::Family => Some(GroupKind::Family),
            Self::Team => Some(GroupKind::Team),
        }
    }
}

/// A billing interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Interval {
    Month,
    Year,
}

impl Interval {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Month => "month",
            Self::Year => "year",
        }
    }
}

/// What a plan counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unit {
    Account,
    Person,
    Member,
}

/// The fixed part of a plan: its name, its unit, the units its price includes, and the
/// most units (a limit of the contract, not of Stripe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSpec {
    pub plan: Plan,
    pub name: &'static str,
    pub unit: Unit,
    pub included: u32,
    pub max: u32,
}

/// The three plans, in the order of `GET /v1/plans`.
pub const CATALOG: [PlanSpec; 3] = [
    PlanSpec {
        plan: Plan::Personal,
        name: "Connect Personal",
        unit: Unit::Account,
        included: 1,
        max: 1,
    },
    PlanSpec {
        plan: Plan::Family,
        name: "Connect Family",
        unit: Unit::Person,
        included: 4,
        max: 10,
    },
    PlanSpec {
        plan: Plan::Team,
        name: "Connect Team",
        unit: Unit::Member,
        included: 1,
        max: 250,
    },
];

/// Every lookup key Connect resolves, in a fixed order.
pub const LOOKUP_KEYS: [&str; 6] = [
    "connect_personal_month",
    "connect_personal_year",
    "connect_family_month",
    "connect_family_year",
    "connect_team_month",
    "connect_team_year",
];

/// `connect_<plan>_<interval>`.
pub fn lookup_key(plan: Plan, interval: Interval) -> &'static str {
    match (plan, interval) {
        (Plan::Personal, Interval::Month) => LOOKUP_KEYS[0],
        (Plan::Personal, Interval::Year) => LOOKUP_KEYS[1],
        (Plan::Family, Interval::Month) => LOOKUP_KEYS[2],
        (Plan::Family, Interval::Year) => LOOKUP_KEYS[3],
        (Plan::Team, Interval::Month) => LOOKUP_KEYS[4],
        (Plan::Team, Interval::Year) => LOOKUP_KEYS[5],
    }
}

/// The plan and the interval of a lookup key of Connect.
pub fn parse_lookup_key(key: &str) -> Option<(Plan, Interval)> {
    let plans = [Plan::Personal, Plan::Family, Plan::Team];
    let intervals = [Interval::Month, Interval::Year];
    plans
        .iter()
        .flat_map(|plan| intervals.iter().map(move |interval| (*plan, *interval)))
        .find(|(plan, interval)| lookup_key(*plan, *interval) == key)
}

/// One price of a plan, as `GET /v1/plans` publishes it. Cents, VAT included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPrice {
    pub interval: Interval,
    pub lookup_key: String,
    pub amount: u64,
    /// The price of each unit after `included`; `null` when `max` equals `included`.
    pub extra: Option<u64>,
}

/// One plan of `GET /v1/plans`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanEntry {
    pub plan: Plan,
    pub name: String,
    pub unit: Unit,
    pub included: u32,
    pub max: u32,
    pub prices: Vec<PlanPrice>,
}

/// The answer of `GET /v1/plans`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlansView {
    pub currency: String,
    pub tax: String,
    pub plans: Vec<PlanEntry>,
}

/// A price that passed the checks of `resolve_prices`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrice {
    pub price_id: String,
    pub plan: Plan,
    pub interval: Interval,
    pub amount: u64,
    pub extra: Option<u64>,
}

/// The resolved prices, by lookup key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedPrices(pub BTreeMap<&'static str, ResolvedPrice>);

impl ResolvedPrices {
    pub fn get(&self, plan: Plan, interval: Interval) -> Option<&ResolvedPrice> {
        self.0.get(lookup_key(plan, interval))
    }
}

/// Checks the Stripe prices of the lookup keys against the form of contract section 2
/// and keeps the ones that pass: currency `eur`, `tax_behavior=inclusive`, recurring at
/// the interval of the key; Personal and Team `per_unit`; Family `tiered` and `graduated`
/// with tier 1 `up_to=4` (a flat amount, no unit amount) and tier 2 `up_to=inf`. A price
/// that fails is logged and left out, so its plan or interval is not offered.
pub fn resolve_prices(raw: &HashMap<String, StripePrice>, log: &LogSink) -> ResolvedPrices {
    let mut out = BTreeMap::new();
    for key in LOOKUP_KEYS {
        let Some(price) = raw.get(key) else {
            log(&format!("price {key}: no active price with this lookup key"));
            continue;
        };
        let Some((plan, interval)) = parse_lookup_key(key) else {
            continue;
        };
        match check_price(price, plan, interval) {
            Ok((amount, extra)) => {
                out.insert(
                    key,
                    ResolvedPrice {
                        price_id: price.id.clone(),
                        plan,
                        interval,
                        amount,
                        extra,
                    },
                );
            }
            Err(why) => log(&format!("price {key} ({}): left out: {why}", price.id)),
        }
    }
    ResolvedPrices(out)
}

fn check_price(
    price: &StripePrice,
    plan: Plan,
    interval: Interval,
) -> Result<(u64, Option<u64>), &'static str> {
    if price.currency != "eur" {
        return Err("the currency is not eur");
    }
    if price.tax_behavior.as_deref() != Some("inclusive") {
        return Err("tax_behavior is not inclusive");
    }
    match &price.recurring {
        Some(recurring) if recurring.interval == interval.as_str() && recurring.interval_count == 1 => {}
        _ => return Err("the recurring interval does not match the lookup key"),
    }
    let spec = plan.spec();
    match plan {
        Plan::Personal | Plan::Team => {
            if price.billing_scheme.as_deref().unwrap_or("per_unit") != "per_unit" {
                return Err("the billing scheme is not per_unit");
            }
            let amount = price.unit_amount.filter(|a| *a > 0).ok_or("no unit amount")?;
            let extra = (spec.max > spec.included).then_some(amount);
            Ok((amount, extra))
        }
        Plan::Family => {
            if price.billing_scheme.as_deref() != Some("tiered")
                || price.tiers_mode.as_deref() != Some("graduated")
            {
                return Err("the price is not tiered and graduated");
            }
            let tiers = price.tiers.as_deref().unwrap_or_default();
            let [first, second] = tiers else {
                return Err("the price does not have exactly two tiers");
            };
            if first.up_to != Some(u64::from(spec.included)) || second.up_to.is_some() {
                return Err("the tiers are not up_to=4 and up_to=inf");
            }
            if first.unit_amount.unwrap_or(0) != 0 || second.flat_amount.unwrap_or(0) != 0 {
                return Err("tier 1 has a unit amount or tier 2 a flat amount");
            }
            let amount = first.flat_amount.filter(|a| *a > 0).ok_or("tier 1 has no flat amount")?;
            let extra = second.unit_amount.ok_or("tier 2 has no unit amount")?;
            Ok((amount, Some(extra)))
        }
    }
}

/// The `PlansView` of the resolved prices. A plan without any resolved price is left out.
pub fn plans_view(prices: &ResolvedPrices) -> PlansView {
    let mut plans = Vec::new();
    for spec in &CATALOG {
        let mut entry = PlanEntry {
            plan: spec.plan,
            name: spec.name.to_owned(),
            unit: spec.unit,
            included: spec.included,
            max: spec.max,
            prices: Vec::new(),
        };
        for interval in [Interval::Month, Interval::Year] {
            if let Some(price) = prices.get(spec.plan, interval) {
                entry.prices.push(PlanPrice {
                    interval,
                    lookup_key: lookup_key(spec.plan, interval).to_owned(),
                    amount: price.amount,
                    extra: price.extra,
                });
            }
        }
        if !entry.prices.is_empty() {
            plans.push(entry);
        }
    }
    PlansView {
        currency: "eur".into(),
        tax: "inclusive".into(),
        plans,
    }
}

/// The `409 seat_limit` error.
pub fn seat_limit(message: impl Into<String>) -> RelayError {
    RelayError::new(codes::SEAT_LIMIT, message)
}

/// Checks a count of units against the plan: `1 ≤ n ≤ max`.
pub fn check_count(plan: Plan, count: u32) -> RelayResult<()> {
    let spec = plan.spec();
    if count == 0 || count > spec.max {
        return Err(seat_limit(match plan {
            Plan::Personal => "Connect Personal is for one account.".to_owned(),
            Plan::Family => format!("A family has 1 to {} people.", spec.max),
            Plan::Team => format!("A team has 1 to {} members.", spec.max),
        }));
    }
    Ok(())
}

/// The total in cents for `count` units (contract section 2):
/// `amount + max(0, count − included) × extra`, for `1 ≤ count ≤ max`.
pub fn total_cents(plan: Plan, amount: u64, extra: Option<u64>, count: u32) -> RelayResult<u64> {
    check_count(plan, count)?;
    let spec = plan.spec();
    let further = u64::from(count.saturating_sub(spec.included));
    Ok(amount.saturating_add(further.saturating_mul(extra.unwrap_or(0))))
}

// ---------------------------------------------------------------------------------------
// Configuration.

/// The durations of the plan state (contract section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Durations {
    /// `APASSY_CONNECT_GRACE_DAYS`: entitled after the first failed payment.
    pub grace_days: u64,
    /// `APASSY_CONNECT_READ_ONLY_DAYS`: pulls and downloads after the end.
    pub read_only_days: u64,
    /// `APASSY_CONNECT_DELETE_DAYS`: the stores are deleted this long after the end.
    pub delete_days: u64,
}

impl Default for Durations {
    fn default() -> Self {
        Self {
            grace_days: 14,
            read_only_days: 30,
            delete_days: 90,
        }
    }
}

/// The billing settings of Connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingConfig {
    /// `APASSY_CONNECT_SITE_URL`: the origin of the done, cancel, and join pages.
    pub site_url: String,
    /// `APASSY_CONNECT_FAMILY_EXTRA_CENTS`: tier 2 of `connect_family_month`.
    pub family_extra_cents: u64,
    /// `APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS`: tier 2 of `connect_family_year`.
    pub family_extra_year_cents: u64,
    pub durations: Durations,
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            site_url: DEFAULT_SITE_URL.to_owned(),
            family_extra_cents: 100,
            family_extra_year_cents: 1000,
            durations: Durations::default(),
        }
    }
}

impl BillingConfig {
    /// Reads the settings with `lookup` (the environment in the relay):
    /// `APASSY_CONNECT_SITE_URL`, `APASSY_CONNECT_FAMILY_EXTRA_CENTS` (default 100),
    /// `APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS` (default 1000),
    /// `APASSY_CONNECT_GRACE_DAYS` (14, 1 to 60), `APASSY_CONNECT_READ_ONLY_DAYS` (30, 1 to
    /// 365), `APASSY_CONNECT_DELETE_DAYS` (90, above the read-only days, at most 730).
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> RelayResult<Self> {
        let defaults = Self::default();
        let site_url = lookup("APASSY_CONNECT_SITE_URL")
            .map(|url| url.trim_end_matches('/').to_owned())
            .unwrap_or(defaults.site_url);
        if !site_url.starts_with("https://")
            || site_url.len() > 200
            || site_url[8..].contains(['/', '?', '#', '@', ' ', '\\'])
        {
            return Err(RelayError::invalid(
                "APASSY_CONNECT_SITE_URL must be an https:// origin without a path.",
            ));
        }
        let number = |name: &str, default: u64, min: u64, max: u64| -> RelayResult<u64> {
            let Some(text) = lookup(name) else {
                return Ok(default);
            };
            let value: u64 = text
                .trim()
                .parse()
                .map_err(|_| RelayError::invalid(format!("{name} is not a number.")))?;
            if !(min..=max).contains(&value) {
                return Err(RelayError::invalid(format!("{name} must be {min} to {max}.")));
            }
            Ok(value)
        };
        let family_extra_cents = number("APASSY_CONNECT_FAMILY_EXTRA_CENTS", 100, 0, 100_000)?;
        let family_extra_year_cents =
            number("APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS", 1000, 0, 1_000_000)?;
        let grace_days = number("APASSY_CONNECT_GRACE_DAYS", 14, 1, 60)?;
        let read_only_days = number("APASSY_CONNECT_READ_ONLY_DAYS", 30, 1, 365)?;
        let delete_days = number("APASSY_CONNECT_DELETE_DAYS", 90, read_only_days + 1, 730)?;
        Ok(Self {
            site_url,
            family_extra_cents,
            family_extra_year_cents,
            durations: Durations {
                grace_days,
                read_only_days,
                delete_days,
            },
        })
    }

    fn family_extra(&self, interval: Interval) -> u64 {
        match interval {
            Interval::Month => self.family_extra_cents,
            Interval::Year => self.family_extra_year_cents,
        }
    }
}

// ---------------------------------------------------------------------------------------
// The plan state.

/// The status of a Stripe subscription. A status Stripe adds later is `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeStatus {
    Incomplete,
    IncompleteExpired,
    Trialing,
    Active,
    PastDue,
    Canceled,
    Unpaid,
    Paused,
    #[serde(other)]
    Other,
}

impl StripeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete",
            Self::IncompleteExpired => "incomplete_expired",
            Self::Trialing => "trialing",
            Self::Active => "active",
            Self::PastDue => "past_due",
            Self::Canceled => "canceled",
            Self::Unpaid => "unpaid",
            Self::Paused => "paused",
            Self::Other => "other",
        }
    }

    pub fn parse(text: &str) -> Self {
        serde_json::from_value(Value::String(text.to_owned())).unwrap_or(Self::Other)
    }

    /// The statuses whose plan has ended (read-only, then suspended, then deleted).
    pub fn has_ended(self) -> bool {
        matches!(
            self,
            Self::Canceled | Self::Unpaid | Self::IncompleteExpired | Self::Paused
        )
    }
}

/// The `status` of a `PlanView`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    None,
    Pending,
    Active,
    Trialing,
    PastDue,
    ReadOnly,
    Suspended,
}

/// The inputs of the plan state (contract section 8; `plan-states.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct PlanInput {
    pub stripe_status: Option<StripeStatus>,
    pub cancel_at_period_end: bool,
    pub period_end: Option<u64>,
    pub first_failed_at: Option<u64>,
    /// The end of the plan: Stripe's `ended_at`, or the time Connect saw it end.
    pub ended_at: Option<u64>,
    pub now: u64,
}

/// What a plan state allows (contract section 8, the permission columns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    NewStore,
    Push,
    Dial,
    EntitlementToken,
    Pull,
    Download,
}

/// The plan state at one time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanState {
    pub status: PlanStatus,
    pub entitled: bool,
    pub renews_at: Option<u64>,
    pub ends_at: Option<u64>,
    pub grace_until: Option<u64>,
    pub read_only_until: Option<u64>,
    pub delete_at: Option<u64>,
}

impl PlanState {
    const NONE: Self = Self {
        status: PlanStatus::None,
        entitled: false,
        renews_at: None,
        ends_at: None,
        grace_until: None,
        read_only_until: None,
        delete_at: None,
    };

    /// New store, push, dial, entitlement token: entitled only. Pull and download: also
    /// read-only.
    pub fn allows(&self, capability: Capability) -> bool {
        match capability {
            Capability::NewStore | Capability::Push | Capability::Dial | Capability::EntitlementToken => {
                self.entitled
            }
            Capability::Pull | Capability::Download => {
                self.entitled || self.status == PlanStatus::ReadOnly
            }
        }
    }

    /// `allows`, or `403 plan_required`.
    pub fn require(&self, capability: Capability) -> RelayResult<()> {
        if self.allows(capability) {
            Ok(())
        } else {
            Err(RelayError::new(
                codes::PLAN_REQUIRED,
                "This account is not on Apassy Connect.",
            ))
        }
    }
}

/// The plan state of contract section 8, a pure function of the stored subscription and
/// the time. `end` is `ended_at` for an ended status, or `grace_until` for a `past_due`
/// beyond its grace.
pub fn plan_state(input: &PlanInput, durations: &Durations) -> PlanState {
    let Some(status) = input.stripe_status else {
        return PlanState::NONE;
    };
    let grace = durations.grace_days * DAY;
    let read_only = durations.read_only_days * DAY;
    let delete = durations.delete_days * DAY;
    let ended = |end: Option<u64>, grace_until: Option<u64>| -> PlanState {
        let Some(end) = end else {
            // An end that was never seen: read-only without times, never deleted.
            return PlanState {
                status: PlanStatus::ReadOnly,
                grace_until,
                ..PlanState::NONE
            };
        };
        let read_only_until = end.saturating_add(read_only);
        let delete_at = end.saturating_add(delete);
        if input.now < read_only_until {
            PlanState {
                status: PlanStatus::ReadOnly,
                grace_until,
                read_only_until: Some(read_only_until),
                delete_at: Some(delete_at),
                ..PlanState::NONE
            }
        } else if input.now < delete_at {
            PlanState {
                status: PlanStatus::Suspended,
                grace_until,
                delete_at: Some(delete_at),
                ..PlanState::NONE
            }
        } else {
            PlanState::NONE
        }
    };
    match status {
        StripeStatus::Active | StripeStatus::Trialing => {
            let (renews_at, ends_at) = if input.cancel_at_period_end {
                (None, input.period_end)
            } else {
                (input.period_end, None)
            };
            PlanState {
                status: if status == StripeStatus::Active {
                    PlanStatus::Active
                } else {
                    PlanStatus::Trialing
                },
                entitled: true,
                renews_at,
                ends_at,
                ..PlanState::NONE
            }
        }
        StripeStatus::PastDue => {
            // The webhook sets the first failure; without one the grace counts from the
            // end of the unpaid period, and without that it is over.
            let start = input.first_failed_at.or(input.period_end).unwrap_or(0);
            let grace_until = start.saturating_add(grace);
            if input.now < grace_until {
                PlanState {
                    status: PlanStatus::PastDue,
                    entitled: true,
                    grace_until: Some(grace_until),
                    ..PlanState::NONE
                }
            } else {
                ended(Some(grace_until), Some(grace_until))
            }
        }
        status if status.has_ended() => ended(input.ended_at.or(input.period_end), None),
        // `incomplete`, and a status Stripe adds later.
        _ => PlanState {
            status: PlanStatus::Pending,
            ..PlanState::NONE
        },
    }
}

/// The answer of `GET /v1/account/plan`, and `plan` of `GET /v1/account`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanView {
    pub plan: Option<Plan>,
    pub status: PlanStatus,
    pub entitled: bool,
    pub interval: Option<Interval>,
    pub quantity: Option<u32>,
    pub renews_at: Option<u64>,
    pub ends_at: Option<u64>,
    pub grace_until: Option<u64>,
    pub read_only_until: Option<u64>,
    pub delete_at: Option<u64>,
    pub group_id: Option<String>,
}

impl PlanView {
    /// `status: none`.
    pub fn none() -> Self {
        Self::from_state(&PlanState::NONE, None, None)
    }

    fn from_state(state: &PlanState, row: Option<&SubscriptionRow>, group_id: Option<&str>) -> Self {
        let row = row.filter(|_| state.status != PlanStatus::None);
        Self {
            plan: row.and_then(|row| row.plan),
            status: state.status,
            entitled: state.entitled,
            interval: row.and_then(|row| row.interval),
            quantity: row.map(|row| row.quantity),
            renews_at: state.renews_at,
            ends_at: state.ends_at,
            grace_until: state.grace_until,
            read_only_until: state.read_only_until,
            delete_at: state.delete_at,
            group_id: row.and(group_id.map(str::to_owned)),
        }
    }

    /// The plan state of this view (for `allows` and `require`).
    pub fn state(&self) -> PlanState {
        PlanState {
            status: self.status,
            entitled: self.entitled,
            renews_at: self.renews_at,
            ends_at: self.ends_at,
            grace_until: self.grace_until,
            read_only_until: self.read_only_until,
            delete_at: self.delete_at,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Storage.

/// `stripe_customer`: the Stripe customer of an account and the email copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerRow {
    pub account: String,
    pub customer: String,
    /// The email Stripe collected, for the Devices list and support. Never logged.
    pub email: Option<String>,
}

/// `stripe_subscription` (contract section 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRow {
    pub id: String,
    pub customer: String,
    /// The buying account (a group's owner).
    pub account: String,
    pub group_id: Option<String>,
    pub item: Option<String>,
    pub lookup_key: Option<String>,
    pub plan: Option<Plan>,
    pub interval: Option<Interval>,
    pub quantity: u32,
    pub status: StripeStatus,
    pub period_end: Option<u64>,
    pub cancel_at_period_end: bool,
    pub first_failed_at: Option<u64>,
    pub ended_at: Option<u64>,
    /// `created` of the last applied `customer.subscription.*` event.
    pub last_event_created: u64,
    /// `created` of the last applied `invoice.*` event.
    pub last_invoice_created: u64,
    /// When the maintenance pass deleted the stores of this ended plan.
    pub stores_deleted_at: Option<u64>,
}

impl SubscriptionRow {
    /// The row that `checkout.session.completed` makes before the subscription's own
    /// event arrives: `incomplete`, no price.
    pub fn bound(id: &str, customer: &str, account: &str) -> Self {
        Self {
            id: id.to_owned(),
            customer: customer.to_owned(),
            account: account.to_owned(),
            group_id: None,
            item: None,
            lookup_key: None,
            plan: None,
            interval: None,
            quantity: 1,
            status: StripeStatus::Incomplete,
            period_end: None,
            cancel_at_period_end: false,
            first_failed_at: None,
            ended_at: None,
            last_event_created: 0,
            last_invoice_created: 0,
            stores_deleted_at: None,
        }
    }

    pub fn state(&self, now: u64, durations: &Durations) -> PlanState {
        plan_state(
            &PlanInput {
                stripe_status: Some(self.status),
                cancel_at_period_end: self.cancel_at_period_end,
                period_end: self.period_end,
                first_failed_at: self.first_failed_at,
                ended_at: self.ended_at,
                now,
            },
            durations,
        )
    }
}

/// The kind of a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupKind {
    Family,
    Team,
}

/// The role of an account in its group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupRole {
    Owner,
    Admin,
    Member,
}

/// The state of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberState {
    Pending,
    Active,
}

/// The group of an account (`group_member`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub group_id: String,
    pub kind: GroupKind,
    pub role: GroupRole,
    pub state: MemberState,
}

/// A group (`group`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    pub group_id: String,
    pub kind: GroupKind,
    pub owner_account: String,
}

/// One transaction on the billing tables. Every method reads or writes inside it.
pub trait BillingTx {
    /// True for an account that exists (`account`).
    fn account_exists(&mut self, account: &str) -> RelayResult<bool>;
    fn customer_of_account(&mut self, account: &str) -> RelayResult<Option<CustomerRow>>;
    fn customer(&mut self, customer: &str) -> RelayResult<Option<CustomerRow>>;
    /// Inserts or replaces the row of `row.customer`.
    fn put_customer(&mut self, row: &CustomerRow) -> RelayResult<()>;
    fn subscription(&mut self, id: &str) -> RelayResult<Option<SubscriptionRow>>;
    /// The subscriptions bought by this account.
    fn subscriptions_of_account(&mut self, account: &str) -> RelayResult<Vec<SubscriptionRow>>;
    /// Inserts or replaces the row of `row.id`.
    fn put_subscription(&mut self, row: &SubscriptionRow) -> RelayResult<()>;
    /// The subscriptions whose status is `past_due` or ended, for the maintenance pass.
    fn lapsed_subscriptions(&mut self) -> RelayResult<Vec<SubscriptionRow>>;
    /// Stores an event id. False when it was stored before: the event is a repeat.
    fn record_event(&mut self, id: &str, kind: &str, at: u64) -> RelayResult<bool>;
    /// Deletes event ids stored before `before`; answers how many.
    fn prune_events(&mut self, before: u64) -> RelayResult<u64>;
    /// The group of an account, pending or active.
    fn membership(&mut self, account: &str) -> RelayResult<Option<Membership>>;
    fn group(&mut self, group_id: &str) -> RelayResult<Option<GroupRow>>;
    /// Makes a group with `owner` as its active `owner` member; answers its id.
    fn create_group(&mut self, kind: GroupKind, owner: &str, now: u64) -> RelayResult<String>;
    /// The active members of a group, the owner included.
    fn active_members(&mut self, group_id: &str) -> RelayResult<u32>;
}

/// The storage of billing. `transaction` keeps every change of `f` only when it
/// answers `Ok`.
pub trait BillingStore {
    fn transaction<T>(
        &self,
        f: impl FnOnce(&mut dyn BillingTx) -> RelayResult<T>,
    ) -> RelayResult<T>;
}

/// A new group id: `grp_` and 10 characters of `a-z2-7`.
pub fn new_group_id() -> RelayResult<String> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; 10];
    getrandom::fill(&mut bytes).map_err(|_| RelayError::internal("No randomness."))?;
    let tail: String = bytes
        .iter()
        .map(|b| char::from(ALPHABET[usize::from(b & 31)]))
        .collect();
    Ok(format!("grp_{tail}"))
}

/// True for an account id of connect-account-v1: `acc_` and 10 characters of `a-z2-7`.
pub fn is_account_id(text: &str) -> bool {
    text.len() == 14
        && text.starts_with("acc_")
        && text[4..]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

// ---------------------------------------------------------------------------------------
// The in-memory store of the tests.

#[derive(Debug, Clone, Default)]
struct MemoryState {
    accounts: BTreeSet<String>,
    customers: BTreeMap<String, CustomerRow>,
    subscriptions: BTreeMap<String, SubscriptionRow>,
    events: BTreeMap<String, (String, u64)>,
    groups: BTreeMap<String, GroupRow>,
    members: BTreeMap<String, Membership>,
}

/// `BillingStore` in memory. A transaction works on a copy and replaces the state only
/// when it answers `Ok`, so a failed one changes nothing, as in SQLite.
#[derive(Debug, Default)]
pub struct MemoryBillingStore {
    state: Mutex<MemoryState>,
}

impl MemoryBillingStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_account(&self, account: &str) {
        self.lock().accounts.insert(account.to_owned());
    }

    /// Adds an account to a group (C3 does this through invites and confirmations).
    pub fn add_member(&self, group_id: &str, account: &str, role: GroupRole, state: MemberState) {
        let mut guard = self.lock();
        let kind = guard.groups.get(group_id).map_or(GroupKind::Family, |g| g.kind);
        guard.accounts.insert(account.to_owned());
        guard.members.insert(
            account.to_owned(),
            Membership {
                group_id: group_id.to_owned(),
                kind,
                role,
                state,
            },
        );
    }

    pub fn subscription(&self, id: &str) -> Option<SubscriptionRow> {
        self.lock().subscriptions.get(id).cloned()
    }

    pub fn subscriptions(&self) -> Vec<SubscriptionRow> {
        self.lock().subscriptions.values().cloned().collect()
    }

    pub fn customer(&self, customer: &str) -> Option<CustomerRow> {
        self.lock().customers.get(customer).cloned()
    }

    pub fn customers(&self) -> Vec<CustomerRow> {
        self.lock().customers.values().cloned().collect()
    }

    pub fn groups(&self) -> Vec<GroupRow> {
        self.lock().groups.values().cloned().collect()
    }

    pub fn event_ids(&self) -> Vec<String> {
        self.lock().events.keys().cloned().collect()
    }

    /// A fingerprint of every table, to show that a refused call changed nothing.
    pub fn snapshot(&self) -> String {
        format!("{:?}", *self.lock())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl BillingStore for MemoryBillingStore {
    fn transaction<T>(
        &self,
        f: impl FnOnce(&mut dyn BillingTx) -> RelayResult<T>,
    ) -> RelayResult<T> {
        let mut guard = self.lock();
        let mut copy = guard.clone();
        let out = f(&mut copy)?;
        *guard = copy;
        Ok(out)
    }
}

impl BillingTx for MemoryState {
    fn account_exists(&mut self, account: &str) -> RelayResult<bool> {
        Ok(self.accounts.contains(account))
    }

    fn customer_of_account(&mut self, account: &str) -> RelayResult<Option<CustomerRow>> {
        Ok(self.customers.values().find(|c| c.account == account).cloned())
    }

    fn customer(&mut self, customer: &str) -> RelayResult<Option<CustomerRow>> {
        Ok(self.customers.get(customer).cloned())
    }

    fn put_customer(&mut self, row: &CustomerRow) -> RelayResult<()> {
        self.customers.insert(row.customer.clone(), row.clone());
        Ok(())
    }

    fn subscription(&mut self, id: &str) -> RelayResult<Option<SubscriptionRow>> {
        Ok(self.subscriptions.get(id).cloned())
    }

    fn subscriptions_of_account(&mut self, account: &str) -> RelayResult<Vec<SubscriptionRow>> {
        Ok(self
            .subscriptions
            .values()
            .filter(|s| s.account == account)
            .cloned()
            .collect())
    }

    fn put_subscription(&mut self, row: &SubscriptionRow) -> RelayResult<()> {
        self.subscriptions.insert(row.id.clone(), row.clone());
        Ok(())
    }

    fn lapsed_subscriptions(&mut self) -> RelayResult<Vec<SubscriptionRow>> {
        Ok(self
            .subscriptions
            .values()
            .filter(|s| s.status == StripeStatus::PastDue || s.status.has_ended())
            .cloned()
            .collect())
    }

    fn record_event(&mut self, id: &str, kind: &str, at: u64) -> RelayResult<bool> {
        if self.events.contains_key(id) {
            return Ok(false);
        }
        self.events.insert(id.to_owned(), (kind.to_owned(), at));
        Ok(true)
    }

    fn prune_events(&mut self, before: u64) -> RelayResult<u64> {
        let old = self.events.len();
        self.events.retain(|_, (_, at)| *at >= before);
        Ok((old - self.events.len()) as u64)
    }

    fn membership(&mut self, account: &str) -> RelayResult<Option<Membership>> {
        Ok(self.members.get(account).cloned())
    }

    fn group(&mut self, group_id: &str) -> RelayResult<Option<GroupRow>> {
        Ok(self.groups.get(group_id).cloned())
    }

    fn create_group(&mut self, kind: GroupKind, owner: &str, _now: u64) -> RelayResult<String> {
        let group_id = new_group_id()?;
        self.groups.insert(
            group_id.clone(),
            GroupRow {
                group_id: group_id.clone(),
                kind,
                owner_account: owner.to_owned(),
            },
        );
        self.members.insert(
            owner.to_owned(),
            Membership {
                group_id: group_id.clone(),
                kind,
                role: GroupRole::Owner,
                state: MemberState::Active,
            },
        );
        Ok(group_id)
    }

    fn active_members(&mut self, group_id: &str) -> RelayResult<u32> {
        let count = self
            .members
            .values()
            .filter(|m| m.group_id == group_id && m.state == MemberState::Active)
            .count();
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }
}

// ---------------------------------------------------------------------------------------
// Requests and answers.

/// `POST /v1/account/checkout`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutRequest {
    pub plan: Plan,
    pub interval: Interval,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub people: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seats: Option<u32>,
}

/// The answer of `POST /v1/account/checkout`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutAnswer {
    pub url: String,
    pub session_id: String,
    pub expires_at: u64,
}

/// `POST /v1/account/portal`: `{}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalRequest {}

/// The answer of `POST /v1/account/portal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalAnswer {
    pub url: String,
}

/// `POST /v1/account/group/seats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatsRequest {
    pub quantity: u32,
}

/// The answer of `POST /v1/account/group/seats`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatsAnswer {
    pub quantity: u32,
    /// True when Stripe was asked; the quantity changes when its webhook arrives.
    pub pending: bool,
}

/// The answer of `POST /v1/stripe/webhook`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookAnswer {
    pub received: bool,
    pub duplicate: bool,
}

/// What a webhook did, for the tests and the audit of the wiring step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookEffect {
    /// A repeat of a stored event id.
    Duplicate,
    /// Applied: the account whose plan may have changed.
    Applied { account: String },
    /// Stored id, no change (another type, an older event, or an event that does not
    /// match the stored rows). The reason is logged.
    Ignored,
}

/// The answer and the effect of a webhook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookOutcome {
    pub answer: WebhookAnswer,
    pub effect: WebhookEffect,
}

/// An ended plan whose stores are due for deletion (`end + delete days ≤ now`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueDeletion {
    pub subscription: String,
    pub account: String,
    pub group_id: Option<String>,
    pub delete_at: u64,
}

/// What the maintenance pass found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    pub events_pruned: u64,
    pub due: Vec<DueDeletion>,
}

/// Parses a strict JSON request body.
pub fn parse_request<T: for<'de> Deserialize<'de>>(body: &[u8]) -> RelayResult<T> {
    if body.len() > 64 * 1024 {
        return Err(RelayError::new(codes::PAYLOAD_TOO_LARGE, "The body is larger than 64 KiB."));
    }
    serde_json::from_slice(body).map_err(|_| RelayError::invalid("The request body is not valid."))
}

// ---------------------------------------------------------------------------------------
// The handlers.

/// Billing: the storage, the Stripe client, the settings, and the webhook secret. The
/// relay makes one and calls its handlers from the routes.
pub struct Billing<S: BillingStore> {
    pub store: S,
    pub stripe: StripeClient,
    pub config: BillingConfig,
    webhook_secret: SecretString,
    log: LogSink,
}

impl<S: BillingStore> Billing<S> {
    pub fn new(store: S, stripe: StripeClient, config: BillingConfig, webhook_secret: SecretString) -> RelayResult<Self> {
        stripe::check_webhook_secret(&webhook_secret)?;
        Ok(Self {
            store,
            stripe,
            config,
            webhook_secret,
            log: stripe::stderr_log(),
        })
    }

    /// The same billing with another log sink (the tests capture lines).
    pub fn with_log(mut self, log: LogSink) -> Self {
        self.log = log;
        self
    }

    fn log(&self, line: &str) {
        (self.log)(line);
    }

    /// The resolved prices, from the cache of the Stripe client. Called at start too.
    pub fn prices(&self, now: u64) -> RelayResult<ResolvedPrices> {
        let raw = self.stripe.prices(&LOOKUP_KEYS, now)?;
        Ok(resolve_prices(&raw, &self.log))
    }

    /// `GET /v1/plans` (public).
    pub fn plans(&self, now: u64) -> RelayResult<PlansView> {
        Ok(plans_view(&self.prices(now)?))
    }

    /// `GET /v1/account/plan`: the plan of the account, or of its group for an active
    /// member.
    pub fn plan_view(&self, account: &str, now: u64) -> RelayResult<PlanView> {
        let durations = self.config.durations;
        self.store
            .transaction(|tx| account_plan(tx, account, now, &durations))
    }

    /// `POST /v1/account/checkout` for an authenticated account. Calls Stripe; changes
    /// nothing here (the webhook binds the subscription).
    pub fn checkout(&self, account: &str, body: &[u8], now: u64) -> RelayResult<CheckoutAnswer> {
        let request: CheckoutRequest = parse_request(body)?;
        let count = match (request.plan, request.people, request.seats) {
            (Plan::Personal, None, None) => 1,
            (Plan::Family, Some(people), None) => people,
            (Plan::Team, None, Some(seats)) => seats,
            (Plan::Family, _, _) => {
                return Err(RelayError::invalid("A family checkout needs `people` and no `seats`."));
            }
            (Plan::Team, _, _) => {
                return Err(RelayError::invalid("A team checkout needs `seats` and no `people`."));
            }
            (Plan::Personal, _, _) => {
                return Err(RelayError::invalid("Connect Personal takes no `people` or `seats`."));
            }
        };
        check_count(request.plan, count)?;
        let durations = self.config.durations;
        let customer = self.store.transaction(|tx| {
            if !tx.account_exists(account)? {
                return Err(RelayError::not_found("account"));
            }
            // A member (pending or active) does not buy; its owner's plan covers it. An
            // owner whose plan lapsed may buy again: the new subscription keeps the group.
            if tx
                .membership(account)?
                .is_some_and(|member| member.role != GroupRole::Owner)
            {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "This account is in a family or team. Its owner manages the plan.",
                ));
            }
            if account_plan(tx, account, now, &durations)?.entitled {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "This account has a plan. Change it in the billing portal.",
                ));
            }
            Ok(tx.customer_of_account(account)?.map(|row| row.customer))
        })?;
        let prices = self.prices(now)?;
        let Some(price) = prices.get(request.plan, request.interval) else {
            self.log(&format!(
                "checkout refused: no usable price {}",
                lookup_key(request.plan, request.interval)
            ));
            return Err(RelayError::new(codes::BUSY, "This plan cannot be bought now."));
        };
        if request.plan == Plan::Family && price.extra != Some(self.config.family_extra(request.interval)) {
            self.log(&format!(
                "checkout refused: tier 2 of {} differs from the configured Family extra",
                lookup_key(request.plan, request.interval)
            ));
            return Err(RelayError::new(codes::BUSY, "This plan cannot be bought now."));
        }
        let form = checkout_form(
            account,
            &price.price_id,
            count,
            request.plan,
            customer.as_deref(),
            &self.config.site_url,
        );
        // The same request in the same hour reuses its key, so a repeated click gets the
        // same session and Stripe never makes two subscriptions of one click.
        let key = idempotency_key(
            "checkout",
            &[
                account,
                request.plan.as_str(),
                request.interval.as_str(),
                &count.to_string(),
                customer.as_deref().unwrap_or("-"),
                &(now / 3600).to_string(),
            ],
        );
        let session = self.stripe.create_checkout_session(&form, &key)?;
        self.log(&format!("checkout session {} made for {account}", session.id));
        Ok(CheckoutAnswer {
            url: session.url,
            session_id: session.id,
            expires_at: session.expires_at,
        })
    }

    /// `POST /v1/account/portal` from the account that owns the Stripe customer.
    pub fn portal(&self, account: &str, body: &[u8]) -> RelayResult<PortalAnswer> {
        let _: PortalRequest = parse_request(body)?;
        let customer = self.store.transaction(|tx| {
            if let Some(member) = tx.membership(account)?
                && member.role != GroupRole::Owner
            {
                return Err(RelayError::forbidden(
                    "The owner of the family or team manages its billing.",
                ));
            }
            tx.customer_of_account(account)?
                .map(|row| row.customer)
                .ok_or_else(|| RelayError::not_found("Stripe customer for this account"))
        })?;
        let key = random_idempotency_key("portal")?;
        let return_url = format!("{}/connect/done", self.config.site_url);
        let session = self.stripe.create_portal_session(&customer, &return_url, &key)?;
        Ok(PortalAnswer { url: session.url })
    }

    /// `POST /v1/account/group/seats` by the owner of a group: checks the count and asks
    /// Stripe to change the quantity with `create_prorations`. The stored quantity
    /// changes only when `customer.subscription.updated` arrives.
    pub fn change_seats(&self, account: &str, body: &[u8], now: u64) -> RelayResult<SeatsAnswer> {
        let request: SeatsRequest = parse_request(body)?;
        let group_id = self.store.transaction(|tx| {
            let member = tx
                .membership(account)?
                .filter(|m| m.state == MemberState::Active)
                .ok_or_else(not_in_group)?;
            if member.role != GroupRole::Owner {
                return Err(RelayError::forbidden("Only the owner changes the seats."));
            }
            Ok(member.group_id)
        })?;
        self.request_group_quantity(&group_id, request.quantity, now)
    }

    /// Asks Stripe for a new quantity of the group's subscription. For C3's confirm of a
    /// member (owner or admin, checked by the caller) and for `change_seats`. Refuses a
    /// count outside `1 ≤ n ≤ max` or below the active members (`409 seat_limit`).
    pub fn request_group_quantity(&self, group_id: &str, quantity: u32, now: u64) -> RelayResult<SeatsAnswer> {
        let durations = self.config.durations;
        let (row, active) = self.store.transaction(|tx| {
            let group = tx.group(group_id)?.ok_or_else(|| RelayError::not_found("group"))?;
            let row = group_subscription(tx, &group)?
                .ok_or_else(|| RelayError::not_found("subscription of this group"))?;
            Ok((row, tx.active_members(group_id)?))
        })?;
        let plan = row.plan.ok_or_else(|| RelayError::not_found("plan of this group"))?;
        row.state(now, &durations).require(Capability::Push)?;
        check_count(plan, quantity)?;
        if quantity < active {
            return Err(seat_limit(match plan {
                Plan::Family => format!("The family has {active} people; choose at least {active}."),
                _ => format!("The team has {active} members; choose at least {active}."),
            }));
        }
        if quantity == row.quantity {
            return Ok(SeatsAnswer {
                quantity,
                pending: false,
            });
        }
        let item = row
            .item
            .as_deref()
            .ok_or_else(|| RelayError::new(codes::BUSY, "The subscription is not ready yet."))?;
        // A fresh key for each change: 6, then 5, then 6 again are three changes.
        let key = random_idempotency_key("seats")?;
        self.stripe.update_item_quantity(item, quantity, &key)?;
        self.log(&format!(
            "quantity {quantity} asked for {} of group {group_id}",
            row.id
        ));
        Ok(SeatsAnswer {
            quantity,
            pending: true,
        })
    }

    /// For `DELETE /v1/account` (contract section 9): cancels every subscription of the
    /// account that has not ended, at once, and deletes the email copy. The Stripe
    /// customer row stays for support. Answers whether a subscription was canceled.
    pub fn cancel_for_account_deletion(&self, account: &str) -> RelayResult<bool> {
        let rows = self
            .store
            .transaction(|tx| tx.subscriptions_of_account(account))?;
        let mut canceled = false;
        for row in rows.iter().filter(|row| !row.status.has_ended()) {
            self.stripe.cancel_subscription(&row.id)?;
            canceled = true;
        }
        self.store.transaction(|tx| {
            if let Some(mut customer) = tx.customer_of_account(account)? {
                customer.email = None;
                tx.put_customer(&customer)?;
            }
            Ok(())
        })?;
        Ok(canceled)
    }

    /// The maintenance pass: prunes event ids older than 30 days and lists the ended
    /// plans whose stores are due for deletion. The caller deletes them (an audit row
    /// with counts, I-4 `forget`) and then calls `mark_stores_deleted`.
    pub fn maintenance(&self, now: u64) -> RelayResult<MaintenanceReport> {
        let durations = self.config.durations;
        self.store.transaction(|tx| {
            let events_pruned = tx.prune_events(now.saturating_sub(EVENT_RETENTION))?;
            let mut due = Vec::new();
            for row in tx.lapsed_subscriptions()? {
                if row.stores_deleted_at.is_some() {
                    continue;
                }
                if row.state(now, &durations).status == PlanStatus::None
                    && let Some(delete_at) = deletion_time(&row, &durations)
                    && delete_at <= now
                {
                    due.push(DueDeletion {
                        subscription: row.id.clone(),
                        account: row.account.clone(),
                        group_id: row.group_id.clone(),
                        delete_at,
                    });
                }
            }
            Ok(MaintenanceReport { events_pruned, due })
        })
    }

    /// Records that the stores of an ended plan were deleted, so the pass does not list
    /// it again. A renewal before the deletion keeps the stores; one after it starts
    /// without them.
    pub fn mark_stores_deleted(&self, subscription: &str, now: u64) -> RelayResult<()> {
        self.store.transaction(|tx| {
            let mut row = tx
                .subscription(subscription)?
                .ok_or_else(|| RelayError::not_found("subscription"))?;
            row.stores_deleted_at = Some(now);
            tx.put_subscription(&row)
        })
    }

    /// `POST /v1/stripe/webhook`. In this order: the size (`413`), the signature (`400`),
    /// the event JSON (`400`), the event id (a repeat answers `duplicate: true`), then the
    /// effect. Every refusal changes nothing. An event that cannot apply (an unknown
    /// account, another customer, an unknown price) is logged, its id is stored, and the
    /// answer is 200, so Stripe does not retry it.
    pub fn webhook(&self, signature: Option<&str>, body: &[u8], now: u64) -> RelayResult<WebhookOutcome> {
        if body.len() > MAX_WEBHOOK_BODY {
            return Err(RelayError::new(
                codes::PAYLOAD_TOO_LARGE,
                "The webhook body is larger than 256 KiB.",
            ));
        }
        if let Err(error) = stripe::verify_signature(signature, body, &self.webhook_secret, now) {
            self.log(&format!(
                "webhook refused: {}",
                match error {
                    SignatureError::Header => "no usable Stripe-Signature header",
                    SignatureError::Timestamp => "the signature time is outside 300 s",
                    SignatureError::Mismatch => "the signature does not verify",
                }
            ));
            return Err(RelayError::invalid("The Stripe signature does not verify."));
        }
        let event: Event = serde_json::from_slice(body)
            .map_err(|_| RelayError::invalid("The Stripe event is not valid JSON."))?;
        if !is_stripe_id("evt_", &event.id) || event.kind.is_empty() || event.kind.len() > 100 {
            return Err(RelayError::invalid("The Stripe event has no valid id or type."));
        }
        let durations = self.config.durations;
        let mut lines = Vec::new();
        let effect = self.store.transaction(|tx| {
            lines.clear();
            if !tx.record_event(&event.id, &event.kind, now)? {
                return Ok(WebhookEffect::Duplicate);
            }
            apply_event(tx, &event, now, &durations, &mut lines)
        })?;
        for line in &lines {
            self.log(line);
        }
        let duplicate = effect == WebhookEffect::Duplicate;
        if duplicate {
            self.log(&format!("webhook {} ({}) is a repeat", event.id, event.kind));
        }
        Ok(WebhookOutcome {
            answer: WebhookAnswer {
                received: true,
                duplicate,
            },
            effect,
        })
    }
}

fn not_in_group() -> RelayError {
    RelayError::new(codes::NOT_IN_GROUP, "This account is not in that family or team.")
}

/// The time the stores of an ended plan are deleted, if its end is known.
fn deletion_time(row: &SubscriptionRow, durations: &Durations) -> Option<u64> {
    let end = if row.status == StripeStatus::PastDue {
        row.first_failed_at
            .or(row.period_end)
            .map(|start| start.saturating_add(durations.grace_days * DAY))
    } else {
        row.ended_at.or(row.period_end)
    }?;
    Some(end.saturating_add(durations.delete_days * DAY))
}

/// The checkout form of contract section 4, in the order of `examples.json`.
pub fn checkout_form(
    account: &str,
    price_id: &str,
    quantity: u32,
    plan: Plan,
    customer: Option<&str>,
    site_url: &str,
) -> Form {
    let mut form = Form::new();
    form.push("mode", "subscription")
        .push("line_items[0][price]", price_id)
        .push("line_items[0][quantity]", quantity.to_string())
        .push("automatic_tax[enabled]", "true")
        .push("billing_address_collection", "required")
        .push("client_reference_id", account)
        .push("metadata[account_id]", account)
        .push("subscription_data[metadata][account_id]", account)
        .push("consent_collection[terms_of_service]", "required")
        .push(
            "success_url",
            format!("{site_url}/connect/done?session_id={{CHECKOUT_SESSION_ID}}"),
        )
        .push("cancel_url", format!("{site_url}/connect/cancel"));
    if plan == Plan::Team {
        form.push("tax_id_collection[enabled]", "true");
    }
    if let Some(customer) = customer {
        form.push("customer", customer)
            .push("customer_update[address]", "auto");
    }
    form
}

/// `apassy-<action>-<40 hex>`: a hash of the action's parts, so no id is in the key.
fn idempotency_key(action: &str, parts: &[&str]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"apassy-connect idempotency v1\0");
    hash.update(action.as_bytes());
    for part in parts {
        hash.update(b"\0");
        hash.update(part.as_bytes());
    }
    format!("apassy-{action}-{}", &hex(&hash.finalize())[..40])
}

fn random_idempotency_key(action: &str) -> RelayResult<String> {
    let mut bytes = [0u8; 20];
    getrandom::fill(&mut bytes).map_err(|_| RelayError::internal("No randomness."))?;
    Ok(format!("apassy-{action}-{}", hex(&bytes)))
}

/// The plan of an account: its own subscription, or the group's for an active member of
/// a Family or Team. An entitled state wins over one that is not; then the newest.
fn account_plan(
    tx: &mut dyn BillingTx,
    account: &str,
    now: u64,
    durations: &Durations,
) -> RelayResult<PlanView> {
    let mut candidates: Vec<(SubscriptionRow, Option<String>)> = tx
        .subscriptions_of_account(account)?
        .into_iter()
        .map(|row| {
            let group = row.group_id.clone();
            (row, group)
        })
        .collect();
    if let Some(member) = tx.membership(account)?
        && member.state == MemberState::Active
        && member.role != GroupRole::Owner
        && let Some(group) = tx.group(&member.group_id)?
        && let Some(row) = group_subscription(tx, &group)?
        && row.plan.and_then(Plan::group_kind) == Some(group.kind)
    {
        candidates.push((row, Some(group.group_id)));
    }
    let best = candidates
        .iter()
        .map(|(row, group)| (row.state(now, durations), row, group))
        .filter(|(state, _, _)| state.status != PlanStatus::None)
        .max_by_key(|(state, row, _)| (state.entitled, row.last_event_created));
    Ok(match best {
        Some((state, row, group)) => PlanView::from_state(&state, Some(row), group.as_deref()),
        None => PlanView::none(),
    })
}

/// The subscription of a group: the owner's subscription bound to it.
fn group_subscription(tx: &mut dyn BillingTx, group: &GroupRow) -> RelayResult<Option<SubscriptionRow>> {
    Ok(tx
        .subscriptions_of_account(&group.owner_account)?
        .into_iter()
        .filter(|row| row.group_id.as_deref() == Some(group.group_id.as_str()))
        .max_by_key(|row| row.last_event_created))
}

// ---------------------------------------------------------------------------------------
// Webhook events.

/// A Stripe event: the fields Connect reads. Every other field is ignored.
#[derive(Debug, Deserialize)]
struct Event {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    created: u64,
    data: EventData,
}

#[derive(Debug, Deserialize)]
struct EventData {
    object: Value,
}

fn text<'a>(object: &'a Value, pointer: &str) -> Option<&'a str> {
    object.pointer(pointer).and_then(Value::as_str)
}

fn number(object: &Value, pointer: &str) -> Option<u64> {
    object.pointer(pointer).and_then(Value::as_u64)
}

fn apply_event(
    tx: &mut dyn BillingTx,
    event: &Event,
    now: u64,
    durations: &Durations,
    lines: &mut Vec<String>,
) -> RelayResult<WebhookEffect> {
    let object = &event.data.object;
    let tag = format!("webhook {} ({})", event.id, event.kind);
    let ignore = |lines: &mut Vec<String>, why: &str| {
        lines.push(format!("{tag}: ignored: {why}"));
        Ok(WebhookEffect::Ignored)
    };
    match event.kind.as_str() {
        "checkout.session.completed" => {
            let session = text(object, "/id").unwrap_or("-");
            if text(object, "/mode") != Some("subscription") {
                return ignore(lines, "not a subscription checkout");
            }
            let reference = text(object, "/client_reference_id");
            let metadata = text(object, "/metadata/account_id");
            let (Some(account), Some(meta)) = (reference, metadata) else {
                return ignore(lines, &format!("session {session} names no account"));
            };
            if account != meta || !is_account_id(account) || !tx.account_exists(account)? {
                return ignore(lines, &format!("session {session} names an unknown account"));
            }
            let (Some(customer), Some(subscription)) =
                (text(object, "/customer"), text(object, "/subscription"))
            else {
                return ignore(lines, &format!("session {session} has no customer or subscription"));
            };
            if !is_stripe_id("cus_", customer) || !is_stripe_id("sub_", subscription) {
                return ignore(lines, &format!("session {session} has malformed ids"));
            }
            if let Some(bound) = tx.customer_of_account(account)?
                && bound.customer != customer
            {
                return ignore(lines, &format!("{account} is bound to another customer"));
            }
            if let Some(bound) = tx.customer(customer)?
                && bound.account != account
            {
                return ignore(lines, &format!("customer {customer} is bound to another account"));
            }
            if let Some(row) = tx.subscription(subscription)?
                && (row.account != account || row.customer != customer)
            {
                return ignore(lines, &format!("subscription {subscription} is bound elsewhere"));
            }
            let email = text(object, "/customer_details/email")
                .filter(|email| email.len() <= 254 && email.contains('@'))
                .map(str::to_owned);
            let previous = tx.customer(customer)?.and_then(|row| row.email);
            tx.put_customer(&CustomerRow {
                account: account.to_owned(),
                customer: customer.to_owned(),
                email: email.or(previous),
            })?;
            let mut row = tx
                .subscription(subscription)?
                .unwrap_or_else(|| SubscriptionRow::bound(subscription, customer, account));
            ensure_group(tx, &mut row, now, lines, &tag)?;
            tx.put_subscription(&row)?;
            lines.push(format!("{tag}: {subscription} bound to {account}"));
            Ok(WebhookEffect::Applied {
                account: account.to_owned(),
            })
        }
        "customer.subscription.created" | "customer.subscription.updated" | "customer.subscription.deleted" => {
            let Some(id) = text(object, "/id").filter(|id| is_stripe_id("sub_", id)) else {
                return ignore(lines, "no subscription id");
            };
            let Some(customer) = text(object, "/customer").filter(|c| is_stripe_id("cus_", c)) else {
                return ignore(lines, &format!("{id} has no customer"));
            };
            let metadata = text(object, "/metadata/account_id");
            let existing = tx.subscription(id)?;
            let account = match &existing {
                Some(row) => {
                    if row.customer != customer || metadata.is_some_and(|meta| meta != row.account) {
                        return ignore(lines, &format!("{id} does not match its stored customer or account"));
                    }
                    row.account.clone()
                }
                None => {
                    let Some(account) = metadata.filter(|a| is_account_id(a)) else {
                        return ignore(lines, &format!("{id} names no account"));
                    };
                    if !tx.account_exists(account)? {
                        return ignore(lines, &format!("{id} names an unknown account"));
                    }
                    if let Some(bound) = tx.customer(customer)?
                        && bound.account != account
                    {
                        return ignore(lines, &format!("customer {customer} is bound to another account"));
                    }
                    if let Some(bound) = tx.customer_of_account(account)?
                        && bound.customer != customer
                    {
                        return ignore(lines, &format!("{account} is bound to another customer"));
                    }
                    account.to_owned()
                }
            };
            let mut row = existing.unwrap_or_else(|| SubscriptionRow::bound(id, customer, &account));
            let created_again = event.kind == "customer.subscription.created" && row.last_event_created > 0;
            if event.created < row.last_event_created
                || (event.created == row.last_event_created && created_again)
            {
                return ignore(lines, &format!("{id}: older than the last applied event"));
            }
            let item = object.pointer("/items/data/0");
            let Some(lookup) = item.and_then(|item| text(item, "/price/lookup_key")) else {
                return ignore(lines, &format!("{id} has no price lookup key"));
            };
            let Some((plan, interval)) = parse_lookup_key(lookup) else {
                return ignore(lines, &format!("{id}: unknown lookup key"));
            };
            // A Family subscription does not turn into a Team one (the portal switches only
            // between Personal and Family); a plan of another group kind is not applied.
            if let (Some(kind), Some(group)) = (plan.group_kind(), row.group_id.clone())
                && tx.group(&group)?.is_some_and(|g| g.kind != kind)
            {
                return ignore(lines, &format!("{id}: the plan does not fit its group {group}"));
            }
            let status = if event.kind == "customer.subscription.deleted" {
                StripeStatus::Canceled
            } else {
                text(object, "/status").map_or(StripeStatus::Other, StripeStatus::parse)
            };
            let quantity = item
                .and_then(|item| number(item, "/quantity"))
                .and_then(|q| u32::try_from(q).ok())
                .unwrap_or(1)
                .max(1);
            let was_entitled = row.state(now, durations).entitled;
            row.item = item
                .and_then(|item| text(item, "/id"))
                .filter(|si| is_stripe_id("si_", si))
                .map(str::to_owned)
                .or(row.item);
            row.lookup_key = Some(lookup.to_owned());
            row.plan = Some(plan);
            row.interval = Some(interval);
            row.quantity = quantity;
            row.status = status;
            row.cancel_at_period_end = object
                .pointer("/cancel_at_period_end")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            row.period_end = item
                .and_then(|item| number(item, "/current_period_end"))
                .or_else(|| number(object, "/current_period_end"));
            if status.has_ended() {
                row.ended_at = number(object, "/ended_at")
                    .or(row.ended_at)
                    .or(Some(event.created));
            } else {
                row.ended_at = None;
            }
            match status {
                StripeStatus::Active | StripeStatus::Trialing => {
                    row.first_failed_at = None;
                    row.stores_deleted_at = None;
                }
                StripeStatus::PastDue if row.first_failed_at.is_none() => {
                    row.first_failed_at = Some(event.created);
                }
                _ => {}
            }
            row.last_event_created = event.created;
            ensure_group(tx, &mut row, now, lines, &tag)?;
            tx.put_subscription(&row)?;
            let state = row.state(now, durations);
            lines.push(format!(
                "{tag}: {id} of {account} is {} ({}, quantity {quantity}); entitled {} → {}",
                status.as_str(),
                lookup,
                was_entitled,
                state.entitled
            ));
            Ok(WebhookEffect::Applied { account })
        }
        "invoice.paid" | "invoice.payment_failed" => {
            let subscription = text(object, "/parent/subscription_details/subscription")
                .or_else(|| text(object, "/subscription"));
            let Some(id) = subscription.filter(|id| is_stripe_id("sub_", id)) else {
                return ignore(lines, "the invoice has no subscription");
            };
            let Some(mut row) = tx.subscription(id)? else {
                return ignore(lines, &format!("{id} is not known"));
            };
            if text(object, "/customer") != Some(row.customer.as_str()) {
                return ignore(lines, &format!("{id}: the invoice has another customer"));
            }
            if event.created < row.last_invoice_created {
                return ignore(lines, &format!("{id}: older than the last applied invoice event"));
            }
            if event.kind == "invoice.paid" {
                row.first_failed_at = None;
            } else if row.first_failed_at.is_none() {
                row.first_failed_at = Some(event.created);
            }
            row.last_invoice_created = event.created;
            tx.put_subscription(&row)?;
            lines.push(format!(
                "{tag}: {id} of {}: first failure {}",
                row.account,
                row.first_failed_at.map_or("cleared".to_owned(), |t| t.to_string())
            ));
            Ok(WebhookEffect::Applied { account: row.account })
        }
        _ => {
            lines.push(format!("{tag}: stored, no effect"));
            Ok(WebhookEffect::Ignored)
        }
    }
}

/// Makes the group of a Family or Team subscription, with the buyer as its owner, when it
/// has none yet. An account that is already in another group keeps that group; the
/// subscription stays without one and the line says so.
fn ensure_group(
    tx: &mut dyn BillingTx,
    row: &mut SubscriptionRow,
    now: u64,
    lines: &mut Vec<String>,
    tag: &str,
) -> RelayResult<()> {
    let Some(kind) = row.plan.and_then(Plan::group_kind) else {
        return Ok(());
    };
    if row.group_id.is_some() {
        return Ok(());
    }
    if let Some(member) = tx.membership(&row.account)? {
        if member.role == GroupRole::Owner && member.kind == kind {
            row.group_id = Some(member.group_id);
        } else {
            lines.push(format!("{tag}: {} is in another group; no group made", row.account));
        }
        return Ok(());
    }
    let group_id = tx.create_group(kind, &row.account, now)?;
    lines.push(format!("{tag}: group {group_id} made for {}", row.account));
    row.group_id = Some(group_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_keys_round_trip() {
        for key in LOOKUP_KEYS {
            let (plan, interval) = parse_lookup_key(key).unwrap();
            assert_eq!(lookup_key(plan, interval), key);
        }
        assert_eq!(parse_lookup_key("connect_family_extra_month"), None);
    }

    #[test]
    fn group_and_account_ids_have_the_contract_form() {
        let id = new_group_id().unwrap();
        assert_eq!(id.len(), 14);
        assert!(is_account_id(&format!("acc_{}", &id[4..])));
        assert!(!is_account_id("acc_K7M2Q4X3CA"));
        assert!(!is_account_id("acc_k7m2q4x3c1"));
    }

    #[test]
    fn config_defaults_and_limits() {
        let none = |_: &str| None;
        assert_eq!(BillingConfig::from_lookup(&none).unwrap(), BillingConfig::default());
        let bad_delete = |name: &str| (name == "APASSY_CONNECT_DELETE_DAYS").then(|| "30".to_owned());
        assert!(BillingConfig::from_lookup(&bad_delete).is_err());
        let path = |name: &str| (name == "APASSY_CONNECT_SITE_URL").then(|| "https://a.example/x".to_owned());
        assert!(BillingConfig::from_lookup(&path).is_err());
        let custom = |name: &str| match name {
            "APASSY_CONNECT_GRACE_DAYS" => Some("7".to_owned()),
            "APASSY_CONNECT_FAMILY_EXTRA_CENTS" => Some("150".to_owned()),
            "APASSY_CONNECT_SITE_URL" => Some("https://staging.example/".to_owned()),
            _ => None,
        };
        let config = BillingConfig::from_lookup(&custom).unwrap();
        assert_eq!(config.durations.grace_days, 7);
        assert_eq!(config.family_extra_cents, 150);
        assert_eq!(config.site_url, "https://staging.example");
    }

    #[test]
    fn idempotency_keys_hide_their_parts() {
        let key = idempotency_key("checkout", &["acc_k7m2q4x3ca", "personal"]);
        assert!(key.starts_with("apassy-checkout-"));
        assert!(!key.contains("acc_"));
        assert_eq!(key, idempotency_key("checkout", &["acc_k7m2q4x3ca", "personal"]));
        assert_ne!(key, idempotency_key("checkout", &["acc_k7m2q4x3ca", "family"]));
    }
}
