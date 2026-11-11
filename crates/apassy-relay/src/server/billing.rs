//! Connect billing: plans and prices, Checkout and the Customer Portal, the Stripe
//! webhook, the plan state of an account, and the seats of a group
//! (docs/contracts/connect-billing-v1.md; docs/SPEC.md section "Billing").
//!
//! Rules this module keeps:
//!
//! - **State only from Stripe.** A subscription's status, plan, and quantity change only on
//!   a verified webhook (`Billing::webhook`, after the signature) or on Stripe's own answer
//!   to Connect's read of that subscription (the maintenance pass, `Billing::reconcile`
//!   and `Billing::verify_ended`), with the same rules. Connect writes its own facts only:
//!   the Stripe customer it made for an account before the first checkout, the open
//!   checkout session, a quantity Stripe accepted from Connect before its webhook, and the
//!   mark of deleted stores.
//! - **Idempotent by event id**: an event id is stored in the same transaction as its
//!   effect, and a repeat answers `duplicate: true` without an effect. Stripe does not
//!   keep the order of events, so an older subscription or invoice event than the last
//!   applied one is ignored; `canceled` and `incomplete_expired` are final.
//! - **Paid seats**: the members of a group beyond the people or seats it pays for (the
//!   earliest confirmed first) are not entitled; the count, the comparison, and the
//!   activation of a member run under one lock of the group.
//! - **Nothing paid is dropped in silence**: an event of a subscription that Connect
//!   cannot apply for a known account or customer is recorded for the operator
//!   (`billing_problem`, an audit row, the count in `apassy-relay admin readiness`).
//! - **Logs** name event ids, event types, Stripe object ids, and account ids. Never an
//!   email, a key, a secret, or a body.
//!
//! The handlers are plain functions from parsed input to an answer struct, written
//! against the storage trait `BillingStore`. `MemoryBillingStore` implements it for the
//! tests; the relay implements it on the directory tables `stripe_customer`,
//! `stripe_subscription`, `stripe_event`, `group`, and `group_member`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{RelayError, RelayResult, codes};
use crate::secret::SecretString;
use crate::server::stripe::{
    self, Form, LogSink, MAX_WEBHOOK_BODY, SignatureError, StripeClient, StripePrice, is_stripe_id,
};
use crate::sync_head::hex;

const DAY: u64 = 86_400;
/// How long an event id is kept (contract section 7).
pub const EVENT_RETENTION: u64 = 30 * DAY;
/// A live subscription whose period ended this long ago without a renewal event is read
/// from Stripe by the maintenance pass (at most once a day for each).
pub const STALE_PERIOD_SECS: u64 = 2 * DAY;
/// How often the maintenance pass reads one stale subscription from Stripe at most.
pub const RECHECK_SECS: u64 = DAY;
/// A gap between two billing passes longer than this holds every deletion of stores until
/// the operator resumes them (`apassy-relay admin billing --resume-deletions`).
pub const MAX_PASS_GAP: u64 = 2 * DAY;
/// The relay's clock may be ahead of the latest time it saw from Stripe (the `t` of a
/// verified webhook, the `Date` of a Stripe answer) by this much; beyond it no store is
/// deleted.
pub const MAX_CLOCK_AHEAD: u64 = DAY;
/// Stripe applies a quantity it accepted from Connect at once; a later subscription event
/// carries it. An event this much newer than Connect's request is Stripe's word again.
const REQUEST_SETTLE_SECS: u64 = 300;
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

/// The plan and the interval of a Stripe price object (a subscription item's `price`):
/// its Connect lookup key, or, for a price that lost its key to a newer price of the
/// products script, `metadata.apassy_plan` with a monthly or yearly `recurring` interval.
pub fn plan_of_price(price: &Value) -> Option<(Plan, Interval)> {
    if let Some(found) = price
        .pointer("/lookup_key")
        .and_then(Value::as_str)
        .and_then(parse_lookup_key)
    {
        return Some(found);
    }
    let plan = match price
        .pointer("/metadata/apassy_plan")
        .and_then(Value::as_str)?
    {
        "personal" => Plan::Personal,
        "family" => Plan::Family,
        "team" => Plan::Team,
        _ => return None,
    };
    if price
        .pointer("/recurring/interval_count")
        .and_then(Value::as_u64)
        .is_some_and(|count| count != 1)
    {
        return None;
    }
    let interval = match price
        .pointer("/recurring/interval")
        .and_then(Value::as_str)?
    {
        "month" => Interval::Month,
        "year" => Interval::Year,
        _ => return None,
    };
    Some((plan, interval))
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
            log(&format!(
                "price {key}: no active price with this lookup key"
            ));
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
        Some(recurring)
            if recurring.interval == interval.as_str() && recurring.interval_count == 1 => {}
        _ => return Err("the recurring interval does not match the lookup key"),
    }
    let spec = plan.spec();
    match plan {
        Plan::Personal | Plan::Team => {
            if price.billing_scheme.as_deref().unwrap_or("per_unit") != "per_unit" {
                return Err("the billing scheme is not per_unit");
            }
            let amount = price
                .unit_amount
                .filter(|a| *a > 0)
                .ok_or("no unit amount")?;
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
            let amount = first
                .flat_amount
                .filter(|a| *a > 0)
                .ok_or("tier 1 has no flat amount")?;
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
    /// `APASSY_CONNECT_AUTO_RAISE_SEATS` (default off): the maintenance pass raises the
    /// quantity of an entitled group to its active members at Stripe, with a proration.
    /// Off, the members beyond the paid quantity stay `read_only` until the owner raises
    /// the seats (`POST /v1/account/group/seats`).
    pub auto_raise_seats: bool,
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            site_url: DEFAULT_SITE_URL.to_owned(),
            family_extra_cents: 100,
            family_extra_year_cents: 1000,
            durations: Durations::default(),
            auto_raise_seats: false,
        }
    }
}

impl BillingConfig {
    /// Reads the settings with `lookup` (the environment in the relay):
    /// `APASSY_CONNECT_SITE_URL`, `APASSY_CONNECT_FAMILY_EXTRA_CENTS` (default 100),
    /// `APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS` (default 1000),
    /// `APASSY_CONNECT_GRACE_DAYS` (14, 1 to 60), `APASSY_CONNECT_READ_ONLY_DAYS` (30, 1 to
    /// 365), `APASSY_CONNECT_DELETE_DAYS` (90, above the read-only days, at most 730),
    /// `APASSY_CONNECT_AUTO_RAISE_SEATS` (`0` or `1`, default `0`).
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
                return Err(RelayError::invalid(format!(
                    "{name} must be {min} to {max}."
                )));
            }
            Ok(value)
        };
        let family_extra_cents = number("APASSY_CONNECT_FAMILY_EXTRA_CENTS", 100, 0, 100_000)?;
        let family_extra_year_cents =
            number("APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS", 1000, 0, 1_000_000)?;
        let grace_days = number("APASSY_CONNECT_GRACE_DAYS", 14, 1, 60)?;
        let read_only_days = number("APASSY_CONNECT_READ_ONLY_DAYS", 30, 1, 365)?;
        let delete_days = number("APASSY_CONNECT_DELETE_DAYS", 90, read_only_days + 1, 730)?;
        let auto_raise_seats = match lookup("APASSY_CONNECT_AUTO_RAISE_SEATS")
            .as_deref()
            .map(str::trim)
        {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => {
                return Err(RelayError::invalid(
                    "APASSY_CONNECT_AUTO_RAISE_SEATS is 0 or 1.",
                ));
            }
        };
        Ok(Self {
            site_url,
            family_extra_cents,
            family_extra_year_cents,
            durations: Durations {
                grace_days,
                read_only_days,
                delete_days,
            },
            auto_raise_seats,
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

    /// The statuses a Stripe subscription never leaves.
    pub fn is_final(self) -> bool {
        matches!(self, Self::Canceled | Self::IncompleteExpired)
    }

    /// The statuses under which Stripe charges, or will charge, the customer.
    pub fn charges(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Trialing | Self::PastDue | Self::Incomplete | Self::Unpaid
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

    /// A member beyond the people or seats its group pays for: read-only without times,
    /// until the quantity is raised. Its stores are never deleted for it.
    const BEYOND_SEATS: Self = Self {
        status: PlanStatus::ReadOnly,
        ..Self::NONE
    };

    /// The order of states when an account has more than one: an entitled state, then
    /// read-only, suspended, pending.
    fn rank(&self) -> u8 {
        match self.status {
            _ if self.entitled => 4,
            PlanStatus::ReadOnly => 3,
            PlanStatus::Suspended => 2,
            PlanStatus::Pending => 1,
            _ => 0,
        }
    }

    /// New store, push, dial, entitlement token: entitled only. Pull and download: also
    /// read-only.
    pub fn allows(&self, capability: Capability) -> bool {
        match capability {
            Capability::NewStore
            | Capability::Push
            | Capability::Dial
            | Capability::EntitlementToken => self.entitled,
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

    fn from_state(
        state: &PlanState,
        row: Option<&SubscriptionRow>,
        group_id: Option<&str>,
    ) -> Self {
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
    /// A quantity that Stripe accepted from Connect (a confirm, a seats change) and when,
    /// until a later subscription event carries Stripe's word again.
    pub requested_quantity: Option<u32>,
    pub requested_at: Option<u64>,
    /// When the plan of a group's subscription left the group's kind (a portal switch from
    /// Family to Personal): its members' plan ended then.
    pub kind_left_at: Option<u64>,
    /// When the maintenance pass last read this subscription from Stripe.
    pub checked_at: Option<u64>,
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
            requested_quantity: None,
            requested_at: None,
            kind_left_at: None,
            checked_at: None,
        }
    }

    /// The quantity at Stripe: the one Stripe accepted from Connect after the last
    /// subscription event (Stripe applies it at once), else the stored one.
    pub fn effective_quantity(&self) -> u32 {
        self.requested_quantity.unwrap_or(self.quantity)
    }

    /// The active members, the owner included, that the subscription pays for: its
    /// quantity, and for Family at least the people its price includes.
    pub fn seats_paid(&self) -> u32 {
        let quantity = self.effective_quantity();
        match self.plan {
            Some(plan) if plan.group_kind().is_some() => quantity.max(plan.spec().included),
            _ => quantity,
        }
    }

    /// True for a Family or Team subscription bound to a group of its own kind.
    fn fits(&self, group: &GroupRow) -> bool {
        self.group_id.as_deref() == Some(group.group_id.as_str())
            && self.plan.and_then(Plan::group_kind) == Some(group.kind)
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

/// The open checkout session of an account (`stripe_customer.checkout_*`): a repeated
/// click for the same request gets it while Stripe shows it open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenCheckout {
    pub session_id: String,
    /// A hash of the plan, the interval, the count, and the price id.
    pub request: String,
    pub expires_at: u64,
}

/// A Stripe object that Connect could not apply for a known account or customer
/// (`billing_problem`): the operator looks at it in the Stripe dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The subscription or checkout session id: one row for each.
    pub object: String,
    pub account: Option<String>,
    pub customer: Option<String>,
    pub event: Option<String>,
    /// A short fixed reason (`bound_elsewhere`, `unknown_price`, `deleted_account`, …).
    pub reason: &'static str,
    pub at: u64,
}

/// An open problem row (for the operator command).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProblemRow {
    pub id: u64,
    pub object: String,
    pub account_id: Option<String>,
    pub customer_id: Option<String>,
    pub reason: String,
    pub first_at: u64,
    pub last_at: u64,
    pub events: u64,
}

/// The clock of the deletion pass (`billing_clock`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BillingClock {
    /// The relay's time at the last billing pass.
    pub last_pass_at: Option<u64>,
    /// The latest time seen from Stripe: the `t` of a verified webhook, or the `Date` of a
    /// Stripe answer.
    pub stripe_time: Option<u64>,
    /// Set when a pass found a gap longer than `MAX_PASS_GAP`: deletions wait for the
    /// operator.
    pub held_since: Option<u64>,
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
    /// Every member of a group, pending or active, the owner included.
    fn group_size(&mut self, group_id: &str) -> RelayResult<u32>;
    /// Gives a group another kind (the owner alone in it bought the other plan) and drops
    /// its open invites.
    fn set_group_kind(&mut self, group_id: &str, kind: GroupKind) -> RelayResult<()>;
    /// The place of an active member among the active members of its group, from 0: the
    /// owner first, then the earliest confirmed. `None` for an account that is not active.
    fn member_rank(&mut self, group_id: &str, account: &str) -> RelayResult<Option<u32>>;
    /// Every subscription bound to a group.
    fn subscriptions_of_group(&mut self, group_id: &str) -> RelayResult<Vec<SubscriptionRow>>;
    /// The subscriptions whose status is `active`, `trialing`, or `past_due`.
    fn live_subscriptions(&mut self) -> RelayResult<Vec<SubscriptionRow>>;
    fn open_checkout(&mut self, account: &str) -> RelayResult<Option<OpenCheckout>>;
    /// Sets the open checkout of the account that owns a customer row.
    fn set_open_checkout(&mut self, account: &str, open: Option<&OpenCheckout>) -> RelayResult<()>;
    /// Records a problem, or counts one more event of an open one. One row for each
    /// object: a row that opens again, or an open row of another reason, takes the new
    /// reason (the audit trail keeps the earlier one). True for a new or a reopened row,
    /// or a new reason (the caller writes no audit row of its own).
    fn record_problem(&mut self, problem: &Problem) -> RelayResult<bool>;
    /// Closes the open problem of `object` when its reason is `reason`: Connect resolved
    /// it itself, `how` says how (in the audit row). False when no such problem is open.
    fn close_problem(
        &mut self,
        object: &str,
        reason: &str,
        how: &str,
        at: u64,
    ) -> RelayResult<bool>;
    fn open_problems(&mut self) -> RelayResult<Vec<ProblemRow>>;
    /// Marks a problem resolved; false when there is no open problem with that id.
    fn resolve_problem(&mut self, id: u64, at: u64) -> RelayResult<bool>;
    fn clock(&mut self) -> RelayResult<BillingClock>;
    fn put_clock(&mut self, clock: &BillingClock) -> RelayResult<()>;
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
    /// When each active member was confirmed, as a counter (the owner at 0).
    joined: BTreeMap<String, u64>,
    next_join: u64,
    checkouts: BTreeMap<String, OpenCheckout>,
    problems: BTreeMap<String, ProblemRow>,
    clock: BillingClock,
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

    /// Deletes an account as `DELETE /v1/account` does: its row and its group membership
    /// go; its subscription rows and its customer stay.
    pub fn remove_account(&self, account: &str) {
        let mut guard = self.lock();
        guard.accounts.remove(account);
        guard.members.remove(account);
        guard.joined.remove(account);
    }

    /// Adds an account to a group (C3 does this through invites and confirmations).
    pub fn add_member(&self, group_id: &str, account: &str, role: GroupRole, state: MemberState) {
        let mut guard = self.lock();
        let kind = guard
            .groups
            .get(group_id)
            .map_or(GroupKind::Family, |g| g.kind);
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
        if state == MemberState::Active {
            if !guard.joined.contains_key(account) {
                guard.next_join += 1;
                let order = guard.next_join;
                guard.joined.insert(account.to_owned(), order);
            }
        } else {
            guard.joined.remove(account);
        }
    }

    /// Removes an account from its group (C3's removal).
    pub fn remove_member(&self, account: &str) {
        let mut guard = self.lock();
        guard.members.remove(account);
        guard.joined.remove(account);
    }

    pub fn subscription(&self, id: &str) -> Option<SubscriptionRow> {
        self.lock().subscriptions.get(id).cloned()
    }

    /// Changes a stored subscription (a test's stand-in for an old row or a lost event).
    pub fn edit_subscription(&self, id: &str, edit: impl FnOnce(&mut SubscriptionRow)) {
        if let Some(row) = self.lock().subscriptions.get_mut(id) {
            edit(row);
        }
    }

    /// The open problems.
    pub fn problems(&self) -> Vec<ProblemRow> {
        self.lock().problems.values().cloned().collect()
    }

    pub fn clock(&self) -> BillingClock {
        self.lock().clock
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
        Ok(self
            .customers
            .values()
            .find(|c| c.account == account)
            .cloned())
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
        self.joined.insert(owner.to_owned(), 0);
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

    fn group_size(&mut self, group_id: &str) -> RelayResult<u32> {
        let count = self
            .members
            .values()
            .filter(|m| m.group_id == group_id)
            .count();
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    fn set_group_kind(&mut self, group_id: &str, kind: GroupKind) -> RelayResult<()> {
        if let Some(group) = self.groups.get_mut(group_id) {
            group.kind = kind;
        }
        for member in self.members.values_mut() {
            if member.group_id == group_id {
                member.kind = kind;
            }
        }
        Ok(())
    }

    fn member_rank(&mut self, group_id: &str, account: &str) -> RelayResult<Option<u32>> {
        let mut active: Vec<(bool, u64, &String)> = self
            .members
            .iter()
            .filter(|(_, m)| m.group_id == group_id && m.state == MemberState::Active)
            .map(|(id, m)| {
                (
                    m.role != GroupRole::Owner,
                    self.joined.get(id).copied().unwrap_or(u64::MAX),
                    id,
                )
            })
            .collect();
        active.sort();
        Ok(active
            .iter()
            .position(|(_, _, id)| id.as_str() == account)
            .map(|place| u32::try_from(place).unwrap_or(u32::MAX)))
    }

    fn subscriptions_of_group(&mut self, group_id: &str) -> RelayResult<Vec<SubscriptionRow>> {
        Ok(self
            .subscriptions
            .values()
            .filter(|s| s.group_id.as_deref() == Some(group_id))
            .cloned()
            .collect())
    }

    fn live_subscriptions(&mut self) -> RelayResult<Vec<SubscriptionRow>> {
        Ok(self
            .subscriptions
            .values()
            .filter(|s| {
                matches!(
                    s.status,
                    StripeStatus::Active | StripeStatus::Trialing | StripeStatus::PastDue
                )
            })
            .cloned()
            .collect())
    }

    fn open_checkout(&mut self, account: &str) -> RelayResult<Option<OpenCheckout>> {
        Ok(self.checkouts.get(account).cloned())
    }

    fn set_open_checkout(&mut self, account: &str, open: Option<&OpenCheckout>) -> RelayResult<()> {
        match open {
            Some(open) => self.checkouts.insert(account.to_owned(), open.clone()),
            None => self.checkouts.remove(account),
        };
        Ok(())
    }

    fn record_problem(&mut self, problem: &Problem) -> RelayResult<bool> {
        if let Some(row) = self.problems.get_mut(&problem.object) {
            row.last_at = problem.at;
            row.events += 1;
            if row.reason != problem.reason {
                row.reason = problem.reason.to_owned();
                return Ok(true);
            }
            return Ok(false);
        }
        let id = self.problems.values().map(|row| row.id).max().unwrap_or(0) + 1;
        self.problems.insert(
            problem.object.clone(),
            ProblemRow {
                id,
                object: problem.object.clone(),
                account_id: problem.account.clone(),
                customer_id: problem.customer.clone(),
                reason: problem.reason.to_owned(),
                first_at: problem.at,
                last_at: problem.at,
                events: 1,
            },
        );
        Ok(true)
    }

    fn close_problem(
        &mut self,
        object: &str,
        reason: &str,
        _how: &str,
        _at: u64,
    ) -> RelayResult<bool> {
        if self
            .problems
            .get(object)
            .is_some_and(|row| row.reason == reason)
        {
            self.problems.remove(object);
            return Ok(true);
        }
        Ok(false)
    }

    fn open_problems(&mut self) -> RelayResult<Vec<ProblemRow>> {
        Ok(self.problems.values().cloned().collect())
    }

    fn resolve_problem(&mut self, id: u64, _at: u64) -> RelayResult<bool> {
        let before = self.problems.len();
        self.problems.retain(|_, row| row.id != id);
        Ok(self.problems.len() < before)
    }

    fn clock(&mut self) -> RelayResult<BillingClock> {
        Ok(self.clock)
    }

    fn put_clock(&mut self, clock: &BillingClock) -> RelayResult<()> {
        self.clock = *clock;
        Ok(())
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

/// What `Billing::reconcile` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Stale live subscriptions read from Stripe and applied: (subscription, account).
    pub read: Vec<(String, String)>,
    /// Groups whose quantity was raised to their active members: (group, quantity).
    pub raised: Vec<(String, u32)>,
    /// Calls that failed; the next pass tries again.
    pub failed: usize,
}

/// Whether a pass may delete stores (`Billing::deletion_gate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionGate {
    Open,
    /// The gap since the last pass was longer than `MAX_PASS_GAP`; since this time.
    Held {
        since: u64,
    },
}

/// What Stripe shows for a subscription due for deletion (`Billing::verify_ended`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripeCheck {
    /// Stripe shows it ended, and the relay's clock agrees with Stripe's.
    Ended,
    /// Stripe shows it live; its state was applied.
    Live,
    /// The relay's clock is ahead of Stripe's by more than `MAX_CLOCK_AHEAD`.
    ClockAhead,
}

/// The billing part of `apassy-relay admin readiness` and `admin billing`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BillingStatus {
    /// Stripe objects that Connect could not apply for a known account or customer.
    pub open_problems: usize,
    pub deletions_held_since: Option<u64>,
    pub last_pass_at: Option<u64>,
    pub stripe_time: Option<u64>,
}

/// Parses a strict JSON request body.
pub fn parse_request<T: for<'de> Deserialize<'de>>(body: &[u8]) -> RelayResult<T> {
    if body.len() > 64 * 1024 {
        return Err(RelayError::new(
            codes::PAYLOAD_TOO_LARGE,
            "The body is larger than 64 KiB.",
        ));
    }
    serde_json::from_slice(body).map_err(|_| RelayError::invalid("The request body is not valid."))
}

// ---------------------------------------------------------------------------------------
// The handlers.

/// Locks by name (a group or an account id), made on first use. Unused entries go when
/// the map grows.
#[derive(Default)]
struct LockMap(Mutex<HashMap<String, Arc<Mutex<()>>>>);

impl LockMap {
    fn run<T>(&self, key: &str, f: impl FnOnce() -> T) -> T {
        let lock = {
            let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if map.len() > 1024 {
                map.retain(|_, lock| Arc::strong_count(lock) > 1);
            }
            Arc::clone(map.entry(key.to_owned()).or_default())
        };
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        f()
    }
}

/// Proof that the caller holds the lock of one group (`Billing::with_group_lock`).
pub struct GroupLocked {
    group_id: String,
}

impl GroupLocked {
    pub fn group_id(&self) -> &str {
        &self.group_id
    }
}

/// The plan of a group: its subscription of the group's kind with the best state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPlan {
    pub subscription: String,
    pub plan: Plan,
    pub state: PlanState,
    /// The quantity at Stripe (`SubscriptionRow::effective_quantity`).
    pub quantity: u32,
    /// The active members it pays for (`SubscriptionRow::seats_paid`).
    pub seats_paid: u32,
}

/// Billing: the storage, the Stripe client, the settings, and the webhook secret. The
/// relay makes one and calls its handlers from the routes.
pub struct Billing<S: BillingStore> {
    pub store: S,
    pub stripe: StripeClient,
    pub config: BillingConfig,
    webhook_secret: SecretString,
    log: LogSink,
    /// One lock for each group: a confirm, a seats change, and the quantity check of the
    /// maintenance pass count, compare, and activate under it.
    group_locks: LockMap,
    /// One lock for each account: a webhook that changes its subscriptions and the
    /// deletion of its stores never overlap.
    account_locks: LockMap,
    /// One lock for each account's checkout: two requests at once make one session.
    checkout_locks: LockMap,
}

impl<S: BillingStore> Billing<S> {
    pub fn new(
        store: S,
        stripe: StripeClient,
        config: BillingConfig,
        webhook_secret: SecretString,
    ) -> RelayResult<Self> {
        stripe::check_webhook_secret(&webhook_secret)?;
        Ok(Self {
            store,
            stripe,
            config,
            webhook_secret,
            log: stripe::stderr_log(),
            group_locks: LockMap::default(),
            account_locks: LockMap::default(),
            checkout_locks: LockMap::default(),
        })
    }

    /// Runs `f` under the lock of `group_id`. Do not call `request_group_quantity` or
    /// `change_seats` inside: they take the same lock.
    pub fn with_group_lock<T>(&self, group_id: &str, f: impl FnOnce(&GroupLocked) -> T) -> T {
        self.group_locks.run(group_id, || {
            f(&GroupLocked {
                group_id: group_id.to_owned(),
            })
        })
    }

    /// Runs `f` under the lock of `account`.
    pub fn with_account_lock<T>(&self, account: &str, f: impl FnOnce() -> T) -> T {
        self.account_locks.run(account, f)
    }

    /// The same billing with another log sink (the tests capture lines).
    pub fn with_log(mut self, log: LogSink) -> Self {
        self.log = log;
        self
    }

    /// Writes one line to the billing log.
    pub fn log(&self, line: &str) {
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
    /// nothing here (the webhook binds the subscription). The checkouts of one account run
    /// one at a time, so two requests at once leave one open session.
    pub fn checkout(&self, account: &str, body: &[u8], now: u64) -> RelayResult<CheckoutAnswer> {
        let request: CheckoutRequest = parse_request(body)?;
        self.checkout_locks
            .run(account, || self.checkout_locked(account, &request, now))
    }

    fn checkout_locked(
        &self,
        account: &str,
        request: &CheckoutRequest,
        now: u64,
    ) -> RelayResult<CheckoutAnswer> {
        let count = match (request.plan, request.people, request.seats) {
            (Plan::Personal, None, None) => 1,
            (Plan::Family, Some(people), None) => people,
            (Plan::Team, None, Some(seats)) => seats,
            (Plan::Family, _, _) => {
                return Err(RelayError::invalid(
                    "A family checkout needs `people` and no `seats`.",
                ));
            }
            (Plan::Team, _, _) => {
                return Err(RelayError::invalid(
                    "A team checkout needs `seats` and no `people`.",
                ));
            }
            (Plan::Personal, _, _) => {
                return Err(RelayError::invalid(
                    "Connect Personal takes no `people` or `seats`.",
                ));
            }
        };
        check_count(request.plan, count)?;
        let durations = self.config.durations;
        let (customer, open) = self.store.transaction(|tx| {
            if !tx.account_exists(account)? {
                return Err(RelayError::not_found("account"));
            }
            // A member (pending or active) does not buy; its owner's plan covers it. An
            // owner whose plan lapsed may buy again: a plan of the group's kind keeps the
            // group, so it must pay for the members already in it. A plan of the other kind
            // takes the group only while the owner is alone in it (nobody active or
            // pending): the group then changes its kind when the subscription arrives.
            // Connect Personal leaves the group without a plan, so only an owner without
            // other active members buys it.
            if let Some(member) = tx.membership(account)? {
                if member.role != GroupRole::Owner {
                    return Err(RelayError::new(
                        codes::CONFLICT,
                        "This account is in a family or team. Its owner manages the plan.",
                    ));
                }
                let active = tx.active_members(&member.group_id)?;
                let has_members = match request.plan.group_kind() {
                    Some(kind) if kind == member.kind => false,
                    Some(_) => tx.group_size(&member.group_id)? > 1,
                    None => active > 1,
                };
                if has_members {
                    return Err(RelayError::new(
                        codes::CONFLICT,
                        match member.kind {
                            GroupKind::Family => {
                                "This account has a family with members. Buy Connect Family for them, or remove them first."
                            }
                            GroupKind::Team => {
                                "This account has a team with members. Buy Connect Team for them, or remove them first."
                            }
                        },
                    ));
                }
                if request.plan.group_kind() == Some(member.kind) && count < active {
                    return Err(below_members(request.plan, active));
                }
            }
            if account_plan(tx, account, now, &durations)?.entitled {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "This account has a plan. Change it in the billing portal.",
                ));
            }
            Ok((
                tx.customer_of_account(account)?.map(|row| row.customer),
                tx.open_checkout(account)?,
            ))
        })?;
        let prices = self.prices(now)?;
        let Some(price) = prices.get(request.plan, request.interval) else {
            self.log(&format!(
                "checkout refused: no usable price {}",
                lookup_key(request.plan, request.interval)
            ));
            return Err(RelayError::new(
                codes::BUSY,
                "This plan cannot be bought now.",
            ));
        };
        if request.plan == Plan::Family
            && price.extra != Some(self.config.family_extra(request.interval))
        {
            self.log(&format!(
                "checkout refused: tier 2 of {} differs from the configured Family extra",
                lookup_key(request.plan, request.interval)
            ));
            return Err(RelayError::new(
                codes::BUSY,
                "This plan cannot be bought now.",
            ));
        }
        let request_hash = idempotency_key(
            "checkout-request",
            &[
                request.plan.as_str(),
                request.interval.as_str(),
                &count.to_string(),
                &price.price_id,
            ],
        );
        // Stripe's list of subscriptions is the truth, also for one whose events have not
        // arrived: a subscription that is not over (one beyond its grace, `unpaid`,
        // `paused`, or still `incomplete`) can still charge, so the account pays it or ends
        // it in the portal before it buys again, and never pays for two plans.
        if let Some(customer) = customer.as_deref() {
            self.refuse_live_subscription(account, customer)?;
        }
        // A repeated click for the same request gets the session Stripe still shows open.
        if customer.is_some()
            && let Some(open) = open.as_ref().filter(|open| {
                open.request == request_hash && open.expires_at > now.saturating_add(60)
            })
        {
            let session = self.stripe.checkout_session(&open.session_id)?;
            if session.status.as_deref() == Some("open")
                && let Some(url) = session.url
            {
                return Ok(CheckoutAnswer {
                    url,
                    session_id: session.id,
                    expires_at: session.expires_at,
                });
            }
        }
        // Every open session of the account ends before a new one, the stored one and
        // those Stripe lists for its customer: the account never holds two open sessions.
        // One that cannot be ended refuses the request (`503 busy`), so no new one is made
        // beside it. A session that completed just before it ended made a subscription:
        // the list is read again.
        if let Some(customer) = customer.as_deref()
            && self.end_sessions_locked(account, Some(customer), now)? > 0
        {
            self.refuse_live_subscription(account, customer)?;
        }
        // Every session names the account's own Stripe customer, made before the first
        // one: two checkouts of one account are two subscriptions of one customer, never
        // a second customer that the webhook cannot bind.
        let customer = match customer {
            Some(customer) => customer,
            None => self.make_customer(account)?,
        };
        let form = checkout_form(
            account,
            &price.price_id,
            count,
            request.plan,
            Some(&customer),
            &self.config.site_url,
        );
        // A fresh key for each new session: a retry of this call reuses it, and two
        // clicks at once are one after the other under the account's checkout lock (the
        // second gets the session the first stored). A key made of the request alone
        // would make Stripe answer a completed session again.
        let key = random_idempotency_key("checkout")?;
        let session = self.stripe.create_checkout_session(&form, &key)?;
        // Stored under the account's lock: the deletion of an ended plan's data checks for
        // a stored session under the same lock, so it sees this one or ran before it.
        self.with_account_lock(account, || {
            self.store.transaction(|tx| {
                tx.set_open_checkout(
                    account,
                    Some(&OpenCheckout {
                        session_id: session.id.clone(),
                        request: request_hash.clone(),
                        expires_at: session.expires_at,
                    }),
                )
            })
        })?;
        self.log(&format!(
            "checkout session {} made for {account}",
            session.id
        ));
        Ok(CheckoutAnswer {
            url: session.url,
            session_id: session.id,
            expires_at: session.expires_at,
        })
    }

    /// `409 conflict` when Stripe lists a subscription of the customer that is not over,
    /// or more subscriptions than Connect reads.
    fn refuse_live_subscription(&self, account: &str, customer: &str) -> RelayResult<()> {
        let at_stripe = self.stripe.customer_subscriptions(customer)?;
        self.note_stripe_time(at_stripe.date)?;
        if !at_stripe.complete {
            return Err(RelayError::new(
                codes::CONFLICT,
                "This account has subscriptions at Stripe. Manage them in the billing portal.",
            ));
        }
        if let Some((id, status)) = at_stripe
            .list
            .iter()
            .find(|(_, status)| !StripeStatus::parse(status).is_final())
        {
            self.log(&format!(
                "checkout refused for {account}: subscription {id} is {status} at Stripe"
            ));
            return Err(RelayError::new(
                codes::CONFLICT,
                "This account has a subscription that is not over. Pay or end it in the billing portal.",
            ));
        }
        Ok(())
    }

    /// Ends one Checkout session at Stripe: done when Stripe expires it, or shows it is
    /// not open any more (it completed or expired before). Otherwise `503 busy`.
    fn end_session(&self, account: &str, id: &str) -> RelayResult<()> {
        if self
            .stripe
            .expire_checkout_session(id, &idempotency_key("expire", &[id]))
            .is_ok()
        {
            return Ok(());
        }
        match self.stripe.checkout_session(id) {
            Ok(session) if session.status.as_deref() != Some("open") => Ok(()),
            _ => {
                self.log(&format!(
                    "checkout session {id} of {account} could not be expired"
                ));
                Err(RelayError::new(
                    codes::BUSY,
                    "An open checkout could not be ended at Stripe. Try again later.",
                ))
            }
        }
    }

    /// Ends every open Checkout session of `account` at Stripe, for a caller that holds
    /// its checkout lock: those Stripe lists for its customer (page after page, also the
    /// ones Connect no longer stores) and the stored one; then the stored one is
    /// forgotten. Any failure is an error and the stored session stays. Answers how many
    /// sessions were ended.
    fn end_sessions_locked(
        &self,
        account: &str,
        customer: Option<&str>,
        now: u64,
    ) -> RelayResult<usize> {
        let stored = self.store.transaction(|tx| tx.open_checkout(account))?;
        let mut sessions: BTreeSet<String> = BTreeSet::new();
        if let Some(customer) = customer {
            let listed = self.stripe.customer_open_sessions(customer)?;
            if !listed.complete {
                self.log(&format!(
                    "the open checkout sessions of {account} are more than Connect reads"
                ));
                return Err(RelayError::new(
                    codes::BUSY,
                    "The open checkouts could not be read from Stripe. Try again later.",
                ));
            }
            sessions.extend(listed.list);
        }
        if let Some(open) = stored.as_ref().filter(|open| open.expires_at > now) {
            sessions.insert(open.session_id.clone());
        }
        for session in &sessions {
            self.end_session(account, session)?;
        }
        if let Some(open) = stored {
            self.store.transaction(|tx| {
                if tx
                    .open_checkout(account)?
                    .is_some_and(|stored| stored.session_id == open.session_id)
                {
                    tx.set_open_checkout(account, None)?;
                }
                Ok(())
            })?;
        }
        Ok(sessions.len())
    }

    /// Makes the Stripe customer of an account (`POST /v1/customers` with the account id
    /// in its metadata) and stores it. The key names the account, so two first checkouts
    /// at once get one customer.
    fn make_customer(&self, account: &str) -> RelayResult<String> {
        let made = self
            .stripe
            .create_customer(account, &idempotency_key("customer", &[account]))?;
        let customer = self.store.transaction(|tx| {
            if let Some(row) = tx.customer_of_account(account)? {
                return Ok(row.customer);
            }
            if tx
                .customer(&made)?
                .is_some_and(|row| row.account != account)
            {
                return Err(RelayError::new(
                    codes::UPSTREAM_FAILED,
                    "Stripe did not answer as expected.",
                ));
            }
            tx.put_customer(&CustomerRow {
                account: account.to_owned(),
                customer: made.clone(),
                email: None,
            })?;
            Ok(made.clone())
        })?;
        self.log(&format!("customer {customer} made for {account}"));
        Ok(customer)
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
        let session = self
            .stripe
            .create_portal_session(&customer, &return_url, &key)?;
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

    /// Asks Stripe for a new quantity of the group's subscription, under the lock of the
    /// group. For `change_seats`; C3's confirm uses `request_quantity_locked` under its
    /// own `with_group_lock`. Refuses a count outside `1 ≤ n ≤ max` or below the active
    /// members (`409 seat_limit`).
    pub fn request_group_quantity(
        &self,
        group_id: &str,
        quantity: u32,
        now: u64,
    ) -> RelayResult<SeatsAnswer> {
        self.with_group_lock(group_id, |locked| {
            self.request_quantity_locked(locked, quantity, now)
        })
    }

    /// The plan of a group: its subscription of the group's kind with the best state
    /// (entitled first), or `None`.
    pub fn group_plan(&self, group_id: &str, now: u64) -> RelayResult<Option<GroupPlan>> {
        let durations = self.config.durations;
        self.store.transaction(|tx| {
            let Some(group) = tx.group(group_id)? else {
                return Ok(None);
            };
            Ok(
                group_subscription(tx, &group, now, &durations)?.map(|(row, state)| GroupPlan {
                    subscription: row.id.clone(),
                    plan: row.plan.unwrap_or(Plan::Family),
                    state,
                    quantity: row.effective_quantity(),
                    seats_paid: row.seats_paid(),
                }),
            )
        })
    }

    /// The quantity of `GET /v1/account/group`: the quantity at Stripe of the group's
    /// plan, or without one of the group's newest subscription (a group always has one).
    pub fn group_quantity(&self, group_id: &str, now: u64) -> RelayResult<Option<u32>> {
        if let Some(plan) = self.group_plan(group_id, now)? {
            return Ok(Some(plan.quantity));
        }
        self.store.transaction(|tx| {
            Ok(tx
                .subscriptions_of_group(group_id)?
                .into_iter()
                .max_by_key(|row| row.last_event_created)
                .map(|row| row.effective_quantity()))
        })
    }

    /// `request_group_quantity` for a caller that holds the group's lock. The quantity
    /// Stripe accepts is recorded on the subscription (`requested_quantity`) until its
    /// webhook carries it, so the next count under the lock compares with it.
    pub fn request_quantity_locked(
        &self,
        locked: &GroupLocked,
        quantity: u32,
        now: u64,
    ) -> RelayResult<SeatsAnswer> {
        let durations = self.config.durations;
        let group_id = locked.group_id();
        let (row, state, active) = self.store.transaction(|tx| {
            let group = tx
                .group(group_id)?
                .ok_or_else(|| RelayError::not_found("group"))?;
            let (row, state) = group_subscription(tx, &group, now, &durations)?
                .ok_or_else(|| RelayError::new(codes::PLAN_REQUIRED, PLAN_REQUIRED_TEXT))?;
            Ok((row, state, tx.active_members(group_id)?))
        })?;
        let plan = row
            .plan
            .ok_or_else(|| RelayError::not_found("plan of this group"))?;
        state.require(Capability::Push)?;
        check_count(plan, quantity)?;
        if quantity < active {
            return Err(below_members(plan, active));
        }
        if quantity == row.effective_quantity() {
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
        if let Err(error) = self.stripe.update_item_quantity(item, quantity, &key) {
            // A timeout or a 5xx does not tell whether Stripe took the change: Stripe's
            // item answers. Only a refusal, or an item still at another quantity, fails.
            if error.code != codes::BUSY
                || !self
                    .stripe
                    .item_quantity(item)
                    .is_ok_and(|at_stripe| at_stripe == quantity)
            {
                return Err(error);
            }
            self.log(&format!(
                "quantity {quantity} of {}: the answer was lost; Stripe's item has it",
                row.id
            ));
        }
        self.store.transaction(|tx| {
            if let Some(mut stored) = tx.subscription(&row.id)? {
                stored.requested_quantity = Some(quantity);
                stored.requested_at = Some(now);
                tx.put_subscription(&stored)?;
            }
            Ok(())
        })?;
        self.log(&format!(
            "quantity {quantity} asked for {} of group {group_id}",
            row.id
        ));
        Ok(SeatsAnswer {
            quantity,
            pending: true,
        })
    }

    /// For `DELETE /v1/account` (contract section 9), under the account's checkout lock,
    /// in this order:
    ///
    /// 1. every open Checkout session of the account ends at Stripe (those Stripe lists
    ///    for its customer and the stored one), so none can make a subscription later;
    /// 2. every subscription that is not final is canceled at once (`unpaid` and `paused`
    ///    too: Stripe could still charge them): the stored ones and those Stripe lists for
    ///    the customer, whose events may not have arrived;
    /// 3. Stripe's list is read once more, and a subscription that appeared in between (a
    ///    session that completed just before it ended) is canceled too.
    ///
    /// Then the email copy goes; the Stripe customer row stays for support. A Stripe error
    /// in any step refuses the deletion, and nothing here is deleted. Answers whether a
    /// subscription was canceled.
    pub fn cancel_for_account_deletion(&self, account: &str) -> RelayResult<bool> {
        self.checkout_locks
            .run(account, || self.cancel_for_deletion_locked(account))
    }

    fn cancel_for_deletion_locked(&self, account: &str) -> RelayResult<bool> {
        let now = crate::now_unix();
        let (rows, customer) = self.store.transaction(|tx| {
            Ok((
                tx.subscriptions_of_account(account)?,
                tx.customer_of_account(account)?.map(|row| row.customer),
            ))
        })?;
        self.end_sessions_locked(account, customer.as_deref(), now)?;
        let mut open: BTreeSet<String> = rows
            .iter()
            .filter(|row| !row.status.is_final())
            .map(|row| row.id.clone())
            .collect();
        let listed = |open: &mut BTreeSet<String>| -> RelayResult<()> {
            let Some(customer) = customer.as_deref() else {
                return Ok(());
            };
            let at_stripe = self.stripe.customer_subscriptions(customer)?;
            if !at_stripe.complete {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "This account has more subscriptions at Stripe than Connect reads. End them in the billing portal first.",
                ));
            }
            for (id, status) in at_stripe.list {
                if StripeStatus::parse(&status).is_final() {
                    open.remove(&id);
                } else {
                    open.insert(id);
                }
            }
            Ok(())
        };
        listed(&mut open)?;
        let mut canceled: BTreeSet<String> = BTreeSet::new();
        for id in &open {
            self.stripe.cancel_subscription(id)?;
            canceled.insert(id.clone());
        }
        let mut again = BTreeSet::new();
        listed(&mut again)?;
        let appeared: Vec<String> = again.difference(&canceled).cloned().collect();
        for id in &appeared {
            self.log(&format!(
                "subscription {id} of {account} appeared during the deletion; it is canceled too"
            ));
            self.stripe.cancel_subscription(id)?;
            canceled.insert(id.clone());
        }
        self.store.transaction(|tx| {
            if let Some(mut customer) = tx.customer_of_account(account)? {
                customer.email = None;
                tx.put_customer(&customer)?;
                tx.set_open_checkout(account, None)?;
            }
            Ok(())
        })?;
        Ok(!canceled.is_empty())
    }

    /// Ends the account's open Checkout sessions at Stripe (it joined a group), so none
    /// can make a subscription later, under the account's checkout lock: a checkout that
    /// runs at the same time stores its session first, and this call ends it. A session
    /// that cannot be ended stays stored, and the error says so: a subscription it makes
    /// later is recorded for the operator when it cannot bind.
    pub fn end_open_checkout(&self, account: &str, now: u64) -> RelayResult<()> {
        self.checkout_locks.run(account, || {
            let customer = self
                .store
                .transaction(|tx| Ok(tx.customer_of_account(account)?.map(|row| row.customer)))?;
            self.end_sessions_locked(account, customer.as_deref(), now)
                .map(drop)
        })
    }

    /// True while the account has a stored checkout session that has not expired. The
    /// deletion of an ended plan's data asks it under the account's lock, the lock under
    /// which a checkout stores its session.
    pub fn has_open_checkout(&self, account: &str, now: u64) -> RelayResult<bool> {
        self.store.transaction(|tx| {
            Ok(tx
                .open_checkout(account)?
                .is_some_and(|open| open.expires_at > now))
        })
    }

    /// The maintenance pass: prunes event ids older than 30 days and lists the ended
    /// plans whose stores are due for deletion. The caller checks each with
    /// `deletion_gate` and `verify_ended`, deletes them (an audit row with counts, I-4
    /// `forget`), and then calls `mark_stores_deleted`.
    pub fn maintenance(&self, now: u64) -> RelayResult<MaintenanceReport> {
        let durations = self.config.durations;
        self.store.transaction(|tx| {
            let events_pruned = tx.prune_events(now.saturating_sub(EVENT_RETENTION))?;
            let mut due = Vec::new();
            for row in tx.lapsed_subscriptions()? {
                // A due plan whose deletion did not finish (Stripe showed it ended, then
                // something kept its stores) is read from Stripe again a day later.
                if row
                    .checked_at
                    .is_some_and(|at| now < at.saturating_add(RECHECK_SECS))
                {
                    continue;
                }
                if let Some(delete_at) = due_time(&row, now, &durations) {
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

    /// True while the stores of this subscription are due for deletion (checked again
    /// under the account's lock, after Stripe was asked).
    pub fn still_due(&self, subscription: &str, now: u64) -> RelayResult<bool> {
        let durations = self.config.durations;
        self.store.transaction(|tx| {
            Ok(tx
                .subscription(subscription)?
                .is_some_and(|row| due_time(&row, now, &durations).is_some()))
        })
    }

    /// Whether the deletion of this due subscription takes the stores of its group's
    /// members too: only for a plan of the group's kind, and only when no subscription
    /// bound to the group still gives a plan (entitled, read-only, or suspended).
    pub fn deletes_members(&self, subscription: &str, now: u64) -> RelayResult<bool> {
        let durations = self.config.durations;
        self.store.transaction(|tx| {
            let Some(row) = tx.subscription(subscription)? else {
                return Ok(false);
            };
            let Some(group) = row.group_id.as_deref().map(|id| tx.group(id)).transpose()? else {
                return Ok(false);
            };
            let Some(group) = group else {
                return Ok(false);
            };
            if !row.fits(&group) {
                return Ok(false);
            }
            Ok(group_subscription(tx, &group, now, &durations)?.is_none())
        })
    }

    /// Asks Stripe for a subscription due for deletion and applies what Stripe shows (as a
    /// webhook would). `Ended` only when Stripe shows an ended status and the relay's
    /// clock is within `MAX_CLOCK_AHEAD` of the latest time it saw from Stripe. A Stripe
    /// that cannot be reached is an error: the pass tries again next time.
    ///
    /// A successful read is stamped (`checked_at`): the pass reads a due plan at most once
    /// in `RECHECK_SECS`.
    pub fn verify_ended(&self, subscription: &str, now: u64) -> RelayResult<StripeCheck> {
        let read = self.stripe.subscription(subscription)?;
        self.note_stripe_time(read.date)?;
        let status = text(&read.object, "/status").map_or(StripeStatus::Other, StripeStatus::parse);
        self.apply_read(&read.object, read.date, now)?;
        self.mark_checked(subscription, now)?;
        if !status.has_ended() {
            self.log(&format!(
                "subscription {subscription}: Stripe shows {}; its stores stay",
                status.as_str()
            ));
            return Ok(StripeCheck::Live);
        }
        let stripe_time = self.store.transaction(|tx| Ok(tx.clock()?.stripe_time))?;
        if stripe_time.is_none_or(|seen| now > seen.saturating_add(MAX_CLOCK_AHEAD)) {
            self.log(&format!(
                "subscription {subscription}: the relay's clock is ahead of Stripe's; no store is deleted"
            ));
            return Ok(StripeCheck::ClockAhead);
        }
        Ok(StripeCheck::Ended)
    }

    /// Whether the data of `account` must stay although a plan of it is due for deletion,
    /// and why (`None`: it may go). Asked before anything is deleted, for the buying
    /// account and for each member:
    ///
    /// - an open billing problem of the account or its customer: the operator looks first;
    /// - a stored checkout session that Stripe shows `open` or `complete` (a purchase whose
    ///   events have not arrived); an expired one is forgotten;
    /// - an open checkout session that Stripe lists for its customer;
    /// - a subscription of its customer at Stripe that is not over: anything but
    ///   `canceled` and `incomplete_expired`, except an `unpaid` or `paused` one that
    ///   Connect stores (its own state decides); also a list longer than Connect reads
    ///   (`MAX_LIST_PAGES` pages).
    ///
    /// An account without a Stripe customer has nothing at Stripe (every session names the
    /// customer, made before the first one): its open problems and its stored session
    /// decide. The deletion asks again, under the account's lock, for a stored session
    /// (`has_open_checkout`): a checkout stores its session under that lock.
    ///
    /// A Stripe error is an error: nothing is deleted, the next pass asks again.
    pub fn deletion_blocked(&self, account: &str) -> RelayResult<Option<&'static str>> {
        let (customer, open, problem, known) = self.store.transaction(|tx| {
            let customer = tx.customer_of_account(account)?.map(|row| row.customer);
            let problem = tx.open_problems()?.iter().any(|row| {
                row.account_id.as_deref() == Some(account)
                    || (customer.is_some() && row.customer_id == customer)
            });
            let known: BTreeSet<String> = tx
                .subscriptions_of_account(account)?
                .into_iter()
                .map(|row| row.id)
                .collect();
            Ok((customer, tx.open_checkout(account)?, problem, known))
        })?;
        if problem {
            return Ok(Some("an open billing problem"));
        }
        if let Some(open) = open {
            let session = self.stripe.checkout_session(&open.session_id)?;
            match session.status.as_deref() {
                Some("open" | "complete") => return Ok(Some("a checkout session")),
                _ => self.store.transaction(|tx| {
                    if tx
                        .open_checkout(account)?
                        .is_some_and(|stored| stored.session_id == open.session_id)
                    {
                        tx.set_open_checkout(account, None)?;
                    }
                    Ok(())
                })?,
            }
        }
        let Some(customer) = customer else {
            return Ok(None);
        };
        let sessions = self.stripe.customer_open_sessions(&customer)?;
        if !sessions.complete || !sessions.list.is_empty() {
            return Ok(Some("a checkout session"));
        }
        let at_stripe = self.stripe.customer_subscriptions(&customer)?;
        self.note_stripe_time(at_stripe.date)?;
        if !at_stripe.complete {
            return Ok(Some("more subscriptions at Stripe than Connect reads"));
        }
        let live = at_stripe.list.iter().any(|(id, status)| {
            let status = StripeStatus::parse(status);
            !(status.is_final() || (status.has_ended() && known.contains(id)))
        });
        Ok(live.then_some("a subscription at Stripe that is not over"))
    }

    /// Stamps the time of a successful read of a subscription from Stripe.
    fn mark_checked(&self, subscription: &str, now: u64) -> RelayResult<()> {
        self.store.transaction(|tx| {
            if let Some(mut stored) = tx.subscription(subscription)? {
                stored.checked_at = Some(now);
                tx.put_subscription(&stored)?;
            }
            Ok(())
        })
    }

    /// Whether this pass may delete stores (B10): every pass records its time; a gap
    /// longer than `MAX_PASS_GAP` since the last one holds deletions until the operator
    /// resumes them (`resume_deletions`).
    pub fn deletion_gate(&self, now: u64) -> RelayResult<DeletionGate> {
        let (gate, newly) = self.store.transaction(|tx| {
            let mut clock = tx.clock()?;
            let mut newly = false;
            if clock.held_since.is_none()
                && clock
                    .last_pass_at
                    .is_some_and(|last| now > last.saturating_add(MAX_PASS_GAP))
            {
                clock.held_since = Some(now);
                newly = true;
            }
            clock.last_pass_at = Some(now);
            tx.put_clock(&clock)?;
            Ok((
                clock
                    .held_since
                    .map_or(DeletionGate::Open, |since| DeletionGate::Held { since }),
                newly,
            ))
        })?;
        if newly {
            self.log(
                "the time since the last billing pass is longer than two days: no store is deleted until the operator resumes deletions",
            );
        }
        Ok(gate)
    }

    /// The operator's override of a held deletion (`apassy-relay admin billing
    /// --resume-deletions`): the current clock is taken as right.
    pub fn resume_deletions(&self, now: u64) -> RelayResult<BillingStatus> {
        self.store.transaction(|tx| {
            let mut clock = tx.clock()?;
            clock.held_since = None;
            clock.last_pass_at = Some(now);
            tx.put_clock(&clock)
        })?;
        self.status()
    }

    /// The operator marks a recorded problem resolved (after a refund or a cancel in the
    /// Stripe dashboard).
    pub fn resolve_problem(&self, id: u64, now: u64) -> RelayResult<BillingStatus> {
        if !self.store.transaction(|tx| tx.resolve_problem(id, now))? {
            return Err(RelayError::not_found("open billing problem"));
        }
        self.status()
    }

    /// The open problems, for `apassy-relay admin billing`.
    pub fn problems(&self) -> RelayResult<Vec<ProblemRow>> {
        self.store.transaction(|tx| tx.open_problems())
    }

    /// The billing part of the operator's readiness.
    pub fn status(&self) -> RelayResult<BillingStatus> {
        self.store.transaction(|tx| {
            let clock = tx.clock()?;
            Ok(BillingStatus {
                open_problems: tx.open_problems()?.len(),
                deletions_held_since: clock.held_since,
                last_pass_at: clock.last_pass_at,
                stripe_time: clock.stripe_time,
            })
        })
    }

    /// The reconciliation of the maintenance pass:
    ///
    /// - a live subscription whose period ended more than `STALE_PERIOD_SECS` ago (a
    ///   renewal or an end whose event did not arrive) is read from Stripe, at most once
    ///   in `RECHECK_SECS`, and Stripe's state is applied. The read runs outside the
    ///   account's lock; Stripe's answer is applied under it by the rules of an event;
    /// - a live Family or Team subscription without a group is bound again (its buyer may
    ///   have left the other group since); one that still cannot bind is recorded for the
    ///   operator (`no_group`) when no open problem names it;
    /// - a live Connect Personal subscription with a quantity above 1 (a portal switch
    ///   from Family that kept the people) is read from Stripe first, and gets quantity 1
    ///   at Stripe only when Stripe shows the same item, a price of Connect Personal, a
    ///   quantity above 1, and a status that charges; the quantity is recorded only while
    ///   the stored plan is still Connect Personal, and the `personal_quantity` problem
    ///   closes then;
    /// - only with `BillingConfig::auto_raise_seats`: a group whose active members exceed
    ///   the quantity of its entitled subscription gets that quantity raised to its
    ///   members (up to the plan's maximum), under the group's lock: the members joined
    ///   while they were paid for, or the owner bought again for fewer, and the members
    ///   beyond the quantity are not entitled until then. Stripe's refusal of a raise is
    ///   recorded for the operator (`raise_refused`), and that subscription is not raised
    ///   again while the problem is open. Without the setting (the default) the pass
    ///   raises no quantity: those members stay `read_only` until the owner raises the
    ///   seats, and no charge happens without an action of the owner.
    ///
    /// A failed call is counted and logged; the next pass tries again.
    pub fn reconcile(&self, now: u64) -> RelayResult<ReconcileReport> {
        self.reconcile_until(now, &|| false)
    }

    /// `reconcile` that stops between subscriptions and groups once `stop` answers true
    /// (the relay stops): what is left waits for the next pass.
    pub fn reconcile_until(
        &self,
        now: u64,
        stop: &dyn Fn() -> bool,
    ) -> RelayResult<ReconcileReport> {
        let durations = self.config.durations;
        let mut report = ReconcileReport::default();
        let live = self.store.transaction(|tx| tx.live_subscriptions())?;
        for row in &live {
            if stop() {
                return Ok(report);
            }
            let stale = row
                .period_end
                .is_some_and(|end| now > end.saturating_add(STALE_PERIOD_SECS));
            let recent = row
                .checked_at
                .is_some_and(|at| now < at.saturating_add(RECHECK_SECS));
            if !stale || recent {
                continue;
            }
            let result = self.stripe.subscription(&row.id).and_then(|read| {
                self.note_stripe_time(read.date)?;
                self.with_account_lock(&row.account, || {
                    self.apply_read(&read.object, read.date, now)
                })
            });
            self.mark_checked(&row.id, now)?;
            match result {
                Ok(()) => report.read.push((row.id.clone(), row.account.clone())),
                Err(_) => {
                    report.failed += 1;
                    self.log(&format!(
                        "subscription {}: it could not be read from Stripe; the next pass tries again",
                        row.id
                    ));
                }
            }
        }
        self.bind_groupless(now, &durations, stop)?;
        let live = self.store.transaction(|tx| tx.live_subscriptions())?;
        for row in live.iter().filter(|row| {
            row.plan == Some(Plan::Personal) && row.effective_quantity() > 1 && row.item.is_some()
        }) {
            if stop() {
                return Ok(report);
            }
            if self.personal_quantity(row, now).is_err() {
                report.failed += 1;
                self.log(&format!(
                    "subscription {}: quantity 1 could not be set; the next pass tries again",
                    row.id
                ));
            }
        }
        if !self.config.auto_raise_seats {
            return Ok(report);
        }
        let groups: BTreeSet<String> = self.store.transaction(|tx| {
            Ok(tx
                .live_subscriptions()?
                .into_iter()
                .filter_map(|row| row.group_id)
                .collect())
        })?;
        for group_id in groups {
            if stop() {
                return Ok(report);
            }
            let raised = self.with_group_lock(
                &group_id,
                |locked| -> Result<Option<u32>, (Option<Box<SubscriptionRow>>, RelayError)> {
                    let wanted = self
                        .store
                        .transaction(|tx| {
                            let Some(group) = tx.group(&group_id)? else {
                                return Ok(None);
                            };
                            let Some((row, state)) =
                                group_subscription(tx, &group, now, &durations)?
                            else {
                                return Ok(None);
                            };
                            let refused = tx.open_problems()?.iter().any(|problem| {
                                problem.object == row.id && problem.reason == "raise_refused"
                            });
                            let active = tx.active_members(&group_id)?;
                            let max = row.plan.map_or(1, |plan| plan.spec().max);
                            let wanted = active.min(max);
                            Ok(
                                (state.entitled && !refused && wanted > row.effective_quantity())
                                    .then_some((row, wanted)),
                            )
                        })
                        .map_err(|error| (None, error))?;
                    let Some((row, wanted)) = wanted else {
                        return Ok(None);
                    };
                    self.request_quantity_locked(locked, wanted, now)
                        .map_err(|error| (Some(Box::new(row)), error))?;
                    Ok(Some(wanted))
                },
            );
            match raised {
                Ok(Some(quantity)) => report.raised.push((group_id, quantity)),
                Ok(None) => {}
                Err((row, error)) => {
                    report.failed += 1;
                    if let Some(row) = row.filter(|_| error.code == codes::UPSTREAM_FAILED) {
                        let mut lines = Vec::new();
                        self.store.transaction(|tx| {
                            lines.clear();
                            record_problem(
                                tx,
                                &mut lines,
                                &format!("group {group_id}"),
                                Problem {
                                    object: row.id.clone(),
                                    account: Some(row.account.clone()),
                                    customer: Some(row.customer.clone()),
                                    event: None,
                                    reason: "raise_refused",
                                    at: now,
                                },
                            )
                        })?;
                        for line in &lines {
                            self.log(line);
                        }
                    } else {
                        self.log(&format!(
                            "group {group_id}: its quantity could not be raised to its members; the next pass tries again"
                        ));
                    }
                }
            }
        }
        Ok(report)
    }

    /// The part of `reconcile` for a stored Connect Personal subscription with a quantity
    /// above 1. Stripe's state decides, read first and applied as a read: only for the
    /// same item, a price of Connect Personal now, a quantity above 1, and a status that
    /// charges, the item gets quantity 1 (`create_prorations` is Stripe's default for an
    /// item update). The write requires the stored plan to be still Connect Personal and
    /// the item the same, and it closes the `personal_quantity` problem. A price Connect
    /// cannot map never changes a quantity.
    fn personal_quantity(&self, row: &SubscriptionRow, now: u64) -> RelayResult<()> {
        let read = self.stripe.subscription(&row.id)?;
        self.note_stripe_time(read.date)?;
        self.with_account_lock(&row.account, || {
            self.apply_read(&read.object, read.date, now)
        })?;
        let object = &read.object;
        let item = object.pointer("/items/data/0");
        let same_item = item.and_then(|item| text(item, "/id")) == row.item.as_deref();
        let personal = item
            .and_then(|item| item.pointer("/price"))
            .and_then(plan_of_price)
            .is_some_and(|(plan, _)| plan == Plan::Personal);
        let quantity = item.and_then(|item| number(item, "/quantity")).unwrap_or(1);
        let charges = text(object, "/status")
            .map_or(StripeStatus::Other, StripeStatus::parse)
            .charges();
        if !(same_item && personal && quantity > 1 && charges) {
            self.log(&format!(
                "subscription {}: Stripe shows no Connect Personal item with more than one unit; its quantity stays",
                row.id
            ));
            return Ok(());
        }
        let Some(item) = row.item.as_deref() else {
            return Ok(());
        };
        let key = idempotency_key(
            "personal-quantity",
            &[&row.id, &row.last_event_created.to_string()],
        );
        self.stripe.update_item_quantity(item, 1, &key)?;
        let mut lines = Vec::new();
        let recorded = self.with_account_lock(&row.account, || {
            self.store.transaction(|tx| {
                lines.clear();
                let Some(mut stored) = tx.subscription(&row.id)? else {
                    return Ok(false);
                };
                if stored.plan != Some(Plan::Personal) || stored.item != row.item {
                    return Ok(false);
                }
                stored.requested_quantity = Some(1);
                stored.requested_at = Some(now);
                tx.put_subscription(&stored)?;
                close_problem(
                    tx,
                    &mut lines,
                    &format!("pass {now}"),
                    &stored.id,
                    "personal_quantity",
                    "quantity_set_to_1",
                    now,
                )?;
                Ok(true)
            })
        })?;
        for line in &lines {
            self.log(line);
        }
        self.log(&if recorded {
            format!(
                "subscription {} is Connect Personal: quantity 1 asked from Stripe",
                row.id
            )
        } else {
            format!(
                "subscription {}: quantity 1 set at Stripe; the stored plan changed meanwhile, its webhook decides",
                row.id
            )
        });
        Ok(())
    }

    /// The part of `reconcile` for live Family or Team subscriptions without a group. A
    /// subscription that binds closes its `no_group` problem.
    fn bind_groupless(
        &self,
        now: u64,
        durations: &Durations,
        stop: &dyn Fn() -> bool,
    ) -> RelayResult<()> {
        let groupless: Vec<SubscriptionRow> = self.store.transaction(|tx| {
            Ok(tx
                .live_subscriptions()?
                .into_iter()
                .filter(|row| {
                    row.group_id.is_none() && row.plan.and_then(Plan::group_kind).is_some()
                })
                .collect())
        })?;
        for row in groupless {
            if stop() {
                return Ok(());
            }
            let mut lines = Vec::new();
            let tag = format!("pass {now}");
            self.with_account_lock(&row.account, || {
                self.store.transaction(|tx| {
                    lines.clear();
                    let Some(mut stored) = tx.subscription(&row.id)? else {
                        return Ok(());
                    };
                    if ensure_group(tx, &mut stored, now, durations, &mut lines, &tag)? {
                        if stored.group_id.is_some() {
                            tx.put_subscription(&stored)?;
                            close_problem(
                                tx,
                                &mut lines,
                                &tag,
                                &stored.id,
                                "no_group",
                                "bound_to_group",
                                now,
                            )?;
                        }
                        return Ok(());
                    }
                    if !tx
                        .open_problems()?
                        .iter()
                        .any(|problem| problem.object == stored.id)
                    {
                        record_problem(tx, &mut lines, &tag, no_group_problem(&stored, None, now))?;
                    }
                    Ok(())
                })
            })?;
            for line in &lines {
                self.log(line);
            }
        }
        Ok(())
    }

    /// Keeps the latest time seen from Stripe (B10).
    fn note_stripe_time(&self, time: Option<u64>) -> RelayResult<()> {
        let Some(time) = time else {
            return Ok(());
        };
        self.store.transaction(|tx| {
            let mut clock = tx.clock()?;
            if clock.stripe_time.is_none_or(|seen| time > seen) {
                clock.stripe_time = Some(time);
                tx.put_clock(&clock)?;
            }
            Ok(())
        })
    }

    /// Applies Stripe's answer to a read of a subscription that Connect stores, by the
    /// rules of a subscription event created at Stripe's time of the answer (`Date`).
    /// Without that time the read applies at the time of the last applied event, so the
    /// relay's own clock never becomes the event time of a subscription.
    fn apply_read(&self, object: &Value, date: Option<u64>, now: u64) -> RelayResult<()> {
        let durations = self.config.durations;
        let mut lines = Vec::new();
        self.store.transaction(|tx| {
            lines.clear();
            let id = text(object, "/id").unwrap_or("-");
            let Some(stored) = tx.subscription(id)? else {
                return Ok(());
            };
            let created = date.unwrap_or(stored.last_event_created);
            apply_subscription(
                tx,
                object,
                &SubscriptionSource {
                    kind: SubscriptionKind::Read,
                    created,
                    event: None,
                    tag: format!("read of {id}"),
                },
                now,
                &durations,
                &mut lines,
            )
            .map(|_| ())
        })?;
        for line in &lines {
            self.log(line);
        }
        Ok(())
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
    pub fn webhook(
        &self,
        signature: Option<&str>,
        body: &[u8],
        now: u64,
    ) -> RelayResult<WebhookOutcome> {
        if body.len() > MAX_WEBHOOK_BODY {
            return Err(RelayError::new(
                codes::PAYLOAD_TOO_LARGE,
                "The webhook body is larger than 256 KiB.",
            ));
        }
        let signed_at = match stripe::verify_signature(signature, body, &self.webhook_secret, now) {
            Ok(t) => t,
            Err(error) => return Err(self.signature_refused(error)),
        };
        let event: Event = serde_json::from_slice(body)
            .map_err(|_| RelayError::invalid("The Stripe event is not valid JSON."))?;
        if !is_stripe_id("evt_", &event.id) || event.kind.is_empty() || event.kind.len() > 100 {
            return Err(RelayError::invalid(
                "The Stripe event has no valid id or type.",
            ));
        }
        let durations = self.config.durations;
        // The event's account, so its effect and the deletion of its stores never overlap.
        let account = self.store.transaction(|tx| event_account(tx, &event))?;
        let mut lines = Vec::new();
        let mut apply = || {
            self.store.transaction(|tx| {
                lines.clear();
                if !tx.record_event(&event.id, &event.kind, now)? {
                    return Ok(WebhookEffect::Duplicate);
                }
                let mut clock = tx.clock()?;
                if clock.stripe_time.is_none_or(|seen| signed_at > seen) {
                    clock.stripe_time = Some(signed_at);
                    tx.put_clock(&clock)?;
                }
                apply_event(tx, &event, now, &durations, &mut lines)
            })
        };
        let effect = match &account {
            Some(account) => self.with_account_lock(account, apply)?,
            None => apply()?,
        };
        for line in &lines {
            self.log(line);
        }
        let duplicate = effect == WebhookEffect::Duplicate;
        if duplicate {
            self.log(&format!(
                "webhook {} ({}) is a repeat",
                event.id, event.kind
            ));
        }
        Ok(WebhookOutcome {
            answer: WebhookAnswer {
                received: true,
                duplicate,
            },
            effect,
        })
    }

    /// The checks of a webhook that need no body: a `Stripe-Signature` header with `t`
    /// and `v1`, `t` within 300 s. The route runs it before it reads the body.
    pub fn webhook_precheck(&self, signature: Option<&str>, now: u64) -> RelayResult<()> {
        stripe::check_signature_header(signature, now)
            .map(|_| ())
            .map_err(|error| self.signature_refused(error))
    }

    fn signature_refused(&self, error: SignatureError) -> RelayError {
        self.log(&format!(
            "webhook refused: {}",
            match error {
                SignatureError::Header => "no usable Stripe-Signature header",
                SignatureError::Timestamp => "the signature time is outside 300 s",
                SignatureError::Mismatch => "the signature does not verify",
            }
        ));
        RelayError::invalid("The Stripe signature does not verify.")
    }
}

/// The account a webhook event changes, if Connect can tell before it applies it.
fn event_account(tx: &mut dyn BillingTx, event: &Event) -> RelayResult<Option<String>> {
    let object = &event.data.object;
    let stored = |tx: &mut dyn BillingTx, id: Option<&str>| -> RelayResult<Option<String>> {
        Ok(match id.filter(|id| is_stripe_id("sub_", id)) {
            Some(id) => tx.subscription(id)?.map(|row| row.account),
            None => None,
        })
    };
    Ok(match event.kind.as_str() {
        "checkout.session.completed" => text(object, "/client_reference_id")
            .filter(|account| is_account_id(account))
            .map(str::to_owned),
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => stored(tx, text(object, "/id"))?.or_else(|| {
            text(object, "/metadata/account_id")
                .filter(|account| is_account_id(account))
                .map(str::to_owned)
        }),
        "invoice.paid" | "invoice.payment_failed" => stored(
            tx,
            text(object, "/parent/subscription_details/subscription")
                .or_else(|| text(object, "/subscription")),
        )?,
        _ => None,
    })
}

const PLAN_REQUIRED_TEXT: &str = "This account is not on Apassy Connect.";

/// `409 seat_limit` for a count below the active members.
fn below_members(plan: Plan, active: u32) -> RelayError {
    seat_limit(match plan {
        Plan::Family => format!("The family has {active} people; choose at least {active}."),
        _ => format!("The team has {active} members; choose at least {active}."),
    })
}

fn not_in_group() -> RelayError {
    RelayError::new(
        codes::NOT_IN_GROUP,
        "This account is not in that family or team.",
    )
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

/// The deletion time of a subscription whose stores are due for deletion now: a lapsed
/// plan Connect could map, at `none`, not deleted yet.
fn due_time(row: &SubscriptionRow, now: u64, durations: &Durations) -> Option<u64> {
    if row.stores_deleted_at.is_some()
        || row.plan.is_none()
        || !(row.status == StripeStatus::PastDue || row.status.has_ended())
        || row.state(now, durations).status != PlanStatus::None
    {
        return None;
    }
    deletion_time(row, durations).filter(|delete_at| *delete_at <= now)
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
        // Stripe saves the business name of a collected tax id on the customer: with an
        // existing customer it needs `customer_update[name]=auto` for that.
        if plan == Plan::Team {
            form.push("customer_update[name]", "auto");
        }
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

/// The plan of an account: its own subscriptions, and for an active member of a Family or
/// Team every subscription bound to its group. The best state wins (`PlanState::rank`:
/// entitled, then read-only, suspended, pending); then the newest. A subscription whose
/// price Connect cannot map gives no plan.
///
/// For a member, a subscription of the group's kind gives its state only to the members
/// it pays for (the owner first, then the earliest confirmed); the others are read-only
/// without times. A subscription that left the group's kind (a switch to Personal) gives
/// its members the read-only window of an ended plan from that switch, without a
/// deletion day: the stores of a member are never deleted for a plan that is not its
/// group's.
fn account_plan(
    tx: &mut dyn BillingTx,
    account: &str,
    now: u64,
    durations: &Durations,
) -> RelayResult<PlanView> {
    let mut candidates: Vec<(PlanState, SubscriptionRow, Option<String>)> = Vec::new();
    for row in tx.subscriptions_of_account(account)? {
        if row.plan.is_none() {
            continue;
        }
        let state = row.state(now, durations);
        let group = match row.group_id.as_deref() {
            Some(id) => tx.group(id)?.filter(|group| row.fits(group)),
            None => None,
        };
        candidates.push((state, row, group.map(|group| group.group_id)));
    }
    if let Some(member) = tx.membership(account)?
        && member.state == MemberState::Active
        && member.role != GroupRole::Owner
        && let Some(group) = tx.group(&member.group_id)?
    {
        let rank = tx.member_rank(&group.group_id, account)?;
        for row in tx.subscriptions_of_group(&group.group_id)? {
            if row.plan.is_none() {
                continue;
            }
            let state = if row.fits(&group) {
                let state = row.state(now, durations);
                if state.entitled && rank.is_none_or(|rank| rank >= row.seats_paid()) {
                    PlanState::BEYOND_SEATS
                } else {
                    state
                }
            } else {
                let Some(left) = row.kind_left_at else {
                    continue;
                };
                let ended = plan_state(
                    &PlanInput {
                        stripe_status: Some(StripeStatus::Canceled),
                        cancel_at_period_end: false,
                        period_end: None,
                        first_failed_at: None,
                        ended_at: Some(left),
                        now,
                    },
                    durations,
                );
                PlanState {
                    delete_at: None,
                    ..ended
                }
            };
            candidates.push((state, row, Some(group.group_id.clone())));
        }
    }
    let best = candidates
        .iter()
        .filter(|(state, _, _)| state.status != PlanStatus::None)
        .max_by_key(|(state, row, _)| (state.rank(), row.last_event_created));
    Ok(match best {
        Some((state, row, group)) => PlanView::from_state(state, Some(row), group.as_deref()),
        None => PlanView::none(),
    })
}

/// The subscription that carries a group's plan: bound to the group and of its kind, the
/// best state first (entitled, then read-only, suspended, pending), then the newest. A
/// late event of an older subscription never hides a paid one. `None` when every such
/// subscription is at `none`.
fn group_subscription(
    tx: &mut dyn BillingTx,
    group: &GroupRow,
    now: u64,
    durations: &Durations,
) -> RelayResult<Option<(SubscriptionRow, PlanState)>> {
    Ok(tx
        .subscriptions_of_group(&group.group_id)?
        .into_iter()
        .filter(|row| row.fits(group))
        .map(|row| (row.state(now, durations), row))
        .filter(|(state, _)| state.status != PlanStatus::None)
        .max_by_key(|(state, row)| (state.rank(), row.last_event_created))
        .map(|(state, row)| (row, state)))
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
            let customer = text(object, "/customer").filter(|c| is_stripe_id("cus_", c));
            let subscription = text(object, "/subscription").filter(|s| is_stripe_id("sub_", s));
            // A session that made a subscription Connect cannot bind is recorded for the
            // operator when its account or its customer is known: it charges.
            let problem = |tx: &mut dyn BillingTx,
                           lines: &mut Vec<String>,
                           account: Option<&str>,
                           reason: &'static str,
                           why: &str| {
                if subscription.is_some()
                    && (account.is_some()
                        || customer.is_some_and(|c| tx.customer(c).ok().flatten().is_some()))
                {
                    record_problem(
                        tx,
                        lines,
                        &tag,
                        Problem {
                            object: subscription.unwrap_or(session).to_owned(),
                            account: account.map(str::to_owned),
                            customer: customer.map(str::to_owned),
                            event: Some(event.id.clone()),
                            reason,
                            at: now,
                        },
                    )?;
                }
                ignore(lines, why)
            };
            let (Some(account), Some(meta)) = (reference, metadata) else {
                return problem(
                    tx,
                    lines,
                    None,
                    "no_account",
                    &format!("session {session} names no account"),
                );
            };
            if account != meta || !is_account_id(account) || !tx.account_exists(account)? {
                return problem(
                    tx,
                    lines,
                    None,
                    "unknown_account",
                    &format!("session {session} names an unknown account"),
                );
            }
            let (Some(customer), Some(subscription)) = (customer, subscription) else {
                return ignore(
                    lines,
                    &format!("session {session} has no customer or subscription"),
                );
            };
            if let Some(bound) = tx.customer_of_account(account)?
                && bound.customer != customer
            {
                return problem(
                    tx,
                    lines,
                    Some(account),
                    "bound_elsewhere",
                    &format!("{account} is bound to another customer"),
                );
            }
            if let Some(bound) = tx.customer(customer)?
                && bound.account != account
            {
                return problem(
                    tx,
                    lines,
                    Some(account),
                    "bound_elsewhere",
                    &format!("customer {customer} is bound to another account"),
                );
            }
            if let Some(row) = tx.subscription(subscription)?
                && (row.account != account || row.customer != customer)
            {
                return problem(
                    tx,
                    lines,
                    Some(account),
                    "bound_elsewhere",
                    &format!("subscription {subscription} is bound elsewhere"),
                );
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
            if tx
                .open_checkout(account)?
                .is_some_and(|open| open.session_id == session)
            {
                tx.set_open_checkout(account, None)?;
            }
            let mut row = tx
                .subscription(subscription)?
                .unwrap_or_else(|| SubscriptionRow::bound(subscription, customer, account));
            if ensure_group(tx, &mut row, now, durations, lines, &tag)? {
                if row.group_id.is_some() {
                    close_problem(tx, lines, &tag, &row.id, "no_group", "bound_to_group", now)?;
                }
            } else if row.status.charges() {
                record_problem(
                    tx,
                    lines,
                    &tag,
                    no_group_problem(&row, Some(&event.id), now),
                )?;
            }
            tx.put_subscription(&row)?;
            lines.push(format!("{tag}: {subscription} bound to {account}"));
            Ok(WebhookEffect::Applied {
                account: account.to_owned(),
            })
        }
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted" => apply_subscription(
            tx,
            object,
            &SubscriptionSource {
                kind: match event.kind.as_str() {
                    "customer.subscription.created" => SubscriptionKind::Created,
                    "customer.subscription.deleted" => SubscriptionKind::Deleted,
                    _ => SubscriptionKind::Updated,
                },
                created: event.created,
                event: Some(event.id.clone()),
                tag: tag.clone(),
            },
            now,
            durations,
            lines,
        ),
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
                return ignore(
                    lines,
                    &format!("{id}: older than the last applied invoice event"),
                );
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
                row.first_failed_at
                    .map_or("cleared".to_owned(), |t| t.to_string())
            ));
            Ok(WebhookEffect::Applied {
                account: row.account,
            })
        }
        _ => {
            lines.push(format!("{tag}: stored, no effect"));
            Ok(WebhookEffect::Ignored)
        }
    }
}

/// Records a problem in the transaction of its event, with a log line.
fn record_problem(
    tx: &mut dyn BillingTx,
    lines: &mut Vec<String>,
    tag: &str,
    problem: Problem,
) -> RelayResult<()> {
    let new = tx.record_problem(&problem)?;
    lines.push(format!(
        "{tag}: recorded for the operator: {} ({}){}",
        problem.object,
        problem.reason,
        if new { "" } else { ", again" }
    ));
    Ok(())
}

/// Closes the open problem of `object` with `reason`, which Connect resolved itself
/// (`how`), with a log line.
fn close_problem(
    tx: &mut dyn BillingTx,
    lines: &mut Vec<String>,
    tag: &str,
    object: &str,
    reason: &str,
    how: &str,
    at: u64,
) -> RelayResult<()> {
    if tx.close_problem(object, reason, how, at)? {
        lines.push(format!(
            "{tag}: the problem of {object} ({reason}) is resolved: {how}"
        ));
    }
    Ok(())
}

/// Where a subscription object comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscriptionKind {
    Created,
    Updated,
    /// `customer.subscription.deleted`: the status is `canceled`.
    Deleted,
    /// Stripe's answer to Connect's read (the maintenance pass).
    Read,
}

struct SubscriptionSource {
    kind: SubscriptionKind,
    /// The event's `created`, or the time of the read.
    created: u64,
    event: Option<String>,
    tag: String,
}

/// Applies a Stripe subscription object (an event's or a read's) to its stored row.
///
/// A stored subscription keeps its customer and account; a new one needs a known account
/// in `metadata.account_id` whose customer is this one. The plan and interval come from
/// the price (`plan_of_price`), else the stored ones stay: a price that lost its lookup
/// key never stops the status from applying. `canceled` and `incomplete_expired` are
/// final. A subscription that cannot apply, of a known account or customer, is recorded
/// for the operator.
fn apply_subscription(
    tx: &mut dyn BillingTx,
    object: &Value,
    source: &SubscriptionSource,
    now: u64,
    durations: &Durations,
    lines: &mut Vec<String>,
) -> RelayResult<WebhookEffect> {
    let tag = source.tag.as_str();
    let ignore = |lines: &mut Vec<String>, why: &str| {
        lines.push(format!("{tag}: ignored: {why}"));
        Ok(WebhookEffect::Ignored)
    };
    let Some(id) = text(object, "/id").filter(|id| is_stripe_id("sub_", id)) else {
        return ignore(lines, "no subscription id");
    };
    let Some(customer) = text(object, "/customer").filter(|c| is_stripe_id("cus_", c)) else {
        return ignore(lines, &format!("{id} has no customer"));
    };
    let status = if source.kind == SubscriptionKind::Deleted {
        StripeStatus::Canceled
    } else {
        text(object, "/status").map_or(StripeStatus::Other, StripeStatus::parse)
    };
    let metadata = text(object, "/metadata/account_id");
    let problem = |tx: &mut dyn BillingTx,
                   lines: &mut Vec<String>,
                   account: Option<&str>,
                   reason: &'static str,
                   why: &str|
     -> RelayResult<WebhookEffect> {
        if status.charges() {
            record_problem(
                tx,
                lines,
                tag,
                Problem {
                    object: id.to_owned(),
                    account: account.map(str::to_owned),
                    customer: Some(customer.to_owned()),
                    event: source.event.clone(),
                    reason,
                    at: now,
                },
            )?;
        }
        ignore(lines, why)
    };
    let existing = tx.subscription(id)?;
    let account = match &existing {
        Some(row) => {
            if row.customer != customer || metadata.is_some_and(|meta| meta != row.account) {
                return problem(
                    tx,
                    lines,
                    Some(row.account.as_str()),
                    "bound_elsewhere",
                    &format!("{id} does not match its stored customer or account"),
                );
            }
            row.account.clone()
        }
        None => {
            let known = tx.customer(customer)?;
            let Some(account) = metadata.filter(|a| is_account_id(a)) else {
                return match known {
                    Some(bound) => problem(
                        tx,
                        lines,
                        Some(&bound.account),
                        "no_account",
                        &format!("{id} names no account"),
                    ),
                    None => ignore(lines, &format!("{id} names no account")),
                };
            };
            if !tx.account_exists(account)? {
                return match known {
                    Some(bound) => problem(
                        tx,
                        lines,
                        Some(&bound.account),
                        "deleted_account",
                        &format!("{id} names an unknown account"),
                    ),
                    None => ignore(lines, &format!("{id} names an unknown account")),
                };
            }
            if let Some(bound) = known
                && bound.account != account
            {
                return problem(
                    tx,
                    lines,
                    Some(account),
                    "bound_elsewhere",
                    &format!("customer {customer} is bound to another account"),
                );
            }
            if let Some(bound) = tx.customer_of_account(account)?
                && bound.customer != customer
            {
                return problem(
                    tx,
                    lines,
                    Some(account),
                    "bound_elsewhere",
                    &format!("{account} is bound to another customer"),
                );
            }
            account.to_owned()
        }
    };
    let existing_row = existing.is_some();
    let mut row = existing.unwrap_or_else(|| SubscriptionRow::bound(id, customer, &account));
    if row.status.is_final() && !status.is_final() {
        return ignore(
            lines,
            &format!("{id} is {}, which is final", row.status.as_str()),
        );
    }
    let created_again = source.kind == SubscriptionKind::Created && row.last_event_created > 0;
    if source.created < row.last_event_created
        || (source.created == row.last_event_created && created_again)
    {
        return ignore(lines, &format!("{id}: older than the last applied event"));
    }
    // The account was deleted (its subscriptions were canceled then): a status that
    // charges again, in an event that applies (not final before, not older), is applied
    // and recorded for the operator.
    if existing_row && status.charges() && !tx.account_exists(&account)? {
        record_problem(
            tx,
            lines,
            tag,
            Problem {
                object: id.to_owned(),
                account: Some(account.clone()),
                customer: Some(customer.to_owned()),
                event: source.event.clone(),
                reason: "deleted_account",
                at: now,
            },
        )?;
    }
    let item = object.pointer("/items/data/0");
    let mapped = item
        .and_then(|item| item.pointer("/price"))
        .and_then(plan_of_price);
    let mapped_plan = mapped.map(|(plan, _)| plan);
    match mapped {
        Some((plan, interval)) => {
            row.lookup_key = Some(lookup_key(plan, interval).to_owned());
            row.plan = Some(plan);
            row.interval = Some(interval);
        }
        None if row.plan.is_some() => {
            lines.push(format!(
                "{tag}: {id}: the price is not one of Connect's; the stored plan stays"
            ));
        }
        None => {
            if status.charges() {
                record_problem(
                    tx,
                    lines,
                    tag,
                    Problem {
                        object: id.to_owned(),
                        account: Some(account.clone()),
                        customer: Some(customer.to_owned()),
                        event: source.event.clone(),
                        reason: "unknown_price",
                        at: now,
                    },
                )?;
            }
            lines.push(format!(
                "{tag}: {id}: the price is not one of Connect's; it gives no plan"
            ));
        }
    }
    // A plan of another kind than the group's (a portal switch from Family to Personal)
    // keeps the group; its members' plan ended at the switch.
    if let Some(group) = row
        .group_id
        .as_deref()
        .map(|g| tx.group(g))
        .transpose()?
        .flatten()
    {
        if row.plan.and_then(Plan::group_kind) == Some(group.kind) {
            row.kind_left_at = None;
        } else if row.plan.is_some() && row.kind_left_at.is_none() {
            row.kind_left_at = Some(source.created);
            lines.push(format!(
                "{tag}: {id} left the kind of its group {}",
                group.group_id
            ));
        }
    }
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
    row.quantity = quantity;
    // Stripe's word again once it carries Connect's quantity, or is clearly newer.
    if row.requested_quantity == Some(quantity)
        || row
            .requested_at
            .is_some_and(|at| source.created > at.saturating_add(REQUEST_SETTLE_SECS))
    {
        row.requested_quantity = None;
        row.requested_at = None;
    }
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
            .or(Some(source.created));
    } else {
        row.ended_at = None;
    }
    match status {
        StripeStatus::Active | StripeStatus::Trialing => {
            row.first_failed_at = None;
            row.stores_deleted_at = None;
        }
        StripeStatus::PastDue if row.first_failed_at.is_none() => {
            row.first_failed_at = Some(source.created);
        }
        _ => {}
    }
    row.last_event_created = source.created;
    if ensure_group(tx, &mut row, now, durations, lines, tag)? {
        // Bound now, or a plan that needs no group: a `no_group` problem is over.
        if row.group_id.is_some() || row.plan.and_then(Plan::group_kind).is_none() {
            close_problem(tx, lines, tag, id, "no_group", "bound_to_group", now)?;
        }
    } else if status.charges() {
        record_problem(
            tx,
            lines,
            tag,
            no_group_problem(&row, source.event.as_deref(), now),
        )?;
    }
    // Connect Personal is one account: a quantity above 1 (a portal switch from Family that
    // kept the people) is recorded for the operator, and the maintenance pass sets it to 1
    // at Stripe. Only a price of Connect Personal counts: a price Connect cannot map keeps
    // the stored plan but never asks for a quantity change. Stripe showing one unit,
    // another plan, or a status that does not charge closes the problem.
    if !(row.plan == Some(Plan::Personal) && row.quantity > 1 && status.charges()) {
        close_problem(
            tx,
            lines,
            tag,
            id,
            "personal_quantity",
            "stripe_shows_one_unit_or_another_plan",
            now,
        )?;
    }
    if mapped_plan == Some(Plan::Personal) && row.quantity > 1 && status.charges() {
        record_problem(
            tx,
            lines,
            tag,
            Problem {
                object: row.id.clone(),
                account: Some(account.clone()),
                customer: Some(customer.to_owned()),
                event: source.event.clone(),
                reason: "personal_quantity",
                at: now,
            },
        )?;
    }
    tx.put_subscription(&row)?;
    let state = row.state(now, durations);
    lines.push(format!(
        "{tag}: {id} of {account} is {} ({}, quantity {quantity}); entitled {} → {}",
        status.as_str(),
        row.lookup_key.as_deref().unwrap_or("no plan"),
        was_entitled,
        state.entitled
    ));
    Ok(WebhookEffect::Applied { account })
}

/// Makes the group of a Family or Team subscription, with the buyer as its owner, when it
/// has none yet; binds it to the group the buyer owns when that group is of its kind; and
/// gives the buyer's group the subscription's kind when the buyer is alone in it (nobody
/// active or pending) and no subscription of the group's kind is entitled. False when the
/// subscription stays without a group (the buyer is a member of another group, or owns
/// one of the other kind with members): the caller records it for the operator while it
/// charges. A buyer that no longer exists gets no group, and the answer is true: its
/// subscription is a `deleted_account` problem, not a `no_group` one.
fn ensure_group(
    tx: &mut dyn BillingTx,
    row: &mut SubscriptionRow,
    now: u64,
    durations: &Durations,
    lines: &mut Vec<String>,
    tag: &str,
) -> RelayResult<bool> {
    let Some(kind) = row.plan.and_then(Plan::group_kind) else {
        return Ok(true);
    };
    if row.group_id.is_some() {
        return Ok(true);
    }
    // An account that no longer exists gets no group (its subscription is recorded as
    // `deleted_account` while it charges).
    if !tx.account_exists(&row.account)? {
        lines.push(format!(
            "{tag}: {} no longer exists; {} gets no group",
            row.account, row.id
        ));
        return Ok(true);
    }
    let Some(member) = tx.membership(&row.account)? else {
        let group_id = tx.create_group(kind, &row.account, now)?;
        lines.push(format!("{tag}: group {group_id} made for {}", row.account));
        row.group_id = Some(group_id);
        return Ok(true);
    };
    if member.role == GroupRole::Owner && member.kind == kind {
        row.group_id = Some(member.group_id);
        return Ok(true);
    }
    if member.role == GroupRole::Owner
        && tx.group_size(&member.group_id)? == 1
        && let Some(group) = tx.group(&member.group_id)?
        && !group_subscription(tx, &group, now, durations)?.is_some_and(|(_, state)| state.entitled)
    {
        tx.set_group_kind(&group.group_id, kind)?;
        lines.push(format!(
            "{tag}: group {} of {} takes the kind of {}",
            group.group_id, row.account, row.id
        ));
        row.group_id = Some(group.group_id);
        return Ok(true);
    }
    lines.push(format!(
        "{tag}: {} is in another group; {} stays without a group",
        row.account, row.id
    ));
    Ok(false)
}

/// A Family or Team subscription that charges without a group: recorded for the operator
/// (`no_group`), who ends or refunds it in the Stripe dashboard.
fn no_group_problem(row: &SubscriptionRow, event: Option<&str>, now: u64) -> Problem {
    Problem {
        object: row.id.clone(),
        account: Some(row.account.clone()),
        customer: Some(row.customer.clone()),
        event: event.map(str::to_owned),
        reason: "no_group",
        at: now,
    }
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
        assert_eq!(
            BillingConfig::from_lookup(&none).unwrap(),
            BillingConfig::default()
        );
        let bad_delete =
            |name: &str| (name == "APASSY_CONNECT_DELETE_DAYS").then(|| "30".to_owned());
        assert!(BillingConfig::from_lookup(&bad_delete).is_err());
        let path = |name: &str| {
            (name == "APASSY_CONNECT_SITE_URL").then(|| "https://a.example/x".to_owned())
        };
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
        assert!(!config.auto_raise_seats);
        for (text, expected) in [
            ("0", Some(false)),
            ("1", Some(true)),
            (" 1 ", Some(true)),
            ("yes", None),
            ("2", None),
            ("", None),
        ] {
            let raise =
                |name: &str| (name == "APASSY_CONNECT_AUTO_RAISE_SEATS").then(|| text.to_owned());
            assert_eq!(
                BillingConfig::from_lookup(&raise)
                    .ok()
                    .map(|config| config.auto_raise_seats),
                expected,
                "{text:?}"
            );
        }
    }

    #[test]
    fn idempotency_keys_hide_their_parts() {
        let key = idempotency_key("checkout", &["acc_k7m2q4x3ca", "personal"]);
        assert!(key.starts_with("apassy-checkout-"));
        assert!(!key.contains("acc_"));
        assert_eq!(
            key,
            idempotency_key("checkout", &["acc_k7m2q4x3ca", "personal"])
        );
        assert_ne!(
            key,
            idempotency_key("checkout", &["acc_k7m2q4x3ca", "family"])
        );
    }
}
