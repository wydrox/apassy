//! Billing on the directory (docs/SPEC.md section 34; connect-billing-v1): the
//! `BillingStore` of `server::billing` on the tables `stripe_customer`,
//! `stripe_subscription`, `stripe_event`, `"group"`, and `group_member` of `relay.db`, the
//! `Plans` seam of the accounts, and the maintenance pass that deletes the stores of an
//! ended plan.
//!
//! Every billing transaction is one immediate SQLite transaction of the directory, so an
//! event id and its effect are stored together or not at all. The functions here never
//! run inside another lock of the directory (`Store` is not reentrant).

use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;

use crate::api;
use crate::config::BillingSettings;
use crate::error::{RelayError, RelayResult};
use crate::server::account::Plans;
use crate::server::audit::Audit;
use crate::server::billing::StripeStatus;
use crate::server::billing::{
    Billing, BillingClock, BillingStore, BillingTx, CustomerRow, DeletionGate, DueDeletion,
    GroupKind, GroupRole, GroupRow, MemberState, Membership, OpenCheckout, PlanStatus, Problem,
    ProblemRow, StripeCheck, SubscriptionRow, WebhookEffect, new_group_id, parse_lookup_key,
};
use crate::server::hub::Hub;
use crate::server::store::{Store, db, to_i, to_u};
use crate::server::stripe::{StripeClient, StripeConfig};

/// Billing of a relay: the handlers of `server::billing` on the directory.
pub type ConnectBilling = Billing<DirectoryBilling>;

/// The billing tables of `relay.db`.
pub struct DirectoryBilling {
    store: Arc<Store>,
    /// Writes the audit row of a recorded problem (ids only).
    audit: Arc<Audit>,
}

impl DirectoryBilling {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            audit: Audit::new(),
        }
    }
}

impl BillingStore for DirectoryBilling {
    fn transaction<T>(
        &self,
        f: impl FnOnce(&mut dyn BillingTx) -> RelayResult<T>,
    ) -> RelayResult<T> {
        self.store.tx(|tx| {
            let mut sql = SqlBilling {
                conn: tx,
                audit: &self.audit,
            };
            f(&mut sql)
        })
    }
}

/// The billing of a relay from its settings: the Stripe client on the configured base
/// (`https://api.stripe.com`; a loopback `http://` base only from code, for the tests),
/// the restricted key, and the webhook secret.
pub fn build(settings: &BillingSettings, store: Arc<Store>) -> RelayResult<ConnectBilling> {
    let stripe = StripeClient::new(StripeConfig::new(
        &settings.stripe_api_base,
        settings.secret_key.clone(),
    )?);
    Billing::new(
        DirectoryBilling::new(store),
        stripe,
        settings.config.clone(),
        settings.webhook_secret.clone(),
    )
}

/// One transaction on the billing tables.
struct SqlBilling<'a> {
    conn: &'a Connection,
    audit: &'a Audit,
}

const SUBSCRIPTION_COLUMNS: &str = "subscription_id, customer_id, account_id, group_id, item_id, \
     lookup_key, quantity, status, current_period_end, cancel_at_period_end, first_failure_at, \
     ended_at, event_created, last_invoice_created, stores_deleted_at, requested_quantity, \
     requested_at, kind_left_at, checked_at";

fn optional_u(value: Option<i64>) -> Option<u64> {
    value.map(to_u)
}

fn subscription_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SubscriptionRow> {
    let lookup_key: Option<String> = row.get(5)?;
    let parsed = lookup_key.as_deref().and_then(parse_lookup_key);
    let status: String = row.get(7)?;
    let quantity: Option<i64> = row.get(6)?;
    Ok(SubscriptionRow {
        id: row.get(0)?,
        customer: row.get(1)?,
        account: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
        group_id: row.get(3)?,
        item: row.get(4)?,
        plan: parsed.map(|(plan, _)| plan),
        interval: parsed.map(|(_, interval)| interval),
        lookup_key,
        quantity: quantity
            .and_then(|q| u32::try_from(q).ok())
            .unwrap_or(1)
            .max(1),
        status: StripeStatus::parse(&status),
        period_end: optional_u(row.get(8)?),
        cancel_at_period_end: row.get::<_, i64>(9)? != 0,
        first_failed_at: optional_u(row.get(10)?),
        ended_at: optional_u(row.get(11)?),
        last_event_created: to_u(row.get(12)?),
        last_invoice_created: to_u(row.get(13)?),
        stores_deleted_at: optional_u(row.get(14)?),
        requested_quantity: row
            .get::<_, Option<i64>>(15)?
            .and_then(|q| u32::try_from(q).ok()),
        requested_at: optional_u(row.get(16)?),
        kind_left_at: optional_u(row.get(17)?),
        checked_at: optional_u(row.get(18)?),
    })
}

fn kind_of(text: &str) -> RelayResult<GroupKind> {
    match text {
        "family" => Ok(GroupKind::Family),
        "team" => Ok(GroupKind::Team),
        _ => Err(RelayError::internal(
            "A group in relay.db has an unknown kind.",
        )),
    }
}

fn role_of(text: &str) -> RelayResult<GroupRole> {
    match text {
        "owner" => Ok(GroupRole::Owner),
        "admin" => Ok(GroupRole::Admin),
        "member" => Ok(GroupRole::Member),
        _ => Err(RelayError::internal(
            "A group member in relay.db has an unknown role.",
        )),
    }
}

fn state_of(text: &str) -> RelayResult<MemberState> {
    match text {
        "pending" => Ok(MemberState::Pending),
        "active" => Ok(MemberState::Active),
        _ => Err(RelayError::internal(
            "A group member in relay.db has an unknown state.",
        )),
    }
}

pub(crate) fn kind_text(kind: GroupKind) -> &'static str {
    match kind {
        GroupKind::Family => "family",
        GroupKind::Team => "team",
    }
}

impl BillingTx for SqlBilling<'_> {
    fn account_exists(&mut self, account: &str) -> RelayResult<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM account WHERE id = ?1",
                params![account],
                |_| Ok(()),
            )
            .optional()
            .map_err(db)?
            .is_some())
    }

    fn customer_of_account(&mut self, account: &str) -> RelayResult<Option<CustomerRow>> {
        self.conn
            .query_row(
                "SELECT customer_id, email FROM stripe_customer WHERE account_id = ?1",
                params![account],
                |row| {
                    Ok(CustomerRow {
                        account: account.to_owned(),
                        customer: row.get(0)?,
                        email: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(db)
    }

    fn customer(&mut self, customer: &str) -> RelayResult<Option<CustomerRow>> {
        self.conn
            .query_row(
                "SELECT account_id, email FROM stripe_customer WHERE customer_id = ?1",
                params![customer],
                |row| {
                    Ok(CustomerRow {
                        account: row.get(0)?,
                        customer: customer.to_owned(),
                        email: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(db)
    }

    /// Also keeps `account.email`, the copy that `GET /v1/account` shows.
    fn put_customer(&mut self, row: &CustomerRow) -> RelayResult<()> {
        self.conn
            .execute(
                "INSERT INTO stripe_customer (customer_id, account_id, email, created_at) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(customer_id) DO UPDATE SET \
                 account_id = excluded.account_id, email = excluded.email",
                params![
                    row.customer,
                    row.account,
                    row.email,
                    to_i(crate::now_unix())
                ],
            )
            .map_err(db)?;
        self.conn
            .execute(
                "UPDATE account SET email = ?2 WHERE id = ?1",
                params![row.account, row.email],
            )
            .map_err(db)?;
        Ok(())
    }

    fn subscription(&mut self, id: &str) -> RelayResult<Option<SubscriptionRow>> {
        self.conn
            .query_row(
                &format!(
                    "SELECT {SUBSCRIPTION_COLUMNS} FROM stripe_subscription WHERE subscription_id = ?1"
                ),
                params![id],
                subscription_from_row,
            )
            .optional()
            .map_err(db)
    }

    fn subscriptions_of_account(&mut self, account: &str) -> RelayResult<Vec<SubscriptionRow>> {
        let mut statement = self
            .conn
            .prepare(&format!(
                "SELECT {SUBSCRIPTION_COLUMNS} FROM stripe_subscription WHERE account_id = ?1 \
                 ORDER BY event_created, subscription_id"
            ))
            .map_err(db)?;
        statement
            .query_map(params![account], subscription_from_row)
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)
    }

    /// Also binds the group to its subscription (`"group".subscription_id`).
    fn put_subscription(&mut self, row: &SubscriptionRow) -> RelayResult<()> {
        self.conn
            .execute(
                &format!(
                    "INSERT INTO stripe_subscription ({SUBSCRIPTION_COLUMNS}, updated_at) VALUES \
                     (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
                     ?18, ?19, ?20) \
                     ON CONFLICT(subscription_id) DO UPDATE SET customer_id = excluded.customer_id, \
                     account_id = excluded.account_id, group_id = excluded.group_id, \
                     item_id = excluded.item_id, lookup_key = excluded.lookup_key, \
                     quantity = excluded.quantity, status = excluded.status, \
                     current_period_end = excluded.current_period_end, \
                     cancel_at_period_end = excluded.cancel_at_period_end, \
                     first_failure_at = excluded.first_failure_at, ended_at = excluded.ended_at, \
                     event_created = excluded.event_created, \
                     last_invoice_created = excluded.last_invoice_created, \
                     stores_deleted_at = excluded.stores_deleted_at, \
                     requested_quantity = excluded.requested_quantity, \
                     requested_at = excluded.requested_at, kind_left_at = excluded.kind_left_at, \
                     checked_at = excluded.checked_at, updated_at = excluded.updated_at"
                ),
                params![
                    row.id,
                    row.customer,
                    row.account,
                    row.group_id,
                    row.item,
                    row.lookup_key,
                    i64::from(row.quantity),
                    row.status.as_str(),
                    row.period_end.map(to_i),
                    i64::from(row.cancel_at_period_end),
                    row.first_failed_at.map(to_i),
                    row.ended_at.map(to_i),
                    to_i(row.last_event_created),
                    to_i(row.last_invoice_created),
                    row.stores_deleted_at.map(to_i),
                    row.requested_quantity.map(i64::from),
                    row.requested_at.map(to_i),
                    row.kind_left_at.map(to_i),
                    row.checked_at.map(to_i),
                    to_i(crate::now_unix()),
                ],
            )
            .map_err(db)?;
        if let Some(group) = &row.group_id {
            self.conn
                .execute(
                    "UPDATE \"group\" SET subscription_id = ?2 WHERE id = ?1",
                    params![group, row.id],
                )
                .map_err(db)?;
        }
        Ok(())
    }

    fn lapsed_subscriptions(&mut self) -> RelayResult<Vec<SubscriptionRow>> {
        let lapsed = [
            StripeStatus::PastDue,
            StripeStatus::Canceled,
            StripeStatus::Unpaid,
            StripeStatus::IncompleteExpired,
            StripeStatus::Paused,
        ]
        .map(|status| format!("'{}'", status.as_str()))
        .join(", ");
        let mut statement = self
            .conn
            .prepare(&format!(
                "SELECT {SUBSCRIPTION_COLUMNS} FROM stripe_subscription WHERE status IN ({lapsed}) \
                 ORDER BY subscription_id"
            ))
            .map_err(db)?;
        statement
            .query_map([], subscription_from_row)
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)
    }

    fn record_event(&mut self, id: &str, kind: &str, at: u64) -> RelayResult<bool> {
        let added = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO stripe_event (id, type, received_at) VALUES (?1, ?2, ?3)",
                params![id, kind, to_i(at)],
            )
            .map_err(db)?;
        Ok(added == 1)
    }

    fn prune_events(&mut self, before: u64) -> RelayResult<u64> {
        let removed = self
            .conn
            .execute(
                "DELETE FROM stripe_event WHERE received_at < ?1",
                params![to_i(before)],
            )
            .map_err(db)?;
        Ok(removed as u64)
    }

    fn membership(&mut self, account: &str) -> RelayResult<Option<Membership>> {
        let row: Option<(String, String, String, String)> = self
            .conn
            .query_row(
                "SELECT m.group_id, g.kind, m.role, m.state FROM group_member m \
                 JOIN \"group\" g ON g.id = m.group_id WHERE m.account_id = ?1",
                params![account],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(db)?;
        row.map(|(group_id, kind, role, state)| {
            Ok(Membership {
                group_id,
                kind: kind_of(&kind)?,
                role: role_of(&role)?,
                state: state_of(&state)?,
            })
        })
        .transpose()
    }

    fn group(&mut self, group_id: &str) -> RelayResult<Option<GroupRow>> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT kind, owner_account FROM \"group\" WHERE id = ?1",
                params![group_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        row.map(|(kind, owner_account)| {
            Ok(GroupRow {
                group_id: group_id.to_owned(),
                kind: kind_of(&kind)?,
                owner_account,
            })
        })
        .transpose()
    }

    fn create_group(&mut self, kind: GroupKind, owner: &str, now: u64) -> RelayResult<String> {
        let group_id = new_group_id()?;
        self.conn
            .execute(
                "INSERT INTO \"group\" (id, kind, owner_account, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![group_id, kind_text(kind), owner, to_i(now)],
            )
            .map_err(db)?;
        self.conn
            .execute(
                "INSERT INTO group_member (group_id, account_id, role, state, created_at, joined_at) \
                 VALUES (?1, ?2, 'owner', 'active', ?3, ?3)",
                params![group_id, owner, to_i(now)],
            )
            .map_err(db)?;
        self.conn
            .execute(
                "UPDATE account SET group_id = ?2 WHERE id = ?1",
                params![owner, group_id],
            )
            .map_err(db)?;
        Ok(group_id)
    }

    fn active_members(&mut self, group_id: &str) -> RelayResult<u32> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM group_member WHERE group_id = ?1 AND state = 'active'",
                params![group_id],
                |row| row.get(0),
            )
            .map_err(db)?;
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    fn member_rank(&mut self, group_id: &str, account: &str) -> RelayResult<Option<u32>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT account_id FROM group_member WHERE group_id = ?1 AND state = 'active' \
                 ORDER BY role = 'owner' DESC, joined_at, account_id",
            )
            .map_err(db)?;
        let active = statement
            .query_map(params![group_id], |row| row.get::<_, String>(0))
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok(active
            .iter()
            .position(|id| id == account)
            .map(|place| u32::try_from(place).unwrap_or(u32::MAX)))
    }

    fn subscriptions_of_group(&mut self, group_id: &str) -> RelayResult<Vec<SubscriptionRow>> {
        let mut statement = self
            .conn
            .prepare(&format!(
                "SELECT {SUBSCRIPTION_COLUMNS} FROM stripe_subscription WHERE group_id = ?1 \
                 ORDER BY event_created, subscription_id"
            ))
            .map_err(db)?;
        statement
            .query_map(params![group_id], subscription_from_row)
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)
    }

    fn live_subscriptions(&mut self) -> RelayResult<Vec<SubscriptionRow>> {
        let mut statement = self
            .conn
            .prepare(&format!(
                "SELECT {SUBSCRIPTION_COLUMNS} FROM stripe_subscription \
                 WHERE status IN ('active', 'trialing', 'past_due') ORDER BY subscription_id"
            ))
            .map_err(db)?;
        statement
            .query_map([], subscription_from_row)
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)
    }

    fn open_checkout(&mut self, account: &str) -> RelayResult<Option<OpenCheckout>> {
        let row: Option<(Option<String>, Option<String>, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT checkout_session, checkout_request, checkout_expires_at \
                 FROM stripe_customer WHERE account_id = ?1",
                params![account],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        Ok(match row {
            Some((Some(session_id), Some(request), Some(expires_at))) => Some(OpenCheckout {
                session_id,
                request,
                expires_at: to_u(expires_at),
            }),
            _ => None,
        })
    }

    fn set_open_checkout(&mut self, account: &str, open: Option<&OpenCheckout>) -> RelayResult<()> {
        self.conn
            .execute(
                "UPDATE stripe_customer SET checkout_session = ?2, checkout_request = ?3, \
                 checkout_expires_at = ?4 WHERE account_id = ?1",
                params![
                    account,
                    open.map(|o| o.session_id.as_str()),
                    open.map(|o| o.request.as_str()),
                    open.map(|o| to_i(o.expires_at)),
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    /// Also writes the audit row `billing_problem_recorded` (ids only) for a new or a
    /// reopened problem.
    fn record_problem(&mut self, problem: &Problem) -> RelayResult<bool> {
        let open: Option<(i64, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT id, resolved_at FROM billing_problem WHERE object_id = ?1",
                params![problem.object],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        let new = match open {
            Some((id, resolved)) => {
                self.conn
                    .execute(
                        "UPDATE billing_problem SET last_at = ?2, events = events + 1, \
                         resolved_at = NULL, event_id = coalesce(?3, event_id) WHERE id = ?1",
                        params![id, to_i(problem.at), problem.event],
                    )
                    .map_err(db)?;
                resolved.is_some()
            }
            None => {
                self.conn
                    .execute(
                        "INSERT INTO billing_problem (object_id, account_id, customer_id, \
                         event_id, reason, first_at, last_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                        params![
                            problem.object,
                            problem.account,
                            problem.customer,
                            problem.event,
                            problem.reason,
                            to_i(problem.at)
                        ],
                    )
                    .map_err(db)?;
                true
            }
        };
        if new {
            self.audit.write_on(
                self.conn,
                problem.at,
                "billing",
                "billing_problem_recorded",
                None,
                &json!({"object": problem.object, "account_id": problem.account,
                        "customer_id": problem.customer, "event_id": problem.event,
                        "reason": problem.reason}),
            )?;
        }
        Ok(new)
    }

    fn open_problems(&mut self) -> RelayResult<Vec<ProblemRow>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, object_id, account_id, customer_id, reason, first_at, last_at, events \
                 FROM billing_problem WHERE resolved_at IS NULL ORDER BY id",
            )
            .map_err(db)?;
        statement
            .query_map([], |row| {
                Ok(ProblemRow {
                    id: to_u(row.get(0)?),
                    object: row.get(1)?,
                    account_id: row.get(2)?,
                    customer_id: row.get(3)?,
                    reason: row.get(4)?,
                    first_at: to_u(row.get(5)?),
                    last_at: to_u(row.get(6)?),
                    events: to_u(row.get(7)?),
                })
            })
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)
    }

    fn resolve_problem(&mut self, id: u64, at: u64) -> RelayResult<bool> {
        let changed = self
            .conn
            .execute(
                "UPDATE billing_problem SET resolved_at = ?2 WHERE id = ?1 AND resolved_at IS NULL",
                params![to_i(id), to_i(at)],
            )
            .map_err(db)?;
        if changed == 1 {
            self.audit.write_on(
                self.conn,
                at,
                "operator",
                "billing_problem_resolved",
                None,
                &json!({"problem": id}),
            )?;
        }
        Ok(changed == 1)
    }

    fn clock(&mut self) -> RelayResult<BillingClock> {
        let row: Option<(Option<i64>, Option<i64>, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT last_pass_at, stripe_time, held_since FROM billing_clock WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        Ok(
            row.map_or_else(BillingClock::default, |(last, stripe, held)| BillingClock {
                last_pass_at: optional_u(last),
                stripe_time: optional_u(stripe),
                held_since: optional_u(held),
            }),
        )
    }

    fn put_clock(&mut self, clock: &BillingClock) -> RelayResult<()> {
        self.conn
            .execute(
                "INSERT INTO billing_clock (id, last_pass_at, stripe_time, held_since) \
                 VALUES (1, ?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET \
                 last_pass_at = excluded.last_pass_at, stripe_time = excluded.stripe_time, \
                 held_since = excluded.held_since",
                params![
                    clock.last_pass_at.map(to_i),
                    clock.stripe_time.map(to_i),
                    clock.held_since.map(to_i)
                ],
            )
            .map_err(db)?;
        Ok(())
    }
}

/// The billing view of a plan in the account form (`api::PlanView`, the same JSON).
pub fn api_plan(view: &crate::server::billing::PlanView) -> RelayResult<api::PlanView> {
    serde_json::to_value(view)
        .and_then(serde_json::from_value)
        .map_err(|_| RelayError::internal("A plan view cannot be written."))
}

/// The `Plans` seam of the accounts, from billing (connect-billing-v1 section 8).
pub struct BillingPlans(pub Arc<ConnectBilling>);

impl Plans for BillingPlans {
    fn plan(&self, _directory: &Store, account: &str, now: u64) -> RelayResult<api::PlanView> {
        api_plan(&self.0.plan_view(account, now)?)
    }

    /// The owner of a Family or Team whose group plan is entitled: the people or seats of
    /// that subscription (the quantity at Stripe; members beyond it are not entitled);
    /// every other account: 1.
    fn people(&self, _directory: &Store, account: &str, now: u64) -> RelayResult<u64> {
        let group = self.0.store.transaction(|tx| {
            Ok(tx
                .membership(account)?
                .filter(|member| member.role == GroupRole::Owner)
                .map(|member| member.group_id))
        })?;
        let Some(group) = group else {
            return Ok(1);
        };
        Ok(match self.0.group_plan(&group, now)? {
            Some(plan) if plan.state.entitled => u64::from(plan.quantity.max(1)),
            _ => 1,
        })
    }

    fn cancel_for_deletion(
        &self,
        _directory: &Store,
        account: &str,
        _now: u64,
    ) -> RelayResult<bool> {
        self.0.cancel_for_account_deletion(account)
    }
}

/// `GET /v1/plans`: the public plans and prices.
pub const PLANS_PATH: &str = "/v1/plans";
/// `POST /v1/stripe/webhook`: Stripe's events.
pub const WEBHOOK_PATH: &str = "/v1/stripe/webhook";

/// True for a billing path outside `/v1/account`.
pub fn is_billing_path(path: &str) -> bool {
    path == PLANS_PATH || path == WEBHOOK_PATH
}

/// After an applied webhook: when the account's plan is no longer entitled, the open
/// tunnel streams of the account, and of the active members of its group, close.
pub fn after_webhook(hub: &Hub, billing: &ConnectBilling, effect: &WebhookEffect, now: u64) {
    let WebhookEffect::Applied { account } = effect else {
        return;
    };
    let mut accounts = vec![account.clone()];
    if let Ok(members) = group_members_of_owner(hub, account) {
        accounts.extend(members);
    }
    for account in accounts {
        if billing
            .plan_view(&account, now)
            .is_ok_and(|view| !view.entitled)
        {
            tunnel_plan_ended(hub, &account);
        }
    }
}

/// The other members of the group that `account` owns (none when it owns none).
fn group_members_of_owner(hub: &Hub, account: &str) -> RelayResult<Vec<String>> {
    hub.directory.store.with(|conn| {
        let mut statement = conn
            .prepare(
                "SELECT m.account_id FROM group_member m JOIN \"group\" g ON g.id = m.group_id \
                 WHERE g.owner_account = ?1 AND m.account_id <> ?1 ORDER BY m.account_id",
            )
            .map_err(db)?;
        statement
            .query_map(params![account], |row| row.get(0))
            .map_err(db)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db)
    })
}

/// `apassy-relay admin billing`: the open problems (Stripe objects Connect could not
/// apply for a known account or customer) and the clock of the deletion pass. With
/// `resume_deletions` the current clock is taken as right after a held pass; with
/// `resolve` one problem is marked handled. 503 `busy` without billing.
pub fn operator(
    hub: &Hub,
    resume_deletions: bool,
    resolve: Option<u64>,
    now: u64,
) -> RelayResult<serde_json::Value> {
    let billing = crate::server::account::billing(hub)?;
    if let Some(id) = resolve {
        billing.resolve_problem(id, now)?;
    }
    if resume_deletions {
        billing.resume_deletions(now)?;
        hub.directory.audit.write(
            &hub.directory.store,
            now,
            "operator",
            "billing_deletions_resumed",
            None,
            &json!({}),
        )?;
    }
    let status = billing.status()?;
    let problems = billing.problems()?;
    Ok(json!({"status": status, "problems": problems}))
}

/// The billing part of `apassy-relay admin readiness`: `null` without billing.
pub fn readiness(hub: &Hub) -> serde_json::Value {
    match hub.billing.as_deref() {
        Some(billing) => billing
            .status()
            .ok()
            .and_then(|status| serde_json::to_value(status).ok())
            .unwrap_or(serde_json::Value::Null),
        None => serde_json::Value::Null,
    }
}

/// How often the billing part of the maintenance pass runs at most.
pub const MAINTENANCE_SECS: u64 = 3600;

/// Records `now` as the time of the last billing part of the relay's own maintenance
/// pass: the next one waits `MAINTENANCE_SECS` from it. The tests run `maintain`
/// themselves and call this so the relay's pass does not run beside them.
pub fn defer_background_pass(hub: &Hub, now: u64) {
    hub.billing_maintained_at
        .store(now, std::sync::atomic::Ordering::Relaxed);
}

/// The billing part of the maintenance pass (connect-billing-v1 section 8), in this order:
///
/// 1. event ids older than 30 days go, and the plans due for deletion are listed;
/// 2. `Billing::reconcile`: stale live subscriptions are read from Stripe, and groups with
///    more active members than their quantity get it raised;
/// 3. `Billing::deletion_gate`: after a gap of more than two days since the last pass no
///    store is deleted until the operator resumes deletions;
/// 4. for each due plan, under the lock of its account: Stripe must show it ended, with
///    the relay's clock within a day of Stripe's (`Billing::verify_ended`); it must still
///    be due; then the vault stores and the tunnel nodes of the buying account go, and,
///    for a plan of its group's kind with no other subscription of the group still giving
///    a plan, those of each active member whose plan is over too (`none`, checked again
///    under the member's lock), with the audit row `plan_stores_deleted` (actor `billing`;
///    the counts) and I-4 `forget` for each account. A plan is marked done only when
///    every account of it was handled.
///
/// A failed entry is logged and the pass goes on; the next pass tries it again. Read-only
/// and suspended are states of the plan, not actions: nothing else changes. Answers how
/// many plans were done.
pub fn maintain(hub: &Hub, billing: &ConnectBilling, now: u64) -> RelayResult<usize> {
    let report = billing.maintenance(now)?;
    let reconciled = billing.reconcile(now)?;
    for (_, account) in &reconciled.read {
        after_webhook(
            hub,
            billing,
            &WebhookEffect::Applied {
                account: account.clone(),
            },
            now,
        );
    }
    if let DeletionGate::Held { since } = billing.deletion_gate(now)? {
        if !report.due.is_empty() {
            billing.log(&format!(
                "{} plans are due for deletion, held since {since}: resume with `apassy-relay admin billing --resume-deletions` once the clock is right",
                report.due.len()
            ));
        }
        return Ok(0);
    }
    let mut done = 0;
    for due in &report.due {
        match delete_due(hub, billing, due, now) {
            Ok(true) => done += 1,
            Ok(false) => {}
            Err(_) => billing.log(&format!(
                "the stores of subscription {} could not be deleted; the next pass tries again",
                due.subscription
            )),
        }
    }
    Ok(done)
}

/// One due plan of `maintain`, under the lock of its buying account.
fn delete_due(
    hub: &Hub,
    billing: &ConnectBilling,
    due: &DueDeletion,
    now: u64,
) -> RelayResult<bool> {
    billing.with_account_lock(&due.account, || {
        if billing.verify_ended(&due.subscription, now)? != StripeCheck::Ended
            || !billing.still_due(&due.subscription, now)?
        {
            return Ok(false);
        }
        let mut accounts = vec![due.account.clone()];
        if let Some(group) = &due.group_id
            && billing.deletes_members(&due.subscription, now)?
        {
            let members: Vec<String> = hub.directory.store.with(|conn| {
                let mut statement = conn
                    .prepare(
                        "SELECT account_id FROM group_member WHERE group_id = ?1 AND account_id <> ?2 \
                         AND state = 'active' ORDER BY account_id",
                    )
                    .map_err(db)?;
                statement
                    .query_map(params![group, due.account], |row| row.get(0))
                    .map_err(db)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(db)
            })?;
            accounts.extend(members);
        }
        let mut stores = 0u64;
        let mut nodes = 0u64;
        let mut deleted = Vec::new();
        let mut failed = 0usize;
        for account in &accounts {
            let result = if *account == due.account {
                delete_account_data(hub, billing, account, now)
            } else {
                billing.with_account_lock(account, || delete_account_data(hub, billing, account, now))
            };
            match result {
                Ok(Some((s, n))) => {
                    stores += s;
                    nodes += n;
                    deleted.push(account.clone());
                }
                Ok(None) => {}
                Err(_) => {
                    failed += 1;
                    billing.log(&format!(
                        "the stores of {account} (subscription {}) could not be deleted",
                        due.subscription
                    ));
                }
            }
        }
        hub.directory.store.tx(|tx| {
            for account in &deleted {
                tx.execute(
                    "INSERT INTO brain_event (kind, subject, created_at, next_at) VALUES ('forget', ?1, ?2, ?2)",
                    params![account, to_i(now)],
                )
                .map_err(db)?;
            }
            hub.directory.audit.write_on(
                tx,
                now,
                "billing",
                "plan_stores_deleted",
                None,
                &json!({"subscription": due.subscription, "account_id": due.account,
                        "group_id": due.group_id, "accounts": deleted.len(),
                        "deleted_stores": stores, "deleted_nodes": nodes, "failed": failed}),
            )
        })?;
        if failed > 0 {
            return Ok(false);
        }
        billing.mark_stores_deleted(&due.subscription, now)?;
        Ok(true)
    })
}

/// The stores and nodes of one account of a due plan, when its plan is over (`none`): a
/// member with a plan of its own, entitled or in its own read-only time, keeps them.
/// `None` when it keeps them.
fn delete_account_data(
    hub: &Hub,
    billing: &ConnectBilling,
    account: &str,
    now: u64,
) -> RelayResult<Option<(u64, u64)>> {
    if billing.plan_view(account, now)?.status != PlanStatus::None {
        return Ok(None);
    }
    let stores = crate::server::account::delete_stores_of(hub, account, now)?;
    let nodes = delete_nodes_of(hub, account)?;
    Ok(Some((stores, nodes)))
}

/// Deletes the tunnel nodes of `account` and the grants of those nodes (an ended plan at
/// its deletion day), and closes their WebSockets. Answers how many nodes went.
fn delete_nodes_of(hub: &Hub, account: &str) -> RelayResult<u64> {
    let nodes: Vec<String> = hub.directory.store.tx(|tx| {
        let nodes = {
            let mut statement = tx
                .prepare("SELECT id FROM tunnel_node WHERE account_id = ?1 ORDER BY id")
                .map_err(db)?;
            statement
                .query_map(params![account], |row| row.get(0))
                .map_err(db)?
                .collect::<Result<Vec<String>, _>>()
                .map_err(db)?
        };
        tx.execute(
            "DELETE FROM tunnel_grant WHERE node_id IN (SELECT id FROM tunnel_node WHERE account_id = ?1)",
            params![account],
        )
        .map_err(db)?;
        tx.execute("DELETE FROM tunnel_node WHERE account_id = ?1", params![account])
            .map_err(db)?;
        Ok(nodes)
    })?;
    if let Some(broker) = hub.tunnel() {
        for node in &nodes {
            broker.remove_node(node);
        }
    }
    tunnel_plan_ended(hub, account);
    Ok(nodes.len() as u64)
}

/// The open tunnel streams of an account whose plan ended close (4003); new dials and
/// ingress streams are refused by the plan check of each one (section 35).
pub fn tunnel_plan_ended(hub: &Hub, account: &str) {
    crate::server::tunnel_routes::plan_ended(hub, account);
}

/// The tunnel grants between `account` and each of `others` end, both ways, and their
/// streams close (a member left its group, connect-billing-v1 section 6). Answers how
/// many grants went.
pub fn tunnel_grants_end(
    hub: &Hub,
    account: &str,
    others: &[String],
    now: u64,
) -> RelayResult<usize> {
    crate::server::tunnel_routes::grants_end_between(hub, account, others, now)
}
