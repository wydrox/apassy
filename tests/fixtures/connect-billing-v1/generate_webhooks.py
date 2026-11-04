"""Makes the webhook fixtures of docs/contracts/connect-billing-v1.md section 7:
tests/fixtures/connect-billing-v1/webhook/*.json (the exact signed bodies) and
webhook-vectors.json (the Stripe-Signature headers). Synthetic ids and a synthetic
endpoint secret only; no Stripe account is called.

    python3 -I tests/fixtures/connect-billing-v1/generate_webhooks.py

The signature is Stripe's documented scheme: HMAC-SHA256 with the endpoint secret
(the whole string, `whsec_` included, as UTF-8) over `<t>.<body bytes>`, lowercase
hex, sent as `Stripe-Signature: t=<t>,v1=<hex>`.
"""

import hashlib
import hmac
import json
import pathlib

DIR = pathlib.Path(__file__).resolve().parent
SECRET = "whsec_SYNTHETIC_apassy_connect_billing_v1_fixture"
OTHER_SECRET = "whsec_SYNTHETIC_another_endpoint"
API = "2025-03-31.basil"
ACCOUNT = "acc_k7m2q4x3ca"
CUSTOMER = "cus_SynthAcc0001"
SUBSCRIPTION = "sub_SynthAcc0001"
ITEM = "si_SynthAcc0001"
START = 1790000000
PERIOD_END = 1792592000  # START + 30 days
FAILED = 1792592100
ENDED = 1793801700


def event(eid, etype, created, obj, previous=None):
    data = {"object": obj}
    if previous is not None:
        data["previous_attributes"] = previous
    return {
        "id": eid,
        "object": "event",
        "api_version": API,
        "created": created,
        "data": data,
        "livemode": False,
        "pending_webhooks": 1,
        "request": {"id": None, "idempotency_key": None},
        "type": etype,
    }


def subscription(status, cancel_at_period_end=False, ended_at=None, quantity=1):
    return {
        "id": SUBSCRIPTION,
        "object": "subscription",
        "cancel_at_period_end": cancel_at_period_end,
        "customer": CUSTOMER,
        "ended_at": ended_at,
        "items": {
            "object": "list",
            "data": [
                {
                    "id": ITEM,
                    "object": "subscription_item",
                    "current_period_end": PERIOD_END,
                    "current_period_start": START,
                    "price": {
                        "id": "price_SynthPersonalMonth",
                        "object": "price",
                        "currency": "eur",
                        "lookup_key": "connect_personal_month",
                        "recurring": {"interval": "month", "interval_count": 1},
                        "tax_behavior": "inclusive",
                        "unit_amount": 300,
                    },
                    "quantity": quantity,
                }
            ],
        },
        "livemode": False,
        "metadata": {"account_id": ACCOUNT},
        "status": status,
    }


def invoice(iid, status, paid, attempts, next_attempt):
    return {
        "id": iid,
        "object": "invoice",
        "amount_due": 300,
        "amount_paid": 300 if paid else 0,
        "attempt_count": attempts,
        "billing_reason": "subscription_cycle" if attempts else "subscription_create",
        "currency": "eur",
        "customer": CUSTOMER,
        "livemode": False,
        "next_payment_attempt": next_attempt,
        "parent": {
            "type": "subscription_details",
            "subscription_details": {
                "metadata": {"account_id": ACCOUNT},
                "subscription": SUBSCRIPTION,
            },
        },
        "status": status,
        "total": 300,
    }


EVENTS = [
    (
        "checkout.session.completed",
        event(
            "evt_SynthCheckout0001",
            "checkout.session.completed",
            START,
            {
                "id": "cs_test_SynthSession0001",
                "object": "checkout.session",
                "client_reference_id": ACCOUNT,
                "customer": CUSTOMER,
                "customer_details": {"email": "person@example.test", "name": "Synthetic Person"},
                "livemode": False,
                "metadata": {"account_id": ACCOUNT},
                "mode": "subscription",
                "payment_status": "paid",
                "status": "complete",
                "subscription": SUBSCRIPTION,
            },
        ),
    ),
    (
        "customer.subscription.created",
        event("evt_SynthSubCreated01", "customer.subscription.created", START + 1, subscription("active")),
    ),
    (
        "invoice.paid",
        event("evt_SynthInvoicePaid1", "invoice.paid", START + 2, invoice("in_SynthInvoice0001", "paid", True, 1, None)),
    ),
    (
        "invoice.payment_failed",
        event(
            "evt_SynthInvoiceFail1",
            "invoice.payment_failed",
            FAILED,
            invoice("in_SynthInvoice0002", "open", False, 1, FAILED + 3 * 86400),
        ),
    ),
    (
        "customer.subscription.updated",
        event(
            "evt_SynthSubUpdated01",
            "customer.subscription.updated",
            FAILED + 1,
            subscription("past_due"),
            {"status": "active"},
        ),
    ),
    (
        "customer.subscription.deleted",
        event(
            "evt_SynthSubDeleted01",
            "customer.subscription.deleted",
            ENDED,
            subscription("canceled", ended_at=ENDED),
        ),
    ),
]


def sign(secret: str, t: int, body: bytes) -> str:
    return hmac.new(secret.encode(), str(t).encode() + b"." + body, hashlib.sha256).hexdigest()


def main():
    cases = []
    for etype, ev in EVENTS:
        name = etype.replace(".", "-").replace("_", "-") + ".json"
        body = (json.dumps(ev, indent=2) + "\n").encode()
        (DIR / "webhook" / name).write_bytes(body)
        t = ev["created"]
        v1 = sign(SECRET, t, body)
        cases.append(
            {
                "file": name,
                "type": etype,
                "event_id": ev["id"],
                "t": t,
                "v1": v1,
                "header": f"t={t},v1={v1}",
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        )
    first = cases[0]
    body = (DIR / "webhook" / first["file"]).read_bytes()
    wrong = sign(OTHER_SECRET, first["t"], body)
    refusals = [
        {
            "name": "two_signatures_one_valid",
            "file": first["file"],
            "now": first["t"] + 10,
            "header": f"t={first['t']},v1={wrong},v1={first['v1']},v0=00",
            "accepted": True,
        },
        {
            "name": "wrong_secret",
            "file": first["file"],
            "now": first["t"] + 10,
            "header": f"t={first['t']},v1={wrong}",
            "accepted": False,
        },
        {
            "name": "stale_timestamp",
            "file": first["file"],
            "now": first["t"] + 301,
            "header": first["header"],
            "accepted": False,
        },
        {
            "name": "at_the_tolerance",
            "file": first["file"],
            "now": first["t"] + 300,
            "header": first["header"],
            "accepted": True,
        },
        {
            "name": "future_timestamp",
            "file": first["file"],
            "now": first["t"] - 301,
            "header": first["header"],
            "accepted": False,
        },
        {
            "name": "changed_timestamp",
            "file": first["file"],
            "now": first["t"] + 10,
            "header": f"t={first['t'] + 1},v1={first['v1']}",
            "accepted": False,
        },
        {
            "name": "no_v1",
            "file": first["file"],
            "now": first["t"] + 10,
            "header": f"t={first['t']},v0={first['v1']}",
            "accepted": False,
        },
        {
            "name": "no_timestamp",
            "file": first["file"],
            "now": first["t"] + 10,
            "header": f"v1={first['v1']}",
            "accepted": False,
        },
    ]
    out = {
        "endpoint_secret": SECRET,
        "tolerance_seconds": 300,
        "api_version": API,
        "events": cases,
        "headers": refusals,
    }
    (DIR / "webhook-vectors.json").write_text(json.dumps(out, indent=2) + "\n")


if __name__ == "__main__":
    main()
