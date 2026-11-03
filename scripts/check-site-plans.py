#!/usr/bin/env python3
"""Check the prices of the website against the one source of the plans.

site/src/lib/plans.ts holds the prices that the site shows. This script checks:

1. Each price in plans.ts against the price table of docs/product/plans.md
   section 3 (EUR, VAT included, a month and a year).
2. A year costs YEAR_MONTHS months, and YEAR_MONTHS is what plans.md says.
3. When tests/fixtures/connect-billing-v1/plans.json exists (the billing
   contract of Connect), the price of each Stripe lookup key in it, its
   currency (EUR), and its tax behavior (inclusive).
4. While CONNECT_STATUS is "coming": no page of the site links to Stripe or to
   a checkout. A legal page that is still a draft is not linked from the layout.

Standard library only. Exit 0 when every check passes, 1 otherwise.

    python3 scripts/check-site-plans.py
"""

from __future__ import annotations

import json
import re
import sys
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLANS_MD = ROOT / "docs/product/plans.md"
PLANS_TS = ROOT / "site/src/lib/plans.ts"
FIXTURE = ROOT / "tests/fixtures/connect-billing-v1/plans.json"
PAGES = ROOT / "site/src"
LAYOUT = ROOT / "site/src/layouts/Page.astro"
# The legal pages. Each is a draft while it passes draft to the Legal layout.
LEGAL_PAGES = {
    "/terms": ROOT / "site/src/pages/terms.astro",
    "/imprint": ROOT / "site/src/pages/imprint.astro",
    "/privacy-connect": ROOT / "site/src/pages/privacy-connect.astro",
}

errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)


def cents(text: str) -> int:
    value = Decimal(text) * 100
    if value != value.to_integral_value():
        raise ValueError(f"not a whole number of cents: {text}")
    return int(value)


def read_plans_md() -> tuple[dict[str, tuple[int, int]], int | None]:
    """The price table of section 3: {key: (month cents, year cents)}, and the
    number of months that a year costs."""
    text = PLANS_MD.read_text(encoding="utf-8")
    row = re.compile(r"^\s*\|\s*(Connect [^|]+?)\s*\|\s*(\d+(?:\.\d+)?)\s*\|\s*(\d+(?:\.\d+)?)\s*\|\s*$", re.M)
    found: dict[str, tuple[int, int]] = {}
    for match in row.finditer(text):
        name, month, year = match.group(1), cents(match.group(2)), cents(match.group(3))
        if name == "Connect Personal":
            key = "personal"
        elif re.fullmatch(r"Connect Family \(\d+ people\)", name):
            key = "family"
            found["family_people"] = (int(re.search(r"\d+", name).group()), 0)
        elif name.startswith("Connect Team"):
            key = "team"
        elif m := re.fullmatch(r"Connect Family, each person after (\d+)", name):
            key = "family_extra"
            found["family_extra_after"] = (int(m.group(1)), 0)
        else:
            fail(f"plans.md: unknown price row {name!r}")
            continue
        if key in found:
            fail(f"plans.md: two price rows for {name!r}")
        found[key] = (month, year)
    months = re.search(r"A year costs (\d+) times the monthly price", text)
    return found, int(months.group(1)) if months else None


def read_plans_ts() -> dict[str, object]:
    text = PLANS_TS.read_text(encoding="utf-8")
    out: dict[str, object] = {}

    def one(pattern: str, what: str) -> str | None:
        match = re.search(pattern, text, re.S)
        if not match:
            fail(f"plans.ts: cannot read {what}")
            return None
        return match.group(1)

    out["status"] = one(r'CONNECT_STATUS: "coming" \| "live" = "(coming|live)";', "CONNECT_STATUS")
    out["currency"] = one(r'CURRENCY = "([A-Z]{3})";', "CURRENCY")
    out["vat_included"] = one(r"VAT_INCLUDED = (true|false);", "VAT_INCLUDED")
    year_months = one(r"YEAR_MONTHS = (\d+);", "YEAR_MONTHS")
    out["year_months"] = int(year_months) if year_months else None
    people = one(r"FAMILY_INCLUDED_PEOPLE = (\d+);", "FAMILY_INCLUDED_PEOPLE")
    out["family_people"] = int(people) if people else None
    extra = re.search(r"FAMILY_EXTRA: Price = \{\s*month: (\d+),\s*year: (\d+),", text)
    if extra:
        out["family_extra"] = (int(extra.group(1)), int(extra.group(2)))
    else:
        fail("plans.ts: cannot read FAMILY_EXTRA")
    plan = re.compile(
        r'id: "(personal|family|team)",(.*?)lookupKeys: \{ month: "([a-z_]+)", year: "([a-z_]+)" \}', re.S
    )
    keys: dict[str, int] = {}
    for match in plan.finditer(text):
        price = re.search(r"price: \{\s*month: (\d+),\s*year: (\d+),", match.group(2))
        if not price:
            fail(f"plans.ts: cannot read the price of {match.group(1)}")
            continue
        month, year = int(price.group(1)), int(price.group(2))
        out[match.group(1)] = (month, year)
        keys[match.group(3)] = month
        keys[match.group(4)] = year
    out["lookup_keys"] = keys
    for plan_id in ("personal", "family", "team"):
        if plan_id not in out:
            fail(f"plans.ts: no plan {plan_id}")
    return out


def check_prices(md: dict[str, tuple[int, int]], md_months: int | None, ts: dict[str, object]) -> None:
    if ts.get("currency") != "EUR":
        fail(f"plans.ts: CURRENCY is {ts.get('currency')!r}, plans.md says EUR")
    if ts.get("vat_included") != "true":
        fail("plans.ts: VAT_INCLUDED must be true (plans.md: EUR with VAT included)")
    if md_months is None:
        fail("plans.md: cannot find 'A year costs N times the monthly price'")
    elif ts.get("year_months") != md_months:
        fail(f"plans.ts: YEAR_MONTHS is {ts.get('year_months')}, plans.md says {md_months}")
    if "family_people" in md and ts.get("family_people") != md["family_people"][0]:
        fail(f"plans.ts: FAMILY_INCLUDED_PEOPLE is {ts.get('family_people')}, plans.md says {md['family_people'][0]}")
    if "family_extra_after" in md and md["family_extra_after"][0] != md.get("family_people", (None,))[0]:
        fail("plans.md: the Family extra row and the Family row name a different number of people")
    for key in ("personal", "family", "team", "family_extra"):
        if key not in md:
            fail(f"plans.md: no price row for {key}")
            continue
        if key not in ts:
            continue
        if ts[key] != md[key]:
            fail(f"{key}: plans.ts has {ts[key]} cents (month, year), plans.md has {md[key]}")
        month, year = ts[key]  # type: ignore[misc]
        if isinstance(ts.get("year_months"), int) and year != month * ts["year_months"]:
            fail(f"{key}: the year ({year}) is not {ts['year_months']} months of {month}")


def ints_in(value: object) -> set[int]:
    if isinstance(value, bool):
        return set()
    if isinstance(value, int):
        return {value}
    if isinstance(value, dict):
        return set().union(*(ints_in(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(ints_in(v) for v in value)) if value else set()
    return set()


def walk(value: object):
    yield value
    if isinstance(value, dict):
        for v in value.values():
            yield from walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk(v)


def check_fixture(ts: dict[str, object]) -> None:
    if not FIXTURE.exists():
        print(f"note: {FIXTURE.relative_to(ROOT)} does not exist yet; only plans.md is checked")
        return
    try:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"{FIXTURE.relative_to(ROOT)}: not JSON: {error}")
        return
    expected: dict[str, int] = ts.get("lookup_keys", {})  # type: ignore[assignment]
    found: dict[str, set[int]] = {}
    for node in walk(data):
        if not isinstance(node, dict):
            continue
        key = node.get("lookup_key")
        if isinstance(key, str):
            found.setdefault(key, set()).update(ints_in(node))
        for name, value in node.items():
            if name in expected:
                found.setdefault(name, set()).update(ints_in(value))
        currency = node.get("currency")
        if isinstance(currency, str) and currency.lower() != "eur":
            fail(f"fixture: currency {currency!r}, the site says EUR")
        tax = node.get("tax_behavior")
        if isinstance(tax, str) and tax != "inclusive":
            fail(f"fixture: tax_behavior {tax!r}, the site says VAT included")
    if not found.keys() & expected.keys():
        fail("fixture: names none of the lookup keys of plans.ts; update this script to its format")
        return
    extra_month, extra_year = ts.get("family_extra", (None, None))  # type: ignore[misc]
    for key, amount in expected.items():
        if key not in found:
            fail(f"fixture: no price with the lookup key {key}")
            continue
        if amount not in found[key]:
            fail(f"fixture: {key} has no amount {amount} (found {sorted(found[key])})")
        if key.startswith("connect_family_"):
            extra = extra_month if key.endswith("_month") else extra_year
            if extra not in found[key]:
                fail(f"fixture: {key} has no Family extra amount {extra} (found {sorted(found[key])})")


def check_pages(ts: dict[str, object]) -> None:
    if ts.get("status") == "coming":
        for path in sorted(PAGES.rglob("*")):
            if path.suffix not in {".astro", ".ts", ".md"} or path == PLANS_TS:
                continue
            text = path.read_text(encoding="utf-8")
            if re.search(r"checkout\.stripe\.com|buy\.stripe\.com|billing\.stripe\.com|/v1/account/checkout", text, re.I):
                fail(f"{path.relative_to(ROOT)}: links to a checkout while CONNECT_STATUS is 'coming'")
    layout = LAYOUT.read_text(encoding="utf-8")
    for route, page in LEGAL_PAGES.items():
        if not page.exists():
            fail(f"{page.relative_to(ROOT)}: missing")
            continue
        draft = re.search(r"<Legal\b[^>]*\bdraft\b", page.read_text(encoding="utf-8"))
        if draft and re.search(rf'href="{re.escape(route)}"', layout):
            fail(f"site/src/layouts/Page.astro links {route}, which is still a draft")


def main() -> int:
    md, md_months = read_plans_md()
    ts = read_plans_ts()
    check_prices(md, md_months, ts)
    check_fixture(ts)
    check_pages(ts)
    if errors:
        for message in errors:
            print(f"error: {message}", file=sys.stderr)
        return 1
    print("site plans: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
