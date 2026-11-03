// The one source of the prices on this site: the plans of Apassy Connect
// (docs/product/plans.md section 3, owner decision of 2026-11-03).
//
// Every amount is in euro cents, VAT included. A year costs 10 months.
// scripts/check-site-plans.py checks these numbers against the price table of
// plans.md and, when it exists, against tests/fixtures/connect-billing-v1/plans.json.
// Keep the lines `month: <cents>,` and `year: <cents>,` in this form: the script
// reads them.

/** "coming" until Connect ships (ADR 0037 stage 7): no buy button, no checkout link. */
export const CONNECT_STATUS: "coming" | "live" = "coming";

export const CURRENCY = "EUR";
/** The listed price is what the customer pays. Stripe Tax computes the VAT part. */
export const VAT_INCLUDED = true;
/** A year costs this many months. */
export const YEAR_MONTHS = 10;

export interface Price {
  /** Euro cents a month, VAT included. */
  month: number;
  /** Euro cents a year, VAT included: YEAR_MONTHS times `month`. */
  year: number;
}

export interface Plan {
  id: "personal" | "family" | "team";
  /** The plan name, as plans.md section 5 requires. */
  name: string;
  /** Who the plan is for. */
  for: string;
  /** What one price buys: shown after the amount. */
  per: string;
  price: Price;
  /** The Stripe lookup keys of the prices (implementation plan s7, decision 3). */
  lookupKeys: { month: string; year: string };
  /** What the plan adds to the Connect functions. */
  adds: string[];
}

/** Connect Family includes this many people. */
export const FAMILY_INCLUDED_PEOPLE = 4;

/** Connect Family: the price of each person after FAMILY_INCLUDED_PEOPLE. */
export const FAMILY_EXTRA: Price = {
  month: 100,
  year: 1000,
};

export const PLANS: Plan[] = [
  {
    id: "personal",
    name: "Connect Personal",
    for: "One person and all of their devices",
    per: "",
    price: {
      month: 300,
      year: 3000,
    },
    lookupKeys: { month: "connect_personal_month", year: "connect_personal_year" },
    adds: ["The Connect functions for one person"],
  },
  {
    id: "family",
    name: "Connect Family",
    for: `Up to ${FAMILY_INCLUDED_PEOPLE} people in one price`,
    per: `for ${FAMILY_INCLUDED_PEOPLE} people`,
    price: {
      month: 500,
      year: 5000,
    },
    lookupKeys: { month: "connect_family_month", year: "connect_family_year" },
    adds: [
      "The Connect functions for each person",
      "Shared family vaults in the blind sync store",
      "One organizer adds and removes members",
    ],
  },
  {
    id: "team",
    name: "Connect Team",
    for: "A company or a group",
    per: "per member",
    price: {
      month: 400,
      year: 4000,
    },
    lookupKeys: { month: "connect_team_month", year: "connect_team_year" },
    adds: [
      "The Connect functions for each member",
      "Roles and member management",
      "Billing per seat",
    ],
  },
];

/** "€3" for 300, "€2.50" for 250. */
export function eur(cents: number): string {
  const whole = cents % 100 === 0;
  return `€${(cents / 100).toFixed(whole ? 0 : 2)}`;
}

/** The months that a year saves: 12 - YEAR_MONTHS. */
export const FREE_MONTHS_A_YEAR = 12 - YEAR_MONTHS;
