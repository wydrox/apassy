// The facts of the legal pages that only the owner can give (implementation plan
// s7, owner-needed step 3). Each `null` renders as the marker below. A legal page
// that is not a draft fails the build while it shows the marker
// (layouts/Legal.astro), so a placeholder cannot go live.

export const OWNER_TEXT_NEEDED = "OWNER-TEXT-NEEDED";

export const LEGAL: Record<string, string | null> = {
  /** The legal name of the seller: a company, or a person with a trading name. */
  legalName: null,
  /** The legal form and the register entry, for example the KRS or CEIDG number. */
  register: null,
  /** The postal address of the seller. */
  address: null,
  /** The EU VAT id (NIP with the prefix PL). */
  vatId: null,
  /** The e-mail address for contracts, withdrawal, refunds, and privacy requests. */
  email: null,
  /** The law that governs the contract, for example "the law of Poland". */
  governingLaw: null,
  /** The courts for disputes with business customers. */
  courts: null,
  /** The date the terms come into force. */
  effectiveDate: null,
};
