# ADR 0035: Agent fills through the extension

Date: 2026-11-02

Status: Accepted

## Decision

Agents logging in during computer use call `apassy_fill_in_browser`. The MCP
adapter receives only status and filled field names. Values travel from the vault
through the caller-checked native host to the extension's existing page functions.
No clipboard or agent typing is involved. The user submits the form.

The tool requires item_id, url, purpose and user_request (the user's own words).
fields defaults to username and password; code is explicit. cwd and
idempotency_key are optional. Tracked operations retain value-free outcomes.

The existing run policy checks agent visibility, restored and archived items,
declarations, project/environment restrictions, Always ask, host task evidence,
production allowances, model decisions and owner questions. Code uses retain the
explicit code-covering project-answer requirement. Browser delivery branches only
after the same authorization recheck, before process environment creation. The
internal browser-fill command is descriptive policy input and is never executed.
An unknown action is conservatively classified by the existing rules; a browser
login does not establish a read-only production operation.

Both the agent's URL and the extension's active page must match the same saved
website through `site.rs`. No saved website is a refusal. No registrable-domain
widening is introduced. The requested and actual origin must also be equal.
Exactly one fresh focused-window extension target must match. The extension
checks focus, tab and origin again immediately before page injection. Optional
site access must already be enabled by the owner; an agent cannot grant it.

## Threat model

A screen agent cannot read a masked password field through the display. For two
minutes after an agent fill (or until navigation), a type-attribute observer clears
the filled password if it becomes visible and sends a value-free activity report.
This is a visibility defense, not protection against a malicious website or DOM
access. The page receives the password and can process it normally.

A CDP agent can read DOM values even when a field is masked. Remote debugging and
other unsafe browser switches currently fail the caller guards. A small
`agent_fill_allowed_in` predicate is the trust integration point; routing also
accepts `agent_can_read_page`, which adds the secret-output risk when true.
Untrusted blocked-browser metadata can only veto a fill and cannot authorize one.
The profile-trust worker owns future guard/profile integration; this ADR does not
introduce a trust module or bypass the existing guard.

## Delivery and limits

The service worker polls with an ephemeral random instance ID. A guarded poll may
receive a single short-lived, erasing secret packet. Delivery is tied to the vault
epoch; locking or replacing the vault invalidates queued packets. A separate
acknowledgement contains only field names, never page text or secret values.
Missing acknowledgements are uncertain outcomes: inspect the page before retrying.
Only top-frame fills are supported. Extension worker suspension or missing host
permissions can make a browser temporarily unavailable; these are refusals.

Synthetic tests do not establish signed guard, browser, vault or device acceptance.
