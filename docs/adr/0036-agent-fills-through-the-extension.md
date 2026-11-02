# ADR 0036: Agent fills through the extension

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
production allowances, bouncer brain answers checked by the bouncer gate, and owner questions. Code uses retain the
explicit code-covering project-answer requirement. Browser delivery branches only
after the same authorization recheck, before process environment creation. The
internal browser-fill command is descriptive policy input and is never executed.
An unknown action is conservatively classified by the existing rules; a browser
login does not establish a read-only production operation.

Both the agent's URL and the extension's active page must match the same saved
website through `site.rs`. No saved website is a refusal. No registrable-domain
widening is introduced. The requested and actual origin must also be equal.
Exactly one fresh focused-window extension target must match. The extension
binds approval and the delivery ticket to the extension instance, window, tab,
top frame, browser documentId and navigation/activation generation. Injection
targets that exact documentId. Navigation, tab replacement or tab closure refuses
delivery, including a switch away and back. An unfocused poll preserves the
selected document; after approval delivery waits at most 60 seconds for that
exact document to be active in the focused browser window again. Optional
site access must already be enabled by the owner; an agent cannot grant it.

## Threat model

A screen agent cannot read a masked password field through the display. For the
lifetime of the filled value, a type-attribute observer clears
the filled password if it becomes visible and sends a value-free activity report.
This is a visibility defense, not protection against a malicious website or DOM
access. The page receives the password and can process it normally.
Observation ends when the value changes, the field is removed, or the document
unloads. Visibility reports have no two-minute expiry either.

A CDP agent can read DOM values even when a field is masked. For remote debugging
and other unsafe switches, agent fills require `bypass::authorize_agent_fill` for
the exact `InstanceIdentity` verified by the socket guard for the native host
connection of the extension reporting the bound tab. Extension data cannot supply
this identity. Device-local trust covers the bundle, signing team, canonical
user-data root and debugging port or pipe, across all its profiles (ADR 0021).
Owner passkey/code grants, including an active five-minute grant, never authorize
agent polls or fills. Polling retains the verified identity and remote flag;
changes invalidate queued delivery, and trust is checked again before release.
Trusted unsafe instances set `agent_can_read_page = true` for secret-output risk
routing. The owner question states that the named agent can read the page through
remote debugging. Untrusted blocked-browser metadata can only veto a fill.

## Delivery and limits

The service worker uses an ephemeral random instance ID and a singleton
`agent_wait` long poll. Its request contains only the command, wire version and
instance ID; its answer data is `{type:"agent_wait", pending:true|false}`.
The app holds it for up to 50 seconds, replacing any older wait for that instance.
Only an authenticated fill demand wakes discovery, with no site or values in
the signal. Targeted polls then run at one-second intervals for at most 60 seconds;
discovery and delivery signals are consumed once per instance. Idle browsers
send no URLs and start roughly one host per 50 seconds instead of every second.
Failures back off at 5, 10, 30 and 60 seconds, resetting after success. Worker
evaluation, startup and installation restart the loop without an idle interval.
None of this signal path grants remote-debugging trust or authorizes a fill.

A guarded poll may
receive a single short-lived, erasing secret packet. Delivery is tied to the vault
epoch; locking or replacing the vault invalidates queued packets. A separate
acknowledgement contains only field names, never page text or secret values.
Missing acknowledgements are uncertain outcomes: inspect the page before retrying.
Only top-frame fills are supported. Extension worker suspension or missing host
permissions can make a browser temporarily unavailable; these are refusals.

Synthetic tests do not establish signed guard, browser, vault or device acceptance.
