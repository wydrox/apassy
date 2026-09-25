# Apassy synthetic owner walkthrough

Date: 2026-09-16.
Status: P0 visual prototype. This is not a product release.

This directory is a disposable design prototype of the owner journey.
It uses demo data in memory.
The owner selected a macOS desktop app as the first product platform and form.
This browser walkthrough is not the final production user interface.

## What this walkthrough is

This walkthrough shows the owner path with synthetic items:

1. Store credentials in five categories.
2. Search, edit, and delete fixture items.
3. Show a synthetic value with a demo reveal. Copy does not write to the clipboard.
4. Review a plain-language rule with a fixed interpreter.
5. Enroll a synthetic agent, then revoke it.
6. Permit a normal request.
7. Pause an uncertain request.
8. Deny a production request. This denial cannot be approved.
9. Keep a waiting request when notification delivery fails.
10. Lock the vault. Lock hides item details and makes pending demo authority invalid.

## What this walkthrough is not

This walkthrough is not a secure vault.
It does not encrypt data.
It does not authenticate an owner.
It does not call a service connector, language model, or Jev.
It does not persist state.
It does not prove agent isolation.

Do not enter real secrets.
The model does not accept secret input fields.
It assigns fixed synthetic values.

## Commands

Run the model tests from the repository root:

```
node --test design/walkthrough/model.test.mjs
```

Serve the walkthrough from the repository root. Common browsers need an HTTP origin for ES modules:

```
python3 -m http.server 8765 --bind 127.0.0.1 --directory design/walkthrough
```

Then open:

```
http://127.0.0.1:8765/
```

Ctrl-C stops the server.
No packages are needed.
The app does not make application API or external requests.
The browser loads only the static files from loopback HTTP.

## Files

- `index.html` — page structure
- `styles.css` — layout and colors
- `app.mjs` — user interface
- `model.mjs` — pure state model
- `model.test.mjs` — Node tests for the model

## Supported sample

The fixture interpreter matches this exact text:

```
My reporting agent can use this credential for Project A, against staging, until Friday. Never use it for production. Ask me if the request does not fit the task.
```

It also recognizes three refused samples: ambiguous, conflicting, and unsupported.
Other text is unfamiliar. The interpreter does not guess.

Activation requires an enrolled reporting agent, a reviewable draft, and an explicit owner demo confirmation.
The sample expires at `2026-09-18T23:59:59-04:00` in time zone `America/New_York`.
The sample usage limit is 3.

## Limits

- Reveal and copy are demo controls. Copy does not write to the clipboard.
- Lock and Open vault are demo controls. They are not owner authentication.
- Reset loads the fixture state again. All changes are lost.
- Backup and restore are not present.
- Agent use is a fixture for the reporting API item only.
- This prototype does not complete P0 or MVP.

The owner selected a macOS desktop app as the first product platform and form.
Storage, connector, notification, and product isolation decisions remain open.
