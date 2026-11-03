# ADR 0044 — Connectors as declarative plugins

Date: 2026-11-03.
Status: PROPOSED (draft). Written on the owner's decision of 2026-11-03 ("build everything in the
ADRs except the TEE track"), which brings back the connectors that `docs/goal.md` put out of scope.
Choices are **chosen by this ADR; the owner can change them**.
Answers: [ADR 0010](0010-closing-open-decisions.md), "Connectors" ("A later ADR will define
connectors as plugins. P4a and P4b move to that ADR").
Plan: [implementation-plan-misc.md](../design/implementation-plan-misc.md), units M27 to M29, the
last wave of that plan.

## Context

- A connector runs a named operation against an API with a stored credential. The broker adds the
  secret, the agent gets only the permitted output fields (`apassy_use_credential`, MCP; ADR 0004).
  Today there is one connector, the synthetic `reporting-api-v0`, compiled into
  `src/broker/profile.rs` (`OperationSpec` with `&'static` parameters, output fields, a path
  function, and a check function).
- The TLS rules of [ADR 0005](0005-connector-tls.md) apply: `https://` destinations, SNI and name
  check, no redirect, 64 KiB bodies.
- Placeholders and the run proxy ([ADR 0011](0011-run-proxy-placeholders.md)) already let a process
  or a cloud agent call any API of an item's hosts without the value. They authorize a host, not an
  operation, and the agent sees the whole answer.
- What a connector adds: the bouncer gate decides a **named operation** with a known action class
  (a list of issues is a read), so it can allow routine reads with certainty and ask less (ADR 0025).
  The agent gets **only the fields** that the operation names, so an answer cannot leak more than the
  owner allowed.

## Decision

### 1. A plugin is data, not code

A connector plugin is one JSON file (contract `connector-plugin-v1`, strict: an unknown field is
refused). It has no script, expression, or WebAssembly. The broker interprets it with fixed code.

```json
{
  "v": 1,
  "id": "github",
  "name": "GitHub (read only)",
  "version": "1.0.0",
  "hosts": ["api.github.com"],
  "auth": {"header": "Authorization", "scheme": "Bearer"},
  "operations": [
    {
      "name": "issues.list",
      "title": "List the issues of a repository",
      "action": "read",
      "method": "GET",
      "path": "/repos/{owner}/{repo}/issues",
      "params": [
        {"name": "owner", "in": "path", "kind": "slug"},
        {"name": "repo", "in": "path", "kind": "slug"},
        {"name": "state", "in": "query", "kind": {"enum": ["open", "closed", "all"]}, "required": false}
      ],
      "output": {"list": true, "max_items": 100, "fields": ["/number", "/title", "/state", "/html_url", "/user/login"]}
    }
  ]
}
```

- `hosts`: 1 to 4 exact DNS names, HTTPS on port 443. No wildcard, no IP, no path.
- `auth`: a header name from a fixed list (`Authorization`, `X-API-Key`, `PRIVATE-TOKEN`) and a scheme
  (`Bearer`, `token`, or none). The value is the item's secret field. Never a query parameter.
- `params`: kinds `slug`, `int` (0 to 2^31), `date`, `enum`, each with the rules of `profile.rs`
  (`ParamKind`). Path parameters are percent-encoded; a `/`, `.`, or `..` segment is refused.
- `output`: JSON pointers into each object; everything else is dropped. Strings are cut at 4 KiB.
  The answer is masked for the item's own secret value as today.
- `action`: `read`, `change`, `deploy`, or `delete`. It is an input to the bouncer gate, not a
  permission: production items always ask (ADR 0010), and the hard rules apply.

### 2. Version 1 is read only

Version 1 allows `GET` only. Change operations (methods with a body of typed parameters) wait for
`connector-plugin-v2`, after the first plugin has run. This keeps a wrong manifest from writing.

### 3. Where plugins come from

- **Bundled** plugins are files in `Apassy.app/Contents/Resources/connectors/`. The app signature
  covers them.
- **Owner-installed** plugins: `apassy connectors install <file>` or Settings → Tools → Connectors →
  Install…. The owner check (`OwnerAction::InstallConnector { id, version, sha256, hosts }`) shows the
  hosts and the operation titles. The vault pins the SHA-256 in a local table (`connector_plugin`,
  vault schema 35, plan unit M11). At start, a file whose hash differs from its pin is not loaded and
  the app says so. A new version with a new host needs a new owner check.
- There is no plugin store or download in version 1.

### 4. The token goes only where the item allows

An operation can use an item only when one of the plugin's `hosts` equals a destination host of the
item (its connector destination, or a website for a placeholder variable). A plugin that names
another host cannot get the item's value. The catalog of `apassy_list_access` lists, for each item,
only the operations of plugins that match it.

### 5. First plugin: GitHub, read only (P4a)

`github` with `repos.get`, `issues.list`, `pulls.list`, and `actions.runs.list`, for a fine-grained
personal access token with read permissions, against `api.github.com`. The synthetic
`reporting-api-v0` becomes a bundled test manifest with the same behaviour.

### 6. Databases (P4b)

Not in version 1. A database connector needs a wire protocol per engine and query rules. Until a
later plugin kind exists, database tools run as processes with placeholders and rule packs.

## What this does not protect

- A manifest that names too many output fields shows them to the agent. The owner sees the fields at
  install; bundled plugins get a review.
- A service that changes state on `GET` is not read only. The owner check names the operations.
- The output filter works on the JSON shape. A field that holds a secret by design (for example an
  API that returns tokens) leaks if the manifest names it.

## Consequences

- `docs/goal.md` "Out of scope" loses "Connectors for real services and the plugin design".
- `profile.rs` builds `OperationSpec` from data at start instead of from constants.
- The decision log records `request = 'connector'` (the column of the Bouncer section plan).
- Each connector call is in Activity and Logs as today.

## Required checks

- A manifest with an unknown field, a wildcard host, a query-parameter token, a method other than
  `GET`, or a path with `..` is refused.
- An item whose destination is another host cannot be used by the plugin.
- The output has only the named fields; the masker removes the item's value from every string.
- A redirect, a body over 64 KiB, and a TLS failure send no second request.
- A changed file after the pin is not loaded.
- A production item asks the owner for every operation.
