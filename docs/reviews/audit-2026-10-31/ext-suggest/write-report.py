from pathlib import Path
import json,re,urllib.parse
out=Path('/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/ext-suggest')
# Keep public-page evidence without transient OAuth state, cookies, CSP nonces, or data images.
def scrub(x,key=''):
 if isinstance(x,dict):
  return {k:('[response headers omitted]' if k.lower()=='headers' else '[ephemeral target token omitted]' if k=='token' else scrub(v,k)) for k,v in x.items()}
 if isinstance(x,list):return [scrub(v,key) for v in x]
 if isinstance(x,str):
  if x.startswith('data:image/'):return '[data image omitted]'
  return re.sub(r'https?://[^\s\"<>]+',lambda m:m.group(0).split('?',1)[0].split('#',1)[0],x)
 return x
for p in out.glob('*.json'):
 p.write_text(json.dumps(scrub(json.loads(p.read_text())),indent=2)+'\n')
p=out/'native-requests.jsonl';p.write_text('\n'.join(json.dumps(scrub(json.loads(x)))for x in p.read_text().splitlines()if x)+'\n')
rows=json.loads((out/'matrix-real.json').read_text());receipt=json.loads((out/'receipt.json').read_text())
notes={
'fixture-login':('Yes: username, password; newsletter also qualifies','Yes, inline + popup','None'),
'fixture-react':('Yes: email + password','Yes, inline + popup','None; DOM autocomplete hint'),
'fixture-step1':('Yes: username; no password','Yes, inline + popup','None'),
'fixture-shadow':('Yes, in open shadow root','Yes, inline + popup','None; DOM hint'),
'fixture-same-frame':('Yes in same-origin child; top has no fields','Yes, inline in child + popup list','None; DOM hint'),
'fixture-cross-frame':('Child form exists; HTTP 127.0.0.1 has no inline access','No inline; popup lists parent-site login','None'),
'fixture-toggled':('Username yes; shown-as-text password excluded','Yes, inline + popup','None'),
'fixture-blank':('No login fields','No inline; popup still lists site login','None'),
'fixture-new-and-current':('Yes: separate join/sign-in groups','Yes, inline + popup','None'),
'fixture-signup':('Yes: email + two new-password fields','Yes, inline + popup','None'),
'fixture-typed':('Yes: username + password','Yes, inline + popup','None; DOM hint'),
'fixture-journey-login':('Yes: username + password','Yes, inline + popup','None'),
'fixture-journey-password':('Yes: username + current/new password','Yes, inline + popup','None'),
'github':('Yes: login_field + password','Yes after refocus; autofocus failure below','None'),
'gitlab':('No login inputs on Cloudflare challenge','No inline; popup lists GitLab metadata','HTTP 403; challenge page'),
'google':('Yes: identifierId; username-first, zero password fields','Yes, inline + popup','None; DOM hint'),
'microsoft':('Yes: i0116 + i0118 in DOM','Yes, inline + popup','favicon 404; BSSO info says NoExtension (Microsoft SSO)'),
'vercel':('Yes: email, input-_r_g_','Yes, inline + popup','/api/jwt 403; FedCM empty accounts; API/preload/GSI warnings'),
'x':('Not assessable: HTTP 403 browser error document','Not assessable for login UI','HTTP 403, ERR_HTTP_RESPONSE_CODE_FAILURE'),
}
order=[x for x in rows if x['name'].startswith('fixture-')]+[x for x in rows if not x['name'].startswith('fixture-')]
table=[]
for x in order:
 name=x['name'];fields,ui,page=notes[name];url=x['url'];label=url.replace('http://localhost:62903','localhost:62903')
 shot='x-network-result.png' if name=='x' else name+'-after.png'
 sw='None observed' if name!='x' else 'None observed in supplemental attempt'
 native='No transport errors; metadata replies OK' if name!='x' else 'No login request exercised'
 table.append(f'| [{label}](ext-suggest/{shot}) | {fields} | {ui} | {sw} | {page} | {native} |')
text='''# Apassy extension suggestion audit — 2026-10-31

**Verdict:** metadata suggestions work through the real native host and real scratch-vault matching code, but the owner's persisted profile enables the inline feature on only one hostname. Independently, an autofocus timing defect makes an enabled real GitHub login page appear broken until the field is refocused.

Audit only. No product source edits, commits, pushes, PRs, owner-vault access, owner-app connections, or credential submissions.

## Scope and proof boundary

- Requested checkout reset completed: `git fetch origin && git checkout -B audit/extension-suggest origin/main`. Audited HEAD: `6759f32022e6435ecb60aaba7fdd5d04e4c83e36`. Final worktree status is clean.
- Helium **0.20.2.1**, executable `/Applications/Helium.app/Contents/MacOS/Helium`, isolated temporary user-data directory, CDP **9341 only**. Ports 9222/9223 were never contacted. Browser control uses the small Node WebSocket client [cdp.mjs](ext-suggest/cdp.mjs), without Playwright or another browser.
- Loaded the unmodified worktree `extension/` (manifest 0.5.7, actual worker origin `chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/`). Final launch adds `--enable-unsafe-extension-debugging --headless=new --use-mock-keychain --password-store=basic --no-first-run --no-default-browser-check --window-size=1280,900`. Built-in uBlock was disabled only in this scratch profile during harness diagnosis.
- Built only the native host and a temporary audit adapter linking the real `apassy` library with `desktop,vault`. The adapter creates an actual encrypted scratch vault via `OwnerSession`, unlocks it with a synthetic passphrase, and dispatches `Request::parse` → `logins_for_page` / `suggestions_for_page` → real wire responses. It refuses all other commands. It does **not** instantiate the egui application/controller or run owner-check UI. Controller routing was inspected statically. See [backend.rs](ext-suggest/backend.rs) and [backend-Cargo.toml](ext-suggest/backend-Cargo.toml).
- Scratch HOME, scratch Unix socket, and a profile-local native manifest were used throughout. The wrapper explicitly sets `APASSY_BROWSER_SOCKET` to that scratch socket; no owner socket or application was used. A mock-host smoke test preceded the real backend; matrix conclusions below use the real host/backend, not mock matching.
- The vault held **17 synthetic logins**, including example.com, github.com, gitlab.com, app.example.com, localhost:8080, a login with no Website, public-page control domains, fixture origins, IDN controls, and separate/additional URL fields. No account was chosen and no fill/save/update/create/show was requested. The real backend recorded **207 metadata requests: 90 status, 89 logins, 28 suggestions**. [Native trace](ext-suggest/native-requests.jsonl).
- All builds used `CARGO_TARGET_DIR=/Users/rafalw/Dev/.audit-target-ext CARGO_INCREMENTAL=0`, with free-space checks before each build. Observed free space stayed above 8 GiB. No extension-tests runner or Playwright test was run. Six existing Rust site-matching unit tests passed.
- Public pages were loaded and fields focused only. No credentials were typed into them. Login submissions, Touch ID, real owner vault contents, actual owner runtime state, X SPA behavior behind its 403, and the GitLab form behind its challenge remain **unproved**.

Evidence: [matrix-real.json](ext-suggest/matrix-real.json), [github-gates.json](ext-suggest/github-gates.json), [supplement.json](ext-suggest/supplement.json), [frame-port.json](ext-suggest/frame-port.json), [receipt.json](ext-suggest/receipt.json). Transient public OAuth query parameters and response headers were removed from retained traces. All 70 screenshots are in `ext-suggest/`.

## Owner installation: read-only disk findings

[owner-install.json](ext-suggest/owner-install.json) records the disk snapshot and hashes. No owner browser CDP was used.

| Check | Finding |
| --- | --- |
| Actual profile root | `~/Library/Application Support/net.imput.helium/Default` |
| Installed extension | `Extensions/bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/0.5.6_0`, manifest version **0.5.6**, store install; no recorded disable reasons |
| Source compatibility | All **10** inspected JS/HTML/CSS files are byte-identical to main, including all three suggestion helpers. Version alone is not the explanation. No diff in audited extension/browser/owner-store paths between owner context `a1524ca` and main. |
| App version on disk | `/Applications/Apassy.app` Info.plist says **0.5.7**; no app launch performed |
| Native manifest | `~/Library/Application Support/net.imput.helium/NativeMessagingHosts/com.wydrox.apassy.json` |
| Binary | `/Applications/Apassy.app/Contents/MacOS/apassy-browser-host` exists and is executable; SHA-256 `6219d4dfa4edd301c57b57cc342de6e774a3da932e245cb875a2f7bfcab0f775` |
| Allowed origin | Exactly `chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/`, matching `src/browser/wire.rs:18-20` and `install.rs:88-95` |
| Host permissions | Broad HTTPS and localhost access already granted; permission is not equivalent to enabling the login script |
| Persisted login script | Latest LevelDB WriteBatch for the extension's `dynamic_scripts` key, **sequence 18**, registers `_dc_apassy-login-suggestions` only for **`https://odealo-admin.vercel.app/*`** |
| Separate passkey scripts | Registered for `https://*/*` and `http://localhost/*`; these do not display login suggestions |

The log was parsed as LevelDB records/WriteBatches, selecting the highest sequence, rather than treating historical strings as current configuration. This proves persisted disk configuration, not unsaved state inside the owner's running browser. It predicts no inline script on github.com, gitlab.com, accounts.google.com, login.microsoftonline.com, x.com, or vercel.com.

## Complete suggestion path

1. **Activation:** the manifest has optional host access and no static login content script (`extension/manifest.json:8-12`). The checkbox in `popup.js:480-501` requests a hostname permission. `login-worker.js:9-20,31-66` separately registers `login-target.js` and `login-suggestions.js` for that exact hostname, at `document_idle`, in all matching frames. Passkey activation is separate. A base-domain vault match does not enable scripts on every subdomain.
2. **Detection:** `fill.js:16-149,160-255` contains callable fill/read functions, not a page watcher. Current suggestions use `login-target.js:7-67`. Enabled, visible, writable HTML inputs qualify: passwords, email inputs, or text/tel inputs with username autocomplete or username-like name/id/autocomplete. Open shadow roots are traversed; closed roots are not. Detection groups the intended form/fieldset/group and binds actual nodes to a document/URL/form token. Cross-origin form actions are refused.
3. **Timing:** `login-suggestions.js:111-123` delegates focus/input events, so later-added forms can work without rescanning on every DOM mutation. There is no initial query for an already focused field. `load()` silently closes the menu when capture fails (`:89-100`). Username-first forms work when the input qualifies; a password field is not required.
4. **Request:** focus sends `login_suggestions` with only a token and username prefix (`login-suggestions.js:97`). `background.js:1283-1294` routes it to `handleLoginField`. `login-worker.js:173-202` verifies extension/tab/document/frame metadata, site access, active tab, origin and current target; cross-origin frames are rejected. It sends native `suggestions` using browser-derived sender URL, not a page-supplied URL.
5. **Native/app:** `background.js:66-92` opens one native port. `apassy-browser-host.rs:5-6` calls the relay. `relay.rs:171-177,250-275,295-307` checks extension origin, frames JSON, and exchanges one line with the selected Unix socket. `wire.rs:43-49` selects the socket. `desktop/browser.rs:326-330,402-449` answers metadata only if a vault is unlocked; suggestions do not request owner proof.
6. **Matching:** `desktop/owner_store/browser.rs:154-159,359-383,780-820` filters non-archived password logins by visible Website/URL fields and then case-insensitive username prefix, before the 50-row limit. A missing Website does not fall back to title, service name or email domain. Any one of several separate Website fields can match.
7. **Reply/UI:** wire `Data::Logins` holds origin/host/title/username/item/has_totp, no password (`wire.rs:702-707,844-852`). The worker strips suggestions to item/title/username. The inline chooser is a closed-shadow menu below the field, not a persistent field icon (`login-suggestions.js:17-100`). The toolbar popup independently calls status + logins and can list accounts even on a page with no fields (`background.js:139-184`, `popup.js:76-121`). The badge is an action-failure `!`, not a suggestion count (`background.js:539-564`); it stayed empty during metadata success and silent no-menu cases.

## Browser matrix

All successful inline rows below are **after explicit scratch-profile site permission and feature enablement, followed by field focus/refocus**. Broad permissions were preapproved through Helium's scratch `chrome://extensions` API, then activated through the real popup `chrome.permissions.request`; this avoids a native permission-dialog automation dependency. The extension files/manifest were not modified. This validates granted-state behavior, not the manual permission-dialog UX.

The password-form fixtures are declared in `extension-tests/support/pages.mjs`; all **13** were served on localhost and exercised without importing `support/fixtures.mjs` or a Playwright library. Other `fixtures/` subdirectories contain passkey/unit harnesses, not additional password login pages.

“None observed” refers to Runtime/Log events captured during the recorded attempt; it is not a claim about all browser startup history. DOM autocomplete recommendations are informational. Each page link opens its screenshot.

| Page | Fields detected | Suggestion shown / location | Service-worker console errors | Page console / network errors | Native messaging |
| --- | --- | --- | --- | --- | --- |
'''+ '\n'.join(table)+'''

For X, the supplemental CDP record confirms document **HTTP 403**, `net::ERR_HTTP_RESPONSE_CODE_FAILURE`, and the browser's “Access to x.com was denied” page. The initial matrix runner's `target tab missing chrome-error://chromewebdata/` was a harness assumption after that denial, not an Apassy error. For GitLab the captured page is Cloudflare “Performing security verification,” not a login form. Neither result proves a site-specific detector defect.

## Proven root causes and additional limits

### 1. Primary owner-specific cause: login suggestions are enabled for only one hostname

**Evidence:** owner LevelDB sequence 18, exact matches list above; all main feature files match the installed files. A controlled real GitHub run with the feature off has no injected target helper, no menu and no suggestion request; enabling plus refocusing produces the account. See [github-off-focused.png](ext-suggest/github-off-focused.png), [github-refocus.png](ext-suggest/github-refocus.png), and [github-gates.json](ext-suggest/github-gates.json).

**Code:** `login-worker.js:16-20,31-64`; `popup.js:480-501`. Both registration and permission are required. Passkey permission/activation does not turn on login suggestions. This is configured product behavior whose setup/status is easy to misinterpret, not evidence of a broken native host.

### 2. P1 usability defect: already-focused fields never initiate the first query

**Evidence on real GitHub:** with `login_field` focused and site access off, enablement returns `{ok:true,on:true}`. The helper then reports the field eligible and capture OK, but there is **no menu and no new native request**. Blur/refocus generates one `suggestions` request and the inline GitHub account. Reload with suggestions already enabled again leaves `login_field` focused, capture OK, and no menu. See [github-enable-already-focused.png](ext-suggest/github-enable-already-focused.png), [github-enabled-reload-autofocus.png](ext-suggest/github-enabled-reload-autofocus.png), and the gates JSON.

**Code:** `login-worker.js:55-63` injects at idle; `login-suggestions.js:3-5,111-123` only installs listeners and never initializes from `api.active()`. No owner check is needed to fix metadata lookup timing.

### 3. P2 detector gap: label-only username-first fields are excluded

**Controlled browser proof:** a visible writable text input with neutral id/name `f1`, associated “Email or username” label, aria-label and “Username” placeholder is focused. The helper reports `eligible:false`, `capture:{ok:false,reason:"no_fields"}` and no menu. [Screenshot](ext-suggest/label-only-first-step.png), supplement JSON.

**Code:** `login-target.js:15-16` does not use label text, aria-label or placeholder as positive username signals. This is not a failure of all username-first pages: real Google and the step1 fixture pass. Broadening must remain conservative because newsletter email fields currently qualify too.

### 4. P2 misleading empty state: username filtering is presented as a Website problem

**Controlled real-vault proof:** on the local typed fixture, synthetic username `nonmatching-prefix` returns no inline rows. The same page's popup state still has the matching “Fixture” login. The inline message nevertheless says to edit Website. [Screenshot](ext-suggest/prefix-no-match.png), supplement JSON, [matching-vault.json](ext-suggest/matching-vault.json).

**Code:** prefix filtering is intentional at `owner_store/browser.rs:154-159`; `login-suggestions.js:97-100` uses one empty message regardless of whether the username filter removed existing site matches. “Show all accounts” exists, but the explanation sends users toward the wrong repair.

### 5. Matching rules explain some absent rows; Unicode addresses are a real parser limitation

[matching.json](ext-suggest/matching.json) executes the real `Website`/`Page` code; [matching-vault.json](ext-suggest/matching-vault.json) executes the real `OwnerSession` against the scratch vault.

| Stored Website | Page | Observed result |
| --- | --- | --- |
| `example.com` | `https://app.example.com` | Matches base login; exact subdomain login also appears |
| `app.example.com` | `https://example.com` or `https://auth.example.com` | Does not match; sibling/base widening is not implemented |
| `www.example.org` | `https://example.org` / `https://app.example.org` | Bare host matches; sibling does not |
| `http://example.com` | `https://example.com` | Matches; stored HTTP can upgrade to HTTPS |
| Any external host | external `http:` page | Page parser refuses insecure page |
| `http://localhost:8080` | port 8080 / 8081 | Match / no match |
| `münchen.de` imported visible Website detail | punycode page | Not parsed; Unicode legacy login absent |
| `xn--mnchen-3ya.de` | same canonical page | Matches; punycode login present |
| No Website | tested origins | Seeded item never appears; no inferred match |
| Website + separate “Website 2” | second.example | Matches via the second field |
| Two space-separated URLs in one detail | first/second.example | Not parsed as a URL list; no match |
| `co.uk` or `github.io` | unrelated child domain | **Matches**: no public-suffix boundary validation |

**Code:** `site.rs:154-191,197-204,216-280`; `owner_store/browser.rs:801-820`. The implementation is a host/suffix rule, **not eTLD+1 matching**. Unicode outside ASCII is rejected. Missing Website and strict ports are intentional safety boundaries, not grounds to guess from item names. Public-suffix acceptance is a separate matching-safety finding, not a cause of absent suggestions.

### 6. Frames, shadow DOM, and dynamic forms need precise qualification

- Standard same-origin URL iframe: inline suggestions work in the child document. The popup still captures only the top frame and can have a frame/no-fields target even while listing metadata (`login-worker.js:69-77`).
- Cross-origin iframe, including **same hostname but another port**: scripts can detect its field, but the worker refuses the sender origin and displays “Open this sign-in page in its own tab.” [Frame proof](ext-suggest/cross-origin-port-frame.png), frame-port JSON; `login-worker.js:175-178`. This is the explicit security boundary, not a native failure.
- Same-origin `srcdoc`: child field is present/focused, but no helper is injected. [Screenshot](ext-suggest/same-origin-srcdoc.png). `matchOriginAsFallback:false` at `login-worker.js:57` explains the gap; broad “same-origin frames supported” language needs qualification.
- Cross-origin form action: an eligible field captures `form_origin`; `load()` closes silently. [Screenshot](ext-suggest/cross-origin-action.png); `login-target.js:63`, `login-suggestions.js:91-92`. Preserve refusal; improve explanation.
- Open shadow root works; closed root does not expose its input to detection. [Closed-root control](ext-suggest/closed-shadow.png); `login-target.js:17-28`. Closed roots are already documented as unsupported.
- Late-inserted SPA form works once its field receives focus. [Screenshot](ext-suggest/late-spa-form.png). Lack of a MutationObserver does not, by itself, establish broken SPA support. Real X SPA acceptance remains unproved because of HTTP 403.
- HTTP localhost can enable inline suggestions, but HTTP 127.0.0.1 / [::1] cannot through `loginMatch`/the checkbox despite backend loopback support (`login-worker.js:9-13`, `popup.js:483`, `manifest.json:9`).

## Native transport and errors

[native-diagnostics.json](ext-suggest/native-diagnostics.json) records deliberate **scratch-only** controls:

| Control | Actual result |
| --- | --- |
| Real host + real scratch vault adapter | Status unlocked; all matrix metadata replies successful |
| Profile-local manifest allowed_origins deliberately denies audit extension | Browser disconnect: “Access to the specified native messaging host is forbidden.”; worker maps to `host_missing` |
| Manifest restored | Status succeeds again |
| Scratch adapter stopped, wrapper still targets scratch socket | Real host returns `not_running`; worker state is `not_running` |

No worker console error was observed in these controls. The normal disconnect listener consumes `chrome.runtime.lastError` (`background.js:84-88`), so absence of a console error does not prove native connectivity. Inspect structured replies. The owner's manifest passes static path/origin checks; its live connection, vault state and actual Website values were intentionally not queried. A locked/no-vault response is handled in `desktop/browser.rs:403-419`; owner lock state remains unknown.

## Ranked fix plan — no implementation performed

| Rank | Priority | Change and location | Test that proves completion; no Playwright needed |
| --- | --- | --- | --- |
| **1** | **P1 UX** | Make exact-host login-suggestion enablement and permission state obvious in popup/setup. Distinguish it from passkeys and broad site access. Explain first-use enablement and empty Website requirements. `popup.html`, `popup.js:480-501`, `login-worker.js:16-66`; update `docs/operations/browser.md` (currently omits the inline workflow and retains obsolete limits). | CDP Helium: fresh profile/off → no inline requests; enable only github.com → inline metadata works there, remains off on another host. Open popup after passkey permission alone and verify it clearly reports suggestions off. Never auto-enable host access. |
| **2** | **P1** | Query the currently focused eligible field after first injection and re-enable; retain generation/document/form checks and metadata-only behavior. `login-suggestions.js:3-5,89-123`, `login-worker.js:59-64`. | Re-run `github-gates.mjs`: already-focused GitHub field and enabled reload show metadata without blur/refocus; exactly bounded suggestion requests, no fill/save, no owner prompt. Add a controlled autofocus fixture to avoid relying solely on live GitHub. |
| **3** | **P2** | Improve conservative username-first recognition with accessible labels/aria-label/placeholder and form context. Share or reconcile positive field heuristics between old fill/read helpers and target capture. `login-target.js:7-16,37-67`, `fill.js` equivalents. | CDP label-only fixture becomes eligible and displays account metadata. Negative cases: search, OTP, hidden/readonly inputs, newsletter-only forms and shown-as-text passwords. Google, open shadow root and multiple-form fixtures continue working. |
| **4** | **P2** | Separate “no accounts for this site” from “no accounts match this username”; make clear/show-all recovery direct. `login-suggestions.js:97-100`; optionally metadata-only result semantics in `login-worker.js`/wire/owner store. | Scratch vault: valid Website + nonmatching prefix gives a username-filter explanation; Show all restores the site account; truly absent Website gives Website guidance. Verify no password is present and no secret command occurs. |
| **5** | **P2 correctness / safety** | Canonicalize IDN Website values and validate host scope, including rejecting public suffixes, without automatically widening to eTLD+1/sibling hosts. Preserve strict port and HTTPS policy; explain multiple URLs as separate Website details. `site.rs:154-191,250-280`, owner edit/import validation and `owner_store/browser.rs:801-820`. | Rust unit tests: Unicode/punycode equivalence; co.uk/github.io rejection; malicious suffix negatives; www asymmetry; subdomain/sibling policy; ports; missing Website; two separate URL fields. CDP + scratch-vault metadata readback proves the normalized item is offered. |
| 6 | P2 | Support or explicitly explain same-origin srcdoc/about:blank frames under an origin-checked policy. Keep cross-origin refusal; provide useful top-frame/popup recovery for frame and form-action failures. `login-worker.js:55-77,173-178`, `login-target.js:41,63`, UI error mapping. | CDP standard same-origin iframe, srcdoc, cross-port and cross-host frames. Only intended origin gets metadata; cross-origin receives explicit own-tab guidance; no credential operation is emitted. |
| 7 | P3 coverage / docs | Move suggestion smoke coverage to a small maintained CDP Helium harness; cover exact-host grants, reload/autofocus, two-step forms, dynamic insertion, labels, frames, matching and native error states. Keep external-page blocks separate from detector failures. | Run the controlled suite without Playwright; log fields/menu/popup/badge/structured native errors and screenshots. Public GitHub/Google/Microsoft/Vercel checks are supplemental; X/GitLab require an accessible login document before claiming acceptance. |

Do not bypass per-fill/per-save owner checks, infer Website from an email address/title, automatically submit forms, or loosen cross-origin/password-delivery checks to repair suggestions. Metadata lookup itself requires no fresh Touch ID.

## Validation and cleanup

- `cargo build --locked --bin apassy-browser-host`: passed.
- Temporary adapter build with `desktop,vault`: passed. Initial offline dependency miss and two audit-adapter initialization/compiler errors were corrected in the temporary harness; they were not product failures. The full GUI executable was not built/launched.
- `cargo test --locked --lib --no-default-features browser::site::tests -- --nocapture`: **6 passed, 0 failed**, 59 filtered out. Existing extension Playwright tests were read for intended behavior, not executed.
- Initial Helium web navigation stalled before the safe-keychain flags were added. This is recorded as a harness limitation, not a product root cause. Final browser matrix and screenshots are from successful isolated Helium runs.
- All three tracked long-running processes (Helium, fixture runtime, scratch backend) stopped. CDP 9341 and fixture-port listeners are absent. The extra frame fixture server closed. `/Users/rafalw/Dev/.audit-target-ext` and the entire temporary HOME/profile/vault root were removed. Final `df -h /` reported **18 GiB available**; concurrent machine activity means this is not a build-cleanup recovery measurement.
- Final source worktree status is clean at the audited HEAD. Only this requested report and audit evidence were written under `/Users/rafalw/Dev/apassy/docs/reviews/audit-2026-10-31/`. See the receipt for binary hashes, process cleanup, counts and commands.
'''
(out.parent/'extension-suggestions.md').write_text(text)
print('report words',len(text.split()),'matrix rows',len(rows),'screenshots',len(list(out.glob('*.png'))))
