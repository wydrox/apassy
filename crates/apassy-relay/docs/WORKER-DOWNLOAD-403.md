# 0.5.8 public-download 403 investigation

Production remained read-only during this investigation: no deploy, rollback,
Cloudflare setting change or VPS write. Evidence was read from
`/opt/apassy/releases/0.5.8/` over SSH. The relay stayed on 0.5.7.

## Failed request and retained evidence

`resume-commands.md` step 8 and `public-assets.py` identify the first request as:

```http
GET /dl/apassy-team-linux-x86_64 HTTP/1.1
Host: apassy-relay.wyderka.cc
User-Agent: Python-urllib/3.9
Accept-Encoding: identity
Connection: close
```

The script called `urllib.request.urlopen(url, timeout=60)` from Apple's Python
3.9.6 on the Mac, with no custom headers, authentication, Range or edge secret.
The wire defaults above follow that client. `public-assets.before-restart.log`
contains only the `HTTPError: HTTP Error 403: Forbidden` traceback: the original
response headers/body, `CF-Ray` and exact Cloudflare decision were **not saved**.
It failed before the script read download bytes or restarted the candidate relay.
The runbook previously specified public readback but supplied no concrete request
command; the saved script was the actual attempted implementation.

Attempt 1's `worker-public-check.log` records passing public delivery for version
0.5.8/source `9dd5172897268862e9806893bcf2b5fe8e463b92`, including both binaries.
Its exact HTTP client/user agent is not retained in the available files.
Attempt 2's `worker-deploy.log` records passing build-hook verification and
"No updated asset files to upload", then version
`47a93158-3857-4255-839e-4cb6cceb671d`. Its `release.json`, `SHA256SUMS` and
`verified.json` name the same artifact sizes/hashes as attempt 1:

| Binary | Bytes | SHA256 |
| --- | ---: | --- |
| Linux x86_64 | 5198120 | `859c85601513230f42e5c793697c7debd688434add8148ba1010294c4ff102fb` |
| Darwin arm64 | 9558240 | `ba451ffe149ac19551c6c8aef7f9b1101e803b5d99a22f60ae6601c26bd3b0e3` |

The available evidence supports identical asset contents, not missing or renamed
downloads. The upload log is not an independently exported historical manifest.

## Reproduction and cause

On 2026-10-31 at 22:22:19–22:22:20 UTC, Python `urlopen` on the same Mac made
three full GETs to the failing public URL against live **0.5.7**, changing only
`User-Agent` in an A/B/A probe:

| User agent | HTTP | Evidence |
| --- | ---: | --- |
| `Python-urllib/3.9` | 403 | `error code: 1010\n`, 17 bytes; `CF-Ray: a5360eceaf1cee42-WAW` |
| `apassy-release-check/0.5.8` | 200 | 5193576 bytes, SHA256 `c0a7b4d430bcd374d78aa321ac4c7f78620cc7fc82bc5a1ced3e59cc075c51f4`, `CF-Cache-Status: HIT` |
| `Python-urllib/3.9` | 403 | Same 17-byte 1010 body; `CF-Ray: a5360ed3b948016a-WAW` |

Both 403s had `Server: cloudflare`, `Content-Type: text/plain; charset=UTF-8`,
`Cache-Control: private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0`,
and **no `cf-mitigated` or `Retry-After` header**. An earlier same-client probe
using `User-Agent: curl/8.7.1` also returned HTTP 200 and the same 0.5.7 binary.

This establishes a current Cloudflare client-signature block for Python's default
user agent, independent of deploying 0.5.8 or repeated downloads. It strongly
explains attempt 2, although its unsaved response cannot prove the historical rule.
Cloudflare documents [1010 as browser-signature blocking](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1010/)
and recommends a descriptive application user agent. A Browser Integrity Check
decision is consistent with this evidence; no account settings or security events
were inspected, so a specific zone rule/service is not claimed as verified.
[Challenge Pages set `cf-mitigated: challenge` and HTML](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/);
the absence of that header does not rule out other Cloudflare blocks.

`git diff b8dc65e 9dd5172 -- deploy/worker` changes only package version metadata,
asset verification scripts/tests, the deploy npm command and the Wrangler build
hook. **No Worker runtime or static routing changed.** `/dl/*` and the static
paths enter `ASSETS.fetch` before relay-secret checks and rate limiters. GET/HEAD
are allowed; other methods return 405, unsafe/missing paths return 404. Headers
and Range are forwarded to assets, with internal edge/prefix headers stripped.
There is no new user-agent, manifest-secret or 403 branch in the Worker.

## Local proof and next attempt

Downloaded both CLI artifacts from successful GitHub
[image run 41246581106](https://github.com/wydrox/apassy-relay/actions/runs/41246581106)
at the exact approved 9dd5172 source into a temporary directory. Verified each
platform SHA256SUMS, metadata and the runbook's combined staging/preflight.
Ran the pinned `npx wrangler dev --local` at that source: VPC was disabled, all
assets were local, and no secret was needed. Replayed the saved six-request
Python script with only the base URL/local directory changed: all six HTTP 200
responses matched exact staged bytes. Python-default, curl and application user
agents all passed local GET/HEAD, with and without Range or a dummy edge header.
The local asset server answered full HTTP 200 to Range (not 206 or 403); missing
and renamed binary paths returned 404. Attempt 1's exact user agent is unknown,
so this tests its verified artifact conditions, not an invented HTTP transcript.

The new read-only checker uses the tested application user agent and retains
bounded response diagnostics, retries and exact-byte acceptance; fixture tests
reproduce the old urllib 403/1010, transient challenges/stale bytes, and rejection
of persistent challenges, wrong bytes and redirects. The runbook retains the
manifest/config image-identity correction and explains how to use the new checker
while keeping an existing artifact checkout pinned to its approved source SHA.

GO for a separately approved next deployment using those verified artifacts and
the corrected image identity gate. Before deploying, verify connectivity with
the new client against the current verified release; after deploying, require all
six candidate files to pass the public gate before restarting the relay. NO-GO
on exhausted retries, challenge responses, redirects or any byte/source mismatch.
This investigation does not establish live 0.5.8 acceptance or authorize deployment.
