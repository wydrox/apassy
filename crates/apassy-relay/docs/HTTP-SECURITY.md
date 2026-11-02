# HTTP parser and deadline mitigation (2026-10-31)

The original `tiny_http` crate still publishes **0.12.0** (`cargo search tiny_http`).
Upstream reports [CVE-2026-66752](https://github.com/tiny-http/tiny-http/issues/287)
for request framing and [CVE-2026-66753](https://github.com/tiny-http/tiny-http/issues/288)
for CR/LF header injection remain open. The published maintained fork
[`tiny_http_dh` 0.12.3](https://github.com/dheijl/tiny-http-dh) advertises fixes, but
its manifest requires Rust **1.98.1**; this relay pins **1.97.0**. It is not a
compatible dependency upgrade. No unreleased commit is assumed to fix the reports.

This bounded mitigation vendors the original 0.12.0 source, with its MIT/Apache
licenses, and patches the narrow parser/transport boundary. See
[`vendor/tiny_http/APASSY-PATCH.md`](../vendor/tiny_http/APASSY-PATCH.md). The
unchanged upstream version identifies the base source, not an upstream fixed
release. Future upgrades must remove/reapply these changes deliberately.

- Reject duplicate Content-Length or Transfer-Encoding, both together, invalid or
  overflowing lengths, and any transfer coding except a single `chunked`.
- The line reader rejects bare CR/LF before trimming; header constructors/parser
  reject CR, LF, NUL and other prohibited control bytes;
  field names must be HTTP tokens. Folded headers are rejected; only SP/HTAB count
  as optional whitespace. Lines are limited to 8 KiB, with at most 100 fields and
  64 KiB of total header lines. Guarded connections reject upgrades, whose upstream
  reader otherwise ignores CL/TE framing.
- Inbound chunk metadata is limited to 8 KiB per line without allocation, uses
  checked hexadecimal arithmetic and strict CRLF, and rejects incomplete chunks.
  Incomplete length-delimited bodies also fail. Trailers remain unsupported, as in
  the base crate. Valid chunk extensions and ordinary chunked bodies still work.
- The relay uses one request per connection and explicitly closes it after the
  response. Absolute header/body budgets are 10/30 seconds, with at most 5 seconds
  of blocking socket read or write. Body progress does not reset its total budget.
  This permits the existing 64 MiB upload cap at sufficient throughput; clients on
  slower links receive a transport failure and must retry after checking the head.
- A single timer thread closes expired transports after 90 seconds from acceptance,
  including blocked writes. This allowance includes the existing 25-second polls.
  It cancels transport I/O; it cannot roll back an already committed DB mutation or
  preempt arbitrary CPU work. Clients must resolve ambiguous write outcomes.
- Busy refusal cancels socket input before dropping any unread body. Other early
  refusals may drain within the same absolute body budget. Health cancels input too,
  so GET bodies cannot hold its four seats. Small bodies are not pre-read before
  relay admission. The accept loop
  dispatches 503 writes to a separate lane of at most eight workers; overflow closes
  the socket immediately. Health has four reserved seats. Destructor draining uses
  a bounded 8 KiB buffer rather than allocating the untrusted declared length.
  Admission caps live transports at 1024 before parsing or spawning a worker.

`tests/server_http.rs` exercises stalled/refused uploads, health/approval progress,
trickling bodies and malformed framing/header constructors. Existing sync and proxy
suites cover normal uploads/streams. These are local/CI regressions, not a claim of
Cloudflare/VPC exploit testing or production acceptance. Header-stage floods can
still fill the bounded transport pool until their deadlines; rate controls and process
limits remain relevant. A maintained server migration is separate work.

CI installs pinned `cargo-audit` **0.22.2** and checks the current RustSec database,
with warnings denied and no advisory ignores. The published CVEs above are tracked
here even if absent from RustSec. Audit success is dependency database evidence;
it does not independently certify this local parser patch. CI also requires a
negative control: `bash scripts/test-advisory-gate.sh` must reject `time 0.1.44`
specifically with RUSTSEC-2020-0071. Scanner/network/fixture errors do not pass it.

## Independent review addendum

The review started at `8d7f9af`. Every source change against the cached crates.io
0.12.0 crate was inspected: request/header construction, client limits and lifetime,
connection timeouts, deadline reaper, RefinedTcpStream clones, response close header,
EqualReader destructor, util exports and dummy-trait warning suppression. Unchanged
source files and Cargo manifest compare byte-for-byte. Added `deadline.rs` was
reviewed in full. The tarball matches the SHA-256 in APASSY-PATCH.md. Both license
files are byte-identical to upstream, and its manifest retains authors, repository
and dual-license attribution. The new inbound chunk reader was reviewed in full.

| Published advisory | Disposition for this relay |
| --- | --- |
| [CVE-2020-35884 / RUSTSEC-2020-0031](https://rustsec.org/advisories/RUSTSEC-2020-0031.html) | Mitigated: upstream lists 0.8.0+ as fixed; this 0.12.0 base also gets strict TE/CL rejection and no connection reuse. |
| [CVE-2026-66752](https://github.com/tiny-http/tiny-http/issues/287) | Fixed by the local patch: one `chunked` TE only, never together with CL; duplicate/overflowing CL, folding and guarded upgrades fail. No pipelined successor is dispatched. |
| [CVE-2026-66753](https://github.com/tiny-http/tiny-http/issues/288) | Fixed by the local patch on relay construction paths: Header::from_bytes/from_str reject line controls and invalid names. The relay never constructs a Header directly from its public fields. |

The Worker forwards a parsed Request body, not the original HTTP bytes. It drops
CL/TE and the body on GET/HEAD, so a public health GET cannot carry the tested body
attack through this Worker. For other methods it checks declared lengths, replaces
the edge secret and streams to a fixed origin. Cloudflare's
[Request framing documentation](https://developers.cloudflare.com/workers/runtime-apis/request/#set-the-content-length-header)
states that the runtime derives framing from the body source; arbitrary streams
can become chunked. The origin must therefore accept valid chunks and validate
framing itself. Node tests establish local forwarding behavior only; actual VPC
wire bytes and edge rejection of malformed public requests were not tested.
Origin attack tests bypass the Worker deliberately.

Privileged mutation enumeration (route table in `src/server/http.rs`):

| Mutation group | Authority checked with the write |
| --- | --- |
| Invite create; collection create/policy; item create/archive; grant create/revoke; approval deny | require_member(Approver) |
| Member role | require_member(Owner) |
| Member revoke/leave; agent create/revoke | require_member(Member), current role equality, target ownership/owner rules |
| Device enroll/revoke/key-holder | require_member(Member/Owner), target and last-owner/key-holder rules |
| Join confirm/refuse; link create/confirm/refuse | require_member(Approver/Member), live join/link checks |
| Host release/deny | authorize_host_on: current owner and key-holder/bootstrap state |
| Snapshot push/receipt/delete | require_member(Member/Owner); push/delete hold sync_commit |
| Question post/answer/settle; push-token put/delete | require_member(Member), current device/routing checks |
| Feed put/delete/action-post/action-settle | require_member(Member), device/routing checks |
| Run create, including MCP | agent_by_id, authenticated member equality and current grant checks |

Each listed check and mutation is in Store::tx, which begins IMMEDIATE under the
connection mutex. Demotion/revocation cannot commit between that read and write.
Approve always refuses without mutation. Public team/connect/join/link and
cancellation routes check code/key authority inside their write transaction.
Challenge/token memory writes confer no authority past a later live-device check.
GET expiry maintenance is a server-owned state transition.

Backup: the directory lock freezes its key/list snapshot; order is directory ->
sync_commit -> team store. SQLite's backup API includes committed pages. Each team
DB and its current/previous retained files are copied and verified under sync_commit.
Missing failed-open/suspended teams fail explicitly. Restore checks manifest hashes/
counts and runs read-only snapshot-check, including suspended teams. Older chain
rows intentionally need no pruned file. Contents stay encrypted DBs and encrypted
snapshots; no master/edge key, host keys, live session values or in-memory run keys
are newly included. Forced delete/push/create races and suspended missing/corrupt
file tests cover these boundaries.

App inspection used git show origin/main at
`410eb2c8e3edc868535f86bb4513af7076b79ed8` (package 0.5.7). Relay/questions
clients do not call /v1/runs; question/feed state and encrypted envelopes are
unchanged. Error codes and feed settle reasons are strings, with bounded failure
handling. No app 0.5.8 tag was available, so its released artifact was not verified.
The relay CLI stops on every non-pending status and treats codes as strings;
regressions cover run_interrupted and an unknown code on ended. MCP now explicitly
documents ended as terminal and forbids automatic retry. Connected pending runs
are untouched; only startup settles orphaned keys.

An isolated 256-connection burst test on macOS measured (file descriptors, threads)
from (5, 9) to (5, 5) after idle-worker retirement: no retained descriptor/thread
growth in this test. It is ignored in the parallel suite to avoid counting other
tests' servers; run it separately with:

```sh
cargo test --locked --test server_http repeated_connection_bursts_release_threads_and_file_descriptors -- --ignored --exact --nocapture
```
