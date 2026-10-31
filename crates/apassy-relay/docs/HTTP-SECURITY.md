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
- Header constructors/parser reject CR, LF, NUL and other prohibited control bytes;
  field names must be HTTP tokens. Lines are limited to 8 KiB and 100 header fields.
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
  refusals may drain within the same absolute body budget. The accept loop
  dispatches 503 writes to a separate lane of at most eight workers; overflow closes
  the socket immediately. Health has four reserved seats. Destructor draining uses
  a bounded 8 KiB buffer rather than allocating the untrusted declared length.

`tests/server_http.rs` exercises stalled/refused uploads, health/approval progress,
trickling bodies and malformed framing/header constructors. Existing sync and proxy
suites cover normal uploads/streams. These are local/CI regressions, not a claim of
Cloudflare/VPC exploit testing or production acceptance. Header-stage floods can
still exhaust the original parser's connection pool; rate controls and process
limits remain relevant. A maintained server migration is separate work.

CI installs pinned `cargo-audit` **0.22.2** and checks the current RustSec database,
with warnings denied and no advisory ignores. The published CVEs above are tracked
here even if absent from RustSec. Audit success is dependency database evidence;
it does not independently certify this local parser patch. No scanner is installed
locally for this task.
