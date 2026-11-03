Settings Tools screenshots from the isolated synthetic screenshot tour.
light/settings-tools.png: light system theme input.
dark/settings-tools.png: dark system theme input; the product currently forces light rendering.
Both images were opened and inspected. No dark product-theme support is claimed.

PR: https://github.com/wydrox/apassy/pull/37
Head: 9a86b610cf0b19dd4d7dc50ef694f85e57c432c9

Acceptance gaps are listed in the draft PR: GUI token rollback, complete identity/orphan reconciliation, MCP request timestamps, and native sandbox/installed-host execution.

Full test run: library 1225 passed/5 ignored; integration 794 passed/1 failed/14 ignored. Sole failure: agent_path wall-clock assertion 5.606 seconds against a 5 second limit; isolated rerun passed in 1.95 seconds.
Clippy all-features/all-targets with -D warnings passed.
Targeted CLI 58 passed; onboarding/health 4 passed; eval input 1 passed.
CI last readback: partial pass, remaining checks pending.
