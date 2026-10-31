#!/usr/bin/env bash
# Prove that the installed scanner rejects a known vulnerable lockfile.
set -euo pipefail
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
cat > "$fixture/Cargo.lock" <<'LOCK'
version = 3

[[package]]
name = "time"
version = "0.1.44"
source = "registry+https://github.com/rust-lang/crates.io-index"
LOCK
if cargo audit --file "$fixture/Cargo.lock" --deny warnings --json > "$fixture/report.json"; then
    echo 'FAIL: cargo-audit accepted the vulnerable fixture.' >&2
    exit 1
fi
# A network/parser/scanner failure is not a successful negative control.
python3 - "$fixture/report.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
assert any(item['advisory']['id'] == 'RUSTSEC-2020-0071'
           for item in report['vulnerabilities']['list']), report
print('PASS: vulnerable time 0.1.44 rejected (RUSTSEC-2020-0071).')
PY
