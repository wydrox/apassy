#!/bin/bash
# Shared GitHub / manual Xcode Cloud quality contract. No publication.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 -I - "$@" <<'PY'
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

started = time.monotonic()
deadline = started + 2400  # Includes tooling, fetch, metadata and all quality steps.
receipt = {'schema': 1, 'expected_sha': os.environ.get('APASSY_CI_EXPECTED_SHA', '')[:128],
           'actual_sha': None, 'rust_toolchain': '1.97.0', 'steps': [], 'metadata': {}}
output = Path(os.environ.get('APASSY_CI_RECEIPT', str(Path(tempfile.gettempdir()) / 'apassy-macos-quality.json')))
env = dict(os.environ)
status = 1

def run(name, command, capture=False):
    begin = time.monotonic()
    print('QUALITY START ' + name + ': ' + ' '.join(command), flush=True)
    code = 127
    value = ''
    try:
        proc = subprocess.Popen(command, env=env, text=True, start_new_session=True,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.STDOUT if capture else None)
        try:
            value, _ = proc.communicate(timeout=max(0.01, deadline - time.monotonic()))
            code = proc.returncode
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            code = 124
    finally:
        receipt['steps'].append({'name': name, 'seconds': round(time.monotonic() - begin, 3), 'exit_status': code})
        print(f'QUALITY END {name}: exit={code}', flush=True)
    if code:
        raise subprocess.CalledProcessError(code, command)
    return (value or '').strip()[:2048]

try:
    receipt['actual_sha'] = run('source-identity', ['git', 'rev-parse', 'HEAD'], True)
    expected = receipt['expected_sha']
    if not re.fullmatch('[0-9a-f]{40}', expected) or expected != receipt['actual_sha']:
        raise ValueError('APASSY_CI_EXPECTED_SHA must be the exact full checked-out SHA')
    if run('source-clean', ['git', 'status', '--porcelain', '--untracked-files=no'], True):
        raise ValueError('tracked source differs from the expected commit')
    for name, command in (
        ('uname', ['uname', '-a']), ('architecture', ['uname', '-m']),
        ('xcode-select', ['xcode-select', '-p']), ('xcode', ['xcodebuild', '-version']),
        ('macos-sdk', ['xcrun', '--sdk', 'macosx', '--show-sdk-version']),
        ('watch-sdk', ['xcrun', '--sdk', 'watchsimulator', '--show-sdk-version']),
    ):
        receipt['metadata'][name] = run(name, command, True)
        print(name + ': ' + receipt['metadata'][name], flush=True)
    if sys.argv[1:] == ['--cloud']:
        # Isolated user-writable tooling; no sudo, Homebrew or global defaults.
        tooling = Path(tempfile.mkdtemp(prefix='apassy-ci-rust-'))
        env.update(CARGO_HOME=str(tooling / 'cargo'), RUSTUP_HOME=str(tooling / 'rustup'))
        env['PATH'] = str(tooling / 'cargo/bin') + ':' + env['PATH']
        bootstrap = {
            'arm64': ('aarch64-apple-darwin', '20ef5516c31b1ac2290084199ba77dbbcaa1406c45c1d978ca68558ef5964ef5'),
            'x86_64': ('x86_64-apple-darwin', '9c331076f62b4d0edeae63d9d1c9442d5fe39b37b05025ec8d41c5ed35486496'),
        }
        host, digest = bootstrap[receipt['metadata']['architecture']]
        receipt['metadata']['rustup-bootstrap'] = {'version': '1.28.2', 'host': host, 'sha256': digest}
        installer = str(tooling / 'rustup-init')
        run('download-rustup', ['curl', '--proto', '=https', '--tlsv1.2', '--fail', '--location',
                               '--max-time', '120', f'https://static.rust-lang.org/rustup/archive/1.28.2/{host}/rustup-init', '-o', installer])
        if hashlib.sha256(Path(installer).read_bytes()).hexdigest() != digest:
            raise ValueError('rustup bootstrap checksum mismatch')
        os.chmod(installer, 0o700)
        run('install-rustup', [installer, '-y', '--no-modify-path', '--profile', 'minimal', '--default-toolchain', 'none'])
        run('disable-rustup-self-update', ['rustup', 'set', 'auto-self-update', 'disable'])
        run('install-rust', ['rustup', 'toolchain', 'install', '1.97.0', '--profile', 'minimal', '--component', 'rustfmt', '--component', 'clippy'])
    elif sys.argv[1:]:
        raise ValueError('only --cloud is supported')
    receipt['metadata']['rustc'] = run('rustc-version', ['rustc', '+1.97.0', '-Vv'], True)
    receipt['metadata']['cargo'] = run('cargo-version', ['cargo', '+1.97.0', '-V'], True)
    receipt['metadata']['clippy'] = run('clippy-version', ['cargo', '+1.97.0', 'clippy', '-V'], True)
    receipt['metadata']['rustfmt'] = run('rustfmt-version', ['rustfmt', '+1.97.0', '-V'], True)
    run('fetch', ['cargo', '+1.97.0', 'fetch', '--locked'])
    run('swift-helper', ['xcrun', '--sdk', 'macosx', 'swiftc', '-typecheck', '-swift-version', '5', '-warnings-as-errors', *sorted(glob.glob('native/ApassyHelper/*.swift'))])
    cargo = ['cargo', '+1.97.0']
    run('clippy-full', cargo + ['clippy', '--offline', '--locked', '--all-features', '--all-targets', '--', '-D', 'warnings'])
    run('desktop-without-vault', cargo + ['check', '--offline', '--locked', '--features', 'desktop', '--bin', 'apassy'])
    run('clippy-app', cargo + ['clippy', '--offline', '--locked', '-p', 'apassy-app', '--all-targets', '--', '-D', 'warnings'])
    run('vault-doc-compile-fail', cargo + ['test', '--offline', '--locked', '--features', 'vault', '--doc'])
    run('watch-targets', ['rustup', 'target', 'add', '--toolchain', '1.97.0', 'aarch64-apple-watchos', 'aarch64-apple-watchos-sim'])
    run('watch-core', cargo + ['check', '--offline', '--locked', '-p', 'apassy-core', '--no-default-features', '--target', 'aarch64-apple-watchos-sim'])
    run('fixture-boundary', ['python3', 'tests/isolation/test_fixture_boundary.py'])
    status = 0
except subprocess.CalledProcessError as error:
    status = error.returncode if 0 < error.returncode < 256 else 1
    receipt['error'] = str(error)[:2048]
except Exception as error:
    receipt['error'] = str(error)[:2048]
finally:
    receipt.update(exit_status=status, seconds=round(time.monotonic() - started, 3))
    data = json.dumps(receipt, sort_keys=True)
    # Bounded (< 24 KiB), one-line log transport survives custom-script cleanup.
    if len(data.encode()) > 24576:
        raise RuntimeError('receipt exceeded bound')
    try:
        output.write_text(data + '\n')
    except OSError as error:
        print('Receipt file write failed: ' + str(error), file=sys.stderr)
        status = status or 1
        receipt.update(exit_status=status, receipt_file_error=str(error)[:512])
        data = json.dumps(receipt, sort_keys=True)
    print('APASSY_CI_RECEIPT_JSON=' + data, flush=True)
sys.exit(status)
PY
