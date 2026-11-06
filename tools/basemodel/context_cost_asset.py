"""Read one draft-release checkpoint; stdlib only, no upload capability."""
import hashlib
from enum import Enum
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_SIZE = 256 * 1024 * 1024
CDN_HOSTS = frozenset(('release-assets.githubusercontent.com',
                       'objects.githubusercontent.com', 'github-releases.githubusercontent.com'))
API = 'https://api.github.com/repos/wydrox/apassy'


class Refused(ValueError):
    """Safe fixed-message failure."""


class HTTPPhase(Enum):
    RELEASE_METADATA = 'release_metadata'
    ASSET = 'asset'


class HTTPRefused(Refused):
    """Closed transport diagnostics, without response-derived text."""

    def __init__(self, phase, status):
        super().__init__('cost unmeasured: checkpoint input or transport refused')
        self.phase = HTTPPhase(phase)
        self.status = status if type(status) is int and 100 <= status <= 599 else 'unknown'


def require_http(response, phase, expected):
    status = getattr(response, 'status', None)
    if type(status) is not int or status not in expected:
        raise HTTPRefused(phase, status)


def require(ok):
    if not ok:
        raise Refused('cost unmeasured: checkpoint input or transport refused')


def inputs(env, head):
    require(re.fullmatch(r'[0-9a-f]{40}', env.get('SOURCE_SHA', '')) is not None)
    require(env['SOURCE_SHA'] == env.get('GITHUB_SHA') == head)
    require(re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,19}',
                         env.get('CHECKPOINT_ASSET', '')) is not None)
    transport = env.get('TRANSPORT_ONLY', 'false')
    require(transport in ('true', 'false'))
    keys = ('CHECKPOINT_SHA256',) if transport == 'true' else ('CHECKPOINT_SHA256', 'VAL_SHA256')
    for key in keys:
        require(re.fullmatch(r'[0-9a-f]{64}', env.get(key, '')) is not None)
    if transport == 'true':
        return
    require(re.fullmatch(r'[0-9]{3}', env.get('COST_GROUPS', '')) is not None)
    require(400 <= int(env['COST_GROUPS']) <= 800)


def cdn_url(url):
    require(isinstance(url, str) and url.isascii() and
            not any(ord(c) <= 32 or ord(c) == 127 for c in url) and '\\' not in url)
    try:
        p = urlsplit(url)
        require(p.scheme == 'https' and p.hostname in CDN_HOSTS and
                p.port in (None, 443) and p.username is None and p.password is None and
                not p.fragment)
    except ValueError:
        raise Refused('cost unmeasured: redirect refused') from None
    return url


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_request(request):
    # No automatic redirect or ambient proxy can receive the API credential.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        return opener.open(request, timeout=60)
    except HTTPError as response:
        return response


def api_request(path, token, accept):
    return Request(API + path, headers={'Authorization': 'Bearer ' + token,
                   'Accept': accept, 'X-GitHub-Api-Version': '2022-11-28',
                   'User-Agent': 'apassy-context-cost'})


def download(asset, expected_sha, destination, token, open_fn=open_request):
    require(re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,19}', asset) is not None)
    require(re.fullmatch(r'[0-9a-f]{64}', expected_sha) is not None)
    release_id, asset_id = map(int, asset.split('/'))
    require(bool(token))
    with open_fn(api_request(f'/releases/{release_id}', token, 'application/vnd.github+json')) as r:
        require_http(r, HTTPPhase.RELEASE_METADATA, (200,))
        raw = r.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024)
        release = json.loads(raw)
    require(type(release.get('id')) is int and release['id'] == release_id and
            release.get('draft') is True)
    matches = [a for a in release.get('assets', []) if a.get('id') == asset_id]
    require(len(matches) == 1)
    a = matches[0]
    require(type(a.get('id')) is int and a.get('state') == 'uploaded' and
            type(a.get('size')) is int and 0 < a['size'] <= MAX_SIZE)
    request = api_request(f'/releases/assets/{asset_id}', token, 'application/octet-stream')
    return _stream(request, a['size'], expected_sha, destination, open_fn)


def download_input(asset, expected_sha, destination, manifest, source_sha,
                   open_fn=open_request, now=None):
    """Read one short-lived owner-attested CDN object without API credentials."""
    try:
        require(isinstance(asset, str) and re.fullmatch(
            r'[1-9][0-9]{0,19}/[1-9][0-9]{0,19}', asset) is not None)
        require(isinstance(expected_sha, str) and
                re.fullmatch(r'[0-9a-f]{64}', expected_sha) is not None)
        require(isinstance(source_sha, str) and
                re.fullmatch(r'[0-9a-f]{40}', source_sha) is not None)
        require(isinstance(manifest, str) and len(manifest.encode('utf-8')) <= 32 * 1024)

        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result)
                result[key] = value
            return result

        attestation = json.loads(manifest, object_pairs_hook=pairs)
        require(type(attestation) is dict and set(attestation) == {
            'schema', 'source_sha', 'repository', 'release_id', 'asset_id',
            'draft', 'state', 'size', 'sha256', 'url', 'expires_at'})
        release_id, asset_id = map(int, asset.split('/'))
        require(attestation['schema'] == 'apassy-context-input-v1' and
                attestation['source_sha'] == source_sha and
                attestation['repository'] == 'wydrox/apassy' and
                attestation['sha256'] == expected_sha)
        require(type(attestation['release_id']) is int and
                attestation['release_id'] == release_id and
                type(attestation['asset_id']) is int and attestation['asset_id'] == asset_id)
        require(attestation['draft'] is True and attestation['state'] == 'uploaded')
        require(type(attestation['size']) is int and 1 <= attestation['size'] <= MAX_SIZE)
        clock = time.time() if now is None else now
        require(type(clock) in (int, float) and math.isfinite(clock))
        require(type(attestation['expires_at']) is int and
                clock < attestation['expires_at'] <= clock + 3600)
        url = cdn_url(attestation['url'])
    except Refused:
        raise
    except Exception:
        raise Refused('cost unmeasured: checkpoint input or transport refused') from None
    request = Request(url, headers={'Accept': 'application/octet-stream'})
    return _stream(request, attestation['size'], expected_sha, destination, open_fn)


def _stream(request, expected_size, expected_sha, destination, open_fn):
    seen = {request.full_url}
    created = False
    destination = Path(destination)
    try:
        for hop in range(4):
            with open_fn(request) as r:
                require_http(r, HTTPPhase.ASSET, (200, 302))
                if r.status == 302:
                    url = cdn_url(r.headers.get('Location'))
                    require(url not in seen and hop < 3)
                    seen.add(url)
                    # Fresh request: never copy Authorization onto CDN requests.
                    request = Request(url, headers={'Accept': 'application/octet-stream'})
                    continue
                digest = hashlib.sha256()
                size = 0
                with destination.open('xb') as f:
                    created = True
                    while chunk := r.read(1024 * 1024):
                        size += len(chunk)
                        require(size <= expected_size and size <= MAX_SIZE)
                        digest.update(chunk)
                        f.write(chunk)
                require(size == expected_size and digest.hexdigest() == expected_sha)
                return {'sha256': digest.hexdigest(), 'size': size}
        require(False)
    except BaseException:
        if created:
            destination.unlink()
        raise


def main():
    try:
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        inputs(os.environ, head)
        name = os.environ.get('DESTINATION_NAME', 'context.safetensors')
        require(name in ('context.safetensors', 'bundle.tar'))
        download_input(os.environ['CHECKPOINT_ASSET'], os.environ['CHECKPOINT_SHA256'],
                       Path(os.environ['EXP']) / name, os.environ['APASSY_CONTEXT_INPUT'],
                       os.environ['SOURCE_SHA'])
    except Exception as error:
        # Do not print exception URLs, response bodies, signed queries or credentials.
        print('cost unmeasured: checkpoint input or transport refused', file=sys.stderr)
        if isinstance(error, HTTPRefused):
            print(json.dumps({'phase': error.phase.value, 'status': error.status}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
