#!/usr/bin/env python3
"""Read-only public delivery gate; retain diagnostics without accepting error pages."""

import argparse
import hashlib
import http.client
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def expected_assets(public, version, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Require the approved full source SHA")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Require the approved release version")
    paths = ["dl/apassy-team-linux-x86_64", "dl/apassy-team-darwin-arm64",
             "dl/SHA256SUMS", "dl/release.json", "install.sh", "guide.html"]
    # The Linux node packages (plan S2-S3, L3): both tarballs and both .debs.
    node_names = ["apassy-" + version + "-linux-x86_64.tar.gz",
                  "apassy-" + version + "-linux-aarch64.tar.gz",
                  "apassy_" + version + "_amd64.deb", "apassy_" + version + "_arm64.deb"]
    paths += ["dl/" + name for name in node_names]
    # The Linux vault packages (ADR 0045, L6): both tarballs and both .debs.
    vault_names = ["apassy-vault-" + version + "-linux-x86_64.tar.gz",
                   "apassy-vault-" + version + "-linux-aarch64.tar.gz",
                   "apassy-vault_" + version + "_amd64.deb", "apassy-vault_" + version + "_arm64.deb"]
    paths += ["dl/" + name for name in vault_names]
    blobs = {}
    for path in paths:
        file = public / path
        if file.is_symlink() or not file.is_file():
            raise ValueError("Missing or invalid staged file: " + path)
        blobs[path] = file.read_bytes()
    metadata = json.loads(blobs["dl/release.json"])
    if metadata["version"] != version or metadata["commit"] != commit:
        raise ValueError("Staged downloads differ from the approved version/source")
    sums = []
    for platform in ["linux-x86_64", "darwin-arm64"]:
        name = "apassy-team-" + platform
        blob = blobs["dl/" + name]
        digest = hashlib.sha256(blob).hexdigest()
        if metadata["artifacts"][platform] != dict(filename=name, sha256=digest, size=len(blob)) or not blob:
            raise ValueError("Unverified staged download: " + name)
        sums.append(digest + "  " + name)
    node = metadata.get("node")
    if not isinstance(node, dict) or sorted(node) != sorted(node_names):
        raise ValueError("release.json must list exactly the four Linux node packages")
    for name in node_names:
        blob = blobs["dl/" + name]
        digest = hashlib.sha256(blob).hexdigest()
        if node[name] != dict(sha256=digest, size=len(blob)) or not blob:
            raise ValueError("Unverified staged download: " + name)
        sums.append(digest + "  " + name)
    vault = metadata.get("vault")
    if not isinstance(vault, dict) or sorted(vault) != sorted(vault_names):
        raise ValueError("release.json must list exactly the four Linux vault packages")
    for name in vault_names:
        blob = blobs["dl/" + name]
        digest = hashlib.sha256(blob).hexdigest()
        if vault[name] != dict(sha256=digest, size=len(blob)) or not blob:
            raise ValueError("Unverified staged download: " + name)
        sums.append(digest + "  " + name)
    if sorted(blobs["dl/SHA256SUMS"].decode().strip().splitlines()) != sorted(sums):
        raise ValueError("SHA256SUMS must verify exactly the ten downloads")
    return [("/guide" if path == "guide.html" else "/" + path, blob)
            for path, blob in blobs.items()]


def check(args):
    base = urllib.parse.urlsplit(args.base_url)
    if (base.scheme not in ["https", "http"] or not base.hostname or base.username
            or base.password or base.path not in ["", "/"] or base.query or base.fragment):
        raise ValueError("Use a public origin without credentials, path, query or fragment")
    if base.scheme == "http" and base.hostname not in ["localhost", "127.0.0.1", "::1"]:
        raise ValueError("HTTP is allowed only for local reproduction")
    if args.attempts < 1 or args.attempts > 6 or not 0 <= args.backoff <= 5:
        raise ValueError("Use 1..6 attempts and 0..5 seconds initial backoff")
    assets = expected_assets(args.public_dir, args.version, args.commit)
    args.evidence_dir.mkdir(parents=True, exist_ok=False)
    opener = urllib.request.build_opener(NoRedirect())
    user_agent = "apassy-release-check/" + args.version
    for index, (path, expected) in enumerate(assets):
        url = args.base_url.rstrip("/") + path
        for attempt in range(1, args.attempts + 1):
            record = dict(url=url, method="GET", user_agent=user_agent, attempt=attempt,
                          time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            body = b""
            status = None
            mitigated = None
            try:
                request = urllib.request.Request(url, headers={"User-Agent": user_agent})
                try:
                    response = opener.open(request, timeout=60)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    status = response.status
                    mitigated = response.headers.get("cf-mitigated")
                    record.update(status=status, cf_mitigated=mitigated,
                                  headers={key: ("<redacted>" if key.lower() == "set-cookie" else value)
                                           for key, value in response.headers.items()})
                    # Bound unexpected bodies; a 200 must match the entire expected file.
                    body = response.read(len(expected) + 1 if status == 200 else 4096)
                record.update(bytes_read=len(body), sha256=hashlib.sha256(body).hexdigest())
            except (OSError, http.client.HTTPException) as error:
                record["error"] = str(error)
            accepted = status == 200 and not mitigated and "error" not in record and body == expected
            record["accepted"] = accepted
            prefix = args.evidence_dir / (str(index + 1) + "-" + str(attempt))
            prefix.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n")
            print(json.dumps(record), flush=True)
            print("GET " + path + " HTTP " + str(status) + " cf-mitigated=" +
                  (mitigated or "<absent>"), flush=True)
            if accepted:
                print("PASS " + path + " exact verified bytes", flush=True)
                break
            prefix.with_suffix(".body").write_bytes(body[:4096])
            retryable = status is None or status in [200, 403, 404, 429] or status >= 500
            if not retryable or attempt == args.attempts:
                raise RuntimeError("Public delivery failed: " + path + "; inspect " + str(prefix) + ".json/.body")
            delay = min(args.backoff * (2 ** (attempt - 1)), 30)
            print("Retry in " + str(delay) + "s; no rollout acceptance yet", flush=True)
            time.sleep(delay)
    print("PASS public delivery: " + args.version + " " + args.commit, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="https://apassy-relay.wyderka.cc")
    parser.add_argument("--public-dir", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parent.parent / "public")
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--evidence-dir", type=pathlib.Path, required=True)
    parser.add_argument("--attempts", type=int, default=4)
    parser.add_argument("--backoff", type=float, default=2)
    try:
        check(parser.parse_args())
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
