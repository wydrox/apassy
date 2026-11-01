#!/bin/bash
# Build the Chrome Web Store package of the browser extension (ADR 0021).
#
# Output: target/dist/apassy-extension-<version>.zip, with manifest.json at the
# root of the archive.
#
# The package is extension/ without the "key" of its manifest: the store gives
# the item its own key, and the ID of the item comes from it. The folder in
# Apassy.app keeps the key, so a load of that folder has the ID of the store
# item (docs/operations/chrome-web-store.md).
#
# Usage: scripts/build-extension-zip.sh

set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "error: $*" >&2; exit 1; }

for tool in zip unzip plutil python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done

VERSION="$(awk -F'"' '/^version = / {print $2; exit}' Cargo.toml)"
[ -n "$VERSION" ] || fail "cannot read the package version from Cargo.toml"
EXT_VERSION="$(plutil -extract version raw -o - extension/manifest.json)"
[ "$EXT_VERSION" = "$VERSION" ] \
  || fail "extension/manifest.json has version $EXT_VERSION, Cargo.toml has $VERSION"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
STAGE="$TMP/apassy-extension"
[ -z "$(find extension -type l)" ] || fail "the extension has a symbolic link"
cp -R extension "$STAGE"
find "$STAGE" -name .DS_Store -delete
[ -z "$(find "$STAGE" -name '_*')" ] || fail "the extension has a file whose name starts with _"

# The store item has its own key. -I: the interpreter ignores the environment and
# the current folder.
python3 -I - "$STAGE/manifest.json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    manifest = json.load(f)
manifest.pop("key", None)
with open(path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY

# The same bytes for the same files: a fixed time and a sorted list.
find "$STAGE" -exec touch -h -t 202001010000 {} +
OUT_DIR="target/dist"
mkdir -p "$OUT_DIR"
OUT="$TMP/apassy-extension-$VERSION.zip"
(cd "$STAGE" && find . -type f | LC_ALL=C sort | sed 's|^\./||' | zip -X -q -@ "$OUT")

# Check the actual archive, including every runtime helper. New files or
# permissions need an explicit packaging-policy change rather than silently
# adding site access or private build files to a store upload.
python3 -I - "$OUT" "$VERSION" <<'PY'
import json, sys, zipfile
required = {
    "README.md", "manifest.json", "background.js", "fill.js",
    "login-worker.js", "login-target.js", "login-suggestions.js", "login-save.js", "login-save-worker.js",
    "passkey-page.js", "passkey-bridge.js", "popup.html", "popup.js", "popup.css",
    "icons/16.png", "icons/32.png", "icons/48.png", "icons/128.png",
}
with zipfile.ZipFile(sys.argv[1]) as archive:
    names = archive.namelist()
    if set(names) != required or len(names) != len(required):
        sys.exit("error: unexpected archive files (missing=%r, extra=%r)" %
                 (sorted(required - set(names)), sorted(set(names) - required)))
    if archive.testzip() is not None:
        sys.exit("error: corrupt extension archive")
    manifest = json.loads(archive.read("manifest.json"))
if "key" in manifest:
    sys.exit("error: the store manifest still has a key")
if manifest.get("version") != sys.argv[2]:
    sys.exit("error: the store manifest has another version")
if sorted(manifest.get("permissions", [])) != ["activeTab", "nativeMessaging", "scripting", "storage"]:
    sys.exit("error: unexpected permissions: %r" % manifest.get("permissions"))
if sorted(manifest.get("optional_host_permissions", [])) != ["http://localhost/*", "https://*/*"]:
    sys.exit("error: unexpected optional host permissions: %r" % manifest.get("optional_host_permissions"))
for field in ("host_permissions", "optional_permissions", "content_scripts", "externally_connectable"):
    if field in manifest:
        sys.exit("error: the store manifest has %s" % field)
if manifest.get("manifest_version") != 3 or manifest.get("background") != {"service_worker": "background.js"}:
    sys.exit("error: unexpected background worker configuration")
PY

PACKAGE="$OUT_DIR/apassy-extension-$VERSION.zip"
mv "$OUT" "$PACKAGE"
OUT="$PACKAGE"
echo "Package: $OUT ($(wc -c <"$OUT" | tr -d ' ') bytes)"
echo "SHA-256: $(shasum -a 256 "$OUT" | cut -d' ' -f1)"
unzip -Z1 "$OUT" | sed 's/^/  /'
