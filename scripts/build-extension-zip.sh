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
OUT="$OUT_DIR/apassy-extension-$VERSION.zip"
rm -f "$OUT"
(cd "$STAGE" && find . -type f | LC_ALL=C sort | sed 's|^\./||' | zip -X -q -@ "$OLDPWD/$OUT")

# Check the archive: the manifest at the root, no key, the version.
unzip -p "$OUT" manifest.json >"$TMP/check.json" || fail "the archive has no manifest.json at its root"
python3 -I - "$TMP/check.json" "$VERSION" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
if "key" in manifest:
    sys.exit("error: the store manifest still has a key")
if manifest.get("version") != sys.argv[2]:
    sys.exit("error: the store manifest has another version")
if sorted(manifest.get("permissions", [])) != ["activeTab", "nativeMessaging", "scripting"]:
    sys.exit("error: unexpected permissions: %r" % manifest.get("permissions"))
for field in ("host_permissions", "content_scripts", "externally_connectable"):
    if field in manifest:
        sys.exit("error: the store manifest has %s" % field)
PY

echo "Package: $OUT ($(wc -c <"$OUT" | tr -d ' ') bytes)"
echo "SHA-256: $(shasum -a 256 "$OUT" | cut -d' ' -f1)"
unzip -Z1 "$OUT" | sed 's/^/  /'
