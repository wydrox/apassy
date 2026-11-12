#!/bin/bash
# The Linux screenshot tour of this checkout on a disposable Linux build server, from the
# Mac, in one command:
#
#   scripts/ui-review/on-devbox.sh [OUT_DIR]        (default: output/ui-review)
#
# 1. rsync the checkout (without target/, node_modules/, output/ and .git) to
#    $UI_HOST:$UI_DIR/src;
# 2. build the demo binary (`--features desktop --bin apassy`) and the tour example
#    (`--all-features --example screenshots`) in the toolchain image $UI_BUILD_IMAGE, with
#    the cargo volumes $UI_TARGET_VOLUME and $UI_CARGO_VOLUME, -j $UI_JOBS, one build at a
#    time (flock);
# 3. build the runtime image of scripts/ui-review/Dockerfile and run
#    scripts/screenshots-linux.sh in it (Xvfb, software rendering) for both parts;
# 4. render the panels of the Connect and Devices mockups with its headless Chromium;
# 5. copy shots/ and mockups/ back to OUT_DIR and write OUT_DIR/index.html from
#    OUT_DIR/rows.json (a copy of scripts/ui-review/rows.json when it has none;
#    scripts/ui-review/build-index.py).
#
# Everything runs on synthetic data in containers; nothing touches a real vault, account,
# Stripe or the hosted relay. The Mac builds nothing.
#   UI_HOST=dev@devbox-x86  UI_DIR=work/ui  UI_BUILD_IMAGE=fa-ci:1
#   UI_TARGET_VOLUME=fa2-target  UI_CARGO_VOLUME=fa2-cargo  UI_JOBS=2  UI_MEMORY=2500m
#   APASSY_TOUR_PART, APASSY_TOUR_SCENES, APASSY_TOUR_ONLY go to the tour script.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/output/ui-review}"
HOST="${UI_HOST:-dev@devbox-x86}"
DIR="${UI_DIR:-work/ui}"
BUILD_IMAGE="${UI_BUILD_IMAGE:-fa-ci:1}"
TARGET_VOLUME="${UI_TARGET_VOLUME:-fa2-target}"
CARGO_VOLUME="${UI_CARGO_VOLUME:-fa2-cargo}"
JOBS="${UI_JOBS:-2}"
MEMORY="${UI_MEMORY:-2500m}"

mkdir -p "$OUT/shots" "$OUT/mockups"
ssh "$HOST" "mkdir -p $DIR/src $DIR/out $DIR/shots $DIR/mockups"
rsync -a --checksum --delete --exclude target/ --exclude node_modules/ --exclude output/ \
  --exclude .git "$ROOT/" "$HOST:$DIR/src/"

# The source sits at /w/src, as in the warm target volume.
ssh "$HOST" bash -s -- "$DIR" "$BUILD_IMAGE" "$TARGET_VOLUME" "$CARGO_VOLUME" "$JOBS" "$MEMORY" \
  "${APASSY_TOUR_PART:--}" "${APASSY_TOUR_SCENES:--}" "${APASSY_TOUR_ONLY:--}" <<'REMOTE'
set -euo pipefail
# ssh drops empty arguments: "-" stands for an empty value.
dir=$HOME/$1 image=$2 target=$3 cargo=$4 jobs=$5 memory=$6 part=${7#-} scenes=${8#-} only=${9#-}
flock "$dir/build.lock" docker run --rm --memory="$memory" --cpus="$jobs" \
  -e CARGO_INCREMENTAL=0 -e CARGO_BUILD_JOBS="$jobs" -e CARGO_TARGET_DIR=/target \
  -v "$dir/src:/w/src" -v "$dir/out:/w/out" -v "$target:/target" \
  -v "$cargo:/home/ci/.cargo/registry" -w /w/src "$image" bash -c '
    set -e
    cargo build --locked --features desktop --bin apassy
    cp /target/debug/apassy /w/out/apassy-demo
    cargo build --locked --all-features --example screenshots
    cp /target/debug/examples/screenshots /w/out/screenshots'
docker build -q -t apassy-ui-tour "$dir/src/scripts/ui-review" >/dev/null
rm -rf "$dir/shots" "$dir/mockups"
mkdir -p "$dir/shots" "$dir/mockups"
docker run --rm --hostname linux-desktop --memory=1500m --shm-size=512m -u 1000 \
  -v "$dir/src:/w/src:ro" -v "$dir/out:/w/out:ro" -v "$dir/shots:/w/shots" \
  -e APASSY_DEMO_BIN=/w/out/apassy-demo -e APASSY_TOUR_BIN=/w/out/screenshots \
  -e APASSY_TOUR_PART="$part" -e APASSY_TOUR_SCENES="$scenes" -e APASSY_TOUR_ONLY="$only" \
  apassy-ui-tour bash /w/src/scripts/screenshots-linux.sh /w/shots
docker run --rm --memory=1500m --shm-size=512m -u 1000 \
  -v "$dir/src:/w/src:ro" -v "$dir/mockups:/w/mockups" apassy-ui-tour \
  python3 -I /w/src/scripts/ui-review/render-mockups.py /w/mockups \
  /w/src/docs/design/connect-mockup.html /w/src/docs/design/devices-settings-mockup.html
REMOTE

rsync -a "$HOST:$DIR/shots/" "$OUT/shots/"
rsync -a "$HOST:$DIR/mockups/" "$OUT/mockups/"
# The pairs of the review: scripts/ui-review/rows.json, unless OUT_DIR has its own.
[ -f "$OUT/rows.json" ] || cp "$ROOT/scripts/ui-review/rows.json" "$OUT/rows.json"
if [ -f "$OUT/rows.json" ]; then
  python3 "$ROOT/scripts/ui-review/build-index.py" "$OUT"
fi
echo "Done: $(find "$OUT/shots" -name '*.png' | wc -l | tr -d ' ') screenshots, $(find "$OUT/mockups" -name '*.png' | wc -l | tr -d ' ') mockup panels in $OUT"
