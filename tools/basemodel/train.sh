#!/bin/bash
# Rebuild the Apassy base model from scratch (goal B8).
#
# Steps: build the label exporter, write the replay dump, compose the data set,
# train the decision heads on MPS, and write tools/basemodel/manifest.json.
# See docs/operations/base-model.md.
#
# Usage: tools/basemodel/train.sh [checkpoint-path]
#
# Environment:
#   APASSY_LAYA_DIR       Laya folder with .venv (default: ~/Library/Application Support/Apassy/laya)
#   APASSY_B8_WORK        work folder for the dump and the data (default: /tmp/apassy-b8)
#   APASSY_ALLOW_BATTERY  set to 1 to train on battery power (default: refuse)
#   APASSY_ZERO_SHOT      questions that keep the stock answer, for the manifest (default: keep)
#
# The script never commits the checkpoint. Keep at most one checkpoint on disk.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
LAYA_DIR="${APASSY_LAYA_DIR:-$HOME/Library/Application Support/Apassy/laya}"
PY="$LAYA_DIR/.venv/bin/python"
WORK="${APASSY_B8_WORK:-/tmp/apassy-b8}"
OUT="${1:-$WORK/apassy-base-v1.safetensors}"

fail() { printf 'train.sh: %s\n' "$*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

[ -x "$PY" ] || fail "no Laya virtual environment at $LAYA_DIR/.venv (docs/operations/bouncer.md section 1)"
"$PY" -c 'import laya, sys; sys.exit(0 if laya.__version__ == "0.3.20" else 1)' \
  || fail "laya 0.3.20 is required: uv pip install --python \"$PY\" -r tools/basemodel/requirements.txt"
if [ "${APASSY_ALLOW_BATTERY:-0}" != "1" ]; then
  pmset -g batt | grep -q "AC Power" || fail "not on AC power (set APASSY_ALLOW_BATTERY=1 to override)"
fi
mkdir -p "$WORK" "$(dirname "$OUT")"

step "Build the label exporter"
cargo build --locked --features vault --example basemodel_labels

if [ ! -s "$WORK/replay-dump.tsv" ]; then
  step "Write the replay dump (60000 generated commands, fixed seed)"
  APASSY_REPLAY_DUMP="$WORK/replay-dump.tsv" cargo test --locked --features desktop,vault --test analysis_replay
fi

step "Compose the data set"
python3 tools/basemodel/gen_data.py --dump "$WORK/replay-dump.tsv" --out "$WORK/data" \
  --labels-bin "$ROOT/target/debug/examples/basemodel_labels"

step "Train the decision heads"
rm -f "$OUT"
TMPDIR=/tmp "$PY" tools/basemodel/train.py --data "$WORK/data" --out "$OUT" --report "$OUT.report.json"

step "Write the manifest"
ZS=()
[ -n "${APASSY_ZERO_SHOT+x}" ] && ZS=(--zero-shot "$APASSY_ZERO_SHOT")
"$PY" tools/basemodel/manifest.py --checkpoint "$OUT" --report "$OUT.report.json" \
  --stats "$WORK/data/stats.json" ${ZS[@]+"${ZS[@]}"}

step "Done"
echo "Checkpoint: $OUT"
echo "Install:    mkdir -p \"$LAYA_DIR/models\" && mv \"$OUT\" \"$LAYA_DIR/models/apassy-base-v1.safetensors\""
