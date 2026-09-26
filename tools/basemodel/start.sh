#!/bin/bash
# Start the local bouncer model (goal B8).
#
# With a base-model checkpoint, start tools/basemodel/serve.py. The server
# checks the checkpoint and the base weights against manifest.json and answers
# with the model version apassy-base-v1+<hash8>.
# Without a checkpoint, start the stock zero-shot laya-serve.
#
# Checkpoint search order:
#   1. APASSY_BASE_MODEL (a path)
#   2. $APASSY_LAYA_DIR/models/apassy-base-v1.safetensors
#   3. /Applications/Apassy.app/Contents/Resources/models/apassy-base-v1.safetensors
#
# Environment: LAYA_HOST (default 127.0.0.1), LAYA_PORT (default 8770),
# APASSY_LAYA_DIR (default ~/Library/Application Support/Apassy/laya).
# See docs/operations/bouncer.md section 1.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LAYA_DIR="${APASSY_LAYA_DIR:-$HOME/Library/Application Support/Apassy/laya}"
export LAYA_HOST="${LAYA_HOST:-127.0.0.1}"
export LAYA_PORT="${LAYA_PORT:-8770}"

CKPT="${APASSY_BASE_MODEL:-}"
if [ -z "$CKPT" ]; then
  for candidate in "$LAYA_DIR/models/apassy-base-v1.safetensors" \
      "/Applications/Apassy.app/Contents/Resources/models/apassy-base-v1.safetensors"; do
    if [ -f "$candidate" ]; then CKPT="$candidate"; break; fi
  done
fi

if [ -n "$CKPT" ]; then
  [ -f "$CKPT" ] || { echo "start: APASSY_BASE_MODEL does not exist: $CKPT" >&2; exit 1; }
  echo "start: base model $CKPT on $LAYA_HOST:$LAYA_PORT" >&2
  exec "$LAYA_DIR/.venv/bin/python" "$HERE/serve.py" --checkpoint "$CKPT"
fi
echo "start: no base-model checkpoint. Zero-shot laya-serve on $LAYA_HOST:$LAYA_PORT" >&2
LAYA_MODELS=english exec "$LAYA_DIR/.venv/bin/laya-serve"
