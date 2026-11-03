#!/bin/sh
# Entry point of the bouncer brain image (tools/basemodel/Dockerfile).
#
#   serve [serve.py options]        the server (default)
#   train --data <dir> --out <dir>  one training job: tools/finetune/local_train.py,
#                                   from the baked-in heads, at a low CPU priority
#   bench <bench.py arguments>      tools/basemodel/bench.py
#   <any other command>             run as given
#
# LAYA_API_KEY_FILE: read the token from this file (a Docker or Compose secret), so
# the token is not in `docker inspect`. serve.py refuses to listen on 0.0.0.0 without
# a token.
#
# Threads: with `--cpus=N` the container may use N CPUs, but torch starts one thread
# for each CPU of the host, and the extra threads only wait for the quota. Without an
# explicit OMP_NUM_THREADS, use the CPU quota of the cgroup, else the CPUs that the
# container can run on.
set -eu

if [ -n "${LAYA_API_KEY_FILE:-}" ]; then
  if [ ! -r "$LAYA_API_KEY_FILE" ]; then
    echo "apassy-brain: cannot read LAYA_API_KEY_FILE" >&2
    exit 1
  fi
  LAYA_API_KEY="$(tr -d '\r\n' < "$LAYA_API_KEY_FILE")"
  if [ -z "$LAYA_API_KEY" ]; then
    echo "apassy-brain: LAYA_API_KEY_FILE is empty" >&2
    exit 1
  fi
  export LAYA_API_KEY
fi

if [ -z "${OMP_NUM_THREADS:-}" ]; then
  threads=""
  if [ -r /sys/fs/cgroup/cpu.max ]; then
    read -r quota period < /sys/fs/cgroup/cpu.max || true
    if [ "${quota:-max}" != "max" ] && [ "${period:-0}" -gt 0 ] 2>/dev/null; then
      threads=$(( (quota + period - 1) / period ))
    fi
  fi
  if [ -z "$threads" ]; then
    threads="$(nproc)"
  fi
  if [ "$threads" -lt 1 ]; then
    threads=1
  fi
  OMP_NUM_THREADS="$threads"
  MKL_NUM_THREADS="$threads"
  export OMP_NUM_THREADS MKL_NUM_THREADS
fi

TOOLS=/opt/apassy/tools
command="${1:-serve}"
if [ "$#" -gt 0 ]; then
  shift
fi
case "$command" in
  serve)
    exec python "$TOOLS/basemodel/serve.py" --checkpoint "$APASSY_BASE_MODEL" "$@"
    ;;
  train)
    # Low CPU priority: inference on the same host goes first.
    exec nice -n 10 python "$TOOLS/finetune/local_train.py" --init "$APASSY_BASE_MODEL" "$@"
    ;;
  bench)
    exec python "$TOOLS/basemodel/bench.py" "$@"
    ;;
  *)
    exec "$command" "$@"
    ;;
esac
