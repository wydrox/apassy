# syntax=docker/dockerfile:1
# The self-host image of the bouncer brain (ADR 0035 section 2, implementation plan
# 0035 unit E2). One file, three images:
#
#   CPU, arm64 and x86_64 (default):  --build-arg VARIANT=cpu
#   CUDA, x86_64 only:                --build-arg VARIANT=cuda
#
# Build context: the repository root (Dockerfile.dockerignore next to this file keeps
# the context to the files below). The fine-tuned head checkpoint
# apassy-base-v1.safetensors is not in the repository (docs/operations/base-model.md):
# pass the folder that holds it as the named build context `model`:
#
#   docker build -f tools/basemodel/Dockerfile \
#     --build-context model=<folder with apassy-base-v1.safetensors> \
#     --build-arg APASSY_RELEASE_VERSION=<version> --build-arg APASSY_RELEASE_COMMIT=<sha> \
#     -t apassy-brain:<version>-cpu .
#
# The build checks the checkpoint and the Laya base weights against
# tools/basemodel/manifest.json, as serve.py does at every start. Images are built
# on GitHub (.github/workflows/bouncer-image.yml) or on a devbox, never on the Mac or
# on the production VPS. Runbook: docs/operations/bouncer-hosting.md.

# python:3.12.16-slim-trixie, multi-architecture index digest of 2026-11-02.
ARG PYTHON_IMAGE=python:3.12.16-slim-trixie@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

FROM ${PYTHON_IMAGE} AS runtime
ARG VARIANT=cpu
ARG APASSY_RELEASE_VERSION=dev
ARG APASSY_RELEASE_COMMIT=unknown
# The CPU wheels of torch come from the PyTorch CPU index (no CUDA libraries, for
# arm64 and x86_64). The CUDA image takes the PyPI wheel, which brings the CUDA
# libraries as pip packages; the host needs only the NVIDIA driver and the NVIDIA
# container toolkit.
ARG TORCH_CPU_INDEX=https://download.pytorch.org/whl/cpu

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/opt/apassy/hf \
    HF_HUB_DISABLE_PROGRESS_BARS=1 \
    HF_HUB_DISABLE_TELEMETRY=1

COPY tools/basemodel/requirements.txt /opt/apassy/tools/basemodel/requirements.txt
WORKDIR /opt/apassy/tools/basemodel
RUN <<'SH'
set -eu
torch="$(awk -F'==' '$1 == "torch" {print $2}' requirements.txt)"
test -n "$torch"
case "$VARIANT" in
  cpu)  pip install --index-url "$TORCH_CPU_INDEX" "torch==$torch" ;;
  cuda) test "$(uname -m)" = x86_64; pip install "torch==$torch" ;;
  *)    echo "VARIANT must be cpu or cuda" >&2; exit 1 ;;
esac
# torch==X matches the installed X+cpu, so this keeps the CPU wheel.
pip install -r requirements.txt
python -B - <<'PY'
import os, sys, torch
cuda = torch.version.cuda
print("torch", torch.__version__, "cuda", cuda)
sys.exit(0 if (os.environ["VARIANT"] == "cpu") == (cuda is None) else "wrong torch build")
PY
SH

# The Laya base checkpoint at the pinned revision, with its model card (the license
# statement: Apache-2.0). Then the check of serve.py: the SHA-256 of
# model.safetensors must be the one in the manifest.
COPY tools/basemodel/common.py tools/basemodel/manifest.json /opt/apassy/tools/basemodel/
RUN python -B - <<'PY'
import json, os, shutil
import common
from huggingface_hub import hf_hub_download

folder = common.base_dir()
manifest = json.load(open("manifest.json", encoding="utf-8"))
digest = common.sha256_file(os.path.join(folder, "model.safetensors"))
assert digest == manifest["base"]["weights_sha256"], ("base weights", digest)
card = hf_hub_download(common.BASE_REPO, "README.md", revision=common.BASE_REVISION)
os.makedirs("/opt/apassy/licenses", exist_ok=True)
shutil.copyfile(card, "/opt/apassy/licenses/laya-MODEL-CARD.md")
print("base weights", common.BASE_REPO, common.BASE_REVISION, digest)
PY

# The fine-tuned heads apassy-base-v1 (named build context `model`).
COPY --from=model apassy-base-v1.safetensors /opt/apassy/models/apassy-base-v1.safetensors
RUN python -B - <<'PY'
import json, os
import common
manifest = json.load(open("manifest.json", encoding="utf-8"))
path = "/opt/apassy/models/apassy-base-v1.safetensors"
assert common.sha256_file(path) == manifest["checkpoint"]["sha256"], "checkpoint SHA-256"
assert os.path.getsize(path) == manifest["checkpoint"]["size_bytes"], "checkpoint size"
print("checkpoint", manifest["version"])
PY

COPY LICENSE /opt/apassy/licenses/LICENSE
COPY tools/basemodel/NOTICE /opt/apassy/licenses/NOTICE
COPY tests/fixtures/bouncer/cases.tsv /opt/apassy/bench/cases.tsv
COPY tools/basemodel/app.py tools/basemodel/heads_cache.py tools/basemodel/jobs.py tools/basemodel/serve.py \
     tools/basemodel/train.py tools/basemodel/bench.py tools/basemodel/fetch_weights.py \
     /opt/apassy/tools/basemodel/
COPY tools/finetune/local_train.py /opt/apassy/tools/finetune/local_train.py
COPY --chmod=0755 tools/basemodel/docker-entrypoint.sh /usr/local/bin/apassy-brain

RUN set -eu; \
    chmod -R a+rX,go-w /opt/apassy; \
    useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin brain; \
    mkdir -p /data/heads; \
    chown -R 10001:10001 /data; \
    chmod 0700 /data /data/heads

LABEL org.opencontainers.image.title="apassy-brain" \
      org.opencontainers.image.description="Apassy bouncer brain server (bouncer-brain-v1), variant ${VARIANT}" \
      org.opencontainers.image.version=$APASSY_RELEASE_VERSION \
      org.opencontainers.image.revision=$APASSY_RELEASE_COMMIT \
      org.opencontainers.image.source="https://github.com/wydrox/apassy" \
      org.opencontainers.image.licenses="Apache-2.0" \
      cc.wyderka.apassy.brain.variant=$VARIANT

USER 10001:10001
WORKDIR /data
# The weights are in the image: no download at the start. serve.py refuses to listen
# on 0.0.0.0 without LAYA_API_KEY (or LAYA_API_KEY_FILE, read by the entrypoint).
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    APASSY_BASE_MODEL=/opt/apassy/models/apassy-base-v1.safetensors \
    APASSY_HEADS_DIR=/data/heads \
    APASSY_BENCH_CASES=/opt/apassy/bench/cases.tsv \
    LAYA_HOST=0.0.0.0 \
    LAYA_PORT=8770
VOLUME ["/data"]
EXPOSE 8770
# The model loads in about a minute on a CPU; /health answers only after the load.
HEALTHCHECK --interval=30s --timeout=10s --start-period=300s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('LAYA_PORT', '8770'), timeout=8)"]
ENTRYPOINT ["/usr/local/bin/apassy-brain"]
CMD ["serve"]
