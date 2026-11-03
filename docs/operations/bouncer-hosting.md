# Bouncer brain on your own server (self-host runbook)

Date: 2026-11-03. Decision: [ADR 0035](../adr/0035-bouncer-hosting-and-training-choice.md) section 2. Plan: [implementation plan 0035](../design/implementation-plan-0035.md), units E2 (this image) and K1 (measurements). Protocol: [bouncer-brain-v1](../contracts/bouncer-brain-v1.md) and [bouncer-brain-v2](../contracts/bouncer-brain-v2.md) (training jobs). Words: [bouncer.md](bouncer.md), Words.

Status: the image, its workflow and the bench script exist (E2). The Apassy app uses an own server when you choose it in Settings > Bouncer > Bouncer brain > Runs on > My Server… (HTTPS client, the choice with its owner check and consent, head set upload, merged shadow: units C1, C2, F, G and J1 are merged). Without that choice the bouncer gate keeps using the bouncer brain on this Mac. Training jobs on the server exist (I-srv); the app does not send a job yet (I-cli and J2). The K1 measurements (section 11) are pending: they need one paid devbox run that the owner confirms.

## 1. What runs where

- The **bouncer gate** stays in Apassy on the Mac and makes every decision. The server gives only probabilities.
- The **bouncer brain** server is `tools/basemodel/serve.py` in a container. It receives the state of each request (the user request, the stated purpose of the agent, and the shell command, with the paths in your project and home folder shortened to `.` and `~`), the fixed model questions, the hash of the active head set and of the shadow head set, and the head sets trained on your decisions (numbers, no text). It never receives a secret value, the vault, or the full paths of your project and home folder. You see this list in the consent screen of Apassy (version 1) before you choose the server.
- The server has a bearer token. Tailscale gives reachability only, never authorization. The token of your server is in the vault on your Mac only; it does not sync.
- A non-loopback address must use `https://` with a public certificate (platform roots on the Mac). A Tailscale Serve certificate for the `*.ts.net` name works. A private CA or a self-signed certificate does not.
- Unavailable, slow (more than 20 s per attempt), a wrong version, a wrong head hash (409) or a 401 is "unavailable" for the bouncer gate: it asks the owner. It is never an allowance.

## 2. Images

| Tag | Content |
| --- | --- |
| `ghcr.io/wydrox/apassy-brain:<version>` | CPU image, `linux/amd64` and `linux/arm64` (same as `:<version>-cpu`) |
| `ghcr.io/wydrox/apassy-brain:<version>-cuda` | CUDA image, `linux/amd64` only. Built and tested on a CPU; not tested on a GPU |
| `:<version>-cpu-amd64`, `:<version>-cpu-arm64`, `:<version>-cuda-amd64`, `:sha-<12 hex>-<variant>-<arch>` | the single images |

`<version>` is the shared Apassy release version. The CPU archives `apassy-brain-<version>-cpu-<arch>.tar.gz` with a `.sha256` file are also assets of the GitHub release `<version>` (the CUDA archive is over the 2 GiB asset limit, so it is on GHCR only).

Each image has: Python 3.12, the pinned `tools/basemodel/requirements.txt` (torch from the PyTorch CPU index in the CPU image; from PyPI with CUDA 13 libraries in the CUDA image), `serve.py`, `app.py`, `heads_cache.py`, `common.py`, `train.py`, `bench.py`, `manifest.json`, `tools/finetune/local_train.py`, the Laya base weights at revision `55cf4c4` and the heads `apassy-base-v1+83224960`. The build checks both files against `manifest.json`. The licenses are in `/opt/apassy/licenses`: `LICENSE` (Apache-2.0), `NOTICE` (what is in the image and under which license) and `laya-MODEL-CARD.md` (the model card of the weights at the pinned revision, Apache-2.0).

Check an archive before you load it:

```
sha256sum -c apassy-brain-<version>-cpu-amd64.tar.gz.sha256
docker load -i apassy-brain-<version>-cpu-amd64.tar.gz
docker image inspect apassy-brain:<version>-cpu-amd64 --format '{{.Architecture}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
```

How the images are made: `.github/workflows/bouncer-image.yml`. A tag `bouncer-image-<version>` on the tested release commit publishes. "Run workflow" builds and tests only and keeps the three archives as run artifacts for 7 days. The workflow reads `apassy-base-v1.safetensors` from `models/` in the R2 bucket (as the release workflow does). Never build on the Mac or on the production VPS.

## 3. Run the server

Requirements: Docker, 2 vCPU and 3 GB of memory (the first limits of ADR 0035 section 8; section "Measurements" gives the measured numbers), about 3 GB of disk for the CPU image, Tailscale for the HTTPS address.

1. Make a token file. Apassy can also make the token and show it once (unit C2); then paste it into the file.

   ```
   install -d -m 0700 ~/apassy-brain
   openssl rand -hex 32 | tr -d '\n' > ~/apassy-brain/token
   chmod 0644 ~/apassy-brain/token   # the container user (uid 10001) reads it; keep the folder 0700
   ```

2. Start the container. The port is bound to loopback on the host; Tailscale Serve (section 5) gives the HTTPS address.

   ```
   docker run -d --name apassy-brain --restart unless-stopped \
     --cpus=2 --memory=3g --memory-swap=3g \
     -p 127.0.0.1:8770:8770 \
     -v apassy-brain-data:/data \
     -v ~/apassy-brain/token:/run/secrets/brain-token:ro \
     -e LAYA_API_KEY_FILE=/run/secrets/brain-token \
     ghcr.io/wydrox/apassy-brain:<version>
   ```

   - Without a token the server does not start: it listens on `0.0.0.0` inside the container, and `serve.py` refuses a non-loopback address without `LAYA_API_KEY` (`bind_problem`). `LAYA_API_KEY_FILE` keeps the token out of `docker inspect`; `-e LAYA_API_KEY=…` also works.
   - `/data/heads` keeps the uploaded head sets (`<sha256>.safetensors` and `<sha256>.json`, mode 0600 in a 0700 folder). A bind mount instead of the volume must be owned by uid 10001.
   - `APASSY_HEADS_CACHE` (loaded head sets, default 4) and `APASSY_HEADS_MAX` (stored head sets, default 16) set the limits. `LAYA_LOG_LEVEL=info` logs one line per request: status, number of questions, latency and the first 8 hex of the head hashes, never the state, the questions, the answers or the token.
   - Threads: the entry point sets `OMP_NUM_THREADS` to the CPU quota of the container (`--cpus`), else to the CPUs that it can use. Set `OMP_NUM_THREADS` to change it.
   - The model loads in about a minute. `/health` answers after the load; the image has a Docker health check.

3. Check it on the host:

   ```
   curl -s http://127.0.0.1:8770/health
   curl -s -H "Authorization: Bearer $(cat ~/apassy-brain/token)" -H 'Content-Type: application/json' \
     -d @tests/fixtures/bouncer-brain-v1/request.json http://127.0.0.1:8770/v1/systemone
   ```

   The fixture names a head hash that the server does not have, so the second command answers 409 `unknown_heads`; remove the `heads` field for an answer of `apassy-base-v1+83224960`.

CUDA image: add `--gpus all` (NVIDIA driver with CUDA 13 support and the NVIDIA container toolkit on the host) and use `:<version>-cuda`. Without a GPU it runs on the CPU.

Compose (the same settings):

```yaml
services:
  brain:
    image: ghcr.io/wydrox/apassy-brain:<version>
    restart: unless-stopped
    ports: ["127.0.0.1:8770:8770"]
    environment:
      LAYA_API_KEY_FILE: /run/secrets/brain-token
    secrets: [brain-token]
    volumes: ["brain-data:/data"]
    cpus: 2
    mem_limit: 3g
    memswap_limit: 3g
secrets:
  brain-token:
    file: ./token
volumes:
  brain-data:
```

## 4. The token

- One token per server. Apassy sends it as `Authorization: Bearer <token>` on every route except `GET /health`. The server compares it in constant time. A missing or wrong token gives 401, and the bouncer gate asks the owner.
- The routes that write (`PUT` and `DELETE /v1/heads/<sha256>`, `DELETE /v1/owner`) work only when the server has a token.
- Rotation: write a new token to the file, restart the container (`docker restart apassy-brain`), and enter the new token in Apassy (the change of the hosting needs the owner check, Touch ID). The old token stops at the restart.
- Never put the token in a shell history, a repository, a chat or a log. `openssl rand … > file` writes it without showing it.

## 5. HTTPS with a Tailscale Serve certificate

1. In the Tailscale admin console of the tailnet, turn on MagicDNS and HTTPS certificates (an account setting of the owner).
2. On the server:

   ```
   tailscale serve --bg --https=443 http://127.0.0.1:8770
   tailscale serve status
   ```

   The address is `https://<machine>.<tailnet>.ts.net`. The certificate is a public Let's Encrypt certificate, so the platform roots on the Mac accept it.
3. From the Mac (on the same tailnet): `curl -s https://<machine>.<tailnet>.ts.net/health`.
4. Do not use Tailscale Funnel: it puts the server on the public internet, and then the token is the only protection.
5. In Apassy: Settings > Bouncer > Bouncer brain > Runs on > My Server…, with the address and the token. Apassy shows what leaves the Mac (consent version 1), and the change needs a fresh owner check (Touch ID). Apassy then uploads the active and shadow head sets (unit G) before the switch completes; a failed upload keeps the old host.

## 6. Training on your server

The server runs training jobs itself (`PUT /v1/train/<sha256>`, [fine-tune.md](fine-tune.md) section 6.3). A job starts only when the host has the trainer's memory cap (4 GiB by default, `APASSY_JOB_MEMORY_MB`) plus 1 GiB free, so give the container at least 5 GiB if you train on it; until then the job stays `queued`. The app does not send a job yet (units I-cli and J2). Until then, you can run one job by hand as a separate container from an export folder (`train.jsonl`, `val.jsonl`, `stats.json`, fine-tune.md section 6.1 step 4). The training gate stays: 300 owner decisions and 30 denials.

```
docker run --rm --cpus=2 --memory=4g --memory-swap=4g --cpu-shares=256 \
  -v "$PWD/export:/data/export:ro" -v apassy-brain-train:/data/out \
  ghcr.io/wydrox/apassy-brain:<version> train --data /data/export --out /data/out/candidate --deadline 7200
```

`train` runs `local_train.py` from the heads in the image at `nice 10`. The result is `candidate.safetensors`, `manifest.json` and `result.json`. Delete the export folder after the job: it has the commands and the user requests of the owner decisions. The new head set starts in shadow mode on the Mac; only the owner promotes it.

## 7. Update

`docker pull ghcr.io/wydrox/apassy-brain:<new version>`, then remove and start the container with the same volume. The head sets in `/data/heads` stay. A head set whose manifest names another base revision or other base weights stops working (the server checks it at each load); Apassy uploads it again or asks the owner.

## 8. Deletion

1. Delete the head sets of the owner (the default head set of the image stays):

   ```
   curl -s -o /dev/null -w '%{http_code}\n' -X DELETE \
     -H "Authorization: Bearer $(cat ~/apassy-brain/token)" http://127.0.0.1:8770/v1/owner   # 204
   ```

2. In Apassy, choose Hosting > This Mac (with the owner check). This removes the address and the token from the vault.
3. Stop the HTTPS address: `tailscale serve --https=443 off` (or `tailscale serve reset`).
4. Remove the container, the volumes and the token:

   ```
   docker rm -f apassy-brain
   docker volume rm apassy-brain-data apassy-brain-train
   rm -f ~/apassy-brain/token && rmdir ~/apassy-brain
   docker image rm ghcr.io/wydrox/apassy-brain:<version>
   ```

5. Check: `docker volume ls | grep apassy-brain` shows nothing.

## 9. Build the image once on a devbox

Use this when no GitHub artifact exists yet (for example K1 before the first tag). The build runs on the devbox; the Mac only sends the small build context and the checkpoint. Run it from a clean checkout of the commit to measure.

```
REPO=$(git rev-parse --show-toplevel); cd "$REPO"
CKPT="$HOME/Library/Application Support/Apassy/laya/models/apassy-base-v1.safetensors"
MODEL=$(mktemp -d /tmp/k1-model.XXXXXX)      # only this file goes to the devbox, nothing else of models/
cp "$CKPT" "$MODEL/apassy-base-v1.safetensors"
shasum -a 256 "$MODEL/apassy-base-v1.safetensors"   # must be 832249609f0cfd978cc7697326d55bc6d2676507eec13e5fb3f4bc6b35cfe850
COMMIT=$(git rev-parse HEAD)
docker --context devbox-x86 buildx version
docker --context devbox-x86 build --platform linux/amd64 --build-arg VARIANT=cpu \
  --build-arg APASSY_RELEASE_VERSION=k1 --build-arg APASSY_RELEASE_COMMIT=$COMMIT \
  --build-context model="$MODEL" -f tools/basemodel/Dockerfile -t apassy-brain:k1-cpu .
docker --context devbox-x86 build --platform linux/amd64 --build-arg VARIANT=cuda \
  --build-arg APASSY_RELEASE_VERSION=k1 --build-arg APASSY_RELEASE_COMMIT=$COMMIT \
  --build-context model="$MODEL" -f tools/basemodel/Dockerfile -t apassy-brain:k1-cuda .
docker --context devbox-arm build --platform linux/arm64 --build-arg VARIANT=cpu \
  --build-arg APASSY_RELEASE_VERSION=k1 --build-arg APASSY_RELEASE_COMMIT=$COMMIT \
  --build-context model="$MODEL" -f tools/basemodel/Dockerfile -t apassy-brain:k1-cpu .
docker --context devbox-x86 image inspect apassy-brain:k1-cpu --format '{{.Architecture}}'   # amd64
docker --context devbox-arm image inspect apassy-brain:k1-cpu --format '{{.Architecture}}'   # arm64
rm -rf "$MODEL"
```

With GitHub artifacts instead (the bytes that a tag publishes): Actions > Bouncer brain image > Run workflow on the commit, then on the Mac `gh run download <run id> -n apassy-brain-cpu-amd64 -n apassy-brain-cpu-arm64 -n apassy-brain-cuda-amd64 -D "$K1/images"`, `sha256sum -c` each archive, and `docker --context devbox-x86 load -i "$K1/images/apassy-brain-<version>-cpu-amd64.tar.gz"` (the same for `cuda-amd64` on x86 and `cpu-arm64` on arm). Check the free disk space of the Mac first: the three archives are several GB. Then use the loaded tags in place of `apassy-brain:k1-cpu` and `apassy-brain:k1-cuda` below.

## 10. K1 measurement procedure

One bounded paid session (plan 0035 K1). Who: the top-level agent (ops role). Before it starts: one "yes" of the owner for the cost (CLAUDE.md, Hetzner), and `devbox status` (shared 12.50 EUR/month budget). Limits: at most 2 hours per server; `devbox down --all` at the end, also after a failure or a stop. Docker only through `docker --context devbox-x86 …` and `docker --context devbox-arm …`; nothing on the Mac's Docker, nothing on `ottervibe`. The data is synthetic only (bench.py); no owner data goes to a devbox.

### 10.1 Start

1. `devbox status` and note the budget and the time.
2. Start both servers through Apassy (`apassy_run_with_secrets`, item "devbox tailscale auth key"; command `devbox up x86 && devbox up arm`). Note the start time of each server: its 2 hours start here.
3. Check: `docker --context devbox-x86 info --format '{{.Architecture}} {{.NCPU}} {{.MemTotal}}'` and the same for `devbox-arm`.
4. Get the images (section 9: build on the devbox, or load the GitHub artifacts).

Shell setup on the Mac (each block below uses it; for arm set `S=arm`):

```
K1=~/k1-$(date +%Y%m%d); mkdir -p "$K1/results"; S=x86
D() { docker --context "devbox-$S" "$@"; }   # a function: zsh does not split a "$D" string
IMG=apassy-brain:k1-cpu        # or the loaded tag of the artifact
test -s "$K1/token" || { (umask 077; openssl rand -hex 32 | tr -d '\n' > "$K1/token"); }
```

The token is a synthetic one for this session only.

### 10.2 Prepare each server (x86, then arm)

```
D volume create k1-secret; D volume create k1-bench
D run --rm -i --user 0 -v k1-secret:/run/k1 $IMG sh -c 'umask 022; cat > /run/k1/token' < "$K1/token"
D run --rm -v k1-bench:/data $IMG bench make-heads --out /data/synthetic/heads --count 10 --seed 1
D run --rm -v k1-bench:/data $IMG bench make-train --out /data/synthetic/train
D run --rm -v k1-bench:/data $IMG cat /data/synthetic/heads/index.json
```

`k1-bench` is mounted on `/data`, so a new volume takes the owner of `/data` in the image (uid 10001). The 10 head sets have the shapes of the base heads; the training set is the mapping of `finetune::examples_from_export` on 300 synthetic decisions from `cases.tsv`. Note the hash of head set 1 (`H1`).

### 10.3 Steps 1 and 2: latency and memory

Run the server, then the bench in its network and PID namespace (the bench reads the server's resident memory from `/proc`; its own CPU is outside the limits of the server). Each run starts a new server with a new heads volume, so the first request is cold.

```
# Without limits.
D run -d --name k1-brain -e LAYA_API_KEY_FILE=/run/k1/token -e APASSY_HEADS_CACHE=10 \
  -v k1-secret:/run/k1:ro -v k1-heads-a:/data $IMG
D run --rm --network container:k1-brain --pid container:k1-brain \
  -e LAYA_API_KEY_FILE=/run/k1/token -v k1-secret:/run/k1:ro -v k1-bench:/data $IMG \
  bench suite --url http://127.0.0.1:8770 --heads-dir /data/synthetic/heads --n 50 --owners 10 \
  --label $S-nolimit --out /data/results/$S-nolimit.json
D exec k1-brain bench cgroup > "$K1/results/$S-nolimit.cgroup.json"
D rm -f k1-brain

# With the first limits of ADR 0035 section 8.
D run -d --name k1-brain --cpus=2 --memory=3g --memory-swap=3g \
  -e LAYA_API_KEY_FILE=/run/k1/token -e APASSY_HEADS_CACHE=10 \
  -v k1-secret:/run/k1:ro -v k1-heads-b:/data $IMG
D run --rm --network container:k1-brain --pid container:k1-brain \
  -e LAYA_API_KEY_FILE=/run/k1/token -v k1-secret:/run/k1:ro -v k1-bench:/data $IMG \
  bench suite --url http://127.0.0.1:8770 --heads-dir /data/synthetic/heads --n 50 --owners 10 \
  --label $S-limit --out /data/results/$S-limit.json
D exec k1-brain bench cgroup > "$K1/results/$S-limit.cgroup.json"
D inspect k1-brain --format '{{.State.OOMKilled}} {{.RestartCount}}'
D rm -f k1-brain
```

`suite` gives, in this order: idle resident memory; the cold first request; 50 warm requests with the default heads; 50 with the default heads and `shadow_heads` = H1 (shadow on); 50 with H1 as the active heads; the 10 head sets loaded one by one (cold time and resident memory after each, so the memory per extra head set); 50 requests with H1 alone; then 10 parallel owners (each its own head hash, 50 requests in total); and the peak resident memory. Each request has 5 questions (6 with an owner rule); every third state is long (about 1,400 characters, under 512 tokens: `max_input_tokens` shows the largest). A `422` in `statuses` means a state over the context: rerun with `--long-chars 1000`. The file ends with `checks`: the p95 values, `p95_at_most_20_s`, `per_owner_mib` and `parallel_p95_ratio`.

If x86 with limits has a p95 over 20 s: the architect reads the free CPU and memory of `ottervibe` (read-only, by ops) and names the largest limits it can give; run the "with limits" block again with them (for example `--cpus=4 --memory=4g --memory-swap=4g`, label `$S-limit2`) in the same session.

### 10.4 Step 3: training (x86; arm if the time allows)

```
D run --rm --name k1-train --cpus=2 --memory=4g --memory-swap=4g --cpu-shares=256 \
  -v k1-bench:/data $IMG bench train --data /data/synthetic/train --out /data/train-out/$S \
  --report /data/results/$S-train.json
```

The report has the wall time, the peak resident memory of the trainer (`child_peak_rss_mib`), the peak memory of the container cgroup (`cgroup.memory_peak_mib`) and the `result.json` numbers. Exit status 137 is the memory limit: write it down, then run again with `--memory=6g --memory-swap=6g` to measure the peak.

### 10.5 Step 4: equality with serve.py on this Mac

1. Answers of the container (x86, no limits; shadow H1 gives the base answers and the shadow answers in one request):

   ```
   D run -d --name k1-brain -e LAYA_API_KEY_FILE=/run/k1/token -v k1-secret:/run/k1:ro -v k1-heads-a:/data $IMG
   D run --rm --network container:k1-brain -e LAYA_API_KEY_FILE=/run/k1/token -v k1-secret:/run/k1:ro \
     -v k1-bench:/data $IMG bench answers --url http://127.0.0.1:8770 --shadow H1 --out /data/results/x86-answers-shadow.json
   D run --rm --network container:k1-brain -e LAYA_API_KEY_FILE=/run/k1/token -v k1-secret:/run/k1:ro \
     -v k1-bench:/data $IMG bench answers --url http://127.0.0.1:8770 --heads H1 --out /data/results/x86-answers-h1.json
   D rm -f k1-brain
   ```

   Replace `H1` with the hash of head set 1. `k1-heads-a` still has the 10 head sets of 10.3.
2. Copy the results, head set 1 and the trained candidate to the Mac:

   ```
   D create --name k1-files -v k1-bench:/data $IMG
   D cp k1-files:/data/results/. "$K1/results/"
   mkdir -p "$K1/h1" && D cp k1-files:/data/synthetic/heads/H1.safetensors "$K1/h1/" \
     && D cp k1-files:/data/synthetic/heads/H1.json "$K1/h1/" \
     && D cp k1-files:/data/synthetic/heads/index.json "$K1/h1/"
   D cp k1-files:/data/train-out/x86 "$K1/x86-train-out"
   D rm k1-files
   shasum -a 256 "$K1/h1/H1.safetensors"     # must be H1
   ```

3. One local `serve.py` on the Mac on a free port, with its own heads folder, beside the running Apassy brain (do not stop or change the owner's brain on 8770). Check the free memory first (about 3 GB).

   ```
   cd "$(git rev-parse --show-toplevel)"
   LAYA_DIR="$HOME/Library/Application Support/Apassy/laya"
   mkdir -p "$K1/mac-heads"
   LAYA_HOST=127.0.0.1 LAYA_PORT=8779 LAYA_API_KEY="$(cat "$K1/token")" APASSY_HEADS_DIR="$K1/mac-heads" \
     APASSY_BASE_MODEL="$LAYA_DIR/models/apassy-base-v1.safetensors" \
     tools/basemodel/start.sh > "$K1/mac-serve.log" 2>&1 &
   echo $! > "$K1/mac-serve.pid"
   B() { "$LAYA_DIR/.venv/bin/python" -B tools/basemodel/bench.py "$@"; }
   B upload --url http://127.0.0.1:8779 --token-file "$K1/token" --heads-dir "$K1/h1" --first 1
   B answers --url http://127.0.0.1:8779 --token-file "$K1/token" --shadow H1 --out "$K1/results/mac-answers-shadow.json"
   B answers --url http://127.0.0.1:8779 --token-file "$K1/token" --heads H1 --out "$K1/results/mac-answers-h1.json"
   B compare "$K1/results/x86-answers-shadow.json" "$K1/results/mac-answers-shadow.json"                       # base heads
   B compare "$K1/results/x86-answers-shadow.json" "$K1/results/mac-answers-shadow.json" --key shadow_answers  # stage 2: shadow
   B compare "$K1/results/x86-answers-h1.json" "$K1/results/mac-answers-h1.json"                               # H1 active
   ```

4. Stage 4: train on the Mac from the same synthetic set, then compare the two trained head sets on the Mac server:

   ```
   B make-train --out "$K1/mac-train"
   ~/.local/bin/heavy-check "$LAYA_DIR/.venv/bin/python" -B tools/finetune/local_train.py \
     --data "$K1/mac-train" --out "$K1/mac-train-out" --init "$LAYA_DIR/models/apassy-base-v1.safetensors" --deadline 3600
   B upload --url http://127.0.0.1:8779 --token-file "$K1/token" --candidate "$K1/x86-train-out" --candidate "$K1/mac-train-out"
   B answers --url http://127.0.0.1:8779 --token-file "$K1/token" --heads <x86 candidate sha> --out "$K1/results/train-x86.json"
   B answers --url http://127.0.0.1:8779 --token-file "$K1/token" --heads <Mac candidate sha> --out "$K1/results/train-mac.json"
   B compare "$K1/results/train-x86.json" "$K1/results/train-mac.json"
   kill "$(cat "$K1/mac-serve.pid")"; rm -rf "$K1/mac-heads" "$K1/mac-train"
   ```

   `make-train` gives the same bytes on every machine (`shasum` of `train.jsonl` against the devbox copy, if in doubt). The candidate hashes are `checkpoint.sha256` in each `manifest.json`. `compare` exits 1 when a probability differs by more than 0.02 or the run/ask outcome differs (the model-fact part of `decide` for a command that the packs do not know: `task_match` ≥ 0.75, `destroy` < 0.9, `rule_break` ≤ 0.2). The Mac trains on MPS with an fp16 encoder cache and the devbox on the CPU in fp32: a difference is a finding to write down, not a reason to stop.

### 10.6 Step 5: the CUDA image on the CPU (x86)

```
D run -d --name k1-cuda -e LAYA_API_KEY_FILE=/run/k1/token -v k1-secret:/run/k1:ro apassy-brain:k1-cuda
D run --rm --network container:k1-cuda -e LAYA_API_KEY_FILE=/run/k1/token -v k1-secret:/run/k1:ro \
  -v k1-bench:/data $IMG bench latency --url http://127.0.0.1:8770 --n 3 --out /data/results/x86-cuda-on-cpu.json
D exec k1-cuda python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8770/health').read())"
D rm -f k1-cuda
```

### 10.7 arm, collect, stop

1. Set `S=arm` (the function `D` then uses `devbox-arm`) and run 10.2 and 10.3 (and 10.4 if the 2 hours allow). Then copy its results: `D create --name k1-files -v k1-bench:/data $IMG && D cp k1-files:/data/results/. "$K1/results/" && D rm k1-files`.
2. Keep the runs going: a devbox deletes itself after 30 minutes idle.
3. At the end, and also after a failure or at 2 hours: `devbox down --all`, then `devbox status` (no server left). The devbox volumes go with the servers.
4. Write the numbers in section 11 and keep `$K1/results` until the architect has applied the rules of plan 0035 K1. Then `rm -rf "$K1"` (it has only synthetic data and the session token).

## 11. Measurements

Not measured yet (K1). K1 is one bounded paid run on `devbox-x86` and `devbox-arm` (section 10); the owner has to confirm the cost before it starts. Fill in from `$K1/results/*.json`:

| Value | x86 no limits | x86 2 vCPU / 3 GB | arm no limits | arm 2 vCPU / 3 GB |
| --- | --- | --- | --- | --- |
| Cold first request (s) | | | | |
| Warm p50 / p95, default heads (s) | | | | |
| Warm p50 / p95, shadow on (s) | | | | |
| Idle / peak resident memory (MiB) | | | | |
| Memory per extra head set (MiB) | | | | |
| 10 owners p95 / single p95 | | | | |
| Training wall time / peak memory (2 vCPU / 4 GB) | | | | |

Equality (step 4): base heads, shadow H1, active H1, trained head sets: max \|Δp\| and outcome differences. CUDA image on the CPU: health and one answer.
