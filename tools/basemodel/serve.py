#!/usr/bin/env python3
"""Serve the Apassy base model over the Laya `/v1/systemone` protocol (goal B8).

The server is `app.create_app` (laya-serve's routes and guardrails, plus the head
routes) with one router. The router:

1. loads the English Laya checkpoint at the pinned Hugging Face revision
   (`common.BASE_REVISION`) and checks the SHA-256 of its weights,
2. checks the SHA-256 of the fine-tuned head file against the manifest,
3. replaces the decision heads with the fine-tuned heads,
4. answers every request with the English checkpoint, and
5. reports `apassy-base-v1+<hash8>` in the `model` field of each answer.

Questions in the manifest list `serve.zero_shot_questions` get the answer of the
stock heads (same encoder pass). See docs/operations/base-model.md.

The server is also the bouncer brain of ADR 0035 (contract bouncer-brain-v1): it
keeps a cache of head sets on the one encoder (`heads_cache.py`), answers the
`heads` and `shadow_heads` of a request from one encoder pass, and serves the head
routes (`app.py`). Without `heads`, a request gets the checkpoint above, as before.

Environment: `LAYA_HOST` (default 127.0.0.1), `LAYA_PORT` (default 8770),
`LAYA_DEVICE`, `LAYA_API_KEY` (as in laya-serve), `APASSY_HEADS_DIR` (uploaded head
sets; default `$APASSY_LAYA_DIR/heads`, else
`~/Library/Application Support/Apassy/laya/heads`; never inside a `.app` bundle),
`APASSY_HEADS_CACHE` (loaded uploaded head sets, default 4), `APASSY_HEADS_MAX`
(stored uploaded head sets, default 16).

The server refuses to start on an address other than loopback without
`LAYA_API_KEY`, and serves the head routes that write only with a token.

Run inside the Laya virtual environment:
  .venv/bin/python tools/basemodel/serve.py --checkpoint <file> [--manifest <file>]
"""

import argparse
import ipaddress
import json
import logging
import os
import pathlib
import sys
import re
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# No __pycache__ next to this script: in Apassy.app it breaks the code signature.
_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import common  # noqa: E402
import heads_cache  # noqa: E402
import app as brain_app  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE


def read_manifest(checkpoint, manifest):
    candidates = [manifest] if manifest else [
        os.path.join(os.path.dirname(os.path.abspath(checkpoint)), "manifest.json"),
        os.path.join(HERE, "manifest.json"),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return json.load(f), path
    raise SystemExit("serve: no manifest.json next to the checkpoint or in %s" % HERE)


def verify(checkpoint, manifest, base):
    digest = common.sha256_file(checkpoint)
    expected = manifest["checkpoint"]["sha256"]
    if digest != expected:
        raise SystemExit("serve: checkpoint SHA-256 %s does not match the manifest (%s)" % (digest, expected))
    if os.path.getsize(checkpoint) != manifest["checkpoint"]["size_bytes"]:
        raise SystemExit("serve: checkpoint size does not match the manifest")
    base_manifest = manifest["base"]
    if base_manifest["revision"] != common.BASE_REVISION:
        raise SystemExit("serve: the manifest names another base revision")
    weights = common.sha256_file(os.path.join(base, "model.safetensors"))
    if weights != base_manifest["weights_sha256"]:
        raise SystemExit("serve: base weights SHA-256 %s does not match the manifest" % weights)
    return digest


def temperature_diagnostic(message):
    """Clarify Laya's existing clamp warning, without changing calibration."""
    text = str(message)
    if not text.startswith("laya: this checkpoint ships invalid temperatures"):
        return text
    affected = text.partition("using ")[2].partition(". Treat confidence")[0]
    buckets = re.findall(r"(?:^|, )([^=]+)=", affected)
    # A qtype fallback can affect noul only when there is no option-specific value.
    # Conservatively flag the noul fallback rather than claiming it cannot matter.
    affects_noul = any(b in ("noul:2", "temperature[2]") for b in buckets)
    impact = ("may affect the bouncer's yes/no questions (noul:2)"
              if affects_noul or not buckets else
              "does not affect the bouncer's yes/no questions (noul:2)")
    return ("Apassy: temperature bucket(s) %s clamped by Laya: %s; %s. "
            "Confidence in the affected buckets is uncalibrated."
            % (", ".join(buckets) or "unknown", affected, impact))


def require_complete_state(agent, state, questions):
    """Never score a prefix that can hide the command or an owner rule.

    Laya 0.3.20 silently slices state tokens to the remaining per-question room.
    Use its exact tokenizer and question formatter to check every question first.
    Normal short states and the trained question format remain unchanged.
    """
    from laya.common import build_sequence, serialize_state

    tokens = agent.tok(serialize_state(state).replace(agent.tok.mask_token, " "),
                       add_special_tokens=False)["input_ids"]
    max_len = agent.cfg.get("max_len", 512)
    head_max_len = agent.cfg.get("head_max_len", 192)
    for definition in questions.values():
        header, _ = build_sequence(agent.tok, "", agent._to_internal(definition),
                                   max_len, head_max_len, state_ids=[])
        if len(header) + len(tokens) > max_len:
            raise ValueError("The complete request does not fit the model context. Ask the owner.")


def fp16_encoder_on_mps(agent, model):
    """Keep the encoder in fp16 on an Apple GPU. Return True if it changed the model.

    The base checkpoint stores the encoder in fp16, and Laya autocasts it to fp16 on
    MPS. But Laya 0.3.20 loads it as fp32 (1.6 GB) and casts every weight again in
    each request; the allocator then keeps those copies. With fp16 weights and
    autocast for every request, the answers are the same at about half the memory.
    The fine-tuned heads stay fp32. Moving the model to the CPU and back drops the
    fp32 buffers, which would otherwise stay fragmented in the MPS allocator.
    """
    import torch

    if agent.device.type != "mps":
        return False
    model.tuned.encoder.half()
    # Laya runs a request with fewer rows in fp32; fp16 weights need autocast for all.
    agent.mps_amp_min_rows = 1
    model.to("cpu")
    torch.mps.empty_cache()
    model.to(agent.device)
    torch.mps.empty_cache()
    return True


def zero_shot_rows(zero_shot, questions):
    """Which rows take the stock heads. Rows follow the question order of one state
    (laya Agent._encode_state). None when no question is zero-shot."""
    return [qid in zero_shot for qid in questions] if zero_shot else None


class HeadSelection:
    """The head sets of one request. Set and cleared inside the single inference worker."""

    def __init__(self, active, shadow, questions):
        # None keeps the default path of the server before ADR 0035 (`DualHeads`).
        self.active = None if active.default else active.module
        self.stock_rows = zero_shot_rows(active.zero_shot, questions)
        self.shadow = None if shadow is None else shadow.module
        self.shadow_rows = None if shadow is None else zero_shot_rows(shadow.zero_shot, questions)
        # (logits, act probabilities, markers per row) of the shadow, or the error.
        self.shadow_out = None
        self.shadow_error = None


def on_device(module, device):
    """Move an uploaded head set to `device` if it is elsewhere.

    After laya's GPU-to-CPU fallback, `agent.model.to(cpu)` moved the encoder, the
    default and the stock heads, but not the uploaded head sets.
    """
    if module is not None and module.scorer[-1].weight.device != device:
        module.to(device)
    return module


def make_multi_heads(tuned, stock):
    """The model that laya runs: `tuned` (a DecisionModel), the head sets of a request
    (`.request`, a HeadSelection), and the `stock` heads (or None) for some rows."""
    import torch

    class MultiHeads(torch.nn.Module):
        """The default model, the head sets of a request, and the stock heads for some rows.

        One encoder pass: the active head set answers through laya; the shadow head set
        runs on the same encoder states and keeps its outputs for the shadow answers.
        """

        def __init__(self):
            super().__init__()
            self.tuned = tuned
            self.stock = stock
            self.request = None

        @staticmethod
        def heads(m, h, attention_mask, marker_pos, marker_mask, qtype):
            # The part of DecisionModel.forward after the encoder (laya 0.3.20).
            h = h + m.type_emb(qtype)[:, None, :]
            if m.head is not None:
                pad = ~attention_mask.bool()
                for layer in m.head.layers:
                    h = layer(h, src_key_padding_mask=pad)
            idx = marker_pos.clamp(min=0)[:, :, None].expand(-1, -1, h.size(-1))
            g = torch.gather(h, 1, idx)
            logits = m.scorer(g).squeeze(-1).float()
            logits = logits.masked_fill(~marker_mask, -1e4)
            p = torch.softmax(logits.detach(), -1)
            k = marker_mask.sum(-1).clamp(min=2).float()
            ent = -(p * torch.log(p.clamp_min(1e-9))).sum(-1) / torch.log(k)
            if p.size(-1) >= 2:
                top2 = p.topk(2, -1).values
            else:
                # One option only (laya pads the second slot with 0.0).
                top1 = p.topk(1, -1).values
                top2 = torch.cat([top1, torch.zeros_like(top1)], dim=-1)
            feats = torch.stack([top2[:, 0], top2[:, 0] - top2[:, 1], ent, k / 255.0], -1)
            pooled = h[:, 0].float()
            return logits, m.act_head(torch.cat([pooled, feats], -1))

        def forward(self, input_ids, attention_mask, marker_pos, marker_mask, qtype):
            request = self.request
            n = input_ids.shape[0]
            device = input_ids.device

            def stock_used(rows):
                return self.stock is not None and rows is not None and any(rows) and len(rows) == n

            if request is None:
                return self.tuned(input_ids, attention_mask, marker_pos, marker_mask, qtype)
            active = self.tuned if request.active is None else on_device(request.active, device)
            if request.shadow is None and not stock_used(request.stock_rows):
                return active(input_ids, attention_mask, marker_pos, marker_mask, qtype)
            h = self.tuned.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
            args = (h, attention_mask, marker_pos, marker_mask, qtype)
            stock_out = []

            def answer(m, rows):
                lt, at = self.heads(m, *args)
                if not stock_used(rows):
                    return lt, at
                if not stock_out:
                    stock_out.append(self.heads(self.stock, *args))
                ls, as_ = stock_out[0]
                use = torch.tensor(rows, device=device)[:, None]
                return torch.where(use, ls, lt), torch.where(use, as_, at)

            logits, act = answer(active, request.stock_rows)
            if request.shadow is not None:
                request.shadow_out, request.shadow_error = None, None
                try:
                    sl, sa = answer(on_device(request.shadow, device), request.shadow_rows)
                    # The conversion of laya Agent._forward.
                    request.shadow_out = (sl.float().cpu().numpy(),
                                          torch.softmax(sa.float(), -1).cpu().numpy(),
                                          [int(k) for k in marker_mask.sum(-1).tolist()])
                except Exception as error:  # noqa: BLE001 -- the shadow never fails the request
                    request.shadow_error = error
            return logits, act

    return MultiHeads()


def shadow_answers(agent, request, questions):
    """Decode the stashed shadow outputs of `request` with laya's own answer decoder."""
    if not questions:
        return {}
    if request.shadow_out is None:
        raise request.shadow_error or RuntimeError("no shadow output")
    logits, act, markers = request.shadow_out
    ids = list(questions.keys())
    internal = {qid: agent._to_internal(questions[qid]) for qid in ids}
    # `_decode_answers` reads only the number of markers of each row.
    items = [{"markers": range(k)} for k in markers]
    return agent._decode_answers(logits, act, items, ids, internal, 0)


def build_router(checkpoint, manifest_path=None, device=None, heads_dir=None,
                 cache_limit=heads_cache.DEFAULT_CACHE_LIMIT, max_stored=heads_cache.DEFAULT_STORED_LIMIT):
    import torch
    from laya.agent import Agent
    from laya.common import DecisionModel
    from laya.router import RouteDecision, Router
    from safetensors import SafetensorError

    manifest, _ = read_manifest(checkpoint, manifest_path)
    base = common.base_dir()
    digest = verify(checkpoint, manifest, base)
    version = "%s+%s" % (manifest.get("name", common.MODEL_NAME), digest[:8])
    zero_shot = set(manifest.get("serve", {}).get("zero_shot_questions", []))

    with warnings.catch_warnings(record=True) as diagnostics:
        warnings.simplefilter("always", RuntimeWarning)
        agent = Agent(base, device=device)
    for diagnostic in diagnostics:
        warnings.warn(temperature_diagnostic(diagnostic.message), diagnostic.category, stacklevel=2)
    tuned = agent.model
    head_layers = agent.cfg.get("head_layers", 2)
    n_act = len(agent.cfg.get("act_costs", {})) + 1
    stock = None
    if zero_shot:
        # A second head set with the stock weights. It shares the encoder module.
        stock = DecisionModel(tuned.encoder, head_layers, n_act)
        stock.load_state_dict(tuned.state_dict(), strict=True)
        stock.to(agent.device).eval()
    expected_shapes = {k: list(v.shape) for k, v in tuned.state_dict().items()
                       if k.startswith(common.TRAINED_PREFIXES)}
    tensors, _meta = common.load_checkpoint(checkpoint)
    common.apply_heads(tuned, tensors)
    del tensors
    tuned.eval()

    def load_head_set(path):
        """An uploaded head set: a DecisionModel on the one encoder, fp32 heads, eval mode.

        Built like `stock`; the untrained parts (`act_head`, `temperature`) come from the
        base checkpoint, the trained parts from the file (`common.apply_heads`).
        """
        try:
            heads, _ = common.load_checkpoint(path)
        except SafetensorError:
            raise ValueError("the stored head file does not open") from None
        model = DecisionModel(tuned.encoder, head_layers, n_act)
        untrained = {k: v for k, v in tuned.state_dict().items()
                     if not k.startswith("encoder.") and not k.startswith(common.TRAINED_PREFIXES)}
        model.load_state_dict(untrained, strict=False)
        common.apply_heads(model, heads)
        return model.to(agent.device).eval()

    dual = make_multi_heads(tuned, stock)
    agent.model = dual
    on_mps = fp16_encoder_on_mps(agent, dual)

    default_set = heads_cache.HeadSet(digest, version, tuned, zero_shot,
                                      manifest["checkpoint"]["size_bytes"], default=True)
    cache = heads_cache.HeadSetCache(
        default_set, resolve_heads_dir(heads_dir), manifest["base"], load_head_set,
        limit=cache_limit, expected_shapes=expected_shapes, stock_available=stock is not None,
        log=brain_app.LOG, max_stored=max_stored)

    class BaseRouter(Router):
        """Every request goes to the fine-tuned English checkpoint."""

        def __init__(self):
            super().__init__(max_loaded=1, default="english")
            self.attach("english", agent)
            self.version = version
            self.zero_shot = zero_shot
            self.cache = cache

        def _route(self, state, questions=None, model=None, task=None, lang=None, lang_guess=None):
            return RouteDecision(model="english", repo="%s@%s" % (common.BASE_REPO, common.BASE_REVISION),
                                 reason="apassy base model", detection=None, workflow=None)

        def predict(self, state, questions, model=None, heads=None, shadow_heads=None, **kwargs):
            from fastapi import HTTPException

            try:
                require_complete_state(agent, state, questions)
            except ValueError as error:
                raise HTTPException(status_code=422, detail={
                    "code": "input_too_long", "message": str(error)}) from error
            return heads_cache.answer(
                cache, lambda active, shadow: self._infer(state, questions, active, shadow, kwargs),
                heads, shadow_heads)

        def _infer(self, state, questions, active, shadow, kwargs):
            request = HeadSelection(active, shadow, questions)
            dual.request = request
            try:
                result = super().predict(state, questions, model=None, **kwargs)
                answers = None
                if shadow is not None:
                    try:
                        answers = shadow_answers(agent, request, questions)
                    except Exception as error:  # noqa: BLE001 -- the shadow never fails the request
                        answers = error
            finally:
                dual.request = None
                if on_mps:
                    # Give the activation buffers of this request back to the system.
                    torch.mps.empty_cache()
            return result, answers

    return BaseRouter(), version, sorted(zero_shot)


def limit_from_env(name, default):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        limit = int(raw)
    except ValueError:
        limit = 0
    if limit < 1:
        raise SystemExit("serve: invalid %s %r: must be an integer >= 1" % (name, raw))
    return limit


def cache_limit_from_env():
    return limit_from_env("APASSY_HEADS_CACHE", heads_cache.DEFAULT_CACHE_LIMIT)


def resolve_heads_dir(explicit=None, environ=None, home=None):
    """The heads folder: `explicit`, `APASSY_HEADS_DIR`, `$APASSY_LAYA_DIR/heads`, or
    `~/Library/Application Support/Apassy/laya/heads`. Never inside a `.app` bundle:
    a file written there breaks the code signature of the app."""
    environ = os.environ if environ is None else environ
    path = explicit or environ.get("APASSY_HEADS_DIR") or None
    if path is None:
        laya_dir = environ.get("APASSY_LAYA_DIR") or os.path.join(
            home or os.path.expanduser("~"), "Library", "Application Support", "Apassy", "laya")
        path = os.path.join(laya_dir, "heads")
    path = os.path.abspath(os.path.expanduser(path))
    for candidate in (path, os.path.realpath(path)):
        if any(part.lower().endswith(".app") for part in pathlib.PurePath(candidate).parts):
            raise SystemExit("serve: the heads folder %s is inside an app bundle; set APASSY_HEADS_DIR "
                             "to a data folder" % path)
    return path


def is_loopback(host):
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def bind_problem(host, api_key):
    """Why the server must not start on `host` with `api_key`, or None."""
    if api_key or is_loopback(host):
        return None
    return ("serve: LAYA_HOST %s is not a loopback address and LAYA_API_KEY is not set; "
            "set a token or listen on 127.0.0.1" % host)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", default=os.environ.get("APASSY_BASE_MODEL", ""))
    ap.add_argument("--manifest", default="")
    args = ap.parse_args()
    if not args.checkpoint or not os.path.isfile(args.checkpoint):
        raise SystemExit("serve: no checkpoint. Use the stock laya-serve for zero-shot answers.")

    import uvicorn
    from laya.serve import _resolve_port

    os.environ.setdefault("LAYA_PORT", "8770")
    host = os.environ.get("LAYA_HOST", "127.0.0.1")
    # Before the model loads: these refusals cost nothing.
    problem = bind_problem(host, os.environ.get("LAYA_API_KEY") or None)
    if problem is not None:
        raise SystemExit(problem)
    limit = cache_limit_from_env()
    max_stored = limit_from_env("APASSY_HEADS_MAX", heads_cache.DEFAULT_STORED_LIMIT)
    heads_dir = resolve_heads_dir()
    router, version, zero_shot = build_router(args.checkpoint, args.manifest or None,
                                              os.environ.get("LAYA_DEVICE") or None,
                                              heads_dir=heads_dir, cache_limit=limit,
                                              max_stored=max_stored)
    log_level = os.environ.get("LAYA_LOG_LEVEL", "warning")
    # Counts, latency, status and head hashes only (app.py); never a state or an answer.
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
    brain_app.LOG.addHandler(handler)
    brain_app.LOG.setLevel(getattr(logging, log_level.upper(), logging.WARNING))
    brain_app.LOG.propagate = False
    print("apassy base model %s on %s:%s (zero-shot questions: %s; head sets: %s, %d loaded and "
          "%d stored at most)" % (
              version, host, os.environ["LAYA_PORT"], ", ".join(zero_shot) or "none",
              router.cache.heads_dir, router.cache.limit, router.cache.max_stored), flush=True)
    # h11 refuses a request head over 16 KiB with its own 400; allow more, so the
    # 16 KiB limit of the Apassy-Manifest header answers 413 (app.py).
    uvicorn.run(brain_app.create_app(router, router.cache), host=host, port=_resolve_port(),
                log_level=log_level, h11_max_incomplete_event_size=64 * 1024)


if __name__ == "__main__":
    main()
