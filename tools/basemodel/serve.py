#!/usr/bin/env python3
"""Serve the Apassy base model over the Laya `/v1/systemone` protocol (goal B8).

The server is `laya.serve.create_app` with one router. The router:

1. loads the English Laya checkpoint at the pinned Hugging Face revision
   (`common.BASE_REVISION`) and checks the SHA-256 of its weights,
2. checks the SHA-256 of the fine-tuned head file against the manifest,
3. replaces the decision heads with the fine-tuned heads,
4. answers every request with the English checkpoint, and
5. reports `apassy-base-v1+<hash8>` in the `model` field of each answer.

Questions in the manifest list `serve.zero_shot_questions` get the answer of the
stock heads (same encoder pass). See docs/operations/base-model.md.

Environment: `LAYA_HOST` (default 127.0.0.1), `LAYA_PORT` (default 8770),
`LAYA_DEVICE`, `LAYA_API_KEY` (as in laya-serve).

Run inside the Laya virtual environment:
  .venv/bin/python tools/basemodel/serve.py --checkpoint <file> [--manifest <file>]
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import common  # noqa: E402


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


def build_router(checkpoint, manifest_path=None, device=None):
    import torch
    from laya.agent import Agent
    from laya.common import DecisionModel
    from laya.router import RouteDecision, Router

    manifest, _ = read_manifest(checkpoint, manifest_path)
    base = common.base_dir()
    digest = verify(checkpoint, manifest, base)
    version = "%s+%s" % (manifest.get("name", common.MODEL_NAME), digest[:8])
    zero_shot = set(manifest.get("serve", {}).get("zero_shot_questions", []))

    agent = Agent(base, device=device)
    tuned = agent.model
    stock = None
    if zero_shot:
        # A second head set with the stock weights. It shares the encoder module.
        stock = DecisionModel(tuned.encoder, agent.cfg.get("head_layers", 2),
                              len(agent.cfg.get("act_costs", {})) + 1)
        stock.load_state_dict(tuned.state_dict(), strict=True)
        stock.to(agent.device).eval()
    tensors, _meta = common.load_checkpoint(checkpoint)
    common.apply_heads(tuned, tensors)
    tuned.eval()

    class DualHeads(torch.nn.Module):
        """The tuned model, with the stock heads for some rows. One encoder pass."""

        def __init__(self):
            super().__init__()
            self.tuned = tuned
            self.stock = stock
            self.stock_rows = None

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
            top2 = p.topk(2, -1).values
            feats = torch.stack([top2[:, 0], top2[:, 0] - top2[:, 1], ent, k / 255.0], -1)
            pooled = h[:, 0].float()
            return logits, m.act_head(torch.cat([pooled, feats], -1))

        def forward(self, input_ids, attention_mask, marker_pos, marker_mask, qtype):
            rows = self.stock_rows
            if self.stock is None or rows is None or not any(rows) or len(rows) != input_ids.shape[0]:
                return self.tuned(input_ids, attention_mask, marker_pos, marker_mask, qtype)
            h = self.tuned.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
            lt, at = self.heads(self.tuned, h, attention_mask, marker_pos, marker_mask, qtype)
            ls, as_ = self.heads(self.stock, h, attention_mask, marker_pos, marker_mask, qtype)
            use = torch.tensor(rows, device=input_ids.device)[:, None]
            return torch.where(use, ls, lt), torch.where(use, as_, at)

    dual = DualHeads()
    agent.model = dual

    class BaseRouter(Router):
        """Every request goes to the fine-tuned English checkpoint."""

        def __init__(self):
            super().__init__(max_loaded=1, default="english")
            self.attach("english", agent)
            self.version = version
            self.zero_shot = zero_shot

        def _route(self, state, questions=None, model=None, task=None, lang=None, lang_guess=None):
            return RouteDecision(model="english", repo="%s@%s" % (common.BASE_REPO, common.BASE_REVISION),
                                 reason="apassy base model", detection=None, workflow=None)

        def predict(self, state, questions, model=None, **kwargs):
            # Rows follow the question order of one state (laya Agent._encode_state).
            dual.stock_rows = [qid in self.zero_shot for qid in questions] if self.zero_shot else None
            try:
                result = super().predict(state, questions, model=None, **kwargs)
            finally:
                dual.stock_rows = None
            result["model"] = self.version
            return result

    return BaseRouter(), version, sorted(zero_shot)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", default=os.environ.get("APASSY_BASE_MODEL", ""))
    ap.add_argument("--manifest", default="")
    args = ap.parse_args()
    if not args.checkpoint or not os.path.isfile(args.checkpoint):
        raise SystemExit("serve: no checkpoint. Use the stock laya-serve for zero-shot answers.")

    import uvicorn
    from laya.serve import _resolve_port, create_app

    os.environ.setdefault("LAYA_PORT", "8770")
    router, version, zero_shot = build_router(args.checkpoint, args.manifest or None,
                                              os.environ.get("LAYA_DEVICE") or None)
    host = os.environ.get("LAYA_HOST", "127.0.0.1")
    print("apassy base model %s on %s:%s (zero-shot questions: %s)" % (
        version, host, os.environ["LAYA_PORT"], ", ".join(zero_shot) or "none"), flush=True)
    uvicorn.run(create_app(router), host=host, port=_resolve_port(),
                log_level=os.environ.get("LAYA_LOG_LEVEL", "warning"))


if __name__ == "__main__":
    main()
