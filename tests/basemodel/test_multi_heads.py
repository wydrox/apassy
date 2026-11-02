"""`serve.make_multi_heads` with torch on the CPU and a tiny encoder; no weights or network.

Needs torch and laya (the Laya venv has both); skips without them.
"""
import importlib.util
import pathlib
import sys
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/basemodel"))

try:
    import torch
    from laya.agent import Agent
    from laya.common import DecisionModel
except ImportError:
    torch = None


def load_serve():
    _write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location("apassy_serve", ROOT / "tools/basemodel/serve.py")
        serve = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(serve)
    finally:
        sys.dont_write_bytecode = _write_bytecode
    return serve


if torch is not None:
    class TinyEncoder(torch.nn.Module):
        """What DecisionModel needs of an encoder: `config.hidden_size` and `last_hidden_state`."""

        def __init__(self, hidden=64, vocab=40):
            super().__init__()
            self.config = types.SimpleNamespace(hidden_size=hidden)
            self.emb = torch.nn.Embedding(vocab, hidden)
            self.mix = torch.nn.Linear(hidden, hidden)

        def forward(self, input_ids, attention_mask):
            h = torch.tanh(self.mix(self.emb(input_ids))) * attention_mask[:, :, None]
            return types.SimpleNamespace(last_hidden_state=h)


class FakeAgent:
    """The parts of laya's Agent that `serve.shadow_answers` uses, with laya's own code."""

    _to_internal = staticmethod(Agent._to_internal) if torch is not None else None
    _decode_answers = Agent._decode_answers if torch is not None else None

    def __init__(self):
        self.temperature = [1.0, 1.3, 0.8]
        self.temperature_by_options = {}
        self.lang_temperatures = {}


@unittest.skipIf(torch is None, "requires torch and laya")
class MultiHeads(unittest.TestCase):
    QUESTIONS = {"task_match": {"type": "noul", "instructions": "a?"},
                 "leak": {"type": "noul", "instructions": "b?"},
                 "writes": {"type": "noul", "instructions": "c?"}}

    @classmethod
    def setUpClass(cls):
        cls.serve = load_serve()

    def setUp(self):
        torch.manual_seed(7)
        self.encoder = TinyEncoder()
        self.tuned = DecisionModel(self.encoder, 2, 2).eval()
        self.stock = DecisionModel(self.encoder, 2, 2).eval()
        self.uploaded = DecisionModel(self.encoder, 2, 2).eval()
        n, length = 3, 12
        self.input_ids = torch.randint(1, 40, (n, length))
        self.attention_mask = torch.ones(n, length, dtype=torch.long)
        self.attention_mask[1, 9:] = 0
        self.attention_mask[2, 7:] = 0
        self.marker_pos = torch.tensor([[2, 3], [4, 5], [1, 6]])
        self.marker_mask = torch.ones(n, 2, dtype=torch.bool)
        self.qtype = torch.zeros(n, dtype=torch.long)
        self.items = [{"markers": [0, 1]} for _ in range(n)]

    def inputs(self):
        return (self.input_ids, self.attention_mask, self.marker_pos, self.marker_mask, self.qtype)

    def selection(self, active, shadow=None, active_zero_shot=(), shadow_zero_shot=()):
        """A HeadSelection as `BaseRouter._infer` makes it; `active=None` is the default set."""
        heads_cache = self.serve.heads_cache
        default = heads_cache.HeadSet("d" * 64, "apassy-base-v1+dddddddd", self.tuned, active_zero_shot, 1,
                                      default=True)
        active_set = default if active is None else heads_cache.HeadSet(
            "a" * 64, "x+aaaaaaaa", active, active_zero_shot, 1)
        shadow_set = None if shadow is None else heads_cache.HeadSet(
            "s" * 64, "y+ssssssss", shadow, shadow_zero_shot, 1)
        return self.serve.HeadSelection(active_set, shadow_set, self.QUESTIONS)

    def run_model(self, model, request):
        model.request = request
        try:
            with torch.no_grad():
                return model(*self.inputs())
        finally:
            model.request = None

    def assert_same(self, got, want):
        for g, w in zip(got, want):
            self.assertTrue(torch.allclose(g, w, atol=1e-5), (g, w))

    def decode(self, logits, act):
        """laya's decoding of the active answers (`Agent._forward` then `_decode_answers`)."""
        ids = list(self.QUESTIONS)
        agent = FakeAgent()
        internal = {qid: agent._to_internal(self.QUESTIONS[qid]) for qid in ids}
        return agent._decode_answers(logits.float().cpu().numpy(), torch.softmax(act.float(), -1).cpu().numpy(),
                                     self.items, ids, internal, 0)

    def test_the_default_path_is_the_old_tuned_path(self):
        model = self.serve.make_multi_heads(self.tuned, self.stock)
        with torch.no_grad():
            want = self.tuned(*self.inputs())
        self.assert_same(self.run_model(model, None), want)
        # The default head set without a shadow or stock rows calls `tuned` itself.
        self.assert_same(self.run_model(model, self.selection(None)), want)
        # `heads` is DecisionModel.forward after the encoder.
        with torch.no_grad():
            h = self.encoder(input_ids=self.input_ids, attention_mask=self.attention_mask).last_hidden_state
            got = model.heads(self.tuned, h, self.attention_mask, self.marker_pos, self.marker_mask, self.qtype)
        self.assert_same(got, want)

    def test_stock_rows_take_the_stock_heads(self):
        model = self.serve.make_multi_heads(self.tuned, self.stock)
        logits, act = self.run_model(model, self.selection(None, active_zero_shot={"leak"}))
        with torch.no_grad():
            tl, ta = self.tuned(*self.inputs())
            sl, sa = self.stock(*self.inputs())
        for row, (want_l, want_a) in enumerate([(tl, ta), (sl, sa), (tl, ta)]):
            self.assert_same((logits[row], act[row]), (want_l[row], want_a[row]))

    def test_a_shadow_failure_in_heads_leaves_the_active_answer(self):
        model = self.serve.make_multi_heads(self.tuned, self.stock)
        # Another hidden size: `heads` fails on the shared encoder states.
        broken = DecisionModel(TinyEncoder(hidden=32), 2, 2).eval()
        for active in (None, self.uploaded):
            for zero_shot in ((), {"leak"}):
                with self.subTest(active="default" if active is None else "uploaded", zero_shot=zero_shot):
                    want = self.run_model(model, self.selection(active, None, active_zero_shot=zero_shot))
                    request = self.selection(active, broken, active_zero_shot=zero_shot)
                    self.assert_same(self.run_model(model, request), want)
                    self.assertIsNone(request.shadow_out)
                    self.assertIsInstance(request.shadow_error, RuntimeError)
                    with self.assertRaises(RuntimeError):
                        self.serve.shadow_answers(FakeAgent(), request, self.QUESTIONS)
        with torch.no_grad():
            want = self.tuned(*self.inputs())
        self.assert_same(self.run_model(model, self.selection(None, broken)), want)

    def test_shadow_answers_equal_the_active_decoding_for_the_same_module(self):
        model = self.serve.make_multi_heads(self.tuned, self.stock)
        for active, zero_shot in [(self.uploaded, ()), (self.uploaded, {"leak"}), (None, {"writes"})]:
            with self.subTest(active="default" if active is None else "uploaded", zero_shot=zero_shot):
                shadow = self.tuned if active is None else active
                request = self.selection(active, shadow, active_zero_shot=zero_shot, shadow_zero_shot=zero_shot)
                logits, act = self.run_model(model, request)
                self.assertIsNone(request.shadow_error)
                self.assertEqual(self.serve.shadow_answers(FakeAgent(), request, self.QUESTIONS),
                                 self.decode(logits, act))
                # And the active answer is what the module answers alone.
                alone = self.run_model(model, self.selection(active, None, active_zero_shot=zero_shot))
                self.assert_same((logits, act), alone)

    def test_on_device_keeps_a_set_on_its_device(self):
        moved = []

        class Probe(torch.nn.Module):
            def __init__(self):
                super().__init__()
                self.scorer = torch.nn.Sequential(torch.nn.Linear(1, 1))

            def to(self, device):
                moved.append(device)
                return self

        probe = Probe()
        self.assertIs(self.serve.on_device(probe, torch.device("cpu")), probe)
        self.assertEqual(moved, [])
        self.assertIsNone(self.serve.on_device(None, torch.device("cpu")))


if __name__ == "__main__":
    unittest.main()
