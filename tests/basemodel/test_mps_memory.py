"""Run with the Laya venv; no model weights, vault, or network are needed."""
import importlib.util
import pathlib
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("apassy_serve", ROOT / "tools/basemodel/serve.py")
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)

try:
    import torch
except ImportError:
    torch = None


def tiny_model(device):
    tuned = torch.nn.Module()
    tuned.encoder = torch.nn.Sequential(torch.nn.Embedding(8, 4), torch.nn.LayerNorm(4))
    tuned.scorer = torch.nn.Linear(4, 1)
    model = torch.nn.Module()
    model.tuned = tuned
    return model.to(device)


@unittest.skipIf(torch is None, "requires the Laya venv")
class Fp16EncoderOnMps(unittest.TestCase):
    def test_cpu_model_is_unchanged(self):
        model = tiny_model("cpu")
        agent = SimpleNamespace(device=torch.device("cpu"), mps_amp_min_rows=5)
        self.assertFalse(serve.fp16_encoder_on_mps(agent, model))
        self.assertEqual(agent.mps_amp_min_rows, 5)
        self.assertTrue(all(p.dtype == torch.float32 for p in model.parameters()))

    @unittest.skipUnless(torch is not None and torch.backends.mps.is_available(), "requires MPS")
    def test_mps_encoder_is_fp16_and_heads_stay_fp32(self):
        model = tiny_model("mps")
        agent = SimpleNamespace(device=torch.device("mps"), mps_amp_min_rows=5)
        self.assertTrue(serve.fp16_encoder_on_mps(agent, model))
        self.assertEqual(agent.mps_amp_min_rows, 1)
        for p in model.tuned.encoder.parameters():
            self.assertEqual((p.dtype, p.device.type), (torch.float16, "mps"))
        for p in model.tuned.scorer.parameters():
            self.assertEqual((p.dtype, p.device.type), (torch.float32, "mps"))


if __name__ == "__main__":
    unittest.main()
