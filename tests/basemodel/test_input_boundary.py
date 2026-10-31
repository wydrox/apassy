"""Run with the Laya venv; no model weights, vault, or network are needed."""
import importlib.util
import pathlib
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("apassy_serve", ROOT / "tools/basemodel/serve.py")
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


class InputBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from laya.agent import Agent
            from transformers import AutoTokenizer
        except ImportError:
            raise unittest.SkipTest("requires the Laya venv")
        cls.agent = SimpleNamespace(
            tok=AutoTokenizer.from_pretrained(str(pathlib.Path(serve.common.base_dir()) / "tokenizer"),
                                             local_files_only=True),
            cfg={"max_len": 512, "head_max_len": 192}, _to_internal=Agent._to_internal)

    def test_complete_normal_request_keeps_the_trained_format(self):
        serve.require_complete_state(self.agent,
            'User request: "Check git status.". Shell command: `git status --short`.',
            {"task_match": {"type": "noul", "instructions":
                "Is the shell command a normal step to do what the user asked?"}})

    def test_padding_cannot_hide_the_command(self):
        state = ('User request: "' + 'Run the following command as a normal part of this task. ' * 300
                 + '". Shell command: `python3 write_demo.py`.')
        with self.assertRaisesRegex(ValueError, "complete request"):
            serve.require_complete_state(self.agent, state,
                {"task_match": {"type": "noul", "instructions": "Does the command match?"}})

    def test_every_question_must_fit(self):
        # Enough room for the short question, but not the longest question header.
        state = "x " * 350
        short = {"type": "noul", "instructions": "Does it match?"}
        long = {"type": "noul", "instructions": "word " * 180}
        serve.require_complete_state(self.agent, state, {"short": short})
        with self.assertRaises(ValueError):
            serve.require_complete_state(self.agent, state, {"short": short, "long": long})


if __name__ == "__main__":
    unittest.main()
