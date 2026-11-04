"""No torch, numpy, server or network: the generators of tools/basemodel/bench.py (K1)."""
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/basemodel"))
_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import bench  # noqa: E402
import heads_cache  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

CASES = ROOT / "tests/fixtures/bouncer/cases.tsv"
MANIFEST = ROOT / "tools/basemodel/manifest.json"


class QuestionTexts(unittest.TestCase):
    def test_the_question_texts_are_the_ones_of_the_bouncer(self):
        source = (ROOT / "src/broker/bouncer.rs").read_text(encoding="utf-8")
        for name, text in bench.FACTS + [bench.RULE_FACT]:
            self.assertIn('"%s"' % name, source)
            self.assertIn('"%s"' % text, source, name)

    def test_the_finetune_constants_are_the_ones_of_the_broker(self):
        source = (ROOT / "src/broker/finetune.rs").read_text(encoding="utf-8")
        for name, value in (("VAL_PERCENT", bench.VAL_PERCENT), ("MAX_COPIES", bench.MAX_COPIES),
                            ("MIN_DENIAL_WEIGHT", bench.MIN_DENIAL_WEIGHT),
                            ("MAX_DENIAL_WEIGHT", bench.MAX_DENIAL_WEIGHT)):
            self.assertRegex(source, r"const %s: \w+ = %d;" % (name, value))

    def test_fnv1a_is_the_64_bit_reference(self):
        self.assertEqual(bench.fnv1a(""), 0xCBF29CE484222325)
        self.assertEqual(bench.fnv1a("a"), 0xAF63DC4C8601EC8C)


class TrainingSet(unittest.TestCase):
    def setUp(self):
        self.cases = bench.read_cases(str(CASES))

    def test_the_synthetic_log_opens_the_training_gate(self):
        train, val, stats = bench.make_training_set(self.cases)
        self.assertEqual(stats["owner_decisions"], 300)
        self.assertGreaterEqual(stats["owner_denials"], 30)
        self.assertEqual((stats["train"], stats["val"]), (len(train), len(val)))
        self.assertTrue(2 <= stats["denial_weight"] <= 10)

    def test_a_command_is_in_one_part_only(self):
        train, val, _stats = bench.make_training_set(self.cases)
        command = re.compile(r"Shell command: `(.*?)`\.")
        in_train = {command.search(r["state"]).group(1) for r in train}
        in_val = {command.search(r["state"]).group(1) for r in val}
        self.assertFalse(in_train & in_val)

    def test_the_rows_have_the_trainer_format_and_no_path(self):
        train, val, _stats = bench.make_training_set(self.cases)
        for row in train + val:
            self.assertEqual(set(row), {"state", "question", "instructions", "answer", "teacher", "kind"})
            self.assertIn(row["answer"], (0, 1))
            self.assertNotRegex(row["state"], r"/Users/|/home/|\.db\b")
            if row["teacher"]:
                self.assertEqual(row["kind"], "keep")

    def test_the_set_is_the_same_every_time(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            bench.write_training_set(a, self.cases)
            bench.write_training_set(b, self.cases)
            for name in ("train.jsonl", "val.jsonl", "stats.json"):
                self.assertEqual(pathlib.Path(a, name).read_bytes(), pathlib.Path(b, name).read_bytes())
                self.assertEqual(os.stat(os.path.join(a, name)).st_mode & 0o777, 0o600)

    def test_requests_have_five_or_six_questions(self):
        bodies = bench.make_requests(self.cases, 50)
        self.assertEqual(len(bodies), 50)
        self.assertEqual(sorted({len(b["questions"]) for b in bodies}), [5, 6])
        for body in bodies:
            self.assertEqual(set(body), {"state", "questions"})
            self.assertLess(len(body["state"]), 2000)


class HeadSets(unittest.TestCase):
    def test_synthetic_head_sets_pass_the_upload_checks_of_the_server(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "base.safetensors")
            bench.write_tiny_checkpoint(base)
            header, _start, _size = bench.read_safetensors(base)
            shapes = {k: v["shape"] for k, v in header.items() if k != "__metadata__"}
            out = os.path.join(tmp, "heads")
            # The pure-Python path, as in CI without numpy.
            with mock.patch.dict(sys.modules, {"numpy": None}):
                made = bench.make_head_sets(base, str(MANIFEST), out, 3, 5)
            self.assertEqual(len({m["heads"] for m in made}), 3)
            for entry in made:
                sha = entry["heads"]
                path = os.path.join(out, sha + ".safetensors")
                self.assertEqual(bench.common.sha256_file(path), sha)
                heads_cache.check_head_file(path, shapes)
                stored = json.load(open(os.path.join(out, sha + ".json"), encoding="utf-8"))
                heads_cache.check_manifest(stored, sha, manifest["base"])
                self.assertEqual(stored["checkpoint"]["size_bytes"], os.path.getsize(path))
                self.assertEqual(entry["model"], heads_cache.model_name(stored["name"], sha))
            self.assertEqual(bench.head_sets(out), made)

    def test_the_same_seed_gives_the_same_head_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "base.safetensors")
            bench.write_tiny_checkpoint(base)
            with mock.patch.dict(sys.modules, {"numpy": None}):
                a = bench.make_head_sets(base, str(MANIFEST), os.path.join(tmp, "a"), 1, 9)
                b = bench.make_head_sets(base, str(MANIFEST), os.path.join(tmp, "b"), 1, 9)
                c = bench.make_head_sets(base, str(MANIFEST), os.path.join(tmp, "c"), 1, 10)
            self.assertEqual(a, b)
            self.assertNotEqual(a[0]["heads"], c[0]["heads"])


class Equality(unittest.TestCase):
    @staticmethod
    def answers(rows):
        return {"rows": [{"case": i, "status": 200, "answers": a} for i, a in enumerate(rows)]}

    def test_small_differences_are_equal(self):
        a = self.answers([{"task_match": 0.9, "destroy": 0.1}, {"task_match": 0.2}])
        b = self.answers([{"task_match": 0.91, "destroy": 0.1}, {"task_match": 0.21}])
        result = bench.compare_answers(a, b, 0.02)
        self.assertTrue(result["equal"], result)

    def test_a_large_difference_or_another_outcome_is_not_equal(self):
        a = self.answers([{"task_match": 0.76}])
        b = self.answers([{"task_match": 0.74}])
        result = bench.compare_answers(a, b, 0.02)
        self.assertEqual(result["outcome_differs"], [0])
        self.assertFalse(result["equal"])
        far = bench.compare_answers(self.answers([{"leak": 0.1}]), self.answers([{"leak": 0.2}]), 0.02)
        self.assertFalse(far["equal"])

    def test_a_missing_answer_is_not_equal(self):
        a = self.answers([{"task_match": 0.9}])
        b = {"rows": [{"case": 0, "status": 409}]}
        self.assertFalse(bench.compare_answers(a, b, 0.02)["equal"])

    def test_the_outcome_follows_the_model_facts_of_decide(self):
        self.assertEqual(bench.outcome({"task_match": 0.8}), "run")
        self.assertEqual(bench.outcome({"task_match": 0.7}), "ask")
        self.assertEqual(bench.outcome({"task_match": 0.95, "destroy": 0.92}), "ask")
        self.assertEqual(bench.outcome({"task_match": 0.95, "rule_break": 0.3}), "ask")
        self.assertEqual(bench.outcome({"task_match": 0.95, "rule_break": 0.1}), "run")


class DryRun(unittest.TestCase):
    def test_the_dry_run_needs_no_server(self):
        with mock.patch.dict(sys.modules, {"numpy": None}), mock.patch("sys.stdout"):
            self.assertEqual(bench.main(["--dry-run"]), 0)

    def test_percentiles_are_nearest_rank(self):
        values = [float(i) for i in range(1, 21)]
        self.assertEqual(bench.percentile(values, 50), 10.0)
        self.assertEqual(bench.percentile(values, 95), 19.0)
        self.assertIsNone(bench.percentile([], 95))


if __name__ == "__main__":
    unittest.main()
