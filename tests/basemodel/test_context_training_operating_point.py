"""Stdlib-only source-isolated checks; no trainer, NumPy or Torch imports."""
import ast
from contextlib import nullcontext
import json
import math
from pathlib import Path
import random
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


SOURCE = Path(__file__).resolve().parents[2] / "tools/basemodel/train.py"


def source_function(name, namespace):
    tree = ast.parse(SOURCE.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), "exec"), namespace)
    return namespace[name]


class OperatingPointTests(unittest.TestCase):
    def setUp(self):
        self.aggregate = source_function("validation_operating_point", {"math": math})

    def test_perfect_separation_and_closed_aggregate(self):
        result = self.aggregate([0.1, 0.2, 0.8, 1.0], [0, 0, 1, 1])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["safe_positive_count"], 2)
        self.assertEqual(result["safe_positive_recall"], 1)
        self.assertEqual(result["negative_boundary_ties"], {"positive": 0, "negative": 1})
        self.assertEqual(set(result), {"status", "coverage", "positive_count", "negative_count",
                                      "safe_positive_count", "safe_positive_recall",
                                      "negative_boundary_ties", "histograms"})
        self.assertEqual(result["coverage"]["valid_pairs"], 4)
        self.assertEqual(sum(result["histograms"]["counts"]["positive"]), 2)
        self.assertEqual(sum(result["histograms"]["counts"]["negative"]), 2)
        self.assertEqual(result["histograms"]["counts"]["positive"][-1], 1)
        json.dumps(result, allow_nan=False)

    def test_strict_boundary_ties_and_inverted_scores(self):
        result = self.aggregate([0.5, 0.5, 0.5, 0.4, 0.6], [0, 0, 1, 1, 1])
        self.assertEqual(result["safe_positive_count"], 1)
        self.assertAlmostEqual(result["safe_positive_recall"], 1 / 3)
        self.assertEqual(result["negative_boundary_ties"], {"positive": 1, "negative": 2})
        self.assertEqual(self.aggregate([1, 0], [0, 1])["safe_positive_count"], 0)

    def test_missing_class_including_empty_is_unavailable(self):
        for probabilities, labels in (([0.1, 0.9], [1, 1]), ([0.1, 0.9], [0, 0]), ([], [])):
            with self.subTest(labels=labels):
                result = self.aggregate(probabilities, labels)
                self.assertEqual(result["status"], "unavailable_class")
                self.assertIsNone(result["safe_positive_count"])
                self.assertIsNone(result["safe_positive_recall"])
                self.assertIsNone(result["negative_boundary_ties"])

    def test_malformed_nonfinite_and_misaligned_inputs_never_become_partial_estimates(self):
        cases = ((None, [0, 1]), ([0.1], [0, 1]), ([0.1, 0.9], [0]),
                 ([float("nan"), 0.9], [0, 1]), ([float("inf"), 0.9], [0, 1]),
                 ([-0.1, 0.9], [0, 1]), ([1.1, 0.9], [0, 1]),
                 ([True, 0.9], [0, 1]), (["0.1", 0.9], [0, 1]),
                 ([0.1, 0.9], [False, 1]), ([0.1, 0.9], [0, None]),
                 ([0.1, 0.9], [0, float("nan")]), ([0.1, 0.9], [0, 2]),
                 ([10 ** 400, 0.9], [0, 1]))
        for probabilities, labels in cases:
            with self.subTest(probabilities=probabilities, labels=labels):
                result = self.aggregate(probabilities, labels)
                self.assertEqual(result["status"], "incomplete")
                self.assertIsNone(result["safe_positive_recall"])
                self.assertIsNone(result["histograms"])
                json.dumps(result, allow_nan=False)
        result = self.aggregate([float("nan"), 0.9], [0, 1])
        self.assertEqual(result["coverage"]["nonfinite_probabilities"], 1)
        self.assertEqual(result["coverage"]["valid_pairs"], 1)

    def test_soft_targets_do_not_claim_empirical_binary_recall(self):
        result = self.aggregate([0.1, 0.8, 0.9], [0, 0.75, 1])
        self.assertEqual(result["status"], "unsupported_soft_targets")
        self.assertEqual(result["coverage"]["soft_targets"], 1)
        self.assertIsNone(result["safe_positive_recall"])
        self.assertIsNone(result["histograms"])

    def test_histograms_cover_exact_boundaries_and_every_input(self):
        probabilities = [n / 10 for n in range(11)] * 2
        result = self.aggregate(probabilities, [0] * 11 + [1] * 11)
        for counts in result["histograms"]["counts"].values():
            self.assertEqual(counts, [1] * 9 + [2])
        self.assertEqual(result["coverage"]["valid_pairs"], 22)

    def test_lower_mean_nll_can_have_worse_safe_recall(self):
        labels = [0, 0, 1, 1]
        better_recall = [0.4, 0.4, 0.5, 0.5]
        lower_nll = [0.01, 0.6, 0.59, 0.99]
        def nll(scores):
            return -sum(math.log(p if y else 1 - p) for p, y in zip(scores, labels)) / len(labels)
        self.assertLess(nll(lower_nll), nll(better_recall))
        self.assertEqual(self.aggregate(better_recall, labels)["safe_positive_recall"], 1)
        self.assertEqual(self.aggregate(lower_nll, labels)["safe_positive_recall"], 0.5)


class Vector:
    """Just the list arithmetic needed to execute the actual evaluate function."""
    def __init__(self, values):
        self.values = list(values)

    def binary(self, other, operation):
        values = other.values if isinstance(other, Vector) else [other] * len(self.values)
        return Vector(operation(a, b) for a, b in zip(self.values, values))

    def __getitem__(self, mask):
        return Vector(value for value, selected in zip(self.values, mask.values) if selected)

    def __eq__(self, other):
        return self.binary(other, lambda a, b: a == b)

    def __ge__(self, other):
        return self.binary(other, lambda a, b: a >= b)

    def __add__(self, other):
        return self.binary(other, lambda a, b: a + b)

    def __sub__(self, other):
        return self.binary(other, lambda a, b: a - b)

    def __rsub__(self, other):
        return Vector(other - value for value in self.values)

    def __mul__(self, other):
        return self.binary(other, lambda a, b: a * b)

    def __pow__(self, other):
        return Vector(value ** other for value in self.values)

    def __invert__(self):
        return Vector(not value for value in self.values)

    def any(self):
        return any(self.values)

    def sum(self):
        return sum(self.values)

    def mean(self):
        return sum(self.values) / len(self.values)

    def cpu(self):
        return self

    def tolist(self):
        return self.values[:]


class EvaluateIntegrationTests(unittest.TestCase):
    def evaluate_rows(self, owner_target=1):
        rows = [dict(p=0.2, y=0, q=0), dict(p=0.9, y=1, q=0),
                dict(p=0.3, y=0, q=1), dict(p=0.8, y=owner_target, q=1)]
        aggregate = Mock(wraps=source_function("validation_operating_point", {"math": math}))
        calls = []
        class Logits:
            def __truediv__(self, temperature):
                calls.append(("temperature", temperature))
                return self
        class Softmax:
            def __getitem__(self, key):
                return Vector(row["p"] for row in rows)
        numpy = SimpleNamespace(array=Vector,
                                mean=lambda values: values.mean() if isinstance(values, Vector) else sum(values) / len(values),
                                log=lambda values: Vector(math.log(value) for value in values.values))
        namespace = dict(np=numpy, torch=SimpleNamespace(no_grad=nullcontext, softmax=lambda *_: Softmax()),
                         random=random, QUESTIONS=["task_match", "owner_accepts_use"],
                         batches=lambda *_: [list(range(len(rows)))],
                         collate=lambda selected, _: {key: Vector(row[key] for row in selected) for key in ("y", "q")},
                         head_logits=Mock(return_value=Logits()), encoder_states=Mock(side_effect=AssertionError("extra encoder pass")),
                         ece=lambda *_: 0, validation_operating_point=aggregate)
        evaluate = source_function("evaluate", namespace)
        model, cache = Mock(), Mock()
        result = evaluate(model, rows, 0, "cpu", False, 2, 32, cache)
        aggregate.assert_called_once_with([0.3, 0.8], [0, owner_target])
        cache.batch.assert_called_once_with([0, 1, 2, 3], "cpu")
        namespace["head_logits"].assert_called_once()
        self.assertEqual(calls, [("temperature", 2)])
        self.assertNotIn("operating_point", result["task_match"])
        owner = result["owner_accepts_use"]
        self.assertEqual(owner["operating_point"]["evidence"], "trainer_validation_cache")
        self.assertEqual(owner["operating_point"]["interpretation"], "development_only")
        expected_keys = {"n", "accuracy", "nll", "brier", "ece", "mean_p_yes", "mean_p_no"}
        self.assertEqual(set(result["task_match"]), expected_keys)
        self.assertEqual(set(owner), expected_keys | {"operating_point"})
        self.assertEqual(result["all_nll"], (result["task_match"]["nll"] + owner["nll"]) / 2)
        return result

    def test_actual_evaluate_uses_existing_probabilities_only_for_owner_question(self):
        result = self.evaluate_rows()
        self.assertEqual(result["owner_accepts_use"]["operating_point"]["safe_positive_recall"], 1)

    def test_soft_target_keeps_generic_metrics_and_marks_only_diagnostic_unsupported(self):
        result = self.evaluate_rows(owner_target=0.75)
        owner = result["owner_accepts_use"]
        self.assertEqual(owner["operating_point"]["status"], "unsupported_soft_targets")
        self.assertIsNone(owner["operating_point"]["safe_positive_recall"])
        expected_nll = -(math.log(0.7 + 1e-6) + 0.75 * math.log(0.8 + 1e-6)
                         + 0.25 * math.log(0.2 + 1e-6)) / 2
        self.assertAlmostEqual(owner["nll"], expected_nll)


class CacheModeTests(unittest.TestCase):
    def test_actual_cache_build_sets_eval_before_encoder_extraction(self):
        tree = ast.parse(SOURCE.read_text())
        cache_class = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "FeatureCache")
        build = next(n for n in cache_class.body if isinstance(n, ast.FunctionDef) and n.name == "build")
        events = []
        class Model:
            training = True
            def eval(self):
                self.training = False
                events.append("eval")
        model = Model()
        class Features:
            def half(self):
                return self
            def cpu(self):
                return self
            def numpy(self):
                return self
            def __getitem__(self, key):
                return [[0]]
        class Memory:
            def __setitem__(self, key, value):
                events.append("write")
            def flush(self):
                events.append("flush")
        def encoder(*args):
            self.assertFalse(model.training)
            events.append("encoder")
            return Features()
        destination = SimpleNamespace(path="cache", index_path="index")
        output = nullcontext(SimpleNamespace(write=lambda _: None))
        namespace = dict(np=SimpleNamespace(lib=SimpleNamespace(format=SimpleNamespace(open_memmap=lambda *a, **k: Memory())), float16="fake"),
                         time=SimpleNamespace(time=lambda: 0), torch=SimpleNamespace(no_grad=nullcontext), random=random,
                         batches=lambda *_: [[0]], collate=lambda *_: {}, encoder_states=encoder,
                         release_cache=lambda: None, print=lambda *a, **k: None,
                         os=SimpleNamespace(replace=lambda *a: None, path=SimpleNamespace(basename=lambda p: p)),
                         open=lambda *a: output, json=json)
        exec(compile(ast.Module(body=[build], type_ignores=[]), str(SOURCE), "exec"), namespace)
        namespace["build"](destination, model, [{"ids": [1]}], 0, "cpu", False, 1, "fingerprint", 1)
        self.assertEqual(events, ["eval", "encoder", "write", "flush"])


if __name__ == "__main__":
    unittest.main()
