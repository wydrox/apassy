"""Stdlib wiring checks; real tensor semantics belong to the CPU preflight."""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
BASELINE = {'extra_metadata': '08f28b7ff217792f7a15fffba9e13a89c6b923666b9a0d4b0301db1f938fbb4a', 'runtime_settings': '3a885b7455609934fdb093701ea51b6fa4408606279facf97e64f0489f984c35', 'configure_runtime': 'bb4880885d66ba297049afc661b352770bee27467cd9d6994e30860ab3d38e58', 'initial_head_sha256': '0aaf48ce4edfa9e5d0e0ad1968bbe8be43d92dae8b5908c2df93d2708991d269', 'runtime_identity': '96ac86bc5d3eda3a778ad44a65ce07358eaddfdfc6637e4d97a84313b4a619f0', 'attest_runtime': 'be500ba57f789b79d15b17d2846553ef874a7e6b394815ff5e134d4de3a8d896', 'validate_runtime': '4cb9c03a86dc4ac1f1d013cd8947ca02e346e4fd675e10e6d5a0150055d47858', 'on_ac_power': '4bcb0bd5148e197bcccf966b9364f3182f71420bda635668b0d174adb7a2f786', 'load_rows': '7660a1e8fa017908e70a17c869c72ee8b65f9ed8abeb832e1eafedd9add89432', 'encode': '805c5195f99cd1a01e99119d5f5252fa0213dd551874fd1d40fbc008abb0ab2e', 'collate': '82460fcf164e44f6b3b8655999b12809eec389717acbb4be4062fd3fab41a41b', 'targets': 'eb528680f4624049a409759acc6ccb28f20dd678560671f2434f4dec3ca126de', 'LoRALinear': '4cb88efe17555e1c370edb0e01c9423c888801057d0ff9b9470793e7a25698f1', 'add_lora': '95e3f480d447c349e61d362751a5d58994d764e5a00c06ce8f17947fa641e2b1', 'encoder_states': 'd3b90e88ae6fb0a619732fde9350a94ea4aa5127ee30158df9e571def5d1bec4', 'FeatureCache': '8d0f31d0ceffcdef8646bac7e3911f7c42564fe05d945388317a0697d064e53d', 'head_logits': 'f28887516bd58f3789afa826254234633afd45dffc0f45a0f9b124053f431f8c', 'batches': 'e9d1a9705203bce60f7cc9d30785d16099a31e5354a4b1e0cc996c97f5f91137', 'ece': 'c6ae2c58713eb32f9ee44fe4970cf553d269d0a0d460f636bea83781f9a83afb', 'validation_operating_point': '64d284db81dfe445dd7ae4d3629bd11639b6bf718edc698654d6473a54a697a1', 'evaluate': '339a99304ff1de56385a77f71178f017546fdc275a34dde964782e58a157b6a4', 'teacher_targets': 'fef860aade95983e4f57c3f9f1c7b709e62ff33ec5dcb9c5bd63f9ed36da5577', 'mps_memory_gb': '0bc81b4c6b1f70fff8d518a31adbd53029b6e6a9b1bfc905a30cae2871861cb6', 'mps_tensor_gb': '70faa3ab2d0d59778576ed6d79e56e9f5fc398ac297c0878e2d2fa095d8dc44f', 'release_cache': 'e9d55c32cdb9fff2345b1294405b9ad12ff6cfe56091cbb7905f84d8737ad16b', 'main': 'a983169811fb529cfc8ad72ded0a30171c6b008461e69f14c5c00c4e56c6e255'}

def tree():
    return ast.parse((ROOT / 'tools/basemodel/train.py').read_text())

def digest(node):
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()

class RemoveObjective(ast.NodeTransformer):
    def visit_If(self, node):
        if ast.unparse(node.test) == 'args.objective is not None':
            return None
        return self.generic_visit(node)
    def visit_Expr(self, node):
        if isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == 'ap.add_argument' and node.value.args[0].value == '--objective':
            return None
        return self.generic_visit(node)

def isolated(names):
    nodes = [n for n in tree().body if isinstance(n, ast.FunctionDef) and n.name in names or
             isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ('QUESTIONS', 'RESERVED_METADATA') for t in n.targets)]
    ns = dict(argparse=argparse, json=json, os=os, common=types.SimpleNamespace(MODEL_NAME='fake'), random=Mock(), torch=Mock())
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'isolated trainer', 'exec'), ns)
    return ns

class BatchTailWiringTests(unittest.TestCase):
    def test_legacy_ast_is_identical_to_66082(self):
        for n in tree().body:
            if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in BASELINE:
                with self.subTest(name=n.name):
                    node = RemoveObjective().visit(copy.deepcopy(n)) if n.name == 'main' else n
                    self.assertEqual(digest(node), BASELINE[n.name])

    def test_items_require_hard_owner_non_teacher_and_both_classes(self):
        check = isolated({'objective_items_ok'})['objective_items_ok']
        good = [dict(y=0., teacher=False, q=6), dict(y=1., teacher=False, q=6)]
        saved = copy.deepcopy(good)
        check(good)
        self.assertEqual(good, saved)
        for bad in (None, {}, [], good[:1], [good[1]], [dict(good[0], y=.5), good[1]],
                    [dict(good[0], y=float('nan')), good[1]], [dict(good[0], y=True), good[1]],
                    [dict(good[0], teacher=0), good[1]], [dict(good[0], q=0), good[1]],
                    [dict(good[0], q=True), good[1]], [{}, good[1]], [None, good[1]]):
            with self.subTest(case=repr(bad)), self.assertRaises(ValueError):
                check(bad)

    def test_reserved_and_unsupported_options_precede_seeding_and_agent(self):
        ns = isolated({'main', 'extra_metadata'})
        with patch.dict('sys.modules', {'laya.agent': None}):
            for option in (['--init', 'unused'], ['--lora-layers', '1'],
                           ['--init', 'unused', '--runtime-profile', 'cuda-deterministic-v1'],
                           ['--lora-layers', '1', '--runtime-profile', 'cuda-deterministic-v1']):
                with self.assertRaisesRegex(ValueError, 'objective'):
                    ns['main'](['--data', 'unused', '--out', 'unused', '--objective', 'bce-plus-batch-tail-v1'] + option)
            with self.assertRaisesRegex(ValueError, 'reserved'):
                ns['extra_metadata']('{"training_objective":"forged"}')
        ns['torch'].manual_seed.assert_not_called()
        ns['random'].seed.assert_not_called()

    def test_scale_accounting_and_opt_in_wiring(self):
        main = next(n for n in tree().body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        text = ast.unparse(main)
        for expected in (
            'loss = F.cross_entropy(logits / temperature, targets(b["y"]).to(device))',
            'tail, kind = batch_tail_term(logits, b["y"].to(device), temperature)',
            'train_ce += float(loss.detach()) * len(idx)',
            'train_tail += float(tail.detach()) * len(idx)',
            'objective_batches[kind] += 1', 'loss = loss + tail',
            'objective_items_ok(train_items)', 'objective_items_ok(val_items)'):
            self.assertIn(ast.unparse(ast.parse(expected)), text)
        self.assertLess(text.index('objective_items_ok(val_items)'), text.index('FeatureCache('))
        guards = [n for n in ast.walk(main) if isinstance(n, ast.If) and ast.unparse(n.test) == 'args.objective is not None']
        joined = '\n'.join(ast.unparse(n) for n in guards)
        for field in ('training_objective', 'ce_plus_tail', 'train_ce', 'train_tail', 'mixed_batches', 'positive_only_batches', 'negative_only_batches'):
            self.assertIn(field, joined)
        history = next(n for n in guards if 'history[-1]' in ast.unparse(n))
        self.assertIn('train_ce / max(1, count)', ast.unparse(history))
        self.assertIn('train_tail / max(1, count)', ast.unparse(history))
        tail = next(n for n in tree().body if isinstance(n, ast.FunctionDef) and n.name == 'batch_tail_term')
        for n in ast.walk(tail):
            if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id == 'logits':
                self.assertIsInstance(n.slice, ast.Tuple)  # basic column slicing only
        self.assertIn('torch.amax(z.masked_fill(positive, -math.inf))', ast.unparse(tail))

if __name__ == '__main__':
    unittest.main()
