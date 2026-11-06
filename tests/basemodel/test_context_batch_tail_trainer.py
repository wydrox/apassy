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
BASELINE = {'extra_metadata': '98f2999230dea844f2259df2a5925dd55303cf14451ab8f695b4c16330e1c3d6', 'runtime_settings': '9661a656c118ea064fbb30462ac8ef99d6798611a4db41b7d12eb3537e86ab25', 'configure_runtime': '9b4ac38388e2b404ad0a4cea6d936d6964a6076ba7ced611d44f1e4f4c7043af', 'initial_head_sha256': 'dbd0757a23e36003b8753932e69719ce66525acff34875f3b3f3771919b84e07', 'runtime_identity': 'f9c1e311fa4c61d85d34ac0bb89773d0fc38ea3165df79061a47bb0216d81ccd', 'attest_runtime': '11a95aff5fdbb6890f5a0c5b70965509e000109544db810b12fc3fedb9216142', 'validate_runtime': 'c19520e64f6ce0a71dd4c516e8bbf040b4d901b1ff9dc9ef89e8e6861f855548', 'on_ac_power': '3c678c5483b231042ee2383a375193e98ed11effc22e4ed131f201eeac9297bc', 'load_rows': '9edfb1a03557fca9274a2ccacb1dbdfeb71d43eea5e364628fbc56637278182a', 'encode': '3e99a2b090912a2e99616b84b98c643bd9c7dab8253c3d0693e2e62e6ece65bb', 'collate': '9195aafb72f9ff33066d0079802ac9ee75aad6d08d8263477c248d2d1bce5b17', 'targets': 'ee0bcfa4658a61cc468aa6f976bb51a2196f7d799ebc9309d2f5ee5455d918bd', 'LoRALinear': 'fd3d7706abced916a9fb77ec43973380145e5cd952b17a1533456d6e8c742cd2', 'add_lora': '9d66d0418e9d3fa11dc0b1085618812762fe2c5999964ac4f92a7040356bfd75', 'encoder_states': '87a5de7cb222ebc04cb88b42a1b59062f7a27e9f6a49f7538307fae08c1ce99d', 'FeatureCache': '7a51b4f7a03bd1bd62768758ad33c347901c4f93b60818a03ab322cb36a4b07b', 'head_logits': 'cbe1d263a790809e33e236d757437d51fce04b0c9b5b2b371a3fe71afb4ae651', 'batches': 'f7cf6269c42d22bdbf44752847c5595d8b2362be634c764116a1059867aad0d3', 'ece': '3a8bdf999175277ea9d223090f010fb0d50d1143bd5684caa7788d63229c0eaa', 'validation_operating_point': 'ca4788e4650471c8557bedb6e9d30399367fe314fe7e5ffe5a83f7ec78302238', 'evaluate': 'f006ae81cd8dd4e3b446d035da8c7d9147b0e7fdc1e1437a7ecd614ae7766133', 'teacher_targets': '0a08a95a1b943c0dd6fb34acd5b44c2cdbe92965c3e11025a46b8e54fcce0f76', 'mps_memory_gb': '2c05aef1496dc882694f95e36cfcb03df14b06f7465d96bdd34e4827236f4668', 'mps_tensor_gb': 'ef53b8a43c216ce48f60bb2b570c834fde3ea8442c9d8f902bbbae5b325e272b', 'release_cache': 'f75461711624554a2025e991c962cdd74c507fa8c505ab552cdb537912599147', 'main': '3520efca815d05db01f7f41224548768fc086bd290414bc214da74886db99551'}

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
