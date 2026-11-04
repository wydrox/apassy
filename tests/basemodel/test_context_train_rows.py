"""Stdlib-only adapter checks on serializer goldens and tiny synthetic G1 data."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/basemodel'))
import context_train_rows as A
import context_data as D
import context_v1 as C


class TrainRowsTests(unittest.TestCase):
    def setUp(self):
        self.c = C.load_contract()
        self.row = D.generate(7, 1)[0]

    def source(self, directory):
        D.main(['--out', str(directory), '--groups', '10'])
        return {p.name: p.read_bytes() for p in directory.iterdir()}

    def test_three_byte_goldens_and_exact_legacy_row(self):
        for name, label, answer in [('owner', 'allow_ok', 1.0),
                                    ('legacy', 'must_ask', 0.0),
                                    ('repeat', 'deterministic_ask', 0.0)]:
            fixture = json.loads((ROOT / 'tests/fixtures/secret-decision-context-v1/serializer' /
                                  (name + '.json')).read_bytes())
            row = copy.deepcopy(self.row)
            row.update(request={k: fixture['request'][k] for k in row['request']},
                       action=fixture['action'], secrets=fixture['secrets'], label=label)
            converted, counts = A.convert_rows([row], self.c)
            expected = dict(state=fixture['model_text'], question='owner_accepts_use',
                            instructions=self.c['question']['instructions'], answer=answer, teacher=False)
            self.assertEqual(converted, [expected])
            self.assertEqual(converted[0]['state'].encode('utf-8'), fixture['model_text'].encode('utf-8'))
            self.assertEqual(counts, dict(input=1, selected=1, local_rule=0, OverBudget=0))

    def test_control_calls_blind_and_preserves_input(self):
        row = D.generate(7, 2)[-1]
        before = copy.deepcopy(row)
        with patch.object(A, 'blind', wraps=C.blind) as blind:
            control, counts = A.convert_rows([row], self.c, facts_blind=True)
        blind.assert_called_once_with(row['secrets'], self.c)
        expected, _ = C.serialize(row['request'], row['action'], C.blind(row['secrets'], self.c), self.c)
        self.assertEqual(control[0]['state'], expected)
        self.assertNotEqual(control, A.convert_rows([row], self.c)[0])
        self.assertEqual(row, before)
        self.assertEqual(counts['selected'], 1)

    def test_exporter_writes_exact_golden_train_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / 'source', Path(tmp) / 'out'
            self.source(source)
            rows, expected = [], []
            for name, label, answer in [('owner', 'allow_ok', 1.0),
                                        ('legacy', 'must_ask', 0.0),
                                        ('repeat', 'deterministic_ask', 0.0)]:
                fixture = json.loads((ROOT / 'tests/fixtures/secret-decision-context-v1/serializer' /
                                      (name + '.json')).read_bytes())
                row = copy.deepcopy(self.row)
                row.update(id=row['id'] + ':' + name, label=label, secrets=fixture['secrets'],
                           request={k: fixture['request'][k] for k in row['request']})
                rows.append(row)
                expected.append(dict(state=fixture['model_text'], question='owner_accepts_use',
                                     instructions=self.c['question']['instructions'], answer=answer, teacher=False))
            payload = b''.join(C.canonical(r) for r in rows)
            (source / 'train.jsonl').write_bytes(payload)
            manifest = json.loads((source / 'data-manifest.json').read_bytes())
            manifest['files']['train.jsonl'] = dict(sha256=A.digest(payload), rows=3)
            (source / 'data-manifest.json').write_bytes(C.canonical(manifest))
            self.assertEqual(A.main(['--data', str(source), '--out', str(out)]), 0)
            self.assertEqual((out / 'train.jsonl').read_bytes(), b''.join(C.canonical(r) for r in expected))

    def test_write_error_removes_partial_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / 'source', Path(tmp) / 'out'
            self.source(source)
            original = Path.write_bytes

            def fail_val(path, raw):
                if path == out / 'val.jsonl':
                    raise OSError('synthetic write failure')
                return original(path, raw)

            with patch.object(Path, 'write_bytes', fail_val):
                with self.assertRaisesRegex(OSError, 'synthetic write failure'):
                    A.export_rows(source, out)
            self.assertFalse(out.exists())

    def test_empty_trainable_split_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / 'source', Path(tmp) / 'out'
            self.source(source)
            with patch.object(A, 'serialize', side_effect=C.Refusal('OverBudget')):
                with self.assertRaisesRegex(C.Unsupported, 'no trainable rows'):
                    A.export_rows(source, out)
            self.assertFalse(out.exists())

    def test_explicit_refusals_and_independent_arm_coverage(self):
        overflow, local = copy.deepcopy(self.row), copy.deepcopy(self.row)
        overflow['id'] += ':overflow'
        overflow['request']['purpose'] = 'x' * 1000
        local.update(id=local['id'] + ':local', local_rule='')
        converted, counts = A.convert_rows([self.row, overflow, local], self.c)
        self.assertEqual(len(converted), 1)
        self.assertEqual(counts, dict(input=3, selected=1, OverBudget=1, local_rule=1))
        # Pick an exact boundary where blinding changes the contractual bound.
        row = copy.deepcopy(self.row)
        row['secrets'] = [D.default_secret()]
        text, bound = C.serialize(row['request'], row['action'], row['secrets'], self.c)
        room = self.c['budget']['max_len'] - self.c['budget']['header_tokens']
        row['request']['purpose'] = 'x' * (room + 1 - bound - len(" Agent's stated purpose: "))
        self.assertEqual(A.convert_rows([row], self.c)[1]['OverBudget'], 1)
        self.assertEqual(A.convert_rows([row], self.c, facts_blind=True)[1]['selected'], 1)
        with patch.object(A, 'serialize', side_effect=C.Refusal('Unexpected')):
            with self.assertRaises(C.Refusal):
                A.convert_rows([self.row], self.c)

    def test_unknown_schema_labels_and_h1_rows(self):
        for changes in ({'label': 'unknown'}, {'family': 'H1:fake'}, {'extra': 'unknown'},
                        {'secrets': []}, {'action': 'unknown'}):
            row = copy.deepcopy(self.row)
            row.update(changes)
            with self.assertRaises(C.Unsupported):
                A.convert_rows([row], self.c)

    def test_h1_and_heldout_paths_refused_before_io(self):
        for source in ('/synthetic/H1-fake', '/synthetic/held-out-fake', '/synthetic/heldout-fake'):
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('IO')), \
                 patch.object(Path, 'read_text', side_effect=AssertionError('IO')):
                with self.assertRaisesRegex(C.Unsupported, 'held-out/H1'):
                    A.export_rows(source, '/synthetic/new')
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('IO')):
            with self.assertRaises(C.Unsupported):
                A.export_rows('/synthetic/g1', '/synthetic/new', contract_path='/synthetic/held_out-contract')

    def test_export_provenance_hashes_and_no_source_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / 'source'
            original = self.source(source)
            for blind in (False, True):
                out = base / ('control' if blind else 'context')
                report = A.export_rows(source, out, facts_blind=blind)
                self.assertEqual(report['arm'], out.name)
                self.assertEqual(report['contract_sha256'], C.contract_hash(self.c))
                self.assertEqual(report['question'], self.c['question'])
                self.assertEqual(report['source_sha256'], {k: A.digest(v) for k, v in original.items()})
                for name in ('train.jsonl', 'val.jsonl'):
                    self.assertEqual(report['output_sha256'][name], C.sha256(out / name))
                    rows = D.read_rows(source / name, self.c)
                    converted, counts = A.convert_rows(rows, self.c, facts_blind=blind)
                    self.assertEqual((out / name).read_bytes(), b''.join(C.canonical(r) for r in converted))
                    self.assertEqual(report['counts'][name], counts)
                    print(out.name, name, counts)
            self.assertEqual(original, {p.name: p.read_bytes() for p in source.iterdir()})

    def test_bad_hash_existing_output_overlap_and_schema_do_not_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, out = Path(tmp) / 'source', Path(tmp) / 'out'
            original = self.source(source)
            out.mkdir()
            sentinel = out / 'sentinel'
            sentinel.write_bytes(b'preserved')
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('source opened')):
                with self.assertRaisesRegex(C.Unsupported, 'output exists'):
                    A.export_rows(source, out)
            self.assertEqual(sentinel.read_bytes(), b'preserved')
            sentinel.unlink()
            out.rmdir()
            (source / 'train.jsonl').write_bytes(original['train.jsonl'] + b'\n')
            with self.assertRaisesRegex(C.Unsupported, 'source hash'):
                A.export_rows(source, out)
            self.assertFalse(out.exists())
            for mode in ('overlap', 'schema', 'H1'):
                train = original['train.jsonl']
                if mode != 'overlap':
                    rows = [json.loads(line) for line in train.splitlines()]
                    rows[0].update({'extra': True} if mode == 'schema' else {'family': 'H1:fake'})
                    train = b''.join(C.canonical(r) for r in rows)
                (source / 'train.jsonl').write_bytes(train)
                val = train if mode == 'overlap' else original['val.jsonl']
                (source / 'val.jsonl').write_bytes(val)
                manifest = json.loads(original['data-manifest.json'])
                for name in ('train.jsonl', 'val.jsonl'):
                    raw = (source / name).read_bytes()
                    manifest['files'][name] = dict(sha256=A.digest(raw), rows=len(raw.splitlines()))
                (source / 'data-manifest.json').write_bytes(C.canonical(manifest))
                with self.assertRaises(C.Unsupported):
                    A.export_rows(source, out)
                self.assertFalse(out.exists())

    def test_import_without_tensor_libraries_or_network(self):
        code = '''
import sys

def audit(event, args):
    if event.startswith('socket.'):
        raise AssertionError('network access')
    if event == 'import' and args[0].split('.')[0] in ('torch', 'numpy', 'laya'):
        raise AssertionError('tensor library import')
sys.addaudithook(audit)
import context_train_rows
assert not any(m in sys.modules for m in ('torch', 'numpy', 'laya'))
'''
        proc = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True,
                              env={**os.environ, 'PYTHONPATH': str(ROOT / 'tools/basemodel')})
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())


if __name__ == '__main__':
    unittest.main()
