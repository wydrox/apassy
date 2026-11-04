"""Execute the workflow eligibility arithmetic with synthetic reports; stdlib only."""
import ast
import math
from pathlib import Path
import sys
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/basemodel'))
import context_train as T

WORKFLOW = ROOT / '.github/workflows/bouncer-context-experiment.yml'
INCLUDES = 'cache_lookup_collate_forward_loss_backward_clip_optimizer; validation=loss; scoring=softmax'


def blocks(start, end):
    source = WORKFLOW.read_text()
    found = []
    offset = 0
    while (offset := source.find(start, offset)) >= 0:
        stop = source.index(end, offset)
        found.append(textwrap.dedent(source[offset:stop]))
        offset = stop
    return found


def report_fixture(encoder=5000., training=1024., inference=100.):
    def record(value, batch, samples=3):
        return dict(batch_size=batch, samples=samples, p50_seconds=value / 2,
                    p95_seconds=value)
    raw = training / 64
    cached = dict(method='batch8x4_max_batch32_spot_v1', projection_batch_size=32,
                  sequence_length=512, unit='seconds_per_batch', warmups=2,
                  encoder_in_measured_step=False, threads=2, seconds=100.,
                  provenance='frozen_fp16_disk_cache_fp32_head_logits_adamw', includes=INCLUDES,
                  training=record(raw, 8), validation=record(raw, 8),
                  scoring=dict(record(inference / 2, 1), p95_seconds_per_row=inference / 2),
                  spot32={name: dict(batch_size=32, samples=1, warmups=0,
                                    single_sample_seconds=raw * 2)
                          for name in ('training', 'validation')},
                  scaled_batch8_to32=dict(factor=4, training=raw * 4, validation=raw * 4),
                  projection_step_seconds=dict(source='max(scaled_batch8_to32, spot32)',
                                               training=raw * 4, validation=raw * 4))
    timings = {'1': record(encoder - 1, 1, 32), '8': record(1., 8, 4),
               'cache_write': dict(record(1., 8, 4), unit='seconds_per_row',
                                   provenance='fp16_feature_cache_serialization_disk_write'),
               'cached_head': cached}
    counts = dict(train_rows=32, validation_rows=32, encoder_inputs_800_equivalent=1.,
                  training_batches_800_equivalent=1., validation_batches_800_equivalent=1.,
                  scoring_rows_800_equivalent=1., candidate_groups_min=400, candidate_groups_max=800,
                  provenance='G1_exact_serialized_context_control_union_prefixes_400_to_800')
    return dict(encoder_timings=timings, projection_counts=counts,
                projected_full_seconds=encoder + training + inference,
                projection_components=dict(encoder_cache_seconds=encoder,
                                           training_cache_io_seconds=training,
                                           inference_seconds=inference))


class WorkflowBudget(unittest.TestCase):
    def fragments(self):
        return blocks("            timings = report['encoder_timings']\n", "            budget =")

    def execute(self, report, fragment):
        namespace = dict(report=report, T=T, math=math,
                         projection=report.get('projected_full_seconds'),
                         components=report.get('projection_components'))
        try:
            exec(compile(fragment, '<workflow-budget>', 'exec'), namespace)
        except (AssertionError, KeyError, TypeError, ValueError, T.Unsupported):
            self.assertNotIn('groups', namespace)
            return None
        return namespace['groups']

    def assert_groups(self, report, expected):
        for fragment in self.fragments():
            self.assertEqual(self.execute(report, fragment), expected)

    def test_four_validators_identical_literal_and_ast(self):
        # Include additive components, encoder samples and provenance, not just g.
        validators = blocks("            assert dm['groups'] == 40\n", "            budget =")
        self.assertEqual(len(validators), 4)
        self.assertTrue(all(block == validators[0] for block in validators))
        trees = [ast.dump(ast.parse(block), include_attributes=False) for block in validators]
        self.assertTrue(all(tree == trees[0] for tree in trees))
        self.assertEqual(len(self.fragments()), 4)
        tree = ast.parse(self.fragments()[0])
        selector = next(node for node in ast.walk(tree) if isinstance(node, ast.GeneratorExp))
        conditions = selector.generators[0].ifs
        self.assertEqual(len(conditions), 1)
        self.assertIsInstance(conditions[0], ast.BoolOp)
        self.assertIsInstance(conditions[0].op, ast.And)
        self.assertEqual(len(conditions[0].values), 2)
        for condition in conditions[0].values:
            self.assertIsInstance(condition, ast.Compare)
            self.assertIsInstance(condition.ops[0], ast.LtE)
        self.assertEqual(ast.unparse(conditions[0].values[0].comparators[0]), '0.6 * 300 * 60')
        self.assertEqual(ast.unparse(conditions[0].values[1].comparators[0]), '5400')
        self.assertNotIn('torch', sys.modules)

    def test_valid_and_l1_reduces_groups(self):
        report = report_fixture()
        # Whole budget admits 800; L1 permits only 602.
        self.assertLessEqual(report['projected_full_seconds'] * 1.3, 10800)
        self.assert_groups(report, 602)
        report = report_fixture(encoder=1000.)
        self.assert_groups(report, 800)

    def test_l1_can_refuse_every_group(self):
        report = report_fixture(encoder=9000.)
        self.assertLessEqual(report['projected_full_seconds'] * 400 / 800 * 1.3, 10800)
        self.assert_groups(report, None)

    def test_equality_boundaries_are_inclusive(self):
        report = report_fixture(encoder=1000., training=1024., inference=10800 / 1.3 - 2024.)
        self.assertEqual(report['projected_full_seconds'] * 1.3, 10800)
        self.assert_groups(report, 800)
        report = report_fixture(encoder=5400 / 1.3 - 512.)
        self.assertEqual((report['projection_components']['encoder_cache_seconds'] + 512.) * 1.3, 5400)
        self.assert_groups(report, 800)
        report = report_fixture(encoder=5400 / 1.3 - 512. + .001)
        self.assert_groups(report, 799)
        report = report_fixture(encoder=10800 / 1.3 - 512.)
        self.assert_groups(report, 400)
        report = report_fixture(encoder=10800 / 1.3 - 512. + .001)
        self.assert_groups(report, None)
        report = report_fixture(encoder=1000., training=1024., inference=21600 / 1.3 - 2024.)
        self.assertEqual(report['projected_full_seconds'] * 400 / 800 * 1.3, 10800)
        self.assert_groups(report, 400)

    def test_partial_diagnostics_never_get_groups(self):
        report = report_fixture()
        del report['encoder_timings']['cached_head']
        report['diagnostics'] = dict(cached_head_partial=dict(phase='spot32.training',
                                     completed_calls=15, elapsed_seconds=120., eligibility=False))
        self.assert_groups(report, None)

    def test_spot_winning_uses_real_projection_api(self):
        report = report_fixture(encoder=1000.)
        cached = report['encoder_timings']['cached_head']
        for name in ('training', 'validation'):
            cached['spot32'][name]['single_sample_seconds'] = 1.2 * cached['scaled_batch8_to32'][name]
            cached['projection_step_seconds'][name] = cached['spot32'][name]['single_sample_seconds']
        report.update(T.project_workload(report['encoder_timings'], report['projection_counts']))
        self.assert_groups(report, 800)

    def test_malformed_new_fields_and_legacy_method_refused(self):
        cases = [
            (('method',), 'legacy'), (('projection_batch_size',), 8), (('batch_size',), 32),
            (('seconds',), 120.001), (('seconds',), 120), (('seconds',), float('nan')),
            (('includes',), 'other'), (('threads',), 4), (('warmups',), 1),
            (('sequence_length',), 256), (('encoder_in_measured_step',), True),
            (('training', 'batch_size'), 32), (('validation', 'samples'), 2),
            (('training', 'p95_seconds'), 0.), (('training', 'p95_seconds'), 1.), (('validation', 'p50_seconds'), float('inf')),
            (('scoring', 'p95_seconds_per_row'), 0.),
            (('scaled_batch8_to32', 'factor'), 3), (('scaled_batch8_to32', 'training'), 64.001),
            (('projection_step_seconds', 'source'), 'spot32'),
            (('projection_step_seconds', 'validation'), 64.001),
            (('spot32', 'training', 'samples'), 3), (('spot32', 'validation', 'warmups'), 1),
            (('spot32', 'training', 'single_sample_seconds'), 84.),
            (('spot32', 'validation', 'single_sample_seconds'), 32),
            (('spot32', 'validation', 'single_sample_seconds'), float('inf')),
            (('spot32', 'training', 'p95_seconds'), 32.),
            (('spot32', 'validation', 'p50_seconds'), 16.),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                report = report_fixture()
                target = report['encoder_timings']['cached_head']
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_groups(report, None)
        for key in report_fixture()['encoder_timings']['cached_head']:
            report = report_fixture()
            del report['encoder_timings']['cached_head'][key]
            self.assert_groups(report, None)


if __name__ == '__main__':
    unittest.main()
