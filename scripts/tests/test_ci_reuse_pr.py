"""Isolated fixtures for the PR tree reuse gate; no network or builds."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('reuse', Path(__file__).parents[1] / 'ci-reuse-pr.py')
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.repo = 'wydrox/apassy'
        self.tree, self.head, self.tested, self.main = ('a' * 40, 'b' * 40, 'c' * 40, 'd' * 40)
        self.run = dict(id=12, run_attempt=2, path=reuse.WORKFLOW, workflow_id=34,
                        event='pull_request', head_sha=self.head, status='completed', conclusion='success',
                        repository={'full_name': self.repo}, head_repository={'full_name': self.repo})
        self.record = dict(schema=1, repository=self.repo, workflow=reuse.WORKFLOW,
                           run_id='12', run_attempt='2', tested_sha=self.tested,
                           head_sha=self.head, tree=self.tree)
        self.pr = dict(merged_at='2026-11-01', base={'ref': 'main', 'repo': {'full_name': self.repo}},
                       head={'sha': self.head, 'repo': {'full_name': self.repo}})
        self.responses = {
            'actions/workflows/ci.yml': {'id': 34, 'path': reuse.WORKFLOW},
            f'commits/{self.main}/pulls?per_page=100': [self.pr],
            f'actions/workflows/ci.yml/runs?event=pull_request&head_sha={self.head}&per_page=100':
                {'total_count': 1, 'workflow_runs': [self.run]},
            'actions/runs/12': self.run,
            f'git/commits/{self.tested}': {'sha': self.tested, 'tree': {'sha': self.tree},
                                         'parents': [{'sha': 'e' * 40}, {'sha': self.head}]},
        }
        self.refresh_archive()

    def refresh_archive(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('tested-tree.json', json.dumps(self.record))
        self.data = stream.getvalue()
        self.artifact = dict(id=56, name='ci-tested-tree-12-2', expired=False,
                             size_in_bytes=len(self.data), digest='sha256:' + hashlib.sha256(self.data).hexdigest())
        self.responses['actions/runs/12/artifacts?per_page=100'] = {
            'total_count': 1, 'artifacts': [self.artifact]}

    def get(self, path, raw=False):
        if raw:
            self.assertEqual(path, 'actions/artifacts/56/zip')
            return self.data
        return copy.deepcopy(self.responses[path])

    def decision(self, **kwargs):
        args = dict(event='push', ref='refs/heads/main', repository=self.repo,
                    commit=self.main, tree=self.tree, get=self.get)
        args.update(kwargs)
        return reuse.decide(**args)[0]

    def test_match_uses_merge_tree_not_head(self):
        self.assertNotEqual(self.head, self.tested)
        self.assertNotEqual(self.main, self.tested)
        self.assertTrue(self.decision())

    def test_tree_mismatch(self):
        self.assertFalse(self.decision(tree='f' * 40))

    def test_independent_git_tree_mismatch(self):
        self.responses[f'git/commits/{self.tested}']['tree']['sha'] = 'f' * 40
        self.assertFalse(self.decision())

    def test_fork(self):
        self.run['head_repository']['full_name'] = 'fork/apassy'
        self.assertFalse(self.decision())

    def test_fork_pr(self):
        self.pr['head']['repo']['full_name'] = 'fork/apassy'
        self.assertFalse(self.decision())

    def test_failed_run(self):
        for conclusion in ['failure', 'cancelled', None]:
            self.run['conclusion'] = conclusion
            self.assertFalse(self.decision())

    def test_incomplete_run(self):
        self.run['status'] = 'in_progress'
        self.assertFalse(self.decision())

    def test_missing_artifact(self):
        self.responses['actions/runs/12/artifacts?per_page=100'] = {'total_count': 0, 'artifacts': []}
        self.assertFalse(self.decision())

    def test_expired_artifact(self):
        self.artifact['expired'] = True
        self.assertFalse(self.decision())

    def test_api_error(self):
        def broken(*args, **kwargs):
            raise subprocess.CalledProcessError(1, 'gh')
        self.assertFalse(self.decision(get=broken))

    def test_conflicting_candidates(self):
        key = f'actions/workflows/ci.yml/runs?event=pull_request&head_sha={self.head}&per_page=100'
        self.responses[key] = {'total_count': 2, 'workflow_runs': [self.run, dict(self.run, id=13)]}
        self.assertFalse(self.decision())

    def test_no_candidate(self):
        key = f'actions/workflows/ci.yml/runs?event=pull_request&head_sha={self.head}&per_page=100'
        self.responses[key] = {'total_count': 0, 'workflow_runs': []}
        self.assertFalse(self.decision())

    def test_other_workflow(self):
        for field, value in [('path', '.github/workflows/other.yml'), ('workflow_id', 35)]:
            with self.subTest(field=field):
                original = self.run[field]
                self.run[field] = value
                self.assertFalse(self.decision())
                self.run[field] = original

    def test_never_reuse_other_events(self):
        for event in ['pull_request', 'workflow_dispatch', 'workflow_run']:
            self.assertFalse(self.decision(event=event))
        self.assertFalse(self.decision(ref='refs/heads/feature'))

    def test_wrong_digest(self):
        self.artifact['digest'] = 'sha256:' + '0' * 64
        self.assertFalse(self.decision())

    def test_wrong_attempt(self):
        self.record['run_attempt'] = '1'
        self.refresh_archive()
        self.assertFalse(self.decision())

    def test_not_a_merge_commit(self):
        self.responses[f'git/commits/{self.tested}']['parents'] = [{'sha': self.head}]
        self.assertFalse(self.decision())

    def test_truncated_results(self):
        key = f'actions/workflows/ci.yml/runs?event=pull_request&head_sha={self.head}&per_page=100'
        self.responses[key]['total_count'] = 101
        self.assertFalse(self.decision())

    def test_changed_run(self):
        calls = 0
        def changing(path, **kwargs):
            nonlocal calls
            result = self.get(path, **kwargs)
            if path == 'actions/runs/12':
                calls += 1
                if calls == 2:
                    result['run_attempt'] = 3
            return result
        self.assertFalse(self.decision(get=changing))


if __name__ == '__main__':
    unittest.main()
