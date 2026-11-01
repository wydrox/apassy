#!/usr/bin/env python3
"""Record PR merge-tree evidence and conservatively select it for main CI reuse."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

WORKFLOW = '.github/workflows/ci.yml'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def git(*args):
    return subprocess.check_output(['git', *args], text=True, timeout=20).strip()


def api(path, raw=False):
    # gh handles GitHub's authenticated artifact redirect without exposing tokens.
    data = subprocess.check_output(['gh', 'api', path], timeout=30)
    return data if raw else json.loads(data)


def bounded_list(data, key=None):
    items = data[key] if key else data
    # Deliberately decline rather than make an incomplete candidate selection.
    require(len(items) < 100, 'candidate list may be truncated')
    if key:
        require(data['total_count'] == len(items), 'incomplete API response')
    return items


def validate_run(run, repository, workflow_id, head):
    require(run['repository']['full_name'] == repository, 'foreign repository')
    require(run['head_repository']['full_name'] == repository, 'fork run')
    require(run['path'] == WORKFLOW and run['workflow_id'] == workflow_id,
            'different workflow')
    require(run['event'] == 'pull_request', 'not a PR run')
    require(run['head_sha'] == head, 'different PR head')
    require(run['status'] == 'completed' and run['conclusion'] == 'success',
            'PR run did not complete successfully')
    require(type(run['run_attempt']) is int and run['run_attempt'] > 0, 'bad attempt')


def evidence(run, repository, tree, get):
    name = f"ci-tested-tree-{run['id']}-{run['run_attempt']}"
    artifacts = bounded_list(get(f"actions/runs/{run['id']}/artifacts?per_page=100"), 'artifacts')
    matches = [a for a in artifacts if a['name'] == name]
    require(len(matches) == 1, 'missing or ambiguous artifact')
    artifact = matches[0]
    require(artifact['expired'] is False and artifact['size_in_bytes'] < 65536,
            'expired or oversized artifact')
    data = get(f"actions/artifacts/{artifact['id']}/zip", raw=True)
    require(artifact['digest'] == 'sha256:' + hashlib.sha256(data).hexdigest(),
            'artifact digest mismatch')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(archive.namelist() == ['tested-tree.json'], 'unexpected artifact contents')
        require(archive.getinfo('tested-tree.json').file_size < 16384, 'oversized evidence')
        record = json.loads(archive.read('tested-tree.json'))
    expected = {'schema': 1, 'repository': repository, 'workflow': WORKFLOW,
                'run_id': str(run['id']), 'run_attempt': str(run['run_attempt']),
                'head_sha': run['head_sha'], 'tree': tree}
    require(all(record.get(k) == v for k, v in expected.items()), 'conflicting tree evidence')
    tested = record['tested_sha']
    require(re.fullmatch('[0-9a-f]{40}', tested) is not None, 'invalid tested commit')
    # Independent Git object verification: never mistake workflow_run.head_sha for
    # the synthetic merge commit checked out under github.sha.
    commit = get(f'git/commits/{tested}')
    require(commit['sha'] == tested and commit['tree']['sha'] == tree, 'tested tree mismatch')
    require(len(commit['parents']) == 2 and commit['parents'][1]['sha'] == run['head_sha'],
            'tested commit is not the PR merge commit')
    return tested


def select(repository, commit, tree, get):
    workflow = get('actions/workflows/ci.yml')
    require(workflow['path'] == WORKFLOW, 'different workflow path')
    pulls = bounded_list(get(f'commits/{commit}/pulls?per_page=100'))
    require(len(pulls) == 1, 'missing or ambiguous associated PR')
    pr = pulls[0]
    require(pr['merged_at'] and pr['base']['ref'] == 'main', 'PR not merged into main')
    require(pr['base']['repo']['full_name'] == repository and
            pr['head']['repo']['full_name'] == repository, 'fork PR')
    head = pr['head']['sha']
    runs = bounded_list(get(f'actions/workflows/ci.yml/runs?event=pull_request&head_sha={head}&per_page=100'),
                        'workflow_runs')
    # Multiple runs are conservatively ambiguous, even if they might agree.
    require(len(runs) == 1, 'missing or conflicting candidate runs')
    run = get(f"actions/runs/{runs[0]['id']}")
    require(run['id'] == runs[0]['id'], 'conflicting run ID')
    validate_run(run, repository, workflow['id'], head)
    evidence(run, repository, tree, get)
    # A rerun starting during the lookup invalidates our evidence.
    require(get(f"actions/runs/{run['id']}") == run, 'candidate changed during lookup')
    return str(run['id'])


def decide(event, ref, repository, commit, tree, get):
    if event != 'push' or ref != 'refs/heads/main':
        return False, 'only pushes to main can reuse PR CI'
    try:
        return True, select(repository, commit, tree, get)
    except (OSError, ValueError, KeyError, TypeError, AttributeError,
            subprocess.SubprocessError, zipfile.BadZipFile) as error:
        return False, f'full suite required: {error}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['record', 'select'])
    parser.add_argument('--record', type=Path)
    args = parser.parse_args()
    env = os.environ
    repository = env['GITHUB_REPOSITORY']
    commit = git('rev-parse', 'HEAD')
    require(commit == env['GITHUB_SHA'], 'checkout differs from event commit')
    tree = git('rev-parse', f'{commit}^{{tree}}')
    if args.mode == 'record':
        require(env['GITHUB_EVENT_NAME'] == 'pull_request', 'only PR runs record evidence')
        event = json.loads(Path(env['GITHUB_EVENT_PATH']).read_text())
        record = dict(schema=1, repository=repository, workflow=WORKFLOW,
                      run_id=env['GITHUB_RUN_ID'], run_attempt=env['GITHUB_RUN_ATTEMPT'],
                      tested_sha=commit, tree=tree, head_sha=event['pull_request']['head']['sha'])
        args.record.write_text(json.dumps(record) + '\n')
        return
    get = lambda path, **kw: api(f'repos/{repository}/{path}', **kw)
    reuse, reason = decide(env['GITHUB_EVENT_NAME'], env['GITHUB_REF'], repository, commit, tree, get)
    with open(env['GITHUB_OUTPUT'], 'a') as stream:
        stream.write(f"reuse={'true' if reuse else 'false'}\n")
    message = f'Reusing successful PR CI run {reason} for tree {tree}' if reuse else reason
    print(message)
    with open(env['GITHUB_STEP_SUMMARY'], 'a') as stream:
        stream.write(message + '\n')


if __name__ == '__main__':
    main()
