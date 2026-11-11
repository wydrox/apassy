"""The Linux vault package names the PR head, not the synthetic merge commit.

On a pull request, `github.sha` is the merge of the head into the base; the first
Linux acceptance (2026-11-10) found a CI package that recorded that merge commit,
which nobody can check out once the base moves. The package job now builds the PR
head itself (build-vault-release.sh refuses another commit than the checked-out one).
No network, no build.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).parents[2]


def job(workflow: str, name: str) -> str:
    """The text of one top-level job of a workflow: from `  name:` to the next job."""
    match = re.search(rf'^  {re.escape(name)}:\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)', workflow, re.M | re.S)
    if not match:
        raise AssertionError(f'no job {name}')
    return match.group(1)


class LinuxVaultCommitTests(unittest.TestCase):
    def test_the_package_job_builds_and_records_the_pr_head(self):
        text = job((ROOT / '.github/workflows/ci.yml').read_text(), 'linux-vault-package')
        self.assertIn(
            'APASSY_RELEASE_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}', text)
        self.assertNotIn('APASSY_RELEASE_COMMIT: ${{ github.sha }}', text)
        self.assertIn('packaging/linux/build-vault-release.sh', text)

    def test_the_packager_writes_both_commits_and_dates_from_the_built_tree(self):
        script = (ROOT / 'packaging/linux/build-vault.sh').read_text()
        self.assertIn('built=${APASSY_BUILT_COMMIT:-$commit}', script)
        # A shallow PR checkout has only the merge commit, not the head.
        self.assertIn('log -1 --format=%ct "$built"', script)
        self.assertIn('"commit": commit, "built_from": built', script)


if __name__ == '__main__':
    unittest.main()
