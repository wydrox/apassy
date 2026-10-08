#!/usr/bin/env python3
"""Select an eligible CI run before a release downloads or signs its artifact."""

import argparse
import json
import re
import subprocess
from pathlib import Path


def validate_run(run, repository, commit, run_id, attempt=None):
    checks = {
        "run ID": str(run.get("id")) == run_id,
        "repository": run.get("repository", {}).get("full_name") == repository,
        "head repository": run.get("head_repository", {}).get("full_name") == repository,
        "workflow": run.get("path") == ".github/workflows/ci.yml",
        "event": run.get("event") == "push",
        "branch": run.get("head_branch") == "main",
        "commit": run.get("head_sha") == commit,
        "status": run.get("status") == "completed",
        "result": run.get("conclusion") == "success",
    }
    if type(run.get("run_attempt")) is not int or run["run_attempt"] < 1:
        raise ValueError("CI run has an invalid attempt")
    actual_attempt = str(run["run_attempt"])
    if attempt is not None:
        checks["attempt"] = actual_attempt == attempt
    for field, passed in checks.items():
        if not passed:
            raise ValueError(f"CI run has an ineligible {field}")
    return {
        "run_id": run_id,
        "run_attempt": actual_attempt,
        "artifact_name": f"apassy-release-{commit}-{actual_attempt}",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt")
    parser.add_argument("--github-output", required=True, type=Path)
    args = parser.parse_args()
    patterns = {
        "repository": r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
        "commit": r"[0-9a-f]{40}",
        "run_id": r"[1-9][0-9]*",
        "run_attempt": r"[1-9][0-9]*",
    }
    for name, pattern in patterns.items():
        value = getattr(args, name)
        if value is not None and not re.fullmatch(pattern, value):
            parser.error(f"invalid {name}")
    try:
        payload = subprocess.check_output([
            "gh", "api", f"repos/{args.repository}/actions/runs/{args.run_id}"
        ], text=True)
        run = json.loads(payload)
        outputs = validate_run(run, args.repository, args.commit, args.run_id, args.run_attempt)
        with args.github_output.open("a", encoding="utf-8") as stream:
            for name, value in outputs.items():
                stream.write(f"{name}={value}\n")
    except (OSError, ValueError, AttributeError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Cannot use this CI run: {error}\n")
    print(f"Verified CI run {args.run_id}, attempt {outputs['run_attempt']}.")


if __name__ == "__main__":
    main()
