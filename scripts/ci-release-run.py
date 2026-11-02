#!/usr/bin/env python3
"""Select an eligible CI run before a release downloads or signs its artifact."""

import argparse
import datetime
import json
import re
import subprocess
from pathlib import Path


def validate_run(run, repository, commit, run_id, attempt=None, *, require_success=True):
    checks = {
        "run ID": str(run.get("id")) == run_id,
        "repository": run.get("repository", {}).get("full_name") == repository,
        "head repository": run.get("head_repository", {}).get("full_name") == repository,
        "workflow": run.get("path") == ".github/workflows/ci.yml",
        "event": run.get("event") == "push",
        "branch": run.get("head_branch") == "main",
        "commit": run.get("head_sha") == commit,
        "status": run.get("status") == "completed",
    }
    if require_success:
        checks["result"] = run.get("conclusion") == "success"
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
    }


def api(endpoint):
    return json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))


def api_list(endpoint, key):
    # Read every page; truncation or inconsistent/duplicate results fail closed.
    pages = json.loads(subprocess.check_output([
        "gh", "api", "--paginate", "--slurp", f"{endpoint}?per_page=100"
    ], text=True))
    if not isinstance(pages, list) or not pages:
        raise ValueError(f"invalid {key} pages")
    result = []
    total = pages[0]["total_count"]
    for page in pages:
        if page["total_count"] != total or not isinstance(page[key], list):
            raise ValueError(f"inconsistent {key} pages")
        result.extend(page[key])
    ids = [item["id"] for item in result]
    if (type(total) is not int or len(result) != total
            or any(type(value) is not int or value < 1 for value in ids)
            or len(set(ids)) != len(ids)):
        raise ValueError(f"incomplete or ambiguous {key} listing")
    return result


def timestamp(value):
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def resolve_artifact(run, repository, commit, run_id, attempt=None):
    outputs = validate_run(run, repository, commit, run_id, attempt)
    latest = run["run_attempt"]
    base = f"repos/{repository}/actions/runs/{run_id}"
    candidates = {}
    for artifact in api_list(f"{base}/artifacts", "artifacts"):
        match = re.fullmatch(r"apassy-release-([0-9a-f]{40})-([1-9][0-9]*)", artifact["name"])
        if not match:
            continue
        number = int(match[2])
        source = artifact["workflow_run"]
        if (match[1] != commit or number > latest
                or str(source["id"]) != run_id or source["head_sha"] != commit
                or source["head_branch"] != "main"
                or source["repository_id"] != run["repository"]["id"]
                or source["head_repository_id"] != run["head_repository"]["id"]):
            raise ValueError("artifact has an ineligible source identity")
        if number in candidates:
            raise ValueError("ambiguous release artifacts for one attempt")
        candidates[number] = artifact

    eligible = []
    for number, artifact in candidates.items():
        # Earlier attempts may have failed because an unrelated job failed.
        source = api(f"{base}/attempts/{number}")
        validate_run(source, repository, commit, run_id, str(number), require_success=False)
        jobs = api_list(f"{base}/attempts/{number}/jobs", "jobs")
        producers = [job for job in jobs if job["name"] == "release-binaries"]
        if len(producers) != 1:
            raise ValueError("missing or ambiguous release-binaries job")
        job = producers[0]
        if (str(job["run_id"]) != run_id or job["run_attempt"] != number
                or job["head_sha"] != commit):
            raise ValueError("release-binaries job has an ineligible identity")
        if job["status"] != "completed" or job["conclusion"] != "success":
            continue
        uploads = [step for step in job["steps"]
                   if step["name"] == "Save the unsigned release binaries"]
        if len(uploads) != 1:
            raise ValueError("missing or ambiguous artifact upload step")
        upload = uploads[0]
        if (upload["status"] != "completed" or upload["conclusion"] != "success"
                or not (timestamp(upload["started_at"]) <= timestamp(artifact["created_at"])
                        <= timestamp(upload["completed_at"]))):
            raise ValueError("artifact does not match the successful upload step")
        if artifact["expired"] is False:
            eligible.append((number, artifact))
        elif artifact["expired"] is not True:
            raise ValueError("invalid artifact expiry")
    if not eligible:
        raise ValueError("no artifact from a successful release-binaries attempt")
    number, artifact = max(eligible, key=lambda item: item[0])
    # Re-read after resolution so a concurrent rerun cannot reuse stale success.
    current = api(base)
    validate_run(current, repository, commit, run_id, str(latest))
    return {**outputs, "artifact_attempt": str(number),
            "artifact_id": str(artifact["id"]), "artifact_name": artifact["name"]}


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
        run = api(f"repos/{args.repository}/actions/runs/{args.run_id}")
        outputs = resolve_artifact(run, args.repository, args.commit, args.run_id, args.run_attempt)
        with args.github_output.open("a", encoding="utf-8") as stream:
            for name, value in outputs.items():
                stream.write(f"{name}={value}\n")
    except (OSError, ValueError, AttributeError, TypeError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Cannot use this CI run: {error}\n")
    print(f"Verified CI run {args.run_id}, latest attempt {outputs['run_attempt']}, "
          f"artifact attempt {outputs['artifact_attempt']}.")


if __name__ == "__main__":
    main()
