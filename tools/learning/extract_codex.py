#!/usr/bin/env python3
"""Extract shell commands of one project from local Codex sessions for the learning
replay (goal item B3, docs/operations/learning.md).

Usage: extract_codex.py OUT.json [PROJECT_WORD] [SESSIONS_DIR]

- PROJECT_WORD: a word in the working directory, default "odealo".
- SESSIONS_DIR: default ~/.codex/sessions.

Output: a JSON array [{"at", "cmd", "cwd_rel", "user_request"}] in time order. Keep
OUT outside the repository. The file has real commands and user requests. This script
prints counts only, never a command.
"""
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

if len(sys.argv) < 2:
    sys.exit(__doc__)
OUT = sys.argv[1]
WORD = (sys.argv[2] if len(sys.argv) > 2 else "odealo").lower()
SESSIONS = os.path.expanduser(sys.argv[3] if len(sys.argv) > 3 else "~/.codex/sessions")

STRING = r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`(?:[^`\\]|\\.)*`)'
CMD_RE = re.compile(r"\bcmd\s*:\s*" + STRING, re.S)
WORKDIR_RE = re.compile(r"\bworkdir\s*:\s*" + STRING, re.S)


def js_string(literal):
    """A JavaScript string literal from an `exec` tool call, or None."""
    quote, body = literal[0], literal[1:-1]
    if quote == "`":
        if "${" in body:
            return None
        return body.replace("\\`", "`").replace("\\\\", "\\")
    if quote == "'":
        body = body.replace("\\'", "'").replace('"', '\\"')
    try:
        return json.loads('"' + body + '"')
    except ValueError:
        return None


def to_unix(stamp):
    try:
        return int(datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def split_project(path):
    """The project root (up to the part with WORD) and the path under it."""
    parts = path.rstrip("/").split("/")
    for index, part in enumerate(parts):
        if WORD in part.lower():
            rest = "/".join(parts[index + 1 :])
            return "/".join(parts[: index + 1]), rest or "."
    return None, None


def user_text(payload):
    texts = [
        item["text"]
        for item in payload.get("content") or []
        if isinstance(item, dict) and isinstance(item.get("text"), str)
    ]
    text = "\n".join(texts).strip()
    # Host context blocks are not the user's words.
    if not text or text.startswith("<") or text.startswith("# AGENTS.md"):
        return None
    return text[:1000]


def calls_of(payload, cwd):
    """(command, working directory) pairs of one Codex record."""
    kind = payload.get("type")
    if kind == "function_call" and payload.get("name") in ("exec_command", "shell"):
        try:
            args = json.loads(payload.get("arguments") or "{}")
        except ValueError:
            return []
        cmd = args.get("cmd")
        argv = args.get("command")
        if cmd is None and isinstance(argv, list):
            shell = len(argv) >= 3 and argv[0].endswith("sh") and argv[1] in ("-lc", "-c")
            cmd = argv[2] if shell else " ".join(argv)
        return [(cmd, args.get("workdir") or cwd)] if isinstance(cmd, str) else []
    if kind == "custom_tool_call" and payload.get("name") == "exec":
        source = payload.get("input") or ""
        found = []
        for match in CMD_RE.finditer(source):
            cmd = js_string(match.group(1))
            if cmd is None:
                continue
            near = WORKDIR_RE.search(source, match.end(), match.end() + 400)
            workdir = (js_string(near.group(1)) if near else None) or cwd
            found.append((cmd, workdir))
        return found
    return []


rows = []
files = sorted(glob.glob(os.path.join(SESSIONS, "**", "*.jsonl"), recursive=True))
for path in files:
    cwd, request = None, ""
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            payload = record.get("payload")
            if not isinstance(payload, dict):
                continue
            if record.get("type") in ("turn_context", "session_meta"):
                cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else cwd
                continue
            at = to_unix(record.get("timestamp", ""))
            if at is None:
                continue
            if payload.get("type") == "message" and payload.get("role") == "user":
                request = user_text(payload) or request
                continue
            for cmd, workdir in calls_of(payload, cwd):
                _, rel = split_project(workdir or "")
                if rel is not None and cmd.strip():
                    rows.append({"at": at, "cmd": cmd, "cwd_rel": rel, "user_request": request})

rows.sort(key=lambda row: row["at"])
with open(OUT, "w", encoding="utf-8") as handle:
    json.dump(rows, handle)
days = lambda at: datetime.fromtimestamp(at, timezone.utc).date()  # noqa: E731
span = f"from {days(rows[0]['at'])} to {days(rows[-1]['at'])}" if rows else "no runs"
print(
    f"files {len(files)}, runs {len(rows)}, unique commands {len({r['cmd'] for r in rows})}, "
    f"with user request {sum(1 for r in rows if r['user_request'])}, {span}"
)
