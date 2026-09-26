#!/usr/bin/env python3
"""Build the training set of the Apassy base model (goal B8).

The set is composed from neutral parts. No line is a hand-written risky command.

Sources of commands:
  - the generated set of `tests/analysis_replay.rs` (a dump with a fixed seed),
  - the synthetic coverage set `tests/fixtures/rule_packs/coverage.tsv`,
  - everyday category commands composed from `categories.ENTRIES` and `templates.POOLS`.

Labels:
  - `leak`, `destroy`, `writes`, `remote` come from the command analysis
    (`examples/basemodel_labels.rs`), plus the effects of an everyday category.
    A question without a settled answer gives no example.
  - `task_match` pairs a category request with a command of the same category
    (yes), or with a command of another category of the same stack, or a flagged
    command (no).
  - `rule_break` pairs an owner rule from `categories.RULES` with a command that
    the rule settles.

Excluded: every command of `tests/fixtures/bouncer/*` and `tests/evals/*`. Those
files are for development measurement only. The script reads their commands only
to drop equal commands. No owner data is read.

The state string is the one that `request_body` in `src/broker/bouncer.rs` builds.
The question texts are read from that file, so the training questions are the
questions that the broker asks.

Output: `<out>/train.jsonl`, `<out>/val.jsonl`, `<out>/stats.json`.
"""

import argparse
import collections
import glob
import hashlib
import json
import os
import random
import re
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

import categories as C  # noqa: E402
import templates as T  # noqa: E402

REPLAY_SECRETS = ["SUPABASE_SERVICE_KEY", "DATABASE_URL", "RESEND_API_KEY", "TWILIO_AUTH_TOKEN"]
SHELLS = {"sh", "bash", "zsh"}
WRAPPERS = {"sudo", "doas", "time", "nohup", "exec", "env"}
RISK_FLAGS = {"data_loss", "secret_output", "production", "real_recipient", "remote_code",
              "remote_access", "system_change"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"}
USAGE_WORDS = {"--help", "-h", "help", "--version", "-v", "version", "--dry-run", "--dryrun", "-n"}
# Default number of examples per question. `--scale` multiplies them.
TARGETS = {"task_match": 9000, "writes": 6000, "remote": 4000, "leak": 5000,
           "destroy": 6000, "rule_break": 5000}
QUESTION_ORDER = ["task_match", "writes", "remote", "leak", "destroy", "rule_break"]


# ---------------------------------------------------------------- questions

def broker_questions(path):
    """Read the fact questions from `src/broker/bouncer.rs`."""
    text = open(path, encoding="utf-8").read()
    block = text[text.index("const FACTS"):]
    block = block[:block.index("];")]
    pair = re.compile(r'\(\s*"(\w+)",\s*"((?:[^"\\]|\\.)*)",?\s*\)', re.S)
    facts = {name: body.replace('\\"', '"') for name, body in pair.findall(block)}
    rule = re.search(r'const RULE_FACT: \(&str, &str\) = \("(\w+)", "((?:[^"\\]|\\.)*)"\);', text)
    facts[rule.group(1)] = rule.group(2).replace('\\"', '"')
    assert set(facts) == set(QUESTION_ORDER), facts
    return facts


def state_for(user_request, command, purpose="", instruction=""):
    """The exact state of `request_body` in `src/broker/bouncer.rs`."""
    state = 'User request: "%s". Shell command: `%s`.' % (user_request.strip(), command)
    if purpose.strip():
        state += " Agent's stated purpose: %s" % purpose.strip()
    if instruction.strip():
        state += " Owner rule: %s" % instruction.strip()
    return state


# ---------------------------------------------------------------- helpers

def fill(template, rng, values=None):
    """Replace each `<slot>` with a pool value. One slot name gets one value."""
    values = {} if values is None else values

    def repl(match):
        name = match.group(1)
        if name == "pkg":
            name = values.get("_pkg", "npmpkg")
        if name not in T.POOLS:
            return match.group(0)
        if name not in values:
            values[name] = rng.choice(T.POOLS[name])
        return values[name]

    return re.sub(r"<(\w+)>", repl, template)


def split_script(script):
    """Split a shell script into segments of words. Rough, for program names only."""
    # shlex reads a line break as white space. A line break ends a command.
    script = script.replace("\n", " ; ")
    try:
        lexer = shlex.shlex(script, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return None, False
    segments, current, redirect = [], [], False
    for i, tok in enumerate(tokens):
        if tok in ("|", "||", "&&", ";", "&", "\n", ";;", "|&"):
            if current:
                segments.append(current)
            current = []
            continue
        if tok in (">", ">>", "&>", ">|", "&>>"):
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            before = tokens[i - 1] if i > 0 else ""
            if target != "/dev/null" and not target.startswith("&") and before != "2":
                redirect = True
            continue
        current.append(tok)
    if current:
        segments.append(current)
    return segments, redirect


def segments_of(argv):
    """Word lists of each segment, and whether output goes to a file."""
    if len(argv) >= 3 and argv[0] in SHELLS and argv[1] in ("-c", "-lc"):
        segs, redirect = split_script(argv[2])
        if segs is None:
            return None, False
        # A here-document body is data. Keep the first line of the script only then.
        if "<<" in argv[2]:
            first, _, _ = argv[2].partition("\n")
            segs, redirect = split_script(first)
            if segs is None:
                return None, False
        return segs, redirect
    return [list(argv)], False


def unwrap(words):
    """Drop `NAME=value` prefixes and plain wrappers. Keep package runners."""
    i = 0
    while i < len(words):
        w = words[i]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            i += 1
        elif w in WRAPPERS:
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 1
        else:
            break
    return words[i:]


def program_name(word):
    return word.rsplit("/", 1)[-1]


def url_hosts(words):
    hosts = []
    for w in words:
        m = re.match(r"^['\"]?(https?)://([^/:'\"\s]+)", w)
        if m:
            hosts.append(m.group(2).lower())
    return hosts


def load_packs():
    """Programs of read rules, HTTP clients, and network tools, from `packs/*.json`."""
    read_rule_ids = {
        ("file-tools", "read-tools"), ("file-tools", "sed-without-edit"),
        ("file-tools", "awk-without-system"), ("file-tools", "read-files"),
        ("file-tools", "find-without-action"), ("shell", "print-text"), ("shell", "tests"),
        ("shell", "information"), ("shell", "script-control"), ("system", "information"),
        ("node", "version"),
    }
    read_programs, http_clients = set(), set()
    for path in sorted(glob.glob(os.path.join(ROOT, "packs", "*.json"))):
        pack = json.load(open(path, encoding="utf-8"))
        for rule in pack.get("safe", []):
            if (pack["tool"], rule["id"]) in read_rule_ids:
                read_programs.update(rule["when"].get("program", []))
        http_clients.update(pack.get("roles", {}).get("http_client", []))
    assert read_programs and http_clients
    return read_programs, http_clients


# ---------------------------------------------------------------- categories

def entry_words(entry):
    return entry[2].split()


def build_matcher():
    """Longest leading-word match of a command to a category entry."""
    entries = sorted(C.ENTRIES, key=lambda e: -len(entry_words(e)))
    multi = collections.Counter()
    for e in C.ENTRIES:
        words = entry_words(e)
        if len(words) >= 2 and not words[1].startswith("-"):
            multi[words[0]] += 1

    def match(words):
        # A usage request or a dry run does not do the work of a category.
        if any(w in USAGE_WORDS for w in words[1:]):
            return None
        for e in entries:
            ew = entry_words(e)
            if words[:len(ew)] != ew:
                continue
            rest = words[len(ew):]
            if len(ew) == 1 and multi[ew[0]] and any(not r.startswith("-") for r in rest):
                continue
            return e
        return None

    return match


def git_effect(words):
    """(writes, remote, read) for a git command, or None."""
    words = unwrap(words)
    if len(words) < 2 or program_name(words[0]) != "git":
        return None
    sub = words[1]
    rest = words[2:]
    if sub == "branch":
        if any(not r.startswith("-") for r in rest) or any(r in ("-d", "-D", "-m", "-M", "--delete", "-f", "--force") for r in rest):
            return (1, 0, False)
        return (0, 0, True)
    if sub in C.GIT_EFFECTS:
        writes, remote = C.GIT_EFFECTS[sub]
        return (writes, remote, writes == 0 and remote == 0)
    return None


# ---------------------------------------------------------------- commands

class Pool:
    def __init__(self, rng):
        self.rng = rng
        self.items = []

    def add(self, source, env_names, line=None, argv=None, entry=None, weight=1.0):
        item = {"id": "c%d" % len(self.items), "source": source, "env_names": env_names,
                "entry": entry, "weight": weight}
        if argv is not None:
            item["argv_in"] = argv
        else:
            item["line"] = line
        self.items.append(item)


def pick_env_names(rng, k=None):
    k = k or rng.choice([1, 1, 2, 2, 3])
    names = rng.sample(T.POOLS["secret"] + T.POOLS["dburl"], k)
    return names


def rename_secrets(text, mapping):
    for old, new in mapping.items():
        text = re.sub(r"\$\{%s\}" % old, "${%s}" % new, text)
        text = re.sub(r"\$%s(?![A-Za-z0-9_])" % old, "$" + new, text)
    return text


def realistic(argv):
    """Drop the noisiest generated commands: very long ones and many repeated words."""
    words = " ".join(argv).split()
    if len(words) > 14:
        return False
    counts = collections.Counter(w for w in words if len(w) > 1)
    return not counts or max(counts.values()) < 3


def load_replay(pool, path, rng, limit):
    rows = []
    for line in open(path, encoding="utf-8"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 4:
            continue
        argv = json.loads(parts[3])
        if realistic(argv):
            rows.append(argv)
    rng.shuffle(rows)
    for argv in rows[:limit]:
        env = pick_env_names(rng)
        if rng.random() < 0.7:
            mapping = {old: rng.choice(env) for old in REPLAY_SECRETS}
            argv = [rename_secrets(a, mapping) for a in argv]
        else:
            env = sorted(set(env) | set(REPLAY_SECRETS[:2]))
        pool.add("replay", env, argv=argv, weight=1.0)
    return len(rows)


def load_coverage(pool, path, rng):
    n = 0
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip() or line.startswith("#"):
            continue
        command = line.split("\t", 1)[0].replace("<NL>", "\n").replace("<TAB>", "\t")
        for _ in range(2):
            env = pick_env_names(rng)
            mapping = {old: rng.choice(env) for old in REPLAY_SECRETS}
            pool.add("coverage", env, line=rename_secrets(command, mapping), weight=3.0)
        n += 1
    return n


def compose_categories(pool, rng, per_choice):
    n = 0
    for entry in C.ENTRIES:
        stack, category, words, choices, _ = entry
        for choice in choices:
            for _ in range(per_choice):
                values = {"_pkg": {"python": "pypkg", "rust": "crate", "go": "gomod",
                                   "ruby": "gem"}.get(stack, "npmpkg")}
                line = fill((words + " " + choice).strip(), rng, values)
                pool.add("composed", pick_env_names(rng), line=line, entry=entry, weight=3.0)
                n += 1
    return n


def run_labels(binary, items):
    lines = []
    for it in items:
        row = {"id": it["id"], "purpose": "", "secrets": it["env_names"]}
        if "argv_in" in it:
            row["argv"] = it["argv_in"]
        else:
            row["line"] = it["line"]
        lines.append(json.dumps(row))
    proc = subprocess.run([binary], input=("\n".join(lines) + "\n").encode(), capture_output=True,
                          check=True)
    out = {}
    for line in proc.stdout.decode().splitlines():
        row = json.loads(line)
        out[row["id"]] = row
    return out


def dev_commands(binary):
    """Commands of the development sets, as the broker joins them. For exclusion only."""
    rows, raw = [], set()
    evals = sorted(glob.glob(os.path.join(ROOT, "tests", "evals", "*.jsonl")))
    evals = [p for p in evals if "heldout-v2" not in os.path.basename(p)]
    for path in evals:
        for line in open(path, encoding="utf-8"):
            if line.strip():
                cmd = json.loads(line)["command"]
                raw.add(cmd)
                rows.append({"id": "dev%d" % len(rows), "line": cmd, "purpose": "", "secrets": []})
    for path in sorted(glob.glob(os.path.join(ROOT, "tests", "fixtures", "bouncer", "*.tsv"))):
        for line in open(path, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 3:
                raw.add(parts[2])
                rows.append({"id": "dev%d" % len(rows), "line": parts[2], "purpose": "", "secrets": []})
    proc = subprocess.run([binary], input=("\n".join(json.dumps(r) for r in rows) + "\n").encode(),
                          capture_output=True, check=True)
    joined = {json.loads(l)["command"] for l in proc.stdout.decode().splitlines()}
    norm = {re.sub(r"\s+", " ", c).strip().lower() for c in joined | raw}
    return joined | raw, norm, len(rows)


# ---------------------------------------------------------------- labels

def settle(item, read_programs, http_clients):
    """The settled answers of one command. Absent key: not settled."""
    flags = set(item["flags"]) - {"injection_phrase"}
    safe = item["known_safe"]
    argv = item["argv"]
    segs, redirect = segments_of(argv)
    progs = []
    if segs:
        for s in segs:
            words = unwrap(s)
            if words:
                progs.append(program_name(words[0]))
    all_read = bool(progs) and all(p in read_programs for p in progs)
    removes = any(p in ("rm", "rmdir", "unlink") for p in progs)
    hosts = []
    for s in segs or []:
        words = unwrap(s)
        if words and program_name(words[0]) in http_clients:
            hosts.extend(url_hosts(words[1:]))
    git = git_effect(argv) if segs and len(segs) == 1 else None
    entry = item.get("entry_matched")
    eff = dict(C.CATEGORIES[entry[1]]["effects"]) if entry else {}
    if entry:
        eff.update(entry[4])
    labels = {}

    # leak: secret output is a flag of the analysis.
    if "secret_output" in flags:
        labels["leak"] = 1
    elif safe:
        labels["leak"] = 0

    # destroy: data loss is a flag of the analysis. A removal of build output and a
    # file redirect are not settled.
    if "data_loss" in flags:
        labels["destroy"] = 1
    elif safe and not removes and not redirect:
        labels["destroy"] = 0

    # writes
    installs = "new_dependency" in flags and any(w in ("install", "add", "i") for w in argv[1:4])
    if flags & {"data_loss", "system_change"} or installs:
        labels["writes"] = 1
    elif redirect or (safe and removes):
        labels["writes"] = 1
    elif not flags and eff.get("writes") is not None:
        labels["writes"] = eff["writes"]
    elif not flags and git is not None and git[0] is not None:
        labels["writes"] = git[0]
    elif safe and all_read:
        labels["writes"] = 0

    # remote
    if flags & {"remote_access", "remote_code", "real_recipient"}:
        labels["remote"] = 1
    elif hosts and any(h not in LOCAL_HOSTS for h in hosts):
        labels["remote"] = 1
    elif eff.get("remote") is not None and not (flags - {"new_dependency", "production"}):
        labels["remote"] = eff["remote"]
    elif not flags and git is not None:
        labels["remote"] = git[1]
    elif safe and all_read and not hosts:
        labels["remote"] = 0
    return labels


# ---------------------------------------------------------------- examples

class Builder:
    def __init__(self, rng, questions):
        self.rng = rng
        self.questions = questions
        self.examples = []

    def request_for(self, category, stack):
        spec = C.CATEGORIES[category]
        values = {"_pkg": {"python": "pypkg", "rust": "crate", "go": "gomod", "ruby": "gem"}.get(stack, "npmpkg")}
        return fill(self.rng.choice(spec["requests"]), self.rng, values)

    def any_request(self, item):
        r = self.rng.random()
        entry = item.get("entry_matched")
        if entry and r < 0.5:
            return self.request_for(entry[1], entry[0])
        if r < 0.75:
            return fill(self.rng.choice(T.CODING_REQUESTS), self.rng)
        if r < 0.85:
            return self.rng.choice(T.VAGUE_REQUESTS)
        category = self.rng.choice(sorted(C.CATEGORIES))
        return self.request_for(category, "node")

    def purpose_for(self, request, category=None):
        r = self.rng.random()
        if r < 0.4:
            return request
        if r < 0.7:
            return ""
        if category:
            return self.rng.choice(C.CATEGORIES[category]["purposes"])
        return self.rng.choice(["Do the work.", "Continue the task.", "Next step of the task."])

    def declaration(self):
        return {
            "project": self.rng.choice(T.POOLS["proj"]),
            "environment": self.rng.choice(["development", "local", "staging", "staging", "test"]),
            "risk": self.rng.choice(["low", "medium", "medium", "high"]),
            "scope": self.rng.choice(["read-only", "read-write", "read-write"]),
            "reversibility": self.rng.choice(["reversible", "reversible", "irreversible"]),
        }

    def add(self, question, answer, item, request, purpose, instruction, kind):
        state = state_for(request, item["command"], purpose, instruction)
        self.examples.append({
            "state": state,
            "question": question,
            "instructions": self.questions[question],
            "answer": int(answer),
            "kind": kind,
            "source": item["source"],
            "command": item["command"],
            "user_request": request,
            "purpose": purpose,
            "instruction": instruction,
            "env_names": item["env_names"],
            "declaration": self.declaration(),
            "rule_flags": item["flags"],
            "known_safe": item["known_safe"],
            "category": item["entry_matched"][1] if item.get("entry_matched") else None,
        })


def weighted_sample(rng, items, k):
    """Sample k items with replacement, by weight."""
    if not items or k <= 0:
        return []
    weights = [it["weight"] for it in items]
    return rng.choices(items, weights=weights, k=k)


def spread(rng, items, k):
    """Sample k items without replacement from a list where an item of weight w has
    w copies. Realistic commands (coverage, composed) have weight 3, so they can
    appear up to three times with different requests. Repeat more only when needed."""
    if not items or k <= 0:
        return []
    expanded = [it for it in items for _ in range(max(1, int(it["weight"])))]
    rng.shuffle(expanded)
    out = expanded[:k]
    if len(out) < k:
        out += weighted_sample(rng, items, k - len(out))
    return out


def build(args):
    rng = random.Random(args.seed)
    questions = broker_questions(os.path.join(ROOT, "src", "broker", "bouncer.rs"))
    read_programs, http_clients = load_packs()
    matcher = build_matcher()
    binary = args.labels_bin

    pool = Pool(rng)
    n_replay = load_replay(pool, args.dump, rng, args.replay_limit)
    n_cov = load_coverage(pool, os.path.join(ROOT, "tests", "fixtures", "rule_packs", "coverage.tsv"), rng)
    n_comp = compose_categories(pool, rng, args.per_choice)
    analysed = run_labels(binary, pool.items)
    dev_exact, dev_norm, n_dev = dev_commands(binary)

    items, dropped_dev = [], 0
    seen = set()
    for it in pool.items:
        row = analysed[it["id"]]
        it["argv"] = row["argv"]
        it["command"] = row["command"]
        it["flags"] = row["flags"]
        it["known_safe"] = row["known_safe"]
        norm = re.sub(r"\s+", " ", it["command"]).strip().lower()
        if it["command"] in dev_exact or norm in dev_norm or it.get("line") in dev_exact:
            dropped_dev += 1
            continue
        key = (it["command"], tuple(it["env_names"]))
        if key in seen:
            continue
        seen.add(key)
        if it["entry"] is not None:
            it["entry_matched"] = it["entry"]
        else:
            segs, _ = segments_of(it["argv"])
            it["entry_matched"] = matcher(unwrap(segs[0])) if segs and len(segs) == 1 else None
        it["labels"] = settle(it, read_programs, http_clients)
        items.append(it)

    b = Builder(rng, questions)
    scale = args.scale
    targets = {q: int(n * scale) for q, n in TARGETS.items()}

    # ---- effect questions: writes, remote, leak, destroy
    for q in ("writes", "remote", "leak", "destroy"):
        pos = [it for it in items if it["labels"].get(q) == 1]
        neg = [it for it in items if it["labels"].get(q) == 0]
        half = targets[q] // 2
        for answer, group in ((1, pos), (0, neg)):
            for it in spread(rng, group, half):
                request = b.any_request(it)
                entry = it.get("entry_matched")
                purpose = b.purpose_for(request, entry[1] if entry else None)
                rule = rng.choice(rng.choice(C.RULES)["texts"]) if rng.random() < 0.15 else ""
                b.add(q, answer, it, request, purpose, rule, "effect")

    # ---- task_match
    cat_items = collections.defaultdict(list)
    stack_cats = collections.defaultdict(set)
    for it in items:
        entry = it.get("entry_matched")
        if not entry:
            continue
        flags = set(it["flags"])
        allowed = {"new_dependency", "production", "ask_owner"} if entry[1] in ("dependency_install", "preview_deploy") else set()
        if flags - allowed:
            continue
        cat_items[(entry[0], entry[1])].append(it)
        stack_cats[entry[0]].add(entry[1])
    risky = [it for it in items if set(it["flags"]) & RISK_FLAGS]
    half = targets["task_match"] // 2
    keys = sorted(cat_items)
    # Positives: a category request with a command of that category. A small share
    # pairs a general coding request with a read-only check (tests, linters, git reads).
    reads = [k for k in keys if k[1] in ("tests", "lint_format", "type_check", "git_inspect")]
    made = 0
    while made < half:
        if rng.random() < 0.15:
            stack, cat = rng.choice(reads)
            it = rng.choice(cat_items[(stack, cat)])
            if it["labels"].get("writes") != 0:
                continue
            request = fill(rng.choice(T.CODING_REQUESTS), rng)
            b.add("task_match", 1, it, request, b.purpose_for(request, cat), "", "generic_read")
        else:
            stack, cat = keys[made % len(keys)] if made < len(keys) * 3 else rng.choice(keys)
            it = rng.choice(cat_items[(stack, cat)])
            request = b.request_for(cat, stack)
            b.add("task_match", 1, it, request, b.purpose_for(request, cat), "", "same_category")
        made += 1
    # Negatives. Hard negatives: a request of another category in the same stack.
    hard = int(half * 0.5)
    stacks = sorted(s for s in stack_cats if len(stack_cats[s]) >= 2)
    made = 0
    while made < hard:
        stack = rng.choice(stacks)
        cmd_cat, req_cat = rng.sample(sorted(stack_cats[stack]), 2)
        if frozenset({cmd_cat, req_cat}) in C.RELATED:
            continue
        it = rng.choice(cat_items[(stack, cmd_cat)])
        request = b.request_for(req_cat, stack)
        purpose = b.purpose_for(request, cmd_cat if rng.random() < 0.5 else req_cat)
        b.add("task_match", 0, it, request, purpose, "", "hard_negative")
        made += 1
    n_risky = int(half * 0.35)
    for it in spread(rng, risky, n_risky):
        entry = it.get("entry_matched")
        cats = sorted(c for c in C.CATEGORIES if not entry or c != entry[1])
        r = rng.random()
        if r < 0.6:
            request = b.request_for(rng.choice(cats), entry[0] if entry else "node")
        elif r < 0.9:
            request = fill(rng.choice(T.CODING_REQUESTS), rng)
        else:
            request = rng.choice(T.VAGUE_REQUESTS)
        b.add("task_match", 0, it, request, b.purpose_for(request), "", "flagged_negative")
    deploys = [it for k, v in cat_items.items() if k[1] == "preview_deploy" for it in v]
    for _ in range(half - hard - n_risky):
        it = rng.choice(deploys)
        request = fill(rng.choice(T.CODING_REQUESTS), rng)
        b.add("task_match", 0, it, request, b.purpose_for(request), "", "generic_deploy_negative")

    # ---- rule_break
    per_rule = targets["rule_break"] // len(C.RULES)
    for rule in C.RULES:
        ok, broke = [], []
        for it in items:
            entry = it.get("entry_matched")
            flags = set(it["flags"])
            if rule["kind"] == "fact":
                value = it["labels"].get(rule["fact"])
                if value == 1:
                    broke.append(it)
                elif value == 0:
                    ok.append(it)
                continue
            if flags & rule["break_flags"]:
                broke.append(it)
            elif entry and entry[1] in rule["break"] and not (flags - {"new_dependency", "production", "ask_owner"}):
                broke.append(it)
            elif entry and entry[1] in rule["ok"] and not flags:
                ok.append(it)
        for answer, group in ((1, broke), (0, ok)):
            for it in spread(rng, group, per_rule // 2):
                entry = it.get("entry_matched")
                request = b.request_for(entry[1], entry[0]) if entry and rng.random() < 0.6 else b.any_request(it)
                purpose = b.purpose_for(request, entry[1] if entry else None)
                b.add("rule_break", answer, it, request, purpose, rng.choice(rule["texts"]), "rule")

    # ---- split by command, so a command is in one split only
    train, val = [], []
    for ex in b.examples:
        h = int(hashlib.sha256(ex["command"].encode()).hexdigest()[:8], 16)
        (val if h % 100 < args.val_percent else train).append(ex)
    rng.shuffle(train)
    rng.shuffle(val)

    os.makedirs(args.out, exist_ok=True)
    for name, rows in (("train", train), ("val", val)):
        with open(os.path.join(args.out, name + ".jsonl"), "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def counts(rows):
        c = collections.defaultdict(lambda: [0, 0])
        for r in rows:
            c[r["question"]][r["answer"]] += 1
        return {q: {"no": c[q][0], "yes": c[q][1]} for q in QUESTION_ORDER}

    kinds = collections.Counter((r["question"], r["kind"]) for r in b.examples)
    sources = collections.Counter(r["source"] for r in b.examples)
    stats = {
        "seed": args.seed,
        "commands": {"replay_realistic": n_replay, "replay_used": args.replay_limit,
                     "coverage": n_cov, "composed": n_comp, "pool": len(pool.items),
                     "after_dedupe_and_exclusion": len(items), "dropped_dev_equal": dropped_dev,
                     "dev_commands_checked": n_dev},
        "settled": {q: {"yes": sum(1 for it in items if it["labels"].get(q) == 1),
                        "no": sum(1 for it in items if it["labels"].get(q) == 0)}
                    for q in ("writes", "remote", "leak", "destroy")},
        "train": counts(train),
        "val": counts(val),
        "total": len(b.examples),
        "kinds": {"%s/%s" % k: v for k, v in sorted(kinds.items())},
        "sources": dict(sources),
        "questions": questions,
    }
    with open(os.path.join(args.out, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    print(json.dumps({k: stats[k] for k in ("commands", "settled", "train", "val", "total", "sources")}, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dump", default="/tmp/apassy-b8/replay-dump.tsv",
                    help="APASSY_REPLAY_DUMP output of tests/analysis_replay.rs")
    ap.add_argument("--labels-bin", default=os.path.join(ROOT, "target", "debug", "examples", "basemodel_labels"))
    ap.add_argument("--out", default=os.path.join(HERE, "data"))
    ap.add_argument("--seed", type=int, default=20260926)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--replay-limit", type=int, default=30000)
    ap.add_argument("--per-choice", type=int, default=3)
    ap.add_argument("--val-percent", type=int, default=8)
    build(ap.parse_args())


if __name__ == "__main__":
    main()
