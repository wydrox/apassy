#!/usr/bin/env python3
"""P0 synthetic filesystem boundary fixture for Apassy.

This module is not product isolation evidence for the broker.
Real-secret gate: BLOCKED.

It uses temporary directories and synthetic canaries only.
It does not read the home directory, the keychain, or the environment dump.
It does not use sudo, TCC changes, live credentials, or network calls.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest


SANDBOX_EXEC = "/usr/bin/sandbox-exec"
REAL_SECRET_GATE = "BLOCKED"
SKIP_NOT_EVIDENCE = "This skip is NOT product isolation evidence for Apassy."

VAULT_CANARY_TEXT = "SYNTHETIC-VAULT-CANARY-NOT-A-SECRET\n"
TOKEN_CANARY_TEXT = "SYNTHETIC-OWNER-TOKEN-CANARY-NOT-A-SECRET\n"
PERMITTED_TASK_TEXT = "SYNTHETIC-AGENT-TASK-PERMITTED-NOT-A-SECRET\n"
REPLACE_PAYLOAD = "SYNTHETIC-REPLACE-PAYLOAD-SHOULD-FAIL\n"

FORBIDDEN_VALUE_MARKERS = (
    "-----BEGIN",
    "sk-live",
    "sk-test",
    "sk-proj-",
    "ghp_",
    "github_pat_",
    "gho_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "eyJ",
    "AKIA",
    "ASIA",
    "postgres://",
    "mysql://",
    "mongodb://",
    "redis://",
    "Bearer ",
    "bearer ",
)

CHILD_CODE = r"""
import json
import os
import sys

def try_read(path):
    try:
        handle = open(path, "r")
        try:
            data = handle.read()
        finally:
            handle.close()
        return {"ok": True, "prefix": data[:40], "len": len(data)}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}

def try_write(path):
    try:
        handle = open(path, "w")
        try:
            handle.write("SYNTHETIC-OVERWRITE-SHOULD-FAIL\n")
        finally:
            handle.close()
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}

def try_replace(src, dest):
    try:
        os.replace(src, dest)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}

mode = sys.argv[1]
permitted, vault, token, replace_vault_src, replace_token_src = sys.argv[2:7]
out = {
    "mode": mode,
    "permitted_read": try_read(permitted),
    "vault_read": try_read(vault),
    "token_read": try_read(token),
}
if mode == "probe":
    out["vault_replace"] = try_write(vault)
    out["token_replace"] = try_write(token)
    out["vault_os_replace"] = try_replace(replace_vault_src, vault)
    out["token_os_replace"] = try_replace(replace_token_src, token)
sys.stdout.write(json.dumps(out, separators=(",", ":")))
sys.stdout.write("\n")
"""


def sbpl_literal(path):
    escaped = path.replace("\\", "\\\\").replace('"', '\\"')
    return '(literal "%s")' % escaped


def build_negative_profile(vault_canary, token_canary):
    return "\n".join(
        [
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            "(deny file-read* %s)" % sbpl_literal(vault_canary),
            "(deny file-write* %s)" % sbpl_literal(vault_canary),
            "(deny file-read* %s)" % sbpl_literal(token_canary),
            "(deny file-write* %s)" % sbpl_literal(token_canary),
        ]
    )


def repo_root():
    return os.path.realpath(os.path.join(os.path.dirname(__file__), "..", ".."))


def fixture_path():
    return os.path.join(repo_root(), "tests", "fixtures", "p0-services.json")


def walk_strings(obj):
    found = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                found.append(("key", key, key))
            found.extend(walk_strings(value))
    elif isinstance(obj, list):
        for value in obj:
            found.extend(walk_strings(value))
    elif isinstance(obj, str):
        found.append(("value", obj, obj))
    return found


def print_skip(message):
    text = "%s %s" % (message, SKIP_NOT_EVIDENCE)
    print(text, file=sys.stdout)
    print(text, file=sys.stderr)
    sys.stdout.flush()
    sys.stderr.flush()
    return text


class TestSbplLiteral(unittest.TestCase):
    def test_space_stays_inside_quoted_literal(self):
        self.assertEqual(
            sbpl_literal("/tmp/synthetic vault/canary"),
            '(literal "/tmp/synthetic vault/canary")',
        )

    def test_quote_and_backslash_are_escaped(self):
        self.assertEqual(
            sbpl_literal('/tmp/say "hi"'),
            r'(literal "/tmp/say \"hi\"")',
        )
        self.assertEqual(
            sbpl_literal("/tmp/a\\b"),
            r'(literal "/tmp/a\\b")',
        )

    def test_profile_includes_spaced_literals(self):
        profile = build_negative_profile(
            "/tmp/synthetic vault/canary",
            "/tmp/owner token/canary",
        )
        self.assertIn('(literal "/tmp/synthetic vault/canary")', profile)
        self.assertIn('(literal "/tmp/owner token/canary")', profile)
        self.assertIn("(deny network*)", profile)


class TestP0ServiceCandidates(unittest.TestCase):
    def setUp(self):
        handle = open(fixture_path(), "r")
        try:
            self.raw = handle.read()
            self.data = json.loads(self.raw)
        finally:
            handle.close()

    def test_fixture_is_proposed_synthetic_candidates(self):
        self.assertEqual(self.data.get("status"), "PROPOSED")
        self.assertEqual(len(self.data.get("services") or []), 2)
        identities = self.data.get("identities") or {}
        self.assertTrue(str(identities.get("owner", "")).startswith("synthetic-"))
        self.assertTrue(
            str(identities.get("reporting_agent", "")).startswith("synthetic-")
        )
        self.assertTrue(
            str(identities.get("query_agent", "")).startswith("synthetic-")
        )

    def test_hostnames_use_example_invalid(self):
        for service in self.data["services"]:
            hostname = service["destination"]["hostname"]
            self.assertTrue(
                hostname.endswith(".example.invalid"),
                "hostname %r must use reserved example.invalid" % hostname,
            )

    def test_operations_are_named_typed_bounded_reads(self):
        for service in self.data["services"]:
            self.assertTrue(service.get("least_privilege"))
            self.assertTrue(service["least_privilege"].get("remote_verification_required"))
            operations = service.get("operations") or []
            self.assertGreaterEqual(len(operations), 1)
            for operation in operations:
                self.assertTrue(operation.get("name"))
                self.assertEqual(operation.get("effect"), "read")
                parameters = operation.get("parameters") or []
                self.assertGreaterEqual(len(parameters), 1)
                for parameter in parameters:
                    self.assertTrue(parameter.get("name"))
                    self.assertTrue(parameter.get("type"))
                    self.assertTrue(parameter.get("required"))
                output = operation.get("bounded_output") or {}
                self.assertTrue(output.get("fields"))
                limit = output.get("max_records", output.get("max_rows"))
                self.assertTrue(isinstance(limit, int) and limit > 0)

    def test_fixture_has_no_credential_like_values(self):
        for kind, label, text in walk_strings(self.data):
            if kind != "value":
                continue
            for marker in FORBIDDEN_VALUE_MARKERS:
                self.assertNotIn(
                    marker,
                    text,
                    "fixture value %r looks like a credential marker %r" % (label, marker),
                )


class TestSandboxFilesystemBoundary(unittest.TestCase):
    """Negative filesystem boundary with sandbox-exec.

    Unverified surfaces: memory, clipboard, automation, IPC,
    authenticated owner channels, and full broker isolation.
    Real-secret gate: BLOCKED.
    """

    @classmethod
    def setUpClass(cls):
        if platform.system() != "Darwin":
            raise unittest.SkipTest(
                print_skip("SKIP: this operating system is not macOS.")
            )
        if not (os.path.isfile(SANDBOX_EXEC) and os.access(SANDBOX_EXEC, os.X_OK)):
            raise unittest.SkipTest(
                print_skip(
                    "SKIP: /usr/bin/sandbox-exec is absent or not executable."
                )
            )

    def _cleanup_temp(self, tmp):
        try:
            tmp.cleanup()
        except OSError:
            try:
                shutil.rmtree(tmp.name, ignore_errors=True)
            except OSError:
                pass

    def _make_tree(self, with_spaces):
        prefix = "apassy p0 " if with_spaces else "apassy-p0-"
        tmp = tempfile.TemporaryDirectory(prefix=prefix)
        self.addCleanup(self._cleanup_temp, tmp)
        root = os.path.realpath(tmp.name)
        if with_spaces:
            vault_dir = os.path.join(root, "synthetic vault")
            token_dir = os.path.join(root, "owner token")
            agent_dir = os.path.join(root, "agent task")
            vault_name = "vault canary.txt"
            token_name = "owner token canary.txt"
            permitted_name = "permitted task.txt"
        else:
            vault_dir = os.path.join(root, "vault")
            token_dir = os.path.join(root, "owner-token")
            agent_dir = os.path.join(root, "agent-task")
            vault_name = "vault-canary.txt"
            token_name = "owner-token-canary.txt"
            permitted_name = "permitted-task.txt"
        home_dir = os.path.join(root, "child-home")
        os.mkdir(vault_dir)
        os.mkdir(token_dir)
        os.mkdir(agent_dir)
        os.mkdir(home_dir)
        vault_canary = os.path.realpath(os.path.join(vault_dir, vault_name))
        token_canary = os.path.realpath(os.path.join(token_dir, token_name))
        permitted = os.path.realpath(os.path.join(agent_dir, permitted_name))
        replace_vault_src = os.path.realpath(
            os.path.join(agent_dir, "replace-vault-src.txt")
        )
        replace_token_src = os.path.realpath(
            os.path.join(agent_dir, "replace-token-src.txt")
        )
        self._write(vault_canary, VAULT_CANARY_TEXT)
        self._write(token_canary, TOKEN_CANARY_TEXT)
        self._write(permitted, PERMITTED_TASK_TEXT)
        self._write(replace_vault_src, REPLACE_PAYLOAD)
        self._write(replace_token_src, REPLACE_PAYLOAD)
        return {
            "root": root,
            "home": home_dir,
            "vault": vault_canary,
            "token": token_canary,
            "permitted": permitted,
            "replace_vault_src": replace_vault_src,
            "replace_token_src": replace_token_src,
        }

    def _write(self, path, text):
        handle = open(path, "w")
        try:
            handle.write(text)
        finally:
            handle.close()

    def _read(self, path):
        handle = open(path, "r")
        try:
            return handle.read()
        finally:
            handle.close()

    def _child_env(self, home):
        path = os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        return {
            "PATH": path,
            "HOME": home,
            "TMPDIR": home,
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    def _child_argv(self, paths, mode):
        return [
            sys.executable,
            "-c",
            CHILD_CODE,
            mode,
            paths["permitted"],
            paths["vault"],
            paths["token"],
            paths["replace_vault_src"],
            paths["replace_token_src"],
        ]

    def _run_child(self, argv, paths):
        try:
            return subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                env=self._child_env(paths["home"]),
                cwd=paths["home"],
            )
        except subprocess.TimeoutExpired:
            self.fail(
                "child process timed out. This is a test failure, not a skip."
            )

    def _decode_json(self, proc, context):
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        if proc.returncode != 0:
            self.fail(
                "%s failed to start or exited nonzero. "
                "This is a test failure, not a skip. exit=%s stderr=%r stdout=%r"
                % (context, proc.returncode, stderr, stdout)
            )
        try:
            return json.loads(stdout.strip())
        except ValueError:
            self.fail(
                "%s did not return JSON. "
                "This is a test failure, not a skip. exit=%s stderr=%r stdout=%r"
                % (context, proc.returncode, stderr, stdout)
            )

    def _assert_baseline_readable(self, result, paths):
        self.assertEqual(result.get("mode"), "read")
        self.assertTrue(
            result["vault_read"]["ok"],
            "baseline same-UID child must read the vault canary: %r"
            % result["vault_read"],
        )
        self.assertTrue(
            result["token_read"]["ok"],
            "baseline same-UID child must read the owner-token canary: %r"
            % result["token_read"],
        )
        self.assertTrue(
            result["permitted_read"]["ok"],
            "baseline same-UID child must read the permitted task file: %r"
            % result["permitted_read"],
        )
        self.assertIn("SYNTHETIC-VAULT-CANARY", result["vault_read"]["prefix"])
        self.assertIn("SYNTHETIC-OWNER-TOKEN", result["token_read"]["prefix"])
        self.assertIn("SYNTHETIC-AGENT-TASK", result["permitted_read"]["prefix"])
        self.assertEqual(self._read(paths["vault"]), VAULT_CANARY_TEXT)
        self.assertEqual(self._read(paths["token"]), TOKEN_CANARY_TEXT)

    def _assert_sandboxed_boundary(self, result, paths):
        self.assertEqual(result.get("mode"), "probe")
        self.assertTrue(
            result["permitted_read"]["ok"],
            "sandboxed child must read the permitted task file; "
            "otherwise a deny-all profile can look like isolation: %r"
            % result["permitted_read"],
        )
        self.assertIn("SYNTHETIC-AGENT-TASK", result["permitted_read"]["prefix"])
        self.assertFalse(
            result["vault_read"]["ok"],
            "sandboxed child must not read the vault canary: %r"
            % result["vault_read"],
        )
        self.assertFalse(
            result["token_read"]["ok"],
            "sandboxed child must not read the owner-token canary: %r"
            % result["token_read"],
        )
        self.assertFalse(
            result["vault_replace"]["ok"],
            "sandboxed child must not overwrite the vault canary: %r"
            % result["vault_replace"],
        )
        self.assertFalse(
            result["token_replace"]["ok"],
            "sandboxed child must not overwrite the owner-token canary: %r"
            % result["token_replace"],
        )
        self.assertFalse(
            result["vault_os_replace"]["ok"],
            "sandboxed child must not replace the vault canary: %r"
            % result["vault_os_replace"],
        )
        self.assertFalse(
            result["token_os_replace"]["ok"],
            "sandboxed child must not replace the owner-token canary: %r"
            % result["token_os_replace"],
        )
        self.assertEqual(self._read(paths["vault"]), VAULT_CANARY_TEXT)
        self.assertEqual(self._read(paths["token"]), TOKEN_CANARY_TEXT)

    def _run_boundary(self, with_spaces):
        paths = self._make_tree(with_spaces)
        baseline = self._run_child(self._child_argv(paths, "read"), paths)
        baseline_result = self._decode_json(
            baseline, "same-UID unsandboxed child"
        )
        self._assert_baseline_readable(baseline_result, paths)

        profile = build_negative_profile(paths["vault"], paths["token"])
        if with_spaces:
            self.assertIn(" ", paths["vault"])
            self.assertIn(sbpl_literal(paths["vault"]), profile)
            self.assertIn(sbpl_literal(paths["token"]), profile)

        sandboxed = self._run_child(
            [SANDBOX_EXEC, "-p", profile] + self._child_argv(paths, "probe"),
            paths,
        )
        if sandboxed.returncode != 0:
            self.fail(
                "sandbox-exec failed to activate. "
                "This is a test failure, not a skip. exit=%s stderr=%r stdout=%r"
                % (
                    sandboxed.returncode,
                    sandboxed.stderr.decode("utf-8", "replace"),
                    sandboxed.stdout.decode("utf-8", "replace"),
                )
            )
        sandbox_result = self._decode_json(
            sandboxed, "sandbox-exec child"
        )
        self._assert_sandboxed_boundary(sandbox_result, paths)
        self.assertEqual(REAL_SECRET_GATE, "BLOCKED")

    def test_same_uid_child_can_read_canaries_then_sandbox_denies(self):
        self._run_boundary(with_spaces=False)

    def test_path_with_spaces(self):
        self._run_boundary(with_spaces=True)


if __name__ == "__main__":
    print(
        "Real-secret gate: %s. This fixture is not product isolation evidence."
        % REAL_SECRET_GATE
    )
    unittest.main(verbosity=2)
