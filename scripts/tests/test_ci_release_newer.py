import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.error


SPEC = importlib.util.spec_from_file_location(
    "ci_release_newer", Path(__file__).resolve().parents[1] / "ci-release-newer.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
COMMIT = "a" * 40


class PublicReleaseGuardTests(unittest.TestCase):
    def test_higher_version_allows_and_reads_exact_public_commit(self):
        self.assertEqual(MODULE.evaluate("0.5.5", {"version": "0.5.4", "commit": COMMIT}),
                         (True, "0.5.4", COMMIT))
        self.assertGreater(MODULE.compare_versions("0.10.0", "0.9.9"), 0)

    def test_equal_version_skips_even_with_different_build_metadata(self):
        self.assertEqual(MODULE.evaluate("0.5.5", {"version": "0.5.5", "commit": COMMIT})[0], False)
        self.assertEqual(MODULE.compare_versions("0.5.5+new", "0.5.5+old"), 0)

    def test_lower_version_fails(self):
        with self.assertRaisesRegex(ValueError, "public version 0.5.5 is newer"):
            MODULE.evaluate("0.5.4", {"version": "0.5.5", "commit": COMMIT})

    def test_prerelease_precedence_matches_semver(self):
        ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                   "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
        for lower, higher in zip(ordered, ordered[1:]):
            with self.subTest(lower=lower, higher=higher):
                self.assertGreater(MODULE.compare_versions(higher, lower), 0)
                self.assertLess(MODULE.compare_versions(lower, higher), 0)
        self.assertEqual(MODULE.compare_versions("1.0.0-rc.1", "1.0.0-rc.1"), 0)

    def test_malformed_manifest_or_version_fails_closed(self):
        for manifest in (None, [], {}, {"version": "0.5.4"},
                         {"version": "0.5.4", "commit": "short"},
                         {"version": None, "commit": COMMIT},
                         {"version": "0.5.04", "commit": COMMIT},
                         {"version": "0.5.4-01", "commit": COMMIT},
                         {"version": "0.5.4-", "commit": COMMIT}):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                MODULE.evaluate("0.5.5", manifest)
        with self.assertRaises(ValueError):
            MODULE.evaluate("0.5.05", {"version": "0.5.4", "commit": COMMIT})

    def test_cli_network_failures_including_404_never_allow_bootstrap(self):
        for error in (urllib.error.URLError("unreachable"),
                      urllib.error.HTTPError(MODULE.LATEST_URL, 404, "missing", {}, None)):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                with patch.object(MODULE, "read_public_manifest", side_effect=error), \
                     patch("sys.argv", [SPEC.origin, "--version", "0.5.5", "--github-output", str(output)]), \
                     patch("sys.stderr", new_callable=io.StringIO):
                    self.assertEqual(MODULE.main(), 1)
                self.assertFalse(output.exists())

    def test_http_read_identifies_the_release_checker_and_uses_a_timeout(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.geturl.return_value = MODULE.LATEST_URL
        response.read.return_value = b'{"version":"0.5.4"}'
        with patch.object(MODULE.urllib.request, "urlopen", return_value=response) as fetch:
            self.assertEqual(MODULE.read_public_manifest(), {"version": "0.5.4"})
        request = fetch.call_args.args[0]
        self.assertEqual(request.full_url, MODULE.LATEST_URL)
        self.assertEqual(request.get_header("User-agent"), "apassy-release-version-check/1.0")
        self.assertEqual(fetch.call_args.kwargs["timeout"], 20)

    def test_http_read_rejects_malformed_json_redirects_and_oversized_bodies(self):
        for body, url in ((b"not JSON", MODULE.LATEST_URL),
                          (b"{}", "https://example.com/latest.json"),
                          (b"x" * 65537, MODULE.LATEST_URL)):
            response = MagicMock()
            response.__enter__.return_value = response
            response.status = 200
            response.geturl.return_value = url
            response.read.return_value = body
            with self.subTest(url=url, size=len(body)), \
                 patch.object(MODULE.urllib.request, "urlopen", return_value=response), \
                 self.assertRaises(ValueError):
                MODULE.read_public_manifest()

    def test_cli_same_version_outputs_false_and_public_source(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with patch.object(MODULE, "read_public_manifest", return_value={"version": "0.5.5", "commit": COMMIT}), \
                 patch("sys.argv", [SPEC.origin, "--version", "0.5.5", "--github-output", str(output)]), \
                 patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(MODULE.main(), 0)
            self.assertEqual(output.read_text(), f"production=false\npublic_version=0.5.5\npublic_commit={COMMIT}\n")


if __name__ == "__main__":
    unittest.main()
