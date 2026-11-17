"""Black-box tests for LeakLens' ``python -m leaklens`` command line."""

import html
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from leaklens.scanner import ScanResult


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def github_token():
    return "gh" + "p_" + "A1b2C3" * 6


def aws_access_key():
    return "AKIA" + "1234ABCD" * 2


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *args):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, "-m", "leaklens", *(str(arg) for arg in args)],
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_clean_scan_exits_zero_and_prints_report(self):
        write_text(self.root / "clean.txt", "ordinary source\n")
        proc = self.run_cli("scan", self.root)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stdout.strip())
        self.assertEqual(proc.stderr, "")

    def test_detected_finding_exits_one_and_does_not_print_raw_secret(self):
        token = github_token()
        write_text(self.root / "config.env", "TOKEN=" + token + "\n")
        proc = self.run_cli("scan", self.root)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertNotIn(token, proc.stdout + proc.stderr)

    def test_json_report_has_required_top_level_types_and_redacts(self):
        token = github_token()
        write_text(self.root / "config.env", "TOKEN=" + token + "\n")
        proc = self.run_cli("scan", self.root, "--format", "json")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertIsInstance(payload["findings"], list)
        self.assertTrue(payload["findings"])
        self.assertIsInstance(payload["scanned"], int)
        self.assertIsInstance(payload["skipped"], dict)
        self.assertIsInstance(payload["complete"], bool)
        self.assertNotIn(token, proc.stdout + proc.stderr)

    def test_text_report_redacts_secret(self):
        token = github_token()
        write_text(self.root / "config.env", "TOKEN=" + token + "\n")
        proc = self.run_cli("scan", self.root, "--format", "text")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertNotIn(token, proc.stdout + proc.stderr)

    def test_sarif_report_has_version_and_redacted_result_message(self):
        token = github_token()
        write_text(self.root / "config.env", "TOKEN=" + token + "\n")
        proc = self.run_cli("scan", self.root, "--format", "sarif")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["version"], "2.1.0")
        results = payload["runs"][0]["results"]
        self.assertTrue(results)
        messages = [item["message"]["text"] for item in results]
        self.assertTrue(all("REDACTED" in message for message in messages))
        self.assertNotIn(token, proc.stdout + proc.stderr)

    def test_html_report_escapes_special_filename_and_redacts_secret(self):
        token = github_token()
        filename = "cfg<&>.env"
        write_text(self.root / filename, "TOKEN=" + token + "\n")
        proc = self.run_cli("scan", self.root, "--format", "html")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("REDACTED", proc.stdout)
        self.assertNotIn(token, proc.stdout + proc.stderr)
        self.assertIn(html.escape(filename), proc.stdout)
        self.assertNotIn(filename, proc.stdout.replace(html.escape(filename), ""))

    def test_report_can_be_written_outside_scanned_root(self):
        write_text(self.root / "config.env", "TOKEN=" + github_token() + "\n")
        report = self.base / "report.json"
        proc = self.run_cli("scan", self.root, "--format", "json", "--output", report)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertTrue(report.is_file())
        payload = json.loads(report.read_text(encoding="utf-8"))
        self.assertTrue(payload["findings"])

    def test_report_output_does_not_overwrite_a_source_inside_scan_root(self):
        token = github_token()
        source = write_text(self.root / "keep.env", "TOKEN=" + token + "\n")
        original = source.read_text(encoding="utf-8")
        proc = self.run_cli("scan", self.root, "--format", "json", "--output", source)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(source.read_text(encoding="utf-8"), original)
        self.assertNotIn(token, proc.stdout + proc.stderr)

    def test_invalid_format_is_usage_error_without_traceback(self):
        proc = self.run_cli("scan", self.root, "--format", "unknown")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def test_nonexistent_scan_root_is_usage_or_scan_error_without_traceback(self):
        missing = self.base / "missing"
        proc = self.run_cli("scan", missing)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def test_zero_max_bytes_is_usage_error(self):
        proc = self.run_cli("scan", self.root, "--max-bytes", "0")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def test_oversized_file_is_accounted_for_without_making_traversal_incomplete(self):
        write_text(self.root / "large.txt", "a" * 128)
        proc = self.run_cli("scan", self.root, "--format", "json", "--max-bytes", "16")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["skipped"].get("oversized"), 1)

    def test_cli_exception_output_does_not_leak_scanned_secret(self):
        token = github_token()
        write_text(self.root / "config.env", "TOKEN=" + token + "\n")
        # Invalid output destination exercises the error path after argument parsing.
        proc = self.run_cli("scan", self.root, "--output", self.base / "no-such-dir" / "report.txt")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn(token, proc.stdout + proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_baseline_command_creates_file_and_regular_findings_exit_zero(self):
        token = github_token()
        write_text(self.root / "config.env", "TOKEN=" + token + "\n")
        target = self.base / "baseline.json"
        proc = self.run_cli("baseline", self.root, "--output", target)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(payload["version"], 1)
        self.assertRegex(payload["salt"], r"^[0-9a-f]{64}$")
        self.assertTrue(payload["fingerprints"])
        self.assertNotIn(token, target.read_text(encoding="utf-8"))

    def test_baseline_command_refuses_to_overwrite_existing_file(self):
        target = write_text(self.base / "baseline.json", "do not replace")
        proc = self.run_cli("baseline", self.root, "--output", target)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(target.read_text(encoding="utf-8"), "do not replace")

    def test_baseline_command_rejects_incomplete_scan(self):
        target = self.base / "baseline.json"
        cli = importlib.import_module("leaklens.__main__")
        result = ScanResult(findings=[], scanned=0, skipped={}, errors=["safe error"], complete=False)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, "scan", return_value=result):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = cli.main(["baseline", str(self.root), "--output", str(target)])
        self.assertEqual(status, 2)
        self.assertFalse(target.exists())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_baseline_suppresses_preexisting_finding_and_new_secret_still_fails(self):
        write_text(self.root / "old.env", "TOKEN=" + github_token() + "\n")
        target = self.base / "baseline.json"
        made = self.run_cli("baseline", self.root, "--output", target)
        self.assertEqual(made.returncode, 0, made.stderr)

        old_only = self.run_cli("scan", self.root, "--format", "json", "--baseline", target)
        self.assertEqual(old_only.returncode, 0, old_only.stderr)
        old_payload = json.loads(old_only.stdout)
        self.assertEqual(old_payload["findings"], [])

        new_token = aws_access_key()
        write_text(self.root / "new.env", "access_key=" + new_token + "\n")
        with_new = self.run_cli("scan", self.root, "--format", "json", "--baseline", target)
        self.assertEqual(with_new.returncode, 1, with_new.stderr)
        new_payload = json.loads(with_new.stdout)
        self.assertTrue(new_payload["findings"])
        self.assertNotIn(new_token, with_new.stdout + with_new.stderr)

    def test_cli_exclude_pattern_is_applied(self):
        write_text(self.root / "private" / "secret.env", "TOKEN=" + github_token())
        proc = self.run_cli("scan", self.root, "--format", "json", "--exclude", "private/*.env")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["findings"], [])
        self.assertGreaterEqual(payload["skipped"].get("excluded", 0), 1)

    def test_entropy_switch_is_accepted(self):
        write_text(self.root / "ordinary.txt", "normal text\n")
        proc = self.run_cli("scan", self.root, "--entropy")
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
