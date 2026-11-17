"""Contract tests for LeakLens' offline scanner and baseline API."""

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from leaklens import baseline, scanner


SALT = "leaklens-v1"
BASELINE_SALT = "1" * 64


def github_token():
    return "gh" + "p_" + "A1b2C3" * 6


def aws_access_key():
    return "AKIA" + "1234ABCD" * 2


def generic_secret():
    return "long" + "secret" + "value" + "987654"


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def scan(self, **kwargs):
        return scanner.scan(self.root, **kwargs)

    def test_empty_tree_is_complete_with_expected_result_shape(self):
        result = self.scan()
        self.assertEqual(result.findings, [])
        self.assertEqual(result.scanned, 0)
        self.assertFalse(any(result.skipped.values()))
        self.assertEqual(result.errors, [])
        self.assertTrue(result.complete)

    def test_detects_github_token_in_hidden_env_file_and_redacts_serialization(self):
        token = github_token()
        write_text(self.root / ".hidden.env", "GITHUB_TOKEN=" + token + "\n")
        result = self.scan()
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.path, ".hidden.env")
        self.assertEqual(finding.line, 1)
        self.assertEqual(finding.column, len("GITHUB_TOKEN=") + 1)
        self.assertEqual(finding.rule_id, "github-token")
        self.assertNotIn(token, json.dumps(finding.to_dict()))

    def test_detects_aws_access_key(self):
        write_text(self.root / "config.txt", "access_key = " + aws_access_key() + "\n")
        result = self.scan()
        self.assertTrue(any(f.rule_id == "aws-access-key" for f in result.findings))

    def test_detects_private_key_marker_without_exposing_key_material(self):
        marker = "-----BEGIN " + "PRIVATE KEY" + "-----"
        end_marker = "-----END " + "PRIVATE KEY" + "-----"
        content = marker + "\nsynthetic-key-material\n" + end_marker + "\n"
        write_text(self.root / "key.pem", content)
        result = self.scan()
        self.assertTrue(any(f.rule_id == "private-key" for f in result.findings))
        self.assertNotIn("synthetic-key-material", json.dumps([f.to_dict() for f in result.findings]))

    def test_detects_quoted_generic_assignment_with_sufficient_length(self):
        value = generic_secret()
        write_text(self.root / "settings.py", "service_password = '" + value + "'\n")
        result = self.scan()
        self.assertTrue(any(f.rule_id == "generic-secret" for f in result.findings))
        self.assertNotIn(value, json.dumps([f.to_dict() for f in result.findings]))

    def test_ignores_common_placeholder_assignments(self):
        text = (
            'password = "' + "example" + '_value123456"\n'
            'api_key = "' + "changeme" + '_value123456"\n'
            'token = "' + "placeholder" + '_value123456"\n'
            'secret = "' + "your_" + 'value_goes_here_123"\n'
        )
        write_text(self.root / "template.env", text)
        result = self.scan()
        self.assertEqual(result.findings, [])

    def test_generic_assignment_requires_quoted_value(self):
        write_text(self.root / "plain.txt", "password = " + generic_secret() + "\n")
        result = self.scan()
        self.assertFalse(any(f.rule_id == "generic-secret" for f in result.findings))

    def test_finding_location_uses_one_based_line_and_column(self):
        token = github_token()
        line = "# harmless\nTOKEN=" + token + "\n"
        write_text(self.root / "nested" / "values.env", line)
        finding = self.scan().findings[0]
        self.assertEqual(finding.line, 2)
        self.assertEqual(finding.column, len("TOKEN=") + 1)
        self.assertGreaterEqual(finding.line, 1)
        self.assertGreaterEqual(finding.column, 1)

    def test_scanned_count_counts_readable_files(self):
        write_text(self.root / "a.txt", "no secret here\n")
        write_text(self.root / "b.txt", "also harmless\n")
        result = self.scan()
        self.assertEqual(result.scanned, 2)

    def test_deterministic_findings_and_traversal_order(self):
        write_text(self.root / "z" / "z.env", "x=" + github_token())
        write_text(self.root / "a.env", "x=" + aws_access_key())
        first = self.scan()
        second = self.scan()
        self.assertEqual([f.to_dict() for f in first.findings], [f.to_dict() for f in second.findings])
        self.assertEqual([f.path for f in first.findings], sorted(f.path for f in first.findings))

    def test_ignores_standard_generated_and_dependency_directories(self):
        for name in (".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "dist", "build"):
            write_text(self.root / name / "secret.env", "token=" + github_token())
        result = self.scan()
        self.assertEqual(result.findings, [])
        self.assertEqual(result.scanned, 0)

    def test_fnmatch_exclusion_applies_to_relative_paths(self):
        write_text(self.root / "keep" / "config.env", "key=" + aws_access_key())
        write_text(self.root / "private" / "one.env", "key=" + github_token())
        result = self.scan(exclude=("private/*.env",))
        self.assertEqual([f.path for f in result.findings], ["keep/config.env"])
        self.assertGreaterEqual(result.skipped.get("excluded", 0), 1)

    def test_binary_file_is_skipped_and_accounted_for(self):
        (self.root / "binary.dat").write_bytes(b"text\x00" + github_token().encode("ascii"))
        result = self.scan()
        self.assertEqual(result.findings, [])
        self.assertEqual(result.skipped.get("binary"), 1)

    def test_invalid_utf8_file_is_skipped_and_accounted_for(self):
        (self.root / "invalid.txt").write_bytes(b"\xff\xfe\xfa")
        result = self.scan()
        self.assertEqual(result.findings, [])
        self.assertEqual(result.skipped.get("encoding"), 1)

    def test_oversized_file_is_skipped_and_accounted_for(self):
        write_text(self.root / "large.txt", "x=" + github_token())
        result = self.scan(max_bytes=4)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.skipped.get("oversized"), 1)

    def test_max_bytes_must_be_positive(self):
        for value in (0, -1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.scan(max_bytes=value)

    def test_root_must_be_a_directory(self):
        file_path = write_text(Path(self.temp.name) / "not-a-dir", "x")
        with self.assertRaises(ValueError):
            scanner.scan(file_path)

    def test_root_symlink_is_rejected(self):
        link = Path(self.temp.name) / "root-link"
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("directory symlinks are unavailable")
        with self.assertRaises(ValueError):
            scanner.scan(link)

    def test_file_symlink_is_not_followed_or_scanned(self):
        external = Path(self.temp.name) / "external.env"
        write_text(external, "token=" + github_token())
        link = self.root / "linked.env"
        try:
            link.symlink_to(external)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable")
        result = self.scan()
        self.assertEqual(result.findings, [])
        self.assertEqual(result.skipped.get("symlink"), 1)

    def test_directory_symlink_is_not_followed(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        write_text(outside / "secret.env", "token=" + github_token())
        link = self.root / "linked-dir"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("directory symlinks are unavailable")
        result = self.scan()
        self.assertEqual(result.findings, [])
        self.assertGreaterEqual(result.skipped.get("symlink", 0), 1)

    def test_fingerprint_is_stable_when_secret_line_moves(self):
        token = github_token()
        first_path = write_text(self.root / "same.env", "TOKEN=" + token + "\n")
        first = self.scan().findings[0].fingerprint
        first_path.write_text("comment\ncomment\nTOKEN=" + token + "\n", encoding="utf-8")
        second = self.scan().findings[0].fingerprint
        self.assertEqual(first, second)

    def test_fingerprint_changes_with_salt(self):
        write_text(self.root / "same.env", "TOKEN=" + github_token() + "\n")
        default_fp = self.scan(salt="first-salt").findings[0].fingerprint
        other_fp = self.scan(salt="second-salt").findings[0].fingerprint
        self.assertNotEqual(default_fp, other_fp)

    def test_fingerprint_changes_with_path(self):
        token = github_token()
        write_text(self.root / "one.env", "TOKEN=" + token + "\n")
        first = self.scan().findings[0].fingerprint
        (self.root / "one.env").unlink()
        write_text(self.root / "two.env", "TOKEN=" + token + "\n")
        second = self.scan().findings[0].fingerprint
        self.assertNotEqual(first, second)

    def test_entropy_option_is_accepted_and_keeps_result_shape(self):
        write_text(self.root / "plain.txt", "ordinary source text\n")
        result = self.scan(entropy=True)
        self.assertIsInstance(result.findings, list)
        self.assertIsInstance(result.scanned, int)


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_create_baseline_has_version_salt_and_fingerprints(self):
        write_text(self.root / "credentials.env", "TOKEN=" + github_token())
        result = scanner.scan(self.root, salt=BASELINE_SALT)
        baseline_data = baseline.create_baseline(result, BASELINE_SALT)
        self.assertEqual(baseline_data["version"], 1)
        self.assertRegex(baseline_data["salt"], r"^[0-9a-f]{64}$")
        self.assertTrue(baseline_data["fingerprints"])
        self.assertNotIn(github_token(), json.dumps(baseline_data))

    def test_create_baseline_rejects_incomplete_scan(self):
        result = replace(scanner.scan(self.root), complete=False)
        with self.assertRaises(ValueError):
            baseline.create_baseline(result, BASELINE_SALT)

    def test_write_then_load_baseline_round_trips(self):
        result = scanner.scan(self.root, salt=BASELINE_SALT)
        payload = baseline.create_baseline(result, BASELINE_SALT)
        path = Path(self.temp.name) / "baseline.json"
        baseline.write_baseline(path, payload)
        self.assertEqual(baseline.load_baseline(path), payload)

    def test_load_baseline_rejects_invalid_json(self):
        path = Path(self.temp.name) / "bad.json"
        path.write_text("{broken", encoding="utf-8")
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            baseline.load_baseline(path)

    def test_load_baseline_rejects_unknown_schema_version(self):
        path = Path(self.temp.name) / "bad.json"
        path.write_text(json.dumps({"version": 99, "salt": "a" * 64, "fingerprints": []}), encoding="utf-8")
        with self.assertRaises(ValueError):
            baseline.load_baseline(path)

    def test_load_baseline_rejects_malformed_salt(self):
        path = Path(self.temp.name) / "bad.json"
        path.write_text(json.dumps({"version": 1, "salt": "A" * 64, "fingerprints": []}), encoding="utf-8")
        with self.assertRaises(ValueError):
            baseline.load_baseline(path)

    def test_filter_baseline_suppresses_preexisting_finding(self):
        write_text(self.root / "credentials.env", "TOKEN=" + github_token())
        initial = scanner.scan(self.root, salt=BASELINE_SALT)
        payload = baseline.create_baseline(initial, BASELINE_SALT)
        filtered = baseline.filter_baseline(initial, payload)
        self.assertEqual(filtered.findings, [])
        self.assertTrue(filtered.complete)

    def test_filter_baseline_keeps_new_distinct_finding(self):
        write_text(self.root / "old.env", "TOKEN=" + github_token())
        initial = scanner.scan(self.root, salt=BASELINE_SALT)
        payload = baseline.create_baseline(initial, BASELINE_SALT)
        write_text(self.root / "new.env", "TOKEN=" + aws_access_key())
        filtered = baseline.filter_baseline(scanner.scan(self.root, salt=BASELINE_SALT), payload)
        self.assertTrue(filtered.findings)
        self.assertTrue(all(f.path == "new.env" for f in filtered.findings))


if __name__ == "__main__":
    unittest.main()
