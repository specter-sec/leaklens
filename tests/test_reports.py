"""Report-only invariants; all findings here contain metadata, never real credentials."""
import json
import unittest
from leaklens.scanner import Finding, ScanResult
from leaklens.reports import render


class ReportTests(unittest.TestCase):
    def result(self, path='src/config.py', severity='high', complete=True):
        item = Finding(path, 2, 4, 'github-token', severity, 'GitHub token [REDACTED]', 'a' * 64)
        return ScanResult([item], 1, {'binary': 2}, [], complete)

    def test_json_round_trips_unicode_metadata(self):
        value = json.loads(render(self.result('notes/اردو.py'), 'json'))
        self.assertEqual(value['findings'][0]['path'], 'notes/اردو.py')
        self.assertIs(value['complete'], True)

    def test_sarif_has_unicode_column_kind_and_encoded_uri(self):
        run = json.loads(render(self.result('src/a b.py'), 'sarif'))['runs'][0]
        self.assertEqual(run['columnKind'], 'unicodeCodePoints')
        self.assertEqual(run['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'src/a%20b.py')

    def test_critical_is_sarif_error(self):
        run = json.loads(render(self.result(severity='critical'), 'sarif'))['runs'][0]
        self.assertEqual(run['results'][0]['level'], 'error')

    def test_incomplete_scan_is_reported_in_sarif(self):
        run = json.loads(render(self.result(complete=False), 'sarif'))['runs'][0]
        self.assertIs(run['invocations'][0]['executionSuccessful'], False)

    def test_html_does_not_include_active_content_from_filename(self):
        payload = '<script>alert(1)</script>.py'
        document = render(self.result(payload), 'html')
        self.assertNotIn(payload, document)
        self.assertIn('&lt;script&gt;', document)
        self.assertNotIn('<script>', document)
        self.assertIn("default-src 'none'", document)

    def test_terminal_escapes_control_characters(self):
        report = render(self.result('evil\x1b[31m\n.py'), 'text')
        self.assertNotIn('\x1b', report)
        self.assertIn('\\u001b', report)
        self.assertIn('\\n.py', report)

    def test_empty_html_avoids_claiming_safety(self):
        report = render(ScanResult([], 0, {}, [], True), 'html')
        self.assertIn('No matching findings', report)
        self.assertIn('does not guarantee safety', report)

    def test_unknown_report_format_rejected(self):
        with self.assertRaises(ValueError):
            render(self.result(), 'not-a-format')


if __name__ == '__main__':
    unittest.main()
