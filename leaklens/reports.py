"""Render findings without source excerpts or credential values."""
from __future__ import annotations

import html
import json
from collections import Counter
from urllib.parse import quote

from . import __version__
from .scanner import ScanResult


def render(result: ScanResult, format: str = "text") -> str:
    """Return a report; HTML contains no JavaScript or remote resources."""
    findings = [item.to_dict() for item in result.findings]
    if format == "json":
        return json.dumps({"tool": "LeakLens", "version": __version__,
                           "complete": result.complete, "scanned": result.scanned,
                           "skipped": result.skipped, "errors": result.errors,
                           "findings": findings}, indent=2, ensure_ascii=True) + "\n"
    if format == "sarif":
        ids = sorted({item.rule_id for item in result.findings})
        return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"columnKind": "unicodeCodePoints", "tool": {"driver": {"name": "LeakLens", "version": __version__,
                "informationUri": "https://github.com/specter-sec/leaklens",
                "rules": [{"id": rule} for rule in ids]}},
                "invocations": [{"executionSuccessful": result.complete}],
                "results": [{"ruleId": item.rule_id,
                    "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(item.severity, "warning"),
                    "message": {"text": item.message},
                    "partialFingerprints": {"leaklens/v1": item.fingerprint},
                    "locations": [{"physicalLocation": {"artifactLocation": {
                        "uri": quote(item.path, safe="/")}, "region": {
                            "startLine": item.line, "startColumn": item.column}}}]} for item in result.findings]}]}, indent=2) + "\n"
    if format == "html":
        return _html(result)
    if format != "text":
        raise ValueError("Unsupported report format")
    rows = [f"LeakLens {__version__} | offline secret review", "=" * 58,
            f"Files scanned: {result.scanned} | Findings: {len(findings)} | Complete: {result.complete}",
            f"Skipped: {sum(result.skipped.values())} (see JSON for reasons)"]
    for item in result.findings:
        # Escapes control characters in filenames to prevent terminal injection.
        path = json.dumps(item.path, ensure_ascii=True)
        rows.append(f"{item.severity.upper():6} {path}:{item.line}:{item.column}  {item.rule_id}  [REDACTED]")
    if result.errors:
        rows.append("Scan errors: " + str(len(result.errors)) + "; review JSON for safe error categories.")
    rows.append("Rotate confirmed exposed credentials. A clean scan is not proof of safety.")
    return "\n".join(rows) + "\n"


def _html(result: ScanResult) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    counts = Counter(item.severity for item in result.findings)
    rows = "".join(f'<tr><td><span class="severity">{esc(item.severity.upper())}</span></td>'
                   f'<td><strong>{esc(item.rule_id)}</strong><br><code>{esc(item.path)}:{item.line}:{item.column}</code></td>'
                   '<td class="redacted">[REDACTED]</td></tr>' for item in result.findings)
    if not rows:
        rows = '<tr><td colspan="3">No matching findings. Review coverage and skipped files before concluding.</td></tr>'
    skipped = " · ".join(f"{esc(key)}: {value}" for key, value in sorted(result.skipped.items())) or "None"
    errors = "".join(f"<li>{esc(error)}</li>" for error in result.errors)
    return '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>LeakLens · Offline security review</title><style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1219;color:#e5eef1}*{box-sizing:border-box}body{margin:0}main{max-width:1120px;margin:auto;padding:44px 28px}header{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #2c3b44;padding-bottom:24px}.brand{font-size:25px;font-weight:800;letter-spacing:-1px}.brand span{color:#79e6c7}.badge,.eyebrow{color:#79e6c7;letter-spacing:2px;font-size:12px}.badge{border:1px solid #345449;border-radius:20px;padding:9px 14px;letter-spacing:1px}h1{font-size:clamp(34px,5vw,60px);line-height:1.08;letter-spacing:-2px;margin:14px 0}p{color:#a9bdc6;line-height:1.7;max-width:720px}.intro{padding:34px 0 24px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.stat{border:1px solid #2c3b44;background:#111e27;padding:22px;border-radius:12px}.stat b{display:block;font-size:34px;margin-top:8px}.stat span{font-size:12px;letter-spacing:1px;color:#9eb6c1}h2{font-size:22px;margin:34px 0 18px}.table-wrap{overflow:auto;border:1px solid #2c3b44;border-radius:12px}table{border-collapse:collapse;width:100%;text-align:left}th{background:#14242e;font-size:11px;letter-spacing:1.5px;color:#9eb6c1}th,td{padding:19px;border-bottom:1px solid #263740}tr:last-child td{border:0}code{font-size:12px;color:#a5bdc8;overflow-wrap:anywhere}.severity{font-size:11px;letter-spacing:1px;color:#ffca88}.redacted{font-family:monospace;color:#79e6c7;white-space:nowrap}.note{margin-top:24px;padding:18px 22px;background:#14231f;border-left:3px solid #79e6c7;font-size:14px}.note p{margin:0}.coverage{font-size:13px}footer{margin-top:34px;padding-top:20px;border-top:1px solid #2c3b44;color:#8da5b0;font-size:12px}@media(max-width:640px){main{padding:24px 16px}.stats{grid-template-columns:repeat(2,1fr)}.stat{padding:16px}th,td{padding:12px}.badge{font-size:9px;letter-spacing:0}header{gap:16px}h1{letter-spacing:-1px}}
</style></head><body><main><header><div class="brand">Leak<span>Lens</span> / 01</div><div class="badge">LOCAL SCAN · ZERO UPLOADS</div></header><section class="intro"><div class="eyebrow">DEVELOPER SECURITY / REVIEW REPORT</div><h1>Find the leak.<br>Keep the secret private.</h1><p>Potential credentials, surfaced for review. Credential values and source excerpts are omitted from this report. No network validation or upload is performed.</p></section>''' + (
        f'<section class="stats" aria-label="Scan summary"><div class="stat"><span>FILES SCANNED</span><b>{result.scanned}</b></div>'
        f'<div class="stat"><span>FINDINGS</span><b>{len(result.findings):02d}</b></div>'
        f'<div class="stat"><span>HIGH / CRITICAL</span><b>{counts["high"] + counts["critical"]:02d}</b></div>'
        f'<div class="stat"><span>SCAN COMPLETE</span><b>{"Yes" if result.complete else "No"}</b></div></section>'
        '<h2>Review queue</h2><div class="table-wrap"><table><thead><tr><th>SEVERITY</th><th>DETECTION / LOCATION</th><th>VALUE</th></tr></thead>'
        f'<tbody>{rows}</tbody></table></div><div class="note"><p><strong>Review, revoke, rotate.</strong> Confirm locally, revoke exposed credentials at their provider, and inspect usage. A baseline is an exception list, not a security fix.</p></div>'
        f'<p class="coverage"><strong>Skipped files:</strong> {skipped}<br>Coverage excludes Git history, archives, binary files, oversized files, invalid UTF-8, and ignored paths. A clean result does not guarantee safety.</p>'
        f'<ul class="coverage">{errors}</ul><footer>LeakLens {esc(__version__)} · By IFTIKHAR · Generated locally · No telemetry, scripts, remote fonts or external assets</footer></main></body></html>')
