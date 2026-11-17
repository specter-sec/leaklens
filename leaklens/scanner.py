"""Deterministic, offline secret scanning with redacted public findings."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import stat

from .rules import RULES, Rule


@dataclass
class Finding:
    """A sanitized match; detected material is never stored on this object."""

    path: str
    line: int
    column: int
    rule_id: str
    severity: str
    message: str
    fingerprint: str

    def to_dict(self) -> dict[str, str | int]:
        """Return only the documented, redacted public representation."""
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanResult:
    findings: list[Finding]
    scanned: int
    skipped: dict[str, int]
    errors: list[str]
    complete: bool


_BUILTIN_OMISSIONS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "dist", "build"}
)
_SKIP_CATEGORIES = ("symlink", "binary", "oversized", "excluded", "encoding")
_PLACEHOLDER_EXACT = frozenset(
    {
        "example",
        "example_value",
        "example-value",
        "changeme",
        "change_me",
        "change-me",
        "placeholder",
        "your_secret",
        "your_token",
        "your_password",
        "your_api_key",
        "none",
        "null",
        "undefined",
        "redacted",
    }
)
_ENV_TEMPLATE_RE = re.compile(
    r"^(?:\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{.*\}\}|<[^>]*>|%[^%]*%)$"
)


def _salt_key(salt: str) -> bytes:
    try:
        return bytes.fromhex(salt)
    except ValueError:
        return salt.encode("utf-8")


def _fingerprint(key: bytes, relative: str, rule_id: str, value: str) -> str:
    payload = relative.encode("utf-8") + b"\0" + rule_id.encode("ascii") + b"\0" + value.encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_placeholder(value: str) -> bool:
    candidate = value.strip().lower()
    if candidate in _PLACEHOLDER_EXACT or _ENV_TEMPLATE_RE.fullmatch(candidate):
        return True
    if candidate.startswith(("your_", "your-", "example_", "example-", "changeme_", "changeme-", "placeholder_", "placeholder-")):
        return True
    return False


def _pattern_value(match: re.Match[str]) -> str:
    try:
        return match.group("value") or match.group(0)
    except (IndexError, KeyError):
        return match.group(0)


def _overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _excluded(relative: str, *, is_dir: bool, patterns: tuple[str, ...]) -> bool:
    for raw_pattern in patterns:
        pattern = raw_pattern.replace("\\", "/")
        if not pattern:
            continue
        if fnmatch.fnmatchcase(relative, pattern):
            return True
        # A trailing slash or /** denotes the named directory and its subtree.
        base = pattern[:-3] if pattern.endswith("/**") else pattern[:-1] if pattern.endswith("/") else None
        if base is not None:
            base = base.rstrip("/")
            if relative == base or relative.startswith(base + "/"):
                return True
        # A pattern that selects a directory suppresses all of its contents.
        if is_dir and fnmatch.fnmatchcase(relative + "/__leaklens_child__", pattern):
            return True
    return False


def scan(
    root: Path | str,
    *,
    exclude: tuple[str, ...] = (),
    max_bytes: int = 1_048_576,
    entropy: bool = False,
    salt: str = "leaklens-v1",
) -> ScanResult:
    """Scan a directory locally; file contents and matched values are never returned.

    Exclusions are ``fnmatch`` patterns against relative POSIX paths; ``*`` follows
    Python ``fnmatch`` semantics and can match ``/``. A pattern ending in ``/`` or
    ``/**`` excludes that directory and its descendants. Built-in generated/vendor
    directories are omitted independently of this user-supplied pattern list.
    """
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if isinstance(exclude, str) or not isinstance(exclude, tuple):
        raise ValueError("exclude must be a tuple of glob patterns")
    root_path = Path(root)
    if root_path.is_symlink():
        raise ValueError("root must be a directory, not a symlink")
    try:
        if not root_path.is_dir():
            raise ValueError("root must be a directory")
    except OSError:
        raise ValueError("root must be a readable directory") from None

    omissions = {"symlink": 0, "binary": 0, "oversized": 0, "excluded": 0, "encoding": 0}
    errors: list[str] = []
    findings: list[Finding] = []
    scanned = 0
    complete = True
    key = _salt_key(salt)
    rules: tuple[Rule, ...] = tuple(rule for rule in RULES if entropy or rule.id != "high-entropy")

    def visit(directory: Path) -> None:
        nonlocal complete, scanned
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            complete = False
            errors.append("Unable to read a directory.")
            return

        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root_path).as_posix()
            try:
                if entry.is_symlink():
                    omissions["symlink"] += 1
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                complete = False
                errors.append("Unable to inspect a filesystem entry.")
                continue

            if any(part in _BUILTIN_OMISSIONS for part in Path(relative).parts):
                omissions["excluded"] += 1
                continue
            if _excluded(relative, is_dir=is_dir, patterns=exclude):
                omissions["excluded"] += 1
                continue
            if is_dir:
                visit(path)
                continue
            if not is_file:
                omissions["excluded"] += 1
                continue

            try:
                initial = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(initial.st_mode):
                    omissions["excluded"] += 1
                    continue
                if initial.st_size > max_bytes:
                    omissions["oversized"] += 1
                    continue
                flags = os.O_RDONLY
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(path, flags)
                try:
                    opened = os.fstat(fd)
                    if not stat.S_ISREG(opened.st_mode):
                        omissions["excluded"] += 1
                        continue
                    if opened.st_size > max_bytes:
                        omissions["oversized"] += 1
                        continue
                    with os.fdopen(fd, "rb", closefd=False) as stream:
                        raw = stream.read(max_bytes + 1)
                finally:
                    os.close(fd)
            except OSError:
                # No exception text or file contents are included in public errors.
                complete = False
                errors.append("Unable to read a file.")
                continue

            if len(raw) > max_bytes:
                omissions["oversized"] += 1
                continue
            if b"\0" in raw:
                omissions["binary"] += 1
                continue
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                omissions["encoding"] += 1
                continue

            scanned += 1
            # Internal match tuples retain raw text only for the duration of this file.
            candidates: list[tuple[Rule, re.Match[str], tuple[int, int], str]] = []
            for rule in rules:
                for match in rule.pattern.finditer(text):
                    value = _pattern_value(match)
                    if rule.id == "generic-secret" and _is_placeholder(value):
                        continue
                    if rule.id == "high-entropy" and _entropy(value) < 3.5:
                        continue
                    if not value:
                        continue
                    start, end = match.span("value") if "value" in match.re.groupindex else match.span()
                    candidates.append((rule, match, (start, end), value))

            stronger = [span for rule, _, span, _ in candidates if rule.id not in {"generic-secret", "high-entropy"}]
            filtered: list[tuple[Rule, re.Match[str], tuple[int, int], str]] = []
            for candidate in candidates:
                rule, _, span, _ = candidate
                if rule.id in {"generic-secret", "high-entropy"} and any(_overlaps(span, other) for other in stronger):
                    continue
                filtered.append(candidate)

            seen: set[tuple[str, int, int, str]] = set()
            for rule, match, span, value in filtered:
                start = span[0]
                line = text.count("\n", 0, start) + 1
                line_start = text.rfind("\n", 0, start) + 1
                column = start - line_start + 1
                fingerprint = _fingerprint(key, relative, rule.id, value)
                unique_key = (rule.id, line, column, fingerprint)
                if unique_key in seen:
                    continue
                seen.add(unique_key)
                findings.append(
                    Finding(
                        path=relative,
                        line=line,
                        column=column,
                        rule_id=rule.id,
                        severity=rule.severity,
                        message=f"{rule.name} [REDACTED]",
                        fingerprint=fingerprint,
                    )
                )

    visit(root_path)
    findings.sort(key=lambda finding: (finding.path, finding.line, finding.column, finding.rule_id, finding.fingerprint))
    return ScanResult(findings=findings, scanned=scanned, skipped=omissions, errors=errors, complete=complete)
