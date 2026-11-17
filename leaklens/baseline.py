"""Validated, atomic persistence for LeakLens finding fingerprints."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .scanner import ScanResult


_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_BASELINE_KEYS = frozenset({"version", "salt", "fingerprints"})


def _validate_baseline(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _BASELINE_KEYS:
        raise ValueError("invalid baseline format")
    version = value.get("version")
    salt = value.get("salt")
    fingerprints = value.get("fingerprints")
    if type(version) is not int or version != 1:
        raise ValueError("invalid baseline format")
    if not isinstance(salt, str) or _HEX_64.fullmatch(salt) is None:
        raise ValueError("invalid baseline format")
    if not isinstance(fingerprints, list):
        raise ValueError("invalid baseline format")
    if any(not isinstance(item, str) or _HEX_64.fullmatch(item) is None for item in fingerprints):
        raise ValueError("invalid baseline format")
    if len(set(fingerprints)) != len(fingerprints):
        raise ValueError("invalid baseline format")
    return {"version": 1, "salt": salt, "fingerprints": list(fingerprints)}


def create_baseline(result: ScanResult, salt: str) -> dict[str, Any]:
    """Build a version-1 baseline from a complete scan result."""
    if not result.complete:
        raise ValueError("cannot create a baseline from an incomplete scan")
    if not isinstance(salt, str) or _HEX_64.fullmatch(salt) is None:
        raise ValueError("salt must be 64 lowercase hexadecimal characters")
    fingerprints = sorted({finding.fingerprint for finding in result.findings})
    return _validate_baseline({"version": 1, "salt": salt, "fingerprints": fingerprints})


def load_baseline(path: Path | str) -> dict[str, Any]:
    """Load and strictly validate a baseline without exposing parser details."""
    try:
        raw = Path(path).read_bytes()
        text = raw.decode("utf-8", errors="strict")

        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("invalid baseline format")
                result[key] = item
            return result

        parsed = json.loads(text, object_pairs_hook=reject_duplicate_keys)
        return _validate_baseline(parsed)
    except ValueError:
        raise ValueError("invalid baseline format") from None
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
        raise ValueError("invalid baseline format") from None


def filter_baseline(result: ScanResult, baseline: dict[str, Any]) -> ScanResult:
    """Return a copy whose findings are not already represented in a baseline."""
    valid = _validate_baseline(baseline)
    known = set(valid["fingerprints"])
    return replace(result, findings=[finding for finding in result.findings if finding.fingerprint not in known])


def write_baseline(path: Path | str, baseline: dict[str, Any]) -> None:
    """Atomically write a validated baseline with owner-only permissions."""
    valid = _validate_baseline(baseline)
    destination = Path(path)
    if destination.is_symlink():
        raise ValueError("refusing to write through a symlink")
    parent = destination.parent
    payload = json.dumps(valid, sort_keys=True, separators=(",", ":")) + "\n"
    fd = -1
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=parent)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # Recheck immediately before replace. os.replace replaces a symlink itself,
        # never follows it, so even a concurrent replacement cannot modify its target.
        if destination.is_symlink():
            raise ValueError("refusing to write through a symlink")
        os.replace(temporary, destination)
        temporary = None
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass
