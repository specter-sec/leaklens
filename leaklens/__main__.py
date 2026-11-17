"""Command-line entry point: python -m leaklens."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile

from . import __version__
from .baseline import create_baseline, filter_baseline, load_baseline, write_baseline
from .reports import render
from .scanner import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="leaklens", description="Offline, redacted secret review. Not a safety guarantee.")
    parser.add_argument("--version", action="version", version="LeakLens " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "baseline"):
        child = sub.add_parser(name)
        child.add_argument("path", type=Path, help="Directory to scan; Git history is not scanned")
        child.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="Relative POSIX fnmatch pattern; repeatable")
        child.add_argument("--max-bytes", type=int, default=1048576, help="Skip files larger than this limit (default: 1 MiB)")
        child.add_argument("--entropy", action="store_true", help="Enable noisy high-entropy candidate detection")
        child.add_argument("--output", type=Path, required=name == "baseline", help="New file only; scan reports must be outside the scanned root")
        if name == "scan":
            child.add_argument("--format", choices=("text", "json", "sarif", "html"), default="text")
            child.add_argument("--baseline", type=Path, help="Previously reviewed version-1 baseline JSON")
    return parser


def _safe_new_output(path: Path, root: Path, *, baseline: bool) -> None:
    if path.is_symlink() or path.exists():
        raise ValueError("Output already exists; choose a new file")
    resolved = path.resolve()
    if not resolved.parent.is_dir():
        raise ValueError("Output parent directory must exist")
    if not baseline and resolved.is_relative_to(root.resolve()):
        raise ValueError("Scan report output must be outside the scanned directory")


def _write_new(path: Path, content: str) -> None:
    # O_EXCL refuses an existing file/symlink even if it appeared after validation.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.output:
            _safe_new_output(args.output, args.path, baseline=args.command == "baseline")
        baseline = load_baseline(args.baseline) if args.command == "scan" and args.baseline else None
        salt = baseline["salt"] if baseline else secrets.token_hex(32) if args.command == "baseline" else "leaklens-v1"
        result = scan(args.path, exclude=tuple(args.exclude), max_bytes=args.max_bytes, entropy=args.entropy, salt=salt)
        if args.command == "baseline":
            data = create_baseline(result, salt)
            # Exclusive creation: never replace an existing review baseline.
            _write_new(args.output, json.dumps(data, indent=2) + "\n")
            print("Created review baseline. Review every exception before use.")
            return 0
        if baseline:
            result = filter_baseline(result, baseline)
        content = render(result, args.format)
        if args.output:
            _write_new(args.output, content)
        else:
            sys.stdout.write(content)
        return 2 if not result.complete else 1 if result.findings else 0
    except (OSError, ValueError, UnicodeError, TypeError, KeyError):
        # Never echo exception text: it can include user filenames or source data.
        sys.stderr.write("LeakLens: invalid input or file operation failed. Check directory, baseline schema and new output path.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
