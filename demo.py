"""Create only fictional local fixtures for a safe demonstration.

Usage: python demo.py /tmp/leaklens-demo
Refuses an existing destination; no real credentials or networking involved.
"""
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python demo.py NEW_DIRECTORY", file=sys.stderr)
        return 2
    target = Path(sys.argv[1])
    target.mkdir(parents=False, exist_ok=False)
    (target / "service.env").write_text('GITHUB_TOKEN="' + 'gh' + 'p_' + 'A1b2C3' * 6 + '"\n', encoding="utf-8")
    (target / "cloud.conf").write_text('access_id=' + 'AK' + 'IA' + '1234ABCD' * 2 + '\n', encoding="utf-8")
    (target / "settings.py").write_text('password = "' + 'only-local-demo-' + 'not-a-real-password' + '"\n', encoding="utf-8")
    (target / "README.txt").write_text("Fictional fixtures generated locally. Do not use as credentials.\n", encoding="utf-8")
    print("Created 4 fictional local fixture files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
