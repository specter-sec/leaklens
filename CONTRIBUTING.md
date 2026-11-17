# Contributing to LeakLens

Thanks for improving a small, privacy-first developer utility. Keep changes focused and explain the problem, threat model and expected behavior in your pull request.

## Local checks

Use Python 3.11 or newer from the repository root:

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q leaklens tests demo.py
python3 -m leaklens scan .
```

No third-party test framework or runtime library is needed. New runtime dependencies need explicit discussion because offline and Termux portability are design goals.

## Detection rules

Add positive, negative, boundary and redaction tests. Document false positives and false negatives. Use synthetic values assembled from fragments at runtime, not full token-looking literals or real credentials. Avoid catastrophic-backtracking regexes; input size is bounded but regex complexity still matters. Never add credential validation calls or source excerpts to outputs.

## Privacy and output contract

Terminal, JSON, HTML and SARIF outputs must omit matched secret values and source lines. Test HTML escaping, control-character filenames, malformed baselines, symlinks and output overwrite behavior. Relative paths are still metadata and must be described honestly. Preserve documented exit codes and fail closed on incomplete scans.

Baselines are reviewed exceptions, not a remediation mechanism. Changes must not silently add exceptions, alter a user's source, or follow symlinks into unrelated trees.

## Reviews and conduct

Be respectful, explain tradeoffs and critique code rather than people. Do not include personal data, real secrets, private repository contents or unsupported security claims. Security-sensitive disclosures belong in the private channel described in SECURITY.md.
