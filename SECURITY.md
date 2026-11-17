# Security policy

## Supported release

The current 1.x code line is maintained on a best-effort basis. This small educational tool has no response-time guarantee and is not a security boundary.

## Report a vulnerability privately

Use GitHub's private vulnerability reporting option for this repository if it is available. Otherwise contact the maintainer through the contact channel displayed on the `specter-sec` profile. Do not put live credentials or private source content in a public issue. Public issues are fine for ordinary bugs with minimal synthetic examples.

Useful reports describe the affected revision, a minimal synthetic reproduction, expected behavior, actual behavior and impact. A detector missing a provider that is not in the documented coverage is generally a feature request, not a vulnerability.

## Handling real leaks

Rotate or revoke a confirmed exposed credential at its provider before sharing any report. Review usage and access logs. Removing a string from a checkout does not remove it from Git history or revoke it. Do not test credentials against live services on the maintainer's behalf.

Redacted reports still expose paths and security-relevant metadata. Baseline salts are public and fingerprints are not encryption: low-entropy values can be guessed. Keep source, reports and baselines under appropriate access controls.

The scanner assumes a trusted local filesystem that is not being changed concurrently by an adversary. Do not treat symlink checks or file-size limits as isolation from a hostile process.
