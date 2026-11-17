"""Built-in, local-only detection rules used by LeakLens."""

from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Rule:
    """A named, compiled detector; patterns never imply credential validation."""

    id: str
    name: str
    severity: str
    pattern: re.Pattern[str]


RULES: tuple[Rule, ...] = (
    Rule(
        id="github-token",
        name="GitHub token",
        severity="high",
        pattern=re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{82})(?![A-Za-z0-9_])"),
    ),
    Rule(
        id="aws-access-key",
        name="AWS access key ID",
        severity="high",
        pattern=re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])"),
    ),
    Rule(
        id="private-key",
        name="Private key header",
        severity="critical",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    Rule(
        id="generic-secret",
        name="Generic secret assignment",
        severity="medium",
        pattern=re.compile(
            r"(?i)\b(?:[A-Za-z0-9]+[_-])*(?:api_key|api-key|apikey|secret|token|password)"
            r"(?:[_-][A-Za-z0-9]+)*\b"
            r"\s*[:=]\s*(?P<quote>['\"])(?P<value>[^'\"\s]{12,})(?P=quote)"
        ),
    ),
    Rule(
        id="high-entropy",
        name="High-entropy value",
        severity="low",
        pattern=re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{24,}(?![A-Za-z0-9])"),
    ),
)
