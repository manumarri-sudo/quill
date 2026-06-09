"""Credential / secret detection for file-write tool arguments.

When an agent's Edit / Write / NotebookEdit call would land a hardcoded
credential in a file (the GitHub PAT leak failure mode, Anthropic's
November 2025 incident class), Quill catches it before the write
executes. The scanner runs deterministically on the new content; no
LLM, no network call.

Patterns are conservative on purpose - false positives here mean
asking the operator to confirm a non-secret, which is acceptable.
False negatives mean shipping a credential, which is not. Each
pattern is documented with its source provider format so a future
maintainer can verify against the vendor's published key shape.

The pattern set is intentionally smaller than truffleHog's 700+ -
this module ships the 18 highest-confidence patterns that cover
the bulk of agent-leaked credentials seen in the wild, with room
to grow via the optional `extra_patterns` argument to `scan`.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final


@dataclass(frozen=True, slots=True)
class SecretPattern:
    """One credential type Quill detects."""

    name: str               # "AWS Access Key", "OpenAI API Key", ...
    regex: re.Pattern[str]  # compiled at module load
    description: str = ""


@dataclass(frozen=True, slots=True)
class SecretHit:
    """One match found by scan()."""

    pattern_name: str
    matched_at: int       # offset in scanned text
    length: int           # match length (we never persist the value)


# Vendor-format credential patterns. Each regex is anchored to the
# vendor's published key prefix where possible; ambiguous patterns
# (e.g. JWT) require >= 3 segments to reduce FPs on random base64.
_PATTERNS: Final[tuple[SecretPattern, ...]] = (
    SecretPattern(
        name="AWS Access Key ID",
        regex=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        description="AWS Access Key ID (programmatic IAM credentials)",
    ),
    SecretPattern(
        name="OpenAI API Key (legacy)",
        regex=re.compile(r"\bsk-[A-Za-z0-9]{48}\b"),
        description="OpenAI API key, classic format",
    ),
    SecretPattern(
        name="OpenAI Project API Key",
        regex=re.compile(r"\bsk-proj-[A-Za-z0-9_-]{60,}\b"),
        description="OpenAI project-scoped API key (2024+ format)",
    ),
    SecretPattern(
        name="Anthropic API Key",
        regex=re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b"),
        description="Anthropic API key (sk-ant-apiNN- / sk-ant-adminNN-)",
    ),
    SecretPattern(
        name="GitHub Personal Access Token (classic)",
        regex=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        description="GitHub classic PAT",
    ),
    SecretPattern(
        name="GitHub Personal Access Token (fine-grained)",
        regex=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        description="GitHub fine-grained PAT",
    ),
    SecretPattern(
        name="GitHub OAuth token",
        regex=re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
        description="GitHub OAuth access token",
    ),
    SecretPattern(
        name="GitHub App token",
        regex=re.compile(r"\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b"),
        description="GitHub App user / server token",
    ),
    SecretPattern(
        name="Stripe Live Secret Key",
        regex=re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
        description="Stripe production secret key",
    ),
    SecretPattern(
        name="Stripe Test Secret Key",
        regex=re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b"),
        description="Stripe test-mode secret key",
    ),
    SecretPattern(
        name="Stripe Restricted Key",
        regex=re.compile(r"\brk_(?:live|test)_[A-Za-z0-9]{24,}\b"),
        description="Stripe restricted API key",
    ),
    SecretPattern(
        name="Slack Bot Token",
        regex=re.compile(r"\bxoxb-[A-Za-z0-9-]{50,}\b"),
        description="Slack bot user OAuth token",
    ),
    SecretPattern(
        name="Slack User Token",
        regex=re.compile(r"\bxoxp-[A-Za-z0-9-]{50,}\b"),
        description="Slack user OAuth token",
    ),
    SecretPattern(
        name="Slack Webhook URL",
        regex=re.compile(
            r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}\b",
        ),
        description="Slack incoming-webhook URL",
    ),
    SecretPattern(
        name="Google API Key",
        regex=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        description="Google Cloud / Firebase / Maps API key",
    ),
    SecretPattern(
        name="JWT",
        regex=re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        ),
        description="JSON Web Token (three base64url segments)",
    ),
    SecretPattern(
        name="Private Key (PEM block)",
        regex=re.compile(
            r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|ENCRYPTED|PGP)?\s*PRIVATE KEY-----",
        ),
        description="PEM-encoded private key header",
    ),
    SecretPattern(
        name="HuggingFace Token",
        regex=re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
        description="HuggingFace user access token",
    ),
)


def patterns() -> tuple[SecretPattern, ...]:
    """Read-only view of the built-in pattern set."""
    return _PATTERNS


def scan(
    text: str,
    *,
    extra_patterns: Iterable[SecretPattern] = (),
) -> list[SecretHit]:
    """Find every credential match in `text`.

    Conservative: a single text body is scanned against every pattern;
    each match contributes one SecretHit. The matched value is NEVER
    persisted in the hit (only the pattern name, offset, and length),
    so the scanner can be used safely on audit-logged content.

    `extra_patterns` lets the caller append custom org-specific patterns
    (e.g. an internal token prefix) without forking this module.
    """
    if not text:
        return []
    hits: list[SecretHit] = []
    for pat in (*_PATTERNS, *extra_patterns):
        for m in pat.regex.finditer(text):
            hits.append(
                SecretHit(
                    pattern_name=pat.name,
                    matched_at=m.start(),
                    length=m.end() - m.start(),
                ),
            )
    return hits


# Which Claude Code / Cursor tool-call args carry file content that
# should be scanned. The keys are tool names, the values are the arg
# names whose string values to scan.
_SCANNABLE_ARGS: Final[Mapping[str, tuple[str, ...]]] = {
    "Edit": ("new_string", "content"),
    "MultiEdit": ("new_string",),
    "Write": ("content", "text"),
    "NotebookEdit": ("new_source", "source"),
}


def scan_args(tool_name: str, args: Mapping[str, Any]) -> list[SecretHit]:
    """Scan a tool-call's args for credential leaks.

    Only file-write tools are scanned (Edit / MultiEdit / Write /
    NotebookEdit). Other tool names return an empty hit list.

    String args are scanned directly; list-valued args (MultiEdit's
    `edits` list) are walked one element at a time. Non-string,
    non-list values are ignored.
    """
    keys = _SCANNABLE_ARGS.get(tool_name)
    if not keys:
        return []
    hits: list[SecretHit] = []
    for k in keys:
        v = args.get(k)
        if isinstance(v, str):
            hits.extend(scan(v))
    # MultiEdit's edits is a list[dict] each with old_string + new_string.
    edits = args.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict):
                ns = edit.get("new_string")
                if isinstance(ns, str):
                    hits.extend(scan(ns))
    return hits


def hit_summary(hits: list[SecretHit]) -> str:
    """One-line summary of detected secrets, safe to put in audit log."""
    if not hits:
        return ""
    by_pattern: dict[str, int] = {}
    for h in hits:
        by_pattern[h.pattern_name] = by_pattern.get(h.pattern_name, 0) + 1
    parts = [
        f"{n}×{name}" if n > 1 else name
        for name, n in sorted(by_pattern.items())
    ]
    return ", ".join(parts)
