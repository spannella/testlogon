"""Shared URL validation utilities (GAP-0079 / SEC-021).

`validate_repo_url` rejects repository URLs that could break out of a shell
``git clone`` command string (command injection). It is applied before any
``repo_url`` value is interpolated into a workflow ``command`` field by the
coder/architect agent services.
"""

from __future__ import annotations

import re

# Shell metacharacters (and control chars) that must never appear in a repo URL.
# Includes the literal escape sequences ``\n``/``\r``/``\t`` and any raw
# control character 0x00-0x1f, which covers percent-decoded newlines once
# decoded as well as raw embedded newlines.
_SHELL_META_RE = re.compile(r"[;&|`$<>(){}\[\]'\"\\\s]|[\x00-\x1f]")
# Percent-encoded newline / carriage-return / tab variants.
_PCT_NEWLINE_RE = re.compile(r"%0[09adAD]", re.IGNORECASE)
# Dangerous git transports / local paths.
_DANGEROUS_PROTO_RE = re.compile(r"^(ext::|fd::|fd://|file://|/|\.\.)", re.IGNORECASE)
# Only https:// and git@ SSH form are permitted.
_ALLOWED_PROTO_RE = re.compile(r"^(https://|git@)")


def validate_repo_url(v: str) -> str:
    """Validate a repository URL for safe use in shell command strings.

    Allows: ``https://...`` and ``git@host:user/repo``.
    Rejects: shell metacharacters, percent-encoded newlines, dangerous git
    transports (``ext::``, ``file://`` ...), local paths, control chars, spaces.

    Returns the URL unchanged when valid; raises ``ValueError`` otherwise.
    Empty input is returned unchanged (callers decide whether empty is allowed).
    """
    if not v:
        return v
    if len(v) > 500:
        raise ValueError("Repository URL too long (max 500)")
    if _DANGEROUS_PROTO_RE.match(v):
        raise ValueError("Repository URL uses a dangerous protocol")
    if not _ALLOWED_PROTO_RE.match(v):
        raise ValueError("Repository URL must start with https:// or git@")
    if _PCT_NEWLINE_RE.search(v):
        raise ValueError("Repository URL contains forbidden percent-encoded control characters")
    if _SHELL_META_RE.search(v):
        raise ValueError("Repository URL contains forbidden shell metacharacters")
    return v
