"""Regression tests for GAP-0094 — ``repo_branch`` shell injection in
``app/services/agent_architect.py``.

Offline / no AWS / no command execution: exercises the pure validation and
command-builder functions directly.

The ``clone_repo`` step f-strings the configured ``repo_branch`` into a
``git clone --depth 1 -b <branch> -- <url> /workspace`` shell command. A branch
like ``main;rm -rf /`` or ``$(id)`` must not survive as separate shell
commands/operators, and the config-write validator must reject it.

Fails-before / passes-after:
- ``validate_architect_config`` returns a branch error for a malicious branch.
- ``build_architect_workflow`` produces a clone command that tokenizes
  (``shlex.split``) with the (sanitized) branch as a single inert token.
- A normal branch (``feature/safe-branch``) passes validation unchanged.
"""

import shlex

import pytest

from app.services.agent_architect import (
    validate_architect_config,
    build_architect_workflow,
)

_MALICIOUS_BRANCHES = [
    "main;rm -rf /",
    "main && id",
    "$(reboot)",
    "`id`",
    "main|cat /etc/passwd",
    "main..evil",
    "-b other",
]

_SAFE_BRANCHES = [
    "main",
    "feature/safe-branch",
    "release-1.2.3",
    "fix_typo",
]


@pytest.mark.parametrize("branch", _MALICIOUS_BRANCHES)
def test_validate_rejects_malicious_branch(branch):
    errors = validate_architect_config(
        {"repo_url": "https://github.com/org/repo", "repo_branch": branch}
    )
    assert any("branch" in e.lower() for e in errors), f"got: {errors}"


@pytest.mark.parametrize("branch", _SAFE_BRANCHES)
def test_validate_accepts_safe_branch(branch):
    errors = validate_architect_config(
        {"repo_url": "https://github.com/org/repo", "repo_branch": branch}
    )
    assert not any("branch" in e.lower() for e in errors), f"got: {errors}"


@pytest.mark.parametrize("branch", _MALICIOUS_BRANCHES)
def test_clone_command_neutralizes_malicious_branch(branch):
    wf = build_architect_workflow(
        agent_run_id="t",
        config={"repo_url": "https://github.com/org/repo", "repo_branch": branch},
        ticket={"ticket_id": "T-1", "title": "x", "description": "y"},
    )
    clone = next(s for s in wf["steps"] if s["type"] == "clone_repo")
    cmd = clone["command"]
    tokens = shlex.split(cmd)  # raises if quoting is unbalanced
    # git clone --depth 1 -b <branch> -- <url> /workspace
    assert tokens[:3] == ["git", "clone", "--depth"]
    assert "-b" in tokens
    branch_tok = tokens[tokens.index("-b") + 1]
    # The branch is sanitized to git-safe chars (no shell metacharacters at all),
    # so the whole malicious payload collapses into a single inert branch token
    # that git treats as one (non-existent) ref — never as extra shell commands.
    assert all(c.isalnum() or c in "_/-." for c in branch_tok), branch_tok
    # No shell operator survives anywhere in the tokenized command.
    assert not any(t in (";", "&&", "||", "|", "&") for t in tokens), tokens
    # The fixed command structure stays intact (payload didn't displace argv).
    assert tokens[3] == "1" and tokens[5] == branch_tok and "--" in tokens


def test_clone_command_preserves_safe_branch():
    wf = build_architect_workflow(
        agent_run_id="t",
        config={
            "repo_url": "https://github.com/org/repo",
            "repo_branch": "feature/safe-branch",
        },
        ticket={"ticket_id": "T-1", "title": "x", "description": "y"},
    )
    clone = next(s for s in wf["steps"] if s["type"] == "clone_repo")
    tokens = shlex.split(clone["command"])
    assert "feature/safe-branch" in tokens
