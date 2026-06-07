"""Unit tests for AGENT-007 Agent PR & Ticket Integration service.

Covers the pure-logic helpers (git state detection, work summary
generation, status flow defaults, gh command escaping, and webhook
signature verification) which require no AWS/DDB access.
"""

from __future__ import annotations

import hashlib
import hmac
from types import SimpleNamespace

import pytest

from app.services import agent_pr_integration as svc


def _patch_settings(monkeypatch, **fields):
    """Replace the service's frozen Settings with a mutable stub."""
    base = {
        "github_webhook_secret": "",
        "github_token": "",
        "dev_mode": True,
        "github_api_base_url": "https://api.github.com",
    }
    base.update(fields)
    monkeypatch.setattr(svc, "S", SimpleNamespace(**base), raising=True)


def test_detect_git_state_branch_and_pr():
    out = (
        "On branch agent/w_123/tkt_9\n"
        "3 commits ahead of origin\n"
        "5 files changed, 42 insertions(+)\n"
        "Pull request created: https://github.com/org/repo/pull/42\n"
        "Enumerating objects: 12, done.\n"
    )
    state = svc.detect_git_state(out)
    assert state["branch"] == "agent/w_123/tkt_9"
    assert state["commit_count"] == 3
    assert state["files_changed"] == 5
    assert state["pr_url"] == "https://github.com/org/repo/pull/42"
    assert state["pushed"] is True


def test_detect_git_state_empty():
    state = svc.detect_git_state("")
    assert state == {
        "branch": "",
        "commit_count": 0,
        "files_changed": 0,
        "pr_url": "",
        "pushed": False,
    }


def test_generate_work_summary_extracts_fields():
    out = (
        "modified: app/foo.py\n"
        "new file: app/bar.py\n"
        "deleted: app/old.py\n"
        "[DECISION] used a queue instead of a list\n"
        "[RESOLVED] fixed flaky import\n"
        "12 tests passed, 0 failed\n"
    )
    summary = svc.generate_work_summary(out, "tkt_1", "coder")
    assert set(summary["files_changed"]) == {"app/foo.py", "app/bar.py", "app/old.py"}
    assert summary["test_results"] == {"passed": 12, "failed": 0}
    assert "used a queue instead of a list" in summary["decisions"]
    assert "fixed flaky import" in summary["errors_resolved"]
    assert "tkt_1" in summary["text"]
    assert "coder" in summary["text"]


def test_generate_work_summary_empty_output():
    summary = svc.generate_work_summary("", "tkt_2", "qa")
    assert summary["files_changed"] == []
    assert summary["decisions"] == []
    assert summary["test_results"] == {}
    assert summary["text"].startswith("Ticket: tkt_2")


def test_default_status_flows_coder_chain():
    flow = svc.DEFAULT_STATUS_FLOWS["coder"]
    assert flow["on_claim"] == "in_progress"
    assert flow["on_complete"] == "code_complete"
    assert flow["on_pr_created"] == "in_review"
    assert flow["on_pr_merged"] == "done"
    assert flow["next_agent_type"] == "qa"


def test_default_status_flows_qa_ends_chain():
    flow = svc.DEFAULT_STATUS_FLOWS["qa"]
    assert flow["on_complete"] == "qa_passed"
    assert flow["next_agent_type"] == ""


def test_build_gh_pr_command_escapes_quotes():
    cmd = svc._build_gh_pr_command('Title with "quote"', "Body 'apostrophe'", "feat/x")
    assert cmd.startswith("gh pr create ")
    assert "--title" in cmd and "--body" in cmd and "--head" in cmd
    # Single-quote wrapping means embedded double-quotes are safe verbatim.
    assert 'Title with "quote"' in cmd
    # Embedded single quotes are escaped via the '\'' idiom.
    assert "apostrophe" in cmd


def test_verify_webhook_signature_no_secret_accepts(monkeypatch):
    _patch_settings(monkeypatch, github_webhook_secret="")
    assert svc.verify_webhook_signature(b"{}", "") is True


def test_verify_webhook_signature_valid(monkeypatch):
    secret = "topsecret"
    _patch_settings(monkeypatch, github_webhook_secret=secret)
    body = b'{"action":"closed"}'
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert svc.verify_webhook_signature(body, sig) is True


def test_verify_webhook_signature_invalid(monkeypatch):
    _patch_settings(monkeypatch, github_webhook_secret="topsecret")
    assert svc.verify_webhook_signature(b"{}", "sha256=deadbeef") is False


def test_handle_github_webhook_unhandled_event():
    result = svc.handle_github_webhook({"action": "labeled"}, "issues")
    assert result["handled"] is False
    assert "Unhandled" in result["reason"]


def test_create_pr_via_api_dev_mode_returns_mock(monkeypatch):
    _patch_settings(monkeypatch, dev_mode=True)
    result = svc._create_pr_via_api(
        repo_url="https://github.com/test/repo",
        branch="feat/x",
        title="t",
        description="d",
        user_id="u1",
    )
    assert result["html_url"].startswith("https://github.com/test/repo/pull/")
    assert result["number"] > 0
    assert result["state"] == "open"


# --- GAP-0088: live GitHub API PR creation -------------------------------


def test_create_pr_via_api_no_token_returns_mock(monkeypatch):
    """Empty token => mock data, no outbound HTTP (dev/prod parity)."""
    called = {"n": 0}
    _patch_settings(monkeypatch, dev_mode=False, github_token="")
    monkeypatch.setattr(
        svc.httpx, "post",
        lambda *a, **k: called.__setitem__("n", called["n"] + 1),
    )
    result = svc._create_pr_via_api(
        repo_url="https://github.com/acme/backend",
        branch="agent/ticket-1",
        title="t",
        description="d",
        user_id="u1",
    )
    assert called["n"] == 0
    assert "html_url" in result


def test_create_pr_via_api_live_posts_to_github(monkeypatch):
    """Fails before fix (NotImplementedError); passes after (httpx.post called)."""

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "html_url": "https://github.com/acme/backend/pull/99",
                "number": 99,
                "state": "open",
            }

    captured = {}

    def _fake_post(url, *, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _Resp()

    _patch_settings(
        monkeypatch,
        dev_mode=False,
        github_token="ghp_test_token",
        github_api_base_url="https://api.github.com",
    )
    monkeypatch.setattr(svc.httpx, "post", _fake_post)

    result = svc._create_pr_via_api(
        repo_url="https://github.com/acme/backend",
        branch="agent/ticket-1",
        title="Fix login bug",
        description="Resolves #42",
        user_id="u_test",
    )

    assert captured["url"] == (
        "https://api.github.com/repos/acme/backend/pulls"
    )
    assert captured["json"]["title"] == "Fix login bug"
    assert captured["json"]["head"] == "agent/ticket-1"
    assert captured["json"]["base"] == "main"
    assert captured["headers"]["Authorization"] == "Bearer ghp_test_token"
    assert result["html_url"] == "https://github.com/acme/backend/pull/99"
    assert result["number"] == 99


def test_create_pr_via_api_rejects_unsafe_repo_url(monkeypatch):
    """SSRF / command-injection-prone repo URLs are rejected before any POST."""
    _patch_settings(
        monkeypatch, dev_mode=False, github_token="ghp_test_token"
    )
    monkeypatch.setattr(
        svc.httpx, "post",
        lambda *a, **k: pytest.fail("httpx.post must not be called"),
    )
    with pytest.raises(ValueError):
        svc._create_pr_via_api(
            repo_url="https://github.com/acme/back end",  # space -> rejected
            branch="b",
            title="t",
            description="d",
            user_id="u",
        )


def test_parse_owner_repo_https():
    assert svc._parse_owner_repo("https://github.com/acme/backend") == (
        "acme", "backend",
    )


def test_parse_owner_repo_git_ssh_and_dotgit():
    assert svc._parse_owner_repo("git@github.com:acme/backend.git") == (
        "acme", "backend",
    )


def test_parse_owner_repo_invalid_raises():
    with pytest.raises(ValueError, match="Cannot parse owner/repo"):
        svc._parse_owner_repo("not-a-url")
