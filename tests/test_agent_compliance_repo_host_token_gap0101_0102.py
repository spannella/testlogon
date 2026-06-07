"""Regression tests for GAP-0101 and GAP-0102 (Compliance & Security Agent).

Fully offline / in-memory: no real AWS, no network, no DynamoDB. The tests
exercise pure helper functions on ``app.services.agent_compliance`` and the
``SecurityAgentConfigOut`` Pydantic model directly.

GAP-0101 (SSRF — repo_url host allowlist):
    Before the fix, ``review_pr_mock`` accepted an arbitrary ``pr_ref`` and there
    was no host-allowlist validation, so a real-execution path could clone /
    scan / open PRs against attacker-controlled or internal hosts. After the fix,
    ``validate_repo_host`` rejects any host not in the allowlist, and
    ``review_pr_mock`` invokes it when ``compliance_agent_execute_commands`` is on.

GAP-0102 (GitHub token must never be returned in plaintext):
    Before the fix, the config output had no token indirection; a leaked/added
    ``github_token`` field would be returned verbatim. After the fix, the config
    output exposes only ``has_github_token: bool`` and a write-only
    ``github_token_secret_name`` reference, and ``config_response_dict`` strips
    any raw ``github_token`` while deriving the boolean indicator.
"""
from __future__ import annotations

import pytest

from app.core.settings import S
from app.models import SecurityAgentConfigOut
from app.services import agent_compliance as svc


def _set_setting(name: str, value):
    """Set a field on the frozen Settings singleton (test-only override).

    ``Settings`` is a frozen dataclass, so plain ``monkeypatch.setattr`` raises
    ``FrozenInstanceError``. We bypass via ``object.__setattr__`` and return a
    restore callable.
    """
    sentinel = object()
    old = getattr(S, name, sentinel)

    def restore():
        if old is sentinel:
            object.__delattr__(S, name)
        else:
            object.__setattr__(S, name, old)

    object.__setattr__(S, name, value)
    return restore


@pytest.fixture
def settings_override():
    restores = []

    def apply(**kwargs):
        for k, v in kwargs.items():
            restores.append(_set_setting(k, v))

    yield apply
    for r in reversed(restores):
        r()


# ---------------------------------------------------------------------------
# GAP-0101: repo_url host allowlist (SSRF guard)
# ---------------------------------------------------------------------------


def test_validate_repo_host_rejects_unsafe_host():
    """An attacker-controlled host (and the IMDS endpoint) must be rejected."""
    allowed = ["github.com", "gitlab.com"]

    with pytest.raises(ValueError, match="not in allowed_repo_hosts"):
        svc.validate_repo_host("https://attacker.example.com/evil/repo", allowed)

    # AWS instance metadata service — classic SSRF target.
    with pytest.raises(ValueError, match="not in allowed_repo_hosts"):
        svc.validate_repo_host(
            "https://169.254.169.254/latest/meta-data/", allowed
        )


def test_validate_repo_host_accepts_allowlisted_and_subdomain():
    """Exact host and subdomains of an allowed host pass; empty (CLI) passes."""
    assert (
        svc.validate_repo_host("https://github.com/owner/repo", ["github.com"])
        == "https://github.com/owner/repo"
    )
    # Subdomain of an allowed host (e.g. GitHub Enterprise) is allowed.
    assert svc.validate_repo_host(
        "https://git.github.com/owner/repo", ["github.com"]
    )
    # git@ SSH form host extraction.
    assert svc.validate_repo_host("git@github.com:owner/repo.git", ["github.com"])
    # Empty == CLI mode, no outbound call: allowed.
    assert svc.validate_repo_host("", ["github.com"]) == ""


def test_review_pr_mock_rejects_unsafe_repo_when_execute_enabled(
    monkeypatch, settings_override
):
    """review_pr_mock validates pr_ref host when execute_commands is enabled.

    The effective config is stubbed so no DynamoDB access occurs.
    """
    settings_override(compliance_agent_execute_commands=True)
    monkeypatch.setattr(
        svc,
        "get_effective_config",
        lambda *, user_id: {"allowed_repo_hosts": ["github.com"]},
    )

    with pytest.raises(ValueError, match="not in allowed_repo_hosts"):
        svc.review_pr_mock(
            user_id="u1",
            agent_id="a1",
            pr_ref="https://attacker.example.com/evil",
            diff_findings=[],
        )


def test_default_config_has_repo_host_allowlist():
    """The default security config ships a non-empty repo-host allowlist."""
    assert "allowed_repo_hosts" in svc._DEFAULT_SECURITY_CONFIG
    assert svc._DEFAULT_SECURITY_CONFIG["allowed_repo_hosts"]
    assert "allowed_repo_hosts" in svc._CONFIG_FIELDS


# ---------------------------------------------------------------------------
# GAP-0102: github token indirection — never expose the raw token
# ---------------------------------------------------------------------------


def test_config_output_exposes_has_github_token_not_raw_token(settings_override):
    """config_response_dict yields has_github_token but never the raw token."""
    settings_override(
        dev_mode=False,
        github_token="ghp_should_never_leak",
        github_token_secret_name="",
    )

    # Even if a raw token somehow lands in the stored config, it is stripped and
    # never surfaces in the projected response.
    stored = {
        "scan_on_pr": True,
        "github_token": "ghp_should_never_leak",
        "github_token_secret_name": "arn:aws:secretsmanager:us-east-1:1:secret:t",
    }
    out = svc.config_response_dict(stored)

    assert "github_token" not in out
    assert out["has_github_token"] is True  # secret name configured

    model = SecurityAgentConfigOut(**out)
    dumped = model.model_dump()
    assert "github_token" not in dumped
    assert dumped["has_github_token"] is True
    # The raw token value must not appear anywhere in the serialized output.
    assert "ghp_should_never_leak" not in str(dumped)


def test_config_output_has_github_token_false_when_unconfigured(settings_override):
    """No secret name and no dev token => has_github_token is False."""
    settings_override(dev_mode=False, github_token="", github_token_secret_name="")

    out = svc.config_response_dict({"scan_on_pr": True})
    assert out["has_github_token"] is False
    assert "github_token" not in out


def test_security_config_out_never_declares_raw_github_token_field():
    """The output model must not declare a raw github_token field."""
    assert "github_token" not in SecurityAgentConfigOut.model_fields
    assert "has_github_token" in SecurityAgentConfigOut.model_fields
    assert "github_token_secret_name" in SecurityAgentConfigOut.model_fields


def test_validate_security_config_rejects_raw_github_token():
    """Submitting a raw github_token via config update is rejected."""
    errors = svc.validate_security_config({"github_token": "ghp_x"})
    assert any("github_token" in e for e in errors)
    # The secret-name reference is accepted.
    assert svc.validate_security_config(
        {"github_token_secret_name": "arn:aws:secretsmanager:1:secret:t"}
    ) == []


def test_github_token_never_a_config_field():
    """github_token must never be a persisted config field (GAP-0102)."""
    assert "github_token" not in svc._CONFIG_FIELDS
    assert "github_token_secret_name" in svc._CONFIG_FIELDS
