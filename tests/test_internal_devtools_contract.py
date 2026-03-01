from __future__ import annotations

import base64
import json

import pytest
from fastapi import HTTPException

from app.main import create_app
from app.routers import internal_devtools


def _cursor(offset: int) -> str:
    payload = json.dumps({"offset": offset}).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")


def test_openapi_contains_internal_devtools_routes_with_get_only() -> None:
    app = create_app()
    schema = app.openapi()
    paths = schema.get("paths", {})

    expected = [
        "/internal/dev-tools/email/messages",
        "/internal/dev-tools/sms/conversations",
        "/internal/dev-tools/billing/ledger",
        "/internal/dev-tools/billing/summary",
    ]

    for path in expected:
        assert path in paths
        methods = set(paths[path].keys())
        assert methods == {"get"}


def test_openapi_documents_limit_bounds_and_enums() -> None:
    app = create_app()
    schema = app.openapi()

    email_params = schema["paths"]["/internal/dev-tools/email/messages"]["get"]["parameters"]
    limit_param = next(p for p in email_params if p["name"] == "limit")
    assert limit_param["schema"]["minimum"] == 1
    assert limit_param["schema"]["maximum"] == 200

    ledger_params = schema["paths"]["/internal/dev-tools/billing/ledger"]["get"]["parameters"]
    provider_param = next(p for p in ledger_params if p["name"] == "provider")
    enum_values = next(
        option["enum"]
        for option in provider_param["schema"]["anyOf"]
        if "enum" in option
    )
    assert enum_values == ["stripe", "ccbill", "paypal"]


def test_email_messages_contract_returns_expected_shape() -> None:
    out = internal_devtools.get_devtools_email_messages(
        mailbox="user@example.com",
        thread_id="thread#1",
        q="verification",
        state="all",
        limit=25,
        cursor=_cursor(0),
    )
    payload = out.model_dump()
    assert set(payload.keys()) == {"mailboxes", "threads", "messages", "next_cursor", "parse_warnings"}
    assert payload["messages"] == []
    assert isinstance(payload["parse_warnings"], list)


def test_sms_conversations_contract_returns_expected_shape() -> None:
    out = internal_devtools.get_devtools_sms_conversations(
        participant="+14155550123",
        q="code",
        limit=10,
        cursor=_cursor(0),
    )
    payload = out.model_dump()
    assert set(payload.keys()) == {"conversations", "messages", "next_cursor", "parse_warnings"}
    assert payload["messages"] == []
    assert isinstance(payload["parse_warnings"], list)


def test_billing_contract_returns_expected_shapes() -> None:
    ledger = internal_devtools.get_devtools_billing_ledger(
        provider="paypal",
        status="completed",
        from_ts="2026-03-01T00:00:00Z",
        to_ts="2026-03-02T00:00:00Z",
        limit=50,
        cursor=_cursor(100),
    )
    ledger_payload = ledger.model_dump()
    assert set(ledger_payload.keys()) == {"entries", "summary", "next_cursor", "parse_warnings"}
    assert set(ledger_payload["summary"].keys()) == {
        "gross_inflow",
        "fees",
        "net_total_balance",
        "transaction_count",
        "provider_counts",
        "status_counts",
        "parse_warnings",
    }

    summary = internal_devtools.get_devtools_billing_summary(
        provider="stripe",
        status="failed",
        from_ts="2026-03-01T00:00:00Z",
        to_ts="2026-03-02T00:00:00Z",
    )
    summary_payload = summary.model_dump()
    assert set(summary_payload.keys()) == {
        "gross_inflow",
        "fees",
        "net_total_balance",
        "transaction_count",
        "provider_counts",
        "status_counts",
        "parse_warnings",
    }


def test_invalid_cursor_maps_to_deterministic_400_error() -> None:
    with pytest.raises(HTTPException) as exc:
        internal_devtools.get_devtools_email_messages(cursor="not-valid!!!")

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor must be urlsafe base64 JSON with an integer offset",
    }


def test_repeated_calls_with_same_filters_are_deterministic() -> None:
    params = {
        "provider": "ccbill",
        "status": "pending",
        "from_ts": "2026-03-01T00:00:00Z",
        "to_ts": "2026-03-02T00:00:00Z",
        "limit": 20,
        "cursor": _cursor(40),
    }

    first = internal_devtools.get_devtools_billing_ledger(**params)
    second = internal_devtools.get_devtools_billing_ledger(**params)
    assert first.model_dump() == second.model_dump()


def test_routes_disabled_outside_dev_mode_have_deterministic_error(monkeypatch) -> None:
    monkeypatch.setattr(internal_devtools, "S", type("Stub", (), {"dev_mode": False})())
    with pytest.raises(HTTPException) as exc:
        internal_devtools.get_devtools_email_messages()

    assert exc.value.status_code == 404
    assert exc.value.detail == {
        "code": "devtools_disabled",
        "message": "internal dev-tools routes are disabled",
    }


def test_dev_access_is_logged(monkeypatch) -> None:
    monkeypatch.setattr(internal_devtools, "S", type("Stub", (), {"dev_mode": True, "devtools_sms_log_path": "/tmp/missing-sms.log"})())
    calls = {"n": 0}

    def fake_info(*args, **kwargs):
        calls["n"] += 1

    monkeypatch.setattr(internal_devtools.logger, "info", fake_info)
    internal_devtools.get_devtools_sms_conversations(participant=None, q=None, limit=50, cursor=None)
    assert calls["n"] == 1
