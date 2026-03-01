from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from fastapi import HTTPException

from app.models import (
    DevtoolsBillingLedgerEntryOut,
    DevtoolsBillingLedgerOut,
    DevtoolsBillingLedgerSummaryOut,
    DevtoolsEmailMessagesOut,
)
from app.routers import internal_devtools


def _cursor(offset: int) -> str:
    payload = json.dumps({"offset": offset}).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("utf-8").rstrip("=")


def test_email_endpoint_applies_filters_and_decodes_cursor(monkeypatch) -> None:
    monkeypatch.setattr(
        internal_devtools,
        "S",
        type("Stub", (), {"dev_mode": True, "devtools_email_log_path": "/tmp/dev-email.log"})(),
    )

    calls: dict[str, Any] = {}

    def fake_get_email_messages(log_path: str, **kwargs: Any) -> DevtoolsEmailMessagesOut:
        calls["log_path"] = log_path
        calls.update(kwargs)
        return DevtoolsEmailMessagesOut(next_cursor=_cursor(kwargs["offset"] + kwargs["limit"]))

    monkeypatch.setattr(internal_devtools, "get_email_messages", fake_get_email_messages)

    out = internal_devtools.get_devtools_email_messages(
        mailbox="alice@example.com",
        q="verify",
        state="unread",
        limit=25,
        cursor=_cursor(7),
    )

    assert out.next_cursor == _cursor(32)
    assert calls["log_path"] == "/tmp/dev-email.log"
    assert calls["mailbox"] == "alice@example.com"
    assert calls["q"] == "verify"
    assert calls["state"] == "unread"
    assert calls["limit"] == 25
    assert calls["offset"] == 7


def test_billing_endpoints_filter_contract_and_summary_totals(monkeypatch) -> None:
    monkeypatch.setattr(
        internal_devtools,
        "S",
        type(
            "Stub",
            (),
            {
                "dev_mode": True,
                "devtools_billing_stripe_log_path": "/tmp/stripe.log",
                "devtools_billing_backend_log_path": "/tmp/backend.log",
            },
        )(),
    )

    ledger_calls: dict[str, Any] = {}

    def fake_ledger(stripe_path: str, backend_path: str, **kwargs: Any) -> DevtoolsBillingLedgerOut:
        ledger_calls["stripe_path"] = stripe_path
        ledger_calls["backend_path"] = backend_path
        ledger_calls.update(kwargs)
        entries = [
            DevtoolsBillingLedgerEntryOut(
                id="e1",
                id_strategy="fixture",
                provider="stripe",
                event_type="payment_intent.succeeded",
                status="completed",
                occurred_at="2026-03-01T10:00:00Z",
                amount=10.0,
                fee=0.5,
                net=9.5,
                currency="usd",
                raw_payload={"id": "pi_1"},
            ),
            DevtoolsBillingLedgerEntryOut(
                id="e2",
                id_strategy="fixture",
                provider="stripe",
                event_type="payment_intent.succeeded",
                status="completed",
                occurred_at="2026-03-01T11:00:00Z",
                amount=5.0,
                fee=0.25,
                net=4.75,
                currency="usd",
                raw_payload={"id": "pi_2"},
            ),
        ]
        summary = DevtoolsBillingLedgerSummaryOut(
            gross_inflow=15.0,
            fees=0.75,
            net_total_balance=14.25,
            transaction_count=2,
            provider_counts={"stripe": 2},
            status_counts={"completed": 2},
        )
        return DevtoolsBillingLedgerOut(entries=entries, summary=summary, next_cursor=_cursor(kwargs["offset"] + kwargs["limit"]))

    monkeypatch.setattr(internal_devtools, "get_billing_ledger", fake_ledger)
    monkeypatch.setattr(
        internal_devtools,
        "get_billing_summary",
        lambda *args, **kwargs: DevtoolsBillingLedgerSummaryOut(
            gross_inflow=15.0,
            fees=0.75,
            net_total_balance=14.25,
            transaction_count=2,
            provider_counts={"stripe": 2},
            status_counts={"completed": 2},
        ),
    )

    ledger = internal_devtools.get_devtools_billing_ledger(
        provider="stripe",
        status="completed",
        from_ts="2026-03-01T00:00:00Z",
        to_ts="2026-03-02T00:00:00Z",
        limit=2,
        cursor=_cursor(3),
    )
    summary = internal_devtools.get_devtools_billing_summary(
        provider="stripe",
        status="completed",
        from_ts="2026-03-01T00:00:00Z",
        to_ts="2026-03-02T00:00:00Z",
    )

    assert ledger.summary.gross_inflow == 15.0
    assert ledger.summary.fees == 0.75
    assert ledger.summary.net_total_balance == 14.25
    assert ledger.next_cursor == _cursor(5)

    assert ledger_calls["stripe_path"] == "/tmp/stripe.log"
    assert ledger_calls["backend_path"] == "/tmp/backend.log"
    assert ledger_calls["provider"] == "stripe"
    assert ledger_calls["status"] == "completed"
    assert ledger_calls["offset"] == 3

    assert summary.gross_inflow == 15.0
    assert summary.fees == 0.75
    assert summary.net_total_balance == 14.25


def test_devtools_route_security_gate_and_invalid_cursor_errors(monkeypatch) -> None:
    monkeypatch.setattr(
        internal_devtools,
        "S",
        type("Stub", (), {"dev_mode": False, "devtools_email_log_path": "/tmp/none.log"})(),
    )

    with pytest.raises(HTTPException) as disabled:
        internal_devtools.get_devtools_email_messages()

    assert disabled.value.status_code == 404
    assert disabled.value.detail == {
        "code": "devtools_disabled",
        "message": "internal dev-tools routes are disabled",
    }

    monkeypatch.setattr(
        internal_devtools,
        "S",
        type("Stub", (), {"dev_mode": True, "devtools_email_log_path": "/tmp/none.log"})(),
    )

    with pytest.raises(HTTPException) as bad_cursor:
        internal_devtools.get_devtools_email_messages(cursor="not-valid!!!")

    assert bad_cursor.value.status_code == 400
    assert bad_cursor.value.detail == {
        "code": "invalid_cursor",
        "message": "cursor must be urlsafe base64 JSON with an integer offset",
    }
