from __future__ import annotations

import time
from pathlib import Path

from app.services.devtools import read_service


def test_email_cache_hit_and_ttl_expiry(tmp_path: Path, monkeypatch) -> None:
    log = tmp_path / "emails.log"
    log.write_text(
        "\n".join(
            [
                "[2026-03-01T10:00:00Z] TO=user@example.com PURPOSE=login",
                "  Subject: Code",
                "  Code: 123456",
                "  Body: body",
                "",
            ]
        ),
        encoding="utf-8",
    )

    read_service.clear_devtools_cache()
    calls = {"n": 0}

    real = read_service.parse_email_log

    def wrapped(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(read_service, "parse_email_log", wrapped)

    out1 = read_service.get_email_messages(str(log), mailbox=None, thread_id=None, q=None, state="all", limit=10, offset=0)
    out2 = read_service.get_email_messages(str(log), mailbox=None, thread_id=None, q=None, state="all", limit=10, offset=0)

    assert out1.model_dump() == out2.model_dump()
    assert calls["n"] == 1

    original_monotonic = read_service.time.monotonic
    monkeypatch.setattr(read_service.time, "monotonic", lambda: original_monotonic() + 10)
    read_service.get_email_messages(str(log), mailbox=None, thread_id=None, q=None, state="all", limit=10, offset=0)
    assert calls["n"] == 2


def test_sms_cache_invalidation_on_file_change(tmp_path: Path, monkeypatch) -> None:
    log = tmp_path / "sms.log"
    log.write_text("[2026-03-01T10:00:00Z] SMS TO=+14155550123 Code: 111111\n", encoding="utf-8")

    read_service.clear_devtools_cache()
    calls = {"n": 0}
    real = read_service.parse_sms_log

    def wrapped(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(read_service, "parse_sms_log", wrapped)

    read_service.get_sms_conversations(str(log), participant=None, q=None, limit=10, offset=0)
    read_service.get_sms_conversations(str(log), participant=None, q=None, limit=10, offset=0)
    assert calls["n"] == 1

    time.sleep(0.001)
    log.write_text(
        "[2026-03-01T10:00:00Z] SMS TO=+14155550123 Code: 111111\n[2026-03-01T10:01:00Z] SMS TO=+14155550123 Code: 222222\n",
        encoding="utf-8",
    )

    read_service.get_sms_conversations(str(log), participant=None, q=None, limit=10, offset=0)
    assert calls["n"] == 2


def test_billing_cache_keys_include_filters(tmp_path: Path, monkeypatch) -> None:
    stripe = tmp_path / "stripe.log"
    backend = tmp_path / "backend.log"
    stripe.write_text('{"provider":"stripe","type":"payment_intent.succeeded","created":1700000010,"data":{"object":{"id":"pi_a","status":"completed","amount":1000,"currency":"usd"}}}\n', encoding="utf-8")
    backend.write_text('', encoding="utf-8")

    read_service.clear_devtools_cache()
    calls = {"n": 0}
    real = read_service.parse_billing_logs

    def wrapped(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(read_service, "parse_billing_logs", wrapped)

    read_service.get_billing_ledger(str(stripe), str(backend), provider="stripe", status="completed", from_ts=None, to_ts=None, limit=10, offset=0)
    read_service.get_billing_ledger(str(stripe), str(backend), provider="stripe", status="completed", from_ts=None, to_ts=None, limit=10, offset=0)
    assert calls["n"] == 1

    read_service.get_billing_ledger(str(stripe), str(backend), provider="stripe", status="failed", from_ts=None, to_ts=None, limit=10, offset=0)
    assert calls["n"] == 2
