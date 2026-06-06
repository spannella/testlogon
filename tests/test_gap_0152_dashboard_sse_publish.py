"""Regression test for GAP-0152.

The creator dashboard's real-time SSE push infrastructure (publish function,
subscribe/unsubscribe lifecycle, and the GET /ui/dashboard/stream endpoint) was
fully implemented, but ``dashboard_sse_publish`` had zero call sites: a tip
receipt (earnings update) never pushed a real-time ``earnings:update`` event to
the recipient's open dashboard stream.

Fails-before: ``write_tip_ledger`` returned without ever calling
``dashboard_sse_publish``.
Passes-after: ``write_tip_ledger`` publishes exactly one ``earnings:update``
event to the recipient, and an SSE publish failure does not propagate.

Fully offline: ``T.billing`` is replaced with an in-memory fake and
``dashboard_sse_publish`` is monkeypatched (spy), so no real AWS / DynamoDB
access occurs. The endpoint coroutine / TestClient is not used.
"""
from __future__ import annotations

from app.services import tip_ledger
from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger


class _FakeBillingTable:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def put_item(self, *, Item):
        self.items.append(dict(Item))


def _patch_billing(monkeypatch, request) -> _FakeBillingTable:
    table = _FakeBillingTable()
    # T is a frozen dataclass; bypass immutability and restore on teardown.
    original = tip_ledger.T.billing
    object.__setattr__(tip_ledger.T, "billing", table)
    request.addfinalizer(
        lambda: object.__setattr__(tip_ledger.T, "billing", original)
    )
    # Keep the collaboration-split pre-check fully offline + deterministic: force
    # the "no split" branch so write_tip_ledger proceeds to the single-creator
    # credit path (and thus to the dashboard publish call under test).
    monkeypatch.setattr(
        "app.services.collaboration_revenue.maybe_split_content_revenue",
        lambda **kwargs: None,
    )
    return table


def test_write_tip_ledger_publishes_sse_event(monkeypatch, request):
    """FAILS-BEFORE: no publish call. PASSES-AFTER: one earnings:update event."""
    _patch_billing(monkeypatch, request)

    published: list[tuple[str, dict]] = []

    def spy_publish(user_id, event):
        published.append((user_id, event))

    # The fix lazily imports from app.services.dashboard_sse inside
    # write_tip_ledger, so patching the source-module attribute is what takes
    # effect at call time.
    monkeypatch.setattr(
        "app.services.dashboard_sse.dashboard_sse_publish", spy_publish
    )

    entry = TipLedgerEntry(
        tipper_user_id="user_alice",
        recipient_user_id="user_bob",
        amount_cents=500,
        content_type="message",
        content_id="msg_abc123",
    )
    result = write_tip_ledger(entry)

    # Ledger still written (both entries).
    assert "debit_entry_id" in result
    assert "credit_entry_id" in result

    # Exactly one SSE event published to the recipient.
    assert len(published) == 1, "expected exactly one dashboard_sse_publish call"
    uid, event = published[0]
    assert uid == "user_bob"
    assert event["type"] == "earnings:update"
    assert event["amount_cents"] == 500
    assert event["currency"] == "USD"
    assert event["content_type"] == "message"
    assert event["content_id"] == "msg_abc123"
    assert event["tip_payment_id"] == entry.tip_payment_id


def test_write_tip_ledger_sse_failure_does_not_propagate(monkeypatch, request):
    """An SSE publish failure must not break the tip ledger write."""
    _patch_billing(monkeypatch, request)

    def spy_publish_raises(user_id, event):
        raise RuntimeError("SSE queue unavailable")

    monkeypatch.setattr(
        "app.services.dashboard_sse.dashboard_sse_publish", spy_publish_raises
    )

    entry = TipLedgerEntry(
        tipper_user_id="user_alice",
        recipient_user_id="user_bob",
        amount_cents=100,
        content_type="post",
        content_id="post_xyz",
    )
    # Must not raise even when SSE publish fails.
    result = write_tip_ledger(entry)

    assert "debit_entry_id" in result
    assert "credit_entry_id" in result
