"""GAP-0274 (KYC-011): kyc.case.created webhook-event dispatch on create.

``KycCaseStore.create_case`` must emit ``kyc.case.created`` after the case is
persisted, mirroring ``submit_case`` (which already emits ``kyc.case.submitted``
at the service layer).

Hermetic / offline. The ``KycCaseStore`` takes an injected table handle, so
there is NO global moto/@mock_aws interception and NO real AWS reachability.
The webhook emit is spied by monkeypatching the module-level
``_emit_kyc_event_safe`` helper (mirrors
tests/test_gap_0272_0273_kyc_decision_events.py).
"""
from __future__ import annotations

import app.services.kyc_cases as svc
from app.services.kyc_cases import KycCaseStore


class _FakeTable:
    """In-memory DynamoDB stand-in (copied from the GAP-0272/0273 test)."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict] = {}

    def put_item(self, *, Item):
        self.items[(Item["pk"], Item["sk"])] = dict(Item)

    def get_item(self, *, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(item)} if item else {}


def _spy_emit(monkeypatch) -> list[dict]:
    """Replace _emit_kyc_event_safe with a spy; return the captured-call list."""
    emitted: list[dict] = []

    def _fake(**kw):
        emitted.append(kw)

    monkeypatch.setattr(svc, "_emit_kyc_event_safe", _fake)
    return emitted


def test_create_case_emits_kyc_case_created(monkeypatch) -> None:
    store = KycCaseStore(_table=_FakeTable())
    emitted = _spy_emit(monkeypatch)

    created = store.create_case(
        user_sub="usr_alice",
        intake_profile="standard",
    )

    # GAP-0274: exactly one kyc.case.created event with the right payload.
    assert len(emitted) == 1, f"expected 1 event, got {len(emitted)}"
    ev = emitted[0]
    assert ev["event"] == "kyc.case.created"
    assert ev["user_sub"] == "usr_alice"
    assert ev["case_id"] == created["kyc_case_id"]
    assert ev["status"] == "draft"
    assert ev["intake_profile"] == "standard"


def test_create_case_emit_failure_does_not_break_create(monkeypatch) -> None:
    """A notification failure must never block case creation (best-effort).

    Uses the REAL _emit_kyc_event_safe helper (which has an internal
    try/except) and makes its downstream emit_kyc_event raise, exercising the
    swallow-and-continue contract.
    """
    import sys
    import types

    fake_mod = types.ModuleType("app.services.kyc_webhooks")

    def _boom(**kw):
        raise RuntimeError("notification backend down")

    fake_mod.emit_kyc_event = _boom
    # _emit_kyc_event_safe does a lazy `from app.services.kyc_webhooks import
    # emit_kyc_event`, so override the cached module entry.
    monkeypatch.setitem(sys.modules, "app.services.kyc_webhooks", fake_mod)

    store = KycCaseStore(_table=_FakeTable())
    # Must not propagate the emit failure.
    created = store.create_case(user_sub="usr_bob", intake_profile="standard")
    assert created["user_sub"] == "usr_bob"
    assert created["status"] == "draft"


def test_create_case_registered_in_webhook_event_types() -> None:
    """kyc.case.created must be a recognized subscribable webhook event type."""
    from app.services.webhook_service import (
        WEBHOOK_EVENT_TYPES_V2,
        is_valid_event_type,
    )

    assert "kyc.case.created" in WEBHOOK_EVENT_TYPES_V2
    assert is_valid_event_type("kyc.case.created")
