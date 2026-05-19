from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from app.auth.roles import AdminProfile, AdminProfileType, AdminScope, Role
from app.core.settings import S
from app.routers import billing as billing_router
from app.services.payment_incident_providers import CanonicalProviderEvent, ProviderActionResult, VerificationResult
from app.services.payment_incident_transitions import TransitionResult


def _run_async(coro):
    return asyncio.run(coro)


def _admin_actor():
    return SimpleNamespace(
        sub="admin-1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.BILLING_SUPPORT,)),
    )


@dataclass
class _Repo:
    incidents: list[dict[str, Any]] = field(default_factory=list)
    attempts: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def list_incidents_by_case(self, *, provider: str, case_id: str, limit: int = 1):
        return [r for r in self.incidents if r["provider"] == provider and r["provider_incident_id"] == case_id][:limit]

    def put_incident(self, row: dict[str, Any]):
        payload = dict(row)
        payload.setdefault("created_at", "1700000000")
        payload.setdefault("updated_at", "1700000000")
        self.incidents.append(payload)
        return payload

    def get_incident(self, incident_id: str):
        for item in self.incidents:
            if item.get("incident_id") == incident_id:
                return item
        return None

    def put_retry_attempt(self, *, incident_id: str, attempt_id: str, attempt: dict[str, Any]):
        item = {"incident_id": incident_id, "attempt_id": attempt_id, "payload": attempt}
        self.attempts.append(item)
        return item

    def update_incident_status(self, *, incident_id: str, status: str, status_reason: str | None = None):
        row = self.get_incident(incident_id)
        if not row:
            return None
        row["status"] = status
        if status_reason:
            row["status_reason"] = status_reason
        row["updated_at"] = "1700001111"
        return row

    def list_dispute_evidence(self, *, incident_id: str, limit: int = 50):
        return [r for r in self.evidence if r["incident_id"] == incident_id][:limit]

    def put_dispute_evidence(self, *, incident_id: str, version: int, evidence: dict[str, Any]):
        row = {"incident_id": incident_id, "version": str(version), "payload": evidence}
        self.evidence.append(row)
        return row

    def append_incident_event(self, *, incident_id: str, event_id: str, event_type: str, payload: dict[str, Any] | None = None):
        return {"incident_id": incident_id, "event_id": event_id, "event_type": event_type, "payload": payload or {}}

    def get_ticket_link(self, incident_id: str):
        return None

    def put_ticket_link(self, **kwargs):
        return {}


def _build_request(*, body: bytes = b"{}", headers: dict[str, str] | None = None):
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "scheme": "http",
        "server": ("testserver", 80),
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


@pytest.mark.parametrize(
    ("provider", "route_name", "header_name", "event"),
    [
        ("stripe", "stripe_payment_incidents_webhook", "stripe-signature", CanonicalProviderEvent(provider="stripe", provider_event_id="evt_s_1", incident_id="dp_1", incident_type="dispute", target_status="opened", payload={"source_event_type": "charge.dispute.created"})),
        ("paypal", "paypal_payment_incidents_webhook", "paypal-transmission-sig", CanonicalProviderEvent(provider="paypal", provider_event_id="evt_p_1", incident_id="pp_dp_1", incident_type="dispute", target_status="opened", payload={"source_event_type": "CUSTOMER.DISPUTE.CREATED"})),
        ("ccbill", "ccbill_payment_incidents_webhook", "x-ccbill-signature", CanonicalProviderEvent(provider="ccbill", provider_event_id="evt_c_1", incident_id="cb_1", incident_type="chargeback", target_status="opened", payload={"source_event_type": "Chargeback"})),
    ],
)
def test_integration_webhook_to_incident_to_ticket_with_duplicate_guard(
    monkeypatch,
    provider: str,
    route_name: str,
    header_name: str,
    event: CanonicalProviderEvent,
) -> None:
    repo = _Repo()
    ticket_calls: list[str] = []
    sync_calls: list[str] = []

    class _Adapter:
        provider_key = provider

        def verify_webhook(self, **kwargs):
            return VerificationResult(valid=True, code="ok", message="verified")

        def parse_webhook_events(self, **kwargs):
            return [event]

    class _TransitionService:
        seen: set[str] = set()

        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            event_id = kwargs["provider_event_id"]
            duplicate = event_id in self.seen
            self.seen.add(event_id)
            return TransitionResult(
                incident={
                    "incident_id": kwargs["incident_id"],
                    "status": kwargs["target_status"],
                    "provider": provider,
                    "incident_type": event.incident_type,
                },
                duplicate=duplicate,
                emitted_events=[],
            )

    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _TransitionService)
    monkeypatch.setattr(billing_router, "ensure_incident_ticket_link", lambda *_a, **k: ticket_calls.append(str(k["incident"]["incident_id"])))
    monkeypatch.setattr(billing_router, "sync_ticket_from_incident", lambda *_a, **k: sync_calls.append(str(k["incident"]["incident_id"])))
    monkeypatch.setattr(billing_router, "dispatch_auto_payment_failure_alert", lambda *_a, **_k: True)
    monkeypatch.setattr(billing_router, "clear_auto_payment_failure_alerts", lambda *_a, **_k: 0)
    monkeypatch.setattr(billing_router, "record_incident_created", lambda **_k: None)
    monkeypatch.setattr(billing_router, "_reject_payment_incident_webhook_replay", lambda **_k: None)
    monkeypatch.setattr(billing_router, "_mark_payment_incident_webhook_replay", lambda **_k: None)
    if provider == "stripe":
        monkeypatch.setattr(billing_router, "ensure_stripe_configured", lambda: None)
        object.__setattr__(S, "stripe_webhook_secret", "whsec_test")

    handler = getattr(billing_router, route_name)
    req = _build_request(headers={header_name: "ok"})
    first = _run_async(handler(req))
    second = _run_async(handler(req))

    assert first["processed"] == 1
    assert first["deduped"] == 0
    assert second["deduped"] == 1
    assert len(repo.incidents) == 1
    assert ticket_calls == [repo.incidents[0]["incident_id"]]
    assert sync_calls == [repo.incidents[0]["incident_id"]]


@pytest.mark.parametrize("provider", ["stripe", "paypal", "ccbill"])
def test_integration_admin_evidence_and_submit_response_flow(monkeypatch, provider: str) -> None:
    repo = _Repo(
        incidents=[
            {
                "incident_id": "inc_dispute_1",
                "incident_type": "dispute",
                "provider": provider,
                "provider_incident_id": f"{provider}_dp_1",
                "status": "evidence_required",
                "account_id": "acct_1",
                "customer_id": "acct_1",
            }
        ]
    )

    class _Adapter:
        def submit_dispute_response(self, *, provider_incident_id: str, evidence: dict[str, Any]):
            assert provider_incident_id == f"{provider}_dp_1"
            return ProviderActionResult(ok=True, code="ok", message="submitted", payload={"provider": provider, "evidence": evidence})

    class _TransitionService:
        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            self.repository.update_incident_status(incident_id=kwargs["incident_id"], status=kwargs["target_status"], status_reason="admin.submit")
            return TransitionResult(incident=self.repository.get_incident(kwargs["incident_id"]), duplicate=False, emitted_events=[])

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _TransitionService)
    monkeypatch.setattr(billing_router, "audit_event", lambda *a, **k: None)

    req = _build_request()
    up = billing_router.admin_upload_payment_incident_evidence(
        "inc_dispute_1",
        billing_router.PaymentIncidentEvidenceUploadReq(summary="bank statement", file_refs=["s3://proof-1"], evidence_items=[{"kind": "receipt"}]),
        req,
        actor=_admin_actor(),
    )
    assert up["version"] == 1

    out = billing_router.admin_submit_payment_incident_response(
        "inc_dispute_1",
        billing_router.PaymentIncidentSubmitResponseReq(response_summary="responding", rationale="valid charge"),
        req,
        actor=_admin_actor(),
    )
    assert out["ok"] is True
    assert out["incident"]["status"] == "response_submitted"


@pytest.mark.parametrize("provider", ["stripe", "paypal", "ccbill"])
def test_integration_customer_fix_and_retry_flow(monkeypatch, provider: str) -> None:
    repo = _Repo(
        incidents=[
            {
                "incident_id": "inc_pf_1",
                "incident_type": "payment_failure",
                "provider": provider,
                "status": "customer_action_required",
                "account_id": "user-123",
                "customer_id": "user-123",
                "payment_reference": f"{provider}_ref_1",
            }
        ]
    )

    class _Adapter:
        def retry_payment(self, *, payment_reference: str, metadata: dict[str, Any] | None = None):
            return ProviderActionResult(ok=True, code="ok", message="retried", payload={"provider": provider, "payment_reference": payment_reference})

    class _TransitionService:
        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            self.repository.update_incident_status(incident_id=kwargs["incident_id"], status=kwargs["target_status"], status_reason="customer.retry")
            return TransitionResult(incident=self.repository.get_incident(kwargs["incident_id"]), duplicate=False, emitted_events=[])

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _TransitionService)
    monkeypatch.setattr(billing_router, "audit_event", lambda *a, **k: None)
    monkeypatch.setattr(billing_router, "dispatch_auto_payment_failure_alert", lambda *_a, **_k: True)
    monkeypatch.setattr(billing_router, "clear_auto_payment_failure_alerts", lambda *_a, **_k: 0)
    monkeypatch.setattr(billing_router, "record_retry_attempt", lambda **_k: None)

    out = billing_router.confirm_and_retry_payment_issue(
        "inc_pf_1",
        ctx={"user_sub": "user-123"},
        actor=SimpleNamespace(sub="user-123", role=Role.USER, admin_profile=AdminProfile()),
    )
    assert out["ok"] is True
    assert len(repo.attempts) == 1
    assert repo.get_incident("inc_pf_1")["status"] == "retry_succeeded"


def test_failure_mode_provider_timeout_on_admin_submit(monkeypatch) -> None:
    repo = _Repo(
        incidents=[
            {
                "incident_id": "inc_timeout_1",
                "incident_type": "dispute",
                "provider": "stripe",
                "provider_incident_id": "dp_timeout_1",
                "status": "evidence_required",
            }
        ]
    )

    class _Adapter:
        def submit_dispute_response(self, *, provider_incident_id: str, evidence: dict[str, Any]):
            return ProviderActionResult(ok=False, code="provider_timeout", message="upstream timed out", payload={})

    class _Transitions:
        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            self.repository.update_incident_status(incident_id=kwargs["incident_id"], status=kwargs["target_status"], status_reason="provider_timeout")
            return TransitionResult(incident=self.repository.get_incident(kwargs["incident_id"]), duplicate=False, emitted_events=[])

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _Transitions)
    monkeypatch.setattr(billing_router, "audit_event", lambda *a, **k: None)

    req = _build_request()
    out = billing_router.admin_submit_payment_incident_response(
        "inc_timeout_1",
        billing_router.PaymentIncidentSubmitResponseReq(response_summary="attempt submit"),
        req,
        actor=_admin_actor(),
    )
    assert out["ok"] is False
    assert out["provider_code"] == "provider_timeout"


def test_failure_mode_retry_storm_is_handled(monkeypatch) -> None:
    repo = _Repo(
        incidents=[
            {
                "incident_id": "inc_storm_1",
                "incident_type": "payment_failure",
                "provider": "stripe",
                "status": "ready_to_retry",
                "account_id": "user-123",
                "customer_id": "user-123",
                "payment_reference": "pi_storm_1",
            }
        ]
    )

    class _Adapter:
        def retry_payment(self, *, payment_reference: str, metadata: dict[str, Any] | None = None):
            return ProviderActionResult(ok=False, code="provider_timeout", message="timeout", payload={"payment_reference": payment_reference})

    class _Transitions:
        def __init__(self, repository):
            self.repository = repository

        def apply_provider_transition(self, **kwargs):
            self.repository.update_incident_status(incident_id=kwargs["incident_id"], status=kwargs["target_status"], status_reason="storm")
            return TransitionResult(incident=self.repository.get_incident(kwargs["incident_id"]), duplicate=False, emitted_events=[])

    monkeypatch.setattr(billing_router, "DynamoPaymentIncidentRepository", lambda: repo)
    monkeypatch.setattr(billing_router, "resolve_provider_adapter", lambda _: _Adapter())
    monkeypatch.setattr(billing_router, "PaymentIncidentTransitionService", _Transitions)
    monkeypatch.setattr(billing_router, "audit_event", lambda *a, **k: None)
    monkeypatch.setattr(billing_router, "dispatch_auto_payment_failure_alert", lambda *_a, **_k: True)
    monkeypatch.setattr(billing_router, "clear_auto_payment_failure_alerts", lambda *_a, **_k: 0)
    monkeypatch.setattr(billing_router, "record_retry_attempt", lambda **_k: None)
    monkeypatch.setattr(billing_router, "ensure_incident_ticket_link", lambda *_a, **_k: None)
    monkeypatch.setattr(billing_router, "sync_ticket_from_incident", lambda *_a, **_k: None)

    for _ in range(10):
        out = billing_router.confirm_and_retry_payment_issue(
            "inc_storm_1",
            ctx={"user_sub": "user-123"},
            actor=SimpleNamespace(sub="user-123", role=Role.USER, admin_profile=AdminProfile()),
        )
        assert out["ok"] is False
        assert out["code"] == "provider_timeout"

    assert len(repo.attempts) == 10
    assert repo.get_incident("inc_storm_1")["status"] == "customer_action_required"
