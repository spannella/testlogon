from __future__ import annotations

import threading

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import AdminProfile, AdminProfileType, AdminScope, Role
from app.routers.admin_moderation import router as admin_router
from app.routers.moderation import compat_router, router as moderation_router
from app.services.sessions import require_ui_session


class _AdminRef:
    def __init__(self, value: AuthenticatedUser) -> None:
        self.value = value


def _client(admin_ref: _AdminRef) -> TestClient:
    app = FastAPI()
    app.include_router(moderation_router)
    app.include_router(compat_router)
    app.include_router(admin_router)
    app.dependency_overrides[require_ui_session] = lambda: {"user_sub": "u_reporter", "ip": "127.0.0.1"}
    app.dependency_overrides[get_authenticated_user] = lambda: admin_ref.value
    return TestClient(app)


def test_report_to_resolve_warn_lifecycle(monkeypatch) -> None:
    from app.routers import admin_moderation, moderation

    reports_by_ticket: dict[str, list[dict]] = {}
    report_counter = {"n": 0}
    warning_calls: list[dict] = []

    monkeypatch.setattr(moderation, "_validate_content_exists", lambda inp: None)
    monkeypatch.setattr(moderation, "_enforce_rate_limits", lambda **kwargs: None)
    monkeypatch.setattr(moderation, "_find_recent_duplicate", lambda **kwargs: None)
    monkeypatch.setattr(moderation, "upsert_open_ticket_for_report", lambda **kwargs: {"ticket_id": "modtk_lifecycle"})

    def _create_content_report(**kwargs):
        report_counter["n"] += 1
        report_id = f"rpt_{report_counter['n']}"
        reports_by_ticket.setdefault(kwargs["linked_ticket_id"], []).append(
            {
                "report_id": report_id,
                "topics": list(kwargs.get("topics") or []),
                "metadata": kwargs.get("metadata") or {},
                "content_type": kwargs.get("content_type"),
                "content_id": kwargs.get("content_id"),
            }
        )
        return report_id

    monkeypatch.setattr(moderation, "create_content_report", _create_content_report)
    monkeypatch.setattr(moderation, "write_moderation_audit_event", lambda **kwargs: "audit_mod")
    monkeypatch.setattr(moderation, "write_alert", lambda *args, **kwargs: {"alert_id": "a1"})

    monkeypatch.setattr(
        admin_moderation,
        "_get_ticket_or_404",
        lambda ticket_id: {
            "ticket_id": ticket_id,
            "entity_type": "moderation_ticket",
            "content_type": "feed_post",
            "content_id": "post_1",
            "status": "open",
            "priority": "high",
            "queue": "newsfeed",
            "assigned_admin_user_id": "admin_1",
            "report_count": 1,
            "aggregated_topics": ["criminal"],
            "latest_report_at": "1700000002",
            "updated_at": "1700000002",
            "created_at": "1700000001",
        },
    )
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: reports_by_ticket.get(ticket_id, []))
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_offender"})
    monkeypatch.setattr(admin_moderation.ddb.meta.client, "transact_write_items", lambda **kwargs: {})
    monkeypatch.setattr(admin_moderation.T.moderation_tickets, "update_item", lambda **kwargs: {})
    monkeypatch.setattr(admin_moderation, "apply_content_removal", lambda **kwargs: None)
    monkeypatch.setattr(admin_moderation, "notify_content_removal", lambda **kwargs: None)
    monkeypatch.setattr(admin_moderation, "apply_ban", lambda **kwargs: {"status": "skipped"})
    monkeypatch.setattr(admin_moderation, "issue_warning_notification", lambda **kwargs: warning_calls.append(kwargs) or None)
    monkeypatch.setattr(admin_moderation, "write_moderation_audit_event", lambda **kwargs: "audit_admin")

    admin_ref = _AdminRef(
        AuthenticatedUser(
            sub="admin_1",
            role=Role.ADMIN,
            admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
        )
    )
    client = _client(admin_ref)

    report_resp = client.post(
        "/v1/moderation/reports",
        json={
            "content_type": "feed_post",
            "content_id": "post_1",
            "topics": ["criminal"],
            "reason_text": "Threat content",
        },
    )
    assert report_resp.status_code == 200
    assert report_resp.json()["ticket_id"] == "modtk_lifecycle"

    resolve_resp = client.post(
        "/v1/admin/moderation/tickets/modtk_lifecycle/resolve",
        json={"resolution": "content_removed", "enforcement_action": "warn", "note": "policy violation"},
    )
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["ticket_id"] == "modtk_lifecycle"
    assert warning_calls
    assert warning_calls[0]["policy_category"] == "criminal"


def test_report_invalid_payload_rejected() -> None:
    admin_ref = _AdminRef(AuthenticatedUser(sub="admin_1", role=Role.ADMIN))
    client = _client(admin_ref)

    resp = client.post(
        "/v1/moderation/reports",
        json={
            "content_type": "feed_post",
            "content_id": "post_1",
            "topics": ["not_allowed"],
            "reason_text": "Invalid topic payload",
        },
    )
    assert resp.status_code == 422


def test_report_race_condition_two_submissions_share_ticket(monkeypatch) -> None:
    from app.routers import moderation

    calls = {"upsert": 0, "reports": 0}
    lock = threading.Lock()

    monkeypatch.setattr(moderation, "_validate_content_exists", lambda inp: None)
    monkeypatch.setattr(moderation, "_enforce_rate_limits", lambda **kwargs: None)
    monkeypatch.setattr(moderation, "_find_recent_duplicate", lambda **kwargs: None)

    def _upsert(**kwargs):
        with lock:
            calls["upsert"] += 1
        return {"ticket_id": "modtk_race"}

    def _create_report(**kwargs):
        with lock:
            calls["reports"] += 1
            return f"rpt_{calls['reports']}"

    monkeypatch.setattr(moderation, "upsert_open_ticket_for_report", _upsert)
    monkeypatch.setattr(moderation, "create_content_report", _create_report)
    monkeypatch.setattr(moderation, "write_moderation_audit_event", lambda **kwargs: "audit")
    monkeypatch.setattr(moderation, "write_alert", lambda *args, **kwargs: {"alert_id": "a1"})

    admin_ref = _AdminRef(AuthenticatedUser(sub="admin_1", role=Role.ADMIN))
    client = _client(admin_ref)

    payload = {
        "content_type": "feed_post",
        "content_id": "post_race",
        "topics": ["spam"],
        "reason_text": "Concurrent report",
    }

    responses: list[dict] = []

    def _submit() -> None:
        responses.append(client.post("/v1/moderation/reports", json=payload).json())

    t1 = threading.Thread(target=_submit)
    t2 = threading.Thread(target=_submit)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert len(responses) == 2
    assert {r["ticket_id"] for r in responses} == {"modtk_race"}
    assert len({r["report_id"] for r in responses}) == 2
    assert calls["upsert"] == 2


def test_permission_error_for_admin_resolve() -> None:
    admin_ref = _AdminRef(AuthenticatedUser(sub="u1", role=Role.USER))
    client = _client(admin_ref)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_denied/resolve",
        json={"resolution": "no_violation", "enforcement_action": "none"},
    )
    assert resp.status_code == 403
