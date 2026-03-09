from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.routers.moderation import router, compat_router
from app.services.sessions import require_ui_session


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.include_router(compat_router)
    app.dependency_overrides[require_ui_session] = lambda: {"user_sub": "u_reporter"}
    return TestClient(app)


def test_create_report_returns_2xx_for_valid_payload(monkeypatch) -> None:
    from app.routers import moderation

    monkeypatch.setattr(moderation, "_validate_content_exists", lambda inp: None)
    monkeypatch.setattr(moderation, "_find_recent_duplicate", lambda **kwargs: None)
    monkeypatch.setattr(moderation, "_enforce_rate_limits", lambda **kwargs: None)
    monkeypatch.setattr(moderation, "upsert_open_ticket_for_report", lambda **kwargs: {"ticket_id": "modtk_abc"})
    monkeypatch.setattr(moderation, "create_content_report", lambda **kwargs: "rpt_123")
    audit_calls = []
    alert_calls = []
    monkeypatch.setattr(moderation, "write_moderation_audit_event", lambda **kwargs: audit_calls.append(kwargs) or "a1")
    monkeypatch.setattr(moderation, "write_alert", lambda *args, **kwargs: alert_calls.append((args, kwargs)) or {"alert_id": "a1"})

    client = _client()
    resp = client.post(
        "/v1/moderation/reports",
        json={
            "content_type": "feed_post",
            "content_id": "post_1",
            "topics": ["spam"],
            "reason_text": "This is spam content",
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["report_id"] == "rpt_123"
    assert body["ticket_id"].startswith("modtk_")
    assert body["status"] == "submitted"
    assert audit_calls and audit_calls[0]["action"] == "report_created"
    assert alert_calls and alert_calls[0][1]["title"] == "Report received"


def test_create_report_returns_4xx_for_invalid_topic() -> None:
    client = _client()
    resp = client.post(
        "/v1/moderation/reports",
        json={
            "content_type": "feed_post",
            "content_id": "post_1",
            "topics": ["unknown_topic"],
            "reason_text": "This should fail",
        },
    )

    assert resp.status_code == 422


def test_create_report_returns_4xx_for_invalid_content(monkeypatch) -> None:
    from app.routers import moderation

    def _raise_not_found(inp):
        raise HTTPException(status_code=404, detail="content not found")

    monkeypatch.setattr(moderation, "_validate_content_exists", _raise_not_found)
    monkeypatch.setattr(moderation, "_enforce_rate_limits", lambda **kwargs: None)

    client = _client()
    resp = client.post(
        "/v1/moderation/reports",
        json={
            "content_type": "profile_photo",
            "content_id": "user_missing",
            "topics": ["spam"],
            "reason_text": "Missing content",
        },
    )

    assert resp.status_code == 404


def test_create_report_idempotency_guard_deduplicates(monkeypatch) -> None:
    from app.routers import moderation

    monkeypatch.setattr(moderation, "_validate_content_exists", lambda inp: None)
    monkeypatch.setattr(moderation, "_enforce_rate_limits", lambda **kwargs: None)
    audit_calls = []
    alert_calls = []
    monkeypatch.setattr(moderation, "write_moderation_audit_event", lambda **kwargs: audit_calls.append(kwargs) or "a1")
    monkeypatch.setattr(moderation, "write_alert", lambda *args, **kwargs: alert_calls.append((args, kwargs)) or {"alert_id": "a1"})
    monkeypatch.setattr(
        moderation,
        "_find_recent_duplicate",
        lambda **kwargs: {
            "report_id": "rpt_existing",
            "content_type": "feed_post",
            "content_id": "post_1",
            "ticket_id": "modtk_existing",
            "created_at": "1700000000",
            "entity_type": "content_report",
        },
    )

    client = _client()
    resp = client.post(
        "/v1/moderation/reports",
        json={
            "content_type": "feed_post",
            "content_id": "post_1",
            "topics": ["spam"],
            "reason_text": "Repeated report",
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["report_id"] == "rpt_existing"
    assert body["ticket_id"] == "modtk_existing"
    assert body["status"] == "deduplicated"
    assert audit_calls and audit_calls[0]["action"] == "report_deduplicated"
    assert alert_calls and alert_calls[0][1]["details"]["status"] == "deduplicated"


def test_compat_route_matches_same_contract(monkeypatch) -> None:
    from app.routers import moderation

    monkeypatch.setattr(moderation, "_validate_content_exists", lambda inp: None)
    monkeypatch.setattr(moderation, "_find_recent_duplicate", lambda **kwargs: None)
    monkeypatch.setattr(moderation, "_enforce_rate_limits", lambda **kwargs: None)
    monkeypatch.setattr(moderation, "upsert_open_ticket_for_report", lambda **kwargs: {"ticket_id": "modtk_abc"})
    monkeypatch.setattr(moderation, "create_content_report", lambda **kwargs: "rpt_compat")
    monkeypatch.setattr(moderation, "write_moderation_audit_event", lambda **kwargs: "a1")
    monkeypatch.setattr(moderation, "write_alert", lambda *args, **kwargs: {"alert_id": "a1"})

    client = _client()
    resp = client.post(
        "/moderation/reports",
        json={
            "content_type": "message",
            "content_id": "m1",
            "conversation_id": "c1",
            "topics": ["criminal"],
            "reason_text": "Criminal threat",
        },
    )

    assert resp.status_code == 200
    assert resp.json()["report_id"] == "rpt_compat"


def test_rate_limit_returns_controlled_error(monkeypatch) -> None:
    from app.routers import moderation

    monkeypatch.setattr(moderation, "_validate_content_exists", lambda inp: None)
    monkeypatch.setattr(moderation, "_enforce_rate_limits", lambda **kwargs: None)
    monkeypatch.setattr(
        moderation,
        "_enforce_rate_limits",
        lambda **kwargs: (_ for _ in ()).throw(HTTPException(status_code=429, detail="Rate limit exceeded for moderation reports", headers={"Retry-After": "60"})),
    )

    client = _client()
    resp = client.post(
        "/v1/moderation/reports",
        json={
            "content_type": "feed_post",
            "content_id": "post_1",
            "topics": ["spam"],
            "reason_text": "Repeated report payload",
        },
    )

    assert resp.status_code == 429
    assert resp.json()["detail"] == "Rate limit exceeded for moderation reports"
    assert resp.headers.get("retry-after") == "60"


def test_anti_spam_security_event_is_logged(monkeypatch) -> None:
    from app.routers import moderation

    calls: list[tuple] = []

    monkeypatch.setattr(moderation, "_validate_content_exists", lambda inp: None)
    monkeypatch.setattr(moderation, "_find_recent_duplicate", lambda **kwargs: None)
    monkeypatch.setattr(moderation, "_enforce_rate_limits", lambda **kwargs: None)
    monkeypatch.setattr(moderation, "upsert_open_ticket_for_report", lambda **kwargs: {"ticket_id": "modtk_abc"})
    monkeypatch.setattr(moderation, "create_content_report", lambda **kwargs: "rpt_anti_spam")
    monkeypatch.setattr(moderation, "write_moderation_audit_event", lambda **kwargs: "a1")
    monkeypatch.setattr(moderation, "write_alert", lambda *args, **kwargs: {"alert_id": "a1"})

    def _capture_audit(event, user_sub, request=None, **fields):
        calls.append((event, user_sub, fields))

    monkeypatch.setattr(moderation, "audit_event", _capture_audit)

    client = _client()
    resp = client.post(
        "/v1/moderation/reports",
        json={
            "content_type": "feed_post",
            "content_id": "post_1",
            "topics": ["spam"],
            "reason_text": "https://example.com scam scam scam!!!",
        },
    )

    assert resp.status_code == 200
    assert any(event == "moderation_report_anti_spam_signal" for event, _user, _fields in calls)


def test_create_report_blocks_disabled_surface_flag(monkeypatch) -> None:
    from app.routers import moderation

    monkeypatch.setattr(moderation, "ensure_reporting_surface_enabled", lambda content_type: (_ for _ in ()).throw(HTTPException(status_code=403, detail="feed reporting is disabled")))

    client = _client()
    resp = client.post(
        "/v1/moderation/reports",
        json={
            "content_type": "feed_post",
            "content_id": "post_1",
            "topics": ["spam"],
            "reason_text": "report blocked by flag",
        },
    )

    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"]
