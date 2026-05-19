from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import Role
from app.routers import tickets as tickets_router
from app.services.sessions import require_ui_session


def setup_function() -> None:
    tickets_router._KYC_TICKET_SYNC_COUNTS.clear()
    tickets_router._KYC_TICKET_SYNC_DEADLETTER.clear()


def _build_client(user_sub: str, role: Role) -> TestClient:
    app = FastAPI()
    app.include_router(tickets_router.router)

    async def _auth_override() -> AuthenticatedUser:
        return AuthenticatedUser(sub=user_sub, role=role)

    async def _session_override() -> dict[str, str]:
        return {"user_sub": user_sub, "session_id": "sess_1", "role": role.value}

    app.dependency_overrides[get_authenticated_user] = _auth_override
    app.dependency_overrides[require_ui_session] = _session_override
    return TestClient(app)


def _kyc_ticket(*, status: str = "open", assigned_admin_sub: str | None = None, version: int = 1) -> dict:
    return {
        "ticket_id": "tkt_kyc_kyc_123",
        "subject": "KYC review required: kyc_123",
        "owner_sub": "user-1",
        "status": status,
        "space_id": None,
        "assigned_admin_sub": assigned_admin_sub,
        "assigned_to_sub": assigned_admin_sub,
        "assigned_by": None,
        "assigned_at": None,
        "created_at": 1,
        "updated_at": 1 + version,
        "version": version,
        "messages": [],
        "activity": [],
        "metadata": {"namespace": "kyc", "kyc_case_id": "kyc_123"},
    }


def test_assign_triggers_kyc_sync_hook(monkeypatch) -> None:
    client = _build_client("admin-1", Role.ADMIN)
    events: list[str] = []
    monkeypatch.setattr(tickets_router, "_is_assignable_admin", lambda user_sub: True)
    monkeypatch.setattr(tickets_router.STORE, "get_ticket", lambda ticket_id: _kyc_ticket())
    monkeypatch.setattr(tickets_router.STORE, "assign_ticket", lambda **kwargs: _kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=2))
    monkeypatch.setattr(
        tickets_router,
        "_sync_kyc_for_ticket_event",
        lambda **kwargs: events.append(str(kwargs.get("event_type"))),
    )

    resp = client.post("/tickets/tkt_kyc_kyc_123/assign", json={"assignee_admin_sub": "admin-2"})
    assert resp.status_code == 200
    assert events == ["assigned"]


def test_status_change_triggers_kyc_sync_hook(monkeypatch) -> None:
    client = _build_client("admin-1", Role.ADMIN)
    events: list[str] = []
    monkeypatch.setattr(tickets_router.STORE, "get_ticket", lambda ticket_id: _kyc_ticket(status="in_progress", assigned_admin_sub="admin-2"))
    monkeypatch.setattr(tickets_router.STORE, "update_status", lambda **kwargs: _kyc_ticket(status="waiting_on_user", assigned_admin_sub="admin-2", version=3))
    monkeypatch.setattr(
        tickets_router,
        "_sync_kyc_for_ticket_event",
        lambda **kwargs: events.append(str(kwargs.get("event_type"))),
    )

    resp = client.post("/tickets/tkt_kyc_kyc_123/status", json={"status": "waiting_on_user"})
    assert resp.status_code == 200
    assert events == ["status_changed"]


def test_admin_message_triggers_request_info_sync_hook(monkeypatch) -> None:
    client = _build_client("admin-1", Role.ADMIN)
    events: list[str] = []
    monkeypatch.setattr(tickets_router.STORE, "get_ticket", lambda ticket_id: _kyc_ticket(status="in_progress", assigned_admin_sub="admin-2"))
    monkeypatch.setattr(tickets_router.STORE, "add_message", lambda **kwargs: _kyc_ticket(status="waiting_on_user", assigned_admin_sub="admin-2", version=4))
    monkeypatch.setattr(
        tickets_router,
        "_sync_kyc_for_ticket_event",
        lambda **kwargs: events.append(str(kwargs.get("event_type"))),
    )

    resp = client.post("/tickets/tkt_kyc_kyc_123/messages", json={"body": "Please upload a clearer document."})
    assert resp.status_code == 200
    assert events == ["message_admin"]


def test_sync_hook_audits_skipped_when_store_returns_same_version(monkeypatch) -> None:
    events: list[tuple[str, dict]] = []

    class _StubStore:
        def get_case(self, case_id: str) -> dict:
            return {"kyc_case_id": case_id, "version": 5}

        def sync_from_ticket_event(self, **kwargs) -> dict:
            return {"kyc_case_id": kwargs["case_id"], "version": 5}

    monkeypatch.setattr(tickets_router, "KYC_STORE", _StubStore())
    monkeypatch.setattr(
        tickets_router,
        "audit_event",
        lambda event, user_sub, request, **kwargs: events.append((event, kwargs)),
    )

    tickets_router._sync_kyc_for_ticket_event(
        ticket_before={"ticket_id": "tkt_kyc_kyc_123"},
        ticket_after=_kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=7),
        event_type="status_changed",
        actor_sub="admin-1",
        request=Request({"type": "http", "method": "POST", "path": "/tickets/tkt_kyc_kyc_123/status", "headers": []}),
    )
    assert any(event == "kyc_ticket_sync_skipped" for event, _ in events)
    skipped = next(payload for event, payload in events if event == "kyc_ticket_sync_skipped")
    assert skipped["reason"] == "stale_or_duplicate_event"


def test_sync_hook_audits_success_when_store_advances_version(monkeypatch) -> None:
    events: list[tuple[str, dict]] = []

    class _StubStore:
        def get_case(self, case_id: str) -> dict:
            return {"kyc_case_id": case_id, "version": 3}

        def sync_from_ticket_event(self, **kwargs) -> dict:
            return {"kyc_case_id": kwargs["case_id"], "version": 4}

    monkeypatch.setattr(tickets_router, "KYC_STORE", _StubStore())
    monkeypatch.setattr(
        tickets_router,
        "audit_event",
        lambda event, user_sub, request, **kwargs: events.append((event, kwargs)),
    )

    tickets_router._sync_kyc_for_ticket_event(
        ticket_before={"ticket_id": "tkt_kyc_kyc_123"},
        ticket_after=_kyc_ticket(status="waiting_on_user", assigned_admin_sub="admin-2", version=8),
        event_type="status_changed",
        actor_sub="admin-1",
        request=Request({"type": "http", "method": "POST", "path": "/tickets/tkt_kyc_kyc_123/status", "headers": []}),
    )
    assert any(event == "kyc_ticket_synced" for event, _ in events)


def test_sync_hook_rejects_mismatched_metadata_and_ticket_case_ids(monkeypatch) -> None:
    events: list[tuple[str, dict]] = []
    sync_calls: list[dict] = []

    class _StubStore:
        def get_case(self, case_id: str) -> dict:
            return {"kyc_case_id": case_id, "version": 1}

        def sync_from_ticket_event(self, **kwargs) -> dict:
            sync_calls.append(kwargs)
            return {"kyc_case_id": kwargs["case_id"], "version": 2}

    monkeypatch.setattr(tickets_router, "KYC_STORE", _StubStore())
    monkeypatch.setattr(
        tickets_router,
        "audit_event",
        lambda event, user_sub, request, **kwargs: events.append((event, kwargs)),
    )

    mismatch_ticket = _kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=9)
    mismatch_ticket["metadata"] = {"namespace": "kyc", "kyc_case_id": "kyc_other"}
    mismatch_ticket["ticket_id"] = "tkt_kyc_kyc_123"

    tickets_router._sync_kyc_for_ticket_event(
        ticket_before={"ticket_id": "tkt_kyc_kyc_123"},
        ticket_after=mismatch_ticket,
        event_type="status_changed",
        actor_sub="admin-1",
        request=Request({"type": "http", "method": "POST", "path": "/tickets/tkt_kyc_kyc_123/status", "headers": []}),
    )

    assert not sync_calls
    failed = [payload for event, payload in events if event == "kyc_ticket_sync_failed"]
    assert failed
    assert failed[-1]["reason"] == "ticket_case_id_mismatch"
    assert tickets_router._KYC_TICKET_SYNC_COUNTS["failed_ticket_case_id_mismatch"] >= 1
    assert len(tickets_router._KYC_TICKET_SYNC_DEADLETTER) >= 1


def test_admin_kyc_sync_metrics_endpoint_reports_counters(monkeypatch) -> None:
    admin_client = _build_client("admin-1", Role.ADMIN)
    user_client = _build_client("user-1", Role.USER)

    class _StubStore:
        def get_case(self, case_id: str) -> dict:
            return {"kyc_case_id": case_id, "version": 5}

        def sync_from_ticket_event(self, **kwargs) -> dict:
            return {"kyc_case_id": kwargs["case_id"], "version": 5}

    monkeypatch.setattr(tickets_router, "KYC_STORE", _StubStore())
    monkeypatch.setattr(tickets_router, "audit_event", lambda *args, **kwargs: None)

    tickets_router._sync_kyc_for_ticket_event(
        ticket_before={"ticket_id": "tkt_kyc_kyc_123"},
        ticket_after=_kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=10),
        event_type="status_changed",
        actor_sub="admin-1",
        request=Request({"type": "http", "method": "POST", "path": "/tickets/tkt_kyc_kyc_123/status", "headers": []}),
    )
    denied = user_client.get("/tickets/admin/kyc-sync-metrics")
    assert denied.status_code == 403

    metrics = admin_client.get("/tickets/admin/kyc-sync-metrics")
    assert metrics.status_code == 200
    body = metrics.json()["metrics"]
    payload = body["counters"]
    assert payload.get("skipped_stale_or_duplicate", 0) >= 1
    assert body["deadletter_count"] == 0
    assert body["deadletter_oldest_age_seconds"] is None


def test_admin_kyc_sync_deadletter_endpoint_reports_recent_failures(monkeypatch) -> None:
    admin_client = _build_client("admin-1", Role.ADMIN)
    root_client = _build_client("root-1", Role.ROOT)
    user_client = _build_client("user-1", Role.USER)
    monkeypatch.setattr(tickets_router, "audit_event", lambda *args, **kwargs: None)

    # Push two failures via mismatch guard.
    for case_id in ("kyc_other_1", "kyc_other_2"):
        mismatch_ticket = _kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=9)
        mismatch_ticket["metadata"] = {"namespace": "kyc", "kyc_case_id": case_id}
        mismatch_ticket["ticket_id"] = "tkt_kyc_kyc_123"
        tickets_router._sync_kyc_for_ticket_event(
            ticket_before={"ticket_id": "tkt_kyc_kyc_123"},
            ticket_after=mismatch_ticket,
            event_type="status_changed",
            actor_sub="admin-1",
            request=Request({"type": "http", "method": "POST", "path": "/tickets/tkt_kyc_kyc_123/status", "headers": []}),
        )

    denied = user_client.get("/tickets/admin/kyc-sync-deadletter")
    assert denied.status_code == 403

    deadletter = admin_client.get("/tickets/admin/kyc-sync-deadletter", params={"limit": 1})
    assert deadletter.status_code == 200
    body = deadletter.json()
    assert body["total_count"] >= 2
    assert len(body["items"]) == 1
    assert body["items"][0]["reason"] == "ticket_case_id_mismatch"
    assert body["items"][0]["replay_count"] == 0

    filtered = admin_client.get("/tickets/admin/kyc-sync-deadletter", params={"reason": "ticket_case_id_mismatch"})
    assert filtered.status_code == 200
    assert filtered.json()["total_count"] >= 2

    metrics = admin_client.get("/tickets/admin/kyc-sync-metrics")
    assert metrics.status_code == 200
    metrics_body = metrics.json()["metrics"]
    assert metrics_body["deadletter_count"] >= 2
    assert metrics_body["deadletter_oldest_age_seconds"] is not None

    clear_denied = user_client.delete("/tickets/admin/kyc-sync-deadletter")
    assert clear_denied.status_code == 403

    admin_clear_denied = admin_client.delete("/tickets/admin/kyc-sync-deadletter")
    assert admin_clear_denied.status_code == 403
    assert admin_clear_denied.json()["detail"]["error"]["code"] == "root_role_required"

    cleared = root_client.delete("/tickets/admin/kyc-sync-deadletter")
    assert cleared.status_code == 200
    assert cleared.json()["cleared_count"] >= 2
    assert cleared.json()["remaining_count"] == 0

    after_clear = admin_client.get("/tickets/admin/kyc-sync-deadletter")
    assert after_clear.status_code == 200
    assert after_clear.json()["total_count"] == 0


def test_admin_kyc_sync_deadletter_replay_success_removes_entry(monkeypatch) -> None:
    root_client = _build_client("root-1", Role.ROOT)
    monkeypatch.setattr(tickets_router, "audit_event", lambda *args, **kwargs: None)

    mismatch_ticket = _kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=9)
    mismatch_ticket["metadata"] = {"namespace": "kyc", "kyc_case_id": "kyc_other"}
    mismatch_ticket["ticket_id"] = "tkt_kyc_kyc_123"
    tickets_router._sync_kyc_for_ticket_event(
        ticket_before={"ticket_id": "tkt_kyc_kyc_123"},
        ticket_after=mismatch_ticket,
        event_type="status_changed",
        actor_sub="admin-1",
        request=Request({"type": "http", "method": "POST", "path": "/tickets/tkt_kyc_kyc_123/status", "headers": []}),
    )
    entry_id = tickets_router._KYC_TICKET_SYNC_DEADLETTER[0]["entry_id"]

    class _StubKycStore:
        def get_case(self, case_id: str) -> dict:
            return {"kyc_case_id": case_id, "version": 1}

        def sync_from_ticket_event(self, **kwargs) -> dict:
            return {"kyc_case_id": kwargs["case_id"], "version": 2}

    monkeypatch.setattr(tickets_router, "KYC_STORE", _StubKycStore())
    monkeypatch.setattr(tickets_router.STORE, "get_ticket", lambda ticket_id: _kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=12))

    replay = root_client.post(f"/tickets/admin/kyc-sync-deadletter/{entry_id}/replay")
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["removed"] is True
    assert replay.json()["deadletter_entry_id"] == entry_id
    assert tickets_router._KYC_TICKET_SYNC_DEADLETTER == []
    assert tickets_router._KYC_TICKET_SYNC_COUNTS["deadletter_replay_success"] >= 1


def test_admin_kyc_sync_deadletter_replay_ticket_missing_returns_conflict(monkeypatch) -> None:
    root_client = _build_client("root-1", Role.ROOT)
    monkeypatch.setattr(tickets_router, "audit_event", lambda *args, **kwargs: None)

    mismatch_ticket = _kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=9)
    mismatch_ticket["metadata"] = {"namespace": "kyc", "kyc_case_id": "kyc_other"}
    mismatch_ticket["ticket_id"] = "tkt_kyc_kyc_123"
    tickets_router._sync_kyc_for_ticket_event(
        ticket_before={"ticket_id": "tkt_kyc_kyc_123"},
        ticket_after=mismatch_ticket,
        event_type="status_changed",
        actor_sub="admin-1",
        request=Request({"type": "http", "method": "POST", "path": "/tickets/tkt_kyc_kyc_123/status", "headers": []}),
    )
    entry_id = tickets_router._KYC_TICKET_SYNC_DEADLETTER[0]["entry_id"]
    monkeypatch.setattr(tickets_router.STORE, "get_ticket", lambda ticket_id: None)

    replay = root_client.post(f"/tickets/admin/kyc-sync-deadletter/{entry_id}/replay")
    assert replay.status_code == 409
    assert replay.json()["detail"]["error"]["code"] == "ticket_sync_replay_failed"
    assert tickets_router._KYC_TICKET_SYNC_DEADLETTER[0]["replay_count"] == 1
    assert tickets_router._KYC_TICKET_SYNC_DEADLETTER[0]["last_replay_outcome"] == "ticket_not_found"
    assert tickets_router._KYC_TICKET_SYNC_COUNTS["deadletter_replay_failed_ticket_not_found"] == 1
    listing = root_client.get("/tickets/admin/kyc-sync-deadletter")
    assert listing.status_code == 200
    assert listing.json()["items"][0]["replay_count"] == 1
    assert listing.json()["items"][0]["last_replay_outcome"] == "ticket_not_found"


def test_admin_kyc_sync_deadletter_replay_missing_entry_returns_not_found() -> None:
    root_client = _build_client("root-1", Role.ROOT)
    replay = root_client.post("/tickets/admin/kyc-sync-deadletter/does-not-exist/replay")
    assert replay.status_code == 404
    assert replay.json()["detail"]["error"]["code"] == "ticket_sync_deadletter_not_found"
    assert tickets_router._KYC_TICKET_SYNC_COUNTS["deadletter_replay_not_found"] == 1


def test_non_root_deadletter_replay_endpoints_are_denied() -> None:
    admin_client = _build_client("admin-1", Role.ADMIN)
    replay = admin_client.post("/tickets/admin/kyc-sync-deadletter/does-not-exist/replay")
    assert replay.status_code == 403
    assert replay.json()["detail"]["error"]["code"] == "root_role_required"

    batch = admin_client.post("/tickets/admin/kyc-sync-deadletter/replay-batch", params={"limit": 10})
    assert batch.status_code == 403
    assert batch.json()["detail"]["error"]["code"] == "root_role_required"


def test_admin_kyc_sync_deadletter_batch_replay_mixed_outcomes(monkeypatch) -> None:
    root_client = _build_client("root-1", Role.ROOT)
    monkeypatch.setattr(tickets_router, "audit_event", lambda *args, **kwargs: None)

    for case_id in ("kyc_other_1", "kyc_other_2"):
        mismatch_ticket = _kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=9)
        mismatch_ticket["metadata"] = {"namespace": "kyc", "kyc_case_id": case_id}
        mismatch_ticket["ticket_id"] = "tkt_kyc_kyc_123"
        tickets_router._sync_kyc_for_ticket_event(
            ticket_before={"ticket_id": "tkt_kyc_kyc_123"},
            ticket_after=mismatch_ticket,
            event_type="status_changed",
            actor_sub="admin-1",
            request=Request({"type": "http", "method": "POST", "path": "/tickets/tkt_kyc_kyc_123/status", "headers": []}),
        )

    # Make one replay fail by breaking ticket id lookup.
    tickets_router._KYC_TICKET_SYNC_DEADLETTER[1]["ticket_id"] = "tkt_missing"

    class _StubKycStore:
        def get_case(self, case_id: str) -> dict:
            return {"kyc_case_id": case_id, "version": 1}

        def sync_from_ticket_event(self, **kwargs) -> dict:
            return {"kyc_case_id": kwargs["case_id"], "version": 2}

    monkeypatch.setattr(tickets_router, "KYC_STORE", _StubKycStore())
    monkeypatch.setattr(
        tickets_router.STORE,
        "get_ticket",
        lambda ticket_id: (_kyc_ticket(status="in_progress", assigned_admin_sub="admin-2", version=12) if ticket_id == "tkt_kyc_kyc_123" else None),
    )

    replay = root_client.post("/tickets/admin/kyc-sync-deadletter/replay-batch", params={"limit": 10})
    assert replay.status_code == 200
    body = replay.json()
    assert body["attempted_count"] == 2
    assert body["replayed_count"] == 1
    assert body["failed_count"] == 1
    assert body["removed_count"] == 1
    assert len(tickets_router._KYC_TICKET_SYNC_DEADLETTER) == 1


def test_admin_deadletter_and_metrics_endpoints_emit_audit_events(monkeypatch) -> None:
    admin_client = _build_client("admin-1", Role.ADMIN)
    root_client = _build_client("root-1", Role.ROOT)
    captured: list[str] = []
    monkeypatch.setattr(
        tickets_router,
        "audit_event",
        lambda event, user_sub, request, **kwargs: captured.append(str(event)),
    )
    tickets_router._KYC_TICKET_SYNC_DEADLETTER.append(
        {
            "entry_id": "d1",
            "created_at": 1,
            "reason": "case_not_found",
            "event_type": "status_changed",
            "actor_sub": "admin-1",
            "ticket_id": "tkt_kyc_kyc_123",
            "replay_count": 0,
            "last_replay_at": None,
            "last_replay_outcome": None,
        }
    )

    assert admin_client.get("/tickets/admin/kyc-sync-metrics").status_code == 200
    assert admin_client.get("/tickets/admin/kyc-sync-deadletter").status_code == 200
    assert root_client.delete("/tickets/admin/kyc-sync-deadletter").status_code == 200
    assert root_client.post("/tickets/admin/kyc-sync-deadletter/replay-batch", params={"limit": 10}).status_code == 200

    assert "kyc_ticket_sync_metrics_read" in captured
    assert "kyc_ticket_sync_deadletter_listed" in captured
    assert "kyc_ticket_sync_deadletter_cleared" in captured
    assert "kyc_ticket_sync_deadletter_replay_batch" in captured
