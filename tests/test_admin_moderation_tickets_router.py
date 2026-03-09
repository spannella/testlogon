from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import AdminProfile, AdminProfileType, AdminScope, Role
from app.routers.admin_moderation import router


def _client(user: AuthenticatedUser) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_authenticated_user] = lambda: user
    return TestClient(app)


def test_list_tickets_blocks_unauthorized_role() -> None:
    client = _client(AuthenticatedUser(sub="u1", role=Role.USER))
    resp = client.get("/v1/admin/moderation/tickets")
    assert resp.status_code == 403




def test_get_user_history_blocks_unauthorized_role() -> None:
    client = _client(AuthenticatedUser(sub="u1", role=Role.USER))
    resp = client.get("/v1/admin/moderation/users/u1/history")
    assert resp.status_code == 403


def test_get_user_history_returns_timeline(monkeypatch) -> None:
    from app.routers import admin_moderation

    monkeypatch.setattr(
        admin_moderation.T.user_enforcement_history,
        "query",
        lambda **kwargs: {
            "Items": [
                {
                    "entity_type": "user_enforcement",
                    "user_id": "u_target",
                    "enforcement_id": "enf_b",
                    "enforcement_type": "ban",
                    "status": "active",
                    "source_ticket_id": "modtk_2",
                    "created_at": "1700000002",
                    "created_by_admin_user_id": "admin_1",
                    "duration_days": 30,
                    "note": "repeat abuse",
                },
                {
                    "entity_type": "user_enforcement",
                    "user_id": "u_target",
                    "enforcement_id": "enf_a",
                    "enforcement_type": "warn",
                    "status": "recorded",
                    "source_ticket_id": "modtk_1",
                    "created_at": "1700000001",
                    "created_by_admin_user_id": "admin_1",
                    "duration_days": 0,
                    "note": "first strike",
                },
            ]
        },
    )

    admin_user = AuthenticatedUser(sub="root_1", role=Role.ROOT)
    client = _client(admin_user)
    resp = client.get("/v1/admin/moderation/users/u_target/history", params={"limit": 10})

    assert resp.status_code == 200
    body = resp.json()
    assert [i["enforcement_id"] for i in body["items"]] == ["enf_b", "enf_a"]
    assert body["items"][0]["enforcement_type"] == "ban"
    assert body["items"][0]["duration_days"] == 30


def test_list_tickets_returns_filtered_paginated_results(monkeypatch) -> None:
    from app.routers import admin_moderation

    items = [
        {
            "ticket_id": "modtk_b",
            "entity_type": "moderation_ticket",
            "content_type": "feed_post",
            "content_id": "post_2",
            "status": "open",
            "priority": "critical",
            "queue": "safety",
            "assigned_admin_user_id": "admin_1",
            "report_count": 2,
            "aggregated_topics": {"extortion", "spam"},
            "latest_report_at": "1700000002",
            "updated_at": "1700000002",
            "created_at": "1700000000",
        },
        {
            "ticket_id": "modtk_a",
            "entity_type": "moderation_ticket",
            "content_type": "feed_post",
            "content_id": "post_1",
            "status": "open",
            "priority": "high",
            "queue": "safety",
            "assigned_admin_user_id": "admin_1",
            "report_count": 1,
            "aggregated_topics": {"criminal"},
            "latest_report_at": "1700000001",
            "updated_at": "1700000001",
            "created_at": "1700000000",
        },
    ]

    calls = {"count": 0}

    def _query(**kwargs):
        calls["count"] += 1
        assert kwargs["IndexName"] == "ByAssignedAdminLatestReportAt"
        return {
            "Items": items,
            "LastEvaluatedKey": {"ticket_id": "modtk_a"},
        }

    monkeypatch.setattr(admin_moderation.T.moderation_tickets, "query", _query)

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.get(
        "/v1/admin/moderation/tickets",
        params={"assignee": "admin_1", "topic": "extortion", "limit": 1},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["ticket_id"] == "modtk_b"
    assert body["items"][0]["priority"] == "critical"
    assert body["next_cursor"] is not None
    assert calls["count"] == 1


def test_list_tickets_has_stable_ordering_by_latest_then_ticket(monkeypatch) -> None:
    from app.routers import admin_moderation

    def _query(**kwargs):
        return {
            "Items": [
                {
                    "ticket_id": "modtk_a",
                    "entity_type": "moderation_ticket",
                    "content_type": "feed_post",
                    "content_id": "post_1",
                    "status": "open",
                    "priority": "high",
                    "queue": "general",
                    "assigned_admin_user_id": "",
                    "report_count": 1,
                    "aggregated_topics": ["criminal"],
                    "latest_report_at": "1700000001",
                    "updated_at": "1700000001",
                    "created_at": "1700000000",
                },
                {
                    "ticket_id": "modtk_b",
                    "entity_type": "moderation_ticket",
                    "content_type": "feed_post",
                    "content_id": "post_2",
                    "status": "open",
                    "priority": "high",
                    "queue": "general",
                    "assigned_admin_user_id": "",
                    "report_count": 1,
                    "aggregated_topics": ["criminal"],
                    "latest_report_at": "1700000001",
                    "updated_at": "1700000001",
                    "created_at": "1700000000",
                },
            ]
        }

    monkeypatch.setattr(admin_moderation.T.moderation_tickets, "query", _query)

    admin_user = AuthenticatedUser(sub="root_1", role=Role.ROOT)
    client = _client(admin_user)
    resp = client.get("/v1/admin/moderation/tickets", params={"limit": 10})

    assert resp.status_code == 200
    body = resp.json()
    assert [i["ticket_id"] for i in body["items"]] == ["modtk_b", "modtk_a"]


def test_get_ticket_detail_blocks_unauthorized_role() -> None:
    client = _client(AuthenticatedUser(sub="u1", role=Role.USER))
    resp = client.get("/v1/admin/moderation/tickets/modtk_1")
    assert resp.status_code == 403


def test_get_ticket_detail_returns_snapshot_reports_and_offender_summary(monkeypatch) -> None:
    from app.routers import admin_moderation

    ticket_item = {
        "ticket_id": "modtk_1",
        "entity_type": "moderation_ticket",
        "content_type": "profile_photo",
        "content_id": "user_target",
        "status": "open",
        "priority": "high",
        "queue": "safety",
        "assigned_admin_user_id": "admin_1",
        "report_count": 2,
        "aggregated_topics": ["sexual", "spam"],
        "latest_report_at": "1700000100",
        "updated_at": "1700000100",
        "created_at": "1700000000",
    }

    linked_reports = [
        {
            "report_id": "rpt_2",
            "entity_type": "content_report",
            "reporter_user_id": "u_reporter_2",
            "topics": ["sexual"],
            "reason_text": "unsafe image",
            "created_at": "1700000100",
            "metadata": {},
        },
        {
            "report_id": "rpt_1",
            "entity_type": "content_report",
            "reporter_user_id": "u_reporter_1",
            "topics": ["spam"],
            "reason_text": "bad image",
            "created_at": "1700000001",
            "metadata": {},
        },
    ]

    profile_item = {"user_sub": "user_target", "profile": {"profile_photo_url": "https://cdn.example/p.jpg"}}

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: linked_reports)
    monkeypatch.setattr(admin_moderation.T.profile, "get_item", lambda Key: {"Item": profile_item})
    monkeypatch.setattr(
        admin_moderation.T.moderation_tickets,
        "scan",
        lambda **kwargs: {"Items": [{"entity_type": "moderation_ticket", "status": "open"}, {"entity_type": "moderation_ticket", "status": "closed"}]},
    )
    monkeypatch.setattr(
        admin_moderation.T.user_enforcement_history,
        "query",
        lambda **kwargs: {
            "Items": [
                {
                    "entity_type": "user_enforcement",
                    "user_id": "user_target",
                    "enforcement_id": "enf_1",
                    "enforcement_type": "warn",
                    "status": "recorded",
                    "source_ticket_id": "modtk_prev",
                    "created_at": "1700000002",
                    "created_by_admin_user_id": "admin_1",
                    "note": "prior warning",
                }
            ]
        },
    )

    admin_user = AuthenticatedUser(sub="root_1", role=Role.ROOT)
    client = _client(admin_user)
    resp = client.get("/v1/admin/moderation/tickets/modtk_1")

    assert resp.status_code == 200
    body = resp.json()
    assert body["ticket"]["ticket_id"] == "modtk_1"
    assert body["content_snapshot"]["kind"] == "profile_photo"
    assert body["content_snapshot"]["author_user_id"] == "user_target"
    assert [r["report_id"] for r in body["linked_reports"]] == ["rpt_2", "rpt_1"]
    assert body["offender_history_summary"]["offender_user_id"] == "user_target"
    assert body["offender_history_summary"]["total_tickets"] == 2
    assert body["offender_history_summary"]["open_tickets"] == 1
    assert body["offender_history_summary"]["total_reports"] == 2
    assert body["prior_enforcement_history"][0]["enforcement_type"] == "warn"


def test_claim_ticket_assigns_to_admin(monkeypatch) -> None:
    from app.routers import admin_moderation

    monkeypatch.setattr(admin_moderation, "write_moderation_audit_event", lambda **kwargs: "audit_1")

    item = {
        "ticket_id": "modtk_claim",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": None,
        "report_count": 1,
        "aggregated_topics": ["criminal"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    calls = {"updated": False}

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: item)

    def _update_item(**kwargs):
        calls["updated"] = True
        assert kwargs["ExpressionAttributeValues"][":admin_sub"] == "admin_1"
        return {}

    action_calls = []
    enforcement_calls = []

    def _put_action(**kwargs):
        action_calls.append(kwargs["Item"])
        return {}

    def _put_enforcement(**kwargs):
        enforcement_calls.append(kwargs["Item"])
        return {}

    monkeypatch.setattr(admin_moderation.T.moderation_actions, "put_item", _put_action)
    monkeypatch.setattr(admin_moderation.T.user_enforcement_history, "put_item", _put_enforcement)
    monkeypatch.setattr(admin_moderation.T.moderation_tickets, "update_item", _update_item)

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.post("/v1/admin/moderation/tickets/modtk_claim/claim")
    assert resp.status_code == 200
    assert resp.json()["ticket_id"] == "modtk_claim"
    assert calls["updated"] is True


def test_decide_ticket_closes_and_records_decision(monkeypatch) -> None:
    from app.routers import admin_moderation

    monkeypatch.setattr(admin_moderation, "write_moderation_audit_event", lambda **kwargs: "audit_1")

    ticket_item = {
        "ticket_id": "modtk_decide",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 2,
        "aggregated_topics": ["criminal"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    updates = {"called": False}

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_target"})

    def _update_item(**kwargs):
        updates["called"] = True
        values = kwargs["ExpressionAttributeValues"]
        assert values[":status"] == "closed"
        assert values[":decision"] == "ban"
        assert values[":offender_user_id"] == "u_target"
        return {}

    action_calls = []
    enforcement_calls = []

    def _put_action(**kwargs):
        action_calls.append(kwargs["Item"])
        return {}

    def _put_enforcement(**kwargs):
        enforcement_calls.append(kwargs["Item"])
        return {}

    monkeypatch.setattr(admin_moderation.T.moderation_actions, "put_item", _put_action)
    monkeypatch.setattr(admin_moderation.T.user_enforcement_history, "put_item", _put_enforcement)
    monkeypatch.setattr(admin_moderation.T.moderation_tickets, "update_item", _update_item)

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION, AdminScope.CONTENT_MODERATION_SENIOR)),
    )
    client = _client(admin_user)
    resp = client.post("/v1/admin/moderation/tickets/modtk_decide/decision", json={"decision": "ban", "note": "repeat abuse"})

    assert resp.status_code == 200
    assert resp.json()["ticket_id"] == "modtk_decide"
    assert updates["called"] is True
    assert action_calls and action_calls[0]["source_ticket_id"] == "modtk_decide"
    assert action_calls[0]["action_type"] == "ban"
    assert enforcement_calls and enforcement_calls[0]["source_ticket_id"] == "modtk_decide"
    assert enforcement_calls[0]["enforcement_type"] == "ban"


def test_warn_decision_persists_enforcement_history(monkeypatch) -> None:
    from app.routers import admin_moderation

    monkeypatch.setattr(admin_moderation, "write_moderation_audit_event", lambda **kwargs: "audit_1")

    ticket_item = {
        "ticket_id": "modtk_warn",
        "entity_type": "moderation_ticket",
        "content_type": "message",
        "content_id": "m1",
        "status": "open",
        "priority": "high",
        "queue": "messages",
        "assigned_admin_user_id": "admin_1",
        "report_count": 1,
        "aggregated_topics": ["spam"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_warned"})

    action_calls = []
    enforcement_calls = []

    monkeypatch.setattr(admin_moderation.T.moderation_actions, "put_item", lambda **kwargs: action_calls.append(kwargs["Item"]) or {})
    monkeypatch.setattr(admin_moderation.T.user_enforcement_history, "put_item", lambda **kwargs: enforcement_calls.append(kwargs["Item"]) or {})
    monkeypatch.setattr(admin_moderation.T.moderation_tickets, "update_item", lambda **kwargs: {})

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)
    resp = client.post("/v1/admin/moderation/tickets/modtk_warn/decision", json={"decision": "warn", "note": "first warning"})

    assert resp.status_code == 200
    assert action_calls[0]["source_ticket_id"] == "modtk_warn"
    assert action_calls[0]["action_type"] == "warn"
    assert enforcement_calls[0]["source_ticket_id"] == "modtk_warn"
    assert enforcement_calls[0]["enforcement_type"] == "warn"


def test_resolve_ticket_rejects_invalid_combination(monkeypatch) -> None:
    from app.routers import admin_moderation

    ticket_item = {
        "ticket_id": "modtk_resolve_invalid",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 1,
        "aggregated_topics": ["spam"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }
    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_resolve_invalid/resolve",
        json={"resolution": "no_violation", "enforcement_action": "warn", "note": "invalid combo"},
    )
    assert resp.status_code == 400


def test_resolve_ticket_transactional_pipeline(monkeypatch) -> None:
    from app.routers import admin_moderation

    monkeypatch.setattr(admin_moderation, "write_moderation_audit_event", lambda **kwargs: "audit_1")

    ticket_item = {
        "ticket_id": "modtk_resolve",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 2,
        "aggregated_topics": ["criminal"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_target"})
    removal_calls = {"called": False}
    monkeypatch.setattr(
        admin_moderation,
        "apply_content_removal",
        lambda **kwargs: removal_calls.__setitem__("called", True),
    )
    ban_calls = {"called": False, "duration": None, "policy_category": None}
    monkeypatch.setattr(
        admin_moderation,
        "apply_ban",
        lambda **kwargs: (
            ban_calls.__setitem__("called", True),
            ban_calls.__setitem__("duration", kwargs.get("duration_days")),
            ban_calls.__setitem__("policy_category", kwargs.get("policy_category")),
            {"status": "banned"},
        )[-1],
    )
    monkeypatch.setattr(admin_moderation, "issue_warning_notification", lambda **kwargs: {})
    content_remove_notifications = []
    monkeypatch.setattr(admin_moderation, "notify_content_removal", lambda **kwargs: content_remove_notifications.append(kwargs) or None)
    monkeypatch.setattr(admin_moderation.T.moderation_tickets, "update_item", lambda **kwargs: {})

    tx_calls = {}

    def _tx(*, TransactItems):
        tx_calls["items"] = TransactItems
        return {}

    monkeypatch.setattr(admin_moderation.ddb.meta.client, "transact_write_items", _tx)

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_resolve/resolve",
        json={"resolution": "content_removed", "enforcement_action": "ban", "enforcement_duration_days": 30, "note": "severe abuse"},
    )

    assert resp.status_code == 200
    assert resp.json()["ticket_id"] == "modtk_resolve"
    assert removal_calls["called"] is True
    assert ban_calls["called"] is True
    assert ban_calls["duration"] == 30
    assert ban_calls["policy_category"] == "criminal"
    assert content_remove_notifications
    assert content_remove_notifications[0]["policy_category"] == "criminal"
    items = tx_calls["items"]
    assert len(items) == 4
    update = items[0]["Update"]
    assert update["ConditionExpression"] == "#status = :open"

    action_items = [i["Put"]["Item"] for i in items[1:3]]
    action_types = {next(iter(i["action_type"].values())) for i in action_items}
    assert "content_removed" in action_types
    assert "ban" in action_types

    enforcement_item = items[3]["Put"]["Item"]
    assert next(iter(enforcement_item["source_ticket_id"].values())) == "modtk_resolve"
    assert next(iter(enforcement_item["enforcement_type"].values())) == "ban"
    assert next(iter(enforcement_item["duration_days"].values())) == "30"


def test_resolve_ticket_rejects_invalid_state_transition(monkeypatch) -> None:
    from app.routers import admin_moderation
    from botocore.exceptions import ClientError

    ticket_item = {
        "ticket_id": "modtk_transition",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "closed",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 1,
        "aggregated_topics": ["spam"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_target"})

    def _tx(*, TransactItems):
        raise ClientError({"Error": {"Code": "TransactionCanceledException", "Message": "conditional failed"}}, "TransactWriteItems")

    monkeypatch.setattr(admin_moderation.ddb.meta.client, "transact_write_items", _tx)

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_transition/resolve",
        json={"resolution": "content_removed", "enforcement_action": "none"},
    )
    assert resp.status_code == 409


def test_resolve_ticket_rejects_duration_for_non_ban(monkeypatch) -> None:
    from app.routers import admin_moderation

    ticket_item = {
        "ticket_id": "modtk_duration_invalid",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 1,
        "aggregated_topics": ["spam"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_duration_invalid/resolve",
        json={"resolution": "content_removed", "enforcement_action": "warn", "enforcement_duration_days": 7},
    )
    assert resp.status_code == 400


def test_decide_ticket_ban_requires_senior_scope(monkeypatch) -> None:
    from app.routers import admin_moderation

    ticket_item = {
        "ticket_id": "modtk_decide_perm_ban",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 2,
        "aggregated_topics": ["criminal"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_target"})

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_decide_perm_ban/decision",
        json={"decision": "ban", "note": "perm ban should require senior"},
    )

    assert resp.status_code == 403
    assert resp.json()["detail"]["required_scope"] == "content_moderation_senior"


def test_resolve_ticket_permanent_ban_requires_senior_scope(monkeypatch) -> None:
    from app.routers import admin_moderation

    ticket_item = {
        "ticket_id": "modtk_resolve_perm_ban",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 2,
        "aggregated_topics": ["criminal"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_target"})

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_resolve_perm_ban/resolve",
        json={"resolution": "content_removed", "enforcement_action": "ban", "note": "perm ban should require senior"},
    )

    assert resp.status_code == 403
    assert resp.json()["detail"]["required_scope"] == "content_moderation_senior"


def test_resolve_ticket_permanent_ban_allowed_for_senior_scope(monkeypatch) -> None:
    from app.routers import admin_moderation

    ticket_item = {
        "ticket_id": "modtk_resolve_perm_ban_senior",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 2,
        "aggregated_topics": ["criminal"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_target"})
    monkeypatch.setattr(admin_moderation, "apply_content_removal", lambda **kwargs: {})
    monkeypatch.setattr(admin_moderation, "apply_ban", lambda **kwargs: {"status": "banned"})
    monkeypatch.setattr(admin_moderation, "issue_warning_notification", lambda **kwargs: {})
    monkeypatch.setattr(admin_moderation, "write_moderation_audit_event", lambda **kwargs: "audit_1")
    monkeypatch.setattr(admin_moderation.T.moderation_tickets, "update_item", lambda **kwargs: {})
    monkeypatch.setattr(admin_moderation.ddb.meta.client, "transact_write_items", lambda **kwargs: {})

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION, AdminScope.CONTENT_MODERATION_SENIOR)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_resolve_perm_ban_senior/resolve",
        json={"resolution": "content_removed", "enforcement_action": "ban", "note": "senior perm ban"},
    )

    assert resp.status_code == 200
    assert resp.json()["ticket_id"] == "modtk_resolve_perm_ban_senior"


def test_resolve_ticket_permanent_ban_requires_second_approver_when_flag_enabled(monkeypatch) -> None:
    from app.routers import admin_moderation

    ticket_item = {
        "ticket_id": "modtk_resolve_perm_ban_dual",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 2,
        "aggregated_topics": ["criminal"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "S", type("_S", (), {"moderation_dual_approval_permanent_ban_enabled": True})())
    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_target"})

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION, AdminScope.CONTENT_MODERATION_SENIOR)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_resolve_perm_ban_dual/resolve",
        json={"resolution": "content_removed", "enforcement_action": "ban", "note": "perm ban requires dual"},
    )

    assert resp.status_code == 403
    assert "second approver" in str(resp.json()["detail"]).lower()


def test_resolve_ticket_permanent_ban_allows_second_approver_when_flag_enabled(monkeypatch) -> None:
    from app.routers import admin_moderation

    ticket_item = {
        "ticket_id": "modtk_resolve_perm_ban_dual_ok",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 2,
        "aggregated_topics": ["criminal"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "S", type("_S", (), {"moderation_dual_approval_permanent_ban_enabled": True})())
    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_target"})
    monkeypatch.setattr(admin_moderation, "apply_content_removal", lambda **kwargs: {})
    monkeypatch.setattr(admin_moderation, "apply_ban", lambda **kwargs: {"status": "banned"})
    monkeypatch.setattr(admin_moderation, "issue_warning_notification", lambda **kwargs: {})
    monkeypatch.setattr(admin_moderation, "write_moderation_audit_event", lambda **kwargs: "audit_1")
    monkeypatch.setattr(admin_moderation.T.moderation_tickets, "update_item", lambda **kwargs: {})
    monkeypatch.setattr(admin_moderation.ddb.meta.client, "transact_write_items", lambda **kwargs: {})

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION, AdminScope.CONTENT_MODERATION_SENIOR)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_resolve_perm_ban_dual_ok/resolve",
        json={
            "resolution": "content_removed",
            "enforcement_action": "ban",
            "second_approver_admin_user_id": "admin_2",
            "note": "dual approved perm ban",
        },
    )

    assert resp.status_code == 200
    assert resp.json()["ticket_id"] == "modtk_resolve_perm_ban_dual_ok"


def test_decide_ticket_permanent_ban_requires_second_approver_when_flag_enabled(monkeypatch) -> None:
    from app.routers import admin_moderation

    ticket_item = {
        "ticket_id": "modtk_decide_perm_ban_dual",
        "entity_type": "moderation_ticket",
        "content_type": "feed_post",
        "content_id": "p1",
        "status": "open",
        "priority": "high",
        "queue": "newsfeed",
        "assigned_admin_user_id": "admin_1",
        "report_count": 2,
        "aggregated_topics": ["criminal"],
        "latest_report_at": "1700000001",
        "updated_at": "1700000001",
        "created_at": "1700000000",
    }

    monkeypatch.setattr(admin_moderation, "S", type("_S", (), {"moderation_dual_approval_permanent_ban_enabled": True})())
    monkeypatch.setattr(admin_moderation, "_get_ticket_or_404", lambda ticket_id: ticket_item)
    monkeypatch.setattr(admin_moderation, "_linked_reports", lambda ticket_id: [])
    monkeypatch.setattr(admin_moderation, "_content_snapshot", lambda ticket_item, reports: {"author_user_id": "u_target"})

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION, AdminScope.CONTENT_MODERATION_SENIOR)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_decide_perm_ban_dual/decision",
        json={"decision": "ban", "note": "perm ban requires dual"},
    )

    assert resp.status_code == 403
    assert "second approver" in str(resp.json()["detail"]).lower()


def test_list_tickets_respects_feature_flag_gate(monkeypatch) -> None:
    from app.routers import admin_moderation

    def _deny_board(_admin):
        raise HTTPException(status_code=403, detail="moderation board is disabled")

    monkeypatch.setattr(admin_moderation, "ensure_admin_board_enabled", _deny_board)

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.get("/v1/admin/moderation/tickets")
    assert resp.status_code == 403


def test_resolve_ticket_respects_feature_flag_gate(monkeypatch) -> None:
    from app.routers import admin_moderation

    def _deny_actions(_admin):
        raise HTTPException(status_code=403, detail="moderation actions are disabled")

    monkeypatch.setattr(admin_moderation, "ensure_admin_actions_enabled", _deny_actions)

    admin_user = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin_user)

    resp = client.post(
        "/v1/admin/moderation/tickets/modtk_feature_gate/resolve",
        json={"resolution": "no_violation", "enforcement_action": "none"},
    )
    assert resp.status_code == 403


def test_feature_flags_endpoint_root_can_update_and_admin_cannot(monkeypatch) -> None:
    from app.routers import admin_moderation

    monkeypatch.setattr(admin_moderation, "ensure_admin_board_enabled", lambda admin: None)
    monkeypatch.setattr(
        admin_moderation,
        "get_moderation_feature_flags",
        lambda: {
            "enabled": True,
            "report_feed_enabled": True,
            "report_messages_enabled": True,
            "report_profile_enabled": True,
            "admin_board_enabled": True,
            "admin_actions_enabled": True,
            "enforcement_enabled": True,
            "min_scope_for_board": "content_moderation",
            "min_scope_for_actions": "content_moderation",
            "min_scope_for_permanent_ban": "content_moderation_senior",
        },
    )
    monkeypatch.setattr(
        admin_moderation,
        "set_moderation_feature_flags",
        lambda updates: {
            "enabled": bool(updates.get("enabled", True)),
            "report_feed_enabled": True,
            "report_messages_enabled": True,
            "report_profile_enabled": True,
            "admin_board_enabled": True,
            "admin_actions_enabled": True,
            "enforcement_enabled": True,
            "min_scope_for_board": "content_moderation",
            "min_scope_for_actions": "content_moderation",
            "min_scope_for_permanent_ban": "content_moderation_senior",
        },
    )

    scoped_admin = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(scoped_admin)
    deny = client.put("/v1/admin/moderation/feature-flags", json={"enabled": False})
    assert deny.status_code == 403

    root_client = _client(AuthenticatedUser(sub="root_1", role=Role.ROOT))
    ok = root_client.put("/v1/admin/moderation/feature-flags", json={"enabled": False})
    assert ok.status_code == 200
    assert ok.json()["enabled"] is False
