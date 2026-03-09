from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.roles import AdminProfile, AdminProfileType, AdminScope, Role
from app.routers.admin_moderation import router
from app.services import moderation_kpis


def _client(user: AuthenticatedUser) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_authenticated_user] = lambda: user
    return TestClient(app)


def test_compute_moderation_kpis_aggregates_expected_fields(monkeypatch) -> None:
    tickets = [
        {
            "entity_type": "moderation_ticket",
            "status": "open",
            "priority": "critical",
            "created_at": "1700000000",
        },
        {
            "entity_type": "moderation_ticket",
            "status": "closed",
            "priority": "high",
            "created_at": "1700000100",
            "resolved_at": "1700000700",
        },
    ]
    reports = [
        {
            "entity_type": "content_report",
            "created_at": "1700001000",
            "topics": ["criminal"],
        },
        {
            "entity_type": "content_report",
            "created_at": "1700001000",
            "topics": ["spam"],
        },
    ]
    enforcements = [
        {"entity_type": "user_enforcement", "created_at": "1700001000", "enforcement_type": "warn"},
        {"entity_type": "user_enforcement", "created_at": "1700001000", "enforcement_type": "ban"},
    ]

    monkeypatch.setattr(moderation_kpis, "_scan_all", lambda table, **kwargs: tickets if table is moderation_kpis.T.moderation_tickets else reports if table is moderation_kpis.T.content_reports else enforcements)

    out = moderation_kpis.compute_moderation_kpis(now_ts=1700001200, lookback_hours=24, surge_window_minutes=30)

    assert out["ticket_volume"] == 2
    assert out["resolution_count"] == 1
    assert out["resolution_latency_avg_seconds"] == 600
    assert out["critical_backlog"] == 1
    assert out["warning_count"] == 1
    assert out["ban_count"] == 1
    assert out["extortion_criminal_reports_window_count"] == 1


def test_evaluate_and_dispatch_moderation_alerts_notifies_oncall_and_dedupes(monkeypatch) -> None:
    monkeypatch.setattr(
        moderation_kpis,
        "compute_moderation_kpis",
        lambda **kwargs: {
            "surge_window_minutes": 15,
            "extortion_criminal_reports_window_count": 25,
            "critical_backlog": 30,
            "oldest_open_age_minutes": 200,
        },
    )
    monkeypatch.setattr(
        moderation_kpis,
        "S",
        type(
            "_S",
            (),
            {
                "moderation_oncall_user_subs": "oncall_1,oncall_2",
                "moderation_alert_extortion_criminal_surge_threshold": 10,
                "moderation_kpi_surge_window_minutes": 15,
                "moderation_alert_sla_open_critical_threshold": 20,
                "moderation_alert_sla_oldest_open_minutes_threshold": 120,
                "moderation_alert_sla_window_minutes": 30,
            },
        )(),
    )

    alerts: list[tuple] = []
    audit_calls: list[dict] = []
    monkeypatch.setattr(moderation_kpis, "write_alert", lambda *args, **kwargs: alerts.append((args, kwargs)) or {"alert_id": "a1"})
    monkeypatch.setattr(moderation_kpis, "write_moderation_audit_event", lambda **kwargs: audit_calls.append(kwargs) or "audit_1")
    monkeypatch.setattr(moderation_kpis, "_already_fired", lambda **kwargs: False)

    out = moderation_kpis.evaluate_and_dispatch_moderation_alerts(actor_user_id="admin_1", now_ts=1700001200)

    assert len(out["alerts_fired"]) == 2
    assert out["notified_user_subs"] == ["oncall_1", "oncall_2"]
    assert len(alerts) == 4  # 2 alert types x 2 recipients
    assert len(audit_calls) == 2


def test_moderation_kpis_router_requires_permissions() -> None:
    client = _client(AuthenticatedUser(sub="u1", role=Role.USER))

    resp = client.get("/v1/admin/moderation/kpis")
    assert resp.status_code == 403


def test_moderation_kpis_router_returns_data_and_eval(monkeypatch) -> None:
    from app.routers import admin_moderation

    monkeypatch.setattr(
        admin_moderation,
        "compute_moderation_kpis",
        lambda: {
            "generated_at": 1700001200,
            "lookback_hours": 24,
            "surge_window_minutes": 15,
            "ticket_volume": 10,
            "resolution_count": 8,
            "resolution_latency_avg_seconds": 100,
            "resolution_latency_p95_seconds": 180,
            "warning_count": 2,
            "ban_count": 1,
            "warning_rate": 0.6667,
            "ban_rate": 0.3333,
            "open_ticket_count": 2,
            "critical_backlog": 1,
            "oldest_open_age_minutes": 25,
            "extortion_criminal_reports_window_count": 3,
        },
    )
    monkeypatch.setattr(
        admin_moderation,
        "evaluate_and_dispatch_moderation_alerts",
        lambda actor_user_id: {
            "kpis": {
                "generated_at": 1700001200,
                "lookback_hours": 24,
                "surge_window_minutes": 15,
                "ticket_volume": 10,
                "resolution_count": 8,
                "resolution_latency_avg_seconds": 100,
                "resolution_latency_p95_seconds": 180,
                "warning_count": 2,
                "ban_count": 1,
                "warning_rate": 0.6667,
                "ban_rate": 0.3333,
                "open_ticket_count": 2,
                "critical_backlog": 1,
                "oldest_open_age_minutes": 25,
                "extortion_criminal_reports_window_count": 3,
            },
            "alerts_fired": [{"alert": "sla_breach"}],
            "notified_user_subs": ["oncall_1"],
        },
    )

    admin = AuthenticatedUser(
        sub="admin_1",
        role=Role.ADMIN,
        admin_profile=AdminProfile(type=AdminProfileType.SCOPED, scopes=(AdminScope.CONTENT_MODERATION,)),
    )
    client = _client(admin)

    summary = client.get("/v1/admin/moderation/kpis")
    assert summary.status_code == 200
    assert summary.json()["ticket_volume"] == 10

    eval_resp = client.post("/v1/admin/moderation/kpis/evaluate-alerts")
    assert eval_resp.status_code == 200
    assert eval_resp.json()["ok"] is True
    assert eval_resp.json()["alerts_fired"][0]["alert"] == "sla_breach"
