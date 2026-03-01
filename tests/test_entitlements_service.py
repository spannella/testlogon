from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from app.services.entitlements_service import EntitlementsService, InMemoryEntitlementsRepository


def _now() -> datetime:
    return datetime.now(timezone.utc)


def test_grant_entitlement_supports_all_product_types() -> None:
    repo = InMemoryEntitlementsRepository()
    svc = EntitlementsService(repo)

    order_id = "ord_1"
    repo.orders[order_id] = {"order_id": order_id, "user_id": "u1", "status": "paid", "created_by": "tester"}
    repo.order_items[order_id] = [
        {
            "sku": "files-jan",
            "product_type": "file_bundle",
            "scope": {"allowed_actions": ["download_file"], "resource": {"date": "2026-01-02"}},
            "rental_duration_hours": 24,
        },
        {
            "sku": "api-pro",
            "product_type": "api_package",
            "scope": {"allowed_actions": ["request_units"], "resource": {}},
            "usage_limit": 100,
        },
        {
            "sku": "internal-msg",
            "product_type": "internal_api_package",
            "scope": {"allowed_actions": ["internal_call"], "resource": {"namespace": "messaging.*"}},
        },
    ]

    out = svc.grant_entitlement(order_id)
    assert len(out) == 3
    assert {e.product_type for e in out} == {"file_bundle", "api_package", "internal_api_package"}
    assert all(e.status == "active" for e in out)


def test_revoke_and_check_access_error_mapping() -> None:
    repo = InMemoryEntitlementsRepository()
    svc = EntitlementsService(repo)

    order_id = "ord_2"
    repo.orders[order_id] = {"order_id": order_id, "user_id": "u2", "status": "paid"}
    repo.order_items[order_id] = [
        {
            "sku": "api-basic",
            "product_type": "api_package",
            "scope": {"allowed_actions": ["call_route"], "resource": {"route_id": "GET:/v1/a"}},
            "usage_limit": 1,
        }
    ]
    ent = svc.grant_entitlement(order_id)[0]

    ok = svc.check_access("u2", "call_route", {"route_id": "GET:/v1/a"})
    denied = svc.check_access("u2", "call_route", {"route_id": "GET:/v1/b"})
    assert ok.allowed is True
    assert denied.reason_code == "denied"

    svc.consume_usage("u2", "call_route", 1, "k1")
    exhausted = svc.check_access("u2", "call_route", {"route_id": "GET:/v1/a"})
    assert exhausted.reason_code == "exhausted"

    svc.revoke_entitlement(ent.entitlement_id, "admin_action")
    revoked = svc.check_access("u2", "call_route", {"route_id": "GET:/v1/a"})
    assert revoked.allowed is False
    assert revoked.reason_code == "denied"


def test_expired_maps_to_expired_reason() -> None:
    repo = InMemoryEntitlementsRepository()
    svc = EntitlementsService(repo)
    order_id = "ord_3"
    repo.orders[order_id] = {"order_id": order_id, "user_id": "u3", "status": "paid"}
    repo.order_items[order_id] = [
        {
            "sku": "files-short",
            "product_type": "file_bundle",
            "starts_at": _now() - timedelta(days=2),
            "ends_at": _now() - timedelta(days=1),
            "scope": {"allowed_actions": ["download_file"], "resource": {"date": "2026-01-01"}},
        }
    ]
    svc.grant_entitlement(order_id)
    out = svc.check_access("u3", "download_file", {"date": "2026-01-01"})
    assert out.allowed is False
    assert out.reason_code == "expired"


def test_concurrent_consume_prevents_double_spend() -> None:
    repo = InMemoryEntitlementsRepository()
    svc = EntitlementsService(repo)

    order_id = "ord_4"
    repo.orders[order_id] = {"order_id": order_id, "user_id": "u4", "status": "paid"}
    repo.order_items[order_id] = [
        {
            "sku": "api-concurrency",
            "product_type": "api_package",
            "scope": {"allowed_actions": ["request_units"], "resource": {}},
            "usage_limit": 5,
        }
    ]
    svc.grant_entitlement(order_id)

    def do_consume(i: int):
        return svc.consume_usage("u4", "request_units", 1, f"id-{i}")

    with ThreadPoolExecutor(max_workers=16) as pool:
        res = list(pool.map(do_consume, range(12)))

    consumed = [r for r in res if r.consumed]
    denied = [r for r in res if not r.consumed]
    assert len(consumed) == 5
    assert all(r.reason_code in ("exhausted", None) for r in denied)


def test_idempotency_replay_and_conflict() -> None:
    repo = InMemoryEntitlementsRepository()
    svc = EntitlementsService(repo)

    order_id = "ord_5"
    repo.orders[order_id] = {"order_id": order_id, "user_id": "u5", "status": "paid"}
    repo.order_items[order_id] = [
        {
            "sku": "api-idem",
            "product_type": "api_package",
            "scope": {"allowed_actions": ["request_units"], "resource": {}},
            "usage_limit": 10,
        }
    ]
    svc.grant_entitlement(order_id)

    first = svc.consume_usage("u5", "request_units", 2, "idem-1")
    replay = svc.consume_usage("u5", "request_units", 2, "idem-1")
    conflict = svc.consume_usage("u5", "request_units", 3, "idem-1")

    assert first.consumed is True
    assert replay.consumed is True and replay.replayed is True
    assert conflict.consumed is False
    assert conflict.reason_code == "idempotency_conflict"
