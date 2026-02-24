from __future__ import annotations

from app.routers import entitlements as router


def test_get_entitlements_passes_filters_and_user(monkeypatch) -> None:
    captured = {}

    def _fake(user_id: str, *, product_type=None, status=None, source_system=None, lifecycle_status=None):
        captured["user_id"] = user_id
        captured["product_type"] = product_type
        captured["status"] = status
        captured["source_system"] = source_system
        captured["lifecycle_status"] = lifecycle_status
        return {"items": [], "count": 0, "generated_at": "2026-01-01T00:00:00+00:00"}

    monkeypatch.setattr(router, "list_user_entitlements", _fake)
    out = router.get_entitlements(
        product_type="file_bundle",
        status="active",
        source_system="subscription_cycle",
        lifecycle_status="active",
        ctx={"user_sub": "u-router"},
    )

    assert out["count"] == 0
    assert captured == {
        "user_id": "u-router",
        "product_type": "file_bundle",
        "status": "active",
        "source_system": "subscription_cycle",
        "lifecycle_status": "active",
    }


def test_get_entitlement_usage_passes_user_and_status(monkeypatch) -> None:
    captured = {}

    def _fake(user_id: str, *, status=None):
        captured["user_id"] = user_id
        captured["status"] = status
        return {"items": [], "count": 0, "generated_at": "2026-01-01T00:00:00+00:00"}

    monkeypatch.setattr(router, "list_api_package_usage", _fake)
    out = router.get_entitlement_usage(status="active", ctx={"user_sub": "u-router"})

    assert out["count"] == 0
    assert captured == {"user_id": "u-router", "status": "active"}
