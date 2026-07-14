from __future__ import annotations

from app.services import api_key_route_scope_registry as registry
from app.services.api_key_capabilities import is_known_api_key_capability


def test_registry_covers_all_five_products() -> None:
    products = {policy["product"] for policy in registry.API_KEY_ROUTE_SCOPE_REGISTRY.values()}
    assert {"filemanager", "newsfeed", "tickets", "shopping", "messager"}.issubset(products)


def test_unknown_route_defaults_to_deny_by_returning_empty_scopes() -> None:
    assert registry.resolve_required_scopes_for_route("GET:/v1/unknown") == []


def test_exemptions_have_explicit_rationale() -> None:
    for route_id, exemption in registry.API_KEY_ROUTE_EXEMPTIONS.items():
        assert route_id
        assert (exemption.get("reason") or "").strip()


def test_registry_scopes_are_known_capabilities() -> None:
    for route_id, policy in registry.API_KEY_ROUTE_SCOPE_REGISTRY.items():
        assert route_id
        assert policy["required_scopes"]
        for scope in policy["required_scopes"]:
            assert is_known_api_key_capability(scope), f"unknown scope {scope} in {route_id}"


def test_initial_rollout_tagged_routes_are_all_registered_or_explicitly_exempted() -> None:
    all_known = set(registry.API_KEY_ROUTE_SCOPE_REGISTRY) | set(registry.API_KEY_ROUTE_EXEMPTIONS)
    for route_id in registry.API_KEY_INITIAL_ROLLOUT_TAGGED_ROUTES:
        assert route_id in all_known


def test_tickets_registry_uses_helpdesk_route_templates_and_admin_gates() -> None:
    assert registry.resolve_required_scopes_for_route("POST:/tickets") == ["tickets:write"]
    assert registry.resolve_required_scopes_for_route("POST:/tickets/{ticket_id}/messages") == ["tickets:write"]
    assert registry.resolve_required_scopes_for_route("POST:/tickets/{ticket_id}/assign") == ["tickets:admin"]
    assert registry.resolve_required_scopes_for_route("POST:/tickets/{ticket_id}/status") == ["tickets:admin"]


def test_messager_registry_covers_initial_conversation_read_write_and_controls() -> None:
    assert registry.resolve_required_scopes_for_route("GET:/messaging/conversations") == ["messager:read"]
    assert registry.resolve_required_scopes_for_route("GET:/messaging/conversations/{conversation_id}/messages") == ["messager:read"]
    assert registry.resolve_required_scopes_for_route("POST:/messaging/conversations/{conversation_id}/messages") == ["messager:write"]
    assert registry.resolve_required_scopes_for_route("DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}") == ["messager:manage"]
    assert registry.resolve_required_scopes_for_route("DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/revoke") == ["messager:manage"]


def test_shopping_registry_covers_catalog_cart_checkout_and_orders() -> None:
    assert registry.resolve_required_scopes_for_route("GET:/ui/catalog/categories") == ["shopping:catalog:read"]
    assert registry.resolve_required_scopes_for_route("POST:/ui/shoppingcart/carts/{cart_id}/items") == ["shopping:cart:write"]
    assert registry.resolve_required_scopes_for_route("POST:/ui/shoppingcart/carts/{cart_id}/purchase") == ["shopping:checkout:write"]
    assert registry.resolve_required_scopes_for_route("GET:/ui/purchase-history/transactions") == ["shopping:orders:read"]


def test_missing_registered_route_ids_detects_stale_registry_entries() -> None:
    live = {
        "GET:/v1/fs/list",
        "POST:/v1/fs/upload",
        "GET:/v1/newsfeed",
    }
    missing = registry.missing_registered_route_ids(live)
    assert "GET:/tickets" in missing
    assert "GET:/v1/fs/list" not in missing


def test_is_route_registered_or_exempt_checks_both_tables() -> None:
    assert registry.is_route_registered_or_exempt("GET:/v1/fs/list") is True
    assert registry.is_route_registered_or_exempt("GET:/metrics") is True
    assert registry.is_route_registered_or_exempt("GET:/totally-unknown") is False


def test_summarize_registry_drift_reports_count_and_preview_limit() -> None:
    live = {"GET:/v1/fs/list"}
    summary = registry.summarize_registry_drift(live, preview_limit=3)
    assert summary["stale_route_count"] >= 1
    assert len(summary["stale_route_preview"]) <= 3
    assert "unregistered_live_route_count" in summary
    assert "unregistered_live_route_preview" in summary


def test_unregistered_live_route_ids_tracks_rollout_surface_routes_without_registry_entry() -> None:
    live = {
        "GET:/v1/fs/list",
        "GET:/v1/fs/unknown-surface",
        "GET:/internal/healthz",
    }
    out = registry.unregistered_live_route_ids(live)
    assert "GET:/v1/fs/unknown-surface" in out
    assert "GET:/internal/healthz" not in out


def test_classify_registry_drift_uses_critical_warning_ok_levels() -> None:
    assert registry.classify_registry_drift(stale_route_count=0, unregistered_live_route_count=1, warn_threshold=0) == "warning"  # R1: accidental unregistered -> warning, not critical
    assert registry.classify_registry_drift(stale_route_count=3, unregistered_live_route_count=0, warn_threshold=2) == "critical"  # R1: stale beyond threshold -> critical
    assert registry.classify_registry_drift(stale_route_count=2, unregistered_live_route_count=0, warn_threshold=2) == "ok"
