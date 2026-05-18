from __future__ import annotations

from typing import Dict, Iterable, List, TypedDict


class RouteScopePolicy(TypedDict):
    product: str
    required_scopes: List[str]
    entitlement_required: bool


class RouteExemption(TypedDict):
    reason: str


# Initial rollout scope registry across filemanager, newsfeed, tickets, shopping, messager.
API_KEY_ROUTE_SCOPE_REGISTRY: Dict[str, RouteScopePolicy] = {
    # File Manager
    "GET:/v1/files": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/files/upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "GET:/v1/files/download": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/files/share": {"product": "filemanager", "required_scopes": ["filemanager:share"], "entitlement_required": True},
    # File Manager (actual router paths)
    "GET:/v1/fs/list": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/fs/folder": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "POST:/v1/fs/upload": {"product": "filemanager", "required_scopes": ["filemanager:write"], "entitlement_required": True},
    "GET:/v1/fs/download": {"product": "filemanager", "required_scopes": ["filemanager:read"], "entitlement_required": True},
    "POST:/v1/fs/share": {"product": "filemanager", "required_scopes": ["filemanager:share"], "entitlement_required": True},
    # Newsfeed
    "GET:/v1/newsfeed": {"product": "newsfeed", "required_scopes": ["newsfeed:read"], "entitlement_required": False},
    "POST:/v1/newsfeed/posts": {"product": "newsfeed", "required_scopes": ["newsfeed:write"], "entitlement_required": False},
    "DELETE:/v1/newsfeed/posts/{post_id}": {"product": "newsfeed", "required_scopes": ["newsfeed:moderate"], "entitlement_required": False},
    # Tickets
    "GET:/tickets": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "POST:/tickets": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "GET:/tickets/{ticket_id}": {"product": "tickets", "required_scopes": ["tickets:read"], "entitlement_required": True},
    "GET:/tickets/admin/summary": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/messages": {"product": "tickets", "required_scopes": ["tickets:write"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/assign": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    "POST:/tickets/{ticket_id}/status": {"product": "tickets", "required_scopes": ["tickets:admin"], "entitlement_required": True},
    # Shopping
    "GET:/ui/catalog/categories": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/categories/{category_id}/items": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/catalog/items/search": {"product": "shopping", "required_scopes": ["shopping:catalog:read"], "entitlement_required": False},
    "GET:/ui/shoppingcart/carts": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "GET:/ui/shoppingcart/carts/{cart_id}/items": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts/{cart_id}/items": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts/{cart_id}/items/catalog": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "PATCH:/ui/shoppingcart/carts/{cart_id}/items/{sku}": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "DELETE:/ui/shoppingcart/carts/{cart_id}/items/{sku}": {"product": "shopping", "required_scopes": ["shopping:cart:write"], "entitlement_required": False},
    "POST:/ui/shoppingcart/carts/{cart_id}/purchase": {"product": "shopping", "required_scopes": ["shopping:checkout:write"], "entitlement_required": True},
    "POST:/ui/purchase-history/transactions": {"product": "shopping", "required_scopes": ["shopping:checkout:write"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions/{txn_id}": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    "GET:/ui/purchase-history/transactions/search": {"product": "shopping", "required_scopes": ["shopping:orders:read"], "entitlement_required": True},
    # Messager
    "GET:/messaging/conversations": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "GET:/messaging/conversations/{conversation_id}/messages": {"product": "messager", "required_scopes": ["messager:read"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/image": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "POST:/messaging/conversations/{conversation_id}/messages/file": {"product": "messager", "required_scopes": ["messager:write"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "DELETE:/messaging/conversations/{conversation_id}/messages/{message_id}/revoke": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
    "PATCH:/messaging/conversations/{conversation_id}/messages/{message_id}": {"product": "messager", "required_scopes": ["messager:manage"], "entitlement_required": True},
}


API_KEY_ROUTE_EXEMPTIONS: Dict[str, RouteExemption] = {
    "GET:/health": {"reason": "health probe endpoint, not product API traffic"},
    "GET:/metrics": {"reason": "internal metrics endpoint"},
    "GET:/openapi.json": {"reason": "schema discovery endpoint"},
}

API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES = (
    "/v1/fs",
    "/v1/newsfeed",
    "/tickets",
    "/ui/catalog",
    "/ui/shoppingcart",
    "/ui/purchase-history",
    "/messaging",
)


# Tagged initial rollout routes that must be represented either as protected routes or explicit exemptions.
API_KEY_INITIAL_ROLLOUT_TAGGED_ROUTES: List[str] = sorted(
    set(list(API_KEY_ROUTE_SCOPE_REGISTRY.keys()) + list(API_KEY_ROUTE_EXEMPTIONS.keys()))
)


def get_route_scope_policy(route_id: str) -> RouteScopePolicy | None:
    return API_KEY_ROUTE_SCOPE_REGISTRY.get((route_id or "").strip())


def resolve_required_scopes_for_route(route_id: str) -> List[str]:
    policy = get_route_scope_policy(route_id)
    if not policy:
        return []
    return list(policy["required_scopes"])


def is_entitlement_required_for_route(route_id: str) -> bool:
    policy = get_route_scope_policy(route_id)
    if not policy:
        return False
    return bool(policy["entitlement_required"])


def get_route_exemption(route_id: str) -> RouteExemption | None:
    return API_KEY_ROUTE_EXEMPTIONS.get((route_id or "").strip())


def missing_registered_route_ids(live_route_ids: Iterable[str]) -> List[str]:
    live = {(route_id or "").strip() for route_id in live_route_ids if (route_id or "").strip()}
    return sorted(route_id for route_id in API_KEY_ROUTE_SCOPE_REGISTRY.keys() if route_id not in live)


def unregistered_live_route_ids(live_route_ids: Iterable[str]) -> List[str]:
    live = {(route_id or "").strip() for route_id in live_route_ids if (route_id or "").strip()}
    out: List[str] = []
    for route_id in sorted(live):
        if route_id in API_KEY_ROUTE_SCOPE_REGISTRY or route_id in API_KEY_ROUTE_EXEMPTIONS:
            continue
        _, _, path = route_id.partition(":")
        if not path:
            continue
        if any(path.startswith(prefix) for prefix in API_KEY_INITIAL_ROLLOUT_PATH_PREFIXES):
            out.append(route_id)
    return out


def is_route_registered_or_exempt(route_id: str) -> bool:
    normalized = (route_id or "").strip()
    return normalized in API_KEY_ROUTE_SCOPE_REGISTRY or normalized in API_KEY_ROUTE_EXEMPTIONS


def summarize_registry_drift(live_route_ids: Iterable[str], *, preview_limit: int = 25) -> Dict[str, object]:
    missing = missing_registered_route_ids(live_route_ids)
    unregistered = unregistered_live_route_ids(live_route_ids)
    limit = max(0, int(preview_limit))
    return {
        "stale_route_count": len(missing),
        "stale_route_preview": missing[:limit],
        "unregistered_live_route_count": len(unregistered),
        "unregistered_live_route_preview": unregistered[:limit],
    }


def classify_registry_drift(*, stale_route_count: int, unregistered_live_route_count: int, warn_threshold: int) -> str:
    stale = max(0, int(stale_route_count))
    unregistered = max(0, int(unregistered_live_route_count))
    threshold = max(0, int(warn_threshold))
    if unregistered > 0:
        return "critical"
    if stale > threshold:
        return "warning"
    return "ok"
