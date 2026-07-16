from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, Optional

from fastapi import HTTPException, Request

from app.services.api_metering_contract import route_id_from_request
from app.services.api_keys import effective_api_key_capabilities
from app.services.api_key_capabilities import expand_api_key_capabilities, WILDCARD_API_KEY_CAPABILITY
from app.services.api_key_route_scope_registry import resolve_required_scopes_for_route

EntitlementGate = Callable[[Request | None, Dict[str, Any], list[str]], bool | Dict[str, Any] | None]
RouteScopeResolver = Callable[[str], Iterable[str] | None]


def _normalize_required_scopes(required_scopes: Iterable[str] | None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for scope in required_scopes or []:
        normalized = (scope or "").strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def requires_scope(
    key_item: Dict[str, Any],
    required_scopes: Iterable[str] | None,
    *,
    request: Request | None = None,
    entitlement_gate: Optional[EntitlementGate] = None,
) -> Dict[str, Any]:
    # APIK-E0-1: an admin:all wildcard key is allowed on EVERY route (incl. unmapped),
    # bypassing per-scope and entitlement checks.
    _granted_all = set(expand_api_key_capabilities(effective_api_key_capabilities(key_item)))
    if WILDCARD_API_KEY_CAPABILITY in _granted_all:
        return {
            "ok": True,
            "wildcard": True,
            "required_scopes": _normalize_required_scopes(required_scopes),
            "granted_scopes": sorted(_granted_all),
            "api_key_id": str(key_item.get("key_id") or ""),
            "entitlement": None,
        }
    required = _normalize_required_scopes(required_scopes)
    if not required:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "api_key_scope_denied",
                "reason": "unmapped_route",
                "required_scopes": [],
                "missing_scopes": [],
                "granted_scopes": sorted(expand_api_key_capabilities(effective_api_key_capabilities(key_item))),
                "api_key_id": str(key_item.get("key_id") or ""),
            },
        )

    granted = set(expand_api_key_capabilities(effective_api_key_capabilities(key_item)))

    missing = [scope for scope in required if scope not in granted]
    if missing:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "api_key_scope_denied",
                "reason": "missing_scope",
                "required_scopes": required,
                "missing_scopes": missing,
                "granted_scopes": sorted(granted),
                "api_key_id": str(key_item.get("key_id") or ""),
            },
        )

    entitlement_context: Dict[str, Any] = {}
    if entitlement_gate is not None:
        gate_result = entitlement_gate(request, key_item, required)
        allowed = bool(gate_result)
        if isinstance(gate_result, dict):
            allowed = bool(gate_result.get("allowed", True))
            entitlement_context = dict(gate_result)
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "api_key_scope_denied",
                    "reason": "missing_entitlement",
                    "required_scopes": required,
                    "granted_scopes": sorted(granted),
                    "api_key_id": str(key_item.get("key_id") or ""),
                    "entitlement": entitlement_context or None,
                },
            )

    return {
        "ok": True,
        "required_scopes": required,
        "granted_scopes": sorted(granted),
        "api_key_id": str(key_item.get("key_id") or ""),
        "entitlement": entitlement_context or None,
    }


def requires_scope_for_request(
    request: Request,
    key_item: Dict[str, Any],
    *,
    resolve_required_scopes: RouteScopeResolver,
    entitlement_gate: Optional[EntitlementGate] = None,
) -> Dict[str, Any]:
    route_id = route_id_from_request(request)
    if not route_id:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "api_key_scope_denied",
                "reason": "route_id_missing",
                "required_scopes": [],
                "missing_scopes": [],
                "granted_scopes": sorted(expand_api_key_capabilities(effective_api_key_capabilities(key_item))),
                "api_key_id": str(key_item.get("key_id") or ""),
            },
        )

    required = list(resolve_required_scopes(route_id) or [])
    out = requires_scope(key_item, required, request=request, entitlement_gate=entitlement_gate)
    out["route_id"] = route_id
    return out


def requires_scope_for_request_from_registry(
    request: Request,
    key_item: Dict[str, Any],
    *,
    entitlement_gate: Optional[EntitlementGate] = None,
) -> Dict[str, Any]:
    return requires_scope_for_request(
        request,
        key_item,
        resolve_required_scopes=resolve_required_scopes_for_route,
        entitlement_gate=entitlement_gate,
    )
