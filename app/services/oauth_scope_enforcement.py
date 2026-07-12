"""OAU-004: Per-consumer scope enforcement on OAuth API calls.

Stateless helper — no DDB calls. Reads request.state.oauth_scope (set by
OAU-002's auth branch) and cross-references API_KEY_ROUTE_SCOPE_REGISTRY.
Non-OAuth callers (cookie/Cognito/API-key) are completely unaffected.

No dev_mode branch (SECOPS-007 parity).
"""
from __future__ import annotations

from typing import FrozenSet, List, Optional

from fastapi import HTTPException, Request

from app.core.settings import S
from app.services.alerts import audit_event
from app.services.api_key_route_scope_registry import (
    is_route_registered_or_exempt,
    resolve_required_scopes_for_route,
)
from app.services.api_metering_contract import route_id_from_request


def _parse_oauth_scope(raw: str) -> FrozenSet[str]:
    """Split a space-delimited OAuth scope string into a frozenset (lowercased)."""
    return frozenset(s.strip().lower() for s in (raw or "").split() if s.strip())


def enforce_oauth_scope_for_route(request: Request) -> None:
    """Enforce the OAuth token's granted_scope set against the route's required scopes.

    No-op when:
    - request carries no oauth_scope (non-OAuth caller)
    - route is not registered or is in the exemptions dict
    - all required scopes are present in the granted set

    Raises HTTP 403 with code="oauth_insufficient_scope" when any required scope is missing.
    """
    state = getattr(request, "state", None)
    raw_scope: Optional[str] = getattr(state, "oauth_scope", None)
    if not raw_scope:
        # Not an OAuth-bearer request; nothing to enforce.
        return

    route_id: Optional[str] = route_id_from_request(request)
    if not route_id:
        return

    if not is_route_registered_or_exempt(route_id):
        # Route is outside all known scope-enforcement prefixes; allow.
        return

    required: List[str] = resolve_required_scopes_for_route(route_id)
    if not required:
        # Route is in the exemptions dict; allow.
        return

    granted: FrozenSet[str] = _parse_oauth_scope(raw_scope)
    missing: List[str] = [s for s in required if s not in granted]

    if not missing:
        return

    user_sub: str = str(getattr(state, "oauth_user_sub", None) or "")
    client_id: str = str(getattr(state, "oauth_client_id", None) or "")

    audit_event(
        "oauth_scope_denied",
        user_sub,
        request,
        outcome="error",
        status_code=403,
        route_id=route_id,
        required_scopes=required,
        granted_scopes=sorted(granted),
        missing_scopes=missing,
        client_id=client_id,
    )

    raise HTTPException(
        status_code=403,
        detail={
            "code": "oauth_insufficient_scope",
            "message": "OAuth token does not have the required scopes for this route",
            "required_scopes": required,
            "granted_scopes": sorted(granted),
            "missing_scopes": missing,
            "route_id": route_id,
        },
    )
