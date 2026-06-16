from __future__ import annotations

from typing import Any, Dict

from fastapi import HTTPException, Request

from app.services.api_key_auth_dependency import require_api_key_principal
from app.services.api_key_authorization import requires_scope_for_request_from_registry
from app.services.api_key_rollout import evaluate_api_key_rollout
from app.services.api_key_route_scope_registry import get_route_scope_policy, is_entitlement_required_for_route
from app.services.api_metering_contract import route_id_from_request
from app.services import api_usage_entitlements
from app.services.alerts import audit_event
from app.services.api_key_error_contract import build_api_key_error_detail
from app.core.settings import S
from app.metrics import record_api_key_policy_decision


def _has_api_key_headers(request: Request) -> bool:
    auth = (request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("apikey "):
        return True
    return bool((request.headers.get("x-api-key") or request.headers.get("x-api_key") or "").strip())


def _has_bearer_header(request: Request) -> bool:
    auth = (request.headers.get("authorization") or "").strip().lower()
    return auth.startswith("bearer ")


async def maybe_enforce_api_key_route_policy(request: Request) -> None:
    if not _has_api_key_headers(request):
        return

    route_id = route_id_from_request(request)
    rollout: Dict[str, Any] = {
        "product": "",
        "phase": "ga",
        "enforce": True,
        "shadow": False,
        "reason": "policy_uninitialized",
    }
    principal: Dict[str, Any] = {}

    mode = str(getattr(S, "api_key_dual_credential_mode", "prefer_api_key") or "prefer_api_key").strip().lower()
    if _has_bearer_header(request):
        if mode == "prefer_session":
            record_api_key_policy_decision(
                mode="dual_credential",
                product="",
                outcome="bypass",
                reason="prefer_session",
            )
            audit_event(
                "api_key_dual_credential_bypass",
                "",
                request,
                outcome="success",
                reason="prefer_session",
            )
            return
        if mode == "reject":
            record_api_key_policy_decision(
                mode="dual_credential",
                product="",
                outcome="deny",
                reason="dual_credential_conflict",
            )
            audit_event(
                "api_key_dual_credential_reject",
                "",
                request,
                outcome="failure",
                reason="dual_credential_conflict",
            )
            raise HTTPException(
                status_code=400,
                detail=build_api_key_error_detail(
                    code="api_key_dual_credential_conflict",
                    reason="dual_credential_conflict",
                    message="Both API key and Bearer credentials were provided",
                    request=request,
                ),
            )

    try:
        principal = await require_api_key_principal(request)
        policy = get_route_scope_policy(route_id)
        rollout = evaluate_api_key_rollout(str(policy.get("product") or ""), principal) if policy else {
            "product": "",
            "phase": "ga",
            "enforce": True,
            "shadow": False,
            "reason": "route_unmapped",
        }
        request.state.api_key_rollout_decision = rollout

        key_item: Dict[str, Any] = {
            "key_id": principal.get("api_key_id"),
            "user_sub": principal.get("user_sub"),
            "capabilities": principal.get("capabilities") or [],
        }

        def _entitlement_gate(req: Request | None, _item: Dict[str, Any], _required_scopes: list[str]):
            route_id = route_id_from_request(req) if req is not None else ""
            if not route_id or not is_entitlement_required_for_route(route_id):
                return {"allowed": True, "reason": "not_required"}
            try:
                headers = api_usage_entitlements.enforce_api_package_entitlement_pre_request(req)
                return {"allowed": True, "headers": headers, "reason": "entitlement_ok"}
            except HTTPException as exc:
                return {"allowed": False, "reason": "api_entitlement_denied", "detail": exc.detail}

        if not rollout.get("enforce", True):
            try:
                shadow = requires_scope_for_request_from_registry(
                    request,
                    key_item,
                    entitlement_gate=_entitlement_gate,
                )
                request.state.api_key_shadow_decision = shadow
                audit_event(
                    "api_key_policy_shadow_eval",
                    str(principal.get("user_sub") or ""),
                    request,
                    outcome="success",
                    api_key_id=str(principal.get("api_key_id") or ""),
                    route_id=str(route_id or ""),
                    product=str(rollout.get("product") or ""),
                    phase=str(rollout.get("phase") or ""),
                    reason=str(rollout.get("reason") or ""),
                )
                record_api_key_policy_decision(
                    mode="shadow",
                    product=str(rollout.get("product") or ""),
                    outcome="allow",
                    reason="allowed",
                )
            except HTTPException as shadow_exc:
                request.state.api_key_shadow_error = shadow_exc.detail
                shadow_detail = shadow_exc.detail if isinstance(shadow_exc.detail, dict) else {}
                audit_event(
                    "api_key_policy_shadow_eval",
                    str(principal.get("user_sub") or ""),
                    request,
                    outcome="failure",
                    api_key_id=str(principal.get("api_key_id") or ""),
                    route_id=str(route_id or ""),
                    product=str(rollout.get("product") or ""),
                    phase=str(rollout.get("phase") or ""),
                    reason=str(getattr(shadow_exc, "detail", {})),
                )
                record_api_key_policy_decision(
                    mode="shadow",
                    product=str(rollout.get("product") or ""),
                    outcome="deny",
                    reason=str(shadow_detail.get("reason") or "denied"),
                )
            except Exception as shadow_exc:
                request.state.api_key_shadow_error = {
                    "reason": "internal_error",
                    "error_type": type(shadow_exc).__name__,
                }
                audit_event(
                    "api_key_policy_shadow_eval",
                    str(principal.get("user_sub") or ""),
                    request,
                    outcome="failure",
                    api_key_id=str(principal.get("api_key_id") or ""),
                    route_id=str(route_id or ""),
                    product=str(rollout.get("product") or ""),
                    phase=str(rollout.get("phase") or ""),
                    reason="internal_error",
                )
                record_api_key_policy_decision(
                    mode="shadow",
                    product=str(rollout.get("product") or ""),
                    outcome="error",
                    reason="internal_error",
                )
            return

        decision = requires_scope_for_request_from_registry(request, key_item, entitlement_gate=_entitlement_gate)
        request.state.api_key_scope_decision = decision
        record_api_key_policy_decision(
            mode=str(rollout.get("phase") or "enforce"),
            product=str(rollout.get("product") or ""),
            outcome="allow",
            reason="allowed",
        )
        entitlement = decision.get("entitlement") if isinstance(decision.get("entitlement"), dict) else {}
        if entitlement.get("headers"):
            request.state.api_key_entitlement_headers = dict(entitlement.get("headers") or {})
    except HTTPException as exc:
        if exc.status_code in (401, 403, 429):
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            reason = str(detail.get("reason") or "unknown")
            normalized_detail = build_api_key_error_detail(
                code=str(detail.get("code") or ("api_key_scope_denied" if exc.status_code == 403 else "api_key_error")),
                reason=reason,
                message=str(detail.get("message") or "API key policy denied request"),
                request=request,
                route_id=str(route_id or ""),
                product=str(rollout.get("product") or ""),
                api_key_id=str(principal.get("api_key_id") or ""),
                extra={
                    "required_scopes": detail.get("required_scopes"),
                    "missing_scopes": detail.get("missing_scopes"),
                    "granted_scopes": detail.get("granted_scopes"),
                    "entitlement": detail.get("entitlement"),
                },
            )
            exc = HTTPException(status_code=exc.status_code, detail=normalized_detail)
            record_api_key_policy_decision(
                mode=str(rollout.get("phase") or "enforce"),
                product=str(rollout.get("product") or ""),
                outcome="deny",
                reason=reason,
            )
        if exc.status_code == 403:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            audit_event(
                "api_key_scope_denied",
                str(principal.get("user_sub") or ""),
                request,
                outcome="failure",
                api_key_id=str(principal.get("api_key_id") or ""),
                route_id=str(route_id or ""),
                reason=str(detail.get("reason") or "unknown"),
            )
        raise exc
    except Exception as exc:
        record_api_key_policy_decision(
            mode=str(rollout.get("phase") or "enforce"),
            product=str(rollout.get("product") or ""),
            outcome="error",
            reason="internal_error",
        )
        audit_event(
            "api_key_policy_error",
            str(principal.get("user_sub") or ""),
            request,
            outcome="failure",
            api_key_id=str(principal.get("api_key_id") or ""),
            route_id=str(route_id or ""),
            product=str(rollout.get("product") or ""),
            reason="internal_error",
            error_type=type(exc).__name__,
        )
        raise HTTPException(
            status_code=500,
            detail=build_api_key_error_detail(
                code="api_key_policy_internal_error",
                reason="internal_error",
                message="API key policy evaluation failed",
                request=request,
                route_id=str(route_id or ""),
                product=str(rollout.get("product") or ""),
                api_key_id=str(principal.get("api_key_id") or ""),
            ),
        )

    # OAU-004: Per-consumer OAuth scope enforcement (no-op for all non-OAuth requests)
    from app.core.settings import S as _S
    if getattr(_S, "oauth_provider_scope_enforcement_enabled", False):
        from app.services.oauth_scope_enforcement import enforce_oauth_scope_for_route
        enforce_oauth_scope_for_route(request)
