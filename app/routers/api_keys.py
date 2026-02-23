from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.models import CreateApiKeyReq, RevokeApiKeyReq, ApiKeyIpRulesReq, ApiKeySelfLimitsReq, ApiKeyLimitsPatchReq
from app.services.api_keys import create_api_key, list_api_keys, revoke_api_key, set_api_key_ip_rules, set_api_key_self_limits, get_api_key_item
from app.services.alerts import audit_event
from app.services.api_usage_metering import _api_usage_table, get_api_key_usage_period_totals
from app.services.sessions import require_ui_session, require_fresh_mfa

router = APIRouter(prefix="/ui", tags=["api-keys"])

@router.get("/api_keys")
async def ui_list_api_keys(ctx=Depends(require_ui_session)):
    return {"keys": list_api_keys(ctx["user_sub"])}

@router.post("/api_keys")
async def ui_create_api_key(req: Request, body: CreateApiKeyReq, ctx=Depends(require_ui_session)):
    require_fresh_mfa(ctx)
    created = create_api_key(ctx["user_sub"], body.label or "", expires_in_days=body.expires_in_days)
    audit_event("api_key_create", ctx["user_sub"], req, outcome="success", key_id=created["key_id"])
    return created

@router.post("/api_keys/revoke")
async def ui_revoke_api_key(req: Request, body: RevokeApiKeyReq, ctx=Depends(require_ui_session)):
    require_fresh_mfa(ctx)
    revoke_api_key(ctx["user_sub"], body.key_id)
    audit_event("api_key_revoke", ctx["user_sub"], req, outcome="success", key_id=body.key_id)
    return {"ok": True}

@router.post("/api_keys/ip_rules")
async def ui_set_api_key_ip_rules(req: Request, body: ApiKeyIpRulesReq, ctx=Depends(require_ui_session)):
    require_fresh_mfa(ctx)
    rules = set_api_key_ip_rules(ctx["user_sub"], body.key_id, body.allow_cidrs, body.deny_cidrs)
    audit_event("api_key_ip_rules_set", ctx["user_sub"], req, outcome="success", key_id=body.key_id, allow=len(rules["allow_cidrs"]), deny=len(rules["deny_cidrs"]))
    return {"ok": True, "allow_cidrs": rules["allow_cidrs"], "deny_cidrs": rules["deny_cidrs"]}


@router.post("/api_keys/self_limits")
async def ui_set_api_key_self_limits(req: Request, body: ApiKeySelfLimitsReq, ctx=Depends(require_ui_session)):
    require_fresh_mfa(ctx)
    limits = set_api_key_self_limits(
        ctx["user_sub"],
        body.key_id,
        monthly_calls_cap=body.monthly_calls_cap,
        monthly_spend_cap_micros=body.monthly_spend_cap_micros,
        route_caps={route_id: cap.model_dump() for route_id, cap in body.route_caps.items()},
    )
    audit_event(
        "api_key_self_limits_set",
        ctx["user_sub"],
        req,
        outcome="success",
        key_id=body.key_id,
        monthly_calls_cap=limits["monthly_calls_cap"],
        monthly_spend_cap_micros=limits["monthly_spend_cap_micros"],
        route_caps_count=len(limits.get("route_caps") or {}),
    )
    return {"ok": True, **limits}


@router.patch("/api_keys/{key_id}/limits")
async def ui_patch_api_key_limits(req: Request, key_id: str, body: ApiKeyLimitsPatchReq, ctx=Depends(require_ui_session)):
    require_fresh_mfa(ctx)
    limits = set_api_key_self_limits(
        ctx["user_sub"],
        key_id,
        monthly_calls_cap=body.monthly_calls_cap,
        monthly_spend_cap_micros=body.monthly_spend_cap_micros,
        route_caps={route_id: cap.model_dump() for route_id, cap in body.route_caps.items()},
    )
    audit_event(
        "api_key_limits_patch",
        ctx["user_sub"],
        req,
        outcome="success",
        key_id=key_id,
        monthly_calls_cap=limits["monthly_calls_cap"],
        monthly_spend_cap_micros=limits["monthly_spend_cap_micros"],
        route_caps_count=len(limits.get("route_caps") or {}),
    )
    return limits


@router.get("/api_keys/{key_id}/usage")
async def ui_get_api_key_usage(key_id: str, period: str, ctx=Depends(require_ui_session)):
    if len(period or "") != 7 or period[4] != "-":
        raise HTTPException(400, "period must be YYYY-MM")
    try:
        month = int(period[5:7])
    except Exception:
        raise HTTPException(400, "period must be YYYY-MM")
    if month < 1 or month > 12:
        raise HTTPException(400, "period must be YYYY-MM")

    key_item = get_api_key_item(key_id)
    if not key_item or str(key_item.get("user_sub") or "") != str(ctx["user_sub"]):
        raise HTTPException(404, "API key not found")

    table = _api_usage_table()
    totals = get_api_key_usage_period_totals(table, user_sub=ctx["user_sub"], key_id=key_id, period_id=period) if table is not None else {
        "user_sub": ctx["user_sub"],
        "api_key_id": key_id,
        "period_id": period,
        "calls_total": 0,
        "billable_calls_total": 0,
        "request_units_total": 0,
        "cost_subtotal_micros": 0,
    }

    monthly_calls_cap = int(key_item.get("monthly_calls_cap") or 0)
    monthly_spend_cap_micros = int(key_item.get("monthly_spend_cap_micros") or 0)
    calls_total = int(totals.get("calls_total") or 0)
    spend_total = int(totals.get("cost_subtotal_micros") or 0)

    return {
        "period": period,
        "key_id": key_id,
        "totals": totals,
        "limits": {
            "monthly_calls_cap": monthly_calls_cap,
            "monthly_spend_cap_micros": monthly_spend_cap_micros,
            "route_caps": key_item.get("route_caps") or {},
        },
        "remaining": {
            "monthly_calls_remaining": max(0, monthly_calls_cap - calls_total) if monthly_calls_cap > 0 else None,
            "monthly_spend_micros_remaining": max(0, monthly_spend_cap_micros - spend_total) if monthly_spend_cap_micros > 0 else None,
        },
    }
