"""Risk scoring router (KYC-008).

User endpoints (prefix /ui/risk):
  GET /score        — own latest risk score
  GET /factors      — own risk factors

Admin endpoints (prefix /ui/admin/risk):
  GET  /high-risk                — list high-risk users
  GET  /users/{user_id}/profile  — full risk profile for a user
  POST /users/{user_id}/override — admin override a user's risk score
  GET  /users/{user_id}/factors  — risk factors for a user
  GET  /distribution             — tier distribution counts
  GET  /tier/{tier}              — list users in a tier
  POST /rescore/{case_id}        — re-score a specific case
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from typing import Any, Literal

from app.auth.deps import AuthenticatedUser, get_authenticated_user
from app.auth.policy import require_admin_or_root
from app.services.sessions import require_ui_session
from app.services.kyc_risk_scoring import KycRiskScoringService, RISK_TIERS

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RiskScoreOut(BaseModel):
    score_id: str
    case_id: str
    user_sub: str
    total_score: int = Field(ge=0, le=100)
    risk_tier: Literal["low", "medium", "high", "critical"]
    factors: dict[str, Any]
    trigger: str
    auto_action_taken: str = "none"
    model_version: str
    created_at: int
    previous_score: int | None = None
    previous_tier: str | None = None


class RiskFactorOut(BaseModel):
    factor_name: str
    score: int = Field(ge=0, le=100)
    weight: float
    weighted_score: float
    raw_value: str
    description: str


class RiskProfileOut(BaseModel):
    user_sub: str
    latest_score: RiskScoreOut | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)


class RiskOverrideIn(BaseModel):
    score: int = Field(ge=0, le=100)
    reason: str = Field(min_length=1, max_length=500)


class RiskDistributionOut(BaseModel):
    distribution: dict[str, int]
    total_scored: int
    auto_approve_rate: float
    auto_escalate_rate: float


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

user_router = APIRouter(prefix="/ui/risk", tags=["risk-scoring"])
admin_router = APIRouter(prefix="/ui/admin/risk", tags=["risk-scoring-admin"])


def _scoring_service() -> KycRiskScoringService:
    return KycRiskScoringService()


# ---------------------------------------------------------------------------
# User endpoints
# ---------------------------------------------------------------------------


@user_router.get("/score")
def get_own_risk_score(
    _ctx: dict = Depends(require_ui_session),
):
    """Get the current user's latest risk score."""
    user_sub = _ctx["user_sub"]
    svc = _scoring_service()
    score = svc.get_latest_score(user_sub=user_sub)
    if not score:
        return {"score": None}
    return {"score": score}


@user_router.get("/factors")
def get_own_risk_factors(
    _ctx: dict = Depends(require_ui_session),
):
    """Get the current user's risk factors from their latest score."""
    user_sub = _ctx["user_sub"]
    svc = _scoring_service()
    score = svc.get_latest_score(user_sub=user_sub)
    if not score:
        return {"factors": []}

    factors_map = score.get("factors", {})
    factors_list = []
    for name, data in factors_map.items():
        if isinstance(data, dict):
            factors_list.append({
                "factor_name": name,
                "score": data.get("score", 0),
                "weight": data.get("weight", 0),
                "weighted_score": data.get("weighted_score", 0),
                "raw_value": str(data.get("raw_value", "")),
                "description": data.get("description", ""),
            })
    return {"factors": factors_list}


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------


@admin_router.get("/high-risk")
def admin_list_high_risk_users(
    threshold: int = Query(default=70, ge=0, le=100),
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List users with risk score above threshold."""
    svc = _scoring_service()
    # Get users from high and critical tiers
    results = []
    for tier in ["high", "critical"]:
        items = svc.list_users_by_tier(tier=tier, limit=limit)
        results.extend(items)

    # Filter by threshold and sort
    filtered = [r for r in results if int(r.get("total_score", 0)) >= threshold]
    filtered.sort(key=lambda x: int(x.get("total_score", 0)), reverse=True)
    return {"items": filtered[:limit]}


@admin_router.get("/users/{user_id}/profile")
def admin_get_user_risk_profile(
    user_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Get full risk profile for a user (latest score + history)."""
    svc = _scoring_service()
    latest = svc.get_latest_score(user_sub=user_id)
    history = svc.get_score_history(user_sub=user_id, limit=25)
    return {
        "user_sub": user_id,
        "latest_score": latest,
        "history": history,
    }


@admin_router.post("/users/{user_id}/override")
def admin_override_risk_score(
    user_id: str,
    body: RiskOverrideIn,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Admin override a user's risk score."""
    svc = _scoring_service()
    result = svc.admin_override_risk_score(
        admin_id=user.sub,
        user_sub=user_id,
        score=body.score,
        reason=body.reason,
    )
    return {"ok": True, **result}


@admin_router.get("/users/{user_id}/factors")
def admin_get_user_factors(
    user_id: str,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Get risk factors for a user from their latest score."""
    svc = _scoring_service()
    score = svc.get_latest_score(user_sub=user_id)
    if not score:
        return {"factors": []}

    factors_map = score.get("factors", {})
    factors_list = []
    for name, data in factors_map.items():
        if isinstance(data, dict):
            factors_list.append({
                "factor_name": name,
                "score": data.get("score", 0),
                "weight": data.get("weight", 0),
                "weighted_score": data.get("weighted_score", 0),
                "raw_value": str(data.get("raw_value", "")),
                "description": data.get("description", ""),
            })
    return {"factors": factors_list}


@admin_router.get("/distribution")
def admin_get_risk_distribution(
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Get risk tier distribution counts."""
    svc = _scoring_service()
    return svc.get_tier_distribution()


@admin_router.get("/tier/{tier}")
def admin_list_users_by_tier(
    tier: str,
    limit: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List users in a specific risk tier."""
    if tier not in RISK_TIERS:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": f"Tier must be one of: {', '.join(RISK_TIERS.keys())}"},
        )
    svc = _scoring_service()
    items = svc.list_users_by_tier(tier=tier, limit=limit)
    return {"tier": tier, "items": items, "total": len(items)}


@admin_router.post("/rescore/{case_id}")
def admin_rescore_case(
    case_id: str,
    request: Request,
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Manually trigger re-scoring for a specific case."""
    from app.core.tables import T

    # Look up the case to get user_sub
    try:
        resp = T.kyc_cases.get_item(Key={"pk": f"KYC#{case_id}", "sk": "META"})
        case = resp.get("Item")
    except Exception:
        case = None

    if not case:
        raise HTTPException(status_code=404, detail={"code": "kyc_case_not_found", "message": "Case not found."})

    user_sub = case.get("user_sub", "")
    svc = _scoring_service()
    result = svc.compute_score(
        case_id=case_id,
        user_sub=user_sub,
        trigger="manual",
    )
    return {"ok": True, **result}


@admin_router.post("/rescore-approved")
def admin_rescore_approved_users(
    batch_size: int = Query(default=50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Batch re-score approved users for continuous monitoring."""
    from app.core.tables import T

    # Scan approved cases
    rescored = 0
    errors = 0
    tier_changes = 0
    svc = _scoring_service()

    scan_params: dict[str, Any] = {"Limit": batch_size}
    resp = T.kyc_cases.scan(**scan_params)
    for item in resp.get("Items", []):
        if item.get("status") != "approved":
            continue
        case_id = str(item.get("case_id", "") or item.get("pk", "").replace("KYC#", ""))
        user_sub = str(item.get("user_sub", ""))
        if not case_id or not user_sub:
            continue

        prev = svc.get_latest_score(user_sub=user_sub)
        prev_tier = prev.get("risk_tier") if prev else None

        try:
            result = svc.compute_score(
                case_id=case_id,
                user_sub=user_sub,
                trigger="continuous",
            )
            rescored += 1
            if prev_tier and result.get("risk_tier") != prev_tier:
                tier_changes += 1
        except Exception:
            errors += 1

        if rescored >= batch_size:
            break

    return {
        "rescored_count": rescored,
        "errors": errors,
        "tier_changes": tier_changes,
    }
