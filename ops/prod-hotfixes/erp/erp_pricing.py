"""ERP Pricing-Rules admin router (P1).

Exposes the previously-unmounted pricing_rules service over an operator/admin
surface: list rules for a creator, read one, create a rule, and deactivate a
rule. Admin/root only. Flag-gated behind S.pricing_rules_enabled (the service
raises 404 when off).

Pricing rules are creator-owned. This admin surface lists/reads by creator_id
and, on create, stamps created_by to the requested creator_id (or the admin).
Deactivate re-derives the rule owner so the service's owner check passes for an
admin override.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root
from app.services import pricing_rules as pricing_svc

router = APIRouter(prefix="/v1/admin/pricing-rules", tags=["admin-pricing-rules"])


class CreateRuleIn(BaseModel):
    creator_id: str = Field(..., min_length=1, max_length=200)
    name: str = Field(..., min_length=1, max_length=200)
    rule_type: str = Field(..., pattern="^(tiered|bulk|conditional)$")
    stacking_mode: str = Field(..., pattern="^(best_deal_wins|stackable)$")
    rule_config: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=500, ge=1, le=1000)
    description: str = Field(default="", max_length=1000)
    applies_to_checkout_types: Optional[List[str]] = None
    scope_category_ids: Optional[List[str]] = None
    scope_skus: Optional[List[str]] = None
    expires_at: int = Field(default=0, ge=0)
    max_uses: int = Field(default=0, ge=0)


@router.get("")
def list_rules(
    creator_id: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(default=100, ge=1, le=200),
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    return pricing_svc.list_rules(creator_id, limit=limit)


@router.get("/{rule_id}")
def get_rule(
    rule_id: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    rec = pricing_svc.get_rule(rule_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rec


@router.post("", status_code=201)
def create_rule(
    inp: CreateRuleIn,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    rec, err = pricing_svc.create_rule(
        creator_id=inp.creator_id,
        name=inp.name,
        rule_type=inp.rule_type,
        stacking_mode=inp.stacking_mode,
        rule_config=inp.rule_config,
        priority=inp.priority,
        description=inp.description,
        applies_to_checkout_types=inp.applies_to_checkout_types,
        scope_category_ids=inp.scope_category_ids,
        scope_skus=inp.scope_skus,
        expires_at=inp.expires_at,
        max_uses=inp.max_uses,
    )
    if err:
        raise HTTPException(status_code=400, detail=err)
    return rec


@router.post("/{rule_id}/deactivate")
def deactivate_rule(
    rule_id: str,
    actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> Dict[str, Any]:
    existing = pricing_svc.get_rule(rule_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    rec, err = pricing_svc.deactivate_rule(rule_id, existing.get("created_by", ""))
    if err:
        raise HTTPException(status_code=400, detail=err)
    return rec
