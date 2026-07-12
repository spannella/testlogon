"""CRM Workflow Admin CRUD Router — WFL-009.

Provides REST endpoints for managing workflow rules, run history, and drip
sequences. All endpoints require admin or root auth. Gated by CRM_WORKFLOW_ENABLED.
"""
from __future__ import annotations

from typing import Optional

from boto3.dynamodb.conditions import Key
from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_admin_or_root_csrf
from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.models import (
    DripSequenceCreateIn,
    DripSequenceListOut,
    DripSequenceOut,
    DripSequenceUpdateIn,
    WorkflowRuleCreateIn,
    WorkflowRuleListOut,
    WorkflowRuleOut,
    WorkflowRuleUpdateIn,
    WorkflowRunListOut,
    WorkflowRunOut,
)
from app.services import workflow_drip_sequences as drip_svc
from app.services import workflow_rules as svc

router = APIRouter(prefix="/ui/admin/crm/workflow", tags=["admin-crm-workflow"])


def _require_flag() -> None:
    if not S.crm_workflow_enabled:
        raise HTTPException(status_code=404, detail="crm_workflow not enabled")


def _run_to_out(item: dict) -> WorkflowRunOut:
    return WorkflowRunOut(
        run_id=item.get("run_id", ""),
        rule_id=item.get("rule_id", ""),
        target_module=item.get("target_module", ""),
        record_id=item.get("record_id", ""),
        trigger_type=item.get("trigger_type", ""),
        outcome=item.get("outcome", ""),
        actions_fired=item.get("actions_fired") or [],
        started_at=int(item.get("started_at", 0)),
        finished_at=int(item["finished_at"]) if item.get("finished_at") else None,
        error_message=item.get("error_message"),
    )


def _seq_to_out(seq: dict) -> DripSequenceOut:
    return DripSequenceOut(
        sequence_id=seq["sequence_id"],
        name=seq["name"],
        description=seq.get("description", ""),
        stages=seq.get("stages") or [],
        created_by=seq["created_by"],
        created_at=int(seq["created_at"]),
        updated_at=int(seq["updated_at"]),
    )


# ---------------------------------------------------------------------------
# Rule CRUD
# ---------------------------------------------------------------------------

@router.post("/rules", response_model=WorkflowRuleOut, status_code=201)
async def create_workflow_rule(
    body: WorkflowRuleCreateIn,
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> WorkflowRuleOut:
    _require_flag()
    try:
        rule = svc.create_rule(
            created_by=_actor.sub,
            name=body.name,
            description=body.description,
            target_module=body.target_module,
            trigger_type=body.trigger_type,
            trigger_config=body.trigger_config,
            conditions=[c.model_dump() for c in body.conditions],
            actions=[a.model_dump() for a in body.actions],
            enabled=body.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except OverflowError as exc:
        raise HTTPException(status_code=507, detail=str(exc))
    return WorkflowRuleOut(**rule)


@router.get("/rules", response_model=WorkflowRuleListOut)
async def list_workflow_rules(
    target_module: Optional[str] = Query(default=None),
    enabled_only: bool = Query(default=False),
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> WorkflowRuleListOut:
    _require_flag()
    result = svc.list_rules(
        target_module=target_module,
        enabled_only=enabled_only,
        limit=limit,
        cursor=cursor,
    )
    return WorkflowRuleListOut(
        rules=[WorkflowRuleOut(**r) for r in result["rules"]],
        cursor=result.get("cursor"),
    )


@router.get("/rules/{rule_id}", response_model=WorkflowRuleOut)
async def get_workflow_rule(
    rule_id: str,
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> WorkflowRuleOut:
    _require_flag()
    rule = svc.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return WorkflowRuleOut(**rule)


@router.patch("/rules/{rule_id}", response_model=WorkflowRuleOut)
async def update_workflow_rule(
    rule_id: str,
    body: WorkflowRuleUpdateIn,
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> WorkflowRuleOut:
    _require_flag()
    update_data = body.model_dump(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=422, detail="No fields to update")

    # Convert pydantic sub-models back to plain dicts
    if "conditions" in update_data and update_data["conditions"] is not None:
        update_data["conditions"] = [
            c.model_dump() if hasattr(c, "model_dump") else c
            for c in update_data["conditions"]
        ]
    if "actions" in update_data and update_data["actions"] is not None:
        update_data["actions"] = [
            a.model_dump() if hasattr(a, "model_dump") else a
            for a in update_data["actions"]
        ]

    rule = svc.update_rule(rule_id, updated_by=_actor.sub, **update_data)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return WorkflowRuleOut(**rule)


@router.delete("/rules/{rule_id}")
async def delete_workflow_rule(
    rule_id: str,
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> dict:
    _require_flag()
    svc.delete_rule(rule_id, deleted_by=_actor.sub)
    return {"ok": True}


@router.post("/rules/{rule_id}/enable", response_model=WorkflowRuleOut)
async def enable_workflow_rule(
    rule_id: str,
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> WorkflowRuleOut:
    _require_flag()
    rule = svc.enable_rule(rule_id, actor=_actor.sub)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return WorkflowRuleOut(**rule)


@router.post("/rules/{rule_id}/disable", response_model=WorkflowRuleOut)
async def disable_workflow_rule(
    rule_id: str,
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> WorkflowRuleOut:
    _require_flag()
    rule = svc.disable_rule(rule_id, actor=_actor.sub)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return WorkflowRuleOut(**rule)


# ---------------------------------------------------------------------------
# Run history
# ---------------------------------------------------------------------------

@router.get("/rules/{rule_id}/runs", response_model=WorkflowRunListOut)
async def list_rule_runs(
    rule_id: str,
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> WorkflowRunListOut:
    _require_flag()
    from app.core.tables import T

    exclusive_start = decode_cursor(cursor)
    kwargs: dict = dict(
        KeyConditionExpression=Key("pk").eq(f"RULE#{rule_id}") & Key("sk").begins_with("RUN#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    if exclusive_start:
        kwargs["ExclusiveStartKey"] = exclusive_start
    resp = T.crm_workflow_runs.query(**kwargs)
    runs = [_run_to_out(item) for item in resp.get("Items", [])]
    return WorkflowRunListOut(runs=runs, cursor=encode_cursor(resp.get("LastEvaluatedKey")))


# ---------------------------------------------------------------------------
# Drip sequences (declared before /{rule_id} to prevent path collision)
# ---------------------------------------------------------------------------

@router.get("/drip-sequences", response_model=DripSequenceListOut)
async def list_drip_sequences(
    limit: int = Query(default=25, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> DripSequenceListOut:
    _require_flag()
    result = drip_svc.list_sequences(limit=limit, cursor=cursor)
    return DripSequenceListOut(
        sequences=[_seq_to_out(s) for s in result["sequences"]],
        cursor=result.get("cursor"),
    )


@router.post("/drip-sequences", response_model=DripSequenceOut, status_code=201)
async def create_drip_sequence(
    body: DripSequenceCreateIn,
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> DripSequenceOut:
    _require_flag()
    try:
        seq = drip_svc.create_sequence(
            created_by=_actor.sub,
            name=body.name,
            description=body.description,
            stages=[s.model_dump() for s in body.stages],
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _seq_to_out(seq)


@router.get("/drip-sequences/{sequence_id}", response_model=DripSequenceOut)
async def get_drip_sequence(
    sequence_id: str,
    _actor: AuthenticatedUser = Depends(require_admin_or_root),
) -> DripSequenceOut:
    _require_flag()
    seq = drip_svc.get_sequence(sequence_id)
    if not seq:
        raise HTTPException(status_code=404, detail="Drip sequence not found")
    return _seq_to_out(seq)


@router.patch("/drip-sequences/{sequence_id}", response_model=DripSequenceOut)
async def update_drip_sequence(
    sequence_id: str,
    body: DripSequenceUpdateIn,
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> DripSequenceOut:
    _require_flag()
    update_data = body.model_dump(exclude_unset=True)
    if "stages" in update_data and update_data["stages"] is not None:
        update_data["stages"] = [
            s.model_dump() if hasattr(s, "model_dump") else s
            for s in update_data["stages"]
        ]
    try:
        seq = drip_svc.update_sequence(sequence_id, updated_by=_actor.sub, **update_data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if seq is None:
        raise HTTPException(status_code=404, detail="Drip sequence not found")
    return _seq_to_out(seq)


@router.delete("/drip-sequences/{sequence_id}")
async def delete_drip_sequence(
    sequence_id: str,
    _actor: AuthenticatedUser = Depends(require_admin_or_root_csrf),
) -> dict:
    _require_flag()
    drip_svc.delete_sequence(sequence_id, deleted_by=_actor.sub)
    return {"ok": True}
