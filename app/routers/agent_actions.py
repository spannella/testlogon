"""Agent SSH QA action router (ADR-003 / AQA-006).

Submit / poll / list / cancel non-interactive SSH QA actions for an agent
worker. All routes use ``Depends(require_ui_session)`` so the action runs *as*
the owning ``user_sub``; credential + host resolution is keyed on that sub, so
cross-tenant access is structurally impossible.

The entire router is gated behind ``S.agent_ssh_qa_enabled`` (master flag,
default OFF). It is only registered in ``app/main.py`` when the flag is on, so
with the flag off the feature is fully dormant and existing behavior is
unchanged.
"""

from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from app.core.settings import S
from app.models import (
    AgentActionListOut,
    AgentActionOut,
    RunAgentActionIn,
)
from app.services import agent_ssh_exec as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/agents", tags=["agent-actions"])


def _require_enabled() -> None:
    if not getattr(S, "agent_ssh_qa_enabled", False):
        raise HTTPException(status_code=404, detail="Not found")


@router.post("/{worker_id}/actions", response_model=AgentActionOut)
async def submit_action(
    worker_id: str,
    body: RunAgentActionIn,
    ctx: Dict = Depends(require_ui_session),
):
    _require_enabled()
    try:
        action = svc.submit_action(
            ctx["user_sub"],
            worker_id,
            action_type=body.action_type,
            command=body.command,
            host_id=body.host_id,
            ssh_key_id=body.ssh_key_id,
            path_id=body.path_id,
            timeout_seconds=body.timeout_seconds,
        )
    except svc.AgentSshExecError as exc:
        if exc.code == "worker_not_found":
            raise HTTPException(status_code=404, detail=exc.message)
        if exc.code in ("rate_limited",):
            raise HTTPException(status_code=429, detail={"code": exc.code, "message": exc.message})
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})
    return AgentActionOut(**action)


@router.get("/{worker_id}/actions", response_model=AgentActionListOut)
async def list_actions(worker_id: str, ctx: Dict = Depends(require_ui_session)):
    _require_enabled()
    actions = svc.list_actions(worker_id)
    return AgentActionListOut(
        actions=[AgentActionOut(**a) for a in actions], count=len(actions)
    )


@router.get("/{worker_id}/actions/{action_id}", response_model=AgentActionOut)
async def get_action(worker_id: str, action_id: str, ctx: Dict = Depends(require_ui_session)):
    _require_enabled()
    action = svc.get_action(worker_id, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return AgentActionOut(**action)


@router.post("/{worker_id}/actions/{action_id}/cancel", response_model=AgentActionOut)
async def cancel_action(worker_id: str, action_id: str, ctx: Dict = Depends(require_ui_session)):
    _require_enabled()
    action = svc.cancel_action(ctx["user_sub"], worker_id, action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return AgentActionOut(**action)
