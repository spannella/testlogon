"""Agent Workers router (AGENT-002).

Endpoints for creating, managing, and monitoring agent workers
that run AI coding tools on provisioned compute infrastructure.
"""

from __future__ import annotations

from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException

from app.models import (
    CreateWorkerIn,
    ProvisionStepOut,
    ToolInfo,
    ToolListOut,
    WorkerListOut,
    WorkerOut,
)
from app.services import agent_worker_provisioner as svc
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/ui/agent/workers", tags=["agent-workers"])


# ---------------------------------------------------------------------------
# Static metadata endpoints (tools + compute options)
# ---------------------------------------------------------------------------


@router.get("/tools", response_model=ToolListOut)
async def list_tools(_: Dict = Depends(require_ui_session)):
    """List available AI tools that can be installed on workers."""
    tools = [ToolInfo(**t) for t in svc.TOOL_INFO_LIST]
    return ToolListOut(tools=tools)


@router.get("/compute-options")
async def list_compute_options(_: Dict = Depends(require_ui_session)):
    """List available compute options (EC2 types + K8s presets).

    No ``response_model`` is declared: the ``ComputeOption`` model in
    ``app/models.py`` omits ``startup_seconds``, so declaring it would strip
    that field from the response. Returning the raw option dicts preserves the
    full shape (vcpu, memory_gb, cost_cents_per_min, startup_seconds).
    """
    return {"options": list(svc.COMPUTE_OPTIONS)}


# ---------------------------------------------------------------------------
# Worker CRUD
# ---------------------------------------------------------------------------


@router.post("", response_model=WorkerOut, status_code=201)
async def create_worker(body: CreateWorkerIn, ctx: Dict = Depends(require_ui_session)):
    """Create a new agent worker with automatic provisioning."""
    try:
        result = svc.create_worker(
            user_id=ctx["user_sub"],
            label=body.label,
            agent_type=body.agent_type,
            tool=body.tool,
            compute_type=body.compute_type,
            instance_type=body.instance_type,
            llm_key_id=body.llm_key_id,
            repo_url=body.repo_url,
            branch_convention=body.branch_convention,
            idle_timeout_seconds=body.idle_timeout_seconds,
            template_id=body.template_id,
            custom_install_commands=body.custom_install_commands,
            custom_env_var=body.custom_env_var,
            custom_verify_command=body.custom_verify_command,
        )
        return result
    except LookupError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("", response_model=WorkerListOut)
async def list_workers(
    status: str | None = None,
    agent_type: str | None = None,
    ctx: Dict = Depends(require_ui_session),
):
    """List all workers for the current user."""
    workers = svc.list_workers(ctx["user_sub"], status=status, agent_type=agent_type)
    return WorkerListOut(workers=workers, count=len(workers))


@router.get("/{worker_id}", response_model=WorkerOut)
async def get_worker(worker_id: str, ctx: Dict = Depends(require_ui_session)):
    """Get a single worker by ID."""
    result = svc.get_worker(ctx["user_sub"], worker_id)
    if not result:
        raise HTTPException(status_code=404, detail="Worker not found")
    return result


# ---------------------------------------------------------------------------
# Worker lifecycle
# ---------------------------------------------------------------------------


@router.post("/{worker_id}/stop", response_model=WorkerOut)
async def stop_worker(worker_id: str, ctx: Dict = Depends(require_ui_session)):
    """Stop a running worker."""
    try:
        return svc.stop_worker(ctx["user_sub"], worker_id)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=400, detail=msg)


@router.post("/{worker_id}/start", response_model=WorkerOut)
async def start_worker(worker_id: str, ctx: Dict = Depends(require_ui_session)):
    """Start a stopped worker."""
    try:
        return svc.start_worker(ctx["user_sub"], worker_id)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=400, detail=msg)


@router.delete("/{worker_id}", response_model=WorkerOut)
async def terminate_worker(worker_id: str, ctx: Dict = Depends(require_ui_session)):
    """Terminate a worker permanently."""
    try:
        return svc.terminate_worker(ctx["user_sub"], worker_id)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=400, detail=msg)


# ---------------------------------------------------------------------------
# Provision log
# ---------------------------------------------------------------------------


@router.get("/{worker_id}/provision-log", response_model=List[ProvisionStepOut])
async def get_provision_log(worker_id: str, ctx: Dict = Depends(require_ui_session)):
    """Get the provisioning log for a worker."""
    worker = svc.get_worker(ctx["user_sub"], worker_id)
    if not worker:
        raise HTTPException(status_code=404, detail="Worker not found")
    return svc.get_provision_log(ctx["user_sub"], worker_id)
