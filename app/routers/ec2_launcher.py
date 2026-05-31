"""EC2 Instance Launcher API router (INFRA-003).

Prefix: /ui/remote/ec2
All endpoints use cookie-based session auth (require_ui_session).
"""

from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from app.services.sessions import require_ui_session
from app.models import (
    Ec2AmiInfo,
    Ec2AmiListOut,
    Ec2InstanceListOut,
    Ec2InstanceOut,
    Ec2InstanceTypeInfo,
    Ec2InstanceTypeListOut,
    Ec2LaunchIn,
)
from app.services.ec2_launcher import (
    AMIS,
    INSTANCE_TYPES,
    InstanceLimitExceeded,
    InstanceNotFound,
    InvalidInstanceState,
    launch_instance,
    list_instances,
    get_instance,
    reboot_instance,
    start_instance,
    stop_instance,
    terminate_instance,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/remote/ec2", tags=["ec2-launcher"])


def _instance_out(data: dict) -> Ec2InstanceOut:
    return Ec2InstanceOut(
        instance_id=data.get("instance_id", ""),
        ec2_instance_id=data.get("ec2_instance_id", ""),
        label=data.get("label", ""),
        instance_type=data.get("instance_type", ""),
        ami_id=data.get("ami_id", ""),
        ami_name=data.get("ami_name", ""),
        status=data.get("status", ""),
        public_ip=data.get("public_ip", ""),
        private_ip=data.get("private_ip", ""),
        ssh_key_id=data.get("ssh_key_id", ""),
        host_id=data.get("host_id", ""),
        created_at=int(data.get("created_at", 0)),
        started_at=int(data.get("started_at", 0)),
        stopped_at=int(data.get("stopped_at", 0)),
        terminated_at=int(data.get("terminated_at", 0)),
        last_activity_at=int(data.get("last_activity_at", 0)),
        auto_terminate_after=int(data.get("auto_terminate_after", 7200)),
    )


# ─── Instance type + AMI reference endpoints ─────────────────────

@router.get("/instance-types", response_model=Ec2InstanceTypeListOut)
async def list_instance_types(session: Dict = Depends(require_ui_session)):
    types = [
        Ec2InstanceTypeInfo(
            instance_type=k,
            vcpu=v["vcpu"],
            memory_gb=v["memory_gb"],
            cost_cents_per_min=v["cost_cents_per_min"],
        )
        for k, v in INSTANCE_TYPES.items()
    ]
    return Ec2InstanceTypeListOut(types=types)


@router.get("/amis", response_model=Ec2AmiListOut)
async def list_amis(session: Dict = Depends(require_ui_session)):
    amis = [
        Ec2AmiInfo(ami_id=k, name=v["name"], os_type=v["os_type"], username=v["username"])
        for k, v in AMIS.items()
    ]
    return Ec2AmiListOut(amis=amis)


# ─── Launch ──────────────────────────────────────────────────────

@router.post("/launch", status_code=201, response_model=Ec2InstanceOut)
async def launch_ec2_instance(
    body: Ec2LaunchIn,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = launch_instance(
            user_sub,
            label=body.label,
            instance_type=body.instance_type,
            ami_id=body.ami_id,
            ssh_key_id=body.ssh_key_id,
            auto_terminate_after=body.auto_terminate_after,
            startup_script=body.startup_script,
            template_id=body.template_id,
            security_group_id=body.security_group_id,
        )
    except InstanceLimitExceeded as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _instance_out(item)


# ─── List instances ──────────────────────────────────────────────

@router.get("/instances", response_model=Ec2InstanceListOut)
async def list_ec2_instances(
    status: str | None = None,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    items = list_instances(user_sub, status=status)
    instances = [_instance_out(i) for i in items]
    return Ec2InstanceListOut(instances=instances, count=len(instances))


# ─── Get single instance ────────────────────────────────────────

@router.get("/instances/{instance_id}", response_model=Ec2InstanceOut)
async def get_ec2_instance(
    instance_id: str,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    item = get_instance(user_sub, instance_id)
    if not item:
        raise HTTPException(status_code=404, detail="Instance not found")
    return _instance_out(item)


# ─── Stop ────────────────────────────────────────────────────────

@router.post("/instances/{instance_id}/stop", response_model=Ec2InstanceOut)
async def stop_ec2_instance(
    instance_id: str,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = stop_instance(user_sub, instance_id)
    except InstanceNotFound:
        raise HTTPException(status_code=404, detail="Instance not found")
    except InvalidInstanceState as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _instance_out(item)


# ─── Start ───────────────────────────────────────────────────────

@router.post("/instances/{instance_id}/start", response_model=Ec2InstanceOut)
async def start_ec2_instance(
    instance_id: str,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = start_instance(user_sub, instance_id)
    except InstanceNotFound:
        raise HTTPException(status_code=404, detail="Instance not found")
    except InvalidInstanceState as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _instance_out(item)


# ─── Terminate ───────────────────────────────────────────────────

@router.post("/instances/{instance_id}/terminate", response_model=Ec2InstanceOut)
async def terminate_ec2_instance(
    instance_id: str,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = terminate_instance(user_sub, instance_id)
    except InstanceNotFound:
        raise HTTPException(status_code=404, detail="Instance not found")
    except InvalidInstanceState as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _instance_out(item)


# ─── Reboot ──────────────────────────────────────────────────────

@router.post("/instances/{instance_id}/reboot", response_model=Ec2InstanceOut)
async def reboot_ec2_instance(
    instance_id: str,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = reboot_instance(user_sub, instance_id)
    except InstanceNotFound:
        raise HTTPException(status_code=404, detail="Instance not found")
    except InvalidInstanceState as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _instance_out(item)
