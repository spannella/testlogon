"""Kubernetes Container Launcher API router (INFRA-004).

Prefix: /ui/remote/k8s
All endpoints use cookie-based session auth (require_ui_session).
"""

from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from app.services.sessions import require_ui_session
from app.models import (
    K8sImageInfo,
    K8sImageListOut,
    K8sLaunchPodIn,
    K8sPodListOut,
    K8sPodLogsOut,
    K8sPodOut,
    K8sPresetInfo,
    K8sPresetListOut,
)
from app.services.k8s_launcher import (
    IMAGE_ALLOWLIST,
    RESOURCE_PRESETS,
    InvalidImage,
    InvalidPreset,
    PodAlreadyTerminated,
    PodLimitReached,
    PodNotFound,
    get_pod,
    get_pod_logs,
    launch_pod,
    list_pods,
    terminate_pod,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/remote/k8s", tags=["k8s-launcher"])


def _pod_out(data: dict) -> K8sPodOut:
    return K8sPodOut(
        pod_id=data.get("pod_id", ""),
        k8s_pod_name=data.get("k8s_pod_name", ""),
        namespace=data.get("namespace", ""),
        label=data.get("label", ""),
        image=data.get("image", ""),
        image_display_name=data.get("image_display_name", ""),
        preset=data.get("preset", ""),
        cpu_millicores=int(data.get("cpu_millicores", 0)),
        memory_mb=int(data.get("memory_mb", 0)),
        status=data.get("status", ""),
        pod_ip=data.get("pod_ip", ""),
        service_hostname=data.get("service_hostname", ""),
        ssh_port=int(data.get("ssh_port", 22)),
        ssh_key_id=data.get("ssh_key_id", ""),
        host_id=data.get("host_id", ""),
        created_at=int(data.get("created_at", 0)),
        started_at=int(data.get("started_at", 0)),
        terminated_at=int(data.get("terminated_at", 0)),
        ttl_seconds=int(data.get("ttl_seconds", 14400)),
        expires_at=int(data.get("expires_at", 0)),
        last_activity_at=int(data.get("last_activity_at", 0)),
    )


# ─── Image + Preset reference endpoints ────────────────────────────

@router.get("/images", response_model=K8sImageListOut)
async def list_images(session: Dict = Depends(require_ui_session)):
    images = [
        K8sImageInfo(
            image=k,
            display_name=v["display_name"],
            os_type=v["os_type"],
            username=v["username"],
        )
        for k, v in IMAGE_ALLOWLIST.items()
    ]
    return K8sImageListOut(images=images)


@router.get("/presets", response_model=K8sPresetListOut)
async def list_presets(session: Dict = Depends(require_ui_session)):
    presets = [
        K8sPresetInfo(
            preset=k,
            cpu_millicores=v["cpu_millicores"],
            memory_mb=v["memory_mb"],
            cost_cents_per_min=v["cost_cents_per_min"],
        )
        for k, v in RESOURCE_PRESETS.items()
    ]
    return K8sPresetListOut(presets=presets)


# ─── Launch ─────────────────────────────────────────────────────────

@router.post("/launch", status_code=201, response_model=K8sPodOut)
async def launch_k8s_pod(
    body: K8sLaunchPodIn,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = launch_pod(
            user_sub,
            label=body.label,
            image=body.image,
            preset=body.preset,
            ssh_key_id=body.ssh_key_id,
            ttl_seconds=body.ttl_seconds,
            env_vars=body.env_vars,
            template_id=body.template_id,
        )
    except InvalidImage as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except InvalidPreset as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PodLimitReached as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _pod_out(item)


# ─── List pods ──────────────────────────────────────────────────────

@router.get("/pods", response_model=K8sPodListOut)
async def list_k8s_pods(
    status: str | None = None,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    items = list_pods(user_sub, status=status)
    pods = [_pod_out(i) for i in items]
    return K8sPodListOut(pods=pods, count=len(pods))


# ─── Get single pod ────────────────────────────────────────────────

@router.get("/pods/{pod_id}", response_model=K8sPodOut)
async def get_k8s_pod(
    pod_id: str,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    item = get_pod(user_sub, pod_id)
    if not item:
        raise HTTPException(status_code=404, detail="Pod not found")
    return _pod_out(item)


# ─── Get pod logs ──────────────────────────────────────────────────

@router.get("/pods/{pod_id}/logs", response_model=K8sPodLogsOut)
async def get_k8s_pod_logs(
    pod_id: str,
    tail: int = Query(default=100, ge=1, le=1000),
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        lines = get_pod_logs(user_sub, pod_id, tail=tail)
    except PodNotFound:
        raise HTTPException(status_code=404, detail="Pod not found")
    return K8sPodLogsOut(pod_id=pod_id, lines=lines)


# ─── Terminate pod ─────────────────────────────────────────────────

@router.delete("/pods/{pod_id}", response_model=K8sPodOut)
async def terminate_k8s_pod(
    pod_id: str,
    session: Dict = Depends(require_ui_session),
):
    user_sub = session["user_sub"]
    try:
        item = terminate_pod(user_sub, pod_id)
    except PodNotFound:
        raise HTTPException(status_code=404, detail="Pod not found")
    except PodAlreadyTerminated as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return _pod_out(item)
