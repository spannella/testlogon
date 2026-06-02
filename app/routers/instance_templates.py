"""Instance Templates & Presets API router (INFRA-007).

Prefix: /ui/remote/templates
All endpoints use cookie-based session auth (require_ui_session).

Gallery of reusable launch templates: system templates (read-only, available
to all) + user templates (private, editable). Supports clone and one-click
launch-from-template (materializes a template into an EC2 / K8s launch).
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.settings import S
from app.models import (
    CloneTemplateIn,
    CreateTemplateIn,
    LaunchFromTemplateIn,
    LaunchFromTemplateOut,
    TemplateLaunchInstanceOut,
    TemplateLaunchPodOut,
    TemplateListOut,
    TemplateOut,
    UpdateTemplateIn,
)
from app.services.instance_templates import (
    SystemTemplateImmutable,
    TemplateNotFound,
    clone_template,
    create_template,
    delete_template,
    get_template,
    increment_use_count,
    list_templates,
    materialize_launch_payload,
    resolve_template,
    update_template,
)
from app.services.sessions import require_ui_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ui/remote/templates", tags=["instance-templates"])


def _require_enabled() -> None:
    if not S.instance_templates_enabled:
        raise HTTPException(status_code=400, detail="Instance templates are disabled")


# ─── Create ──────────────────────────────────────────────────────────────────

@router.post("", status_code=201, response_model=TemplateOut)
async def create_user_template(
    body: CreateTemplateIn,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    tpl = create_template(
        session["user_sub"],
        name=body.name,
        description=body.description,
        category=body.category,
        target=body.target,
        instance_type=body.instance_type,
        ami_id=body.ami_id,
        k8s_image=body.k8s_image,
        k8s_preset=body.k8s_preset,
        startup_script=body.startup_script,
        ports=body.ports,
        env_vars=body.env_vars,
        tags=body.tags,
        auto_terminate_after=body.auto_terminate_after,
        request=request,
    )
    return TemplateOut(**tpl)


# ─── List (gallery: system + caller's) ───────────────────────────────────────

@router.get("", response_model=TemplateListOut)
async def list_all_templates(
    category: Optional[str] = None,
    target: Optional[str] = None,
    include_system: bool = True,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    templates = list_templates(
        session["user_sub"],
        category=category,
        target=target,
        include_system=include_system,
    )
    return TemplateListOut(
        templates=[TemplateOut(**t) for t in templates],
        count=len(templates),
    )


# ─── Get detail ──────────────────────────────────────────────────────────────

@router.get("/{template_id}", response_model=TemplateOut)
async def get_template_detail(
    template_id: str,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    tpl = resolve_template(template_id, session["user_sub"])
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return TemplateOut(**tpl)


# ─── Update ──────────────────────────────────────────────────────────────────

@router.patch("/{template_id}", response_model=TemplateOut)
async def update_user_template(
    template_id: str,
    body: UpdateTemplateIn,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    try:
        tpl = update_template(
            session["user_sub"],
            template_id,
            request=request,
            **body.model_dump(exclude_unset=True),
        )
    except SystemTemplateImmutable as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except TemplateNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return TemplateOut(**tpl)


# ─── Delete ──────────────────────────────────────────────────────────────────

@router.delete("/{template_id}")
async def delete_user_template(
    template_id: str,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    try:
        delete_template(session["user_sub"], template_id, request=request)
    except SystemTemplateImmutable as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except TemplateNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"ok": True}


# ─── Clone ───────────────────────────────────────────────────────────────────

@router.post("/{template_id}/clone", status_code=201, response_model=TemplateOut)
async def clone_existing_template(
    template_id: str,
    body: CloneTemplateIn,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    try:
        tpl = clone_template(
            session["user_sub"], template_id, new_name=body.new_name, request=request
        )
    except TemplateNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return TemplateOut(**tpl)


# ─── Launch from template ────────────────────────────────────────────────────

@router.post("/{template_id}/launch", response_model=LaunchFromTemplateOut)
async def launch_from_template(
    template_id: str,
    body: LaunchFromTemplateIn,
    request: Request,
    session: Dict = Depends(require_ui_session),
):
    _require_enabled()
    if not S.template_launch_enabled:
        raise HTTPException(status_code=400, detail="Template launch is disabled")

    user_sub = session["user_sub"]
    template = resolve_template(template_id, user_sub)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    overrides = {
        "label": body.label,
        "instance_type": body.instance_type,
        "ami_id": body.ami_id,
        "k8s_image": body.k8s_image,
        "k8s_preset": body.k8s_preset,
        "auto_terminate_after": body.auto_terminate_after,
    }
    payload = materialize_launch_payload(
        template, label=body.label, overrides=overrides
    )

    try:
        if payload["target"] == "k8s":
            from app.services.k8s_launcher import launch_pod

            pod = launch_pod(
                user_sub,
                label=payload["label"],
                image=payload["image"],
                preset=payload["preset"] or "small",
                ssh_key_id=body.ssh_key_id,
                ttl_seconds=payload["ttl_seconds"],
                env_vars=payload.get("env_vars") or {},
                template_id=template_id,
            )
            increment_use_count(template.get("owner_sub", ""), template_id)
            from app.services.alerts import audit_event

            audit_event(
                "template.launched", user_sub, request,
                outcome="success", template_id=template_id,
                resource_id=pod.get("pod_id", ""), target="k8s",
            )
            return LaunchFromTemplateOut(
                target="k8s",
                template_id=template_id,
                resource_id=pod.get("pod_id", ""),
                pod=TemplateLaunchPodOut(
                    pod_id=pod.get("pod_id", ""),
                    label=pod.get("label", ""),
                    image=pod.get("image", ""),
                    preset=pod.get("preset", ""),
                    status=pod.get("status", ""),
                    pod_ip=pod.get("pod_ip", ""),
                    ttl_seconds=int(pod.get("ttl_seconds", 0)),
                ),
            )
        else:
            from app.services.ec2_launcher import launch_instance

            inst = launch_instance(
                user_sub,
                label=payload["label"],
                instance_type=payload["instance_type"],
                ami_id=payload["ami_id"],
                ssh_key_id=body.ssh_key_id,
                auto_terminate_after=payload["auto_terminate_after"],
                startup_script=payload["startup_script"],
                template_id=template_id,
            )
            increment_use_count(template.get("owner_sub", ""), template_id)
            from app.services.alerts import audit_event

            audit_event(
                "template.launched", user_sub, request,
                outcome="success", template_id=template_id,
                resource_id=inst.get("instance_id", ""), target="ec2",
            )
            return LaunchFromTemplateOut(
                target="ec2",
                template_id=template_id,
                resource_id=inst.get("instance_id", ""),
                instance=TemplateLaunchInstanceOut(
                    instance_id=inst.get("instance_id", ""),
                    label=inst.get("label", ""),
                    instance_type=inst.get("instance_type", ""),
                    ami_id=inst.get("ami_id", ""),
                    status=inst.get("status", ""),
                    public_ip=inst.get("public_ip", ""),
                    auto_terminate_after=int(inst.get("auto_terminate_after", 0)),
                ),
            )
    except HTTPException:
        raise
    except Exception as exc:  # launcher limit/validation errors
        raise HTTPException(status_code=400, detail=str(exc))
