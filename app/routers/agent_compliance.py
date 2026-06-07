"""Compliance & Security Agent router (AGENT-015).

Security finding CRUD + status workflow, periodic/manual audit lifecycle,
finding-trend aggregation, per-framework compliance status, and agent config.

Findings and audits are scoped to the authenticated user (``require_ui_session``)
so the platform owner only ever sees their own findings (security §7). The audit
trigger and config-write paths additionally require admin/root.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from app.auth.policy import require_admin_or_root
from app.models import (
    AgentComplianceStatusOut,
    CreateSecurityFindingIn,
    SecurityAgentConfigOut,
    SecurityAuditOut,
    SecurityAuditsListOut,
    SecurityFindingOut,
    SecurityFindingsListOut,
    SecurityTrendsOut,
    UpdateFindingStatusIn,
    UpdateSecurityConfigIn,
)
from app.services import agent_compliance as svc
from app.services.sessions import require_ui_session

agent_compliance_router = APIRouter(prefix="/ui/agents/compliance", tags=["agent-compliance"])


def _user_id(session: Dict[str, Any]) -> str:
    return str(session.get("user_sub") or "")


def _config_type_id(user_id: str) -> str:
    return f"{svc.COMPLIANCE_AGENT_TYPE}_{user_id}"


# ---------------------------------------------------------------------------
# Config schema
# ---------------------------------------------------------------------------


@agent_compliance_router.get("/config-schema")
async def get_config_schema(session=Depends(require_ui_session)):
    return svc.config_schema()


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@agent_compliance_router.post("/findings", response_model=SecurityFindingOut, status_code=201)
async def create_finding(
    body: CreateSecurityFindingIn,
    session=Depends(require_ui_session),
):
    user_id = _user_id(session)
    try:
        finding = svc.create_finding(
            user_id=user_id,
            agent_id=body.agent_id or _config_type_id(user_id),
            source=body.source,
            source_ref=body.source_ref,
            severity=body.severity,
            category=body.category,
            title=body.title,
            description=body.description,
            file_path=body.file_path,
            line_range=body.line_range,
            code_snippet=body.code_snippet,
            remediation=body.remediation,
        )
    except ValueError as exc:
        code = str(exc)
        if code == "invalid_category":
            raise HTTPException(status_code=422, detail=f"Invalid category: {body.category}")
        if code == "invalid_severity":
            raise HTTPException(status_code=422, detail=f"Invalid severity: {body.severity}")
        raise HTTPException(status_code=422, detail=f"Invalid source: {body.source}")
    return SecurityFindingOut(**finding)


@agent_compliance_router.get("/findings", response_model=SecurityFindingsListOut)
async def list_findings(
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    source_ref: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    user_id = _user_id(session)
    try:
        result = svc.list_findings(
            user_id=user_id,
            severity=severity,
            status=status,
            source_ref=source_ref,
            limit=limit,
            cursor=cursor,
        )
    except ValueError as exc:
        if str(exc) == "invalid_severity":
            raise HTTPException(status_code=422, detail=f"Invalid severity: {severity}")
        raise HTTPException(status_code=422, detail=f"Invalid status: {status}")
    return SecurityFindingsListOut(**result)


@agent_compliance_router.get("/findings/{finding_id}", response_model=SecurityFindingOut)
async def get_finding(finding_id: str, session=Depends(require_ui_session)):
    finding = svc.get_finding(user_id=_user_id(session), finding_id=finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Security finding not found")
    return SecurityFindingOut(**finding)


@agent_compliance_router.patch("/findings/{finding_id}/status", response_model=SecurityFindingOut)
async def update_finding_status(
    finding_id: str,
    body: UpdateFindingStatusIn,
    session=Depends(require_ui_session),
):
    try:
        finding = svc.update_finding_status(
            user_id=_user_id(session),
            finding_id=finding_id,
            status=body.status,
            note=body.note,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Security finding not found")
    except ValueError as exc:
        if str(exc) == "invalid_transition":
            raise HTTPException(
                status_code=409,
                detail="Cannot transition finding from a terminal state",
            )
        raise HTTPException(status_code=422, detail=f"Invalid status: {body.status}")
    return SecurityFindingOut(**finding)


# ---------------------------------------------------------------------------
# Audits
# ---------------------------------------------------------------------------


@agent_compliance_router.get("/audits", response_model=SecurityAuditsListOut)
async def list_audits(
    limit: int = Query(default=20, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    session=Depends(require_ui_session),
):
    result = svc.list_audits(user_id=_user_id(session), limit=limit, cursor=cursor)
    return SecurityAuditsListOut(**result)


@agent_compliance_router.get("/audits/{audit_id}", response_model=SecurityAuditOut)
async def get_audit(audit_id: str, session=Depends(require_ui_session)):
    audit = svc.get_audit(user_id=_user_id(session), audit_id=audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Audit not found")
    return SecurityAuditOut(**audit)


@agent_compliance_router.post("/audits/trigger", response_model=SecurityAuditOut)
async def trigger_audit(
    session=Depends(require_ui_session),
    admin=Depends(require_admin_or_root),
):
    user_id = _user_id(session)
    try:
        audit = svc.run_mock_audit(
            user_id=user_id,
            agent_id=_config_type_id(user_id),
            worker_id="mock-worker",
        )
    except ValueError as exc:
        if str(exc) == "audit_in_progress":
            raise HTTPException(status_code=409, detail="A security audit is already in progress")
        raise HTTPException(status_code=422, detail=str(exc))
    return SecurityAuditOut(**audit)


# ---------------------------------------------------------------------------
# Trends & compliance status
# ---------------------------------------------------------------------------


@agent_compliance_router.get("/trends", response_model=SecurityTrendsOut)
async def get_trends(
    days: int = Query(default=90),
    session=Depends(require_ui_session),
):
    try:
        trends = svc.get_finding_trends(user_id=_user_id(session), days=days)
    except ValueError:
        raise HTTPException(status_code=422, detail="days must be between 1 and 365")
    return SecurityTrendsOut(**trends)


@agent_compliance_router.get("/compliance", response_model=AgentComplianceStatusOut)
async def get_compliance(session=Depends(require_ui_session)):
    return AgentComplianceStatusOut(**svc.get_compliance_status(user_id=_user_id(session)))


# ---------------------------------------------------------------------------
# Config (per-user agent type)
# ---------------------------------------------------------------------------


@agent_compliance_router.get("/config", response_model=SecurityAgentConfigOut)
async def get_config(session=Depends(require_ui_session)):
    user_id = _user_id(session)
    config = svc.get_security_config(agent_type_id=_config_type_id(user_id))
    if config is None:
        config = svc.get_effective_config(user_id=user_id)
    return SecurityAgentConfigOut(**svc.config_response_dict(config))


@agent_compliance_router.put("/config", response_model=SecurityAgentConfigOut)
async def update_config(
    body: UpdateSecurityConfigIn,
    session=Depends(require_ui_session),
    admin=Depends(require_admin_or_root),
):
    user_id = _user_id(session)
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    errors = svc.validate_security_config(patch)
    if errors:
        raise HTTPException(status_code=422, detail="; ".join(errors))
    result = svc.update_security_config(
        agent_type_id=_config_type_id(user_id), owner_sub=user_id, config=patch
    )
    return SecurityAgentConfigOut(**svc.config_response_dict(result))


# ---------------------------------------------------------------------------
# Verify remediation (agent re-check helper)
# ---------------------------------------------------------------------------


@agent_compliance_router.post("/findings/{finding_id}/verify-remediation")
async def verify_remediation(
    finding_id: str,
    body: Dict[str, Any] = Body(default_factory=dict),
    session=Depends(require_ui_session),
):
    user_id = _user_id(session)
    try:
        return svc.verify_remediation(
            user_id=user_id,
            finding_id=finding_id,
            agent_id=str(body.get("agent_id") or _config_type_id(user_id)),
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Security finding not found")
