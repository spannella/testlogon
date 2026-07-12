"""CRM Project Management router — PRJ-001 through PRJ-010.

All routes are gated by S.crm_projects_enabled (CRM_PROJECTS_ENABLED env var, default OFF).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.cursor import decode_cursor, encode_cursor
from app.core.settings import S
from app.models import (
    CrmMilestoneSummaryResp,
    CrmProjectAddContactLinkIn,
    CrmProjectAddMemberIn,
    CrmProjectContactLinkListResp,
    CrmProjectContactLinkOut,
    CrmProjectCreateIn,
    CrmProjectListResp,
    CrmProjectMemberListResp,
    CrmProjectMemberOut,
    CrmProjectMemberRole,
    CrmProjectOut,
    CrmProjectStatus,
    CrmProjectStatusHistoryResp,
    CrmProjectTaskCreateReq,
    CrmProjectTaskListResp,
    CrmProjectTaskModel,
    CrmProjectTaskReorderReq,
    CrmProjectTaskUpdateReq,
    CrmProjectUpdateIn,
    CrmProjectUpdateMemberIn,
    CrmProjectWorkloadResp,
    CrmTemplateCreateIn,
    CrmTemplateFromProjectIn,
    CrmTemplateInstantiateIn,
    CrmTemplateListOut,
    CrmProjectTemplateModel,
)
from app.services.sessions import require_ui_session

router = APIRouter(prefix="/v1/crm/projects", tags=["crm-projects"])


# ---------------------------------------------------------------------------
# Guard helper (PRJ-001)
# ---------------------------------------------------------------------------

def _require_crm_projects() -> None:
    """Raise HTTP 404 when the CRM Projects feature flag is off.

    Called as the first statement in every route handler. Keeps flag enforcement
    co-located with the feature rather than in a middleware layer, exercisable
    in offline hermetic tests without spinning up the full FastAPI app.
    """
    if not S.crm_projects_enabled:
        raise HTTPException(status_code=404, detail="crm_projects_not_enabled")


def _current_user(ctx: Dict = Depends(require_ui_session)) -> str:
    return ctx["user_sub"]


# ===========================================================================
# PRJ-006: Template routes
# IMPORTANT: These must be declared BEFORE the /{project_id} parameterized
# routes to prevent FastAPI from matching the literal "templates" as project_id.
# ===========================================================================

@router.post("/templates", response_model=CrmProjectTemplateModel, status_code=201)
def create_template_route(
    body: CrmTemplateCreateIn,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_templates import create_template
    return create_template(user, body.name, description=body.description, task_defs=body.task_defs)


@router.post("/templates/from-project/{project_id}", response_model=CrmProjectTemplateModel, status_code=201)
def create_template_from_project_route(
    project_id: str,
    body: CrmTemplateFromProjectIn,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_templates import create_template_from_project
    return create_template_from_project(user, project_id, body.name, description=body.description)


@router.get("/templates", response_model=CrmTemplateListOut)
def list_templates_route(
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_templates import list_templates
    return list_templates(user, limit=limit, cursor=cursor)


@router.get("/templates/{template_id}", response_model=CrmProjectTemplateModel)
def get_template_route(
    template_id: str,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_templates import get_template
    return get_template(user, template_id)


@router.delete("/templates/{template_id}")
def delete_template_route(
    template_id: str,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_templates import delete_template
    return delete_template(user, template_id)


@router.post("/templates/{template_id}/instantiate", response_model=CrmProjectOut, status_code=201)
def instantiate_from_template_route(
    template_id: str,
    body: CrmTemplateInstantiateIn,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_templates import instantiate_from_template
    return instantiate_from_template(user, template_id, body.project_name, start_date=body.start_date)


# ===========================================================================
# PRJ-002: Project header CRUD
# ===========================================================================

@router.post("", response_model=CrmProjectOut, status_code=201)
def create_crm_project_route(
    body: CrmProjectCreateIn,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_projects import create_crm_project
    return create_crm_project(
        user,
        body.name,
        description=body.description,
        status=body.status,
        priority=body.priority,
        start_date=body.start_date,
        end_date=body.end_date,
        assigned_user_sub=body.assigned_user_sub,
        account_id=body.account_id,
    )


@router.get("", response_model=CrmProjectListResp)
def list_crm_projects_route(
    limit: int = Query(20, ge=1, le=100),
    cursor: Optional[str] = Query(default=None),
    status: Optional[CrmProjectStatus] = Query(default=None),
    name_query: Optional[str] = Query(default=None, max_length=120),
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_projects import list_crm_projects
    return list_crm_projects(user, limit=limit, cursor=cursor, status_filter=status, name_query=name_query)


@router.get("/{project_id}", response_model=CrmProjectOut)
def get_crm_project_route(
    project_id: str,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_projects import get_crm_project
    return get_crm_project(user, project_id)


@router.patch("/{project_id}", response_model=CrmProjectOut)
def update_crm_project_route(
    project_id: str,
    body: CrmProjectUpdateIn,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_projects import update_crm_project
    return update_crm_project(user, project_id, body)


@router.delete("/{project_id}")
def delete_crm_project_route(
    project_id: str,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_projects import delete_crm_project
    return delete_crm_project(user, project_id)


# ===========================================================================
# PRJ-003/004/005: Task routes
# Route ordering: fixed-path routes before parameterized ones to avoid
# capturing literal "order" or "milestones" as task_id values.
# ===========================================================================

@router.post("/{project_id}/tasks", response_model=CrmProjectTaskModel, status_code=201)
def create_task_route(
    project_id: str,
    body: CrmProjectTaskCreateReq,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_tasks import create_task
    return create_task(
        user,
        project_id,
        body.name,
        task_order=body.task_order,
        duration_days=body.duration_days,
        start_date=body.start_date,
        end_date=body.end_date,
        description=body.description,
        assigned_user_sub=body.assigned_user_sub,
        is_milestone=body.is_milestone,
        percent_complete=body.percent_complete,
        predecessor_task_ids=body.predecessor_task_ids,
        project_resource_type=body.project_resource_type,
        linked_contact_id=body.linked_contact_id,
    )


@router.get("/{project_id}/tasks", response_model=CrmProjectTaskListResp)
def list_tasks_route(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    milestones_only: bool = Query(default=False),
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_tasks import list_tasks
    result = list_tasks(user, project_id, limit=limit, cursor=cursor, milestones_only=milestones_only)
    return CrmProjectTaskListResp(items=result["items"], cursor=result.get("cursor"))


@router.put("/{project_id}/tasks/order", response_model=Dict[str, List[CrmProjectTaskModel]])
def reorder_tasks_route(
    project_id: str,
    body: CrmProjectTaskReorderReq,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_tasks import reorder_tasks
    items = reorder_tasks(user, project_id, body.task_ids)
    return {"items": items}


@router.get("/{project_id}/milestones", response_model=CrmMilestoneSummaryResp)
def get_milestone_summary_route(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_tasks import get_milestone_summary
    result = get_milestone_summary(user, project_id, limit=limit, cursor=cursor)
    return CrmMilestoneSummaryResp(**result)


@router.get("/{project_id}/workload", response_model=CrmProjectWorkloadResp)
def get_project_workload_route(
    project_id: str,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_tasks import get_project_workload
    return get_project_workload(user, project_id)


@router.get("/{project_id}/tasks/{task_id}", response_model=CrmProjectTaskModel)
def get_task_route(
    project_id: str,
    task_id: str,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_tasks import get_task
    return get_task(user, task_id, project_id)


@router.patch("/{project_id}/tasks/{task_id}", response_model=CrmProjectTaskModel)
def update_task_route(
    project_id: str,
    task_id: str,
    body: CrmProjectTaskUpdateReq,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_tasks import update_task
    return update_task(
        user,
        task_id,
        project_id,
        name=body.name,
        description=body.description,
        task_order=body.task_order,
        duration_days=body.duration_days,
        start_date=body.start_date,
        end_date=body.end_date,
        percent_complete=body.percent_complete,
        is_milestone=body.is_milestone,
        assigned_user_sub=body.assigned_user_sub,
        predecessor_task_ids=body.predecessor_task_ids,
        project_resource_type=body.project_resource_type,
        linked_contact_id=body.linked_contact_id,
        _fields_set=body.model_fields_set,
    )


@router.delete("/{project_id}/tasks/{task_id}")
def delete_task_route(
    project_id: str,
    task_id: str,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_tasks import delete_task
    return delete_task(user, task_id, project_id)


# ===========================================================================
# PRJ-007: Team member routes
# ===========================================================================

@router.post("/{project_id}/members", response_model=CrmProjectMemberOut, status_code=201)
def add_member_route(
    project_id: str,
    body: CrmProjectAddMemberIn,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_members import add_member
    return add_member(user, project_id, body.user_sub, body.role)


@router.get("/{project_id}/members", response_model=CrmProjectMemberListResp)
def list_members_route(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_members import list_members
    return list_members(user, project_id, limit=limit, cursor=cursor)


@router.patch("/{project_id}/members/{user_sub}", response_model=CrmProjectMemberOut)
def update_member_route(
    project_id: str,
    user_sub: str,
    body: CrmProjectUpdateMemberIn,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_members import update_member
    return update_member(user, project_id, user_sub, body.role)


@router.delete("/{project_id}/members/{user_sub}")
def remove_member_route(
    project_id: str,
    user_sub: str,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_members import remove_member
    return remove_member(user, project_id, user_sub)


# ===========================================================================
# PRJ-010: Contact link routes
# ===========================================================================

@router.post("/{project_id}/contact-links", response_model=CrmProjectContactLinkOut, status_code=201)
def add_contact_link_route(
    project_id: str,
    body: CrmProjectAddContactLinkIn,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_contact_links import add_contact_link
    return add_contact_link(user, project_id, body.linked_entity_id, linked_entity_type=body.linked_entity_type, note=body.note)


@router.get("/{project_id}/contact-links", response_model=CrmProjectContactLinkListResp)
def list_contact_links_route(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_contact_links import list_contact_links
    return list_contact_links(user, project_id, limit=limit, cursor=cursor)


@router.delete("/{project_id}/contact-links/{entity_id}")
def remove_contact_link_route(
    project_id: str,
    entity_id: str,
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_contact_links import remove_contact_link
    return remove_contact_link(user, project_id, entity_id)


# ===========================================================================
# PRJ-009: Status history
# ===========================================================================

@router.get("/{project_id}/status-history", response_model=CrmProjectStatusHistoryResp)
def get_status_history_route(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None),
    user: str = Depends(_current_user),
) -> Any:
    _require_crm_projects()
    from app.services.crm_project_status import get_status_history
    return get_status_history(user, project_id, limit=limit, cursor=cursor)
