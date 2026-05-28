"""Admin background job monitoring endpoints (PLATFORM-008)."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.time import now_ts
from app.services.job_registry import get_all_tasks, get_task
from app.services.sessions import require_ui_session

router = APIRouter(tags=["admin-jobs"])


def _require_admin(ctx: Dict[str, Any]) -> None:
    """Check that the session has admin or root role."""
    role = ctx.get("role", "user")
    if str(role).lower() not in ("root", "admin"):
        raise HTTPException(status_code=403, detail="Admin access required")


@router.get("/ui/admin/jobs/status")
async def job_status(ctx: Dict[str, Any] = Depends(require_ui_session)):
    """Get health status of all background tasks + queue depths."""
    _require_admin(ctx)

    tasks = get_all_tasks()
    now = now_ts()

    # Scheduled actions queue
    try:
        from app.services.scheduled_actions import count_failed_actions, count_pending_actions
        pending_actions = count_pending_actions()
        failed_actions = count_failed_actions()
    except Exception:
        pending_actions = -1
        failed_actions = -1

    # Webhook delivery queue
    try:
        from app.services.webhook_service import admin_get_health_summary
        webhook_health = admin_get_health_summary()
    except Exception:
        webhook_health = {}

    return {
        "tasks": tasks,
        "queues": {
            "scheduled_actions": {
                "pending": pending_actions,
                "failed": failed_actions,
            },
            "webhook_deliveries": {
                "pending": webhook_health.get("failed_count_24h", 0),
                "dead_letter": webhook_health.get("dead_letter_count_24h", 0),
                "success_24h": webhook_health.get("success_count_24h", 0),
                "total_endpoints": webhook_health.get("total_endpoints", 0),
                "enabled_endpoints": webhook_health.get("enabled_endpoints", 0),
            },
        },
        "timestamp": now,
    }


@router.get("/ui/admin/jobs/task/{task_name}")
async def job_task_detail(task_name: str, ctx: Dict[str, Any] = Depends(require_ui_session)):
    """Get detailed status of a specific background task."""
    _require_admin(ctx)

    task = get_task(task_name)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task '{task_name}' not found")
    return task


@router.get("/ui/admin/jobs/failed")
async def failed_jobs(
    limit: int = Query(default=50, ge=1, le=200),
    action_type: Optional[str] = Query(default=None),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """List failed scheduled actions across all users."""
    _require_admin(ctx)

    from app.services.scheduled_actions import query_failed_actions
    items = query_failed_actions(limit=limit, action_type=action_type)
    return {"items": items, "count": len(items)}


@router.post("/ui/admin/jobs/retry/{action_id}")
async def retry_failed_job(
    action_id: str,
    user_sub: str = Query(...),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    """Retry a permanently failed action (admin override).

    Reschedules the action back to pending state with retry_count=0
    and a new due time (now + 5 seconds).
    """
    _require_admin(ctx)

    from app.services.scheduled_actions import reschedule_failed_action
    result = reschedule_failed_action(user_sub, action_id)
    if not result:
        raise HTTPException(status_code=404, detail="Action not found or not in failed state")
    return {"ok": True, "action_id": action_id, "status": "rescheduled"}
