"""Admin background job dashboard — run history + health + manual triggers (PLATFORM-008).

Persistent observability for the platform's background schedulers, complementing
the in-memory health endpoints in ``app/routers/admin_jobs.py``. All endpoints
require ADMIN or ROOT; the manual "run now" trigger and demo seeding require ROOT.

Prefix: /ui/admin/jobs
    GET  /registry                 -> known jobs + metadata
    GET  /health                   -> per-job latest status + health
    GET  /runs                     -> recent runs across all jobs
    GET  /runs/{job_name}          -> recent runs for one job
    GET  /runs/{job_name}/latest   -> latest run for one job
    POST /run-now/{job_name}       -> manually trigger a safe job (ROOT)
    POST /seed-demo                -> deterministic seed runs (ROOT, dev/test)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.deps import AuthenticatedUser
from app.auth.policy import require_admin_or_root, require_root
from app.core.settings import S
from app.core.time import now_ts
from app.models import (
    JobHealthOut,
    JobRegistryOut,
    JobRunNowOut,
    JobRunsOut,
    JobSeedOut,
)
from app.services import job_dashboard as svc

job_dashboard_router = APIRouter(prefix="/ui/admin/jobs", tags=["job-dashboard"])


@job_dashboard_router.get("/registry", response_model=JobRegistryOut)
async def get_job_registry(_user: AuthenticatedUser = Depends(require_admin_or_root)):
    """List all known background jobs and their metadata."""
    return {"jobs": svc.list_known_jobs()}


@job_dashboard_router.get("/health", response_model=JobHealthOut)
async def get_job_health(_user: AuthenticatedUser = Depends(require_admin_or_root)):
    """Per-job health derived from the latest recorded run (last/next run, status, error)."""
    return {"jobs": svc.job_health(), "timestamp": now_ts()}


@job_dashboard_router.get("/runs", response_model=JobRunsOut)
async def get_recent_runs(
    limit: int = Query(default=100, ge=1, le=500),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List recent runs across all jobs, newest first."""
    items = svc.list_recent_runs(limit=limit)
    return {"items": items, "count": len(items)}


@job_dashboard_router.get("/runs/{job_name}", response_model=JobRunsOut)
async def get_job_runs(
    job_name: str,
    limit: int = Query(default=50, ge=1, le=500),
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """List recent runs for a single job, newest first."""
    if not svc.is_known_job(job_name):
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_name}")
    items = svc.list_job_runs(job_name, limit=limit)
    return {"items": items, "count": len(items)}


@job_dashboard_router.get("/runs/{job_name}/latest")
async def get_job_latest_run(
    job_name: str,
    _user: AuthenticatedUser = Depends(require_admin_or_root),
):
    """Get the latest recorded run for a single job."""
    if not svc.is_known_job(job_name):
        raise HTTPException(status_code=404, detail=f"Unknown job: {job_name}")
    run = svc.latest_run(job_name)
    if not run:
        raise HTTPException(status_code=404, detail="No runs recorded for this job")
    return run


@job_dashboard_router.post("/run-now/{job_name}", response_model=JobRunNowOut)
async def run_job_now(
    job_name: str,
    user: AuthenticatedUser = Depends(require_root),
):
    """Manually trigger a single iteration of a job (ROOT only, run-now-safe jobs)."""
    try:
        run = await svc.trigger_run_now(job_name, triggered_by=f"manual:{user.sub}")
    except svc.RunNowNotAllowed as exc:
        # Unknown vs. not-allowed: 404 for unknown, 403 for unsafe.
        if not svc.is_known_job(job_name):
            raise HTTPException(status_code=404, detail=str(exc))
        raise HTTPException(status_code=403, detail=str(exc))
    return {"ok": True, "job_name": job_name, "run": run}


@job_dashboard_router.post("/seed-demo", response_model=JobSeedOut)
async def seed_demo(_user: AuthenticatedUser = Depends(require_root)):
    """Seed deterministic demo job runs (ROOT only; dev/test convenience)."""
    if not S.dev_mode:
        raise HTTPException(status_code=403, detail="Seeding is only available in dev mode")
    result = svc.seed_demo_runs()
    return result
