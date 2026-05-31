"""Background job dashboard — run-history recording + observability (PLATFORM-008).

This is the *persistent* observability layer for the platform's background
schedulers/loops. It complements the in-memory health registry
(``app/services/job_registry.py``) by recording a durable history of individual
job runs to DynamoDB so admins can see each job's last-run / next-run / status /
duration / error over time, even after a process restart.

Design:
- A static **job registry** (``KNOWN_JOBS``) describes every known background
  job: a human label, the source scheduler, the expected poll interval, and
  whether it is safe to trigger manually ("run now").
- ``record_job_run(job_name, status, ...)`` appends a run record to the
  ``job_runs`` DDB table. Schedulers call this once per poll cycle. History is
  capped per-job (``job_dashboard_max_runs_per_job``) by trimming the oldest
  rows, and rows carry a TTL.
- Query helpers expose run history, the latest run per job, and a per-job
  health summary derived from the latest runs.
- ``seed_demo_runs()`` writes deterministic run records for tests/dev.

DDB schema (table ``job_runs``):
    PK: job_name                 (e.g. "unified_scheduler")
    SK: run_id = "RUN#{started_at:020d}#{run_uuid}"   (sorts newest-last)
    GSI ByStartedAt: GSI_PK="JOBRUN"  started_at (N)   -> cross-job recent runs
Attributes: status, started_at, finished_at, duration_ms, items_processed,
    items_failed, error, triggered_by, ttl.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Valid terminal/poll statuses for a recorded run.
VALID_STATUSES = ("success", "failed", "skipped", "running", "partial")

_GSI_PK_VALUE = "JOBRUN"


# ---------------------------------------------------------------------------
# Static job registry
# ---------------------------------------------------------------------------
# Each entry: name -> metadata. ``run_now_safe`` gates the manual trigger.
# ``run_now`` is a dotted import path "module:callable" invoked (best-effort)
# for a single iteration when an admin triggers a manual run; may be None.
KNOWN_JOBS: Dict[str, Dict[str, Any]] = {
    "unified_scheduler": {
        "label": "Unified Content Scheduler",
        "source": "app/services/unified_scheduler.py",
        "description": "Processes scheduled posts, file shares, and catalog sales.",
        "poll_interval_seconds": 15,
        "run_now_safe": True,
        "run_now": "app.services.unified_scheduler:run_unified_scheduler_once",
    },
    "webhook_dispatcher": {
        "label": "Webhook Dispatcher",
        "source": "app/services/webhook_dispatcher.py",
        "description": "Delivers pending webhook notifications to user endpoints.",
        "poll_interval_seconds": 10,
        "run_now_safe": True,
        "run_now": "app.services.webhook_dispatcher:run_webhook_dispatcher_once",
    },
    "billing_dunning": {
        "label": "Billing Dunning",
        "source": "app/services/billing_dunning.py",
        "description": "Retries failed subscription charges and sends dunning notices.",
        "poll_interval_seconds": 300,
        "run_now_safe": False,
        "run_now": None,
    },
    "billing_reconcile": {
        "label": "Billing Reconciliation",
        "source": "app/services/billing_reconcile.py",
        "description": "Reconciles local billing state against payment providers.",
        "poll_interval_seconds": 600,
        "run_now_safe": False,
        "run_now": None,
    },
    "filemgr_purge": {
        "label": "File Manager Purge",
        "source": "app/services/filemanager.py",
        "description": "Purges soft-deleted files past their retention window.",
        "poll_interval_seconds": 3600,
        "run_now_safe": False,
        "run_now": None,
    },
    "filemgr_mount_reconcile": {
        "label": "File Mount Reconciliation",
        "source": "app/services/filemanager_mount_reconcile.py",
        "description": "Reconciles external file mounts.",
        "poll_interval_seconds": 600,
        "run_now_safe": False,
        "run_now": None,
    },
    "scheduled_messages": {
        "label": "Scheduled Messages",
        "source": "app/routers/messaging.py",
        "description": "Promotes due scheduled messages to delivery.",
        "poll_interval_seconds": 30,
        "run_now_safe": True,
        "run_now": None,
    },
    "broadcast_scheduler": {
        "label": "Broadcast Scheduler",
        "source": "app/services/broadcast_scheduler.py",
        "description": "Dispatches scheduled broadcast campaigns.",
        "poll_interval_seconds": 60,
        "run_now_safe": False,
        "run_now": None,
    },
    "broadcast_reminder": {
        "label": "Broadcast Reminder",
        "source": "app/services/broadcast_scheduler.py",
        "description": "Sends pre-broadcast reminder notifications.",
        "poll_interval_seconds": 60,
        "run_now_safe": False,
        "run_now": None,
    },
    "broadcast_reconciler": {
        "label": "Broadcast Reconciler",
        "source": "app/services/broadcast_reconciler.py",
        "description": "Reconciles broadcast delivery state.",
        "poll_interval_seconds": 120,
        "run_now_safe": False,
        "run_now": None,
    },
    "transcode_worker": {
        "label": "Transcode Worker",
        "source": "app/services/transcode_worker.py",
        "description": "Transcodes uploaded media into delivery formats.",
        "poll_interval_seconds": 30,
        "run_now_safe": False,
        "run_now": None,
    },
    "projects_reconcile": {
        "label": "Projects Reconciliation",
        "source": "app/services/projects_reconcile.py",
        "description": "Reconciles project state and rollups.",
        "poll_interval_seconds": 300,
        "run_now_safe": False,
        "run_now": None,
    },
}


def list_known_jobs() -> List[Dict[str, Any]]:
    """Return the static registry as a sorted list of job metadata dicts."""
    out = []
    for name in sorted(KNOWN_JOBS):
        meta = KNOWN_JOBS[name]
        out.append(
            {
                "name": name,
                "label": meta.get("label", name),
                "source": meta.get("source", ""),
                "description": meta.get("description", ""),
                "poll_interval_seconds": int(meta.get("poll_interval_seconds", 0)),
                "run_now_safe": bool(meta.get("run_now_safe", False)),
            }
        )
    return out


def is_known_job(job_name: str) -> bool:
    return job_name in KNOWN_JOBS


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _run_sk(started_at: int, run_id: str) -> str:
    # Zero-pad started_at so lexical SK order == chronological order.
    return f"RUN#{int(started_at):020d}#{run_id}"


def _ttl_epoch(ts: int) -> int:
    return ts + max(1, S.job_dashboard_ttl_days) * 86400


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

def record_job_run(
    job_name: str,
    status: str = "success",
    *,
    started_at: Optional[int] = None,
    finished_at: Optional[int] = None,
    duration_ms: Optional[float] = None,
    items_processed: int = 0,
    items_failed: int = 0,
    error: Optional[str] = None,
    triggered_by: str = "scheduler",
) -> Dict[str, Any]:
    """Record a single background-job run to the ``job_runs`` table.

    Safe to call from background loops — exceptions are swallowed and logged so
    a recording failure never breaks a scheduler. Returns the stored run dict
    (or a minimal dict on failure).

    Args:
        job_name: Job identifier (ideally a key in ``KNOWN_JOBS``).
        status: One of VALID_STATUSES; coerced to "success" if unknown.
        started_at / finished_at: Unix timestamps; default to now.
        duration_ms: Wall-clock duration; computed from start/finish if omitted.
        items_processed / items_failed: Per-run item counters.
        error: Error message (truncated to 1000 chars).
        triggered_by: "scheduler", "manual:<user_sub>", or "seed".
    """
    now = now_ts()
    started = int(started_at if started_at is not None else now)
    finished = int(finished_at if finished_at is not None else now)
    if status not in VALID_STATUSES:
        status = "success"
    if duration_ms is None:
        duration_ms = max(0.0, float((finished - started) * 1000))

    run_id = uuid.uuid4().hex
    item: Dict[str, Any] = {
        "job_name": job_name,
        "run_id": _run_sk(started, run_id),
        "status": status,
        "started_at": started,
        "finished_at": finished,
        "duration_ms": round(float(duration_ms), 1),
        "items_processed": int(items_processed),
        "items_failed": int(items_failed),
        "triggered_by": triggered_by,
        "GSI_PK": _GSI_PK_VALUE,
        "ttl": _ttl_epoch(now),
    }
    if error:
        item["error"] = str(error)[:1000]

    try:
        T.job_runs.put_item(Item=item)
    except Exception:
        logger.exception("record_job_run failed for job=%s", job_name)
        return item

    try:
        from app.metrics import record_job_run_metrics

        record_job_run_metrics(job_name, status, item["duration_ms"],
                               int(items_processed), int(items_failed))
    except Exception:
        logger.debug("record_job_run: metrics emit failed", exc_info=True)

    # Best-effort retention trim.
    try:
        _trim_history(job_name)
    except Exception:
        logger.debug("record_job_run: history trim failed for %s", job_name, exc_info=True)

    return _run_out(item)


def _trim_history(job_name: str) -> None:
    """Delete the oldest runs for a job beyond the retention cap."""
    cap = max(1, S.job_dashboard_max_runs_per_job)
    # Fetch oldest-first; if more than cap, delete the overflow at the front.
    resp = T.job_runs.query(
        KeyConditionExpression=Key("job_name").eq(job_name),
        ScanIndexForward=True,
        ProjectionExpression="job_name, run_id",
    )
    items = resp.get("Items", [])
    while resp.get("LastEvaluatedKey"):
        resp = T.job_runs.query(
            KeyConditionExpression=Key("job_name").eq(job_name),
            ScanIndexForward=True,
            ProjectionExpression="job_name, run_id",
            ExclusiveStartKey=resp["LastEvaluatedKey"],
        )
        items.extend(resp.get("Items", []))

    overflow = len(items) - cap
    for it in items[:max(0, overflow)]:
        try:
            T.job_runs.delete_item(Key={"job_name": it["job_name"], "run_id": it["run_id"]})
        except Exception:
            logger.debug("trim delete failed", exc_info=True)


# ---------------------------------------------------------------------------
# Querying
# ---------------------------------------------------------------------------

def _run_out(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "job_name": item.get("job_name", ""),
        "run_id": item.get("run_id", ""),
        "status": item.get("status", ""),
        "started_at": int(item.get("started_at", 0) or 0),
        "finished_at": int(item.get("finished_at", 0) or 0),
        "duration_ms": float(item.get("duration_ms", 0) or 0),
        "items_processed": int(item.get("items_processed", 0) or 0),
        "items_failed": int(item.get("items_failed", 0) or 0),
        "error": item.get("error"),
        "triggered_by": item.get("triggered_by", ""),
    }


def list_job_runs(job_name: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    """List recent runs for a single job, newest first."""
    try:
        resp = T.job_runs.query(
            KeyConditionExpression=Key("job_name").eq(job_name),
            ScanIndexForward=False,
            Limit=max(1, min(limit, 500)),
        )
        return [_run_out(i) for i in resp.get("Items", [])]
    except Exception:
        logger.exception("list_job_runs failed for %s", job_name)
        return []


def list_recent_runs(*, limit: int = 100) -> List[Dict[str, Any]]:
    """List recent runs across all jobs, newest first (uses ByStartedAt GSI)."""
    try:
        resp = T.job_runs.query(
            IndexName="ByStartedAt",
            KeyConditionExpression=Key("GSI_PK").eq(_GSI_PK_VALUE),
            ScanIndexForward=False,
            Limit=max(1, min(limit, 500)),
        )
        return [_run_out(i) for i in resp.get("Items", [])]
    except Exception:
        logger.exception("list_recent_runs failed")
        return []


def latest_run(job_name: str) -> Optional[Dict[str, Any]]:
    """Return the most recent run for a job, or None."""
    runs = list_job_runs(job_name, limit=1)
    return runs[0] if runs else None


def _next_run_at(job_name: str, last_started: int) -> Optional[int]:
    meta = KNOWN_JOBS.get(job_name)
    if not meta or not last_started:
        return None
    interval = int(meta.get("poll_interval_seconds", 0) or 0)
    if interval <= 0:
        return None
    return last_started + interval


def job_health() -> List[Dict[str, Any]]:
    """Per-job health summary derived from the latest recorded run.

    Health states:
      - "ok": latest run succeeded (or partial with no failures).
      - "degraded": latest run partial/skipped, or had item failures.
      - "failed": latest run failed.
      - "unknown": no runs recorded yet.
    """
    out: List[Dict[str, Any]] = []
    for name in sorted(KNOWN_JOBS):
        meta = KNOWN_JOBS[name]
        last = latest_run(name)
        if not last:
            health = "unknown"
        elif last["status"] == "failed":
            health = "failed"
        elif last["status"] in ("partial", "skipped") or last["items_failed"] > 0:
            health = "degraded"
        else:
            health = "ok"

        out.append(
            {
                "name": name,
                "label": meta.get("label", name),
                "description": meta.get("description", ""),
                "poll_interval_seconds": int(meta.get("poll_interval_seconds", 0)),
                "run_now_safe": bool(meta.get("run_now_safe", False)),
                "health": health,
                "last_status": last["status"] if last else None,
                "last_run_at": last["started_at"] if last else None,
                "last_finished_at": last["finished_at"] if last else None,
                "last_duration_ms": last["duration_ms"] if last else None,
                "last_error": last.get("error") if last else None,
                "last_items_processed": last["items_processed"] if last else 0,
                "last_items_failed": last["items_failed"] if last else 0,
                "next_run_at": _next_run_at(name, last["started_at"]) if last else None,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Manual trigger ("run now")
# ---------------------------------------------------------------------------

class RunNowNotAllowed(Exception):
    """Raised when a job is unknown or not safe to trigger manually."""


async def trigger_run_now(job_name: str, *, triggered_by: str) -> Dict[str, Any]:
    """Manually trigger a single iteration of a job (root-only at router).

    Only jobs flagged ``run_now_safe`` may be triggered. Records a run with
    ``triggered_by="manual:<user>"``. If the job exposes a one-shot callable
    (``run_now`` in KNOWN_JOBS), it is invoked best-effort; otherwise the run is
    recorded as "skipped" (signal-only).
    """
    meta = KNOWN_JOBS.get(job_name)
    if not meta:
        raise RunNowNotAllowed(f"Unknown job: {job_name}")
    if not meta.get("run_now_safe"):
        raise RunNowNotAllowed(f"Job '{job_name}' is not safe to run manually")

    started = now_ts()
    processed = 0
    failed = 0
    status = "success"
    error: Optional[str] = None

    target = meta.get("run_now")
    if target:
        try:
            mod_path, _, attr = target.partition(":")
            import importlib

            module = importlib.import_module(mod_path)
            fn = getattr(module, attr, None)
            if fn is not None:
                result = fn()
                if hasattr(result, "__await__"):
                    result = await result
                if isinstance(result, dict):
                    processed = int(result.get("items_processed", 0) or 0)
                    failed = int(result.get("items_failed", 0) or 0)
            else:
                status = "skipped"
        except Exception as exc:  # pragma: no cover - defensive
            status = "failed"
            error = str(exc)
            logger.exception("trigger_run_now failed for %s", job_name)
    else:
        status = "skipped"

    finished = now_ts()
    run = record_job_run(
        job_name,
        status,
        started_at=started,
        finished_at=finished,
        items_processed=processed,
        items_failed=failed,
        error=error,
        triggered_by=triggered_by,
    )
    return run


# ---------------------------------------------------------------------------
# Deterministic seeding (tests / dev)
# ---------------------------------------------------------------------------

def seed_demo_runs(*, base_ts: Optional[int] = None) -> Dict[str, Any]:
    """Write a deterministic set of job runs for dashboards/tests.

    Produces a known mix: unified_scheduler (success), webhook_dispatcher
    (partial w/ failures), billing_dunning (failed). Idempotent enough for
    tests — each call appends fresh rows but the dashboard always shows the
    latest per job.
    """
    base = int(base_ts if base_ts is not None else now_ts())
    written = 0

    # unified_scheduler: a clean recent run plus an older one.
    record_job_run(
        "unified_scheduler", "success",
        started_at=base - 120, finished_at=base - 120,
        duration_ms=42.0, items_processed=7, items_failed=0,
        triggered_by="seed",
    )
    record_job_run(
        "unified_scheduler", "success",
        started_at=base - 15, finished_at=base - 15,
        duration_ms=38.5, items_processed=3, items_failed=0,
        triggered_by="seed",
    )
    written += 2

    # webhook_dispatcher: partial with some failures (degraded).
    record_job_run(
        "webhook_dispatcher", "partial",
        started_at=base - 10, finished_at=base - 9,
        duration_ms=210.0, items_processed=12, items_failed=2,
        triggered_by="seed",
    )
    written += 1

    # billing_dunning: a failed run (failed health).
    record_job_run(
        "billing_dunning", "failed",
        started_at=base - 300, finished_at=base - 299,
        duration_ms=15.0, items_processed=0, items_failed=1,
        error="seed: provider timeout", triggered_by="seed",
    )
    written += 1

    return {"ok": True, "seeded": written}
