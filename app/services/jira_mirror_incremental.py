from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from typing import Any

from app.services.jira_api_client import JiraApiClient
from app.services.jira_ticket_sync_store import JiraTicketSyncStore
from app.services.jira_token_lifecycle import get_or_refresh_access_token

try:
    from app.metrics import Counter, Gauge
except Exception:  # pragma: no cover
    class _NoopMetric:
        def labels(self, **kwargs):
            return self

        def inc(self, value: float = 1.0) -> None:
            return None

        def set(self, value: float) -> None:
            return None

    def Counter(*args, **kwargs):
        return _NoopMetric()

    def Gauge(*args, **kwargs):
        return _NoopMetric()


JIRA_INCREMENTAL_POLLS = Counter(
    "jira_incremental_polls_total",
    "Jira incremental poll executions by outcome",
    ["outcome"],
)
JIRA_INCREMENTAL_ISSUES_IMPORTED = Counter(
    "jira_incremental_issues_imported_total",
    "Jira issues imported by incremental sync",
    ["project_key"],
)
JIRA_INCREMENTAL_NEXT_POLL_TS = Gauge(
    "jira_incremental_next_poll_unix",
    "Next incremental poll unix timestamp by project",
    ["project_key"],
)


@dataclass(frozen=True)
class JiraIncrementalProjectResult:
    project_key: str
    imported: int
    updated_after: str
    next_poll_after: int
    skipped_by_cadence: bool


def _poll_interval_seconds() -> int:
    raw = str(os.getenv("JIRA_MIRROR_POLL_INTERVAL_SECONDS", "300")).strip() or "300"
    try:
        return max(30, int(raw))
    except ValueError:
        return 300


def _now_ts() -> int:
    import time

    return int(time.time())


def _to_iso_utc(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_incremental_mirror_sync(
    *,
    workspace_id: str,
    connection_id: str,
    project_keys: list[str],
    page_size: int = 50,
    now_ts: int | None = None,
    store: JiraTicketSyncStore | None = None,
    api: JiraApiClient | None = None,
) -> list[JiraIncrementalProjectResult]:
    repo = store or JiraTicketSyncStore()
    client = api or JiraApiClient()
    now = int(now_ts) if now_ts is not None else _now_ts()
    poll_interval = _poll_interval_seconds()

    conn = repo.get_connection(workspace_id=workspace_id, connection_id=connection_id)
    if not conn:
        raise ValueError("jira connection not found")
    cloud_id = str(conn.get("cloud_id") or "").strip()
    if not cloud_id:
        raise ValueError("jira connection cloud_id missing")

    access_token = get_or_refresh_access_token(workspace_id=workspace_id, connection_id=connection_id, store=repo)
    outcomes: list[JiraIncrementalProjectResult] = []

    for project_key in [x.strip() for x in project_keys if x and x.strip()]:
        checkpoint = repo.get_mirror_incremental_checkpoint(
            workspace_id=workspace_id,
            connection_id=connection_id,
            project_key=project_key,
        ) or {}
        updated_after = str(checkpoint.get("updated_after") or "1970-01-01T00:00:00Z")
        imported_total = int(checkpoint.get("imported_count") or 0)
        next_poll_after = int(checkpoint.get("next_poll_after") or 0)
        if now < next_poll_after:
            JIRA_INCREMENTAL_POLLS.labels(outcome="skipped_cadence").inc()
            outcomes.append(
                JiraIncrementalProjectResult(
                    project_key=project_key,
                    imported=0,
                    updated_after=updated_after,
                    next_poll_after=next_poll_after,
                    skipped_by_cadence=True,
                )
            )
            continue

        start_at = 0
        latest_updated = updated_after
        imported_this_poll = 0
        while True:
            jql = f'project={project_key} AND updated >= "{updated_after}" ORDER BY updated ASC'
            status, body = client.search_issues(
                cloud_id=cloud_id,
                access_token=access_token,
                jql=jql,
                start_at=start_at,
                max_results=page_size,
            )
            if status >= 400:
                repo.upsert_mirror_incremental_checkpoint(
                    workspace_id=workspace_id,
                    connection_id=connection_id,
                    project_key=project_key,
                    updated_after=updated_after,
                    last_polled_at=now,
                    next_poll_after=now + poll_interval,
                    imported_count=imported_total,
                    status="failed",
                    error_code=f"jira_issue_query_{status}",
                )
                JIRA_INCREMENTAL_POLLS.labels(outcome="failed").inc()
                raise RuntimeError(f"jira incremental issue query failed status={status}")

            issues = body.get("issues") or []
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                fields = issue.get("fields") if isinstance(issue.get("fields"), dict) else {}
                issue_updated = str(fields.get("updated") or "")
                if issue_updated and issue_updated > latest_updated:
                    latest_updated = issue_updated
                repo.upsert_issue_mirror(
                    workspace_id=workspace_id,
                    external_issue_id=str(issue.get("id") or ""),
                    external_issue_key=str(issue.get("key") or ""),
                    cloud_id=cloud_id,
                    project_key=project_key,
                    summary=str(fields.get("summary") or ""),
                    description=str(fields.get("description") or ""),
                    status=str((fields.get("status") or {}).get("name") if isinstance(fields.get("status"), dict) else ""),
                    priority=str((fields.get("priority") or {}).get("name") if isinstance(fields.get("priority"), dict) else ""),
                    assignee_account_id=str((fields.get("assignee") or {}).get("accountId") if isinstance(fields.get("assignee"), dict) else "") or None,
                    reporter_account_id=str((fields.get("reporter") or {}).get("accountId") if isinstance(fields.get("reporter"), dict) else "") or None,
                    labels=[str(x) for x in (fields.get("labels") or []) if str(x).strip()],
                    updated_at_remote=issue_updated,
                )
                imported_total += 1
                imported_this_poll += 1

            max_results = int(body.get("maxResults") or page_size)
            total = int(body.get("total") or 0)
            start_at = int(body.get("startAt") or start_at) + max_results
            if bool(body.get("isLast") is True or start_at >= total):
                break

        next_poll_after = now + poll_interval
        repo.upsert_mirror_incremental_checkpoint(
            workspace_id=workspace_id,
            connection_id=connection_id,
            project_key=project_key,
            updated_after=latest_updated if latest_updated else _to_iso_utc(now),
            last_polled_at=now,
            next_poll_after=next_poll_after,
            imported_count=imported_total,
            status="active",
            error_code="",
        )
        JIRA_INCREMENTAL_POLLS.labels(outcome="success").inc()
        JIRA_INCREMENTAL_ISSUES_IMPORTED.labels(project_key=project_key).inc(imported_this_poll)
        JIRA_INCREMENTAL_NEXT_POLL_TS.labels(project_key=project_key).set(next_poll_after)
        outcomes.append(
            JiraIncrementalProjectResult(
                project_key=project_key,
                imported=imported_this_poll,
                updated_after=latest_updated if latest_updated else _to_iso_utc(now),
                next_poll_after=next_poll_after,
                skipped_by_cadence=False,
            )
        )
    return outcomes
