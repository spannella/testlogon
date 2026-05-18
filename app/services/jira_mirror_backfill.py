from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.jira_api_client import JiraApiClient
from app.services.jira_ticket_sync_store import JiraTicketSyncStore
from app.services.jira_token_lifecycle import get_or_refresh_access_token


@dataclass(frozen=True)
class JiraMirrorBackfillProjectResult:
    project_key: str
    imported: int
    completed: bool
    next_start_at: int


@dataclass(frozen=True)
class JiraMirrorBackfillResult:
    workspace_id: str
    connection_id: str
    projects: list[JiraMirrorBackfillProjectResult]


def _stringify_description(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    return str(raw)


def run_initial_mirror_backfill(
    *,
    workspace_id: str,
    connection_id: str,
    project_keys: list[str],
    page_size: int = 50,
    store: JiraTicketSyncStore | None = None,
    api: JiraApiClient | None = None,
) -> JiraMirrorBackfillResult:
    repo = store or JiraTicketSyncStore()
    client = api or JiraApiClient()

    connection = repo.get_connection(workspace_id=workspace_id, connection_id=connection_id)
    if not connection:
        raise ValueError("jira connection not found")
    cloud_id = str(connection.get("cloud_id") or "").strip()
    if not cloud_id:
        raise ValueError("jira connection cloud_id missing")

    access_token = get_or_refresh_access_token(workspace_id=workspace_id, connection_id=connection_id, store=repo)

    results: list[JiraMirrorBackfillProjectResult] = []
    for project_key in [x.strip() for x in project_keys if x and x.strip()]:
        checkpoint = repo.get_mirror_backfill_checkpoint(
            workspace_id=workspace_id,
            connection_id=connection_id,
            project_key=project_key,
        )
        imported_total = int(checkpoint.get("imported_count") or 0) if checkpoint else 0
        start_at = int(checkpoint.get("next_start_at") or 0) if checkpoint else 0
        completed = False

        while True:
            jql = f"project={project_key} ORDER BY updated ASC"
            status, body = client.search_issues(
                cloud_id=cloud_id,
                access_token=access_token,
                jql=jql,
                start_at=start_at,
                max_results=page_size,
            )
            if status >= 400:
                repo.upsert_mirror_backfill_checkpoint(
                    workspace_id=workspace_id,
                    connection_id=connection_id,
                    project_key=project_key,
                    next_start_at=start_at,
                    status="failed",
                    imported_count=imported_total,
                    error_code=f"jira_issue_query_{status}",
                )
                raise RuntimeError(f"jira issue query failed for {project_key} with status={status}")

            issues = body.get("issues") or []
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                fields = issue.get("fields") if isinstance(issue.get("fields"), dict) else {}
                repo.upsert_issue_mirror(
                    workspace_id=workspace_id,
                    external_issue_id=str(issue.get("id") or ""),
                    external_issue_key=str(issue.get("key") or ""),
                    cloud_id=cloud_id,
                    project_key=project_key,
                    summary=str(fields.get("summary") or ""),
                    description=_stringify_description(fields.get("description")),
                    status=str((fields.get("status") or {}).get("name") if isinstance(fields.get("status"), dict) else ""),
                    priority=str((fields.get("priority") or {}).get("name") if isinstance(fields.get("priority"), dict) else ""),
                    assignee_account_id=str((fields.get("assignee") or {}).get("accountId") if isinstance(fields.get("assignee"), dict) else "") or None,
                    reporter_account_id=str((fields.get("reporter") or {}).get("accountId") if isinstance(fields.get("reporter"), dict) else "") or None,
                    labels=[str(x) for x in (fields.get("labels") or []) if str(x).strip()],
                    updated_at_remote=str(fields.get("updated") or ""),
                )
                imported_total += 1

            max_results = int(body.get("maxResults") or page_size)
            total = int(body.get("total") or 0)
            start_at = int(body.get("startAt") or start_at) + max_results
            completed = bool(body.get("isLast") is True or start_at >= total)
            repo.upsert_mirror_backfill_checkpoint(
                workspace_id=workspace_id,
                connection_id=connection_id,
                project_key=project_key,
                next_start_at=start_at,
                status="completed" if completed else "in_progress",
                imported_count=imported_total,
                error_code="",
            )
            if completed:
                break

        results.append(
            JiraMirrorBackfillProjectResult(
                project_key=project_key,
                imported=imported_total,
                completed=completed,
                next_start_at=start_at,
            )
        )

    return JiraMirrorBackfillResult(workspace_id=workspace_id, connection_id=connection_id, projects=results)
