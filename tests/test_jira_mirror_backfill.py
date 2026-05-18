from __future__ import annotations

from typing import Any

from app.services.jira_mirror_backfill import run_initial_mirror_backfill


class _FakeStore:
    def __init__(self) -> None:
        self.connection = {"workspace_id": "ws_1", "connection_id": "conn_1", "cloud_id": "cloud_1"}
        self.checkpoints: dict[tuple[str, str], dict[str, Any]] = {}
        self.mirror_calls: list[dict[str, Any]] = []
        self.checkpoint_calls: list[dict[str, Any]] = []

    def get_connection(self, *, workspace_id: str, connection_id: str) -> dict[str, Any] | None:
        if workspace_id == "ws_1" and connection_id == "conn_1":
            return dict(self.connection)
        return None

    def get_mirror_backfill_checkpoint(self, *, workspace_id: str, connection_id: str, project_key: str) -> dict[str, Any] | None:
        return self.checkpoints.get((connection_id, project_key))

    def upsert_mirror_backfill_checkpoint(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        project_key: str,
        next_start_at: int,
        status: str,
        imported_count: int,
        error_code: str = "",
    ) -> dict[str, Any]:
        row = {
            "workspace_id": workspace_id,
            "connection_id": connection_id,
            "project_key": project_key,
            "next_start_at": next_start_at,
            "status": status,
            "imported_count": imported_count,
            "error_code": error_code,
        }
        self.checkpoints[(connection_id, project_key)] = dict(row)
        self.checkpoint_calls.append(dict(row))
        return row

    def upsert_issue_mirror(self, **kwargs: Any) -> dict[str, Any]:
        self.mirror_calls.append(dict(kwargs))
        return dict(kwargs)


class _FakeApi:
    def __init__(self, pages: dict[str, list[dict[str, Any]]]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def search_issues(self, *, cloud_id: str, access_token: str, jql: str, start_at: int, max_results: int) -> tuple[int, dict[str, Any]]:
        self.calls.append(
            {
                "cloud_id": cloud_id,
                "access_token": access_token,
                "jql": jql,
                "start_at": start_at,
                "max_results": max_results,
            }
        )
        project_key = jql.split("=")[1].split(" ")[0]
        for row in self.pages[project_key]:
            if int(row.get("startAt") or 0) == int(start_at):
                return 200, row
        raise AssertionError(f"missing fake page for project={project_key} start_at={start_at}")


def test_run_initial_mirror_backfill_imports_all_pages_for_projects(monkeypatch) -> None:
    store = _FakeStore()
    api = _FakeApi(
        {
            "PROJ": [
                {
                    "startAt": 0,
                    "maxResults": 2,
                    "total": 3,
                    "isLast": False,
                    "issues": [
                        {"id": "1", "key": "PROJ-1", "fields": {"summary": "A", "updated": "2026-04-01T00:00:00Z"}},
                        {"id": "2", "key": "PROJ-2", "fields": {"summary": "B", "updated": "2026-04-01T00:01:00Z"}},
                    ],
                },
                {
                    "startAt": 2,
                    "maxResults": 2,
                    "total": 3,
                    "isLast": True,
                    "issues": [{"id": "3", "key": "PROJ-3", "fields": {"summary": "C", "updated": "2026-04-01T00:02:00Z"}}],
                },
            ],
            "OPS": [
                {"startAt": 0, "maxResults": 2, "total": 1, "isLast": True, "issues": [{"id": "4", "key": "OPS-1", "fields": {}}]}
            ],
        }
    )
    monkeypatch.setattr("app.services.jira_mirror_backfill.get_or_refresh_access_token", lambda **kwargs: "token-1")

    result = run_initial_mirror_backfill(
        workspace_id="ws_1",
        connection_id="conn_1",
        project_keys=["PROJ", "OPS"],
        page_size=2,
        store=store,  # type: ignore[arg-type]
        api=api,  # type: ignore[arg-type]
    )

    assert len(store.mirror_calls) == 4
    assert [p.project_key for p in result.projects] == ["PROJ", "OPS"]
    assert store.checkpoints[("conn_1", "PROJ")]["status"] == "completed"
    assert store.checkpoints[("conn_1", "OPS")]["status"] == "completed"


def test_run_initial_mirror_backfill_resumes_from_checkpoint(monkeypatch) -> None:
    store = _FakeStore()
    store.checkpoints[("conn_1", "PROJ")] = {
        "workspace_id": "ws_1",
        "connection_id": "conn_1",
        "project_key": "PROJ",
        "next_start_at": 2,
        "imported_count": 2,
        "status": "in_progress",
        "error_code": "",
    }
    api = _FakeApi(
        {
            "PROJ": [
                {
                    "startAt": 2,
                    "maxResults": 2,
                    "total": 3,
                    "isLast": True,
                    "issues": [{"id": "3", "key": "PROJ-3", "fields": {"summary": "C", "updated": "2026-04-01T00:02:00Z"}}],
                }
            ]
        }
    )
    monkeypatch.setattr("app.services.jira_mirror_backfill.get_or_refresh_access_token", lambda **kwargs: "token-1")

    result = run_initial_mirror_backfill(
        workspace_id="ws_1",
        connection_id="conn_1",
        project_keys=["PROJ"],
        page_size=2,
        store=store,  # type: ignore[arg-type]
        api=api,  # type: ignore[arg-type]
    )

    assert api.calls[0]["start_at"] == 2
    assert result.projects[0].imported == 3
    assert store.checkpoints[("conn_1", "PROJ")]["status"] == "completed"
