from __future__ import annotations

from typing import Any

from app.services.jira_mirror_incremental import run_incremental_mirror_sync


class _FakeStore:
    def __init__(self) -> None:
        self.connection = {"workspace_id": "ws_1", "connection_id": "conn_1", "cloud_id": "cloud_1"}
        self.incremental_checkpoints: dict[tuple[str, str], dict[str, Any]] = {}
        self.mirror_calls: list[dict[str, Any]] = []
        self.incremental_checkpoint_calls: list[dict[str, Any]] = []

    def get_connection(self, *, workspace_id: str, connection_id: str) -> dict[str, Any] | None:
        if workspace_id == "ws_1" and connection_id == "conn_1":
            return dict(self.connection)
        return None

    def get_mirror_incremental_checkpoint(
        self, *, workspace_id: str, connection_id: str, project_key: str
    ) -> dict[str, Any] | None:
        return self.incremental_checkpoints.get((connection_id, project_key))

    def upsert_mirror_incremental_checkpoint(self, **kwargs: Any) -> dict[str, Any]:
        row = dict(kwargs)
        self.incremental_checkpoints[(str(kwargs["connection_id"]), str(kwargs["project_key"]))] = dict(row)
        self.incremental_checkpoint_calls.append(dict(row))
        return row

    def upsert_issue_mirror(self, **kwargs: Any) -> dict[str, Any]:
        self.mirror_calls.append(dict(kwargs))
        return dict(kwargs)


class _FakeApi:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
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
        return 200, dict(self.payload)


def test_incremental_sync_fetches_only_changed_since_checkpoint(monkeypatch) -> None:
    store = _FakeStore()
    store.incremental_checkpoints[("conn_1", "PROJ")] = {
        "updated_after": "2026-04-01T00:00:00Z",
        "imported_count": 2,
        "next_poll_after": 0,
    }
    api = _FakeApi(
        {
            "startAt": 0,
            "maxResults": 50,
            "total": 1,
            "isLast": True,
            "issues": [
                {"id": "3", "key": "PROJ-3", "fields": {"summary": "Changed", "updated": "2026-04-01T01:00:00Z"}}
            ],
        }
    )
    monkeypatch.setattr("app.services.jira_mirror_incremental.get_or_refresh_access_token", lambda **kwargs: "token-1")

    out = run_incremental_mirror_sync(
        workspace_id="ws_1",
        connection_id="conn_1",
        project_keys=["PROJ"],
        now_ts=1000,
        store=store,  # type: ignore[arg-type]
        api=api,  # type: ignore[arg-type]
    )

    assert 'updated >= "2026-04-01T00:00:00Z"' in api.calls[0]["jql"]
    assert out[0].imported == 1
    assert store.incremental_checkpoints[("conn_1", "PROJ")]["updated_after"] == "2026-04-01T01:00:00Z"


def test_incremental_sync_respects_poll_cadence_and_skips_until_next_poll(monkeypatch) -> None:
    store = _FakeStore()
    store.incremental_checkpoints[("conn_1", "PROJ")] = {
        "updated_after": "2026-04-01T00:00:00Z",
        "imported_count": 2,
        "next_poll_after": 5000,
    }
    api = _FakeApi({"startAt": 0, "maxResults": 50, "total": 0, "isLast": True, "issues": []})
    monkeypatch.setattr("app.services.jira_mirror_incremental.get_or_refresh_access_token", lambda **kwargs: "token-1")
    monkeypatch.setenv("JIRA_MIRROR_POLL_INTERVAL_SECONDS", "900")

    out = run_incremental_mirror_sync(
        workspace_id="ws_1",
        connection_id="conn_1",
        project_keys=["PROJ"],
        now_ts=2000,
        store=store,  # type: ignore[arg-type]
        api=api,  # type: ignore[arg-type]
    )

    assert out[0].skipped_by_cadence is True
    assert out[0].next_poll_after == 5000
    assert api.calls == []
