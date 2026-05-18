from __future__ import annotations

from typing import Any

from app.services.jira_ticket_sync_store import JiraTicketSyncStore


class FakeTable:
    def __init__(self) -> None:
        self.put_calls: list[dict[str, Any]] = []
        self.get_calls: list[dict[str, Any]] = []
        self.query_calls: list[dict[str, Any]] = []
        self._get_item: dict[str, Any] = {}
        self._query_items: list[dict[str, Any]] = []
        self.delete_calls: list[dict[str, Any]] = []
        self._items: dict[tuple[str, str], dict[str, Any]] = {}
        self.put_kwargs_calls: list[dict[str, Any]] = []

    def put_item(self, *, Item: dict[str, Any], **kwargs: Any) -> None:  # noqa: N803
        self.put_calls.append(Item)
        self.put_kwargs_calls.append(kwargs)
        self._items[(str(Item["pk"]), str(Item["sk"]))] = dict(Item)

    def get_item(self, *, Key: dict[str, Any]) -> dict[str, Any]:  # noqa: N803
        self.get_calls.append(Key)
        key = (str(Key.get("pk", "")), str(Key.get("sk", "")))
        if key in self._items:
            return {"Item": dict(self._items[key])}
        return {"Item": self._get_item} if self._get_item else {}

    def query(self, **kwargs: Any) -> dict[str, Any]:
        self.query_calls.append(kwargs)
        return {"Items": list(self._query_items)}

    def delete_item(self, *, Key: dict[str, Any]) -> None:  # noqa: N803
        self.delete_calls.append(Key)
        key = (str(Key.get("pk", "")), str(Key.get("sk", "")))
        self._items.pop(key, None)


def test_upsert_connection_sets_workspace_and_sync_indexes() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)

    item = store.upsert_connection(
        workspace_id="ws_1",
        connection_id="conn_1",
        user_id="user_1",
        cloud_id="cloud_1",
        site_url="https://example.atlassian.net",
        auth_type="oauth",
        scopes=["read:jira-work", "write:jira-work"],
        access_token_ref="secret://a",
        refresh_token_ref="secret://b",
        expires_at=12345,
        status="active",
    )

    assert item["entity_type"] == "jira_connection"
    assert item["gsi_jira_workspace_pk"] == "WORKSPACE#ws_1"
    assert item["gsi_jira_sync_state_pk"] == "SYNC_STATE#active"
    assert table.put_calls and table.put_calls[0]["connection_id"] == "conn_1"


def test_put_external_link_sets_issue_lookup_index() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)

    item = store.put_external_link(
        workspace_id="ws_1",
        internal_ticket_id="tkt_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        project_key="PROJ",
        link_mode="bidirectional",
        sync_state="in_sync",
        created_by="user_1",
        link_id="jlink_fixed",
    )

    assert item["pk"] == "TICKET#tkt_1"
    assert item["gsi_jira_issue_pk"] == "JIRA_ISSUE#10001"
    assert item["gsi_jira_issue_sk"] == "LINK#jlink_fixed"


def test_get_link_by_external_issue_id_uses_configured_issue_index() -> None:
    table = FakeTable()
    table._query_items = [{"entity_type": "ticket_external_link", "link_id": "jlink_1"}]
    store = JiraTicketSyncStore(_table=table)

    rows = store.get_link_by_external_issue_id(external_issue_id="10001")

    assert rows == [{"entity_type": "ticket_external_link", "link_id": "jlink_1"}]
    assert table.query_calls
    assert table.query_calls[0]["KeyConditionExpression"] == "gsi_jira_issue_pk = :pk"


def test_create_external_link_rejects_duplicate_active_link() -> None:
    table = FakeTable()
    table._query_items = [
        {
            "entity_type": "ticket_external_link",
            "external_issue_id": "10001",
            "external_issue_key": "PROJ-1",
            "sync_state": "in_sync",
        }
    ]
    store = JiraTicketSyncStore(_table=table)

    try:
        store.create_external_link(
            workspace_id="ws_1",
            internal_ticket_id="tkt_1",
            external_issue_id="10001",
            external_issue_key="PROJ-1",
            project_key="PROJ",
            link_mode="bidirectional",
            sync_state="in_sync",
            created_by="user_1",
        )
        assert False, "expected duplicate active link validation error"
    except ValueError as exc:
        assert "active link already exists" in str(exc)


def test_create_external_link_allows_create_when_previous_deleted() -> None:
    table = FakeTable()
    table._query_items = [
        {
            "entity_type": "ticket_external_link",
            "external_issue_id": "10001",
            "external_issue_key": "PROJ-1",
            "sync_state": "deleted",
        }
    ]
    store = JiraTicketSyncStore(_table=table)

    item = store.create_external_link(
        workspace_id="ws_1",
        internal_ticket_id="tkt_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        project_key="PROJ",
        link_mode="bidirectional",
        sync_state="in_sync",
        created_by="user_1",
        link_id="jlink_fixed",
    )
    assert item["link_id"] == "jlink_fixed"
    assert table.put_calls and table.put_calls[0]["external_issue_key"] == "PROJ-1"


def test_list_links_by_external_issue_key_filters_workspace_rows() -> None:
    table = FakeTable()
    table._query_items = [
        {"entity_type": "ticket_external_link", "external_issue_key": "PROJ-1", "link_id": "j1"},
        {"entity_type": "ticket_external_link", "external_issue_key": "PROJ-2", "link_id": "j2"},
        {"entity_type": "jira_connection", "external_issue_key": "PROJ-1", "link_id": "ignored"},
    ]
    store = JiraTicketSyncStore(_table=table)

    rows = store.list_links_by_external_issue_key(workspace_id="ws_1", external_issue_key="PROJ-1")
    assert rows == [{"entity_type": "ticket_external_link", "external_issue_key": "PROJ-1", "link_id": "j1"}]


def test_delete_external_link_deletes_existing_link() -> None:
    table = FakeTable()
    table._get_item = {"entity_type": "ticket_external_link", "link_id": "jlink_1"}
    store = JiraTicketSyncStore(_table=table)

    ok = store.delete_external_link(internal_ticket_id="tkt_1", link_id="jlink_1")
    assert ok is True
    assert table.delete_calls == [{"pk": "TICKET#tkt_1", "sk": "JIRA_LINK#jlink_1"}]


def test_deactivate_external_link_marks_row_deleted_without_deleting_history() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)
    store.put_external_link(
        workspace_id="ws_1",
        internal_ticket_id="tkt_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        project_key="PROJ",
        link_mode="bidirectional",
        sync_state="queued",
        created_by="user_1",
        link_id="jlink_1",
    )

    row = store.deactivate_external_link(internal_ticket_id="tkt_1", link_id="jlink_1", actor_user_id="user_1")
    assert row is not None
    assert row["sync_state"] == "deleted"
    got = store.get_external_link(internal_ticket_id="tkt_1", link_id="jlink_1")
    assert got is not None
    assert got["sync_state"] == "deleted"


def test_update_external_link_sync_metadata_sets_last_synced_and_sync_state() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)
    store.put_external_link(
        workspace_id="ws_1",
        internal_ticket_id="tkt_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        project_key="PROJ",
        link_mode="bidirectional",
        sync_state="queued",
        created_by="user_1",
        link_id="jlink_1",
    )
    row = store.update_external_link_sync_metadata(
        internal_ticket_id="tkt_1",
        link_id="jlink_1",
        sync_state="in_sync",
        last_sync_direction="inbound",
        outbound_update_token="idem-1",
    )
    assert row is not None
    assert row["sync_state"] == "in_sync"
    assert row["last_sync_direction"] == "inbound"
    assert int(row["last_synced_at"]) > 0
    assert row["last_outbound_update_token"] == "idem-1"


def test_persist_external_link_conflict_sets_conflict_state_and_payload() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)
    store.put_external_link(
        workspace_id="ws_1",
        internal_ticket_id="tkt_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        project_key="PROJ",
        link_mode="bidirectional",
        sync_state="queued",
        created_by="user_1",
        link_id="jlink_1",
    )
    row = store.persist_external_link_conflict(
        internal_ticket_id="tkt_1",
        link_id="jlink_1",
        conflict_fields=["title", "status"],
        local_candidates={"title": "Local", "status": "To Do"},
        remote_candidates={"title": "Remote", "status": "In Progress"},
    )
    assert row is not None
    assert row["sync_state"] == "conflict"
    assert row["conflict_state"] == "detected"
    assert row["conflict_payload"]["local"]["title"] == "Local"
    assert row["conflict_payload"]["remote"]["title"] == "Remote"


def test_clear_external_link_conflict_resets_state_and_payload() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)
    store.put_external_link(
        workspace_id="ws_1",
        internal_ticket_id="tkt_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        project_key="PROJ",
        link_mode="bidirectional",
        sync_state="queued",
        created_by="user_1",
        link_id="jlink_1",
    )
    store.persist_external_link_conflict(
        internal_ticket_id="tkt_1",
        link_id="jlink_1",
        conflict_fields=["title"],
        local_candidates={"title": "Local"},
        remote_candidates={"title": "Remote"},
    )
    row = store.clear_external_link_conflict(
        internal_ticket_id="tkt_1",
        link_id="jlink_1",
        last_sync_direction="inbound",
    )
    assert row is not None
    assert row["sync_state"] == "in_sync"
    assert row["conflict_state"] == "none"
    assert row["conflict_payload"] == {}


def test_upsert_issue_mirror_persists_mirror_entity() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)

    item = store.upsert_issue_mirror(
        workspace_id="ws_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        cloud_id="cloud_1",
        project_key="PROJ",
        summary="Example",
        description="Details",
        status="In Progress",
        priority="High",
        assignee_account_id="acc-1",
        reporter_account_id="acc-2",
        labels=["incident", "customer"],
        updated_at_remote="2026-03-24T00:00:00Z",
    )

    assert item["entity_type"] == "jira_issue_mirror"
    assert item["pk"] == "JIRA_ISSUE#10001"
    assert sorted(item["labels"]) == ["customer", "incident"]
    assert isinstance(item["ingested_at"], int)
    assert item["updated_at_remote"] == "2026-03-24T00:00:00Z"


def test_upsert_issue_mirror_is_idempotent_by_external_issue_id() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)

    store.upsert_issue_mirror(
        workspace_id="ws_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        cloud_id="cloud_1",
        project_key="PROJ",
        summary="Original summary",
        description="Original description",
        status="To Do",
        priority="Medium",
        assignee_account_id=None,
        reporter_account_id="acc-2",
        labels=["incident"],
        updated_at_remote="2026-03-24T00:00:00Z",
    )
    second = store.upsert_issue_mirror(
        workspace_id="ws_1",
        external_issue_id="10001",
        external_issue_key="PROJ-1",
        cloud_id="cloud_1",
        project_key="PROJ",
        summary="Updated summary",
        description="Updated description",
        status="In Progress",
        priority="High",
        assignee_account_id="acc-1",
        reporter_account_id="acc-2",
        labels=["incident", "customer"],
        updated_at_remote="2026-03-25T00:00:00Z",
    )

    assert table.put_calls[0]["pk"] == table.put_calls[1]["pk"] == "JIRA_ISSUE#10001"
    assert table.put_calls[0]["sk"] == table.put_calls[1]["sk"] == "MIRROR"
    mirror = store.get_issue_mirror(external_issue_id="10001")
    assert mirror is not None
    assert mirror["summary"] == "Updated summary"
    assert mirror["updated_at_remote"] == "2026-03-25T00:00:00Z"
    assert mirror["ingested_at"] == second["ingested_at"]


def test_list_issue_mirrors_for_workspace_filters_entity_type() -> None:
    table = FakeTable()
    table._query_items = [
        {"entity_type": "jira_issue_mirror", "external_issue_key": "PROJ-1"},
        {"entity_type": "ticket_external_link", "external_issue_key": "PROJ-1"},
    ]
    store = JiraTicketSyncStore(_table=table)

    rows = store.list_issue_mirrors_for_workspace(workspace_id="ws_1")
    assert rows == [{"entity_type": "jira_issue_mirror", "external_issue_key": "PROJ-1"}]


def test_get_issue_mirror_by_key_returns_workspace_match() -> None:
    table = FakeTable()
    table._query_items = [
        {"entity_type": "jira_issue_mirror", "external_issue_key": "PROJ-1", "external_issue_id": "10001"},
        {"entity_type": "jira_issue_mirror", "external_issue_key": "PROJ-2", "external_issue_id": "10002"},
    ]
    store = JiraTicketSyncStore(_table=table)

    mirror = store.get_issue_mirror_by_key(workspace_id="ws_1", external_issue_key="PROJ-2")
    assert mirror is not None
    assert mirror["external_issue_id"] == "10002"


def test_append_sync_event_creates_immutable_event_row() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)

    item = store.append_sync_event(
        workspace_id="ws_1",
        internal_ticket_id="tkt_1",
        direction="outbound",
        result="success",
        error_code="",
        payload_hash="abc",
        trace_id="trace-1",
    )

    assert item["entity_type"] == "ticket_sync_event"
    assert item["pk"] == "TICKET#tkt_1"
    assert item["gsi_jira_sync_state_pk"] == "SYNC_STATE#success"
    assert item["direction"] == "outbound"
    assert item["trace_id"] == "trace-1"
    assert item["error_code"] == ""
    assert table.put_kwargs_calls[0]["ConditionExpression"] == "attribute_not_exists(pk) AND attribute_not_exists(sk)"


def test_list_sync_events_for_ticket_filters_to_sync_event_entities() -> None:
    table = FakeTable()
    table._query_items = [
        {"entity_type": "ticket_sync_event", "sk": "SYNC_EVENT#0000000000001#sev_1"},
        {"entity_type": "jira_connection", "sk": "JIRA_CONN#conn_1"},
    ]
    store = JiraTicketSyncStore(_table=table)

    rows = store.list_sync_events_for_ticket(internal_ticket_id="tkt_1")
    assert rows == [{"entity_type": "ticket_sync_event", "sk": "SYNC_EVENT#0000000000001#sev_1"}]


def test_list_sync_events_for_workspace_filters_by_time_window() -> None:
    table = FakeTable()
    table._query_items = [
        {"entity_type": "ticket_sync_event", "sk": "SYNC_EVENT#0000000000010#sev_10", "trace_id": "trace-10"},
        {"entity_type": "ticket_sync_event", "sk": "SYNC_EVENT#0000000000020#sev_20", "trace_id": "trace-20"},
        {"entity_type": "ticket_sync_event", "sk": "SYNC_EVENT#0000000000030#sev_30", "trace_id": "trace-30"},
        {"entity_type": "ticket_external_link", "sk": "JIRA_LINK#jlink_1"},
    ]
    store = JiraTicketSyncStore(_table=table)

    rows = store.list_sync_events_for_workspace(workspace_id="ws_1", since_ts=20, until_ts=30)
    assert [row["trace_id"] for row in rows] == ["trace-20", "trace-30"]



def test_list_connections_for_user_filters_workspace_connections() -> None:
    table = FakeTable()
    table._query_items = [
        {"entity_type": "jira_connection", "user_id": "u1", "connection_id": "c1"},
        {"entity_type": "jira_connection", "user_id": "u2", "connection_id": "c2"},
    ]
    store = JiraTicketSyncStore(_table=table)

    rows = store.list_connections_for_user(workspace_id="ws_1", user_id="u1")
    assert rows == [{"entity_type": "jira_connection", "user_id": "u1", "connection_id": "c1"}]


def test_get_connection_for_user_cloud_returns_match() -> None:
    table = FakeTable()
    table._query_items = [
        {"entity_type": "jira_connection", "user_id": "u1", "cloud_id": "cA", "connection_id": "connA"},
        {"entity_type": "jira_connection", "user_id": "u1", "cloud_id": "cB", "connection_id": "connB"},
    ]
    store = JiraTicketSyncStore(_table=table)

    row = store.get_connection_for_user_cloud(workspace_id="ws_1", user_id="u1", cloud_id="cB")
    assert row is not None
    assert row["connection_id"] == "connB"


def test_delete_connection_issues_delete_item_when_present() -> None:
    table = FakeTable()
    table._get_item = {"workspace_id": "ws_1", "connection_id": "conn_1"}
    store = JiraTicketSyncStore(_table=table)

    ok = store.delete_connection(workspace_id="ws_1", connection_id="conn_1")
    assert ok is True
    assert table.delete_calls == [{"pk": "WORKSPACE#ws_1", "sk": "JIRA_CONN#conn_1"}]


def test_upsert_and_get_mirror_backfill_checkpoint_roundtrip() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)

    store.upsert_mirror_backfill_checkpoint(
        workspace_id="ws_1",
        connection_id="conn_1",
        project_key="PROJ",
        next_start_at=50,
        status="in_progress",
        imported_count=200,
        error_code="",
    )
    row = store.get_mirror_backfill_checkpoint(workspace_id="ws_1", connection_id="conn_1", project_key="PROJ")
    assert row is not None
    assert row["next_start_at"] == 50
    assert row["imported_count"] == 200


def test_upsert_and_get_mirror_incremental_checkpoint_roundtrip() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)

    store.upsert_mirror_incremental_checkpoint(
        workspace_id="ws_1",
        connection_id="conn_1",
        project_key="PROJ",
        updated_after="2026-04-01T00:00:00Z",
        last_polled_at=1000,
        next_poll_after=1600,
        imported_count=300,
        status="active",
        error_code="",
    )
    row = store.get_mirror_incremental_checkpoint(workspace_id="ws_1", connection_id="conn_1", project_key="PROJ")
    assert row is not None
    assert row["updated_after"] == "2026-04-01T00:00:00Z"
    assert row["next_poll_after"] == 1600


def test_upsert_and_get_project_preferences_roundtrip() -> None:
    table = FakeTable()
    store = JiraTicketSyncStore(_table=table)

    item = store.upsert_project_preferences(
        workspace_id="ws_1",
        user_id="u1",
        cloud_id="cloud_1",
        project_keys=["PROJ", "OPS", "PROJ", ""],
    )
    assert item["entity_type"] == "jira_project_preferences"
    assert item["project_keys"] == ["OPS", "PROJ"]

    row = store.get_project_preferences(workspace_id="ws_1", user_id="u1", cloud_id="cloud_1")
    assert row is not None
    assert row["project_keys"] == ["OPS", "PROJ"]
