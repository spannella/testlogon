from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import uuid

from app.core.settings import S


def _now_ts() -> int:
    import time

    return int(time.time())


def _ticket_pk(ticket_id: str) -> str:
    return f"TICKET#{ticket_id}"


def _jira_issue_pk(external_issue_id: str) -> str:
    return f"JIRA_ISSUE#{external_issue_id}"


def _workspace_pk(workspace_id: str) -> str:
    return f"WORKSPACE#{workspace_id}"


@dataclass
class JiraTicketSyncStore:
    _table: Any = field(default=None)

    def __post_init__(self) -> None:
        if self._table is None:
            from app.core.tables import T

            self._table = T.tickets

    def upsert_connection(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        user_id: str | None,
        cloud_id: str,
        site_url: str,
        auth_type: str,
        scopes: list[str],
        access_token_ref: str,
        refresh_token_ref: str,
        expires_at: int,
        status: str,
    ) -> dict[str, Any]:
        now = _now_ts()
        actor = user_id or "service"
        item = {
            "pk": _workspace_pk(workspace_id),
            "sk": f"JIRA_CONN#{connection_id}",
            "entity_type": "jira_connection",
            "workspace_id": workspace_id,
            "connection_id": connection_id,
            "user_id": user_id,
            "cloud_id": cloud_id,
            "site_url": site_url,
            "auth_type": auth_type,
            "scopes": sorted({s.strip() for s in scopes if s.strip()}),
            "access_token_ref": access_token_ref,
            "refresh_token_ref": refresh_token_ref,
            "expires_at": int(expires_at),
            "status": status,
            "created_at": now,
            "updated_at": now,
            "gsi_jira_workspace_pk": _workspace_pk(workspace_id),
            "gsi_jira_workspace_sk": f"UPDATED#{now:013d}#CONN#{connection_id}",
            "gsi_jira_sync_state_pk": f"SYNC_STATE#{status}",
            "gsi_jira_sync_state_sk": f"UPDATED#{now:013d}#CONN#{connection_id}#ACTOR#{actor}",
        }
        self._table.put_item(Item=item)
        return item

    def get_connection(self, *, workspace_id: str, connection_id: str) -> dict[str, Any] | None:
        row = self._table.get_item(
            Key={"pk": _workspace_pk(workspace_id), "sk": f"JIRA_CONN#{connection_id}"}
        ).get("Item")
        return dict(row) if row else None

    def list_workspace_connections(self, *, workspace_id: str, limit: int = 50) -> list[dict[str, Any]]:
        res = self._table.query(
            IndexName=S.tickets_jira_workspace_index_name,
            KeyConditionExpression="gsi_jira_workspace_pk = :pk",
            ExpressionAttributeValues={":pk": _workspace_pk(workspace_id)},
            ScanIndexForward=False,
            Limit=max(1, min(int(limit), 100)),
        )
        return [dict(x) for x in (res.get("Items") or []) if x.get("entity_type") == "jira_connection"]


    def list_connections_for_user(self, *, workspace_id: str, user_id: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.list_workspace_connections(workspace_id=workspace_id, limit=limit)
        return [row for row in rows if str(row.get("user_id") or "") == user_id]

    def get_connection_for_user_cloud(self, *, workspace_id: str, user_id: str, cloud_id: str) -> dict[str, Any] | None:
        for row in self.list_connections_for_user(workspace_id=workspace_id, user_id=user_id, limit=100):
            if str(row.get("cloud_id") or "") == cloud_id:
                return row
        return None

    def update_connection_status(self, *, workspace_id: str, connection_id: str, status: str) -> dict[str, Any] | None:
        cur = self.get_connection(workspace_id=workspace_id, connection_id=connection_id)
        if not cur:
            return None
        return self.upsert_connection(
            workspace_id=workspace_id,
            connection_id=connection_id,
            user_id=cur.get("user_id"),
            cloud_id=str(cur.get("cloud_id") or "unknown"),
            site_url=str(cur.get("site_url") or ""),
            auth_type=str(cur.get("auth_type") or "oauth"),
            scopes=list(cur.get("scopes") or []),
            access_token_ref=str(cur.get("access_token_ref") or ""),
            refresh_token_ref=str(cur.get("refresh_token_ref") or ""),
            expires_at=int(cur.get("expires_at") or 0),
            status=status,
        )

    def delete_connection(self, *, workspace_id: str, connection_id: str) -> bool:
        existing = self.get_connection(workspace_id=workspace_id, connection_id=connection_id)
        if not existing:
            return False
        self._table.delete_item(Key={"pk": _workspace_pk(workspace_id), "sk": f"JIRA_CONN#{connection_id}"})
        return True

    def upsert_project_preferences(
        self,
        *,
        workspace_id: str,
        user_id: str,
        cloud_id: str,
        project_keys: list[str],
    ) -> dict[str, Any]:
        now = _now_ts()
        normalized = sorted({str(x).strip() for x in project_keys if str(x).strip()})
        item = {
            "pk": _workspace_pk(workspace_id),
            "sk": f"JIRA_PREFS#{user_id}#{cloud_id}",
            "entity_type": "jira_project_preferences",
            "workspace_id": workspace_id,
            "user_id": user_id,
            "cloud_id": cloud_id,
            "project_keys": normalized,
            "updated_at": now,
            "gsi_jira_workspace_pk": _workspace_pk(workspace_id),
            "gsi_jira_workspace_sk": f"UPDATED#{now:013d}#PREFS#{user_id}#{cloud_id}",
            "gsi_jira_sync_state_pk": "SYNC_STATE#prefs",
            "gsi_jira_sync_state_sk": f"UPDATED#{now:013d}#PREFS#{user_id}#{cloud_id}",
        }
        self._table.put_item(Item=item)
        return item

    def get_project_preferences(self, *, workspace_id: str, user_id: str, cloud_id: str) -> dict[str, Any] | None:
        row = self._table.get_item(Key={"pk": _workspace_pk(workspace_id), "sk": f"JIRA_PREFS#{user_id}#{cloud_id}"}).get("Item")
        return dict(row) if row else None

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
        now = _now_ts()
        item = {
            "pk": _workspace_pk(workspace_id),
            "sk": f"JIRA_BACKFILL#{connection_id}#{project_key}",
            "entity_type": "jira_backfill_checkpoint",
            "workspace_id": workspace_id,
            "connection_id": connection_id,
            "project_key": project_key,
            "next_start_at": int(next_start_at),
            "imported_count": int(imported_count),
            "status": status,
            "error_code": error_code,
            "updated_at": now,
            "gsi_jira_workspace_pk": _workspace_pk(workspace_id),
            "gsi_jira_workspace_sk": f"UPDATED#{now:013d}#BACKFILL#{connection_id}#{project_key}",
            "gsi_jira_sync_state_pk": f"SYNC_STATE#{status}",
            "gsi_jira_sync_state_sk": f"UPDATED#{now:013d}#BACKFILL#{connection_id}#{project_key}",
        }
        self._table.put_item(Item=item)
        return item

    def get_mirror_backfill_checkpoint(
        self, *, workspace_id: str, connection_id: str, project_key: str
    ) -> dict[str, Any] | None:
        row = self._table.get_item(
            Key={"pk": _workspace_pk(workspace_id), "sk": f"JIRA_BACKFILL#{connection_id}#{project_key}"}
        ).get("Item")
        return dict(row) if row else None

    def upsert_mirror_incremental_checkpoint(
        self,
        *,
        workspace_id: str,
        connection_id: str,
        project_key: str,
        updated_after: str,
        last_polled_at: int,
        next_poll_after: int,
        imported_count: int,
        status: str,
        error_code: str = "",
    ) -> dict[str, Any]:
        now = _now_ts()
        item = {
            "pk": _workspace_pk(workspace_id),
            "sk": f"JIRA_INCREMENTAL#{connection_id}#{project_key}",
            "entity_type": "jira_incremental_checkpoint",
            "workspace_id": workspace_id,
            "connection_id": connection_id,
            "project_key": project_key,
            "updated_after": updated_after,
            "last_polled_at": int(last_polled_at),
            "next_poll_after": int(next_poll_after),
            "imported_count": int(imported_count),
            "status": status,
            "error_code": error_code,
            "updated_at": now,
            "gsi_jira_workspace_pk": _workspace_pk(workspace_id),
            "gsi_jira_workspace_sk": f"UPDATED#{now:013d}#INCR#{connection_id}#{project_key}",
            "gsi_jira_sync_state_pk": f"SYNC_STATE#{status}",
            "gsi_jira_sync_state_sk": f"UPDATED#{now:013d}#INCR#{connection_id}#{project_key}",
        }
        self._table.put_item(Item=item)
        return item

    def get_mirror_incremental_checkpoint(
        self, *, workspace_id: str, connection_id: str, project_key: str
    ) -> dict[str, Any] | None:
        row = self._table.get_item(
            Key={"pk": _workspace_pk(workspace_id), "sk": f"JIRA_INCREMENTAL#{connection_id}#{project_key}"}
        ).get("Item")
        return dict(row) if row else None

    def put_external_link(
        self,
        *,
        workspace_id: str,
        internal_ticket_id: str,
        external_issue_id: str,
        external_issue_key: str,
        project_key: str,
        link_mode: str,
        sync_state: str,
        created_by: str,
        link_id: str | None = None,
    ) -> dict[str, Any]:
        now = _now_ts()
        resolved_link_id = link_id or f"jlink_{uuid.uuid4().hex[:12]}"
        item = {
            "pk": _ticket_pk(internal_ticket_id),
            "sk": f"JIRA_LINK#{resolved_link_id}",
            "entity_type": "ticket_external_link",
            "workspace_id": workspace_id,
            "internal_ticket_id": internal_ticket_id,
            "provider": "jira",
            "link_id": resolved_link_id,
            "external_issue_id": external_issue_id,
            "external_issue_key": external_issue_key,
            "project_key": project_key,
            "link_mode": link_mode,
            "sync_state": sync_state,
            "conflict_state": "none",
            "last_synced_at": 0,
            "last_sync_direction": "none",
            "created_by": created_by,
            "created_at": now,
            "updated_at": now,
            "gsi_jira_issue_pk": _jira_issue_pk(external_issue_id),
            "gsi_jira_issue_sk": f"LINK#{resolved_link_id}",
            "gsi_jira_workspace_pk": _workspace_pk(workspace_id),
            "gsi_jira_workspace_sk": f"UPDATED#{now:013d}#LINK#{resolved_link_id}",
            "gsi_jira_sync_state_pk": f"SYNC_STATE#{sync_state}",
            "gsi_jira_sync_state_sk": f"UPDATED#{now:013d}#LINK#{resolved_link_id}",
        }
        self._table.put_item(Item=item)
        return item

    def create_external_link(
        self,
        *,
        workspace_id: str,
        internal_ticket_id: str,
        external_issue_id: str,
        external_issue_key: str,
        project_key: str,
        link_mode: str,
        sync_state: str,
        created_by: str,
        link_id: str | None = None,
    ) -> dict[str, Any]:
        existing = self.find_active_link_for_ticket_issue(
            internal_ticket_id=internal_ticket_id,
            external_issue_id=external_issue_id,
            external_issue_key=external_issue_key,
        )
        if existing is not None:
            raise ValueError("active link already exists for ticket and Jira issue")
        return self.put_external_link(
            workspace_id=workspace_id,
            internal_ticket_id=internal_ticket_id,
            external_issue_id=external_issue_id,
            external_issue_key=external_issue_key,
            project_key=project_key,
            link_mode=link_mode,
            sync_state=sync_state,
            created_by=created_by,
            link_id=link_id,
        )

    def list_links_for_ticket(self, *, internal_ticket_id: str) -> list[dict[str, Any]]:
        res = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
            ExpressionAttributeValues={":pk": _ticket_pk(internal_ticket_id), ":sk": "JIRA_LINK#"},
        )
        return [dict(x) for x in (res.get("Items") or [])]

    def find_active_link_for_ticket_issue(
        self,
        *,
        internal_ticket_id: str,
        external_issue_id: str,
        external_issue_key: str,
    ) -> dict[str, Any] | None:
        for row in self.list_links_for_ticket(internal_ticket_id=internal_ticket_id):
            if row.get("entity_type") != "ticket_external_link":
                continue
            if row.get("sync_state") == "deleted":
                continue
            if (
                str(row.get("external_issue_id") or "") == external_issue_id
                or str(row.get("external_issue_key") or "") == external_issue_key
            ):
                return row
        return None

    def get_link_by_external_issue_id(self, *, external_issue_id: str) -> list[dict[str, Any]]:
        res = self._table.query(
            IndexName=S.tickets_jira_issue_index_name,
            KeyConditionExpression="gsi_jira_issue_pk = :pk",
            ExpressionAttributeValues={":pk": _jira_issue_pk(external_issue_id)},
        )
        return [dict(x) for x in (res.get("Items") or []) if x.get("entity_type") == "ticket_external_link"]

    def list_links_by_external_issue_key(
        self, *, workspace_id: str, external_issue_key: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        res = self._table.query(
            IndexName=S.tickets_jira_workspace_index_name,
            KeyConditionExpression="gsi_jira_workspace_pk = :pk",
            ExpressionAttributeValues={":pk": _workspace_pk(workspace_id)},
            ScanIndexForward=False,
            Limit=max(1, min(int(limit), 200)),
        )
        rows = []
        for row in (res.get("Items") or []):
            if row.get("entity_type") != "ticket_external_link":
                continue
            if str(row.get("external_issue_key") or "") != external_issue_key:
                continue
            rows.append(dict(row))
        return rows

    def delete_external_link(self, *, internal_ticket_id: str, link_id: str) -> bool:
        key = {"pk": _ticket_pk(internal_ticket_id), "sk": f"JIRA_LINK#{link_id}"}
        row = self._table.get_item(Key=key).get("Item")
        if not row:
            return False
        self._table.delete_item(Key=key)
        return True

    def get_external_link(self, *, internal_ticket_id: str, link_id: str) -> dict[str, Any] | None:
        row = self._table.get_item(Key={"pk": _ticket_pk(internal_ticket_id), "sk": f"JIRA_LINK#{link_id}"}).get("Item")
        return dict(row) if row else None

    def deactivate_external_link(self, *, internal_ticket_id: str, link_id: str, actor_user_id: str) -> dict[str, Any] | None:
        row = self.get_external_link(internal_ticket_id=internal_ticket_id, link_id=link_id)
        if not row:
            return None
        if str(row.get("sync_state") or "") == "deleted":
            return row
        now = _now_ts()
        item = dict(row)
        item["sync_state"] = "deleted"
        item["updated_at"] = now
        item["unlinked_at"] = now
        item["unlinked_by"] = actor_user_id
        item["gsi_jira_workspace_sk"] = f"UPDATED#{now:013d}#LINK#{link_id}"
        item["gsi_jira_sync_state_pk"] = "SYNC_STATE#deleted"
        item["gsi_jira_sync_state_sk"] = f"UPDATED#{now:013d}#LINK#{link_id}"
        self._table.put_item(Item=item)
        return item

    def update_external_link_sync_metadata(
        self,
        *,
        internal_ticket_id: str,
        link_id: str,
        sync_state: str,
        last_sync_direction: str,
        conflict_state: str = "none",
        outbound_update_token: str | None = None,
    ) -> dict[str, Any] | None:
        row = self.get_external_link(internal_ticket_id=internal_ticket_id, link_id=link_id)
        if not row:
            return None
        now = _now_ts()
        item = dict(row)
        item["sync_state"] = sync_state
        item["conflict_state"] = conflict_state
        item["last_sync_direction"] = last_sync_direction
        item["last_synced_at"] = now
        item["updated_at"] = now
        if outbound_update_token is not None:
            item["last_outbound_update_token"] = outbound_update_token
            item["last_outbound_at"] = now
        item["gsi_jira_sync_state_pk"] = f"SYNC_STATE#{sync_state}"
        item["gsi_jira_sync_state_sk"] = f"UPDATED#{now:013d}#LINK#{link_id}"
        item["gsi_jira_workspace_sk"] = f"UPDATED#{now:013d}#LINK#{link_id}"
        self._table.put_item(Item=item)
        return item

    def persist_external_link_conflict(
        self,
        *,
        internal_ticket_id: str,
        link_id: str,
        conflict_fields: list[str],
        local_candidates: dict[str, Any],
        remote_candidates: dict[str, Any],
    ) -> dict[str, Any] | None:
        row = self.get_external_link(internal_ticket_id=internal_ticket_id, link_id=link_id)
        if not row:
            return None
        now = _now_ts()
        item = dict(row)
        item["sync_state"] = "conflict"
        item["conflict_state"] = "detected"
        item["conflict_fields"] = sorted({str(x) for x in conflict_fields if str(x).strip()})
        item["conflict_payload"] = {
            "local": dict(local_candidates),
            "remote": dict(remote_candidates),
        }
        item["conflict_detected_at"] = now
        item["updated_at"] = now
        item["gsi_jira_sync_state_pk"] = "SYNC_STATE#conflict"
        item["gsi_jira_sync_state_sk"] = f"UPDATED#{now:013d}#LINK#{link_id}"
        item["gsi_jira_workspace_sk"] = f"UPDATED#{now:013d}#LINK#{link_id}"
        self._table.put_item(Item=item)
        return item

    def clear_external_link_conflict(
        self,
        *,
        internal_ticket_id: str,
        link_id: str,
        last_sync_direction: str,
    ) -> dict[str, Any] | None:
        row = self.get_external_link(internal_ticket_id=internal_ticket_id, link_id=link_id)
        if not row:
            return None
        now = _now_ts()
        item = dict(row)
        item["sync_state"] = "in_sync"
        item["conflict_state"] = "none"
        item["conflict_fields"] = []
        item["conflict_payload"] = {}
        item["conflict_resolved_at"] = now
        item["last_sync_direction"] = last_sync_direction
        item["last_synced_at"] = now
        item["updated_at"] = now
        item["gsi_jira_sync_state_pk"] = "SYNC_STATE#in_sync"
        item["gsi_jira_sync_state_sk"] = f"UPDATED#{now:013d}#LINK#{link_id}"
        item["gsi_jira_workspace_sk"] = f"UPDATED#{now:013d}#LINK#{link_id}"
        self._table.put_item(Item=item)
        return item

    def upsert_issue_mirror(
        self,
        *,
        workspace_id: str,
        external_issue_id: str,
        external_issue_key: str,
        cloud_id: str,
        project_key: str,
        summary: str,
        description: str,
        status: str,
        priority: str,
        assignee_account_id: str | None,
        reporter_account_id: str | None,
        labels: list[str],
        updated_at_remote: str,
    ) -> dict[str, Any]:
        now = _now_ts()
        item = {
            "pk": _jira_issue_pk(external_issue_id),
            "sk": "MIRROR",
            "entity_type": "jira_issue_mirror",
            "workspace_id": workspace_id,
            "external_issue_id": external_issue_id,
            "external_issue_key": external_issue_key,
            "cloud_id": cloud_id,
            "project_key": project_key,
            "summary": summary,
            "description": description,
            "status": status,
            "priority": priority,
            "assignee_account_id": assignee_account_id,
            "reporter_account_id": reporter_account_id,
            "labels": sorted({x.strip() for x in labels if x.strip()}),
            "updated_at_remote": updated_at_remote,
            "ingested_at": now,
            "updated_at": now,
            "gsi_jira_issue_pk": _jira_issue_pk(external_issue_id),
            "gsi_jira_issue_sk": "MIRROR",
            "gsi_jira_workspace_pk": _workspace_pk(workspace_id),
            "gsi_jira_workspace_sk": f"UPDATED#{now:013d}#ISSUE#{external_issue_id}",
            "gsi_jira_sync_state_pk": f"SYNC_STATE#{status}",
            "gsi_jira_sync_state_sk": f"UPDATED#{now:013d}#ISSUE#{external_issue_id}",
        }
        self._table.put_item(Item=item)
        return item

    def get_issue_mirror(self, *, external_issue_id: str) -> dict[str, Any] | None:
        row = self._table.get_item(Key={"pk": _jira_issue_pk(external_issue_id), "sk": "MIRROR"}).get("Item")
        return dict(row) if row else None

    def get_issue_mirror_by_key(self, *, workspace_id: str, external_issue_key: str) -> dict[str, Any] | None:
        rows = self.list_issue_mirrors_for_workspace(workspace_id=workspace_id, limit=200)
        for row in rows:
            if str(row.get("external_issue_key") or "") == external_issue_key:
                return row
        return None

    def list_issue_mirrors_for_workspace(self, *, workspace_id: str, limit: int = 100) -> list[dict[str, Any]]:
        res = self._table.query(
            IndexName=S.tickets_jira_workspace_index_name,
            KeyConditionExpression="gsi_jira_workspace_pk = :pk",
            ExpressionAttributeValues={":pk": _workspace_pk(workspace_id)},
            ScanIndexForward=False,
            Limit=max(1, min(int(limit), 200)),
        )
        return [dict(x) for x in (res.get("Items") or []) if x.get("entity_type") == "jira_issue_mirror"]

    def append_sync_event(
        self,
        *,
        workspace_id: str,
        internal_ticket_id: str,
        direction: str,
        result: str,
        error_code: str,
        payload_hash: str,
        trace_id: str,
    ) -> dict[str, Any]:
        now = _now_ts()
        event_id = f"sev_{uuid.uuid4().hex[:12]}"
        item = {
            "pk": _ticket_pk(internal_ticket_id),
            "sk": f"SYNC_EVENT#{now:013d}#{event_id}",
            "entity_type": "ticket_sync_event",
            "workspace_id": workspace_id,
            "event_id": event_id,
            "internal_ticket_id": internal_ticket_id,
            "direction": direction,
            "result": result,
            "error_code": error_code,
            "payload_hash": payload_hash,
            "trace_id": trace_id,
            "created_at": now,
            "gsi_jira_workspace_pk": _workspace_pk(workspace_id),
            "gsi_jira_workspace_sk": f"UPDATED#{now:013d}#SYNC#{event_id}",
            "gsi_jira_sync_state_pk": f"SYNC_STATE#{result}",
            "gsi_jira_sync_state_sk": f"UPDATED#{now:013d}#SYNC#{event_id}",
        }
        self._table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
        return item

    def list_sync_events_for_ticket(self, *, internal_ticket_id: str, limit: int = 50) -> list[dict[str, Any]]:
        res = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk)",
            ExpressionAttributeValues={":pk": _ticket_pk(internal_ticket_id), ":sk": "SYNC_EVENT#"},
            ScanIndexForward=False,
            Limit=max(1, min(int(limit), 200)),
        )
        return [dict(x) for x in (res.get("Items") or []) if x.get("entity_type") == "ticket_sync_event"]

    def list_sync_events_for_workspace(
        self,
        *,
        workspace_id: str,
        since_ts: int | None = None,
        until_ts: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        res = self._table.query(
            IndexName=S.tickets_jira_workspace_index_name,
            KeyConditionExpression="gsi_jira_workspace_pk = :pk",
            ExpressionAttributeValues={":pk": _workspace_pk(workspace_id)},
            ScanIndexForward=False,
            Limit=max(1, min(int(limit), 200)),
        )

        def _event_ts(row: dict[str, Any]) -> int:
            sk = str(row.get("sk") or "")
            parts = sk.split("#")
            if len(parts) < 3:
                return 0
            try:
                return int(parts[1])
            except (TypeError, ValueError):
                return 0

        rows: list[dict[str, Any]] = []
        for row in (res.get("Items") or []):
            if row.get("entity_type") != "ticket_sync_event":
                continue
            ts = _event_ts(row)
            if since_ts is not None and ts < int(since_ts):
                continue
            if until_ts is not None and ts > int(until_ts):
                continue
            rows.append(dict(row))
        return rows
