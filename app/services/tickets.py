from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from botocore.exceptions import ClientError

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_TICKET_STATUSES = (
    "open",
    "in_progress",
    "waiting_on_user",
    "done",
    "code_complete",
    "qa_in_progress",
    "qa_approved",
    "blocked",
    "deploying",
    "deployed",
    "investigating",
    "analyzing",
    "tickets_created",
)
_STATUS_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "open": ("in_progress", "done", "blocked"),
    "in_progress": ("waiting_on_user", "done", "open", "code_complete", "blocked"),
    "waiting_on_user": ("in_progress", "done", "open"),
    "done": ("open",),
    # AGENT-009: code_complete tickets are picked up by the QA agent.
    "code_complete": ("done", "in_progress", "open", "qa_in_progress"),
    "qa_in_progress": ("qa_approved", "in_progress", "code_complete", "open"),
    "qa_approved": ("done", "in_progress", "open"),
    "blocked": ("open", "in_progress"),
}

# AGENT-008: label index partition prefix. Label fan-out rows live in the base
# tickets table under pk="LABELIDX#{label}" so the coder agent can query eligible
# tickets by label without a new GSI (queryable on the base table partition key).
_LABEL_INDEX_PREFIX = "LABELIDX#"


def label_index_pk(label: str) -> str:
    return f"{_LABEL_INDEX_PREFIX}{label}"


def _label_index_sk(created_at: int, ticket_id: str) -> str:
    return f"{created_at:013d}#{ticket_id}"


def _complexity_from_labels(labels: list[str]) -> str | None:
    for level in ("critical", "high", "medium", "low"):
        if f"complexity:{level}" in labels:
            return level
    return None


class TicketStateError(Exception):
    def __init__(self, detail: dict[str, Any]):
        super().__init__(str(detail.get("code", "invalid_ticket_status_transition")))
        self.detail = detail


def _ticket_pk(ticket_id: str) -> str:
    return f"TICKET#{ticket_id}"


def _meta_item_key(ticket_id: str) -> dict[str, str]:
    return {"pk": _ticket_pk(ticket_id), "sk": "META"}


def _msg_sk(ts: int, message_id: str) -> str:
    return f"MSG#{ts:013d}#{message_id}"


def _act_sk(ts: int, activity_id: str) -> str:
    return f"ACT#{ts:013d}#{activity_id}"


def _owner_index_pk(owner_sub: str) -> str:
    return f"OWNER#{owner_sub}"


def _status_index_pk(status: str) -> str:
    return f"STATUS#{status}"


def _assignee_index_pk(assignee_sub: str) -> str:
    return f"ASSIGNEE#{assignee_sub}"


def _updated_index_sk(updated_at: int, ticket_id: str) -> str:
    return f"UPDATED#{updated_at:013d}#TICKET#{ticket_id}"


def _space_pk(space_id: str) -> str:
    return f"SPACE#{space_id}"


def _space_meta_key(space_id: str) -> dict[str, str]:
    return {"pk": _space_pk(space_id), "sk": "META"}


def _space_member_sk(member_sub: str) -> str:
    return f"MEMBER#{member_sub}"


def _space_index_pk(space_id: str) -> str:
    return f"SPACE#{space_id}"


def _space_status_index_pk(space_id: str, status: str) -> str:
    return f"SPACE#{space_id}#STATUS#{status}"


def _space_assignee_index_pk(space_id: str, assignee_sub: str) -> str:
    return f"SPACE#{space_id}#ASSIGNEE#{assignee_sub}"


def _member_index_pk(member_sub: str) -> str:
    return f"MEMBER#{member_sub}"


def _member_index_sk(space_id: str) -> str:
    return f"SPACE#{space_id}"


def _coerce_status(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized == "reopened":
        return "open"
    return normalized


def _next_status_for_message(*, sender_role: str, current_status: str) -> str:
    if sender_role == "admin":
        return "waiting_on_user"
    if current_status == "done":
        return "open"
    return "in_progress"


@dataclass
class TicketStore:
    _table: Any = field(default=T.tickets)

    def create_space(self, *, owner_sub: str, name: str, visibility: str = "private") -> dict[str, Any]:
        ts = now_ts()
        space_id = f"spc_{uuid.uuid4().hex[:12]}"
        self._table.put_item(Item={
            "pk": _space_pk(space_id),
            "sk": "META",
            "entity_type": "ticket_space",
            "space_id": space_id,
            "owner_sub": owner_sub,
            "name": name,
            "visibility": visibility,
            "created_at": ts,
            "updated_at": ts,
        })
        self._table.put_item(Item={
            "pk": _space_pk(space_id),
            "sk": _space_member_sk(owner_sub),
            "entity_type": "space_membership",
            "space_id": space_id,
            "member_sub": owner_sub,
            "role": "owner",
            "created_at": ts,
            "updated_at": ts,
            "gsi_member_pk": _member_index_pk(owner_sub),
            "gsi_member_sk": _member_index_sk(space_id),
        })
        return self.get_space(space_id) or {}

    def add_space_member(self, *, space_id: str, member_sub: str, role: str) -> dict[str, Any] | None:
        space = self.get_space(space_id)
        if not space:
            return None
        ts = now_ts()
        self._table.put_item(Item={
            "pk": _space_pk(space_id),
            "sk": _space_member_sk(member_sub),
            "entity_type": "space_membership",
            "space_id": space_id,
            "member_sub": member_sub,
            "role": role,
            "created_at": ts,
            "updated_at": ts,
            "gsi_member_pk": _member_index_pk(member_sub),
            "gsi_member_sk": _member_index_sk(space_id),
        })
        return self.get_space(space_id)

    def remove_space_member(self, *, space_id: str, member_sub: str) -> dict[str, Any] | None:
        space = self.get_space(space_id)
        if not space:
            return None
        if member_sub == space.get("owner_sub"):
            return space
        self._table.delete_item(Key={"pk": _space_pk(space_id), "sk": _space_member_sk(member_sub)})
        return self.get_space(space_id)

    def get_space(self, space_id: str) -> dict[str, Any] | None:
        meta = self._table.get_item(Key=_space_meta_key(space_id)).get("Item")
        if not meta:
            return None
        members = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={":pk": _space_pk(space_id), ":sk_prefix": "MEMBER#"},
            ScanIndexForward=True,
        ).get("Items", [])
        return {
            "space_id": meta.get("space_id", space_id),
            "owner_sub": meta.get("owner_sub", ""),
            "name": meta.get("name", ""),
            "visibility": meta.get("visibility", "private"),
            "created_at": int(meta.get("created_at", 0) or 0),
            "updated_at": int(meta.get("updated_at", 0) or 0),
            "members": [
                {
                    "space_id": item.get("space_id", space_id),
                    "member_sub": item.get("member_sub", ""),
                    "role": item.get("role", "viewer"),
                    "created_at": int(item.get("created_at", 0) or 0),
                    "updated_at": int(item.get("updated_at", 0) or 0),
                }
                for item in members
            ],
        }

    def list_spaces_for_member(self, *, member_sub: str, limit: int = 25, cursor: str | None = None) -> dict[str, Any]:
        headers, next_cursor = self._query_headers_by_index(
            index_name=S.tickets_member_spaces_index_name,
            pk=_member_index_pk(member_sub),
            key_expr="gsi_member_pk = :pk",
            limit=max(1, min(int(limit or 25), 100)),
            cursor=cursor,
        )
        spaces: list[dict[str, Any]] = []
        for row in headers:
            space_id = row.get("space_id")
            if not space_id:
                continue
            space = self.get_space(space_id)
            if space:
                spaces.append(space)
        return {"spaces": spaces, "next_cursor": next_cursor}

    def create_ticket(
        self,
        *,
        owner_sub: str,
        subject: str,
        description: str,
        space_id: str | None = None,
        ticket_id: str | None = None,
        category: str | None = None,
        metadata: dict[str, Any] | None = None,
        labels: list[str] | None = None,
        estimated_effort_hours: int | None = None,
    ) -> dict[str, Any]:
        ts = now_ts()
        resolved_ticket_id = ticket_id or f"tkt_{uuid.uuid4().hex[:12]}"
        existing = self.get_ticket(resolved_ticket_id)
        if existing:
            return existing
        message_id = f"msg_{uuid.uuid4().hex[:12]}"
        activity_id = f"act_{uuid.uuid4().hex[:12]}"

        norm_labels = sorted({str(l).strip() for l in (labels or []) if str(l).strip()})
        complexity = _complexity_from_labels(norm_labels)

        header = {
            "pk": _ticket_pk(resolved_ticket_id),
            "sk": "META",
            "entity_type": "ticket_meta",
            "ticket_id": resolved_ticket_id,
            "subject": subject,
            "owner_sub": owner_sub,
            "category": category,
            "metadata": metadata or {},
            "labels": norm_labels,
            "complexity": complexity,
            "estimated_effort_hours": estimated_effort_hours,
            "status": "open",
            "space_id": space_id,
            "assigned_admin_sub": None,
            "assigned_to_sub": None,
            "assigned_by": None,
            "assigned_at": None,
            "created_at": ts,
            "updated_at": ts,
            "last_message_at": ts,
            "last_message_by_role": "user",
            "version": 1,
            "gsi1pk": _owner_index_pk(owner_sub),
            "gsi1sk": _updated_index_sk(ts, resolved_ticket_id),
            "gsi2pk": _status_index_pk("open"),
            "gsi2sk": _updated_index_sk(ts, resolved_ticket_id),
            "gsi3pk": _assignee_index_pk("unassigned"),
            "gsi3sk": _updated_index_sk(ts, resolved_ticket_id),
            "gsi_space_pk": _space_index_pk(space_id) if space_id else None,
            "gsi_space_sk": _updated_index_sk(ts, resolved_ticket_id) if space_id else None,
            "gsi_space_status_pk": _space_status_index_pk(space_id, "open") if space_id else None,
            "gsi_space_status_sk": _updated_index_sk(ts, resolved_ticket_id) if space_id else None,
            "gsi_space_assignee_pk": _space_assignee_index_pk(space_id, "unassigned") if space_id else None,
            "gsi_space_assignee_sk": _updated_index_sk(ts, resolved_ticket_id) if space_id else None,
        }
        self._table.put_item(Item={k: v for k, v in header.items() if v is not None})
        # AGENT-008: fan-out one label index row per label for agent eligibility queries.
        for label in norm_labels:
            self._table.put_item(Item={
                "pk": label_index_pk(label),
                "sk": _label_index_sk(ts, resolved_ticket_id),
                "entity_type": "ticket_label_index",
                "ticket_id": resolved_ticket_id,
                "label": label,
                "space_id": space_id,
                "subject": subject,
                "complexity": complexity,
                "created_at": ts,
            })
        self._table.put_item(Item={
            "pk": _ticket_pk(resolved_ticket_id),
            "sk": _msg_sk(ts, message_id),
            "entity_type": "ticket_message",
            "ticket_id": resolved_ticket_id,
            "message_id": message_id,
            "sender_sub": owner_sub,
            "sender_role": "user",
            "body": description,
            "created_at": ts,
            "email_alert_queued_for": [],
        })
        self._table.put_item(Item={
            "pk": _ticket_pk(resolved_ticket_id),
            "sk": _act_sk(ts, activity_id),
            "entity_type": "ticket_activity",
            "ticket_id": resolved_ticket_id,
            "activity_id": activity_id,
            "activity_type": "ticket_opened",
            "actor_sub": owner_sub,
            "created_at": ts,
        })
        return self.get_ticket(resolved_ticket_id) or {}

    def _query_partition_prefix(self, *, ticket_id: str, sk_prefix: str) -> list[dict[str, Any]]:
        resp = self._table.query(
            KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
            ExpressionAttributeValues={":pk": _ticket_pk(ticket_id), ":sk_prefix": sk_prefix},
            ScanIndexForward=True,
        )
        return resp.get("Items", [])

    def get_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        header = self._table.get_item(Key=_meta_item_key(ticket_id)).get("Item")
        if not header:
            return None
        messages = self._query_partition_prefix(ticket_id=ticket_id, sk_prefix="MSG#")
        activities = self._query_partition_prefix(ticket_id=ticket_id, sk_prefix="ACT#")
        return {
            "ticket_id": header["ticket_id"],
            "subject": header.get("subject", ""),
            "owner_sub": header.get("owner_sub", ""),
            "category": header.get("category"),
            "metadata": header.get("metadata", {}),
            "labels": list(header.get("labels", []) or []),
            "complexity": header.get("complexity"),
            "estimated_effort_hours": (
                int(header["estimated_effort_hours"])
                if header.get("estimated_effort_hours") is not None
                else None
            ),
            "status": header.get("status", "open"),
            "space_id": header.get("space_id"),
            "assigned_admin_sub": header.get("assigned_admin_sub"),
            "assigned_to_sub": header.get("assigned_to_sub"),
            "assigned_by": header.get("assigned_by"),
            "assigned_at": header.get("assigned_at"),
            "created_at": int(header.get("created_at", 0) or 0),
            "updated_at": int(header.get("updated_at", 0) or 0),
            "version": int(header.get("version", 0) or 0),
            "messages": [{
                "message_id": item.get("message_id", ""),
                "sender_sub": item.get("sender_sub", ""),
                "sender_role": item.get("sender_role", "user"),
                "body": item.get("body", ""),
                "created_at": int(item.get("created_at", 0) or 0),
                "email_alert_queued_for": item.get("email_alert_queued_for", []),
            } for item in messages],
            "activity": [{
                "type": item.get("activity_type", ""),
                "actor_sub": item.get("actor_sub", ""),
                "assignee_sub": item.get("assignee_sub"),
                "status": item.get("status"),
                "created_at": int(item.get("created_at", 0) or 0),
            } for item in activities],
        }

    def _encode_cursor(self, token: dict[str, Any]) -> str:
        raw = json.dumps(token, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8")

    def _decode_cursor(self, cursor: str | None) -> dict[str, Any] | None:
        if not cursor:
            return None
        try:
            raw = base64.urlsafe_b64decode(cursor.encode("utf-8")).decode("utf-8")
            value = json.loads(raw)
            if isinstance(value, dict):
                return value
        except Exception:
            return None
        return None

    def _query_headers_by_index(self, *, index_name: str, pk: str, key_expr: str, limit: int, cursor: str | None) -> tuple[list[dict[str, Any]], str | None]:
        params: dict[str, Any] = {
            "IndexName": index_name,
            "KeyConditionExpression": key_expr,
            "ExpressionAttributeValues": {":pk": pk},
            "ScanIndexForward": False,
            "Limit": limit,
        }
        decoded = self._decode_cursor(cursor)
        if decoded and decoded.get("index") == index_name and decoded.get("pk") == pk and isinstance(decoded.get("lek"), dict):
            params["ExclusiveStartKey"] = decoded["lek"]
        resp = self._table.query(**params)
        items = resp.get("Items", [])
        next_cursor = None
        lek = resp.get("LastEvaluatedKey")
        if lek:
            next_cursor = self._encode_cursor({"index": index_name, "pk": pk, "lek": lek})
        return items, next_cursor

    def _assemble_headers(self, headers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for row in headers:
            ticket_id = row.get("ticket_id")
            if not ticket_id:
                continue
            assembled = self.get_ticket(ticket_id)
            if assembled:
                out.append(assembled)
        return out

    def list_tickets(self, *, limit: int = 25, cursor: str | None = None, status: str | None = None, assignee_sub: str | None = None, owner_sub: str | None = None) -> dict[str, Any]:
        page_limit = max(1, min(int(limit or 25), 100))

        if owner_sub:
            headers, next_cursor = self._query_headers_by_index(
                index_name=S.tickets_owner_index_name,
                pk=_owner_index_pk(owner_sub),
                key_expr="gsi1pk = :pk",
                limit=page_limit,
                cursor=cursor,
            )
            return {"tickets": self._assemble_headers(headers), "next_cursor": next_cursor}

        if assignee_sub:
            headers, next_cursor = self._query_headers_by_index(
                index_name=S.tickets_assignee_index_name,
                pk=_assignee_index_pk(assignee_sub),
                key_expr="gsi3pk = :pk",
                limit=page_limit,
                cursor=cursor,
            )
            return {"tickets": self._assemble_headers(headers), "next_cursor": next_cursor}

        status_filter = status or "open"
        headers, next_cursor = self._query_headers_by_index(
            index_name=S.tickets_status_index_name,
            pk=_status_index_pk(status_filter),
            key_expr="gsi2pk = :pk",
            limit=page_limit,
            cursor=cursor,
        )
        return {"tickets": self._assemble_headers(headers), "next_cursor": next_cursor}

    def list_space_tickets(self, *, space_id: str, limit: int = 25, cursor: str | None = None, status: str | None = None, assigned_to_sub: str | None = None) -> dict[str, Any]:
        page_limit = max(1, min(int(limit or 25), 100))
        if assigned_to_sub:
            headers, next_cursor = self._query_headers_by_index(
                index_name=S.tickets_space_assignee_index_name,
                pk=_space_assignee_index_pk(space_id, assigned_to_sub),
                key_expr="gsi_space_assignee_pk = :pk",
                limit=page_limit,
                cursor=cursor,
            )
            return {"tickets": self._assemble_headers(headers), "next_cursor": next_cursor}
        if status:
            headers, next_cursor = self._query_headers_by_index(
                index_name=S.tickets_space_status_index_name,
                pk=_space_status_index_pk(space_id, status),
                key_expr="gsi_space_status_pk = :pk",
                limit=page_limit,
                cursor=cursor,
            )
            return {"tickets": self._assemble_headers(headers), "next_cursor": next_cursor}
        headers, next_cursor = self._query_headers_by_index(
            index_name=S.tickets_space_index_name,
            pk=_space_index_pk(space_id),
            key_expr="gsi_space_pk = :pk",
            limit=page_limit,
            cursor=cursor,
        )
        return {"tickets": self._assemble_headers(headers), "next_cursor": next_cursor}


    def _query_all_headers_by_index(self, *, index_name: str, pk: str, key_expr: str, limit: int = 100) -> list[dict[str, Any]]:
        all_items: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            items, next_cursor = self._query_headers_by_index(
                index_name=index_name,
                pk=pk,
                key_expr=key_expr,
                limit=limit,
                cursor=cursor,
            )
            all_items.extend(items)
            if not next_cursor:
                break
            cursor = next_cursor
        return all_items

    def get_admin_summary(self, *, stale_after_seconds: int = 48 * 3600) -> dict[str, Any]:
        status_counts: dict[str, int] = {}
        stale_count = 0
        stale_cutoff = now_ts() - max(1, int(stale_after_seconds))

        for status in _TICKET_STATUSES:
            headers = self._query_all_headers_by_index(
                index_name=S.tickets_status_index_name,
                pk=_status_index_pk(status),
                key_expr="gsi2pk = :pk",
            )
            status_counts[status] = len(headers)
            if status in {"open", "in_progress", "waiting_on_user"}:
                stale_count += sum(1 for item in headers if int(item.get("updated_at", 0) or 0) < stale_cutoff)

        unassigned = self._query_all_headers_by_index(
            index_name=S.tickets_assignee_index_name,
            pk=_assignee_index_pk("unassigned"),
            key_expr="gsi3pk = :pk",
        )
        total_count = sum(status_counts.values())
        return {
            "by_status": status_counts,
            "unassigned_count": len(unassigned),
            "stale_count": stale_count,
            "stale_after_seconds": max(1, int(stale_after_seconds)),
            "total_count": total_count,
        }

    def _conditional_update_meta(self, *, ticket_id: str, expected_version: int, values: dict[str, Any]) -> bool:
        names = {
            "#status": "status",
            "#assigned_admin_sub": "assigned_admin_sub",
            "#assigned_to_sub": "assigned_to_sub",
            "#updated_at": "updated_at",
            "#assigned_by": "assigned_by",
            "#assigned_at": "assigned_at",
            "#last_message_at": "last_message_at",
            "#last_message_by_role": "last_message_by_role",
            "#version": "version",
            "#gsi2pk": "gsi2pk",
            "#gsi2sk": "gsi2sk",
            "#gsi3pk": "gsi3pk",
            "#gsi3sk": "gsi3sk",
            "#gsi1sk": "gsi1sk",
            "#gsi_space_pk": "gsi_space_pk",
            "#gsi_space_sk": "gsi_space_sk",
            "#gsi_space_status_pk": "gsi_space_status_pk",
            "#gsi_space_status_sk": "gsi_space_status_sk",
            "#gsi_space_assignee_pk": "gsi_space_assignee_pk",
            "#gsi_space_assignee_sk": "gsi_space_assignee_sk",
        }
        all_values = {":expected_version": expected_version, ":next_version": expected_version + 1, **values}
        # Core attributes always SET (may be None for non-assigned tickets — DynamoDB NULL is valid for non-key attrs)
        set_parts = [
            "#status = :status", "#assigned_admin_sub = :assigned_admin_sub", "#assigned_to_sub = :assigned_to_sub",
            "#assigned_by = :assigned_by", "#assigned_at = :assigned_at", "#updated_at = :updated_at",
            "#last_message_at = :last_message_at", "#last_message_by_role = :last_message_by_role",
            "#version = :next_version", "#gsi2pk = :gsi2pk", "#gsi2sk = :gsi2sk",
            "#gsi3pk = :gsi3pk", "#gsi3sk = :gsi3sk", "#gsi1sk = :gsi1sk",
        ]
        # Space GSI key attributes: SET if non-None (space ticket), REMOVE if None (non-space ticket).
        # DynamoDB does not allow NULL values for GSI hash/range keys.
        _space_gsi = [
            ("#gsi_space_pk", ":gsi_space_pk"),
            ("#gsi_space_sk", ":gsi_space_sk"),
            ("#gsi_space_status_pk", ":gsi_space_status_pk"),
            ("#gsi_space_status_sk", ":gsi_space_status_sk"),
            ("#gsi_space_assignee_pk", ":gsi_space_assignee_pk"),
            ("#gsi_space_assignee_sk", ":gsi_space_assignee_sk"),
        ]
        remove_parts = []
        space_gsi_placeholders: set[str] = set()
        for alias, placeholder in _space_gsi:
            if all_values.get(placeholder) is not None:
                set_parts.append(f"{alias} = {placeholder}")
            else:
                remove_parts.append(alias)
                space_gsi_placeholders.add(placeholder)
        update_expr = f"SET {', '.join(set_parts)}"
        if remove_parts:
            update_expr += f" REMOVE {', '.join(remove_parts)}"
        # Only omit None values for space GSI keys (those use REMOVE, not SET)
        expr_values = {k: v for k, v in all_values.items() if k not in space_gsi_placeholders}
        try:
            self._table.update_item(
                Key=_meta_item_key(ticket_id),
                UpdateExpression=update_expr,
                ConditionExpression="#version = :expected_version",
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=expr_values,
            )
            return True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise

    def _apply_header_update_once(self, *, ticket_id: str, build_values) -> dict[str, Any] | None:
        cur = self.get_ticket(ticket_id)
        if not cur:
            return None
        expected_version = int(cur.get("version", 1))
        values = build_values(cur)
        ok = self._conditional_update_meta(ticket_id=ticket_id, expected_version=expected_version, values=values)
        if not ok:
            raise TicketStateError({
                "code": "ticket_update_conflict",
                "ticket_id": ticket_id,
                "expected_version": expected_version,
            })
        return self.get_ticket(ticket_id)

    def assign_ticket(self, *, ticket_id: str, actor_sub: str, assignee_sub: str) -> dict[str, Any] | None:
        ts = now_ts()

        def _values(cur: dict[str, Any]) -> dict[str, Any]:
            status = cur.get("status", "open")
            space_id = cur.get("space_id")
            return {
                ":status": status,
                ":assigned_admin_sub": assignee_sub,
                ":assigned_to_sub": assignee_sub,
                ":assigned_by": actor_sub,
                ":assigned_at": ts,
                ":updated_at": ts,
                ":last_message_at": cur.get("updated_at", ts),
                ":last_message_by_role": cur.get("messages", [{}])[-1].get("sender_role", "user") if cur.get("messages") else "user",
                ":gsi2pk": _status_index_pk(status),
                ":gsi2sk": _updated_index_sk(ts, ticket_id),
                ":gsi3pk": _assignee_index_pk(assignee_sub),
                ":gsi3sk": _updated_index_sk(ts, ticket_id),
                ":gsi1sk": _updated_index_sk(ts, ticket_id),
                ":gsi_space_pk": _space_index_pk(space_id) if space_id else None,
                ":gsi_space_sk": _updated_index_sk(ts, ticket_id) if space_id else None,
                ":gsi_space_status_pk": _space_status_index_pk(space_id, status) if space_id else None,
                ":gsi_space_status_sk": _updated_index_sk(ts, ticket_id) if space_id else None,
                ":gsi_space_assignee_pk": _space_assignee_index_pk(space_id, assignee_sub) if space_id else None,
                ":gsi_space_assignee_sk": _updated_index_sk(ts, ticket_id) if space_id else None,
            }

        updated = self._apply_header_update_once(ticket_id=ticket_id, build_values=_values)
        if not updated:
            return None
        self._table.put_item(Item={
            "pk": _ticket_pk(ticket_id),
            "sk": _act_sk(ts, f"act_{uuid.uuid4().hex[:12]}"),
            "entity_type": "ticket_activity",
            "ticket_id": ticket_id,
            "activity_id": f"act_{uuid.uuid4().hex[:12]}",
            "activity_type": "ticket_assigned",
            "actor_sub": actor_sub,
            "assignee_sub": assignee_sub,
            "created_at": ts,
        })
        return self.get_ticket(ticket_id)

    def add_message(self, *, ticket_id: str, sender_sub: str, sender_role: str, body: str, email_targets: list[str]) -> dict[str, Any] | None:
        ts = now_ts()
        cur = self.get_ticket(ticket_id)
        if not cur:
            return None
        next_status = _next_status_for_message(sender_role=sender_role, current_status=cur.get("status", "open"))
        message_id = f"msg_{uuid.uuid4().hex[:12]}"
        self._table.put_item(Item={
            "pk": _ticket_pk(ticket_id),
            "sk": _msg_sk(ts, message_id),
            "entity_type": "ticket_message",
            "ticket_id": ticket_id,
            "message_id": message_id,
            "sender_sub": sender_sub,
            "sender_role": sender_role,
            "body": body,
            "created_at": ts,
            "email_alert_queued_for": email_targets,
        })
        activity_type = "ticket_reopened" if cur.get("status") == "done" and next_status == "open" else "ticket_message"
        self._table.put_item(Item={
            "pk": _ticket_pk(ticket_id),
            "sk": _act_sk(ts, f"act_{uuid.uuid4().hex[:12]}"),
            "entity_type": "ticket_activity",
            "ticket_id": ticket_id,
            "activity_id": f"act_{uuid.uuid4().hex[:12]}",
            "activity_type": activity_type,
            "actor_sub": sender_sub,
            "status": next_status,
            "created_at": ts,
        })

        def _values(_cur: dict[str, Any]) -> dict[str, Any]:
            assigned = _cur.get("assigned_admin_sub")
            space_id = _cur.get("space_id")
            return {
                ":status": next_status,
                ":assigned_admin_sub": assigned,
                ":assigned_to_sub": _cur.get("assigned_to_sub"),
                ":assigned_by": _cur.get("assigned_by"),
                ":assigned_at": _cur.get("assigned_at"),
                ":updated_at": ts,
                ":last_message_at": ts,
                ":last_message_by_role": sender_role,
                ":gsi2pk": _status_index_pk(next_status),
                ":gsi2sk": _updated_index_sk(ts, ticket_id),
                ":gsi3pk": _assignee_index_pk(assigned or "unassigned"),
                ":gsi3sk": _updated_index_sk(ts, ticket_id),
                ":gsi1sk": _updated_index_sk(ts, ticket_id),
                ":gsi_space_pk": _space_index_pk(space_id) if space_id else None,
                ":gsi_space_sk": _updated_index_sk(ts, ticket_id) if space_id else None,
                ":gsi_space_status_pk": _space_status_index_pk(space_id, next_status) if space_id else None,
                ":gsi_space_status_sk": _updated_index_sk(ts, ticket_id) if space_id else None,
                ":gsi_space_assignee_pk": _space_assignee_index_pk(space_id, _cur.get("assigned_to_sub") or "unassigned") if space_id else None,
                ":gsi_space_assignee_sk": _updated_index_sk(ts, ticket_id) if space_id else None,
            }

        updated = self._apply_header_update_once(ticket_id=ticket_id, build_values=_values)
        if not updated:
            return None
        return self.get_ticket(ticket_id)

    def update_status(self, *, ticket_id: str, actor_sub: str, status: str) -> dict[str, Any] | None:
        requested_status = _coerce_status(status)
        if requested_status not in _TICKET_STATUSES:
            raise TicketStateError({
                "code": "invalid_ticket_status",
                "requested_status": status,
                "allowed_statuses": list(_TICKET_STATUSES),
            })

        ts = now_ts()
        cur = self.get_ticket(ticket_id)
        if not cur:
            return None
        current_status = cur.get("status", "open")
        allowed_next = _STATUS_TRANSITIONS.get(current_status, ())
        if requested_status not in allowed_next and requested_status != current_status:
            raise TicketStateError({
                "code": "invalid_ticket_status_transition",
                "ticket_id": ticket_id,
                "current_status": current_status,
                "requested_status": requested_status,
                "allowed_next_statuses": list(allowed_next),
            })

        def _values(_cur: dict[str, Any]) -> dict[str, Any]:
            assigned = _cur.get("assigned_admin_sub")
            space_id = _cur.get("space_id")
            return {
                ":status": requested_status,
                ":assigned_admin_sub": assigned,
                ":assigned_to_sub": _cur.get("assigned_to_sub"),
                ":assigned_by": _cur.get("assigned_by"),
                ":assigned_at": _cur.get("assigned_at"),
                ":updated_at": ts,
                ":last_message_at": _cur.get("updated_at", ts),
                ":last_message_by_role": _cur.get("messages", [{}])[-1].get("sender_role", "user") if _cur.get("messages") else "user",
                ":gsi2pk": _status_index_pk(requested_status),
                ":gsi2sk": _updated_index_sk(ts, ticket_id),
                ":gsi3pk": _assignee_index_pk(assigned or "unassigned"),
                ":gsi3sk": _updated_index_sk(ts, ticket_id),
                ":gsi1sk": _updated_index_sk(ts, ticket_id),
                ":gsi_space_pk": _space_index_pk(space_id) if space_id else None,
                ":gsi_space_sk": _updated_index_sk(ts, ticket_id) if space_id else None,
                ":gsi_space_status_pk": _space_status_index_pk(space_id, requested_status) if space_id else None,
                ":gsi_space_status_sk": _updated_index_sk(ts, ticket_id) if space_id else None,
                ":gsi_space_assignee_pk": _space_assignee_index_pk(space_id, _cur.get("assigned_to_sub") or "unassigned") if space_id else None,
                ":gsi_space_assignee_sk": _updated_index_sk(ts, ticket_id) if space_id else None,
            }

        updated = self._apply_header_update_once(ticket_id=ticket_id, build_values=_values)
        if not updated:
            return None
        self._table.put_item(Item={
            "pk": _ticket_pk(ticket_id),
            "sk": _act_sk(ts, f"act_{uuid.uuid4().hex[:12]}"),
            "entity_type": "ticket_activity",
            "ticket_id": ticket_id,
            "activity_id": f"act_{uuid.uuid4().hex[:12]}",
            "activity_type": "ticket_status_changed",
            "actor_sub": actor_sub,
            "status": requested_status,
            "created_at": ts,
        })
        return self.get_ticket(ticket_id)


STORE = TicketStore()
