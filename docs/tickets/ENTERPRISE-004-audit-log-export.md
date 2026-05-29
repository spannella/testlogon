# ENTERPRISE-004: Audit Log Export System

**Ticket**: ENTERPRISE-004
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform generates audit events across multiple subsystems -- login events, admin actions, moderation decisions, broadcast operations, billing transactions, and file operations. These events are stored in DynamoDB tables scattered across the codebase (`T.alerts`, `T.role_audit`, `T.moderation_audit_log`, `T.broadcast_action_audit`), each with its own schema and query pattern. Enterprise customers need to export these audit events in a unified format for:

- **Compliance audits** (SOC 2 Type II, ISO 27001): External auditors require a complete, tamper-evident log of all administrative actions.
- **GDPR data access requests**: Users can request all actions taken on their data.
- **Forensic investigation**: Security teams need to reconstruct timelines of suspicious activity.
- **Regulatory reporting**: Financial services customers must produce periodic reports of billing events.

Today there is no unified audit export. The existing CSV export endpoint (`/ui/export/csv` in `app/routers/csv_export.py`) supports only `billing_ledger`, `contacts`, and `questionnaire_responses` (line 19):
<!-- VERIFIED: app/routers/csv_export.py:19 — VALID_SOURCES = {"billing_ledger", "contacts", "questionnaire_responses"} -->

```python
# app/routers/csv_export.py, line 19
VALID_SOURCES = {"billing_ledger", "contacts", "questionnaire_responses"}
```

Audit events are not exportable. There is no JSON export format, no date range filtering on audit data, no async export for large datasets, and no scheduled recurring export capability.

### 1.2 How It Works

1. An admin navigates to the Audit Log Export page and selects filters: date range, event categories (auth, moderation, billing, files), actor, target user.
2. For small exports (<10,000 events), the system streams the result as CSV or JSON directly.
3. For large exports (>10,000 events), the system creates an async export job that scans DynamoDB, writes the result to S3, and provides a time-limited presigned download URL.
4. Admins can configure scheduled recurring exports (e.g., weekly SOC 2 audit dump) that run automatically and deposit files in S3 or send a download link via email.
5. All export files include a SHA-256 integrity hash and a signed manifest for tamper detection.

### 1.3 Design Principles

- **Unified schema**: All audit events from all subsystems are normalized to a common envelope format with `event_type`, `actor`, `target`, `timestamp`, `metadata`.
- **Compliance-ready**: Exports include tamper-evident hashes, event counts, and schema version markers that satisfy SOC 2 evidence requirements.
- **Non-blocking**: Large exports run asynchronously. The UI shows progress and notifies on completion.
- **Access controlled**: Only ROOT and ADMIN (with appropriate scope) can export audit logs. All export operations are themselves audited.

### 1.4 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Root admin | As a root admin, I want to export all auth events from the last 30 days as CSV. | POST export with category=auth, format=csv, date range; CSV downloads with all matching events. |
| Root admin | As a root admin, I want to export moderation actions for a specific user. | POST export with target_user_sub filter; only events involving that user are included. |
| Compliance officer | As a compliance officer, I want a weekly automated SOC 2 audit export. | Scheduled export runs every Monday at 2 AM; result deposited in S3; email notification sent. |
| Root admin | As a root admin, I want to verify an export file has not been tampered with. | Export manifest includes SHA-256 hash; verification endpoint confirms integrity. |
| Root admin | As a root admin, I want to see a list of past exports with download links. | GET exports returns paginated list with status, size, download URL, expiry. |
| Auditor | As an external auditor, I want to import the export into my audit tool. | JSON export uses a well-defined schema with ISO 8601 timestamps and structured metadata. |

---

## 2. Current State Analysis

### 2.1 Audit Event Sources

The platform has multiple audit event sources, each with its own storage and schema:

#### 2.1.1 General Audit Events (`app/services/alerts.py`)

The `audit_event()` function (line 695) is the primary audit recording mechanism:
<!-- CORRECTED: audit_event is at line 695, not 570 -->

```python
# app/services/alerts.py, lines 695-696
def audit_event(event: str, user_sub: str, request=None, **fields: Any) -> None:
    payload: Dict[str, Any] = {"event": event, "user_sub": user_sub, "ts": now_ts(), **fields}
```

This records events to the `T.alerts` table. Events include `ui_session_start`, `ui_session_finalize`, `mfa_email_verify`, `mfa_sms_verify`, `role_grant`, `role_revoke`, `impersonation_start`, `impersonation_stop`, and many more. The function enriches events with IP address, user agent, and profile identity (lines 703-705):
<!-- CORRECTED: IP/user_agent enrichment is at lines 703-705, not 578-580 -->

```python
# app/services/alerts.py, lines 703-705
if request is not None:
    payload["ip"] = client_ip_from_request(request)
    payload["user_agent"] = (request.headers.get("user-agent", "")[:256])
```

And impersonation context (lines 706-712):
<!-- CORRECTED: impersonation context extraction is at lines 706-712, not 581-593 -->

```python
actor_sub = getattr(state, "actor_sub", "")
effective_sub = getattr(state, "effective_sub", "")
impersonation_id = getattr(state, "impersonation_id", "")
```

The alerts table item has these attributes:

| Attribute | Type | Description |
|-----------|------|-------------|
| `user_sub` | S (PK) | User who triggered the event |
| `alert_id` | S (SK) | Unique alert identifier (`alert_{uuid}`) |
| `event` | S | Event name (`ui_session_start`, `role_grant`, etc.) |
| `ts` | N | Unix timestamp (seconds) |
| `outcome` | S | `success`, `failure`, `info`, `warning` |
| `ip` | S | Client IP address |
| `user_agent` | S | Browser user agent (first 256 chars) |
| `actor_sub` | S | Impersonating admin (if impersonation active) |
| `effective_sub` | S | Impersonated user (if impersonation active) |
| `impersonation_id` | S | Impersonation session ID |
| `profile_display_name` | S | Actor's display name at time of event |
| `profile_email` | S | Actor's email at time of event |
| `details` | M | Event-specific metadata map |

#### 2.1.2 Moderation Audit Log (`app/services/moderation_audit_log.py`)

The `write_moderation_audit_event()` function (line 10) writes to `T.moderation_audit_log`:
<!-- VERIFIED: app/services/moderation_audit_log.py:10-41 — write_moderation_audit_event, full function -->

```python
# app/services/moderation_audit_log.py, lines 10-41
def write_moderation_audit_event(
    *,
    action: str,
    actor_user_id: str,
    ticket_id: str = "",
    report_id: str = "",
    content_type: str = "",
    content_id: str = "",
    target_user_id: str = "",
    metadata: dict[str, Any] | None = None,
) -> str:
    now = str(int(time.time()))
    audit_id = f"modaudit_{uuid.uuid4().hex[:24]}"
    item: dict[str, Any] = {
        "audit_id": audit_id,
        "entity_type": "moderation_audit_event",
        "action": action,
        "actor_user_id": actor_user_id,
        ...
    }
    T.moderation_audit_log.put_item(Item=item)
```

Events include `approve_ticket`, `reject_content`, `ban_user`, `issue_warning`, `take_down_content`, etc.

The moderation audit log table item:

| Attribute | Type | Description |
|-----------|------|-------------|
| `audit_id` | S (PK) | `modaudit_{uuid_hex[:24]}` |
| `entity_type` | S | Always `"moderation_audit_event"` |
| `action` | S | `approve_ticket`, `reject_content`, `ban_user`, etc. |
| `actor_user_id` | S | Admin who performed the action |
| `ticket_id` | S | Related support ticket (GSI key, omitted when empty) |
| `report_id` | S | Related report ID (GSI key, omitted when empty) |
| `content_type` | S | `post`, `message`, `comment`, `file` |
| `content_id` | S | ID of affected content |
| `target_user_id` | S | User whose content was moderated |
| `created_at` | S | ISO 8601 timestamp string |
| `metadata` | M | Additional context (reason, notes, etc.) |

#### 2.1.3 Broadcast Audit (`app/services/broadcast_audit.py`)

The `record_broadcast_action()` function (line 45) writes to `T.broadcast_action_audit`:
<!-- VERIFIED: app/services/broadcast_audit.py:45 — record_broadcast_action -->

```python
# app/services/broadcast_audit.py, lines 45-65
def record_broadcast_action(
    *,
    action: str,
    actor: str,
    correlation_id: str,
    resource_type: str,
    resource_id: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> BroadcastActionAuditEventModel:
    event = BroadcastActionAuditEventModel(
        audit_id=str(uuid4()),
        action=action,
        actor=actor,
        ...
    )
    T.broadcast_action_audit.put_item(Item=audit_to_item(event))
```

The `query_broadcast_actions()` function (line 68) supports filtering by actor and date range using the `ByActorCreatedAt` GSI:
<!-- VERIFIED: app/services/broadcast_audit.py:68 — query_broadcast_actions -->

```python
# app/services/broadcast_audit.py, lines 68-92
def query_broadcast_actions(
    *,
    actor: Optional[str] = None,
    created_from: Optional[str] = None,
    created_to: Optional[str] = None,
    limit: int = 50,
) -> List[BroadcastActionAuditEventModel]:
    ...
    resp = T.broadcast_action_audit.query(
        IndexName="ByActorCreatedAt",
        KeyConditionExpression=key_expr,
        Limit=limit,
        ScanIndexForward=False,
    )
```

Broadcast audit table item:

| Attribute | Type | Description |
|-----------|------|-------------|
| `audit_id` | S (PK) | UUID string |
| `action` | S | `start_broadcast`, `stop_broadcast`, `schedule_broadcast`, etc. |
| `actor` | S | User who performed the action (GSI PK for `ByActorCreatedAt`) |
| `correlation_id` | S | Broadcast session or schedule ID |
| `resource_type` | S | `broadcast`, `recording`, `schedule` |
| `resource_id` | S | ID of affected resource |
| `created_at` | S | ISO 8601 timestamp (GSI SK for `ByActorCreatedAt`) |
| `metadata` | M | Action-specific metadata |
| `scope` | S | Always `"ALL"` (GSI PK for `ByCreatedAt` global index) |

#### 2.1.4 Admin Moderation Router Audit (`app/routers/admin_moderation.py`)

The admin moderation router calls `write_moderation_audit_event` from line 23:
<!-- VERIFIED: app/routers/admin_moderation.py:23 — import write_moderation_audit_event -->

```python
# app/routers/admin_moderation.py, line 23
from app.services.moderation_audit_log import write_moderation_audit_event
```

And uses it within ticket resolution, content removal, and ban operations to create a complete moderation audit trail.

#### 2.1.5 Role Audit (`app/core/tables.py`)

The role audit table (line 119):
<!-- CORRECTED: role_audit is at line 17 (class field) and line 141 (initialization), not 119 -->

```python
# app/core/tables.py, line 119
role_audit=ddb.Table(S.role_audit_table_name),
```

Stores admin role grant/revoke events with `user_sub`, `action`, `target_sub`, `new_role`, `actor_sub`, `timestamp`.

Role audit table item:

| Attribute | Type | Description |
|-----------|------|-------------|
| `audit_id` | S (PK) | UUID string |
| `user_sub` | S | Admin who performed the action |
| `action` | S | `role_grant`, `role_revoke`, `role_update` |
| `target_sub` | S | User whose role changed |
| `old_role` | S | Previous role (if applicable) |
| `new_role` | S | New role assigned |
| `actor_sub` | S | Same as `user_sub` (for consistency) |
| `timestamp` | N | Unix timestamp (seconds) |
| `admin_profile` | M | Admin profile snapshot at time of change |

#### 2.1.6 Billing Ledger (`app/services/billing_shared.py`)

Billing ledger entries in `T.billing` use `pk=USER#{user_sub}`, `sk=LEDGER#{ledger_id}`:

| Attribute | Type | Description |
|-----------|------|-------------|
| `pk` | S (PK) | `USER#{user_sub}` |
| `sk` | S (SK) | `LEDGER#{ledger_id}` |
| `ledger_id` | S | UUID string |
| `type` | S | `debit`, `credit` |
| `amount_cents` | N | Transaction amount in cents |
| `reason` | S | `Tip sent`, `Unlock purchase`, `Subscription payment`, etc. |
| `target_user` | S | Counterparty user ID |
| `resource_type` | S | `message`, `post`, `subscription` |
| `resource_id` | S | ID of related resource |
| `payment_method_id` | S | Payment method used |
| `created_at` | N | Unix timestamp |

### 2.2 Existing CSV Export (`app/routers/csv_export.py`)

The current export system (lines 1-80) uses streaming CSV for small datasets:
<!-- VERIFIED: app/routers/csv_export.py:22 — @router.get("/export/csv") (router prefix="/ui") -->

```python
# app/routers/csv_export.py, lines 22-46
@router.get("/export/csv")
async def export_csv(
    source: str = Query(..., pattern=r"^(billing_ledger|contacts|questionnaire_responses)$"),
    from_date: Optional[int] = Query(None, ge=0),
    to_date: Optional[int] = Query(None, ge=0),
    ...
    ctx=Depends(require_ui_session),
):
```
<!-- CORRECTED: was "lines 22-44", actually lines 22-46; route path is "/export/csv" not "/ui/export/csv" (prefix adds /ui) -->

This endpoint returns a `StreamingResponse` with `Content-Type: text/csv`. It validates date ranges (lines 74-79):
<!-- VERIFIED: app/routers/csv_export.py:74-79 — date range validation -->

```python
# app/routers/csv_export.py, lines 75-79
if from_date is not None and to_date is not None and from_date > to_date:
    raise HTTPException(status_code=422, detail="from_date must be <= to_date")
```

The audit export system builds on this pattern but adds JSON format support, async processing, and the unified audit event schema.

### 2.3 DynamoDB Table References

| Table Handle | Settings Key | Audit Data |
|---|---|---|
| `T.alerts` | `alerts_table_name` (line 76) | Auth events, session events, general audit |
| `T.role_audit` | `role_audit_table_name` (line 43) | Admin role changes |
| `T.moderation_audit_log` | `moderation_audit_log_table_name` (line 563) | Moderation actions |
| `T.broadcast_action_audit` | `broadcast_action_audit_table_name` (line 459) | Broadcast operations |
| `T.billing` (LEDGER entries) | `billing_table_name` (line 321) | Financial transactions |
<!-- VERIFIED: settings.py lines — alerts:76, role_audit:43, broadcast_action_audit:459, billing:321 -->
<!-- CORRECTED: moderation_audit_log_table_name is at line 566 (previous "correction" to 563 was wrong) -->

---

## 3. Technical Design

### 3.1 Unified Audit Event Schema

All audit sources are normalized to a common envelope:

```python
# app/services/audit_export.py (new)

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class UnifiedAuditEvent:
    event_id: str                    # Unique event identifier
    event_type: str                  # Category: auth, moderation, broadcast, billing, file, admin
    event_action: str                # Specific action: login, ban_user, tip_sent, file_uploaded
    timestamp: str                   # ISO 8601 UTC (e.g., "2026-05-28T14:30:00Z")
    timestamp_unix: int              # Unix epoch seconds
    actor_user_id: str               # Who performed the action
    actor_role: str                  # Role at time of action
    actor_ip: Optional[str] = None   # IP address (if available)
    actor_user_agent: Optional[str] = None  # User agent (if available)
    target_user_id: Optional[str] = None    # Who was affected (if applicable)
    target_resource_type: Optional[str] = None  # conversation, file, post, ticket, etc.
    target_resource_id: Optional[str] = None    # ID of affected resource
    outcome: str = "success"         # success, failure, warning
    metadata: dict = field(default_factory=dict)  # Source-specific details
    source_table: str = ""           # DDB table this was read from (for traceability)
    tenant_id: str = ""              # Tenant context
    impersonation_context: Optional[dict] = None  # Actor/effective sub if impersonation

    def to_csv_row(self, columns: list[str]) -> list[str]:
        """Return values in column order, JSON-encoding complex fields."""
        row = []
        for col in columns:
            val = getattr(self, col, "")
            if isinstance(val, dict):
                row.append(json.dumps(val, default=str))
            elif val is None:
                row.append("")
            else:
                row.append(str(val))
        return row

    def to_ndjson_line(self) -> str:
        """Return a single JSON line for NDJSON format."""
        d = asdict(self)
        # Remove None values for compact output
        d = {k: v for k, v in d.items() if v is not None}
        return json.dumps(d, default=str)
```

### 3.2 Source Adapters

Each audit source has an adapter that reads from DynamoDB and produces `UnifiedAuditEvent` records. All adapters implement a common base class:

```python
# app/services/audit_adapters.py (new)

from __future__ import annotations

import abc
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterator, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.tables import T
from app.core.time import now_ts
from app.services.audit_export import UnifiedAuditEvent

logger = logging.getLogger(__name__)


class BaseAuditAdapter(abc.ABC):
    """Base class for audit source adapters."""

    source_table: str = ""
    event_type: str = ""

    @abc.abstractmethod
    def query(
        self,
        from_ts: int,
        to_ts: int,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        event_actions: Optional[list[str]] = None,
        limit: int = 1000,
    ) -> Iterator[UnifiedAuditEvent]:
        """Yield UnifiedAuditEvent records from the source table."""
        ...

    def _ts_to_iso(self, ts: int | float | str | Decimal) -> str:
        """Convert any timestamp representation to ISO 8601 UTC."""
        if isinstance(ts, str):
            # Could be ISO already or a string of digits
            if ts.replace(".", "").isdigit():
                ts = float(ts)
            else:
                return ts  # Already ISO
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")

    def _ts_to_unix(self, ts: int | float | str | Decimal) -> int:
        """Convert any timestamp to Unix seconds integer."""
        if isinstance(ts, (int, float, Decimal)):
            return int(ts)
        if isinstance(ts, str):
            if ts.replace(".", "").isdigit():
                return int(float(ts))
            # Parse ISO 8601
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return int(dt.timestamp())
        return 0

    def _paginate_query(self, table, **kwargs) -> Iterator[dict]:
        """Generic DynamoDB paginator that handles LastEvaluatedKey."""
        while True:
            resp = table.query(**kwargs)
            for item in resp.get("Items", []):
                yield item
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key

    def _paginate_scan(self, table, **kwargs) -> Iterator[dict]:
        """Generic DynamoDB scan paginator."""
        while True:
            resp = table.scan(**kwargs)
            for item in resp.get("Items", []):
                yield item
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key


class AlertsAdapter(BaseAuditAdapter):
    """Reads from T.alerts and produces UnifiedAuditEvent records.

    The alerts table uses pk=user_sub, sk=alert_id. There is no time-range
    GSI, so we must scan with a FilterExpression on the `ts` attribute.
    For actor-specific queries we can use the PK directly.
    """

    source_table = "alerts"
    event_type = "auth"

    # Map alert event names to unified action names
    _ACTION_MAP = {
        "ui_session_start": "session_start",
        "ui_session_finalize": "login",
        "mfa_email_verify": "mfa_verify_email",
        "mfa_sms_verify": "mfa_verify_sms",
        "mfa_totp_verify": "mfa_verify_totp",
        "mfa_recovery": "mfa_recovery_code_used",
        "api_key_create": "api_key_created",
        "api_key_revoke": "api_key_revoked",
        "ui_session_revoke": "session_revoked",
        "ui_session_revoke_others": "sessions_revoked_all",
        "totp_device_confirm": "totp_device_added",
        "totp_device_remove": "totp_device_removed",
        "device_new": "new_device_detected",
        "device_trust": "device_trusted",
        "device_revoke": "device_trust_revoked",
        "role_grant": "role_granted",
        "role_revoke": "role_revoked",
        "impersonation_start": "impersonation_started",
        "impersonation_stop": "impersonation_stopped",
    }

    def query(
        self,
        from_ts: int,
        to_ts: int,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        event_actions: Optional[list[str]] = None,
        limit: int = 1000,
    ) -> Iterator[UnifiedAuditEvent]:
        count = 0

        if actor:
            # Query by PK (user_sub) with filter on ts range
            filter_expr = Attr("ts").between(from_ts, to_ts)
            if event_actions:
                filter_expr = filter_expr & Attr("event").is_in(event_actions)

            for item in self._paginate_query(
                T.alerts,
                KeyConditionExpression=Key("user_sub").eq(actor),
                FilterExpression=filter_expr,
                ScanIndexForward=False,
            ):
                evt = self._item_to_event(item)
                if evt and (target is None or evt.target_user_id == target):
                    yield evt
                    count += 1
                    if count >= limit:
                        return
        else:
            # Full scan with filter -- expensive but necessary for cross-user queries
            filter_expr = Attr("ts").between(from_ts, to_ts)
            if event_actions:
                filter_expr = filter_expr & Attr("event").is_in(event_actions)
            if target:
                # Target could be in effective_sub or in the event fields
                filter_expr = filter_expr & (
                    Attr("effective_sub").eq(target)
                    | Attr("user_sub").eq(target)
                )

            for item in self._paginate_scan(
                T.alerts,
                FilterExpression=filter_expr,
            ):
                evt = self._item_to_event(item)
                if evt:
                    yield evt
                    count += 1
                    if count >= limit:
                        return

    def _item_to_event(self, item: dict) -> Optional[UnifiedAuditEvent]:
        """Convert an alerts table item to a UnifiedAuditEvent."""
        event_name = item.get("event", "")
        ts = item.get("ts", 0)

        # Build impersonation context if present
        impersonation_ctx = None
        if item.get("actor_sub") or item.get("impersonation_id"):
            impersonation_ctx = {
                "actor_sub": item.get("actor_sub", ""),
                "effective_sub": item.get("effective_sub", ""),
                "impersonation_id": item.get("impersonation_id", ""),
            }

        # Collect metadata from details and known fields
        metadata = {}
        details = item.get("details", {})
        if isinstance(details, dict):
            metadata.update(details)
        for key in ("event_source", "event_channel", "cli_event_name",
                     "profile_display_name", "profile_email"):
            if item.get(key):
                metadata[key] = item[key]

        return UnifiedAuditEvent(
            event_id=item.get("alert_id", f"alert_{uuid.uuid4().hex[:16]}"),
            event_type="auth",
            event_action=self._ACTION_MAP.get(event_name, event_name),
            timestamp=self._ts_to_iso(ts),
            timestamp_unix=self._ts_to_unix(ts),
            actor_user_id=item.get("user_sub", ""),
            actor_role=item.get("role", "user"),
            actor_ip=item.get("ip"),
            actor_user_agent=item.get("user_agent"),
            target_user_id=item.get("effective_sub") or None,
            outcome=item.get("outcome", "info"),
            metadata=metadata,
            source_table=self.source_table,
            impersonation_context=impersonation_ctx,
        )


class ModerationAuditAdapter(BaseAuditAdapter):
    """Reads from T.moderation_audit_log.

    The moderation audit log uses audit_id as PK with no SK. It stores
    created_at as a string timestamp. We scan with FilterExpression.
    """

    source_table = "moderation_audit_log"
    event_type = "moderation"

    def query(
        self,
        from_ts: int,
        to_ts: int,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        event_actions: Optional[list[str]] = None,
        limit: int = 1000,
    ) -> Iterator[UnifiedAuditEvent]:
        # created_at is stored as string timestamp in this table
        from_str = str(from_ts)
        to_str = str(to_ts)
        count = 0

        filter_expr = Attr("created_at").between(from_str, to_str)
        filter_expr = filter_expr & Attr("entity_type").eq("moderation_audit_event")
        if actor:
            filter_expr = filter_expr & Attr("actor_user_id").eq(actor)
        if target:
            filter_expr = filter_expr & Attr("target_user_id").eq(target)
        if event_actions:
            filter_expr = filter_expr & Attr("action").is_in(event_actions)

        for item in self._paginate_scan(
            T.moderation_audit_log,
            FilterExpression=filter_expr,
        ):
            evt = self._item_to_event(item)
            if evt:
                yield evt
                count += 1
                if count >= limit:
                    return

    def _item_to_event(self, item: dict) -> Optional[UnifiedAuditEvent]:
        ts_str = item.get("created_at", "0")
        ts_unix = self._ts_to_unix(ts_str)

        metadata = dict(item.get("metadata", {}) or {})
        if item.get("ticket_id"):
            metadata["ticket_id"] = item["ticket_id"]
        if item.get("report_id"):
            metadata["report_id"] = item["report_id"]

        return UnifiedAuditEvent(
            event_id=item.get("audit_id", ""),
            event_type="moderation",
            event_action=item.get("action", ""),
            timestamp=self._ts_to_iso(ts_str),
            timestamp_unix=ts_unix,
            actor_user_id=item.get("actor_user_id", ""),
            actor_role="admin",
            target_user_id=item.get("target_user_id") or None,
            target_resource_type=item.get("content_type") or None,
            target_resource_id=item.get("content_id") or None,
            outcome="success",
            metadata=metadata,
            source_table=self.source_table,
        )


class BroadcastAuditAdapter(BaseAuditAdapter):
    """Reads from T.broadcast_action_audit.

    Uses the ByCreatedAt GSI with scope="ALL" for time-range queries,
    or ByActorCreatedAt for actor-specific queries. created_at is ISO 8601.
    """

    source_table = "broadcast_action_audit"
    event_type = "broadcast"

    def query(
        self,
        from_ts: int,
        to_ts: int,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        event_actions: Optional[list[str]] = None,
        limit: int = 1000,
    ) -> Iterator[UnifiedAuditEvent]:
        from_iso = datetime.fromtimestamp(from_ts, tz=timezone.utc).isoformat()
        to_iso = datetime.fromtimestamp(to_ts, tz=timezone.utc).isoformat()
        count = 0

        if actor:
            key_expr = Key("actor").eq(actor) & Key("created_at").between(from_iso, to_iso)
            kwargs: dict[str, Any] = {
                "IndexName": "ByActorCreatedAt",
                "KeyConditionExpression": key_expr,
                "ScanIndexForward": False,
            }
        else:
            key_expr = Key("scope").eq("ALL") & Key("created_at").between(from_iso, to_iso)
            kwargs = {
                "IndexName": "ByCreatedAt",
                "KeyConditionExpression": key_expr,
                "ScanIndexForward": False,
            }

        if event_actions:
            kwargs["FilterExpression"] = Attr("action").is_in(event_actions)

        for item in self._paginate_query(T.broadcast_action_audit, **kwargs):
            evt = self._item_to_event(item)
            if evt:
                yield evt
                count += 1
                if count >= limit:
                    return

    def _item_to_event(self, item: dict) -> Optional[UnifiedAuditEvent]:
        created_at = item.get("created_at", "")
        ts_unix = self._ts_to_unix(created_at) if created_at else 0

        return UnifiedAuditEvent(
            event_id=item.get("audit_id", ""),
            event_type="broadcast",
            event_action=item.get("action", ""),
            timestamp=created_at,
            timestamp_unix=ts_unix,
            actor_user_id=item.get("actor", ""),
            actor_role="user",
            target_resource_type=item.get("resource_type") or None,
            target_resource_id=item.get("resource_id") or None,
            outcome="success",
            metadata=dict(item.get("metadata", {}) or {}),
            source_table=self.source_table,
        )


class RoleAuditAdapter(BaseAuditAdapter):
    """Reads from T.role_audit.

    The role audit table stores admin role changes. It uses audit_id as PK.
    timestamp is stored as a number (Unix seconds).
    """

    source_table = "role_audit"
    event_type = "admin"

    def query(
        self,
        from_ts: int,
        to_ts: int,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        event_actions: Optional[list[str]] = None,
        limit: int = 1000,
    ) -> Iterator[UnifiedAuditEvent]:
        count = 0
        filter_expr = Attr("timestamp").between(from_ts, to_ts)
        if actor:
            filter_expr = filter_expr & Attr("user_sub").eq(actor)
        if target:
            filter_expr = filter_expr & Attr("target_sub").eq(target)
        if event_actions:
            filter_expr = filter_expr & Attr("action").is_in(event_actions)

        for item in self._paginate_scan(
            T.role_audit,
            FilterExpression=filter_expr,
        ):
            evt = self._item_to_event(item)
            if evt:
                yield evt
                count += 1
                if count >= limit:
                    return

    def _item_to_event(self, item: dict) -> Optional[UnifiedAuditEvent]:
        ts = item.get("timestamp", 0)

        metadata = {}
        if item.get("old_role"):
            metadata["old_role"] = item["old_role"]
        if item.get("new_role"):
            metadata["new_role"] = item["new_role"]
        if item.get("admin_profile"):
            metadata["admin_profile"] = dict(item["admin_profile"])

        return UnifiedAuditEvent(
            event_id=item.get("audit_id", ""),
            event_type="admin",
            event_action=item.get("action", ""),
            timestamp=self._ts_to_iso(ts),
            timestamp_unix=self._ts_to_unix(ts),
            actor_user_id=item.get("user_sub", ""),
            actor_role="admin",
            target_user_id=item.get("target_sub") or None,
            outcome="success",
            metadata=metadata,
            source_table=self.source_table,
        )


class BillingLedgerAdapter(BaseAuditAdapter):
    """Reads LEDGER# entries from T.billing.

    Billing table uses pk=USER#{user_sub}, sk=LEDGER#{ledger_id}.
    For cross-user queries we must scan. For actor-specific queries
    we query by pk with SK begins_with filter.
    """

    source_table = "billing"
    event_type = "billing"

    def query(
        self,
        from_ts: int,
        to_ts: int,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        event_actions: Optional[list[str]] = None,
        limit: int = 1000,
    ) -> Iterator[UnifiedAuditEvent]:
        count = 0

        if actor:
            # Query by PK with SK prefix filter
            key_expr = Key("pk").eq(f"USER#{actor}") & Key("sk").begins_with("LEDGER#")
            filter_expr = Attr("created_at").between(from_ts, to_ts)
            if target:
                filter_expr = filter_expr & Attr("target_user").eq(target)
            if event_actions:
                filter_expr = filter_expr & Attr("reason").is_in(event_actions)

            for item in self._paginate_query(
                T.billing,
                KeyConditionExpression=key_expr,
                FilterExpression=filter_expr,
            ):
                evt = self._item_to_event(item, actor)
                if evt:
                    yield evt
                    count += 1
                    if count >= limit:
                        return
        else:
            # Full scan for LEDGER items
            filter_expr = (
                Attr("sk").begins_with("LEDGER#")
                & Attr("created_at").between(from_ts, to_ts)
            )
            if target:
                filter_expr = filter_expr & Attr("target_user").eq(target)
            if event_actions:
                filter_expr = filter_expr & Attr("reason").is_in(event_actions)

            for item in self._paginate_scan(
                T.billing,
                FilterExpression=filter_expr,
            ):
                user_sub = (item.get("pk", "").replace("USER#", ""))
                evt = self._item_to_event(item, user_sub)
                if evt:
                    yield evt
                    count += 1
                    if count >= limit:
                        return

    def _item_to_event(self, item: dict, user_sub: str) -> Optional[UnifiedAuditEvent]:
        ts = item.get("created_at", 0)
        ledger_id = item.get("ledger_id", item.get("sk", "").replace("LEDGER#", ""))

        amount = item.get("amount_cents", 0)
        if isinstance(amount, Decimal):
            amount = int(amount)

        metadata = {
            "type": item.get("type", ""),
            "amount_cents": amount,
            "reason": item.get("reason", ""),
            "currency": item.get("currency", "usd"),
        }
        if item.get("resource_type"):
            metadata["resource_type"] = item["resource_type"]
        if item.get("resource_id"):
            metadata["resource_id"] = item["resource_id"]
        if item.get("payment_method_id"):
            metadata["payment_method_id"] = item["payment_method_id"]

        # Map billing type to action name
        txn_type = item.get("type", "")
        reason = item.get("reason", "")
        action = f"{txn_type}_{reason}".lower().replace(" ", "_")[:64]

        return UnifiedAuditEvent(
            event_id=ledger_id,
            event_type="billing",
            event_action=action,
            timestamp=self._ts_to_iso(ts),
            timestamp_unix=self._ts_to_unix(ts),
            actor_user_id=user_sub,
            actor_role="user",
            target_user_id=item.get("target_user") or None,
            target_resource_type=item.get("resource_type") or None,
            target_resource_id=item.get("resource_id") or None,
            outcome="success",
            metadata=metadata,
            source_table=self.source_table,
        )


# ─── Adapter Registry ──────────────────────────────────────────────────────

ADAPTERS: dict[str, BaseAuditAdapter] = {
    "auth": AlertsAdapter(),
    "moderation": ModerationAuditAdapter(),
    "broadcast": BroadcastAuditAdapter(),
    "admin": RoleAuditAdapter(),
    "billing": BillingLedgerAdapter(),
}

VALID_CATEGORIES = set(ADAPTERS.keys())
```

### 3.3 Export Formats

#### 3.3.1 CSV Format

```csv
event_id,event_type,event_action,timestamp,actor_user_id,actor_role,target_user_id,target_resource_type,target_resource_id,outcome,actor_ip,metadata
evt_001,auth,login,2026-05-28T14:30:00Z,alice@test.local,user,,,,success,192.168.1.1,"{""device"":""Chrome/126""}"
evt_002,moderation,ban_user,2026-05-28T14:35:00Z,admin@test.local,admin,spammer@test.local,user,spammer@test.local,success,10.0.0.1,"{""duration"":""permanent""}"
```

- UTF-8 with BOM (Excel compatible)
- RFC 4180 compliant escaping
- Headers in first row
- Metadata JSON-encoded in last column

#### 3.3.2 JSON Format (NDJSON)

```json
{"event_id":"evt_001","event_type":"auth","event_action":"login","timestamp":"2026-05-28T14:30:00Z","timestamp_unix":1716904200,"actor_user_id":"alice@test.local","actor_role":"user","actor_ip":"192.168.1.1","outcome":"success","metadata":{"device":"Chrome/126"}}
{"event_id":"evt_002","event_type":"moderation","event_action":"ban_user","timestamp":"2026-05-28T14:35:00Z","timestamp_unix":1716904500,"actor_user_id":"admin@test.local","actor_role":"admin","target_user_id":"spammer@test.local","outcome":"success","metadata":{"duration":"permanent"}}
```

- Newline-delimited JSON (one event per line)
- Suitable for Splunk, Elasticsearch, AWS CloudWatch Logs import

#### 3.3.3 Export Manifest

Every export includes a manifest file:

```json
{
    "export_id": "exp_abc123",
    "schema_version": "1.0",
    "format": "ndjson",
    "event_count": 15432,
    "date_range": {
        "from": "2026-05-01T00:00:00Z",
        "to": "2026-05-28T23:59:59Z"
    },
    "categories": ["auth", "moderation", "billing"],
    "filters": {
        "actor_user_id": null,
        "target_user_id": null
    },
    "file_sha256": "a1b2c3d4e5f6...",
    "file_size_bytes": 2847291,
    "created_at": "2026-05-28T15:00:00Z",
    "created_by": "root.admin@testdev.local",
    "signature": "hmac-sha256:...",
    "signing_key_id": "dev-export-signing-key"
}
```

The `signature` field is an HMAC-SHA256 of the manifest (excluding the signature field itself), using the compliance export signing key from settings:

```python
# app/core/settings.py, lines 690-697
messaging_compliance_export_manifest_signing_key: str = os.environ.get(
    "MESSAGING_COMPLIANCE_EXPORT_MANIFEST_SIGNING_KEY",
    "dev-export-signing-key",
)
messaging_compliance_export_manifest_signing_key_id: str = os.environ.get(
    "MESSAGING_COMPLIANCE_EXPORT_MANIFEST_SIGNING_KEY_ID",
    "dev-key-v1",
)
```
<!-- VERIFIED: app/core/settings.py:690-697 — compliance export signing key settings -->
<!-- CORRECTED: was "lines 691-697", actually starts at line 690 -->

### 3.4 Export Pipeline Implementation

The export pipeline handles both sync (streaming) and async (background worker) exports:

```python
# app/services/audit_export_pipeline.py (new)

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import logging
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

import boto3

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.audit_adapters import ADAPTERS, VALID_CATEGORIES
from app.services.audit_export import UnifiedAuditEvent

logger = logging.getLogger(__name__)

# Column order for CSV exports
CSV_COLUMNS = [
    "event_id", "event_type", "event_action", "timestamp", "timestamp_unix",
    "actor_user_id", "actor_role", "actor_ip", "actor_user_agent",
    "target_user_id", "target_resource_type", "target_resource_id",
    "outcome", "metadata", "source_table",
]


def _gen_export_id() -> str:
    return f"exp_{uuid.uuid4().hex}"


def _merge_sorted_events(
    categories: list[str],
    from_ts: int,
    to_ts: int,
    actor: Optional[str] = None,
    target: Optional[str] = None,
    event_actions: Optional[list[str]] = None,
    limit: int = 10_000_000,
) -> Iterator[UnifiedAuditEvent]:
    """Query all adapters and yield events sorted by timestamp ascending."""
    import heapq

    # Use a heap to merge-sort events from multiple adapters by timestamp
    heap: list[tuple[int, int, UnifiedAuditEvent]] = []
    counter = 0  # Tiebreaker for heap ordering

    for category in categories:
        adapter = ADAPTERS.get(category)
        if not adapter:
            continue
        try:
            for event in adapter.query(
                from_ts=from_ts,
                to_ts=to_ts,
                actor=actor,
                target=target,
                event_actions=event_actions,
                limit=limit,
            ):
                heapq.heappush(heap, (event.timestamp_unix, counter, event))
                counter += 1
        except Exception:
            logger.exception("Adapter %s query failed", category)

    yielded = 0
    while heap and yielded < limit:
        _, _, event = heapq.heappop(heap)
        yield event
        yielded += 1


def generate_streaming_csv(
    categories: list[str],
    from_ts: int,
    to_ts: int,
    actor: Optional[str] = None,
    target: Optional[str] = None,
    event_actions: Optional[list[str]] = None,
    limit: int = 10_000,
) -> Iterator[str]:
    """Generate streaming CSV rows for small exports.

    Yields one string per row (including header). Uses UTF-8 BOM
    for Excel compatibility.
    """
    # BOM
    yield "﻿"

    # Header row
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    yield buf.getvalue()

    for event in _merge_sorted_events(categories, from_ts, to_ts, actor, target, event_actions, limit):
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(event.to_csv_row(CSV_COLUMNS))
        yield buf.getvalue()


def generate_streaming_ndjson(
    categories: list[str],
    from_ts: int,
    to_ts: int,
    actor: Optional[str] = None,
    target: Optional[str] = None,
    event_actions: Optional[list[str]] = None,
    limit: int = 10_000,
) -> Iterator[str]:
    """Generate streaming NDJSON lines for small exports."""
    for event in _merge_sorted_events(categories, from_ts, to_ts, actor, target, event_actions, limit):
        yield event.to_ndjson_line() + "\n"


def create_export_job(
    categories: list[str],
    format: str,
    from_ts: int,
    to_ts: int,
    created_by: str,
    actor_user_id: Optional[str] = None,
    target_user_id: Optional[str] = None,
    event_actions: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create an async export job record in DynamoDB."""
    export_id = _gen_export_id()
    now = now_ts()

    item = {
        "export_id": export_id,
        "sk": "META",
        "status": "pending",
        "categories": categories,
        "format": format,
        "from_date": from_ts,
        "to_date": to_ts,
        "created_by": created_by,
        "created_at": now,
        "actor_filter": actor_user_id or "",
        "target_filter": target_user_id or "",
        "event_actions_filter": event_actions or [],
        "event_count": 0,
        "file_size_bytes": 0,
        "events_scanned": 0,
        "events_written": 0,
        "attempt_count": 0,
        "max_attempts": 3,
    }
    T.audit_exports.put_item(Item=item)
    return item


def _compute_manifest_signature(manifest: dict) -> str:
    """Compute HMAC-SHA256 signature of the manifest (excluding signature field)."""
    signable = {k: v for k, v in manifest.items() if k != "signature"}
    payload = json.dumps(signable, sort_keys=True, default=str)
    sig = hmac.new(
        S.audit_export_signing_key.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{sig}"


def verify_manifest_signature(manifest: dict) -> bool:
    """Verify the HMAC signature on a manifest."""
    expected_sig = _compute_manifest_signature(manifest)
    actual_sig = manifest.get("signature", "")
    return hmac.compare_digest(expected_sig, actual_sig)


def process_export_job(export_id: str) -> None:
    """Execute an export job: query adapters, write file, upload to S3.

    Called by the background worker. Updates job status throughout.
    """
    # Fetch job record
    resp = T.audit_exports.get_item(Key={"export_id": export_id, "sk": "META"})
    job = resp.get("Item")
    if not job or job.get("status") not in ("pending", "processing"):
        return

    # Mark as processing
    now = now_ts()
    T.audit_exports.update_item(
        Key={"export_id": export_id, "sk": "META"},
        UpdateExpression="SET #st = :st, started_at = :sa, attempt_count = attempt_count + :one",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":st": "processing", ":sa": now, ":one": 1},
    )

    try:
        categories = job.get("categories", [])
        fmt = job.get("format", "ndjson")
        from_ts = int(job.get("from_date", 0))
        to_ts = int(job.get("to_date", 0))
        actor = job.get("actor_filter") or None
        target = job.get("target_filter") or None
        event_actions = job.get("event_actions_filter") or None

        # Write events to a temporary file
        event_count = 0
        sha256 = hashlib.sha256()

        with tempfile.NamedTemporaryFile(mode="w", suffix=f".{fmt}", delete=False) as tmp:
            if fmt == "csv":
                # Write BOM + header
                bom = "﻿"
                tmp.write(bom)
                sha256.update(bom.encode("utf-8"))

                writer = csv.writer(tmp)
                header_buf = io.StringIO()
                csv.writer(header_buf).writerow(CSV_COLUMNS)
                header_line = header_buf.getvalue()
                tmp.write(header_line)
                sha256.update(header_line.encode("utf-8"))

                for event in _merge_sorted_events(
                    categories, from_ts, to_ts, actor, target, event_actions,
                    limit=S.audit_export_max_events,
                ):
                    row_buf = io.StringIO()
                    csv.writer(row_buf).writerow(event.to_csv_row(CSV_COLUMNS))
                    line = row_buf.getvalue()
                    tmp.write(line)
                    sha256.update(line.encode("utf-8"))
                    event_count += 1

                    # Periodic progress update (every 5000 events)
                    if event_count % 5000 == 0:
                        T.audit_exports.update_item(
                            Key={"export_id": export_id, "sk": "META"},
                            UpdateExpression="SET events_written = :ew",
                            ExpressionAttributeValues={":ew": event_count},
                        )

            else:  # ndjson
                for event in _merge_sorted_events(
                    categories, from_ts, to_ts, actor, target, event_actions,
                    limit=S.audit_export_max_events,
                ):
                    line = event.to_ndjson_line() + "\n"
                    tmp.write(line)
                    sha256.update(line.encode("utf-8"))
                    event_count += 1

                    if event_count % 5000 == 0:
                        T.audit_exports.update_item(
                            Key={"export_id": export_id, "sk": "META"},
                            UpdateExpression="SET events_written = :ew",
                            ExpressionAttributeValues={":ew": event_count},
                        )

            tmp_path = tmp.name
            file_size = tmp.tell()

        file_hash = sha256.hexdigest()

        # Upload to S3
        s3_key = f"audit-exports/{export_id}/data.{fmt}"
        s3 = boto3.client("s3", endpoint_url=S.s3_endpoint_url) if S.s3_endpoint_url else boto3.client("s3")
        s3.upload_file(tmp_path, S.audit_export_s3_bucket, s3_key)

        # Generate manifest
        manifest = {
            "export_id": export_id,
            "schema_version": "1.0",
            "format": fmt,
            "event_count": event_count,
            "date_range": {
                "from": datetime.fromtimestamp(from_ts, tz=timezone.utc).isoformat(),
                "to": datetime.fromtimestamp(to_ts, tz=timezone.utc).isoformat(),
            },
            "categories": categories,
            "filters": {
                "actor_user_id": actor,
                "target_user_id": target,
                "event_actions": event_actions,
            },
            "file_sha256": file_hash,
            "file_size_bytes": file_size,
            "created_at": datetime.fromtimestamp(now_ts(), tz=timezone.utc).isoformat(),
            "created_by": job.get("created_by", ""),
            "signing_key_id": S.audit_export_signing_key_id,
            "contains_pii": True,
        }
        manifest["signature"] = _compute_manifest_signature(manifest)

        # Upload manifest
        manifest_key = f"audit-exports/{export_id}/manifest.json"
        s3.put_object(
            Bucket=S.audit_export_s3_bucket,
            Key=manifest_key,
            Body=json.dumps(manifest, indent=2),
            ContentType="application/json",
        )

        # Generate presigned download URL (24 hours)
        download_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S.audit_export_s3_bucket, "Key": s3_key},
            ExpiresIn=S.audit_export_url_ttl_seconds,
        )
        download_expires = now_ts() + S.audit_export_url_ttl_seconds

        # Update job record to completed
        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression=(
                "SET #st = :st, completed_at = :ca, event_count = :ec, "
                "file_size_bytes = :fs, download_url = :du, download_expires_at = :de, "
                "manifest_sha256 = :ms, events_written = :ew, s3_key = :sk, "
                "manifest_s3_key = :mk"
            ),
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": "completed",
                ":ca": now_ts(),
                ":ec": event_count,
                ":fs": file_size,
                ":du": download_url,
                ":de": download_expires,
                ":ms": file_hash,
                ":ew": event_count,
                ":sk": s3_key,
                ":mk": manifest_key,
            },
        )

        # Send notification to requesting admin
        try:
            from app.services.alerts import write_alert
            write_alert(
                job.get("created_by", ""),
                event="audit_export_completed",
                outcome="success",
                title=f"Audit export ready ({event_count} events)",
                details={"export_id": export_id, "event_count": event_count},
            )
        except Exception:
            logger.warning("Failed to send export completion notification")

        # Clean up temp file
        import os
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    except Exception as exc:
        logger.exception("Export job %s failed", export_id)

        attempt = int(job.get("attempt_count", 0)) + 1
        max_attempts = int(job.get("max_attempts", 3))
        new_status = "failed" if attempt >= max_attempts else "pending"

        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression="SET #st = :st, error_message = :em, last_error_at = :lea",
            ExpressionAttributeNames={"#st": "status"},
            ExpressionAttributeValues={
                ":st": new_status,
                ":em": str(exc)[:500],
                ":lea": now_ts(),
            },
        )
```

### 3.5 Export Worker Background Task

The export worker runs as a background async task, similar to the webhook dispatcher:

```python
# app/services/audit_export_worker.py (new)

from __future__ import annotations

import asyncio
import logging
import time as _time

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.services.audit_export_pipeline import process_export_job
from app.services.job_registry import register_task, report_error, report_poll

logger = logging.getLogger(__name__)


async def run_audit_export_worker_loop() -> None:
    """Background coroutine that processes pending audit export jobs."""
    poll_interval = S.audit_export_worker_poll_interval_seconds
    max_concurrent = S.audit_export_worker_max_concurrent

    register_task(
        "audit_export_worker",
        poll_interval,
        enabled=True,
        description="Processes async audit export jobs",
    )
    logger.info(
        "Audit export worker started (poll=%ds, max_concurrent=%d)",
        poll_interval,
        max_concurrent,
    )

    while True:
        _poll_start = _time.perf_counter()
        _processed = 0
        _failed = 0
        try:
            now = now_ts()

            # Query pending jobs (ordered by created_at via GSI)
            resp = T.audit_exports.query(
                IndexName="status-created-index",
                KeyConditionExpression=Key("status").eq("pending"),
                ScanIndexForward=True,
                Limit=max_concurrent,
            )
            pending_jobs = resp.get("Items", [])

            # Also check for stale processing jobs (>1 hour old)
            stale_resp = T.audit_exports.query(
                IndexName="status-created-index",
                KeyConditionExpression=Key("status").eq("processing"),
                ScanIndexForward=True,
                Limit=10,
            )
            for item in stale_resp.get("Items", []):
                started = int(item.get("started_at", 0))
                if started > 0 and (now - started) > 3600:
                    # Reset stale job to pending
                    attempt = int(item.get("attempt_count", 0))
                    max_attempts = int(item.get("max_attempts", 3))
                    if attempt < max_attempts:
                        T.audit_exports.update_item(
                            Key={"export_id": item["export_id"], "sk": "META"},
                            UpdateExpression="SET #st = :st",
                            ExpressionAttributeNames={"#st": "status"},
                            ExpressionAttributeValues={":st": "pending"},
                        )
                        logger.warning(
                            "Reset stale export job %s (started %ds ago)",
                            item["export_id"],
                            now - started,
                        )

            # Process pending jobs
            for job in pending_jobs[:max_concurrent]:
                try:
                    export_id = job["export_id"]
                    logger.info("Processing export job %s", export_id)
                    # Run in executor to avoid blocking the event loop
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, process_export_job, export_id)
                    _processed += 1
                except Exception:
                    _failed += 1
                    logger.exception(
                        "Export job %s processing failed",
                        job.get("export_id", "?"),
                    )

            _duration_ms = (_time.perf_counter() - _poll_start) * 1000
            report_poll(
                "audit_export_worker",
                items_processed=_processed,
                items_failed=_failed,
                duration_ms=_duration_ms,
            )

        except Exception as exc:
            report_error("audit_export_worker", str(exc))
            logger.exception("Audit export worker loop error")

        await asyncio.sleep(poll_interval)


async def start_audit_export_worker_task() -> None:
    """FastAPI startup event handler."""
    if S.audit_export_enabled and S.audit_export_worker_enabled:
        asyncio.create_task(run_audit_export_worker_loop())
    else:
        register_task(
            "audit_export_worker",
            S.audit_export_worker_poll_interval_seconds,
            enabled=False,
            description="Processes async audit export jobs",
        )
```

### 3.6 Async Export Pipeline

For exports >10,000 events:

1. **Job creation**: `POST /v1/admin/audit/exports` creates a job record in `T.audit_exports` with `status=pending`.
2. **Background worker**: The audit export worker (registered at startup like `start_webhook_dispatcher_task` in `app/main.py` line 443) polls for pending jobs.
<!-- CORRECTED: start_webhook_dispatcher_task is at line 472, not 443 -->
3. **Scan phase**: The worker iterates through all selected source adapters, merging results by timestamp.
4. **Write phase**: Results are written to a temporary file, then uploaded to S3 (`privacy-export` bucket reused from PRIVACY-001, settings line 1250).
5. **Presigned URL**: A download URL with 24-hour TTL is generated and stored on the job record.
6. **Notification**: An alert is sent to the requesting admin via the alerts system.

### 3.7 Scheduled Recurring Exports

Building on the existing unified scheduler (`app/services/unified_scheduler.py`, started at `app/main.py` line 437):
<!-- CORRECTED: start_unified_scheduler_task is at line 466, not 437 -->

```python
# Scheduled action record
{
    "action_id": "sched_audit_weekly",
    "action_type": "audit_export",
    "owner_user_sub": "root.admin@testdev.local",
    "schedule_cron": "0 2 * * 1",  # Monday 2 AM
    "params": {
        "categories": ["auth", "moderation", "admin"],
        "format": "ndjson",
        "rolling_window_days": 7,
    },
    "status": "active",
    "last_run_at": 1716768000,
    "next_run_at": 1717372800,
}
```

The `scheduled_actions` table (settings line 1305) already supports this:
<!-- VERIFIED: app/core/settings.py:1305-1311 — scheduled actions settings -->

```python
# app/core/settings.py, lines 1305-1311
scheduled_actions_table_name: str = os.environ.get("SCHEDULED_ACTIONS_TABLE_NAME", "scheduled_actions")
unified_scheduler_enabled: bool = os.environ.get("UNIFIED_SCHEDULER_ENABLED", "1") not in ("0", "false", "False")
unified_scheduler_poll_interval_seconds: int = int(os.environ.get("UNIFIED_SCHEDULER_POLL_INTERVAL_SECONDS", "15"))
```

The scheduled export executor to register in `unified_scheduler.py`:

```python
# app/services/schedule_executors.py -- addition

async def execute_scheduled_audit_export(user_sub: str, payload: dict) -> None:
    """Execute a scheduled audit export job.

    Called by the unified scheduler when a cron-triggered audit_export
    action fires.
    """
    from app.services.audit_export_pipeline import create_export_job

    categories = payload.get("categories", ["auth", "moderation", "admin"])
    fmt = payload.get("format", "ndjson")
    rolling_days = int(payload.get("rolling_window_days", 7))

    now = now_ts()
    from_ts = now - (rolling_days * 86400)
    to_ts = now

    create_export_job(
        categories=categories,
        format=fmt,
        from_ts=from_ts,
        to_ts=to_ts,
        created_by=user_sub,
    )
    logger.info("Created scheduled audit export for user %s", user_sub)
```

Register in `_EXECUTORS`:

```python
_EXECUTORS = {
    "post": schedule_executors.execute_scheduled_post,
    "file_share": schedule_executors.execute_scheduled_file_share,
    "catalog_sale": schedule_executors.execute_scheduled_catalog_sale,
    "audit_export": schedule_executors.execute_scheduled_audit_export,  # NEW
}
```

---

## 4. API Endpoints

### 4.1 Audit Export Management (Admin only)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/admin/audit/exports` | `require_root_session` or ADMIN with `audit_export` scope | Create an export job |
| GET | `/v1/admin/audit/exports` | `require_root_session` or ADMIN | List export jobs (paginated) |
| GET | `/v1/admin/audit/exports/{export_id}` | `require_root_session` or ADMIN | Get export status and download URL |
| GET | `/v1/admin/audit/exports/{export_id}/download` | `require_root_session` or ADMIN | Redirect to S3 presigned URL |
| DELETE | `/v1/admin/audit/exports/{export_id}` | `require_root_session` | Delete export file from S3 |
| POST | `/v1/admin/audit/exports/{export_id}/verify` | `require_root_session` or ADMIN | Verify manifest integrity |

### 4.2 Audit Log Query (Preview before export)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/admin/audit/events` | `require_root_session` or ADMIN | Query audit events with filters (paginated, max 200 per page) |
| GET | `/v1/admin/audit/events/categories` | `require_root_session` or ADMIN | List available event categories |
| GET | `/v1/admin/audit/events/summary` | `require_root_session` or ADMIN | Event counts by category for a date range |

### 4.3 Scheduled Export Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/admin/audit/schedules` | `require_root_session` | Create scheduled recurring export |
| GET | `/v1/admin/audit/schedules` | `require_root_session` | List scheduled exports |
| PATCH | `/v1/admin/audit/schedules/{schedule_id}` | `require_root_session` | Update schedule |
| DELETE | `/v1/admin/audit/schedules/{schedule_id}` | `require_root_session` | Delete schedule |

### 4.4 Request / Response Models

```python
# app/models.py -- new models

class AuditExportCreateReq(BaseModel):
    categories: list[str] = Field(min_length=1, description="Event categories to include")
    format: str = Field(default="ndjson", pattern=r"^(csv|ndjson|json)$")
    from_date: int = Field(ge=0, description="Unix timestamp start (inclusive)")
    to_date: int = Field(ge=0, description="Unix timestamp end (inclusive)")
    actor_user_id: Optional[str] = None
    target_user_id: Optional[str] = None
    event_actions: Optional[list[str]] = None  # filter specific actions

class AuditExportOut(BaseModel):
    export_id: str
    status: str                  # pending | processing | completed | failed
    categories: list[str]
    format: str
    from_date: int
    to_date: int
    event_count: Optional[int]
    file_size_bytes: Optional[int]
    download_url: Optional[str]
    download_expires_at: Optional[int]
    manifest_sha256: Optional[str]
    created_at: int
    created_by: str
    completed_at: Optional[int]
    error_message: Optional[str]
    events_scanned: Optional[int] = None
    events_written: Optional[int] = None

class AuditEventOut(BaseModel):
    event_id: str
    event_type: str
    event_action: str
    timestamp: str
    timestamp_unix: int
    actor_user_id: str
    actor_role: Optional[str]
    actor_ip: Optional[str]
    target_user_id: Optional[str]
    target_resource_type: Optional[str]
    target_resource_id: Optional[str]
    outcome: str
    metadata: dict

class AuditEventSummaryOut(BaseModel):
    category: str
    event_count: int
    earliest_event: Optional[str] = None  # ISO 8601
    latest_event: Optional[str] = None    # ISO 8601

class AuditCategoriesOut(BaseModel):
    categories: list[dict]  # [{name: "auth", description: "...", event_count_hint: N}]

class AuditScheduleCreateReq(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    categories: list[str] = Field(min_length=1)
    format: str = Field(default="ndjson", pattern=r"^(csv|ndjson|json)$")
    schedule_cron: str = Field(description="Cron expression (e.g., '0 2 * * 1' for weekly)")
    rolling_window_days: int = Field(default=7, ge=1, le=365)
    notification_email: Optional[str] = None

class AuditScheduleOut(BaseModel):
    schedule_id: str
    name: str
    categories: list[str]
    format: str
    schedule_cron: str
    rolling_window_days: int
    notification_email: Optional[str]
    status: str                  # active | paused | deleted
    last_run_at: Optional[int]
    next_run_at: Optional[int]
    last_export_id: Optional[str]
    created_at: int
    created_by: str
```

### 4.5 Router Implementation

```python
# app/routers/audit_export.py (new)

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse, StreamingResponse

from app.services.sessions import require_ui_session  # NOTE: require_ui_session is in app/services/sessions.py:283, NOT app/auth/deps.py
from app.auth.deps import require_root_session
from app.auth.roles import AdminScope, Role, admin_profile_has_scope
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from app.models import (
    AuditExportCreateReq,
    AuditExportOut,
    AuditEventOut,
    AuditScheduleCreateReq,
    AuditScheduleOut,
)
from app.services.alerts import audit_event
from app.services.audit_adapters import ADAPTERS, VALID_CATEGORIES
from app.services.audit_export_pipeline import (
    create_export_job,
    generate_streaming_csv,
    generate_streaming_ndjson,
    verify_manifest_signature,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/admin/audit", tags=["audit-export"])

SYNC_EXPORT_THRESHOLD = 10_000  # Events below this stream directly
MAX_PREVIEW_EVENTS = 200


def _require_audit_access(ctx: dict) -> None:
    """Verify the caller has ROOT role or ADMIN with AUDIT_EXPORT scope."""
    role = ctx.get("role")
    if role == Role.ROOT:
        return
    if role == Role.ADMIN:
        profile = ctx.get("admin_profile")
        if profile and admin_profile_has_scope(profile, AdminScope.AUDIT_EXPORT):
            return
    raise HTTPException(status_code=403, detail="Audit export access required")


def _validate_categories(categories: list[str]) -> None:
    """Validate that all categories are known."""
    invalid = set(categories) - VALID_CATEGORIES
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown categories: {', '.join(sorted(invalid))}. "
                   f"Valid: {', '.join(sorted(VALID_CATEGORIES))}",
        )


def _validate_date_range(from_date: int, to_date: int) -> None:
    """Validate date range constraints."""
    if from_date > to_date:
        raise HTTPException(status_code=422, detail="from_date must be <= to_date")
    max_range = S.audit_export_max_date_range_days * 86400
    if (to_date - from_date) > max_range:
        raise HTTPException(
            status_code=400,
            detail=f"Date range exceeds maximum of {S.audit_export_max_date_range_days} days",
        )


# ─── Export CRUD ───────────────────────────────────────────────────────────

@router.post("/exports", status_code=201, response_model=AuditExportOut)
async def create_audit_export(
    body: AuditExportCreateReq,
    ctx: Dict[str, Any] = Depends(require_ui_session),
    request=None,
):
    _require_audit_access(ctx)
    _validate_categories(body.categories)
    _validate_date_range(body.from_date, body.to_date)

    user_sub = ctx["user_sub"]

    # Rate limit: max 10 exports per admin per hour
    # (Implementation: check recent exports in DDB by user-created-index GSI)
    cutoff = now_ts() - 3600
    from boto3.dynamodb.conditions import Key
    recent = T.audit_exports.query(
        IndexName="user-created-index",
        KeyConditionExpression=Key("created_by").eq(user_sub)
        & Key("created_at").gte(cutoff),
    )
    if len(recent.get("Items", [])) >= 10:
        raise HTTPException(status_code=429, detail="Export rate limit: max 10 per hour")

    job = create_export_job(
        categories=body.categories,
        format=body.format,
        from_ts=body.from_date,
        to_ts=body.to_date,
        created_by=user_sub,
        actor_user_id=body.actor_user_id,
        target_user_id=body.target_user_id,
        event_actions=body.event_actions,
    )

    audit_event("audit_export_created", user_sub, request,
                export_id=job["export_id"],
                categories=body.categories,
                date_range=f"{body.from_date}-{body.to_date}")

    return _job_to_out(job)


@router.get("/exports", response_model=dict)
async def list_audit_exports(
    cursor: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_audit_access(ctx)

    kwargs: dict[str, Any] = {
        "IndexName": "user-created-index",
        "KeyConditionExpression": Key("created_by").eq(ctx["user_sub"]),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        import base64, json
        try:
            kwargs["ExclusiveStartKey"] = json.loads(base64.b64decode(cursor))
        except Exception:
            pass

    resp = T.audit_exports.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    if resp.get("LastEvaluatedKey"):
        import base64, json
        next_cursor = base64.b64encode(
            json.dumps(resp["LastEvaluatedKey"]).encode()
        ).decode()

    return {
        "exports": [_job_to_out(item) for item in items],
        "cursor": next_cursor,
    }


@router.get("/exports/{export_id}", response_model=AuditExportOut)
async def get_audit_export(
    export_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_audit_access(ctx)

    resp = T.audit_exports.get_item(Key={"export_id": export_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Export not found")
    return _job_to_out(item)


@router.get("/exports/{export_id}/download")
async def download_audit_export(
    export_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
    request=None,
):
    _require_audit_access(ctx)

    resp = T.audit_exports.get_item(Key={"export_id": export_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Export not found")
    if item.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Export not yet completed")

    download_url = item.get("download_url")
    expires = int(item.get("download_expires_at", 0))
    if not download_url or expires < now_ts():
        # Regenerate presigned URL
        s3_key = item.get("s3_key")
        if not s3_key:
            raise HTTPException(status_code=410, detail="Export file no longer available")
        import boto3
        s3 = boto3.client("s3", endpoint_url=S.s3_endpoint_url) if S.s3_endpoint_url else boto3.client("s3")
        download_url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S.audit_export_s3_bucket, "Key": s3_key},
            ExpiresIn=S.audit_export_url_ttl_seconds,
        )
        new_expires = now_ts() + S.audit_export_url_ttl_seconds
        T.audit_exports.update_item(
            Key={"export_id": export_id, "sk": "META"},
            UpdateExpression="SET download_url = :du, download_expires_at = :de",
            ExpressionAttributeValues={":du": download_url, ":de": new_expires},
        )

    audit_event("audit_export_downloaded", ctx["user_sub"], request, export_id=export_id)
    return RedirectResponse(url=download_url, status_code=302)


@router.delete("/exports/{export_id}", status_code=204)
async def delete_audit_export(
    export_id: str,
    ctx: Dict[str, Any] = Depends(require_root_session),
    request=None,
):
    resp = T.audit_exports.get_item(Key={"export_id": export_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Export not found")

    # Delete S3 objects
    try:
        import boto3
        s3 = boto3.client("s3", endpoint_url=S.s3_endpoint_url) if S.s3_endpoint_url else boto3.client("s3")
        if item.get("s3_key"):
            s3.delete_object(Bucket=S.audit_export_s3_bucket, Key=item["s3_key"])
        if item.get("manifest_s3_key"):
            s3.delete_object(Bucket=S.audit_export_s3_bucket, Key=item["manifest_s3_key"])
    except Exception:
        logger.warning("Failed to delete S3 objects for export %s", export_id)

    # Mark as deleted (keep metadata for audit trail)
    T.audit_exports.update_item(
        Key={"export_id": export_id, "sk": "META"},
        UpdateExpression="SET #st = :st, download_url = :null, deleted_at = :da, deleted_by = :db",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={
            ":st": "deleted",
            ":null": None,
            ":da": now_ts(),
            ":db": ctx["user_sub"],
        },
    )

    audit_event("audit_export_deleted", ctx["user_sub"], request, export_id=export_id)


@router.post("/exports/{export_id}/verify")
async def verify_audit_export(
    export_id: str,
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_audit_access(ctx)

    resp = T.audit_exports.get_item(Key={"export_id": export_id, "sk": "META"})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Export not found")
    if item.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Export not completed")

    # Fetch manifest from S3
    manifest_key = item.get("manifest_s3_key")
    if not manifest_key:
        raise HTTPException(status_code=410, detail="Manifest not available")

    import boto3, json
    s3 = boto3.client("s3", endpoint_url=S.s3_endpoint_url) if S.s3_endpoint_url else boto3.client("s3")

    try:
        manifest_obj = s3.get_object(Bucket=S.audit_export_s3_bucket, Key=manifest_key)
        manifest = json.loads(manifest_obj["Body"].read())
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to read manifest")

    # Verify HMAC signature
    sig_valid = verify_manifest_signature(manifest)

    # Verify file hash
    data_key = item.get("s3_key")
    hash_valid = False
    if data_key:
        try:
            import hashlib
            data_obj = s3.get_object(Bucket=S.audit_export_s3_bucket, Key=data_key)
            sha256 = hashlib.sha256()
            for chunk in data_obj["Body"].iter_chunks(chunk_size=65536):
                sha256.update(chunk)
            computed_hash = sha256.hexdigest()
            hash_valid = computed_hash == manifest.get("file_sha256")
        except Exception:
            pass

    return {
        "export_id": export_id,
        "signature_valid": sig_valid,
        "hash_valid": hash_valid,
        "manifest": manifest,
        "verification_timestamp": now_ts(),
    }


# ─── Event query (preview) ────────────────────────────────────────────────

@router.get("/events")
async def query_audit_events(
    categories: str = Query(..., description="Comma-separated categories"),
    from_date: int = Query(..., ge=0),
    to_date: int = Query(..., ge=0),
    actor_user_id: Optional[str] = Query(None),
    target_user_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=MAX_PREVIEW_EVENTS),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_audit_access(ctx)

    cat_list = [c.strip() for c in categories.split(",")]
    _validate_categories(cat_list)
    _validate_date_range(from_date, to_date)

    from app.services.audit_export_pipeline import _merge_sorted_events
    events = list(_merge_sorted_events(
        cat_list, from_date, to_date,
        actor=actor_user_id,
        target=target_user_id,
        limit=limit,
    ))

    return {
        "events": [
            AuditEventOut(
                event_id=e.event_id,
                event_type=e.event_type,
                event_action=e.event_action,
                timestamp=e.timestamp,
                timestamp_unix=e.timestamp_unix,
                actor_user_id=e.actor_user_id,
                actor_role=e.actor_role,
                actor_ip=e.actor_ip,
                target_user_id=e.target_user_id,
                target_resource_type=e.target_resource_type,
                target_resource_id=e.target_resource_id,
                outcome=e.outcome,
                metadata=e.metadata,
            ).model_dump()
            for e in events
        ],
        "count": len(events),
    }


@router.get("/events/categories")
async def list_audit_categories(
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_audit_access(ctx)
    return {
        "categories": [
            {
                "name": name,
                "description": {
                    "auth": "Authentication, session, and MFA events",
                    "moderation": "Content moderation actions",
                    "broadcast": "Broadcast start/stop/schedule events",
                    "admin": "Admin role grants, revokes, and impersonation",
                    "billing": "Financial transactions and payment events",
                }.get(name, name),
            }
            for name in sorted(VALID_CATEGORIES)
        ]
    }


@router.get("/events/summary")
async def audit_event_summary(
    from_date: int = Query(..., ge=0),
    to_date: int = Query(..., ge=0),
    ctx: Dict[str, Any] = Depends(require_ui_session),
):
    _require_audit_access(ctx)
    _validate_date_range(from_date, to_date)

    summary = []
    for category, adapter in ADAPTERS.items():
        try:
            count = 0
            earliest = None
            latest = None
            for event in adapter.query(from_ts=from_date, to_ts=to_date, limit=10_000):
                count += 1
                if earliest is None or event.timestamp_unix < earliest:
                    earliest = event.timestamp_unix
                if latest is None or event.timestamp_unix > latest:
                    latest = event.timestamp_unix
            summary.append({
                "category": category,
                "event_count": count,
                "earliest_event": datetime.fromtimestamp(earliest, tz=timezone.utc).isoformat() if earliest else None,
                "latest_event": datetime.fromtimestamp(latest, tz=timezone.utc).isoformat() if latest else None,
            })
        except Exception:
            summary.append({"category": category, "event_count": 0})

    return {"summary": summary}


# ─── Helper ────────────────────────────────────────────────────────────────

def _job_to_out(item: dict) -> dict:
    """Convert a DDB export job item to an API response dict."""
    return {
        "export_id": item.get("export_id", ""),
        "status": item.get("status", ""),
        "categories": list(item.get("categories", [])),
        "format": item.get("format", "ndjson"),
        "from_date": int(item.get("from_date", 0)),
        "to_date": int(item.get("to_date", 0)),
        "event_count": int(item["event_count"]) if item.get("event_count") else None,
        "file_size_bytes": int(item["file_size_bytes"]) if item.get("file_size_bytes") else None,
        "download_url": item.get("download_url"),
        "download_expires_at": int(item["download_expires_at"]) if item.get("download_expires_at") else None,
        "manifest_sha256": item.get("manifest_sha256"),
        "created_at": int(item.get("created_at", 0)),
        "created_by": item.get("created_by", ""),
        "completed_at": int(item["completed_at"]) if item.get("completed_at") else None,
        "error_message": item.get("error_message"),
        "events_scanned": int(item["events_scanned"]) if item.get("events_scanned") else None,
        "events_written": int(item["events_written"]) if item.get("events_written") else None,
    }
```

Registration in `app/main.py`:

```python
# app/main.py -- additions
from app.routers.audit_export import router as audit_export_router
from app.services.audit_export_worker import start_audit_export_worker_task

app.include_router(audit_export_router)
app.add_event_handler("startup", start_audit_export_worker_task)
```

---

## 5. Frontend Components

### 5.1 Audit Export Page

**File**: `frontend/src/pages/admin/AuditExport.tsx` (new)

- Sidebar entry under Admin section with `ScrollText` icon
- Two tabs: "Exports" and "Schedules"

#### Exports Tab
- Filter bar: date range picker, multi-select for categories, actor/target user search, format selector
- "Preview" button queries `/v1/admin/audit/events` and shows a sample table of 10 events
- "Export" button creates the export job via POST
- Export jobs table: ID, Status (with badge), Categories, Date Range, Size, Download button, Created
- Download button generates a presigned URL redirect
- Status polling: `useQuery` with 5-second refetch interval while status is `processing`

#### Schedules Tab
- Table of scheduled exports with name, cron schedule (human-readable), categories, format, next run
- Create/Edit dialog with cron builder (preset buttons: daily, weekly, monthly + custom input)
- Delete with confirmation

```typescript
// frontend/src/pages/admin/AuditExport.tsx (new)

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollText, Download, Eye, Loader2, CheckCircle2, XCircle, Clock } from "lucide-react";
import {
  createAuditExport,
  listAuditExports,
  getAuditExport,
  downloadAuditExport,
  listAuditCategories,
  queryAuditEvents,
  verifyAuditExport,
} from "@/api/endpoints/audit";
import type { AuditExportCreateReq, AuditExportOut } from "@/api/types";

function StatusBadge({ status }: { status: string }) {
  const variants: Record<string, { variant: string; icon: React.ReactNode }> = {
    pending: { variant: "secondary", icon: <Clock className="w-3 h-3" /> },
    processing: { variant: "default", icon: <Loader2 className="w-3 h-3 animate-spin" /> },
    completed: { variant: "success", icon: <CheckCircle2 className="w-3 h-3" /> },
    failed: { variant: "destructive", icon: <XCircle className="w-3 h-3" /> },
  };
  const { variant, icon } = variants[status] ?? variants.pending;
  return (
    <Badge variant={variant as any} className="gap-1">
      {icon} {status}
    </Badge>
  );
}

export default function AuditExport() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState("exports");
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [format, setFormat] = useState("ndjson");
  const [fromDate, setFromDate] = useState<number>(
    Math.floor(Date.now() / 1000) - 30 * 86400
  );
  const [toDate, setToDate] = useState<number>(Math.floor(Date.now() / 1000));

  const categoriesQ = useQuery({
    queryKey: ["audit", "categories"],
    queryFn: listAuditCategories,
  });

  const exportsQ = useQuery({
    queryKey: ["audit", "exports"],
    queryFn: () => listAuditExports(),
    refetchInterval: (data) =>
      data?.exports?.some((e: AuditExportOut) => e.status === "processing")
        ? 5000
        : false,
  });

  const createMut = useMutation({
    mutationFn: createAuditExport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["audit", "exports"] });
    },
  });

  const handleExport = () => {
    if (selectedCategories.length === 0) return;
    createMut.mutate({
      categories: selectedCategories,
      format,
      from_date: fromDate,
      to_date: toDate,
    });
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-3">
        <ScrollText className="w-8 h-8" />
        <h1 className="text-2xl font-bold">Audit Log Export</h1>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="exports">Exports</TabsTrigger>
          <TabsTrigger value="schedules">Schedules</TabsTrigger>
        </TabsList>

        <TabsContent value="exports" className="space-y-4">
          {/* Filter bar */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Export Filters</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-4">
              {/* Category multi-select, date pickers, format selector */}
              <Select value={format} onValueChange={setFormat}>
                <SelectTrigger className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ndjson">NDJSON</SelectItem>
                  <SelectItem value="csv">CSV</SelectItem>
                </SelectContent>
              </Select>

              <Button onClick={handleExport} disabled={createMut.isPending}>
                {createMut.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin mr-2" />
                ) : null}
                Export
              </Button>
            </CardContent>
          </Card>

          {/* Export jobs table */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Export History</CardTitle>
            </CardHeader>
            <CardContent>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left p-2">ID</th>
                    <th className="text-left p-2">Status</th>
                    <th className="text-left p-2">Categories</th>
                    <th className="text-left p-2">Events</th>
                    <th className="text-left p-2">Size</th>
                    <th className="text-left p-2">Created</th>
                    <th className="text-left p-2">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {exportsQ.data?.exports?.map((exp: AuditExportOut) => (
                    <tr key={exp.export_id} className="border-b">
                      <td className="p-2 font-mono text-xs">
                        {exp.export_id.slice(0, 12)}...
                      </td>
                      <td className="p-2">
                        <StatusBadge status={exp.status} />
                      </td>
                      <td className="p-2">
                        {exp.categories.join(", ")}
                      </td>
                      <td className="p-2">
                        {exp.event_count?.toLocaleString() ?? "-"}
                      </td>
                      <td className="p-2">
                        {exp.file_size_bytes
                          ? `${(exp.file_size_bytes / 1024).toFixed(1)} KB`
                          : "-"}
                      </td>
                      <td className="p-2">
                        {new Date(exp.created_at * 1000).toLocaleDateString()}
                      </td>
                      <td className="p-2">
                        {exp.status === "completed" && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => downloadAuditExport(exp.export_id)}
                          >
                            <Download className="w-4 h-4" />
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="schedules">
          {/* Schedules tab content */}
        </TabsContent>
      </Tabs>
    </div>
  );
}
```

### 5.2 Audit Event Viewer

**File**: `frontend/src/pages/admin/AuditEventViewer.tsx` (new)

- Real-time audit event list with infinite scroll
- Category filter pills (auth, moderation, billing, broadcast, admin, file)
- Click on event row expands to show full metadata JSON
- Actor and target user IDs are clickable links to user profile

### 5.3 Export Download Handler

**File**: `frontend/src/api/endpoints/audit.ts` (new)

```typescript
// frontend/src/api/endpoints/audit.ts

import { api } from "@/api/client";  // NOTE: codebase uses named `api` export, not default `client` import
import type {
  AuditExportCreateReq,
  AuditExportOut,
  AuditEventOut,
  AuditScheduleCreateReq,
  AuditScheduleOut,
} from "../types";

// ─── Exports ──────────────────────────────────────────────────────────────

export const createAuditExport = (req: AuditExportCreateReq) =>
  api.post<AuditExportOut>("/v1/admin/audit/exports", req).then((r) => r.data);

export const listAuditExports = (cursor?: string) =>
  client
    .get<{ exports: AuditExportOut[]; cursor?: string }>(
      "/v1/admin/audit/exports",
      { params: { cursor } }
    )
    .then((r) => r.data);

export const getAuditExport = (exportId: string) =>
  client
    .get<AuditExportOut>(`/v1/admin/audit/exports/${exportId}`)
    .then((r) => r.data);

export const downloadAuditExport = (exportId: string) =>
  window.open(`/v1/admin/audit/exports/${exportId}/download`, "_blank");

export const deleteAuditExport = (exportId: string) =>
  api.delete(`/v1/admin/audit/exports/${exportId}`);

export const verifyAuditExport = (exportId: string) =>
  client
    .post<{
      export_id: string;
      signature_valid: boolean;
      hash_valid: boolean;
      manifest: Record<string, any>;
    }>(`/v1/admin/audit/exports/${exportId}/verify`)
    .then((r) => r.data);

// ─── Events (preview) ────────────────────────────────────────────────────

export const queryAuditEvents = (params: {
  categories: string;
  from_date: number;
  to_date: number;
  actor_user_id?: string;
  target_user_id?: string;
  limit?: number;
}) =>
  client
    .get<{ events: AuditEventOut[]; count: number }>(
      "/v1/admin/audit/events",
      { params }
    )
    .then((r) => r.data);

export const listAuditCategories = () =>
  client
    .get<{ categories: { name: string; description: string }[] }>(
      "/v1/admin/audit/events/categories"
    )
    .then((r) => r.data);

export const auditEventSummary = (fromDate: number, toDate: number) =>
  client
    .get<{
      summary: {
        category: string;
        event_count: number;
        earliest_event?: string;
        latest_event?: string;
      }[];
    }>("/v1/admin/audit/events/summary", {
      params: { from_date: fromDate, to_date: toDate },
    })
    .then((r) => r.data);

// ─── Schedules ────────────────────────────────────────────────────────────

export const createAuditSchedule = (req: AuditScheduleCreateReq) =>
  client
    .post<AuditScheduleOut>("/v1/admin/audit/schedules", req)
    .then((r) => r.data);

export const listAuditSchedules = () =>
  client
    .get<{ schedules: AuditScheduleOut[] }>("/v1/admin/audit/schedules")
    .then((r) => r.data);

export const updateAuditSchedule = (
  scheduleId: string,
  req: Partial<AuditScheduleCreateReq>
) =>
  client
    .patch<AuditScheduleOut>(`/v1/admin/audit/schedules/${scheduleId}`, req)
    .then((r) => r.data);

export const deleteAuditSchedule = (scheduleId: string) =>
  api.delete(`/v1/admin/audit/schedules/${scheduleId}`);
```

### 5.4 Frontend TypeScript Types

```typescript
// frontend/src/api/types.ts -- additions

export interface AuditExportCreateReq {
  categories: string[];
  format: "csv" | "ndjson" | "json";
  from_date: number;
  to_date: number;
  actor_user_id?: string;
  target_user_id?: string;
  event_actions?: string[];
}

export interface AuditExportOut {
  export_id: string;
  status: "pending" | "processing" | "completed" | "failed" | "deleted";
  categories: string[];
  format: string;
  from_date: number;
  to_date: number;
  event_count: number | null;
  file_size_bytes: number | null;
  download_url: string | null;
  download_expires_at: number | null;
  manifest_sha256: string | null;
  created_at: number;
  created_by: string;
  completed_at: number | null;
  error_message: string | null;
  events_scanned: number | null;
  events_written: number | null;
}

export interface AuditEventOut {
  event_id: string;
  event_type: string;
  event_action: string;
  timestamp: string;
  timestamp_unix: number;
  actor_user_id: string;
  actor_role: string | null;
  actor_ip: string | null;
  target_user_id: string | null;
  target_resource_type: string | null;
  target_resource_id: string | null;
  outcome: string;
  metadata: Record<string, any>;
}

export interface AuditScheduleCreateReq {
  name: string;
  categories: string[];
  format: "csv" | "ndjson" | "json";
  schedule_cron: string;
  rolling_window_days: number;
  notification_email?: string;
}

export interface AuditScheduleOut {
  schedule_id: string;
  name: string;
  categories: string[];
  format: string;
  schedule_cron: string;
  rolling_window_days: number;
  notification_email: string | null;
  status: "active" | "paused" | "deleted";
  last_run_at: number | null;
  next_run_at: number | null;
  last_export_id: string | null;
  created_at: number;
  created_by: string;
}
```

### 5.5 Route and Sidebar Integration

```typescript
// App.tsx additions
<Route path="/admin/audit-export" element={<AuditExport />} />
<Route path="/admin/audit-events" element={<AuditEventViewer />} />
```

Sidebar: `ScrollText` icon under Admin group in `Sidebar.tsx` and `AppShell.tsx`.

---

## 6. DynamoDB Table Definitions

### 6.1 New Tables for `scripts/local-ddb-init.py`

```python
TableDef("audit_exports", pk="export_id", sk="sk",
    gsis=[
        GSIDef("status-created-index", pk="status", sk="created_at"),
        GSIDef("user-created-index", pk="created_by", sk="created_at"),
    ],
    attr_types={"created_at": "N"}),
```

### 6.2 Audit Exports Table Item Schema

| Attribute | Type | Description |
|-----------|------|-------------|
| `export_id` | S (PK) | `exp_{uuid_hex}` |
| `sk` | S (SK) | Always `"META"` |
| `status` | S | `pending`, `processing`, `completed`, `failed`, `deleted` |
| `categories` | L | List of category strings |
| `format` | S | `csv`, `ndjson` |
| `from_date` | N | Unix timestamp start |
| `to_date` | N | Unix timestamp end |
| `created_by` | S | User sub who created the export |
| `created_at` | N | Unix timestamp of creation |
| `started_at` | N | Unix timestamp when processing began |
| `completed_at` | N | Unix timestamp when processing finished |
| `actor_filter` | S | Actor user sub filter (empty if none) |
| `target_filter` | S | Target user sub filter (empty if none) |
| `event_actions_filter` | L | List of event action filters |
| `event_count` | N | Total events in the export |
| `events_scanned` | N | Events scanned so far (progress) |
| `events_written` | N | Events written so far (progress) |
| `file_size_bytes` | N | Size of the export file |
| `download_url` | S | S3 presigned download URL |
| `download_expires_at` | N | When the presigned URL expires |
| `manifest_sha256` | S | SHA-256 hash of the data file |
| `s3_key` | S | S3 object key for the data file |
| `manifest_s3_key` | S | S3 object key for the manifest |
| `error_message` | S | Error message if failed |
| `attempt_count` | N | Number of processing attempts |
| `max_attempts` | N | Maximum processing attempts |
| `deleted_at` | N | When the export was deleted |
| `deleted_by` | S | Who deleted the export |

### 6.3 Settings Additions for `app/core/settings.py`

```python
# Audit Export (ENTERPRISE-004)
audit_export_enabled: bool = os.environ.get("AUDIT_EXPORT_ENABLED", "1") not in ("0", "false", "False")
audit_exports_table_name: str = os.environ.get("AUDIT_EXPORTS_TABLE_NAME", "audit_exports")
audit_export_s3_bucket: str = os.environ.get("AUDIT_EXPORT_S3_BUCKET", "audit-exports")
audit_export_url_ttl_seconds: int = int(os.environ.get("AUDIT_EXPORT_URL_TTL_SECONDS", "86400"))
audit_export_max_events: int = int(os.environ.get("AUDIT_EXPORT_MAX_EVENTS", "10000000"))
audit_export_max_date_range_days: int = int(os.environ.get("AUDIT_EXPORT_MAX_DATE_RANGE_DAYS", "365"))
audit_export_worker_enabled: bool = os.environ.get("AUDIT_EXPORT_WORKER_ENABLED", "1") not in ("0", "false", "False")
audit_export_worker_poll_interval_seconds: int = int(os.environ.get("AUDIT_EXPORT_WORKER_POLL_INTERVAL", "15"))
audit_export_worker_max_concurrent: int = int(os.environ.get("AUDIT_EXPORT_WORKER_MAX_CONCURRENT", "2"))
audit_export_signing_key: str = os.environ.get("AUDIT_EXPORT_SIGNING_KEY", "dev-audit-export-signing-key")
audit_export_signing_key_id: str = os.environ.get("AUDIT_EXPORT_SIGNING_KEY_ID", "audit-key-v1")
```

### 6.4 Tables Dataclass Addition

```python
# app/core/tables.py addition
audit_exports=ddb.Table(S.audit_exports_table_name),
```

### 6.5 AdminScope Enum Addition

```python
# app/auth/roles.py addition
class AdminScope(str, Enum):
    ...
    AUDIT_EXPORT = "audit_export"
```

---

## 7. E2E Test Plan

### 7.1 Test File

**File**: `frontend/e2e/audit-export.spec.ts` (new)

### 7.2 Test Sections

| Section | Tests | Description |
|---------|-------|-------------|
| 99 | 4 | Audit events query API (list events, filter by category, filter by actor, filter by date range) |
| 100 | 3 | Audit export categories API (list categories, event summary by category, empty range) |
| 101 | 5 | Export job API (create CSV export, create JSON export, list jobs, get job status, download) |
| 102 | 3 | Export verification API (verify valid manifest, detect tampered file, expired download) |
| 103 | 4 | Scheduled exports API (create schedule, list schedules, update schedule, delete schedule) |
| 104 | 3 | Audit export UI (filter panel, export button, download link) |
| 105 | 2 | Access control (non-admin user gets 403, admin with wrong scope gets 403) |

### 7.3 Test Setup

```typescript
// frontend/e2e/audit-export.spec.ts

import { test, expect, type Page, type BrowserContext } from "@playwright/test";

const ROOT_ID = "root";
const ALICE_ID = "alice";
const ROOT_SUB = "root.admin@testdev.local";
const ALICE_SUB = "e2e_alice@test.local";

// Import session helpers from admin tests
import { sessions, injectAuth } from "./helpers/auth";

let rootPage: Page;
let alicePage: Page;
const TS = Date.now();

test.beforeAll(async ({ browser }) => {
  // Create page contexts for root and alice
  const rootCtx = await browser.newContext();
  rootPage = await rootCtx.newPage();
  await injectAuth(rootPage, ROOT_ID);

  const aliceCtx = await browser.newContext();
  alicePage = await aliceCtx.newPage();
  await injectAuth(alicePage, ALICE_ID);

  // Generate audit events by performing auditable actions:
  // 1. Alice navigates to messages (creates session audit event)
  await alicePage.goto("/messages");
  await alicePage.waitForLoadState("domcontentloaded");

  // 2. Root navigates to admin (creates session audit event)
  await rootPage.goto("/admin");
  await rootPage.waitForLoadState("domcontentloaded");

  // Wait for events to be recorded in DDB
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  await sleep(2000);
});

// ─── Section 99: Audit Events Query API ───────────────────────────────────

test.describe("99 · Audit events query API", () => {
  test("99.1 · list events returns recent audit events", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await rootPage.request.get("/v1/admin/audit/events", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      params: {
        categories: "auth",
        from_date: now - 86400,
        to_date: now,
        limit: 10,
      },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.events).toBeDefined();
    expect(Array.isArray(data.events)).toBe(true);
    expect(data.count).toBeGreaterThanOrEqual(0);
  });

  test("99.2 · filter by category returns only matching events", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await rootPage.request.get("/v1/admin/audit/events", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      params: {
        categories: "moderation",
        from_date: now - 86400,
        to_date: now,
        limit: 50,
      },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    for (const evt of data.events) {
      expect(evt.event_type).toBe("moderation");
    }
  });

  test("99.3 · filter by actor returns only that actor's events", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await rootPage.request.get("/v1/admin/audit/events", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      params: {
        categories: "auth",
        from_date: now - 86400,
        to_date: now,
        actor_user_id: ALICE_SUB,
        limit: 50,
      },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    for (const evt of data.events) {
      expect(evt.actor_user_id).toBe(ALICE_SUB);
    }
  });

  test("99.4 · invalid category returns 400", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await rootPage.request.get("/v1/admin/audit/events", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      params: {
        categories: "nonexistent_category",
        from_date: now - 86400,
        to_date: now,
      },
    });
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 100: Audit Export Categories API ─────────────────────────────

test.describe("100 · Audit export categories API", () => {
  test("100.1 · list categories returns all 5 categories", async () => {
    const resp = await rootPage.request.get("/v1/admin/audit/events/categories", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.categories.length).toBe(5);
    const names = data.categories.map((c: any) => c.name);
    expect(names).toContain("auth");
    expect(names).toContain("moderation");
    expect(names).toContain("broadcast");
    expect(names).toContain("admin");
    expect(names).toContain("billing");
  });

  test("100.2 · event summary returns counts per category", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await rootPage.request.get("/v1/admin/audit/events/summary", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      params: { from_date: now - 86400, to_date: now },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.summary.length).toBe(5);
    for (const cat of data.summary) {
      expect(cat.category).toBeTruthy();
      expect(typeof cat.event_count).toBe("number");
    }
  });

  test("100.3 · empty date range returns zero counts", async () => {
    const resp = await rootPage.request.get("/v1/admin/audit/events/summary", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      params: { from_date: 100, to_date: 200 },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    for (const cat of data.summary) {
      expect(cat.event_count).toBe(0);
    }
  });
});

// ─── Section 101: Export Job API ──────────────────────────────────────────

test.describe("101 · Export job API", () => {
  let csvExportId: string;
  let jsonExportId: string;

  test("101.1 · create CSV export job", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await rootPage.request.post("/v1/admin/audit/exports", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      data: {
        categories: ["auth"],
        format: "csv",
        from_date: now - 86400,
        to_date: now,
      },
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.export_id).toMatch(/^exp_/);
    expect(data.status).toBe("pending");
    expect(data.format).toBe("csv");
    csvExportId = data.export_id;
  });

  test("101.2 · create NDJSON export job", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await rootPage.request.post("/v1/admin/audit/exports", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      data: {
        categories: ["auth", "moderation", "billing"],
        format: "ndjson",
        from_date: now - 7 * 86400,
        to_date: now,
      },
    });
    expect(resp.status()).toBe(201);
    const data = await resp.json();
    expect(data.export_id).toMatch(/^exp_/);
    jsonExportId = data.export_id;
  });

  test("101.3 · list export jobs includes created exports", async () => {
    const resp = await rootPage.request.get("/v1/admin/audit/exports", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
    });
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.exports.length).toBeGreaterThanOrEqual(2);
    const ids = data.exports.map((e: any) => e.export_id);
    expect(ids).toContain(csvExportId);
    expect(ids).toContain(jsonExportId);
  });

  test("101.4 · get export by ID returns correct status", async () => {
    const resp = await rootPage.request.get(
      `/v1/admin/audit/exports/${csvExportId}`,
      { headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token } }
    );
    expect(resp.status()).toBe(200);
    const data = await resp.json();
    expect(data.export_id).toBe(csvExportId);
    expect(["pending", "processing", "completed"]).toContain(data.status);
  });

  test("101.5 · date range > 365 days returns 400", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await rootPage.request.post("/v1/admin/audit/exports", {
      headers: { "x-csrf-token": sessions[ROOT_ID].csrf_token },
      data: {
        categories: ["auth"],
        format: "ndjson",
        from_date: now - 400 * 86400,
        to_date: now,
      },
    });
    expect(resp.status()).toBe(400);
  });
});

// ─── Section 105: Access Control ──────────────────────────────────────────

test.describe("105 · Access control", () => {
  test("105.1 · non-admin user gets 403", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await alicePage.request.get("/v1/admin/audit/events", {
      headers: { "x-csrf-token": sessions[ALICE_ID].csrf_token },
      params: { categories: "auth", from_date: now - 86400, to_date: now },
    });
    expect(resp.status()).toBe(403);
  });

  test("105.2 · non-admin user cannot create exports", async () => {
    const now = Math.floor(Date.now() / 1000);
    const resp = await alicePage.request.post("/v1/admin/audit/exports", {
      headers: { "x-csrf-token": sessions[ALICE_ID].csrf_token },
      data: {
        categories: ["auth"],
        format: "ndjson",
        from_date: now - 86400,
        to_date: now,
      },
    });
    expect(resp.status()).toBe(403);
  });
});
```

---

## 8. Edge Cases & Error Handling

### 8.1 Large Date Ranges

Exports spanning >365 days are rejected with 400. For compliance needs requiring multi-year exports, the admin must create multiple exports and concatenate them.

### 8.2 DynamoDB Scan Limits

Each adapter paginates through DynamoDB using `LastEvaluatedKey`. A single export job may require thousands of DynamoDB pages. The worker tracks progress (`events_scanned`, `events_written`) and updates the job record periodically.

**Important**: DynamoDB returns up to 1MB per page before applying `FilterExpression`. For sparse tables (e.g., billing ledger filtered by date), a single page may return zero matching items even though more pages exist. All adapters must loop on `LastEvaluatedKey` until it is absent, not until zero results are returned.

### 8.3 Empty Exports

If no events match the filters, the export completes with `event_count=0`. The file contains only headers (CSV) or is empty (NDJSON). The manifest reflects `event_count: 0`.

### 8.4 Concurrent Export Limit

At most `audit_export_worker_max_concurrent` (default 2) export jobs run simultaneously. Additional jobs queue as `pending` and are picked up when a slot opens.

### 8.5 Export Retention

Completed export files in S3 are retained for 30 days (configurable). After TTL, the S3 object is deleted and the job record `download_url` becomes null. The manifest and metadata remain in DynamoDB for audit trail purposes.

### 8.6 Interrupted Exports

If the worker crashes mid-export, the job remains in `processing` status. On restart, the worker detects stale `processing` jobs (>1 hour old) and resets them to `pending` for retry. Each job has a `max_attempts` field (default 3).

### 8.7 Timezone Handling

All timestamps in the unified schema use UTC (ISO 8601 with `Z` suffix). DynamoDB stores Unix timestamps (integers). The adapter converts using `datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()`. The frontend date range picker sends UTC timestamps.

### 8.8 Decimal Coercion

DynamoDB returns `Decimal` for all numeric values. The billing adapter must coerce `amount_cents` from `Decimal` to `int` before JSON serialization, as `json.dumps` does not handle `Decimal` natively. The `to_ndjson_line` method uses `default=str` as a safety net.

### 8.9 ISO vs Unix Timestamp Inconsistency

Different source tables use different timestamp formats:
- `T.alerts` uses Unix seconds (integer) in `ts`
- `T.moderation_audit_log` uses string representation of Unix seconds in `created_at`
- `T.broadcast_action_audit` uses ISO 8601 strings in `created_at`
- `T.role_audit` uses Unix seconds (integer) in `timestamp`
- `T.billing` uses Unix seconds (integer) in `created_at`

Each adapter's `_item_to_event` method handles the conversion appropriate to its source format. The `BaseAuditAdapter._ts_to_iso` and `_ts_to_unix` helper methods detect the format and convert accordingly.

### 8.10 Presigned URL Regeneration

When a download URL expires (after 24 hours by default), the download endpoint regenerates a fresh presigned URL from the stored S3 key. The caller is transparently redirected to the new URL.

---

## 9. Security Considerations

### 9.1 Access Control

Only ROOT and ADMIN users with the `AUDIT_EXPORT` scope (new scope to be added to `AdminScope` enum) can access audit export endpoints. The export creation itself is audited:

```python
audit_event("audit_export_created", ctx["user_sub"], request,
    export_id=export_id,
    categories=body.categories,
    date_range=f"{body.from_date}-{body.to_date}",
)
```

### 9.2 PII in Audit Logs

Audit events may contain PII (email addresses, IP addresses). The export manifest includes a `contains_pii: true` flag. Exports are encrypted at rest in S3 (SSE-S3). Presigned download URLs are time-limited (24 hours by default).

### 9.3 Tamper Detection

The manifest's `file_sha256` is computed before upload. The HMAC signature covers the entire manifest (excluding the `signature` field). Verification endpoint re-computes the hash from the S3 object and validates the HMAC.

### 9.4 Export Audit Trail

All export operations are themselves audited (export created, downloaded, deleted, schedule created). This prevents an admin from exporting sensitive data and deleting the evidence.

### 9.5 Rate Limiting

Export creation is rate-limited to 10 exports per admin per hour to prevent abuse. The rate limit key is `AUDIT_EXPORT#{admin_sub}`. Implementation uses a GSI query on `created_by + created_at` to count recent exports.

### 9.6 S3 Bucket Security

The audit export S3 bucket uses:
- Server-side encryption (SSE-S3)
- Bucket policy denying public access
- Versioning enabled (for tamper detection)
- Object lock (compliance mode) for retention enforcement
- VPC endpoint access only in production

### 9.7 Cross-Tenant Isolation

When multi-tenancy is enabled (ENTERPRISE-001), the export pipeline automatically scopes all adapter queries to the requesting tenant. The `tenant_id` field on `UnifiedAuditEvent` is populated from the request context. A ROOT admin in tenant A cannot export audit events from tenant B.

### 9.8 Manifest Signing Key Rotation

The `audit_export_signing_key_id` tracks which key was used to sign each manifest. When rotating signing keys, old manifests remain verifiable by storing a map of `key_id -> key` in settings. The verification endpoint looks up the signing key by `signing_key_id` from the manifest.

---

## 10. Compliance Mappings

### 10.1 SOC 2 Type II

| SOC 2 Criteria | Audit Export Coverage |
|---|---|
| CC6.1 (Logical access) | Auth events: login, logout, MFA changes, failed login attempts |
| CC6.2 (Access modifications) | Admin events: role grant, role revoke, impersonation |
| CC6.3 (System access) | Session events: creation, revocation, expiry |
| CC7.2 (Monitoring) | Moderation events: content review, ban, warning |
| CC8.1 (Change management) | Admin events: settings changes, feature flag toggles |

### 10.2 GDPR Article 15 (Right of Access)

The audit export supports filtering by `target_user_id`, allowing a data subject to request all audit events where they were the target. This supplements the existing privacy export (PRIVACY-001) with action-level detail.

### 10.3 ISO 27001 Control A.12.4

Audit log protection controls:
- Logs are stored in DynamoDB with no user-level delete access
- Exports are signed and hash-verified
- Export operations are themselves audited
- Retention periods are configurable per compliance requirement

---

## 11. Migration Plan

### 11.1 Phase 1: Unified Schema & Adapters (Week 1)

1. Define `UnifiedAuditEvent` dataclass in `app/services/audit_export.py`
2. Implement `BaseAuditAdapter` with pagination helpers
3. Implement all 5 source adapters (`AlertsAdapter`, `ModerationAuditAdapter`, `BroadcastAuditAdapter`, `RoleAuditAdapter`, `BillingLedgerAdapter`)
4. Unit tests for adapter normalization (verify ISO timestamps, field mapping, filter correctness)

### 11.2 Phase 2: Export Pipeline (Week 2)

1. Create `audit_exports` DDB table in `scripts/local-ddb-init.py`
2. Add `audit_exports` table handle to `app/core/tables.py`
3. Add settings to `app/core/settings.py`
4. Implement sync export (streaming CSV/JSON for small datasets)
5. Implement async export worker with S3 upload
6. Implement manifest generation with HMAC signing
7. Register worker startup in `app/main.py`

### 11.3 Phase 3: API & Scheduling (Week 3)

1. Add `AUDIT_EXPORT` to `AdminScope` enum
2. Add Pydantic request/response models to `app/models.py`
3. Implement `audit_export.py` router with all endpoints
4. Register router in `app/main.py`
5. Add `audit_export` executor to unified scheduler `_EXECUTORS`
6. Implement scheduled export CRUD endpoints

### 11.4 Phase 4: Frontend & E2E (Week 4)

1. Add TypeScript types to `frontend/src/api/types.ts`
2. Add API endpoints to `frontend/src/api/endpoints/audit.ts`
3. Build `AuditExport.tsx` page with filters, export table, and schedule management
4. Build `AuditEventViewer.tsx` page with infinite scroll and metadata expansion
5. Add routes to `App.tsx` and sidebar entries

---

## Codebase References

| Ref | File | Line(s) | Status |
|-----|------|---------|--------|
| `audit_event` | `app/services/alerts.py` | 695 | VERIFIED (ticket said 570) |
| IP/user_agent enrichment | `app/services/alerts.py` | 703-705 | VERIFIED (ticket said 578-580) |
| Impersonation context | `app/services/alerts.py` | 706-712 | VERIFIED (ticket said 581-593) |
| `write_moderation_audit_event` | `app/services/moderation_audit_log.py` | 10 | VERIFIED |
| `record_broadcast_action` | `app/services/broadcast_audit.py` | 45 | VERIFIED |
| `query_broadcast_actions` | `app/services/broadcast_audit.py` | 68 | VERIFIED |
| `role_audit` table handle | `app/core/tables.py` | 17 (field), 141 (init) | VERIFIED (ticket said 119) |
| CSV export router | `app/routers/csv_export.py` | 22 | VERIFIED |
| `require_ui_session` | `app/services/sessions.py` | 283 | VERIFIED (NOT in app/auth/deps.py) |
| Settings: alerts_table_name | `app/core/settings.py` | 76 | VERIFIED |
| Settings: role_audit_table_name | `app/core/settings.py` | 43 | VERIFIED |
| Settings: broadcast_action_audit | `app/core/settings.py` | 459 | VERIFIED |
| Settings: moderation_audit_log | `app/core/settings.py` | 566 | VERIFIED |
| Settings: billing_table_name | `app/core/settings.py` | 321 | VERIFIED |
| Settings: compliance export | `app/core/settings.py` | 690-693 | VERIFIED |
| `start_unified_scheduler_task` | `app/main.py` | 466 | VERIFIED (ticket said 437) |
| `start_webhook_dispatcher_task` | `app/main.py` | 472 | VERIFIED (ticket said 443) |
| Audit export service | `app/services/audit_export.py` | exists | VERIFIED |
| Audit export pipeline | `app/services/audit_export_pipeline.py` | exists | VERIFIED |
| Audit export router | `app/routers/audit_export.py` | exists, registered at `app/main.py:157,448` | VERIFIED |
| Frontend audit API | `frontend/src/api/endpoints/audit-export.ts` | exists | VERIFIED |
6. Write E2E test suite (`frontend/e2e/audit-export.spec.ts`)
