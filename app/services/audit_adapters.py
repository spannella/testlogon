"""Audit source adapters for ENTERPRISE-004 unified audit log export."""
from __future__ import annotations

import abc
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterator, Optional

from boto3.dynamodb.conditions import Attr, Key

from app.core.tables import T
from app.services.audit_export import UnifiedAuditEvent

logger = logging.getLogger(__name__)


class BaseAuditAdapter(abc.ABC):
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
        ...

    def _ts_to_iso(self, ts: int | float | str | Decimal) -> str:
        if isinstance(ts, str):
            if ts.replace(".", "").isdigit():
                ts = float(ts)
            else:
                return ts
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")

    def _ts_to_unix(self, ts: int | float | str | Decimal) -> int:
        if isinstance(ts, (int, float, Decimal)):
            return int(ts)
        if isinstance(ts, str):
            if ts.replace(".", "").isdigit():
                return int(float(ts))
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return int(dt.timestamp())
            except Exception:
                return 0
        return 0

    def _paginate_query(self, table: Any, **kwargs: Any) -> Iterator[dict]:
        while True:
            resp = table.query(**kwargs)
            for item in resp.get("Items", []):
                yield item
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key

    def _paginate_scan(self, table: Any, **kwargs: Any) -> Iterator[dict]:
        while True:
            resp = table.scan(**kwargs)
            for item in resp.get("Items", []):
                yield item
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            kwargs["ExclusiveStartKey"] = last_key


class AlertsAdapter(BaseAuditAdapter):
    source_table = "alerts"
    event_type = "auth"

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
            filter_expr = Attr("ts").between(from_ts, to_ts)
            if event_actions:
                filter_expr = filter_expr & Attr("event").is_in(event_actions)
            if target:
                filter_expr = filter_expr & (
                    Attr("effective_sub").eq(target) | Attr("user_sub").eq(target)
                )
            for item in self._paginate_scan(T.alerts, FilterExpression=filter_expr):
                evt = self._item_to_event(item)
                if evt:
                    yield evt
                    count += 1
                    if count >= limit:
                        return

    def _item_to_event(self, item: dict) -> Optional[UnifiedAuditEvent]:
        event_name = item.get("event", "")
        ts = item.get("ts", 0)
        impersonation_ctx = None
        if item.get("actor_sub") or item.get("impersonation_id"):
            impersonation_ctx = {
                "actor_sub": item.get("actor_sub", ""),
                "effective_sub": item.get("effective_sub", ""),
                "impersonation_id": item.get("impersonation_id", ""),
            }
        metadata: dict[str, Any] = {}
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
        for item in self._paginate_scan(T.moderation_audit_log, FilterExpression=filter_expr):
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
        for item in self._paginate_scan(T.role_audit, FilterExpression=filter_expr):
            evt = self._item_to_event(item)
            if evt:
                yield evt
                count += 1
                if count >= limit:
                    return

    def _item_to_event(self, item: dict) -> Optional[UnifiedAuditEvent]:
        ts = item.get("timestamp", 0)
        metadata: dict[str, Any] = {}
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
            filter_expr = (
                Attr("sk").begins_with("LEDGER#")
                & Attr("created_at").between(from_ts, to_ts)
            )
            if target:
                filter_expr = filter_expr & Attr("target_user").eq(target)
            if event_actions:
                filter_expr = filter_expr & Attr("reason").is_in(event_actions)
            for item in self._paginate_scan(T.billing, FilterExpression=filter_expr):
                user_sub = item.get("pk", "").replace("USER#", "")
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
        metadata: dict[str, Any] = {
            "type": item.get("type", ""),
            "amount_cents": amount,
            "reason": item.get("reason", ""),
            "currency": item.get("currency", "usd"),
        }
        if item.get("resource_type"):
            metadata["resource_type"] = item["resource_type"]
        if item.get("resource_id"):
            metadata["resource_id"] = item["resource_id"]
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


# ---- Adapter Registry ----

ADAPTERS: dict[str, BaseAuditAdapter] = {
    "auth": AlertsAdapter(),
    "moderation": ModerationAuditAdapter(),
    "broadcast": BroadcastAuditAdapter(),
    "admin": RoleAuditAdapter(),
    "billing": BillingLedgerAdapter(),
}

VALID_CATEGORIES = set(ADAPTERS.keys())
