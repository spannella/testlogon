from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from datetime import datetime, timezone

from boto3.dynamodb.conditions import Attr, Key

from app.core.tables import T
from app.services.alerts import audit_event
from app.services.commerce_order_service import commerce_order_service
from app.services.commercial_line_items import from_subscription_plan
from app.services.entitlements_service import EntitlementsService, InMemoryEntitlementsRepository
from app.services.payment_reconciliation import InMemoryPaymentReconciliationRepository, PaymentWebhookReconciliationService

logger = logging.getLogger(__name__)

SUBSCRIPTION_SYSTEM_PROVIDER = "subscription_system"


def _subscription_charge_event_id(invoice_id: str) -> str:
    return f"subscription_charge:{invoice_id}"


class CanonicalOrderEntitlementsRepository(InMemoryEntitlementsRepository):
    """Entitlements repository adapter that loads canonical order rows from commerce tables."""

    def __init__(self, *, orders_table: Any = None, order_items_table: Any = None) -> None:
        super().__init__()
        self.orders_table = orders_table or T.orders
        self.order_items_table = order_items_table or T.order_items

    def get_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        cached = super().get_order(order_id)
        if cached is not None:
            return cached
        try:
            item = self.orders_table.get_item(Key={"order_id": order_id}).get("Item")
        except Exception:
            item = None
        if item is None:
            return None
        self.orders[order_id] = dict(item)
        return self.orders[order_id]

    def get_order_items(self, order_id: str) -> List[Dict[str, Any]]:
        cached = super().get_order_items(order_id)
        if cached:
            return cached

        rows: List[Dict[str, Any]] = []
        try:
            resp = self.order_items_table.query(KeyConditionExpression=Key("order_id").eq(order_id))
            rows = [dict(it) for it in resp.get("Items", [])]
        except Exception:
            rows = []

        if not rows:
            try:
                scan = self.order_items_table.scan()
                rows = [dict(it) for it in scan.get("Items", []) if str(it.get("order_id") or "") == order_id]
            except Exception:
                rows = []

        self.order_items[order_id] = rows
        return list(rows)


class TableBackedEntitlementsRepository(CanonicalOrderEntitlementsRepository):
    """Repository adapter that persists entitlements into DynamoDB while reading canonical order rows."""

    def __init__(self, *, orders_table: Any = None, order_items_table: Any = None, entitlements_table: Any = None) -> None:
        super().__init__(orders_table=orders_table, order_items_table=order_items_table)
        self.entitlements_table = entitlements_table or T.entitlements

    @staticmethod
    def _serialize_record(record: Any) -> Dict[str, Any]:
        starts_at = record.starts_at.isoformat() if hasattr(record.starts_at, "isoformat") else record.starts_at
        ends_at = record.ends_at.isoformat() if record.ends_at and hasattr(record.ends_at, "isoformat") else record.ends_at
        created_at = record.created_at.isoformat() if hasattr(record.created_at, "isoformat") else record.created_at
        updated_at = record.updated_at.isoformat() if hasattr(record.updated_at, "isoformat") else record.updated_at
        return {
            "user_id": record.user_id,
            "entitlement_id": record.entitlement_id,
            "sku": record.sku,
            "product_type": record.product_type,
            "status": record.status,
            "scope": dict(record.scope or {}),
            "starts_at": starts_at,
            "ends_at": ends_at,
            "usage_limit": int(record.usage_limit),
            "usage_consumed": int(record.usage_consumed),
            "created_at": created_at,
            "updated_at": updated_at,
            "created_by": record.created_by,
        }

    @staticmethod
    def _to_utc_dt(value: Any) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            dt = value
        else:
            text = str(value).strip()
            if not text:
                return None
            if text.isdigit():
                dt = datetime.fromtimestamp(int(text), tz=timezone.utc)
            else:
                if text.endswith("Z"):
                    text = text[:-1] + "+00:00"
                dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @classmethod
    def _parse_record(cls, item: Dict[str, Any]) -> Any:
        from app.services.entitlements_service import EntitlementRecord

        starts_at = cls._to_utc_dt(item.get("starts_at")) or datetime.now(timezone.utc)
        ends_at = cls._to_utc_dt(item.get("ends_at"))
        created_at = cls._to_utc_dt(item.get("created_at")) or datetime.now(timezone.utc)
        updated_at = cls._to_utc_dt(item.get("updated_at")) or created_at

        return EntitlementRecord(
            entitlement_id=str(item.get("entitlement_id") or ""),
            user_id=str(item.get("user_id") or ""),
            sku=str(item.get("sku") or ""),
            product_type=str(item.get("product_type") or ""),
            status=str(item.get("status") or "pending_payment"),
            scope=dict(item.get("scope") or {}),
            starts_at=starts_at,
            ends_at=ends_at,
            usage_limit=int(item.get("usage_limit") or 0),
            usage_consumed=int(item.get("usage_consumed") or 0),
            created_at=created_at,
            updated_at=updated_at,
            created_by=item.get("created_by"),
        )

    def put_entitlement(self, record: Any) -> None:
        super().put_entitlement(record)
        item = self._serialize_record(record)
        try:
            self.entitlements_table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(entitlement_id)",
            )
        except Exception as exc:
            err = getattr(exc, "response", {}).get("Error", {}) if hasattr(exc, "response") else {}
            if err.get("Code") not in {"ConditionalCheckFailedException"}:
                raise

    def get_entitlement(self, entitlement_id: str) -> Optional[Any]:
        cached = super().get_entitlement(entitlement_id)
        if cached is not None:
            return cached
        try:
            resp = self.entitlements_table.scan(FilterExpression=Attr("entitlement_id").eq(entitlement_id), Limit=1)
            items = list(resp.get("Items", []))
        except Exception:
            items = []
        if not items:
            return None
        rec = self._parse_record(dict(items[0]))
        self.entitlements[rec.entitlement_id] = rec
        return rec

    def list_entitlements_for_subject(self, subject: str) -> List[Any]:
        cached = [e for e in self.entitlements.values() if e.user_id == subject]
        if cached:
            return list(cached)
        try:
            resp = self.entitlements_table.query(KeyConditionExpression=Key("user_id").eq(subject))
            items = list(resp.get("Items", []))
        except Exception:
            items = []
        out: List[Any] = []
        for item in items:
            rec = self._parse_record(dict(item))
            self.entitlements[rec.entitlement_id] = rec
            out.append(rec)
        return out


class SubscriptionCycleReconciliationGateway:
    """Adapter that posts normalized subscription-cycle charge events into payment reconciliation."""

    def __init__(self, *, entitlements_repo: Optional[InMemoryEntitlementsRepository] = None) -> None:
        self.entitlements_repo = entitlements_repo or TableBackedEntitlementsRepository()
        self.reconciliation_repo = InMemoryPaymentReconciliationRepository()
        self._service = PaymentWebhookReconciliationService(
            repository=self.reconciliation_repo,
            entitlements=EntitlementsService(self.entitlements_repo),
        )

    def _enrich_dead_letter_metadata(
        self,
        *,
        normalized_event: Any,
        payload: Dict[str, Any],
        reason: str,
    ) -> Dict[str, Any]:
        raw = dict(payload.get("raw") or {})
        invoice_id = str(raw.get("invoice_id") or "")
        subscription_id = str(raw.get("subscription_id") or "")
        owner_team = str(raw.get("owner_team") or "commerce_platform")
        remediation_hint = str(raw.get("remediation_hint") or "replay_recurring_grants_for_invoice_range")

        for row in reversed(self.reconciliation_repo.dead_letters):
            if str(row.get("provider_event_id") or "") == str(normalized_event.provider_event_id):
                row.update(
                    {
                        "order_id": normalized_event.order_id,
                        "invoice_id": invoice_id,
                        "subscription_id": subscription_id,
                        "provider_event_id": normalized_event.provider_event_id,
                        "owner_team": owner_team,
                        "remediation_hint": remediation_hint,
                        "dead_letter_reason": reason,
                    }
                )
                break

        return {
            "order_id": normalized_event.order_id,
            "invoice_id": invoice_id,
            "subscription_id": subscription_id,
            "provider_event_id": normalized_event.provider_event_id,
            "owner_team": owner_team,
            "remediation_hint": remediation_hint,
            "dead_letter_reason": reason,
        }

    def process_webhook_event(self, *, provider: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        normalized = self._service.normalize_event(provider=provider, payload=payload)
        order = self.entitlements_repo.get_order(normalized.order_id)
        items = self.entitlements_repo.get_order_items(normalized.order_id)
        if order is None or not items:
            reason = "missing_order" if order is None else "missing_order_items"
            self.reconciliation_repo.add_dead_letter(normalized, reason=reason)
            self.reconciliation_repo.mark_processed(normalized, outcome="dead_lettered")
            dead_letter_meta = self._enrich_dead_letter_metadata(normalized_event=normalized, payload=payload, reason=reason)
            audit_event(
                "subscription_cycle_reconciliation_invariant_failed",
                str((payload.get("raw") or {}).get("subscriber_id") or "system"),
                None,
                outcome="error",
                order_id=normalized.order_id,
                provider_event_id=normalized.provider_event_id,
                reason=reason,
                owner_team=dead_letter_meta["owner_team"],
                remediation_hint=dead_letter_meta["remediation_hint"],
            )
            return {
                "status": "dead_lettered",
                "order_id": normalized.order_id,
                "provider_event_id": normalized.provider_event_id,
                "reason": reason,
                "owner_team": dead_letter_meta["owner_team"],
                "invoice_id": dead_letter_meta["invoice_id"],
                "subscription_id": dead_letter_meta["subscription_id"],
                "remediation_hint": dead_letter_meta["remediation_hint"],
            }
        result = self._service.process_webhook_event(provider=provider, payload=payload)
        if str(result.get("status") or "").lower() == "dead_lettered":
            dead_letter_meta = self._enrich_dead_letter_metadata(
                normalized_event=normalized,
                payload=payload,
                reason=str(result.get("status") or "dead_lettered"),
            )
            audit_event(
                "subscription_cycle_reconciliation_dead_lettered",
                str((payload.get("raw") or {}).get("subscriber_id") or "system"),
                None,
                outcome="error",
                order_id=normalized.order_id,
                invoice_id=dead_letter_meta["invoice_id"],
                provider_event_id=normalized.provider_event_id,
                owner_team=dead_letter_meta["owner_team"],
                remediation_hint=dead_letter_meta["remediation_hint"],
            )
            result = {
                **result,
                "owner_team": dead_letter_meta["owner_team"],
                "invoice_id": dead_letter_meta["invoice_id"],
                "subscription_id": dead_letter_meta["subscription_id"],
                "provider_event_id": dead_letter_meta["provider_event_id"],
                "remediation_hint": dead_letter_meta["remediation_hint"],
            }
        return result

    def list_dead_letters_for_invoice_range(self, *, invoice_start: str, invoice_end: Optional[str] = None) -> List[Dict[str, Any]]:
        start = str(invoice_start or "").strip()
        end = str(invoice_end or "").strip() or start
        if not start:
            raise ValueError("invoice_start is required")
        if end < start:
            raise ValueError("invoice_end must be >= invoice_start")

        rows: List[Dict[str, Any]] = []
        for row in self.reconciliation_repo.dead_letters:
            invoice_id = str(row.get("invoice_id") or (dict(row.get("raw") or {}).get("raw") or {}).get("invoice_id") or "")
            if start <= invoice_id <= end:
                rows.append(dict(row))
        return rows

    def replay_dead_letters_for_invoice_range(self, *, invoice_start: str, invoice_end: Optional[str] = None) -> Dict[str, Any]:
        start = str(invoice_start or "").strip()
        end = str(invoice_end or "").strip() or start
        if not start:
            raise ValueError("invoice_start is required")
        if end < start:
            raise ValueError("invoice_end must be >= invoice_start")

        pending = list(self.reconciliation_repo.dead_letters)
        keep: List[Dict[str, Any]] = []
        selected: List[Dict[str, Any]] = []
        for row in pending:
            invoice_id = str(row.get("invoice_id") or (dict(row.get("raw") or {}).get("raw") or {}).get("invoice_id") or "")
            if start <= invoice_id <= end:
                selected.append(row)
            else:
                keep.append(row)

        self.reconciliation_repo.dead_letters = keep
        replayed = 0
        processed = 0
        failed = 0
        for row in selected:
            replayed += 1
            out = self.process_webhook_event(provider=str(row.get("provider") or SUBSCRIPTION_SYSTEM_PROVIDER), payload=dict(row.get("raw") or {}))
            if out.get("status") in {"processed", "duplicate"}:
                processed += 1
            else:
                failed += 1

        return {
            "invoice_start": start,
            "invoice_end": end,
            "replayed": replayed,
            "processed": processed,
            "failed": failed,
            "remaining_dead_letters": len(self.reconciliation_repo.dead_letters),
        }


default_reconciliation_gateway = SubscriptionCycleReconciliationGateway()


def emit_subscription_cycle_order(
    *,
    subscription: Dict[str, Any],
    plan: Dict[str, Any],
    invoice: Dict[str, Any],
    reconciliation_hook: Optional[Any] = None,
    enable_default_reconciliation: bool = True,
) -> Dict[str, Any]:
    subscription_id = str(subscription.get("subscription_id") or "")
    invoice_id = str(invoice.get("invoice_id") or invoice.get("provider_invoice_id") or "")
    subscriber_id = str(subscription.get("subscriber_id") or "")
    if not subscription_id or not invoice_id or not subscriber_id:
        raise ValueError("subscription_id, invoice_id, and subscriber_id are required")

    plan_payload = {
        "plan_id": str(plan.get("plan_id") or subscription.get("plan_id") or ""),
        "plan_version": int(plan.get("plan_version") or 1),
        "sku": str(plan.get("sku") or f"subscription_plan:{subscription.get('plan_id') or 'unknown'}"),
        "product_type": str(plan.get("product_type") or "internal_api_package"),
        "billing_model": "subscription",
        "interval": str(subscription.get("interval") or plan.get("interval") or "month"),
        "renewal_policy": str(subscription.get("renewal_policy") or "auto"),
        "subscription_id": subscription_id,
        "price_cents": int(invoice.get("amount_cents") or subscription.get("price_cents") or 0),
        "currency": str(invoice.get("currency") or subscription.get("currency") or "USD"),
        "scope": dict(plan.get("scope") or {}),
        "access_template": dict(plan.get("access_template") or {}),
        "limit_overrides": dict(plan.get("limit_overrides") or {}),
        "credit_grant": dict(plan.get("credit_grant") or {}),
        "current_period_start": invoice.get("period_start"),
        "current_period_end": invoice.get("period_end"),
    }
    line_item = from_subscription_plan(plan_payload)

    correlation_id = f"subscription_cycle:{subscription_id}:invoice:{invoice_id}"
    order = commerce_order_service.create_order_from_line_items(
        user_id=subscriber_id,
        source_system="subscription_cycle",
        line_items=[line_item.model_dump()],
        correlation_id=correlation_id,
        metadata={
            "subscription_id": subscription_id,
            "invoice_id": invoice_id,
            "provider_invoice_id": invoice.get("provider_invoice_id"),
            "event_kind": "subscription_charge",
        },
    )

    order_id = str(order.get("order_id") or "")
    reconciliation_result: Dict[str, Any] = {"status": "skipped", "reason": "disabled"}
    gateway = reconciliation_hook
    if gateway is None and enable_default_reconciliation:
        gateway = default_reconciliation_gateway

    if gateway is not None:
        normalized_event_id = _subscription_charge_event_id(invoice_id)
        payload = {
            "event_id": normalized_event_id,
            "order_id": order_id,
            "status": "succeeded",
            "occurred_at": invoice.get("created_at"),
                "raw": {
                    "subscription_id": subscription_id,
                    "subscriber_id": subscriber_id,
                    "invoice_id": invoice_id,
                    "owner_team": "commerce_platform",
                    "remediation_hint": "replay_recurring_grants_for_invoice_range",
                },
            }
        audit_event(
            "subscription_cycle_reconciliation_attempted",
            subscriber_id,
            None,
            outcome="info",
            order_id=order_id,
            subscription_id=subscription_id,
            invoice_id=invoice_id,
            normalized_event_id=normalized_event_id,
            failure_reason=None,
            provider=SUBSCRIPTION_SYSTEM_PROVIDER,
        )
        try:
            reconciliation_result = gateway.process_webhook_event(provider=SUBSCRIPTION_SYSTEM_PROVIDER, payload=payload)
            audit_event(
                "subscription_cycle_reconciliation_succeeded",
                subscriber_id,
                None,
                outcome="success",
                order_id=order_id,
                subscription_id=subscription_id,
                invoice_id=invoice_id,
                normalized_event_id=normalized_event_id,
                failure_reason=None,
                reconciliation_status=str(reconciliation_result.get("status") or "processed"),
            )
        except Exception as exc:
            reconciliation_result = {"status": "failed", "reason": str(exc)}
            logger.exception("subscription cycle reconciliation failed", extra={"order_id": order_id, "invoice_id": invoice_id})
            audit_event(
                "subscription_cycle_reconciliation_failed",
                subscriber_id,
                None,
                outcome="error",
                order_id=order_id,
                subscription_id=subscription_id,
                invoice_id=invoice_id,
                normalized_event_id=normalized_event_id,
                failure_reason=str(exc),
            )

    audit_event(
        "subscription_cycle_order_emitted",
        subscriber_id,
        None,
        outcome="success",
        order_id=order_id,
        subscription_id=subscription_id,
        invoice_id=invoice_id,
    )

    return {
        "order_id": order_id,
        "subscription_id": subscription_id,
        "invoice_id": invoice_id,
        "correlation_id": correlation_id,
        "reconciliation": reconciliation_result,
    }
