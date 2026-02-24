from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.tables import T
from app.services.alerts import audit_event
from app.services.entitlements_service import EntitlementsService
from app.services.subscription_cycle_orders import TableBackedEntitlementsRepository

TERMINAL_PAYMENT_SUCCESS = {"paid", "captured", "succeeded"}
BILLABLE_MODELS = {"one_time", "subscription", "rental"}


class CommerceEntitlementOrchestrator:
    """Coordinates entitlement grants for canonical commerce orders with idempotent triggers."""

    def __init__(self, *, entitlements_service: Optional[EntitlementsService] = None, dead_letter_table: Any = None) -> None:
        self.entitlements_service = entitlements_service or EntitlementsService(TableBackedEntitlementsRepository())
        self.dead_letter_table = dead_letter_table or T.purchase_events
        self._processed_triggers: Dict[str, Dict[str, Any]] = {}
        self._failed_orders: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _trigger_key(*, source_system: str, trigger_event_id: str) -> str:
        return f"{source_system}:{trigger_event_id}"

    @staticmethod
    def _dead_letter_pk(source_system: str) -> str:
        return f"ENTITLEMENT_DLQ#{source_system}"

    @staticmethod
    def _dead_letter_sk(ts: int, order_id: str, trigger_event_id: str) -> str:
        return f"DLQ#{ts}#{order_id}#{trigger_event_id}"

    @staticmethod
    def _extract_cart_id(trigger_event_id: str) -> Optional[str]:
        parts = str(trigger_event_id or "").split(":")
        if len(parts) >= 4 and parts[0] == "cart_purchase":
            return parts[2]
        return None

    @staticmethod
    def _is_terminal_success(order: Dict[str, Any]) -> bool:
        status = str(order.get("status") or "").lower()
        if status in TERMINAL_PAYMENT_SUCCESS:
            return True
        metadata = dict(order.get("metadata") or {})
        payment_status = str(metadata.get("payment_status") or "").lower()
        return payment_status in TERMINAL_PAYMENT_SUCCESS

    @staticmethod
    def _is_billable_item(item: Dict[str, Any]) -> bool:
        billing_model = str(item.get("billing_model") or "").strip().lower()
        if billing_model and billing_model not in BILLABLE_MODELS:
            return False
        if not billing_model:
            billing_model = "one_time"

        if billing_model not in BILLABLE_MODELS:
            return False

        amount = int(item.get("unit_price_cents") or item.get("amount_cents") or 0)
        if amount > 0:
            return True

        pricing_ref = dict(item.get("pricing_ref") or {})
        if int(pricing_ref.get("amount_cents") or 0) > 0:
            return True
        return False

    def _load_order_context(self, order_id: str) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        order = self.entitlements_service.repo.get_order(order_id)
        if not order:
            raise ValueError("order not found")
        items = self.entitlements_service.repo.get_order_items(order_id)
        if not items:
            raise ValueError("order has no items")
        return dict(order), [dict(it) for it in items]

    def _persist_dead_letter(self, *, order_id: str, source_system: str, trigger_event_id: str, user_id: str, reason: str) -> Dict[str, Any]:
        ts = int(time.time())
        row = {
            "pk": self._dead_letter_pk(source_system),
            "sk": self._dead_letter_sk(ts, order_id, trigger_event_id),
            "dead_lettered_at": ts,
            "order_id": order_id,
            "source_system": source_system,
            "trigger_event_id": trigger_event_id,
            "cart_id": self._extract_cart_id(trigger_event_id),
            "user_id": user_id,
            "status": "dead_lettered",
            "owner_team": "commerce_platform",
            "remediation_hint": "replay_cart_entitlement_dead_letters",
            "failure_reason": reason,
            "attempt_count": 1,
            "last_attempt_at": ts,
        }
        self.dead_letter_table.put_item(Item=row)
        return row

    def _load_all_dead_letters(self, *, source_system: str = "shopping_cart") -> List[Dict[str, Any]]:
        try:
            resp = self.dead_letter_table.query(KeyConditionExpression=f"pk = '{self._dead_letter_pk(source_system)}'")
            items = list(resp.get("Items", []))
        except Exception:
            try:
                scan = self.dead_letter_table.scan()
                items = [
                    dict(it)
                    for it in scan.get("Items", [])
                    if str(it.get("pk") or "") == self._dead_letter_pk(source_system)
                ]
            except Exception:
                items = []
        return [dict(it) for it in items]

    def list_dead_letters_for_order(self, order_id: str, *, source_system: str = "shopping_cart") -> List[Dict[str, Any]]:
        return [row for row in self._load_all_dead_letters(source_system=source_system) if str(row.get("order_id") or "") == order_id]

    def list_dead_letters_for_cart(self, cart_id: str, *, source_system: str = "shopping_cart") -> List[Dict[str, Any]]:
        return [row for row in self._load_all_dead_letters(source_system=source_system) if str(row.get("cart_id") or "") == cart_id]

    def list_dead_letters_for_time_window(self, *, start_ts: int, end_ts: Optional[int] = None, source_system: str = "shopping_cart") -> List[Dict[str, Any]]:
        end = int(end_ts if end_ts is not None else start_ts)
        if end < start_ts:
            raise ValueError("end_ts must be >= start_ts")
        return [
            row
            for row in self._load_all_dead_letters(source_system=source_system)
            if start_ts <= int(row.get("dead_lettered_at") or 0) <= end
        ]

    def _replay_rows(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        replayed = 0
        processed = 0
        failed = 0
        for row in rows:
            replayed += 1
            out = self.process_order_entitlements(
                str(row.get("order_id") or ""),
                trigger_event_id=str(row.get("trigger_event_id") or f"replay:{row.get('order_id') or ''}"),
                source_system=str(row.get("source_system") or "shopping_cart"),
            )
            if out.get("status") in {"processed", "duplicate"}:
                processed += 1
            else:
                failed += 1
        return {"replayed": replayed, "processed": processed, "failed": failed}

    def replay_dead_letters_for_order(self, order_id: str, *, source_system: str = "shopping_cart") -> Dict[str, Any]:
        rows = [row for row in self.list_dead_letters_for_order(order_id, source_system=source_system) if str(row.get("status") or "") == "dead_lettered"]
        out = self._replay_rows(rows)
        return {"order_id": order_id, **out}

    def replay_dead_letters_for_cart(self, cart_id: str, *, source_system: str = "shopping_cart") -> Dict[str, Any]:
        rows = [row for row in self.list_dead_letters_for_cart(cart_id, source_system=source_system) if str(row.get("status") or "") == "dead_lettered"]
        out = self._replay_rows(rows)
        return {"cart_id": cart_id, **out}

    def replay_dead_letters_for_time_window(self, *, start_ts: int, end_ts: Optional[int] = None, source_system: str = "shopping_cart") -> Dict[str, Any]:
        rows = [row for row in self.list_dead_letters_for_time_window(start_ts=start_ts, end_ts=end_ts, source_system=source_system) if str(row.get("status") or "") == "dead_lettered"]
        out = self._replay_rows(rows)
        return {"start_ts": start_ts, "end_ts": int(end_ts if end_ts is not None else start_ts), **out}

    def process_order_entitlements(self, order_id: str, *, trigger_event_id: str, source_system: str) -> Dict[str, Any]:
        key = self._trigger_key(source_system=source_system, trigger_event_id=trigger_event_id)
        prior = self._processed_triggers.get(key)
        if prior is not None:
            return {
                "status": "duplicate",
                "order_id": order_id,
                "trigger_event_id": trigger_event_id,
                "source_system": source_system,
                "entitlement_count": int(prior.get("entitlement_count") or 0),
                "entitlement_ids": list(prior.get("entitlement_ids") or []),
                "gate": prior.get("gate"),
            }

        try:
            order, items = self._load_order_context(order_id)
            requires_payment = any(self._is_billable_item(item) for item in items)
            payment_satisfied = self._is_terminal_success(order)
            if requires_payment and not payment_satisfied:
                deferred = {
                    "order_id": order_id,
                    "source_system": source_system,
                    "trigger_event_id": trigger_event_id,
                    "entitlement_count": 0,
                    "entitlement_ids": [],
                    "gate": {
                        "requires_payment": True,
                        "payment_state": str(order.get("status") or "pending"),
                        "decision": "deferred",
                    },
                    "processed_at": datetime.now(timezone.utc).isoformat(),
                }
                self._processed_triggers[key] = deferred
                audit_event(
                    "commerce_entitlement_orchestration_deferred",
                    str(order.get("user_id") or "system"),
                    None,
                    outcome="info",
                    order_id=order_id,
                    source_system=source_system,
                    trigger_event_id=trigger_event_id,
                    payment_state=str(order.get("status") or "pending"),
                )
                return {"status": "deferred", **deferred}

            records = self.entitlements_service.grant_entitlement(order_id)
            event = {
                "order_id": order_id,
                "source_system": source_system,
                "trigger_event_id": trigger_event_id,
                "entitlement_count": len(records),
                "entitlement_ids": [r.entitlement_id for r in records],
                "gate": {
                    "requires_payment": requires_payment,
                    "payment_state": str(order.get("status") or "unknown"),
                    "decision": "granted",
                },
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }
            self._processed_triggers[key] = event
            self._failed_orders.pop(order_id, None)
            audit_event(
                "commerce_entitlement_orchestrated",
                str((records[0].user_id if records else order.get("user_id") or "system")),
                None,
                outcome="success",
                order_id=order_id,
                source_system=source_system,
                trigger_event_id=trigger_event_id,
                entitlement_count=len(records),
            )
            return {"status": "processed", **event}
        except Exception as exc:
            failure = {
                "order_id": order_id,
                "source_system": source_system,
                "trigger_event_id": trigger_event_id,
                "error": str(exc),
                "failed_at": datetime.now(timezone.utc).isoformat(),
            }
            self._failed_orders[order_id] = failure
            dead_letter = self._persist_dead_letter(
                order_id=order_id,
                source_system=source_system,
                trigger_event_id=trigger_event_id,
                user_id=str(self.entitlements_service.repo.get_order(order_id).get("user_id") if self.entitlements_service.repo.get_order(order_id) else "system"),
                reason=str(exc),
            )
            audit_event(
                "commerce_entitlement_orchestration_failed",
                str(dead_letter.get("user_id") or "system"),
                None,
                outcome="error",
                order_id=order_id,
                source_system=source_system,
                trigger_event_id=trigger_event_id,
                failure_reason=str(exc),
                owner_team=str(dead_letter.get("owner_team") or "commerce_platform"),
                remediation_hint=str(dead_letter.get("remediation_hint") or "replay_cart_entitlement_dead_letters"),
            )
            return {"status": "failed", **failure, "dead_letter": dead_letter}

    def replay_failed_order(self, order_id: str) -> Dict[str, Any]:
        failed = self._failed_orders.get(order_id)
        if failed is None:
            return {"status": "not_found", "order_id": order_id, "replayed": False}
        result = self.process_order_entitlements(
            order_id,
            trigger_event_id=str(failed.get("trigger_event_id") or f"replay:{order_id}"),
            source_system=str(failed.get("source_system") or "shopping_cart"),
        )
        return {"status": result.get("status"), "order_id": order_id, "replayed": True, "result": result}
