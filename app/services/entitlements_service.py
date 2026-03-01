from __future__ import annotations

import threading
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.services.alerts import audit_event
from app.services.entitlement_policy import CheckAccessResponse, ConsumeUsageResponse
from app.services.entitlements import EntitlementState, resolve_effective_status


@dataclass
class EntitlementRecord:
    entitlement_id: str
    user_id: str
    sku: str
    product_type: str
    status: str
    scope: Dict[str, Any]
    starts_at: datetime
    ends_at: Optional[datetime]
    usage_limit: int
    usage_consumed: int
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str]


class InMemoryEntitlementsRepository:
    def __init__(self) -> None:
        self.orders: Dict[str, Dict[str, Any]] = {}
        self.order_items: Dict[str, List[Dict[str, Any]]] = {}
        self.entitlements: Dict[str, EntitlementRecord] = {}
        self.idempotency: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def get_order(self, order_id: str) -> Optional[Dict[str, Any]]:
        return self.orders.get(order_id)

    def get_order_items(self, order_id: str) -> List[Dict[str, Any]]:
        return list(self.order_items.get(order_id, []))

    def put_entitlement(self, record: EntitlementRecord) -> None:
        self.entitlements[record.entitlement_id] = record

    def get_entitlement(self, entitlement_id: str) -> Optional[EntitlementRecord]:
        return self.entitlements.get(entitlement_id)

    def list_entitlements_for_subject(self, subject: str) -> List[EntitlementRecord]:
        return [e for e in self.entitlements.values() if e.user_id == subject]

    def consume_usage(self, *, entitlement_id: str, meter: str, amount: int, idempotency_key: str) -> ConsumeUsageResponse:
        with self._lock:
            prior = self.idempotency.get(idempotency_key)
            ent = self.entitlements[entitlement_id]
            if prior is not None:
                if prior["entitlement_id"] != entitlement_id or prior["meter"] != meter or prior["amount"] != amount:
                    return ConsumeUsageResponse(
                        consumed=False,
                        entitlement_id=entitlement_id,
                        usage_consumed=ent.usage_consumed,
                        usage_limit=ent.usage_limit,
                        reason_code="idempotency_conflict",
                        message="idempotency_key replay with different payload",
                    )
                prev_resp = prior["response"]
                return ConsumeUsageResponse(**{**prev_resp.__dict__, "replayed": True})

            if ent.usage_limit > 0 and ent.usage_consumed + amount > ent.usage_limit:
                resp = ConsumeUsageResponse(
                    consumed=False,
                    entitlement_id=entitlement_id,
                    usage_consumed=ent.usage_consumed,
                    usage_limit=ent.usage_limit,
                    reason_code="exhausted",
                    message="Usage amount exceeds remaining entitlement balance",
                )
                self.idempotency[idempotency_key] = {
                    "entitlement_id": entitlement_id,
                    "meter": meter,
                    "amount": amount,
                    "response": resp,
                }
                return resp

            ent.usage_consumed += amount
            ent.updated_at = datetime.now(timezone.utc)
            resp = ConsumeUsageResponse(
                consumed=True,
                entitlement_id=entitlement_id,
                usage_consumed=ent.usage_consumed,
                usage_limit=ent.usage_limit,
            )
            self.idempotency[idempotency_key] = {
                "entitlement_id": entitlement_id,
                "meter": meter,
                "amount": amount,
                "response": resp,
            }
            return resp


class EntitlementsService:
    def __init__(self, repository: InMemoryEntitlementsRepository) -> None:
        self.repo = repository

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def grant_entitlement(self, order_id: str) -> List[EntitlementRecord]:
        order = self.repo.get_order(order_id)
        if not order:
            raise ValueError("order not found")
        items = self.repo.get_order_items(order_id)
        if not items:
            raise ValueError("order has no items")

        now = datetime.now(timezone.utc)
        status = "active" if str(order.get("status", "")).lower() in {"paid", "captured", "succeeded"} else "pending_payment"
        out: List[EntitlementRecord] = []
        for idx, item in enumerate(items, start=1):
            starts_at = self._utc(item.get("starts_at") or now)
            ends_at_raw = item.get("ends_at")
            if ends_at_raw is None and item.get("rental_duration_hours"):
                ends_at_raw = starts_at + timedelta(hours=int(item.get("rental_duration_hours") or 0))
            ends_at = self._utc(ends_at_raw) if ends_at_raw else None
            stable_src = f"{order_id}:{item.get('item_id') or idx}:{item.get('sku') or ''}:{item.get('product_type') or ''}"
            entitlement_id = hashlib.sha256(stable_src.encode("utf-8")).hexdigest()[:32]
            rec = EntitlementRecord(
                entitlement_id=entitlement_id,
                user_id=str(order["user_id"]),
                sku=str(item["sku"]),
                product_type=str(item["product_type"]),
                status=status,
                scope=dict(item.get("scope") or {}),
                starts_at=starts_at,
                ends_at=ends_at,
                usage_limit=int(item.get("usage_limit") or 0),
                usage_consumed=0,
                created_at=now,
                updated_at=now,
                created_by=str(order.get("created_by") or "system"),
            )
            self.repo.put_entitlement(rec)
            out.append(rec)
            audit_event(
                "entitlement_granted",
                rec.user_id,
                None,
                outcome="success",
                entitlement_id=rec.entitlement_id,
                sku=rec.sku,
                product_type=rec.product_type,
                order_id=order_id,
            )
        return out

    def revoke_entitlement(self, entitlement_id: str, reason: str) -> EntitlementRecord:
        rec = self.repo.get_entitlement(entitlement_id)
        if rec is None:
            raise ValueError("entitlement not found")
        rec.status = "revoked"
        rec.updated_at = datetime.now(timezone.utc)
        audit_event(
            "entitlement_revoked",
            rec.user_id,
            None,
            outcome="success",
            entitlement_id=rec.entitlement_id,
            reason=reason,
        )
        return rec

    def _find_matching_entitlement(self, subject: str, action: str, resource: Dict[str, Any], *, ignore_resource: bool = False) -> Optional[EntitlementRecord]:
        entitlements = sorted(self.repo.list_entitlements_for_subject(subject), key=lambda x: x.entitlement_id)
        now = datetime.now(timezone.utc)
        for ent in entitlements:
            effective = resolve_effective_status(EntitlementState(status=ent.status, starts_at=ent.starts_at, ends_at=ent.ends_at), now=now)
            if effective != "active":
                continue
            allowed_actions = set(ent.scope.get("allowed_actions") or [])
            if action not in allowed_actions:
                continue
            constraints = dict(ent.scope.get("resource") or {})
            if (not ignore_resource) and any(resource.get(k) != v for k, v in constraints.items()):
                continue
            return ent
        return None

    def check_access(self, subject: str, action: str, resource: Dict[str, Any]) -> CheckAccessResponse:
        entitlements = sorted(self.repo.list_entitlements_for_subject(subject), key=lambda x: x.entitlement_id)
        if not entitlements:
            return CheckAccessResponse(allowed=False, entitlement_id=None, reason_code="denied", message="No entitlement for subject")

        now = datetime.now(timezone.utc)
        ent = self._find_matching_entitlement(subject, action, resource)
        if ent is not None:
            if ent.usage_limit > 0 and ent.usage_consumed >= ent.usage_limit:
                return CheckAccessResponse(allowed=False, entitlement_id=ent.entitlement_id, reason_code="exhausted", message="Entitlement usage exhausted")
            return CheckAccessResponse(allowed=True, entitlement_id=ent.entitlement_id)

        for cand in entitlements:
            effective = resolve_effective_status(EntitlementState(status=cand.status, starts_at=cand.starts_at, ends_at=cand.ends_at), now=now)
            if effective == "expired":
                return CheckAccessResponse(allowed=False, entitlement_id=cand.entitlement_id, reason_code="expired", message="Entitlement expired")
        return CheckAccessResponse(allowed=False, entitlement_id=entitlements[0].entitlement_id, reason_code="denied", message="Action/resource denied by entitlement scope")

    def consume_usage(self, subject: str, meter: str, amount: int, idempotency_key: str) -> ConsumeUsageResponse:
        if amount <= 0:
            raise ValueError("amount must be > 0")
        ent = self._find_matching_entitlement(subject, meter, {}, ignore_resource=True)
        if ent is None:
            access = self.check_access(subject, meter, {})
            return ConsumeUsageResponse(
                consumed=False,
                entitlement_id=access.entitlement_id,
                usage_consumed=0,
                usage_limit=0,
                reason_code=access.reason_code,
                message=access.message,
            )
        if ent.usage_limit > 0 and ent.usage_consumed >= ent.usage_limit:
            return ConsumeUsageResponse(consumed=False, entitlement_id=ent.entitlement_id, usage_consumed=ent.usage_consumed, usage_limit=ent.usage_limit, reason_code="exhausted", message="Entitlement usage exhausted")
        return self.repo.consume_usage(entitlement_id=ent.entitlement_id, meter=meter, amount=amount, idempotency_key=idempotency_key)
