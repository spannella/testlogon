from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from app.services.alerts import audit_event
from app.services.entitlements_service import EntitlementsService

PaymentStatus = Literal[
    "pending",
    "succeeded",
    "failed",
    "refunded",
    "chargeback",
]

TERMINAL_SUCCESS = {"succeeded"}
TERMINAL_FAILURE = {"failed", "refunded", "chargeback"}


@dataclass(frozen=True)
class NormalizedPaymentEvent:
    provider: str
    provider_event_id: str
    order_id: str
    status: PaymentStatus
    occurred_at: datetime
    raw: Dict[str, Any]


class InMemoryPaymentReconciliationRepository:
    def __init__(self) -> None:
        self.payment_states: Dict[str, Dict[str, Any]] = {}
        self.processed_events: Dict[str, Dict[str, Any]] = {}
        self.dead_letters: List[Dict[str, Any]] = []

    @staticmethod
    def _event_key(provider: str, event_id: str) -> str:
        return f"{provider}:{event_id}"

    def mark_processed(self, evt: NormalizedPaymentEvent, *, outcome: str) -> bool:
        key = self._event_key(evt.provider, evt.provider_event_id)
        if key in self.processed_events:
            return False
        self.processed_events[key] = {
            "provider": evt.provider,
            "provider_event_id": evt.provider_event_id,
            "order_id": evt.order_id,
            "status": evt.status,
            "occurred_at": evt.occurred_at.isoformat(),
            "outcome": outcome,
        }
        return True

    def update_payment_state(self, evt: NormalizedPaymentEvent) -> None:
        self.payment_states[evt.order_id] = {
            "provider": evt.provider,
            "provider_event_id": evt.provider_event_id,
            "status": evt.status,
            "occurred_at": evt.occurred_at.isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def add_dead_letter(self, evt: NormalizedPaymentEvent, reason: str) -> None:
        self.dead_letters.append(
            {
                "provider": evt.provider,
                "provider_event_id": evt.provider_event_id,
                "order_id": evt.order_id,
                "status": evt.status,
                "occurred_at": evt.occurred_at.isoformat(),
                "reason": reason,
                "raw": evt.raw,
            }
        )

    def pop_dead_letters(self) -> List[Dict[str, Any]]:
        out = list(self.dead_letters)
        self.dead_letters.clear()
        return out


class PaymentWebhookReconciliationService:
    def __init__(self, *, repository: InMemoryPaymentReconciliationRepository, entitlements: EntitlementsService) -> None:
        self.repo = repository
        self.entitlements = entitlements

    @staticmethod
    def _utc(value: Any) -> datetime:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(int(value), tz=timezone.utc)
        else:
            text = str(value or "").strip()
            if not text:
                dt = datetime.now(timezone.utc)
            else:
                if text.isdigit():
                    dt = datetime.fromtimestamp(int(text), tz=timezone.utc)
                else:
                    if text.endswith("Z"):
                        text = text[:-1] + "+00:00"
                    dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def normalize_event(self, *, provider: str, payload: Dict[str, Any]) -> NormalizedPaymentEvent:
        p = provider.strip().lower()
        if p == "stripe":
            event_id = str(payload.get("id") or "")
            data_obj = payload.get("data", {}).get("object", {}) if isinstance(payload.get("data"), dict) else {}
            order_id = str(data_obj.get("metadata", {}).get("order_id") or data_obj.get("order_id") or "")
            kind = str(payload.get("type") or "")
            if kind in {"payment_intent.succeeded", "charge.succeeded", "checkout.session.completed"}:
                status: PaymentStatus = "succeeded"
            elif kind in {"charge.refunded"}:
                status = "refunded"
            elif kind in {"charge.dispute.funds_withdrawn", "charge.dispute.created"}:
                status = "chargeback"
            elif kind in {"payment_intent.payment_failed", "charge.failed"}:
                status = "failed"
            else:
                status = "pending"
            occurred_at = self._utc(payload.get("created")) if payload.get("created") else datetime.now(timezone.utc)
        elif p == "paypal":
            event_id = str(payload.get("id") or "")
            resource = payload.get("resource") if isinstance(payload.get("resource"), dict) else {}
            order_id = str(resource.get("custom_id") or resource.get("invoice_id") or "")
            kind = str(payload.get("event_type") or "")
            if kind in {"PAYMENT.CAPTURE.COMPLETED", "CHECKOUT.ORDER.APPROVED", "BILLING.SUBSCRIPTION.ACTIVATED"}:
                status = "succeeded"
            elif kind in {"PAYMENT.CAPTURE.REFUNDED", "BILLING.SUBSCRIPTION.CANCELLED"}:
                status = "refunded"
            elif kind in {"CUSTOMER.DISPUTE.CREATED"}:
                status = "chargeback"
            elif kind in {"PAYMENT.CAPTURE.DENIED", "PAYMENT.CAPTURE.DECLINED"}:
                status = "failed"
            else:
                status = "pending"
            occurred_at = self._utc(payload.get("create_time"))
        else:
            event_id = str(payload.get("event_id") or payload.get("id") or "")
            order_id = str(payload.get("order_id") or "")
            status = str(payload.get("status") or "pending").lower()  # type: ignore[assignment]
            if status not in {"pending", "succeeded", "failed", "refunded", "chargeback"}:
                status = "pending"
            occurred_at = self._utc(payload.get("occurred_at"))

        if not event_id:
            raise ValueError("provider_event_id is required")
        if not order_id:
            raise ValueError("order_id is required")

        return NormalizedPaymentEvent(
            provider=p,
            provider_event_id=event_id,
            order_id=order_id,
            status=status,
            occurred_at=occurred_at,
            raw=payload,
        )

    def process_webhook_event(self, *, provider: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        evt = self.normalize_event(provider=provider, payload=payload)

        # idempotency: duplicate delivery returns deterministic duplicate result
        key = self.repo._event_key(evt.provider, evt.provider_event_id)
        existing = self.repo.processed_events.get(key)
        if existing is not None and existing.get("outcome") != "dead_lettered":
            return {"status": "duplicate", "provider_event_id": evt.provider_event_id, "order_id": evt.order_id}
        if existing is None:
            self.repo.mark_processed(evt, outcome="received")

        self.repo.update_payment_state(evt)

        try:
            if evt.status in TERMINAL_SUCCESS:
                ents = self.entitlements.grant_entitlement(evt.order_id)
                for e in ents:
                    audit_event(
                        "payment_webhook_entitlement_link",
                        e.user_id,
                        None,
                        outcome="success",
                        provider=evt.provider,
                        provider_event_id=evt.provider_event_id,
                        order_id=evt.order_id,
                        payment_status=evt.status,
                        entitlement_id=e.entitlement_id,
                    )
                self.repo.processed_events[self.repo._event_key(evt.provider, evt.provider_event_id)]["outcome"] = "entitlements_granted"
                return {"status": "processed", "action": "granted", "entitlement_count": len(ents), "order_id": evt.order_id}

            if evt.status in TERMINAL_FAILURE:
                revoked = 0
                for ent in self.entitlements.repo.list_entitlements_for_subject(self.entitlements.repo.orders.get(evt.order_id, {}).get("user_id", "")):
                    if ent.status in {"active", "pending_payment"}:
                        self.entitlements.revoke_entitlement(ent.entitlement_id, f"payment_{evt.status}")
                        revoked += 1
                        audit_event(
                            "payment_webhook_entitlement_link",
                            ent.user_id,
                            None,
                            outcome="success",
                            provider=evt.provider,
                            provider_event_id=evt.provider_event_id,
                            order_id=evt.order_id,
                            payment_status=evt.status,
                            entitlement_id=ent.entitlement_id,
                        )
                self.repo.processed_events[self.repo._event_key(evt.provider, evt.provider_event_id)]["outcome"] = "entitlements_revoked"
                return {"status": "processed", "action": "revoked", "revoked_count": revoked, "order_id": evt.order_id}

            self.repo.processed_events[self.repo._event_key(evt.provider, evt.provider_event_id)]["outcome"] = "no_op_pending"
            return {"status": "processed", "action": "pending", "order_id": evt.order_id}
        except Exception as exc:
            self.repo.add_dead_letter(evt, reason=str(exc))
            self.repo.processed_events[self.repo._event_key(evt.provider, evt.provider_event_id)]["outcome"] = "dead_lettered"
            return {"status": "dead_lettered", "order_id": evt.order_id, "provider_event_id": evt.provider_event_id}

    def replay_dead_letters(self) -> Dict[str, Any]:
        events = self.repo.pop_dead_letters()
        processed = 0
        failed = 0
        for row in events:
            out = self.process_webhook_event(provider=str(row["provider"]), payload=dict(row.get("raw") or {}))
            if out.get("status") == "processed":
                processed += 1
            elif out.get("status") == "duplicate":
                processed += 1
            else:
                failed += 1
        return {"replayed": len(events), "processed": processed, "failed": failed}
