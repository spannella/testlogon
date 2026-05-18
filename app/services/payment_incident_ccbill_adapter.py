from __future__ import annotations

import json
import hashlib
import hmac
from typing import Any

from app.core.settings import S
from app.services.payment_incident_providers import (
    CanonicalProviderEvent,
    PaymentIncidentProviderAdapter,
    ProviderActionResult,
    VerificationResult,
)


class CCBillPaymentIncidentAdapter(PaymentIncidentProviderAdapter):
    provider_key = "ccbill"

    def verify_webhook(self, *, signature: str | None, body: bytes, headers: dict[str, str] | None = None) -> VerificationResult:
        sig = str(signature or "").strip()
        if not sig:
            return VerificationResult(valid=False, code="invalid_signature", message="missing ccbill signature header")
        if not _verify_ccbill_signature(body, sig):
            return VerificationResult(valid=False, code="invalid_signature", message="invalid ccbill webhook signature")
        return VerificationResult(valid=True, code="ok", message="verified")

    def parse_webhook_events(self, *, body: bytes, headers: dict[str, str] | None = None) -> list[CanonicalProviderEvent]:
        try:
            event = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            return []

        event_type = str(event.get("eventType") or event.get("event_type") or "")
        event_id = str(event.get("eventId") or event.get("id") or "")
        transaction = event.get("transaction") or {}

        if event_type in {"Chargeback", "DisputeOpened", "Dispute"}:
            dispute_id = str(event.get("disputeId") or transaction.get("transactionId") or "")
            if not dispute_id:
                return []
            return [
                CanonicalProviderEvent(
                    provider="ccbill",
                    provider_event_id=event_id,
                    incident_id=dispute_id,
                    incident_type="chargeback" if event_type == "Chargeback" else "dispute",
                    target_status="opened",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": str(transaction.get("transactionId") or dispute_id),
                        "amount": str(transaction.get("amount") or event.get("amount") or "0"),
                        "currency": str(transaction.get("currency") or event.get("currency") or "usd"),
                    },
                )
            ]

        if event_type in {"RebillDeclined", "TransactionDeclined"}:
            txn = str(transaction.get("transactionId") or event.get("transactionId") or "")
            if not txn:
                return []
            return [
                CanonicalProviderEvent(
                    provider="ccbill",
                    provider_event_id=event_id,
                    incident_id=txn,
                    incident_type="payment_failure",
                    target_status="customer_action_required",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": txn,
                        "requires_customer_action": True,
                        "customer_action_type": "update_method",
                        "retry_mode": "autopay",
                    },
                )
            ]

        if event_type in {"TransactionFailed"}:
            txn = str(transaction.get("transactionId") or event.get("transactionId") or "")
            if not txn:
                return []
            return [
                CanonicalProviderEvent(
                    provider="ccbill",
                    provider_event_id=event_id,
                    incident_id=txn,
                    incident_type="payment_failure",
                    target_status="failed_initial",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": txn,
                        "requires_customer_action": True,
                        "customer_action_type": "confirm",
                        "retry_mode": "immediate",
                    },
                )
            ]

        if event_type in {"RebillSuccess", "TransactionSuccess"}:
            txn = str(transaction.get("transactionId") or event.get("transactionId") or "")
            if not txn:
                return []
            return [
                CanonicalProviderEvent(
                    provider="ccbill",
                    provider_event_id=event_id,
                    incident_id=txn,
                    incident_type="payment_failure",
                    target_status="retry_succeeded",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": txn,
                        "retry_mode": "autopay" if event_type == "RebillSuccess" else "immediate",
                    },
                )
            ]

        return []

    def fetch_dispute_details(self, *, provider_incident_id: str) -> ProviderActionResult:
        return ProviderActionResult(
            ok=True,
            code="ok",
            message="fetch_dispute_details_queued",
            payload={"provider": "ccbill", "provider_incident_id": provider_incident_id},
        )

    def submit_dispute_response(self, *, provider_incident_id: str, evidence: dict[str, Any]) -> ProviderActionResult:
        return ProviderActionResult(
            ok=True,
            code="ok",
            message="submit_dispute_response_queued",
            payload={"provider_incident_id": provider_incident_id, "evidence": evidence},
        )

    def retry_payment(self, *, payment_reference: str, metadata: dict[str, Any] | None = None) -> ProviderActionResult:
        mode = str((metadata or {}).get("retry_mode") or "immediate")
        return ProviderActionResult(
            ok=True,
            code="ok",
            message="retry_queued",
            payload={
                "provider": "ccbill",
                "payment_reference": payment_reference,
                "retry_mode": mode,
                "action": "retry_transaction" if mode == "immediate" else "retry_rebill",
            },
        )


def _verify_ccbill_signature(raw_body: bytes, signature_header: str) -> bool:
    secret = str(getattr(S, "ccbill_webhook_signature_secret", "") or "").strip()
    if not secret:
        # local/test fallback used across dev docs/mocks
        secret = "local-ccbill-webhook-secret"
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest.lower(), str(signature_header or "").strip().lower())
