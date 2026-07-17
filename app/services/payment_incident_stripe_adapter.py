from __future__ import annotations

import importlib.util
import json
import sys
from typing import Any

from app.core.settings import S
from app.services.payment_incident_providers import (
    CanonicalProviderEvent,
    PaymentIncidentProviderAdapter,
    ProviderActionResult,
    VerificationResult,
)

if "stripe" in sys.modules:
    stripe = sys.modules["stripe"]  # type: ignore
elif importlib.util.find_spec("stripe") is not None:
    import stripe  # type: ignore
else:  # pragma: no cover
    stripe = None  # type: ignore


class StripePaymentIncidentAdapter(PaymentIncidentProviderAdapter):
    provider_key = "stripe"

    def verify_webhook(self, *, signature: str | None, body: bytes, headers: dict[str, str] | None = None) -> VerificationResult:
        if not stripe:
            return VerificationResult(valid=False, code="stripe_not_configured", message="stripe sdk not installed")
        try:
            stripe.Webhook.construct_event(payload=body, sig_header=signature, secret=S.stripe_webhook_secret)
            return VerificationResult(valid=True, code="ok", message="verified")
        except Exception:
            return VerificationResult(valid=False, code="invalid_signature", message="invalid stripe webhook signature")

    def parse_webhook_events(self, *, body: bytes, headers: dict[str, str] | None = None) -> list[CanonicalProviderEvent]:
        try:
            event = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            return []

        event_type = str(event.get("type") or "")
        event_id = str(event.get("id") or "")
        obj = (event.get("data") or {}).get("object") or {}

        if event_type in {"charge.dispute.created", "charge.dispute.updated", "charge.dispute.closed",
                          "charge.dispute.funds_withdrawn", "charge.dispute.funds_reinstated"}:
            dispute_id = str(obj.get("id") or "")
            target_status = _map_dispute_status(event_type, str(obj.get("status") or ""))
            if not dispute_id or not target_status:
                return []
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id=event_id,
                    incident_id=dispute_id,
                    incident_type="dispute",
                    target_status=target_status,
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": obj.get("charge"),
                        "amount": str(obj.get("amount") or "0"),
                        "currency": str(obj.get("currency") or "usd"),
                        # DISP-030: surface the funds-movement signal (Stripe pulls the
                        # funds on created/funds_withdrawn, restores on funds_reinstated).
                        "funds_moved": event_type in {"charge.dispute.created", "charge.dispute.funds_withdrawn"},
                        "funds_restored": event_type == "charge.dispute.funds_reinstated",
                        # DISP-032: the response deadline Stripe hands us (evidence_details.due_by).
                        "due_by": ((obj.get("evidence_details") or {}) or {}).get("due_by"),
                        # DISP-031/033/034: the internal-charge coordinates the reconciler drives
                        # the ledger rail off of. Real-when-keyed we set these in dispute.metadata
                        # at charge time; the mock webhook carries them the same way.
                        "charge_meta": obj.get("metadata") or {},
                    },
                )
            ]

        if event_type == "payment_intent.payment_failed":
            pi_id = str(obj.get("id") or "")
            if not pi_id:
                return []
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id=event_id,
                    incident_id=pi_id,
                    incident_type="payment_failure",
                    target_status="failed_initial",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": pi_id,
                        "requires_customer_action": True,
                        "customer_action_type": "confirm",
                        "retry_mode": "immediate",
                    },
                )
            ]

        if event_type == "invoice.payment_failed":
            invoice_id = str(obj.get("id") or "")
            if not invoice_id:
                return []
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id=event_id,
                    incident_id=invoice_id,
                    incident_type="payment_failure",
                    target_status="customer_action_required",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": invoice_id,
                        "requires_customer_action": True,
                        "customer_action_type": "update_method",
                        "retry_mode": "autopay",
                    },
                )
            ]

        if event_type == "invoice.payment_succeeded":
            invoice_id = str(obj.get("id") or "")
            if not invoice_id:
                return []
            return [
                CanonicalProviderEvent(
                    provider="stripe",
                    provider_event_id=event_id,
                    incident_id=invoice_id,
                    incident_type="payment_failure",
                    target_status="retry_succeeded",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": invoice_id,
                        "retry_mode": "autopay",
                    },
                )
            ]

        return []

    def fetch_dispute_details(self, *, provider_incident_id: str) -> ProviderActionResult:
        if not stripe:
            return ProviderActionResult(ok=False, code="stripe_not_configured", message="stripe sdk not installed")
        try:
            dispute = stripe.Dispute.retrieve(provider_incident_id)
        except Exception as exc:  # pragma: no cover - network failures mocked in tests
            return ProviderActionResult(ok=False, code="provider_error", message=str(exc))
        return ProviderActionResult(ok=True, code="ok", message="fetched", payload={"dispute": dispute})

    def submit_dispute_response(self, *, provider_incident_id: str, evidence: dict[str, Any]) -> ProviderActionResult:
        if not stripe:
            return ProviderActionResult(ok=False, code="stripe_not_configured", message="stripe sdk not installed")
        try:
            dispute = stripe.Dispute.modify(provider_incident_id, evidence=evidence)
        except Exception as exc:  # pragma: no cover
            return ProviderActionResult(ok=False, code="provider_error", message=str(exc))
        return ProviderActionResult(ok=True, code="ok", message="submitted", payload={"dispute": dispute})

    def retry_payment(self, *, payment_reference: str, metadata: dict[str, Any] | None = None) -> ProviderActionResult:
        if not stripe:
            return ProviderActionResult(ok=False, code="stripe_not_configured", message="stripe sdk not installed")

        mode = str((metadata or {}).get("retry_mode") or "immediate")
        try:
            if mode == "autopay":
                invoice = stripe.Invoice.retrieve(payment_reference)
                paid = stripe.Invoice.pay(invoice.get("id") or payment_reference)
                return ProviderActionResult(ok=True, code="ok", message="retried", payload={"invoice": paid})

            intent = stripe.PaymentIntent.confirm(payment_reference)
            return ProviderActionResult(ok=True, code="ok", message="retried", payload={"payment_intent": intent})
        except Exception as exc:  # pragma: no cover
            return ProviderActionResult(ok=False, code="provider_error", message=str(exc))


def _map_dispute_status(event_type: str, provider_status: str) -> str:
    status = provider_status.strip().lower()
    if event_type == "charge.dispute.created":
        return "opened"
    # DISP-030: funds_withdrawn -> opened (Stripe has now actually pulled the
    # contested funds; the reconciler treats it as the hold trigger, idempotent
    # with created). funds_reinstated -> opened as well (funds restored mid-life;
    # the terminal won/lost still comes on dispute.closed) — payload.funds_restored
    # carries the distinction for audit.
    if event_type == "charge.dispute.funds_withdrawn":
        return "opened"
    if event_type == "charge.dispute.funds_reinstated":
        return "opened"
    if event_type == "charge.dispute.updated":
        if status in {"needs_response", "warning_needs_response", "warning_under_review"}:
            return "evidence_required"
        if status in {"under_review", "warning_closed"}:
            return "under_review"
        return "opened"
    if event_type == "charge.dispute.closed":
        if status in {"won"}:
            return "won"
        if status in {"lost"}:
            return "lost"
        return "accepted"
    return ""
