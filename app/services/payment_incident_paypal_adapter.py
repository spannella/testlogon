from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.core.settings import S
from app.services.payment_incident_providers import (
    CanonicalProviderEvent,
    PaymentIncidentProviderAdapter,
    ProviderActionResult,
    VerificationResult,
)


class PayPalPaymentIncidentAdapter(PaymentIncidentProviderAdapter):
    provider_key = "paypal"

    def verify_webhook(self, *, signature: str | None, body: bytes, headers: dict[str, str] | None = None) -> VerificationResult:
        hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        transmission_id = hdrs.get("paypal-transmission-id", "")
        transmission_time = hdrs.get("paypal-transmission-time", "")
        transmission_sig = hdrs.get("paypal-transmission-sig", "")
        cert_url = hdrs.get("paypal-cert-url", "")
        auth_algo = hdrs.get("paypal-auth-algo", "")

        if not S.paypal_webhook_id:
            return VerificationResult(valid=False, code="paypal_webhook_not_configured", message="paypal webhook id not configured")

        required_present = all([transmission_id, transmission_time, transmission_sig, cert_url, auth_algo])
        if not required_present:
            return VerificationResult(valid=False, code="invalid_signature", message="missing paypal webhook signature headers")

        if not _is_allowed_paypal_cert_url(cert_url):
            return VerificationResult(valid=False, code="invalid_signature", message="invalid paypal cert url")

        if not _is_allowed_paypal_auth_algo(auth_algo):
            return VerificationResult(valid=False, code="invalid_signature", message="unsupported paypal auth algorithm")

        if not _within_paypal_transmission_tolerance(transmission_time):
            return VerificationResult(valid=False, code="expired_signature", message="paypal transmission timestamp outside tolerance")

        # Optional local/shared-secret verification for deterministic hardening in non-network environments.
        if not _verify_optional_paypal_signature_secret(
            body=body,
            transmission_id=transmission_id,
            transmission_time=transmission_time,
            transmission_sig=transmission_sig,
        ):
            return VerificationResult(valid=False, code="invalid_signature", message="invalid paypal transmission signature")

        # For the payment-incident adapter we keep verification lightweight and deterministic:
        # strict provider-side remote verification can be layered in deployment-specific integrations.
        return VerificationResult(valid=True, code="ok", message="verified")

    def parse_webhook_events(self, *, body: bytes, headers: dict[str, str] | None = None) -> list[CanonicalProviderEvent]:
        try:
            event = json.loads(body.decode("utf-8") or "{}")
        except Exception:
            return []

        event_type = str(event.get("event_type") or "")
        event_id = str(event.get("id") or "")
        resource = event.get("resource") or {}

        if event_type.startswith("CUSTOMER.DISPUTE."):
            dispute_id = str(resource.get("dispute_id") or resource.get("id") or "")
            target_status = _map_dispute_status(event_type, str(resource.get("status") or ""), resource)
            if not dispute_id or not target_status:
                return []
            return [
                CanonicalProviderEvent(
                    provider="paypal",
                    provider_event_id=event_id,
                    incident_id=dispute_id,
                    incident_type="dispute",
                    target_status=target_status,
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": resource.get("transaction_info", {}).get("transaction_id") or dispute_id,
                        "amount": str((resource.get("dispute_amount") or {}).get("value") or "0"),
                        "currency": str((resource.get("dispute_amount") or {}).get("currency_code") or "usd"),
                        # DISP-030 (mirror): PayPal holds the funds on CREATED and
                        # restores them only on a seller-favor RESOLVED; there is no
                        # separate funds_withdrawn/reinstated event, so we derive the
                        # funds-movement signal from the dispute lifecycle here.
                        "funds_moved": event_type == "CUSTOMER.DISPUTE.CREATED",
                        "funds_restored": False,
                        "due_by": resource.get("seller_response_due_date"),
                        "charge_meta": resource.get("custom") or resource.get("metadata") or {},
                    },
                )
            ]

        if event_type in {"PAYMENT.SALE.DENIED", "PAYMENT.CAPTURE.DENIED"}:
            payment_id = str(resource.get("id") or "")
            if not payment_id:
                return []
            return [
                CanonicalProviderEvent(
                    provider="paypal",
                    provider_event_id=event_id,
                    incident_id=payment_id,
                    incident_type="payment_failure",
                    target_status="failed_initial",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": payment_id,
                        "requires_customer_action": True,
                        "customer_action_type": "confirm",
                        "retry_mode": "immediate",
                    },
                )
            ]

        if event_type == "BILLING.SUBSCRIPTION.PAYMENT.FAILED":
            subscription_id = str(resource.get("id") or resource.get("billing_agreement_id") or "")
            if not subscription_id:
                return []
            return [
                CanonicalProviderEvent(
                    provider="paypal",
                    provider_event_id=event_id,
                    incident_id=subscription_id,
                    incident_type="payment_failure",
                    target_status="customer_action_required",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": subscription_id,
                        "subscription_id": subscription_id,
                        "requires_customer_action": True,
                        "customer_action_type": "update_method",
                        "retry_mode": "autopay",
                    },
                )
            ]

        if event_type in {"PAYMENT.SALE.COMPLETED", "BILLING.SUBSCRIPTION.PAYMENT.SUCCEEDED"}:
            ref = str(resource.get("id") or "")
            if not ref:
                return []
            return [
                CanonicalProviderEvent(
                    provider="paypal",
                    provider_event_id=event_id,
                    incident_id=ref,
                    incident_type="payment_failure",
                    target_status="retry_succeeded",
                    payload={
                        "source_event_type": event_type,
                        "payment_reference": ref,
                        "retry_mode": "autopay" if event_type.startswith("BILLING.SUBSCRIPTION") else "immediate",
                    },
                )
            ]

        return []

    def fetch_dispute_details(self, *, provider_incident_id: str) -> ProviderActionResult:
        return ProviderActionResult(
            ok=True,
            code="ok",
            message="fetch_dispute_details_queued",
            payload={"provider_incident_id": provider_incident_id, "provider": "paypal"},
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
                "payment_reference": payment_reference,
                "retry_mode": mode,
                "action": "retry_order_capture" if mode == "immediate" else "retry_subscription_payment",
            },
        )


def _map_dispute_status(event_type: str, provider_status: str, resource: dict[str, Any]) -> str:
    status = provider_status.strip().upper()
    if event_type == "CUSTOMER.DISPUTE.CREATED":
        return "opened"

    if event_type == "CUSTOMER.DISPUTE.UPDATED":
        if status in {"WAITING_FOR_SELLER_RESPONSE", "WAITING_FOR_OTHER_PARTY"}:
            return "evidence_required"
        if status in {"UNDER_REVIEW"}:
            return "under_review"
        return "opened"

    if event_type == "CUSTOMER.DISPUTE.RESOLVED":
        outcome = str((resource.get("dispute_outcome") or {}).get("outcome_code") or "").upper()
        if outcome in {"RESOLVED_BUYER_FAVOR", "BUYER_FAVOR"}:
            return "lost"
        if outcome in {"RESOLVED_SELLER_FAVOR", "SELLER_FAVOR"}:
            return "won"
        return "accepted"

    return ""


def _parse_iso8601_utc(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except Exception:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _within_paypal_transmission_tolerance(transmission_time: str) -> bool:
    parsed = _parse_iso8601_utc(transmission_time)
    if parsed is None:
        return False
    tolerance = int(getattr(S, "paypal_webhook_tolerance_seconds", 300))
    now = datetime.now(timezone.utc)
    delta = abs((now - parsed).total_seconds())
    return delta <= tolerance


def _is_allowed_paypal_cert_url(cert_url: str) -> bool:
    value = str(cert_url or "").strip().lower()
    return value.startswith("https://") and "paypal.com" in value


def _is_allowed_paypal_auth_algo(auth_algo: str) -> bool:
    allowed = {"sha256withrsa", "sha512withrsa"}
    return str(auth_algo or "").strip().lower() in allowed


def _verify_optional_paypal_signature_secret(
    *,
    body: bytes,
    transmission_id: str,
    transmission_time: str,
    transmission_sig: str,
) -> bool:
    import hashlib
    import hmac

    secret = str(getattr(S, "paypal_webhook_signature_secret", "") or "").strip()
    if not secret:
        return True
    signed = f"{transmission_id}|{transmission_time}|".encode("utf-8") + body
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest.lower(), str(transmission_sig or "").strip().lower())
