"""Webhook endpoint management and event dispatch (PLATFORM-002)."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.crypto import kms_encrypt, kms_decrypt
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ─── Event types ────────────────────────────────────────────────────────────

WEBHOOK_EVENT_TYPES: Dict[str, str] = {
    # Messaging
    "message.created": "A new message was sent in a conversation you participate in",
    "message.updated": "A message was edited or its metadata changed",
    "conversation.created": "A new conversation was started with you",
    # Billing
    "payment.received": "A payment was received (tip, unlock, subscription)",
    "payment.failed": "A payment attempt failed",
    "subscription.created": "A new subscription was created",
    "subscription.cancelled": "A subscription was cancelled",
    "subscription.renewed": "A subscription was renewed",
    "wallet.deposit": "A wallet deposit was completed",
    # Newsfeed
    "post.created": "A new post was published",
    "post.comment": "A comment was added to your post",
    "post.reaction": "A reaction was added to your post",
    "post.tip": "A tip was sent on your post",
    # Broadcast
    "broadcast.started": "A broadcast went live",
    "broadcast.stopped": "A broadcast ended",
    "broadcast.scheduled": "A broadcast was scheduled",
    # Account
    "account.login": "A new login to your account",
    "account.mfa_change": "MFA device added or removed",
    "account.profile_update": "Profile was updated",
    # Moderation
    "moderation.action": "A moderation action was taken on your content",
    # Files
    "file.uploaded": "A new file was uploaded",
    "file.shared": "A file was shared with you",
    # Webhook system
    "webhook.test": "Test event for verifying webhook configuration",
}

# ─── v2 expanded event types (ENTERPRISE-005) ───────────────────────────────

WEBHOOK_EVENT_TYPES_V2: Dict[str, str] = {
    **WEBHOOK_EVENT_TYPES,

    # Messaging (expanded)
    "message.deleted": "A message was deleted",
    "message.reaction_added": "A reaction was added to a message",
    "message.tip_received": "A tip was received on a message",
    "message.unlocked": "A locked message was unlocked",
    "message.expired": "A message expired (TTL)",
    "conversation.member_added": "A member was added to a group conversation",
    "conversation.member_removed": "A member was removed from a group conversation",

    # Billing (expanded)
    "payment.refunded": "A payment was refunded",
    "payment.disputed": "A payment dispute was opened",
    "wallet.withdrawal": "A wallet withdrawal was processed",
    "invoice.generated": "A monthly invoice was generated",
    "payment_method.added": "A payment method was added",
    "payment_method.removed": "A payment method was removed",

    # Subscriptions (expanded)
    "subscription.payment_failed": "A subscription payment failed",
    "subscription.downgraded": "A subscription was downgraded",
    "subscription.upgraded": "A subscription was upgraded",
    "subscription.trial_ending": "A subscription trial is ending soon",

    # Tickets
    "ticket.created": "A support ticket was created",
    "ticket.resolved": "A support ticket was resolved",
    "ticket.assigned": "A ticket was assigned to an agent",
    "ticket.commented": "A comment was added to a ticket",

    # Calendar
    "calendar.event.created": "A calendar event was created",
    "calendar.event.updated": "A calendar event was updated",
    "calendar.event.cancelled": "A calendar event was cancelled",
    "calendar.booking.requested": "A booking was requested",
    "calendar.booking.confirmed": "A booking was confirmed",

    # VOD / Video
    "video.uploaded": "A video was uploaded",
    "video.published": "A video was published",
    "video.transcoded": "A video transcode completed",
    "video.deleted": "A video was deleted",
    "video.view": "A video was viewed (batched, delayed)",

    # Calls
    "call.started": "A call was started",
    "call.ended": "A call ended",
    "call.recording_available": "A call recording is ready",
    "call.missed": "A call was missed",

    # Stories
    "story.created": "A story was published",
    "story.expired": "A story expired",
    "story.viewed": "A story was viewed",

    # Moderation (expanded)
    "moderation.content_removed": "Content was removed by moderators",
    "moderation.warning_issued": "A warning was issued to a user",
    "moderation.ban_applied": "A user was banned",
    "moderation.appeal_submitted": "An appeal was submitted",
    "moderation.appeal_resolved": "An appeal was resolved",

    # Files (expanded)
    "file.deleted": "A file was deleted",
    "file.moved": "A file was moved",
    "file.downloaded": "A file was downloaded",

    # Account (expanded)
    "account.created": "A new account was created",
    "account.deleted": "An account was deleted",
    "account.password_changed": "Account password was changed",
    "account.email_verified": "Account email was verified",
    "account.api_key_created": "An API key was created",
    "account.api_key_revoked": "An API key was revoked",

    # Referrals
    "referral.signup": "A referred user signed up",
    "referral.commission": "A referral commission was earned",

    # Organizations
    "org.member_joined": "A member joined an organization",
    "org.member_removed": "A member was removed from an organization",

    # KYC (KYC-011)
    "kyc.case.created": "A new KYC verification case was created",
    "kyc.case.submitted": "A KYC case was submitted for review",
    "kyc.case.approved": "A KYC case was approved",
    "kyc.case.rejected": "A KYC case was rejected",
    "kyc.case.needs_info": "Additional information was requested for a KYC case",
    "kyc.case.disputed": "A rejected KYC case was disputed/appealed by the applicant",
    "kyc.case.resubmitted": "A previously-rejected KYC case was resubmitted after a retry",
    "kyc.tier.changed": "A user verification tier changed",
    "kyc.tier.upgraded": "A user verification tier was upgraded",
    "kyc.tier.downgraded": "A user verification tier was downgraded",
    "kyc.document.verified": "A KYC document was verified",
    "kyc.document.rejected": "A KYC document was rejected",
    "kyc.residency.verified": "A residency proof was verified",
    "kyc.proof_of_funds.verified": "A proof-of-funds submission was verified",
    "kyc.liveness.passed": "A liveness/verification call passed",
    "kyc.liveness.failed": "A liveness/verification call failed",
    "kyc.id_scan.result": "An ID document scan produced a result",
    "kyc.sanctions.match": "A sanctions/PEP screening match was found",
    "kyc.sanctions.clear": "A sanctions/PEP screening came back clear",

    # Advertiser / Ad platform (ADS-011 / GAP-0055)
    "ad.campaign.created": "A new ad campaign was created",
    "ad.campaign.updated": "An ad campaign was updated",
    "ad.campaign.paused": "An ad campaign was paused",
    "ad.campaign.completed": "An ad campaign budget was exhausted and it was auto-paused",
    "ad.campaign.resumed": "A paused ad campaign was resumed",
    "ad.creative.submitted": "An ad creative was submitted for moderation",
    "ad.creative.approved": "An ad creative was approved",
    "ad.creative.rejected": "An ad creative was rejected by moderation",
    "ad.billing.budget_alert": "An ad campaign crossed a budget spend threshold",
    "ad.billing.invoice_ready": "A monthly ad invoice is available",
    "ad.account.approved": "An advertiser account was approved",
    "ad.account.suspended": "An advertiser account was suspended for fraud",
    "ad.webhook.test": "Test event for verifying advertiser webhook configuration",
}

# Canonical allowlist of KYC webhook event types (KYC-011).
# These are also added to WEBHOOK_EVENT_TYPES_V2 above so subscriptions validate.
KYC_WEBHOOK_EVENT_TYPES: Dict[str, str] = {
    k: v for k, v in WEBHOOK_EVENT_TYPES_V2.items() if k.startswith("kyc.")
}

# Canonical allowlist of advertiser/ad-platform webhook event types
# (ADS-011 / GAP-0055). These are also present in WEBHOOK_EVENT_TYPES_V2 above
# so endpoint subscriptions validate via is_valid_event_type().
AD_WEBHOOK_EVENT_TYPES: Dict[str, str] = {
    k: v for k, v in WEBHOOK_EVENT_TYPES_V2.items() if k.startswith("ad.")
}


def get_event_types() -> Dict[str, str]:
    """Return the active event type registry."""
    if S.webhooks_v2_enabled:
        return WEBHOOK_EVENT_TYPES_V2
    return WEBHOOK_EVENT_TYPES


def is_valid_event_type(event_type: str) -> bool:
    """Check whether an event type is valid in the current mode.

    KYC event types (KYC-011) are always valid regardless of the v2 flag so
    that KYC webhook subscriptions work even when v2 is disabled.
    """
    return event_type in get_event_types() or event_type in KYC_WEBHOOK_EVENT_TYPES


# ─── Retry schedule ─────────────────────────────────────────────────────────

RETRY_DELAYS_SECONDS = [0, 60, 300, 1800, 7200]


# ─── Endpoint CRUD ──────────────────────────────────────────────────────────

def _gen_endpoint_id() -> str:
    return f"wh_{uuid.uuid4().hex}"


def _gen_delivery_id() -> str:
    return f"wd_{uuid.uuid4().hex}"


def _gen_event_id() -> str:
    return f"evt_{uuid.uuid4().hex}"


def _gen_secret() -> str:
    return f"whsec_{secrets.token_urlsafe(32)}"


def register_endpoint(
    user_sub: str,
    url: str,
    event_types: List[str],
    description: str = "",
    retry_policy: Optional[Dict[str, Any]] = None,
    signature_version: str = "v2",
    circuit_failure_threshold: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a new webhook endpoint. Returns the endpoint dict with plaintext secret."""
    if not url.startswith("https://"):
        raise ValueError("URL must use HTTPS")

    # SSRF validation (skip DNS in dev mode for test URLs)
    if S.webhooks_v2_enabled:
        from app.services.webhook_ssrf import validate_webhook_url
        try:
            validate_webhook_url(url, skip_dns=S.dev_mode)
        except ValueError:
            if not S.dev_mode:
                raise

    for et in event_types:
        if not is_valid_event_type(et):
            raise ValueError(f"Unknown event type: {et}")

    # Check max endpoints limit
    existing = list_endpoints(user_sub)
    if len(existing) >= S.webhooks_max_endpoints_per_user:
        raise OverflowError(f"Maximum webhook endpoints reached ({S.webhooks_max_endpoints_per_user})")

    endpoint_id = _gen_endpoint_id()
    plaintext_secret = _gen_secret()

    # Encrypt secret for storage
    try:
        encrypted_secret = kms_encrypt(plaintext_secret)
    except Exception:
        # If KMS is unavailable (dev mode), store plaintext with marker
        encrypted_secret = f"PLAIN:{plaintext_secret}"

    now = now_ts()

    # Normalize v2 retry policy
    from app.services.webhook_retry import normalize_retry_policy
    normalized_policy = normalize_retry_policy(retry_policy)
    cb_threshold = circuit_failure_threshold or S.webhooks_default_circuit_failure_threshold

    item = {
        "pk": f"USER#{user_sub}",
        "sk": f"ENDPOINT#{endpoint_id}",
        "endpoint_id": endpoint_id,
        "user_sub": user_sub,
        "url": url,
        "description": description,
        "secret": encrypted_secret,
        "event_types": set(event_types) if event_types else set(["webhook.test"]),
        "enabled": True,
        "created_at": now,
        "updated_at": now,
        "failure_count": 0,
        # v2 fields
        "retry_policy": normalized_policy,
        "signature_version": signature_version,
        "circuit_state": "closed",
        "circuit_consecutive_failures": 0,
        "circuit_failure_threshold": cb_threshold,
        "circuit_cooldown_seconds": S.webhooks_circuit_initial_cooldown_seconds,
    }
    T.webhook_endpoints.put_item(Item=item)

    # Write event-type index items for fast dispatch lookup
    for et in event_types:
        T.webhook_endpoints.put_item(Item={
            "pk": f"EVENT#{et}",
            "sk": f"ENDPOINT#{endpoint_id}",
            "endpoint_id": endpoint_id,
            "user_sub": user_sub,
            "url": url,
            "enabled": True,
        })

    return {
        "endpoint_id": endpoint_id,
        "url": url,
        "description": description,
        "event_types": event_types,
        "enabled": True,
        "secret": plaintext_secret,
        "created_at": now,
        "updated_at": now,
        "failure_count": 0,
        "retry_policy": normalized_policy,
        "signature_version": signature_version,
        "circuit_state": "closed",
        "circuit_consecutive_failures": 0,
        "circuit_failure_threshold": cb_threshold,
        "circuit_cooldown_seconds": S.webhooks_circuit_initial_cooldown_seconds,
    }


def _endpoint_out(item: Dict[str, Any]) -> Dict[str, Any]:
    """Build a public-facing endpoint dict from a DDB item."""
    et = item.get("event_types", set())
    rp = item.get("retry_policy")
    # Convert Decimal values in retry_policy to int
    if rp and isinstance(rp, dict):
        rp = {k: int(v) if hasattr(v, 'as_integer_ratio') else v for k, v in rp.items()}
    return {
        "endpoint_id": item["endpoint_id"],
        "url": item["url"],
        "description": item.get("description", ""),
        "event_types": sorted(et) if et else [],
        "enabled": item.get("enabled", True),
        "secret": None,
        "created_at": int(item.get("created_at", 0)),
        "updated_at": int(item.get("updated_at", 0)),
        "last_delivery_at": int(item["last_delivery_at"]) if item.get("last_delivery_at") else None,
        "failure_count": int(item.get("failure_count", 0)),
        "disabled_reason": item.get("disabled_reason"),
        # v2 fields
        "retry_policy": rp,
        "signature_version": item.get("signature_version", "v2"),
        "circuit_state": item.get("circuit_state", "closed"),
        "circuit_consecutive_failures": int(item.get("circuit_consecutive_failures", 0)),
        "circuit_failure_threshold": int(item.get("circuit_failure_threshold", S.webhooks_default_circuit_failure_threshold)),
        "circuit_cooldown_seconds": int(item.get("circuit_cooldown_seconds", S.webhooks_circuit_initial_cooldown_seconds)) if item.get("circuit_cooldown_seconds") is not None else None,
        "circuit_test_at": int(item["circuit_test_at"]) if item.get("circuit_test_at") else None,
    }


def list_endpoints(user_sub: str) -> List[Dict[str, Any]]:
    """List all webhook endpoints for a user."""
    resp = T.webhook_endpoints.query(
        KeyConditionExpression=Key("pk").eq(f"USER#{user_sub}")
        & Key("sk").begins_with("ENDPOINT#"),
    )
    items = resp.get("Items", [])
    return [_endpoint_out(item) for item in items]


def get_endpoint(user_sub: str, endpoint_id: str) -> Optional[Dict[str, Any]]:
    """Get a single endpoint by ID."""
    resp = T.webhook_endpoints.get_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
    )
    item = resp.get("Item")
    if not item:
        return None
    return _endpoint_out(item)


def _get_endpoint_raw(user_sub: str, endpoint_id: str) -> Optional[Dict[str, Any]]:
    """Get raw endpoint item (including encrypted secret)."""
    resp = T.webhook_endpoints.get_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
    )
    return resp.get("Item")


def update_endpoint(
    user_sub: str,
    endpoint_id: str,
    url: Optional[str] = None,
    description: Optional[str] = None,
    event_types: Optional[List[str]] = None,
    enabled: Optional[bool] = None,
    retry_policy: Optional[Dict[str, Any]] = None,
    signature_version: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Update an existing endpoint."""
    item = _get_endpoint_raw(user_sub, endpoint_id)
    if not item:
        return None

    if url is not None:
        if not url.startswith("https://"):
            raise ValueError("URL must use HTTPS")
        item["url"] = url

    if description is not None:
        item["description"] = description

    old_event_types = set(item.get("event_types", set()))

    if retry_policy is not None:
        from app.services.webhook_retry import normalize_retry_policy
        item["retry_policy"] = normalize_retry_policy(retry_policy)

    if signature_version is not None:
        if signature_version not in ("v1", "v2", "both"):
            raise ValueError("signature_version must be v1, v2, or both")
        item["signature_version"] = signature_version

    if event_types is not None:
        for et in event_types:
            if not is_valid_event_type(et):
                raise ValueError(f"Unknown event type: {et}")
        new_et = set(event_types)
        item["event_types"] = new_et

        # Remove old event-type index items
        for et in old_event_types - new_et:
            try:
                T.webhook_endpoints.delete_item(
                    Key={"pk": f"EVENT#{et}", "sk": f"ENDPOINT#{endpoint_id}"},
                )
            except Exception:
                pass

        # Add new event-type index items
        for et in new_et - old_event_types:
            T.webhook_endpoints.put_item(Item={
                "pk": f"EVENT#{et}",
                "sk": f"ENDPOINT#{endpoint_id}",
                "endpoint_id": endpoint_id,
                "user_sub": user_sub,
                "url": item["url"],
                "enabled": item.get("enabled", True) if enabled is None else enabled,
            })

        # Update URL on existing event-type index items
        if url is not None:
            for et in new_et & old_event_types:
                try:
                    T.webhook_endpoints.update_item(
                        Key={"pk": f"EVENT#{et}", "sk": f"ENDPOINT#{endpoint_id}"},
                        UpdateExpression="SET #u = :u",
                        ExpressionAttributeNames={"#u": "url"},
                        ExpressionAttributeValues={":u": url},
                    )
                except Exception:
                    pass

    if enabled is not None:
        item["enabled"] = enabled
        # Update event-type index items
        current_types = set(item.get("event_types", set()))
        for et in current_types:
            try:
                T.webhook_endpoints.update_item(
                    Key={"pk": f"EVENT#{et}", "sk": f"ENDPOINT#{endpoint_id}"},
                    UpdateExpression="SET enabled = :e",
                    ExpressionAttributeValues={":e": enabled},
                )
            except Exception:
                pass

    item["updated_at"] = now_ts()
    T.webhook_endpoints.put_item(Item=item)

    return _endpoint_out(item)


def delete_endpoint(user_sub: str, endpoint_id: str) -> bool:
    """Delete an endpoint and its event-type index items."""
    item = _get_endpoint_raw(user_sub, endpoint_id)
    if not item:
        return False

    # Delete event-type index items
    for et in item.get("event_types", set()):
        try:
            T.webhook_endpoints.delete_item(
                Key={"pk": f"EVENT#{et}", "sk": f"ENDPOINT#{endpoint_id}"},
            )
        except Exception:
            pass

    T.webhook_endpoints.delete_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
    )
    return True


def rotate_secret(user_sub: str, endpoint_id: str) -> Optional[str]:
    """Generate and store a new secret, return the plaintext."""
    item = _get_endpoint_raw(user_sub, endpoint_id)
    if not item:
        return None

    plaintext_secret = _gen_secret()
    try:
        encrypted_secret = kms_encrypt(plaintext_secret)
    except Exception:
        encrypted_secret = f"PLAIN:{plaintext_secret}"

    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression="SET secret = :s, updated_at = :u",
        ExpressionAttributeValues={":s": encrypted_secret, ":u": now_ts()},
    )
    return plaintext_secret


def _decrypt_secret(encrypted: str) -> str:
    """Decrypt a stored endpoint secret."""
    if encrypted.startswith("PLAIN:"):
        return encrypted[6:]
    return kms_decrypt(encrypted).decode("utf-8")


# ─── HMAC Signature ─────────────────────────────────────────────────────────

def compute_signature(secret: str, timestamp: int, payload: str) -> str:
    """Compute HMAC-SHA256 signature for webhook delivery."""
    message = f"{timestamp}.{payload}"
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def _extract_event_id(payload: str) -> str:
    """Extract event_id from a JSON payload string."""
    try:
        data = json.loads(payload)
        return data.get("id", "")
    except Exception:
        return ""


# ─── Event Dispatch ─────────────────────────────────────────────────────────

def dispatch_webhook_event(
    event_type: str,
    user_sub: str,
    data: Dict[str, Any],
) -> List[str]:
    """Find matching endpoints and create pending delivery records.

    Returns list of created delivery IDs.
    """
    if not S.webhooks_enabled:
        return []

    # Look up endpoints subscribed to this event type
    resp = T.webhook_endpoints.query(
        KeyConditionExpression=Key("pk").eq(f"EVENT#{event_type}")
        & Key("sk").begins_with("ENDPOINT#"),
    )
    index_items = resp.get("Items", [])

    delivery_ids = []
    now = now_ts()
    event_id = _gen_event_id()
    payload = json.dumps({
        "id": event_id,
        "type": event_type,
        "created_at": now,
        "data": data,
    })
    ttl_epoch = now + (S.webhooks_delivery_ttl_days * 86400)

    for idx_item in index_items:
        if not idx_item.get("enabled", True):
            continue

        delivery_id = _gen_delivery_id()
        delivery = {
            "pk": f"ENDPOINT#{idx_item['endpoint_id']}",
            "sk": f"DELIVERY#{delivery_id}",
            "delivery_id": delivery_id,
            "endpoint_id": idx_item["endpoint_id"],
            "user_sub": idx_item.get("user_sub", user_sub),
            "event_type": event_type,
            "event_id": event_id,
            "payload": payload,
            "status": "pending",
            "attempt_count": 0,
            "max_attempts": S.webhooks_max_retries,
            "next_retry_at": now,
            "created_at": now,
            "ttl_epoch": ttl_epoch,
        }
        T.webhook_deliveries.put_item(Item=delivery)
        delivery_ids.append(delivery_id)

    return delivery_ids


# ─── Delivery Processing ────────────────────────────────────────────────────

async def deliver_webhook(
    url: str,
    payload: str,
    secret: str,
    delivery_id: str,
    event_type: str,
    signature_version: str = "v2",
) -> Dict[str, Any]:
    """HTTP POST webhook delivery with v1/v2 signature support. Returns result dict."""
    import httpx

    timestamp = int(time.time())
    v2_signature = compute_signature(secret, timestamp, payload)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Platform-Webhooks/2.0",
        "X-Webhook-Timestamp": str(timestamp),
        "X-Webhook-Event": event_type,
        "X-Webhook-Event-Id": _extract_event_id(payload),
        "X-Webhook-Delivery-Id": delivery_id,
    }

    # Signature headers based on version preference
    if signature_version in ("v2", "both"):
        headers["X-Webhook-Signature"] = f"v2={v2_signature}"
    if signature_version in ("v1", "both"):
        v1_sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        headers["X-Webhook-Signature-v1"] = f"sha256={v1_sig}"
    if signature_version not in ("v1", "v2", "both"):
        headers["X-Webhook-Signature"] = f"v2={v2_signature}"

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=S.webhooks_delivery_timeout_seconds) as client:
            resp = await client.post(url, content=payload, headers=headers)
            duration_ms = int((time.monotonic() - start) * 1000)
            success = 200 <= resp.status_code < 300
            return {
                "success": success,
                "response_code": resp.status_code,
                "response_body": resp.text[:500] if resp.text else "",
                "error": None if success else f"HTTP {resp.status_code}",
                "duration_ms": duration_ms,
            }
    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        return {
            "success": False,
            "response_code": None,
            "response_body": None,
            "error": str(exc)[:500],
            "duration_ms": duration_ms,
        }


async def test_endpoint(user_sub: str, endpoint_id: str) -> Dict[str, Any]:
    """Send a synchronous test delivery to verify endpoint connectivity."""
    raw_item = _get_endpoint_raw(user_sub, endpoint_id)
    if not raw_item:
        return {"delivery_id": "", "status": "failed", "error": "Endpoint not found", "duration_ms": 0}

    secret = _decrypt_secret(raw_item["secret"])
    delivery_id = f"wd_test_{uuid.uuid4().hex[:12]}"
    now = now_ts()
    payload = json.dumps({
        "id": _gen_event_id(),
        "type": "webhook.test",
        "created_at": now,
        "data": {"message": "This is a test webhook delivery."},
    })

    result = await deliver_webhook(
        url=raw_item["url"],
        payload=payload,
        secret=secret,
        delivery_id=delivery_id,
        event_type="webhook.test",
    )

    # Record test delivery in delivery log
    ttl_epoch = now + (S.webhooks_delivery_ttl_days * 86400)
    delivery_item = {
        "pk": f"ENDPOINT#{endpoint_id}",
        "sk": f"DELIVERY#{delivery_id}",
        "delivery_id": delivery_id,
        "endpoint_id": endpoint_id,
        "user_sub": user_sub,
        "event_type": "webhook.test",
        "event_id": delivery_id,
        "payload": payload,
        "status": "success" if result["success"] else "failed",
        "attempt_count": 1,
        "max_attempts": 1,
        "last_attempt_at": now,
        "last_response_code": result.get("response_code"),
        "last_response_body": result.get("response_body"),
        "last_error": result.get("error"),
        "created_at": now,
        "next_retry_at": now,
        "ttl_epoch": ttl_epoch,
    }
    # Remove None values (DDB can't store None as GSI key)
    delivery_item = {k: v for k, v in delivery_item.items() if v is not None}
    T.webhook_deliveries.put_item(Item=delivery_item)

    return {
        "delivery_id": delivery_id,
        "status": "success" if result["success"] else "failed",
        "response_code": result.get("response_code"),
        "response_body": result.get("response_body"),
        "error": result.get("error"),
        "duration_ms": result.get("duration_ms", 0),
    }


# ─── Delivery Log ───────────────────────────────────────────────────────────

def get_delivery_log(
    endpoint_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Get paginated delivery history for an endpoint."""
    kwargs: Dict[str, Any] = {
        "KeyConditionExpression": Key("pk").eq(f"ENDPOINT#{endpoint_id}")
        & Key("sk").begins_with("DELIVERY#"),
        "ScanIndexForward": False,
        "Limit": limit,
    }
    if cursor:
        import base64
        try:
            kwargs["ExclusiveStartKey"] = json.loads(base64.b64decode(cursor))
        except Exception:
            pass

    resp = T.webhook_deliveries.query(**kwargs)
    items = resp.get("Items", [])
    next_cursor = None
    last_key = resp.get("LastEvaluatedKey")
    if last_key:
        import base64
        next_cursor = base64.b64encode(json.dumps(last_key).encode()).decode()

    result = []
    for item in items:
        result.append({
            "delivery_id": item.get("delivery_id", ""),
            "endpoint_id": item.get("endpoint_id", ""),
            "event_type": item.get("event_type", ""),
            "event_id": item.get("event_id", ""),
            "status": item.get("status", ""),
            "attempt_count": int(item.get("attempt_count", 0)),
            "max_attempts": int(item.get("max_attempts", 5)),
            "next_retry_at": int(item["next_retry_at"]) if item.get("next_retry_at") else None,
            "last_attempt_at": int(item["last_attempt_at"]) if item.get("last_attempt_at") else None,
            "last_response_code": int(item["last_response_code"]) if item.get("last_response_code") else None,
            "last_response_body": item.get("last_response_body"),
            "last_error": item.get("last_error"),
            "created_at": int(item.get("created_at", 0)),
            "payload": item.get("payload"),
        })
    return result, next_cursor


# ─── Delivery state management ──────────────────────────────────────────────

def mark_delivery_success(delivery: Dict[str, Any], result: Dict[str, Any]) -> None:
    """Mark a delivery as successful."""
    now = now_ts()
    update_expr = "SET #st = :st, last_attempt_at = :la, last_response_code = :rc, attempt_count = :ac"
    expr_vals: Dict[str, Any] = {
        ":st": "success",
        ":la": now,
        ":rc": result.get("response_code", 200),
        ":ac": int(delivery.get("attempt_count", 0)) + 1,
    }
    expr_names = {"#st": "status"}
    if result.get("response_body"):
        update_expr += ", last_response_body = :rb"
        expr_vals[":rb"] = result["response_body"][:500]

    T.webhook_deliveries.update_item(
        Key={"pk": delivery["pk"], "sk": delivery["sk"]},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )


def reset_endpoint_failure_count(endpoint_id: str, user_sub: str) -> None:
    """Reset failure count to 0 on successful delivery."""
    now = now_ts()
    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression="SET failure_count = :z, last_delivery_at = :la, updated_at = :u",
        ExpressionAttributeValues={":z": 0, ":la": now, ":u": now},
    )


def handle_delivery_failure(
    delivery: Dict[str, Any],
    endpoint: Dict[str, Any],
    result: Dict[str, Any],
) -> None:
    """Handle a failed delivery: schedule retry or mark as dead letter."""
    from app.services.webhook_retry import compute_retry_delay, normalize_retry_policy, should_retry

    attempt = int(delivery.get("attempt_count", 0)) + 1
    now = now_ts()
    created_at = int(delivery.get("created_at", now))

    # Get endpoint's retry policy (v2) or fall back to v1 behavior
    raw_policy = endpoint.get("retry_policy")
    policy = normalize_retry_policy(raw_policy)

    update_expr = "SET #st = :st, last_attempt_at = :la, attempt_count = :ac, last_error = :le"
    expr_vals: Dict[str, Any] = {
        ":la": now,
        ":ac": attempt,
        ":le": (result.get("error") or "Unknown error")[:500],
    }
    expr_names = {"#st": "status"}

    if result.get("response_code"):
        update_expr += ", last_response_code = :rc"
        expr_vals[":rc"] = result["response_code"]
    if result.get("response_body"):
        update_expr += ", last_response_body = :rb"
        expr_vals[":rb"] = result["response_body"][:500]

    if should_retry(policy, attempt, created_at, now):
        # Schedule retry with computed delay
        expr_vals[":st"] = "failed"
        delay = compute_retry_delay(policy, attempt)
        expr_vals[":nra"] = now + delay
        update_expr += ", next_retry_at = :nra"
    else:
        # Dead letter
        expr_vals[":st"] = "dead_letter"
        update_expr += ", next_retry_at = :nra"
        expr_vals[":nra"] = now

    T.webhook_deliveries.update_item(
        Key={"pk": delivery["pk"], "sk": delivery["sk"]},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_vals,
    )

    # Increment endpoint failure count
    endpoint_id = endpoint.get("endpoint_id", "")
    user_sub = endpoint.get("user_sub", "")
    new_failure_count = int(endpoint.get("failure_count", 0)) + 1

    update_ep_expr = "SET failure_count = :fc, updated_at = :u"
    ep_vals: Dict[str, Any] = {":fc": new_failure_count, ":u": now}

    if new_failure_count >= S.webhooks_auto_disable_threshold:
        update_ep_expr += ", enabled = :e, disabled_reason = :dr"
        ep_vals[":e"] = False
        ep_vals[":dr"] = "auto_disabled_consecutive_failures"

    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression=update_ep_expr,
        ExpressionAttributeValues=ep_vals,
    )


def mark_delivery_dead_letter(delivery: Dict[str, Any], reason: str = "endpoint_disabled") -> None:
    """Mark a delivery as dead letter."""
    now = now_ts()
    T.webhook_deliveries.update_item(
        Key={"pk": delivery["pk"], "sk": delivery["sk"]},
        UpdateExpression="SET #st = :st, last_error = :le, last_attempt_at = :la, next_retry_at = :nra",
        ExpressionAttributeNames={"#st": "status"},
        ExpressionAttributeValues={":st": "dead_letter", ":le": reason, ":la": now, ":nra": now},
    )


# ─── Admin queries ──────────────────────────────────────────────────────────

def admin_list_all_endpoints(limit: int = 100) -> List[Dict[str, Any]]:
    """Scan all endpoints across users (admin only)."""
    # Scan for items with sk beginning with ENDPOINT#
    resp = T.webhook_endpoints.scan(
        FilterExpression="begins_with(sk, :prefix)",
        ExpressionAttributeValues={":prefix": "ENDPOINT#"},
        Limit=limit,
    )
    items = resp.get("Items", [])
    result = []
    for item in items:
        if not item.get("endpoint_id"):
            continue
        et = item.get("event_types", set())
        result.append({
            "endpoint_id": item["endpoint_id"],
            "user_sub": item.get("user_sub", ""),
            "url": item["url"],
            "description": item.get("description", ""),
            "event_types": sorted(et) if et else [],
            "enabled": item.get("enabled", True),
            "created_at": int(item.get("created_at", 0)),
            "failure_count": int(item.get("failure_count", 0)),
            "disabled_reason": item.get("disabled_reason"),
        })
    return result


def admin_get_health_summary() -> Dict[str, Any]:
    """Get delivery health summary for admin dashboard."""
    # Get all endpoints
    all_endpoints = admin_list_all_endpoints(limit=500)
    total = len(all_endpoints)
    enabled = sum(1 for e in all_endpoints if e.get("enabled", True))
    disabled = total - enabled

    # Get recent deliveries (last 24h) using ByUser GSI scan
    now = now_ts()
    cutoff = now - 86400

    # We do a scan on the deliveries table with a filter
    success_count = 0
    failed_count = 0
    dead_letter_count = 0
    total_deliveries = 0

    try:
        resp = T.webhook_deliveries.scan(
            FilterExpression="created_at >= :cutoff",
            ExpressionAttributeValues={":cutoff": cutoff},
            Limit=1000,
        )
        for item in resp.get("Items", []):
            total_deliveries += 1
            status = item.get("status", "")
            if status == "success":
                success_count += 1
            elif status == "failed":
                failed_count += 1
            elif status == "dead_letter":
                dead_letter_count += 1
    except Exception:
        pass

    return {
        "total_endpoints": total,
        "enabled_endpoints": enabled,
        "disabled_endpoints": disabled,
        "total_deliveries_24h": total_deliveries,
        "success_count_24h": success_count,
        "failed_count_24h": failed_count,
        "dead_letter_count_24h": dead_letter_count,
    }


def admin_disable_endpoint(endpoint_id: str, user_sub: str, reason: str = "admin_disabled") -> bool:
    """Admin force-disable an endpoint."""
    item = _get_endpoint_raw(user_sub, endpoint_id)
    if not item:
        return False

    now = now_ts()
    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression="SET enabled = :e, disabled_reason = :dr, updated_at = :u",
        ExpressionAttributeValues={":e": False, ":dr": reason, ":u": now},
    )

    # Update event-type index items
    for et in item.get("event_types", set()):
        try:
            T.webhook_endpoints.update_item(
                Key={"pk": f"EVENT#{et}", "sk": f"ENDPOINT#{endpoint_id}"},
                UpdateExpression="SET enabled = :e",
                ExpressionAttributeValues={":e": False},
            )
        except Exception:
            pass

    return True


def admin_list_dead_letters(limit: int = 50) -> List[Dict[str, Any]]:
    """List dead letter deliveries across all endpoints."""
    resp = T.webhook_deliveries.query(
        IndexName="ByStatus",
        KeyConditionExpression=Key("status").eq("dead_letter"),
        ScanIndexForward=False,
        Limit=limit,
    )
    items = resp.get("Items", [])
    result = []
    for item in items:
        result.append({
            "delivery_id": item.get("delivery_id", ""),
            "endpoint_id": item.get("endpoint_id", ""),
            "user_sub": item.get("user_sub", ""),
            "event_type": item.get("event_type", ""),
            "status": item.get("status", ""),
            "attempt_count": int(item.get("attempt_count", 0)),
            "last_error": item.get("last_error"),
            "created_at": int(item.get("created_at", 0)),
        })
    return result


def query_due_deliveries(status: str, now: int, limit: int = 50) -> List[Dict[str, Any]]:
    """Query deliveries that are due for processing via ByStatus GSI."""
    resp = T.webhook_deliveries.query(
        IndexName="ByStatus",
        KeyConditionExpression=Key("status").eq(status) & Key("next_retry_at").lte(now),
        Limit=limit,
    )
    return resp.get("Items", [])
