"""CMP-004 — Unsubscribe / opt-out link for campaign emails.

Reuses the HMAC-signed one-time-use token pattern from cart_reminders.py.
Opt-out is written to T.cart_reminder_config (same table as cart opt-outs)
so a single opt-out row suppresses all marketing channels.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from typing import Any, Dict, Optional

from app.core.crypto import b64url, b64url_decode
from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

_CONSUMED_PK_PREFIX = "MKTOPTOUT#CONSUMED#"
_OPTOUT_PK_PREFIX = "OPTOUT#USER#"


def _unsubscribe_secret() -> bytes:
    secret = getattr(S, "marketing_unsubscribe_secret", "") or getattr(S, "ui_access_token_secret", "")
    return secret.encode("utf-8") if secret else b"marketing_unsubscribe"


def _sign_unsubscribe_token(party_id: str, campaign_id: str) -> str:
    ttl_days = getattr(S, "marketing_unsubscribe_token_ttl_days", 30)
    now = now_ts()
    payload = {
        "party_id": party_id,
        "campaign_id": campaign_id,
        "jti": uuid.uuid4().hex,
        "exp": now + int(ttl_days) * 86400,
        "iat": now,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(_unsubscribe_secret(), raw, hashlib.sha256).digest()
    return f"{b64url(raw)}.{b64url(sig)}"


def _verify_unsubscribe_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = b64url_decode(raw_b64)
        sig = b64url_decode(sig_b64)
        expected = hmac.new(_unsubscribe_secret(), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            return None
        if int(obj.get("exp", 0)) < now_ts():
            return None
        return obj
    except Exception:
        return None


def _mark_token_consumed(jti: str) -> bool:
    try:
        T.cart_reminder_config.put_item(
            Item={
                "pk": f"{_CONSUMED_PK_PREFIX}{jti}",
                "sk": "META",
                "consumed_at": now_ts(),
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True
    except Exception:
        return False


def generate_unsubscribe_url(party_id: str, campaign_id: str) -> str:
    """Mint and return a signed, time-limited unsubscribe URL."""
    token = _sign_unsubscribe_token(party_id, campaign_id)
    base = getattr(S, "public_base_url", "http://localhost:8000").rstrip("/")
    return f"{base}/ui/crm-marketing/optout/{token}"


def process_unsubscribe(token: str) -> Dict[str, Any]:
    """Verify token and write opt-out row. Returns success or error dict."""
    payload = _verify_unsubscribe_token(token)
    if not payload:
        return {"ok": False, "message": "Invalid or expired unsubscribe link."}

    jti = payload.get("jti", "")
    party_id = payload.get("party_id", "")

    if not _mark_token_consumed(jti):
        # Already consumed — treat as success (idempotent)
        return {"ok": True, "message": "You have already been unsubscribed."}

    # Write global opt-out (same row as cart_reminders.set_reminder_preference)
    try:
        ts = now_ts()
        T.cart_reminder_config.put_item(
            Item={
                "pk": f"{_OPTOUT_PK_PREFIX}{party_id}",
                "sk": "META",
                "opted_out": True,
                "updated_at": ts,
            }
        )
    except Exception:
        return {"ok": False, "message": "Could not record unsubscribe. Please try again."}

    try:
        from app.services.alerts import audit_event
        audit_event(
            "marketing.unsubscribe",
            party_id,
            campaign_id=payload.get("campaign_id"),
        )
    except Exception:
        pass

    return {"ok": True, "message": "You have been unsubscribed from marketing emails."}
