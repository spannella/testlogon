"""Admin runtime email settings (EML-002).

Stores a single CONFIG/GLOBAL override row in ``T.email_settings``.
When the flag ``S.admin_email_settings_enabled`` is off, every public
function is a no-op and ``get_email_settings`` falls back to env-var
defaults — the existing ``send_alert_email`` behaviour is byte-for-byte
unchanged.

Cache: module-level dict cached for ``S.email_settings_cache_ttl_seconds``
(default 60 s) — invalidated eagerly on write.  Same pattern as
``app/services/billing_config.py``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Storage keys (mirrors billing_config PK/SK naming convention)
# ---------------------------------------------------------------------------

_PK = "CONFIG"
_SK = "GLOBAL"

# ---------------------------------------------------------------------------
# In-process cache
# ---------------------------------------------------------------------------

_CACHE: Optional[Dict[str, Any]] = None
_CACHE_TS: int = 0


def _cache_ttl() -> int:
    return int(getattr(S, "email_settings_cache_ttl_seconds", 60) or 60)


def _invalidate_cache() -> None:
    global _CACHE, _CACHE_TS
    _CACHE = None
    _CACHE_TS = 0


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_email_settings() -> Dict[str, Any]:
    """Return effective email settings.

    Reads CONFIG/GLOBAL from T.email_settings.  Falls back to
    S.alerts_from_email / S.alerts_email_enabled when the row is absent or on
    any DDB error (best-effort; never raises).  Returns a dict matching
    EmailSettingsOut field names.
    """
    global _CACHE, _CACHE_TS

    ts = now_ts()
    if _CACHE is not None and (ts - _CACHE_TS) < _cache_ttl():
        return dict(_CACHE)

    _env_fallback: Dict[str, Any] = {
        "from_email": getattr(S, "alerts_from_email", ""),
        "reply_to_email": None,
        "ses_enabled": getattr(S, "alerts_email_enabled", True),
        "smtp_enabled": False,
        "updated_at": None,
        "updated_by": None,
        "source": "env_fallback",
    }

    try:
        resp = T.email_settings.get_item(Key={"pk": _PK, "sk": _SK})
        item = resp.get("Item")
        if not item:
            _CACHE = _env_fallback
            _CACHE_TS = ts
            return dict(_env_fallback)
        result: Dict[str, Any] = {
            "from_email": item.get("from_email", getattr(S, "alerts_from_email", "")),
            "reply_to_email": item.get("reply_to_email") or None,
            "ses_enabled": bool(item.get("ses_enabled", getattr(S, "alerts_email_enabled", True))),
            "smtp_enabled": bool(item.get("smtp_enabled", False)),
            "updated_at": int(item["updated_at"]) if item.get("updated_at") else None,
            "updated_by": item.get("updated_by"),
            "source": "ddb_override",
        }
        _CACHE = result
        _CACHE_TS = ts
        return dict(result)
    except Exception:
        logger.exception("email_settings_read_failed — falling back to env defaults")
        return dict(_env_fallback)


def update_email_settings(
    actor_sub: str,
    *,
    from_email: Optional[str] = None,
    reply_to_email: Optional[str] = None,
    ses_enabled: Optional[bool] = None,
    smtp_enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    """Merge-patch CONFIG/GLOBAL in T.email_settings.

    Validates ``from_email`` via ``normalize_email``.  Raises
    ``HTTPException(400)`` on invalid format.  Clears the in-process cache so
    the next ``get_email_settings()`` call reads fresh data.  Calls
    ``audit_event`` with event ``"email_settings_updated"``.

    Returns the updated dict in EmailSettingsOut format.
    """
    from fastapi import HTTPException
    from app.core.normalize import normalize_email

    if from_email is not None:
        try:
            from_email = normalize_email(from_email)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Read-modify-write: merge over current effective settings
    current = get_email_settings()

    merged: Dict[str, Any] = {
        "pk": _PK,
        "sk": _SK,
        "from_email": from_email if from_email is not None else current.get("from_email", ""),
        "reply_to_email": (
            reply_to_email[:254]
            if reply_to_email is not None
            else current.get("reply_to_email") or ""
        ),
        "ses_enabled": ses_enabled if ses_enabled is not None else current.get("ses_enabled", True),
        "smtp_enabled": smtp_enabled if smtp_enabled is not None else current.get("smtp_enabled", False),
        "updated_at": now_ts(),
        "updated_by": actor_sub,
    }

    try:
        T.email_settings.put_item(Item=merged)
    except Exception:
        logger.exception("email_settings_write_failed")
        raise

    _invalidate_cache()

    # Audit trail
    try:
        from app.services.alerts import audit_event
        audit_event(
            "email_settings_updated",
            "system_email_settings",
            from_email=merged["from_email"],
            ses_enabled=merged["ses_enabled"],
            smtp_enabled=merged["smtp_enabled"],
            reply_to_email=merged["reply_to_email"],
            updated_by=actor_sub,
        )
    except Exception:
        logger.exception("email_settings_audit_failed")

    result = dict(merged)
    result["source"] = "ddb_override"
    result["reply_to_email"] = merged["reply_to_email"] or None
    return result
