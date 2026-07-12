"""BRAND-001 — Platform branding service (decision D6).

Provides a cached, env-fallback, never-raising ``get_branding()`` helper and
a ``set_branding(...)`` upsert for the PLATFORM#BRANDING settings row.

Modelled directly on ``app/services/billing_config.py`` (cache + env-fallback
+ DDB read).  No ``if S.dev_mode`` branches anywhere — SECOPS-007 parity.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PK = "PLATFORM"
_SK = "BRANDING"

# ---------------------------------------------------------------------------
# Module-level cache (mirrors billing_config.py:46-47)
# ---------------------------------------------------------------------------

_cache: Optional[Dict[str, Any]] = None
_cache_ts: int = 0


def _cache_ttl() -> int:
    return int(getattr(S, "branding_cache_ttl_seconds", 60) or 60)


def _defaults() -> Dict[str, Any]:
    name = getattr(S, "platform_name", "") or "testlogon"
    return {
        "platform_name": name,
        "name": name,   # alias — callers using ["name"] or ["platform_name"] both work
        "logo_url": getattr(S, "platform_logo_url", "") or "",
        "support_email": getattr(S, "platform_support_email", "") or "",
        "updated_at": None,
        "updated_by": None,
    }


def invalidate_cache() -> None:
    """Drop the in-memory branding cache (forces a fresh DDB read next call)."""
    global _cache, _cache_ts
    _cache = None
    _cache_ts = 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_branding() -> Dict[str, Any]:
    """Return the effective branding (DDB override-or-env-default).

    Cached for ``branding_cache_ttl_seconds`` (default 60 s).  **Never
    raises** — any DDB error collapses to the env defaults so that
    ``{{platform_name}}`` template rendering can never ``AttributeError``
    even if the table is missing or throttled.
    """
    global _cache, _cache_ts
    now = now_ts()
    if _cache is not None and (now - _cache_ts) < _cache_ttl():
        return dict(_cache)

    out = _defaults()
    try:
        resp = T.platform_settings.get_item(Key={"pk": _PK, "sk": _SK})
        item = resp.get("Item")
    except Exception:
        # Defensive: DDB outage / missing table / credentials error → env defaults.
        item = None

    if item:
        nm = item.get("name")
        if nm:
            out["name"] = nm
            out["platform_name"] = nm
        if item.get("logo_url") is not None:
            out["logo_url"] = item["logo_url"]
        if item.get("support_email") is not None:
            out["support_email"] = item["support_email"]
        if item.get("updated_at") is not None:
            out["updated_at"] = int(item["updated_at"])
        out["updated_by"] = item.get("updated_by")

    _cache = dict(out)
    _cache_ts = now
    return out


def set_branding(
    *,
    name: Optional[str] = None,
    logo_url: Optional[str] = None,
    support_email: Optional[str] = None,
    actor_sub: str,
) -> Dict[str, Any]:
    """Upsert the PLATFORM#BRANDING row with only the provided fields.

    ``name`` is a DynamoDB reserved word and is aliased via
    ``ExpressionAttributeNames={"#nm": "name"}``.

    Always invalidates the in-memory cache after a successful write so
    that a subsequent ``get_branding()`` in the same process reflects the
    change immediately (read-your-writes guarantee).

    Returns the result of ``get_branding()`` (the new effective state).
    """
    expr_parts: List[str] = ["updated_at = :ua", "updated_by = :ub"]
    vals: Dict[str, Any] = {":ua": now_ts(), ":ub": actor_sub or "system"}

    if name is not None:
        expr_parts.append("#nm = :nm")
        vals[":nm"] = name
    if logo_url is not None:
        expr_parts.append("logo_url = :lu")
        vals[":lu"] = logo_url
    if support_email is not None:
        expr_parts.append("support_email = :se")
        vals[":se"] = support_email

    update_kwargs: Dict[str, Any] = dict(
        Key={"pk": _PK, "sk": _SK},
        UpdateExpression="SET " + ", ".join(expr_parts),
        ExpressionAttributeValues=vals,
    )
    # Only include ExpressionAttributeNames when the #nm alias is actually used;
    # DynamoDB (and moto) reject unused entries in ExpressionAttributeNames.
    if name is not None:
        update_kwargs["ExpressionAttributeNames"] = {"#nm": "name"}

    T.platform_settings.update_item(**update_kwargs)

    invalidate_cache()

    # Best-effort audit — swallowed so a logging failure never blocks the write.
    _audit("branding.updated", actor_sub, fields=[
        k for k in ("name", "logo_url", "support_email")
        if locals().get(k) is not None
    ])

    return get_branding()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _audit(event: str, actor_sub: str, **fields: Any) -> None:
    """Best-effort audit wrapper (lazy import to avoid circular deps)."""
    try:
        from app.services.alerts import audit_event
        audit_event(event, actor_sub or "system", None, **fields)
    except Exception:
        pass
