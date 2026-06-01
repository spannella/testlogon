"""Syndicate open licensing -- auto-license management (LICENSE-005).

Open licensing is an optional rule for syndicates. When a syndicate admin
enables it, every member's registered content is auto-licensed to every other
member using uniform, syndicate-level terms. Auto-licenses are created via the
existing LICENSE-002 ``issued_licenses`` service (``license_mode=syndicate_auto``)
and persist even after a member leaves or open licensing is disabled.

Per-syndicate config (enabled flag + terms) and the content registry live in the
dedicated ``syndicate_open_licensing`` table (``T.syndicate_open_licensing``):

  - Config:   pk=SYND#{syndicate_id}        sk=CONFIG
  - Content:  pk=SYND#{syndicate_id}        sk=CONTENT#{content_id}
              also GSI1PK=SYND_CREATOR#{syndicate_id}#{creator_id} GSI1SK=registered_at
  - Exempt:   pk=SYND#{syndicate_id}        sk=EXEMPT#{content_id}

Membership and admin checks are delegated to ``app/services/syndicates.py``;
license records to ``app/services/issued_licenses.py``. This module only
orchestrates them.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts
from app.services import syndicates as syndicate_svc
from app.services import issued_licenses as license_svc

logger = logging.getLogger(__name__)

VALID_CONTENT_TYPES = {"video", "music", "image", "post", "broadcast", "clip"}
MAX_PCT = 100


# ---------------------------------------------------------------------------
# Terms validation / normalization
# ---------------------------------------------------------------------------

def _validate_terms(terms: Dict[str, Any]) -> Dict[str, Any]:
    """Validate + normalize license terms. Returns a clean dict."""
    profit = int(terms.get("profit_share_pct", 0) or 0)
    fixed = int(terms.get("fixed_cost_cents", 0) or 0)
    revenue = int(terms.get("revenue_share_pct", 0) or 0)
    currency = str(terms.get("currency", "usd") or "usd").lower()[:3]
    if not (0 <= profit <= MAX_PCT):
        raise HTTPException(status_code=422, detail="profit_share_pct must be 0-100")
    if not (0 <= revenue <= MAX_PCT):
        raise HTTPException(status_code=422, detail="revenue_share_pct must be 0-100")
    if fixed < 0:
        raise HTTPException(status_code=422, detail="fixed_cost_cents must be >= 0")
    return {
        "profit_share_pct": profit,
        "fixed_cost_cents": fixed,
        "revenue_share_pct": revenue,
        "currency": currency,
    }


def _coerce_terms(raw: Any) -> Dict[str, Any]:
    """Coerce a stored terms map (with possible Decimal values) to clean ints."""
    raw = raw or {}
    return {
        "profit_share_pct": int(raw.get("profit_share_pct", 0) or 0),
        "fixed_cost_cents": int(raw.get("fixed_cost_cents", 0) or 0),
        "revenue_share_pct": int(raw.get("revenue_share_pct", 0) or 0),
        "currency": str(raw.get("currency", "usd") or "usd"),
    }


# ---------------------------------------------------------------------------
# Config storage
# ---------------------------------------------------------------------------

def _config_key(syndicate_id: str) -> Dict[str, str]:
    return {"pk": f"SYND#{syndicate_id}", "sk": "CONFIG"}


def _get_config_item(syndicate_id: str) -> Optional[Dict[str, Any]]:
    resp = T.syndicate_open_licensing.get_item(Key=_config_key(syndicate_id))
    return resp.get("Item")


def get_open_licensing_config(*, syndicate_id: str) -> Dict[str, Any]:
    """Get open licensing configuration for a syndicate."""
    syndicate_svc.get_syndicate(syndicate_id)  # touch; raises nothing if missing
    item = _get_config_item(syndicate_id)
    if not item:
        return {
            "syndicate_id": syndicate_id,
            "open_licensing_enabled": False,
            "open_licensing_terms": None,
            "enabled_at": None,
            "disabled_at": None,
        }
    return {
        "syndicate_id": syndicate_id,
        "open_licensing_enabled": bool(item.get("open_licensing_enabled", False)),
        "open_licensing_terms": _coerce_terms(item.get("open_licensing_terms"))
        if item.get("open_licensing_terms") is not None
        else None,
        "enabled_at": int(item["enabled_at"]) if item.get("enabled_at") is not None else None,
        "disabled_at": int(item["disabled_at"]) if item.get("disabled_at") is not None else None,
    }


def _is_enabled(syndicate_id: str) -> bool:
    item = _get_config_item(syndicate_id)
    return bool(item and item.get("open_licensing_enabled"))


def _current_terms(syndicate_id: str) -> Dict[str, Any]:
    item = _get_config_item(syndicate_id)
    return _coerce_terms((item or {}).get("open_licensing_terms"))


# ---------------------------------------------------------------------------
# Enable / disable / terms (admin only)
# ---------------------------------------------------------------------------

def enable_open_licensing(
    *,
    syndicate_id: str,
    admin_sub: str,
    terms: Dict[str, Any],
) -> Dict[str, Any]:
    """Enable open licensing on a syndicate. Admin only.

    Auto-licenses any already-registered (non-exempt) content among current
    members. Idempotent -- re-enabling does not duplicate existing licenses.
    """
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    clean = _validate_terms(terms)
    ts = now_ts()
    meta = syndicate_svc.get_syndicate(syndicate_id) or {}

    T.syndicate_open_licensing.put_item(Item={
        "pk": f"SYND#{syndicate_id}",
        "sk": "CONFIG",
        "syndicate_id": syndicate_id,
        "open_licensing_enabled": True,
        "open_licensing_terms": clean,
        "enabled_at": ts,
        "updated_at": ts,
        # disabled_at intentionally omitted/cleared when re-enabling
    })

    # Auto-license existing registered content among current members.
    self_healed = _reconcile_all_content(syndicate_id, terms=clean)

    # Notify members
    for m in syndicate_svc.list_members(syndicate_id):
        uid = m.get("user_id")
        if uid and uid != admin_sub:
            _safe_alert(uid, "syndicate_open_licensing_enabled", "Syndicate Open Licensing Enabled", {
                "syndicate_id": syndicate_id,
                "syndicate_name": meta.get("name", ""),
                "terms": clean,
            })

    return {
        "syndicate_id": syndicate_id,
        "open_licensing_enabled": True,
        "open_licensing_terms": clean,
        "enabled_at": ts,
        "disabled_at": None,
        "licenses_created": self_healed,
    }


def disable_open_licensing(*, syndicate_id: str, admin_sub: str) -> Dict[str, Any]:
    """Disable open licensing. Existing auto-licenses remain active."""
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    existing = _get_config_item(syndicate_id)
    ts = now_ts()
    terms = _coerce_terms((existing or {}).get("open_licensing_terms"))

    T.syndicate_open_licensing.put_item(Item={
        "pk": f"SYND#{syndicate_id}",
        "sk": "CONFIG",
        "syndicate_id": syndicate_id,
        "open_licensing_enabled": False,
        "open_licensing_terms": terms,
        "enabled_at": int(existing["enabled_at"]) if existing and existing.get("enabled_at") is not None else ts,
        "disabled_at": ts,
        "updated_at": ts,
    })

    for m in syndicate_svc.list_members(syndicate_id):
        uid = m.get("user_id")
        if uid and uid != admin_sub:
            _safe_alert(uid, "syndicate_open_licensing_disabled", "Syndicate Open Licensing Disabled", {
                "syndicate_id": syndicate_id,
            })

    return {
        "syndicate_id": syndicate_id,
        "open_licensing_enabled": False,
        "open_licensing_terms": terms,
        "disabled_at": ts,
    }


def update_open_licensing_terms(
    *,
    syndicate_id: str,
    admin_sub: str,
    terms: Dict[str, Any],
) -> Dict[str, Any]:
    """Update syndicate-level license terms. Applies to FUTURE auto-licenses only.

    Existing auto-licenses keep their frozen terms.
    """
    syndicate_svc._require_admin(syndicate_id, admin_sub)
    clean = _validate_terms(terms)
    existing = _get_config_item(syndicate_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Open licensing has not been configured")
    ts = now_ts()
    T.syndicate_open_licensing.update_item(
        Key=_config_key(syndicate_id),
        UpdateExpression="SET open_licensing_terms = :t, updated_at = :ts",
        ExpressionAttributeValues={":t": clean, ":ts": ts},
    )
    return {
        "syndicate_id": syndicate_id,
        "open_licensing_enabled": bool(existing.get("open_licensing_enabled", False)),
        "open_licensing_terms": clean,
    }


# ---------------------------------------------------------------------------
# Content registration + auto-licensing
# ---------------------------------------------------------------------------

def register_content(
    *,
    syndicate_id: str,
    creator_sub: str,
    content_id: str,
    content_type: str,
) -> Dict[str, Any]:
    """Register content under syndicate open licensing.

    Creates auto-license records to every current member (except the creator),
    idempotently. Requires open licensing to be enabled.
    """
    syndicate_svc._require_is_member(syndicate_id, creator_sub)
    if content_type not in VALID_CONTENT_TYPES:
        raise HTTPException(status_code=422, detail=f"Invalid content_type: {content_type}")
    if not _is_enabled(syndicate_id):
        raise HTTPException(status_code=400, detail="Open licensing is not enabled for this syndicate")

    ts = now_ts()
    terms = _current_terms(syndicate_id)

    # Content registry record (idempotent put -- preserve registered_at if existing)
    existing = T.syndicate_open_licensing.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"CONTENT#{content_id}"}
    ).get("Item")
    registered_at = int(existing["registered_at"]) if existing and existing.get("registered_at") is not None else ts
    is_exempt = bool(existing.get("exempt")) if existing else False

    T.syndicate_open_licensing.put_item(Item={
        "pk": f"SYND#{syndicate_id}",
        "sk": f"CONTENT#{content_id}",
        "content_id": content_id,
        "content_type": content_type,
        "creator_id": creator_sub,
        "registered_at": registered_at,
        "exempt": is_exempt,
        "GSI1PK": f"SYND_CREATOR#{syndicate_id}#{creator_sub}",
        "GSI1SK": registered_at,
    })

    if is_exempt:
        return {"content_id": content_id, "syndicate_id": syndicate_id, "licenses_created": 0}

    created = _auto_license_content_to_members(
        syndicate_id=syndicate_id,
        content_id=content_id,
        content_type=content_type,
        creator_id=creator_sub,
        terms=terms,
    )
    return {"content_id": content_id, "syndicate_id": syndicate_id, "licenses_created": created}


def _auto_license_content_to_members(
    *,
    syndicate_id: str,
    content_id: str,
    content_type: str,
    creator_id: str,
    terms: Dict[str, Any],
    only_licensee: Optional[str] = None,
) -> int:
    """Issue syndicate_auto licenses for one content item to current members.

    Idempotent: skips members who already hold an active auto-license for this
    content. If ``only_licensee`` is set, only that member is considered.
    """
    existing = license_svc.list_licenses_for_content(content_id=content_id)
    already: set = set()
    for lic in existing:
        if (
            lic.get("license_mode") == "syndicate_auto"
            and lic.get("syndicate_id") == syndicate_id
            and lic.get("status") == "active"
            and lic.get("licensee_id")
        ):
            already.add(lic["licensee_id"])

    created = 0
    for m in syndicate_svc.list_members(syndicate_id):
        uid = m.get("user_id")
        if not uid or uid == creator_id:
            continue
        if only_licensee and uid != only_licensee:
            continue
        if uid in already:
            continue
        try:
            license_svc.issue_license(
                licensor_sub=creator_id,
                content_id=content_id,
                content_type=content_type,
                license_mode="syndicate_auto",
                licensee_id=uid,
                profit_share_pct=terms.get("profit_share_pct", 0),
                fixed_cost_cents=terms.get("fixed_cost_cents", 0),
                revenue_share_pct=terms.get("revenue_share_pct", 0),
                currency=terms.get("currency", "usd"),
                syndicate_id=syndicate_id,
            )
            created += 1
        except Exception:
            logger.warning("Failed to auto-issue syndicate license", exc_info=True)
    return created


def _list_registered_content(syndicate_id: str) -> List[Dict[str, Any]]:
    """All CONTENT# records registered under a syndicate."""
    resp = T.syndicate_open_licensing.query(
        KeyConditionExpression=Key("pk").eq(f"SYND#{syndicate_id}")
        & Key("sk").begins_with("CONTENT#"),
    )
    return resp.get("Items", [])


def _reconcile_all_content(syndicate_id: str, *, terms: Dict[str, Any]) -> int:
    """Re-issue auto-licenses for all non-exempt registered content among members."""
    total = 0
    for item in _list_registered_content(syndicate_id):
        if item.get("exempt"):
            continue
        total += _auto_license_content_to_members(
            syndicate_id=syndicate_id,
            content_id=item["content_id"],
            content_type=item.get("content_type", "post"),
            creator_id=item.get("creator_id", ""),
            terms=terms,
        )
    return total


# ---------------------------------------------------------------------------
# Membership lifecycle hooks (invoked from syndicates.py)
# ---------------------------------------------------------------------------

def on_member_joined(*, syndicate_id: str, new_member_id: str) -> int:
    """When a new member joins a syndicate with open licensing, auto-license all
    existing registered content (by other members) to the new member.

    Idempotent. Returns count of auto-licenses created. No-op if disabled.
    """
    try:
        if not _is_enabled(syndicate_id):
            return 0
        terms = _current_terms(syndicate_id)
        count = 0
        for item in _list_registered_content(syndicate_id):
            if item.get("exempt"):
                continue
            creator_id = item.get("creator_id", "")
            if creator_id == new_member_id:
                continue
            count += _auto_license_content_to_members(
                syndicate_id=syndicate_id,
                content_id=item["content_id"],
                content_type=item.get("content_type", "post"),
                creator_id=creator_id,
                terms=terms,
                only_licensee=new_member_id,
            )
        return count
    except Exception:
        logger.warning("on_member_joined open-licensing hook failed", exc_info=True)
        return 0


def on_member_left(*, syndicate_id: str, member_id: str) -> Dict[str, Any]:
    """When a member leaves, existing auto-licenses REMAIN active.

    No new auto-licenses will be created for/by that member. No revocation.
    """
    return {"syndicate_id": syndicate_id, "member_id": member_id, "action": "licenses_preserved"}


# ---------------------------------------------------------------------------
# Exemption
# ---------------------------------------------------------------------------

def exempt_content(*, syndicate_id: str, creator_sub: str, content_id: str) -> Dict[str, Any]:
    """Exempt a content item from syndicate auto-licensing. Owner only.

    Revokes existing syndicate_auto licenses for this content.
    """
    syndicate_svc._require_is_member(syndicate_id, creator_sub)
    content = T.syndicate_open_licensing.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"CONTENT#{content_id}"}
    ).get("Item")
    if not content:
        raise HTTPException(status_code=404, detail="Content is not registered under this syndicate")
    if content.get("creator_id") != creator_sub:
        raise HTTPException(status_code=403, detail="Only the content owner can exempt it")

    ts = now_ts()
    T.syndicate_open_licensing.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"CONTENT#{content_id}"},
        UpdateExpression="SET exempt = :e",
        ExpressionAttributeValues={":e": True},
    )
    T.syndicate_open_licensing.put_item(Item={
        "pk": f"SYND#{syndicate_id}",
        "sk": f"EXEMPT#{content_id}",
        "content_id": content_id,
        "creator_id": creator_sub,
        "exempted_at": ts,
    })

    revoked = _revoke_auto_licenses_for_content(content_id, syndicate_id, creator_sub)
    return {"content_id": content_id, "syndicate_id": syndicate_id, "revoked_count": revoked, "exempt": True}


def remove_content_exemption(*, syndicate_id: str, creator_sub: str, content_id: str) -> Dict[str, Any]:
    """Remove exemption, re-enabling auto-licensing for this content. Owner only."""
    syndicate_svc._require_is_member(syndicate_id, creator_sub)
    content = T.syndicate_open_licensing.get_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"CONTENT#{content_id}"}
    ).get("Item")
    if not content:
        raise HTTPException(status_code=404, detail="Content is not registered under this syndicate")
    if content.get("creator_id") != creator_sub:
        raise HTTPException(status_code=403, detail="Only the content owner can manage its exemption")

    T.syndicate_open_licensing.update_item(
        Key={"pk": f"SYND#{syndicate_id}", "sk": f"CONTENT#{content_id}"},
        UpdateExpression="SET exempt = :e",
        ExpressionAttributeValues={":e": False},
    )
    try:
        T.syndicate_open_licensing.delete_item(
            Key={"pk": f"SYND#{syndicate_id}", "sk": f"EXEMPT#{content_id}"}
        )
    except Exception:
        logger.warning("Failed to delete exempt record", exc_info=True)

    created = 0
    if _is_enabled(syndicate_id):
        created = _auto_license_content_to_members(
            syndicate_id=syndicate_id,
            content_id=content_id,
            content_type=content.get("content_type", "post"),
            creator_id=content.get("creator_id", creator_sub),
            terms=_current_terms(syndicate_id),
        )
    return {"content_id": content_id, "syndicate_id": syndicate_id, "licenses_created": created, "exempt": False}


def _revoke_auto_licenses_for_content(content_id: str, syndicate_id: str, licensor_sub: str) -> int:
    """Revoke all active syndicate_auto licenses for a content item in this syndicate."""
    revoked = 0
    for lic in license_svc.list_licenses_for_content(content_id=content_id, status_filter="active"):
        if lic.get("license_mode") != "syndicate_auto":
            continue
        if lic.get("syndicate_id") != syndicate_id:
            continue
        try:
            license_svc.revoke_license(
                licensor_sub=licensor_sub,
                issued_license_id=lic["issued_license_id"],
                content_id=content_id,
                reason="Content exempted from syndicate open licensing",
            )
            revoked += 1
        except Exception:
            logger.warning("Failed to revoke syndicate_auto license", exc_info=True)
    return revoked


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

def list_syndicate_content(
    *,
    syndicate_id: str,
    creator_id: Optional[str] = None,
    include_exempt: bool = True,
) -> List[Dict[str, Any]]:
    """List content registered under syndicate open licensing."""
    items = _list_registered_content(syndicate_id)
    out: List[Dict[str, Any]] = []
    for item in items:
        if creator_id and item.get("creator_id") != creator_id:
            continue
        if not include_exempt and item.get("exempt"):
            continue
        out.append({
            "content_id": item.get("content_id", ""),
            "content_type": item.get("content_type", ""),
            "creator_id": item.get("creator_id", ""),
            "registered_at": int(item.get("registered_at", 0) or 0),
            "exempt": bool(item.get("exempt", False)),
        })
    out.sort(key=lambda c: c["registered_at"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Internal: alerts
# ---------------------------------------------------------------------------

def _safe_alert(user_id: str, event: str, title: str, details: Dict[str, Any]) -> None:
    try:
        from app.services.alerts import write_alert
        write_alert(user_id, event=event, outcome="info", title=title, details=details)
    except Exception:
        logger.warning("Failed to write open-licensing alert", exc_info=True)
