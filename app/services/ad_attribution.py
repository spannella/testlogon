"""ADV-401: last-click CPA attribution over the AdClicks store.

Given a viewer + a conversion event, resolve the most recent UNEXPIRED,
UNCONVERTED AdClicks row for that viewer (last-click, 7-day window via the
GSI ByViewer), atomically claim it (mark converted), then charge the campaign
its CPA bid through the funds-guarded ad_billing._process_charge and credit
revenue placement-aware via ad_billing._split_revenue.

Idempotent: the conditional claim (attribute_not_exists(converted_at)) plus the
charge_conversion idempotency_key ({ad_click_id}#conversion) guarantee AT MOST
ONE conversion charge per ad_click_id. Safe/no-op on missing/expired/converted
clicks.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# Last-click attribution window (matches the AdClicks TTL / expires_at = 7 days).
ATTRIBUTION_WINDOW_SECONDS = 604800


def _eligible(row: Optional[Dict[str, Any]], viewer_sub: str, cutoff: int, now: int) -> bool:
    """A click is eligible to attribute iff it belongs to this viewer, is inside
    the 7d window, is not already converted, and (defensively) is not TTL-expired."""
    if not row:
        return False
    if str(row.get("viewer_sub", "") or "") != viewer_sub:
        return False
    if int(row.get("created_at", 0) or 0) < cutoff:
        return False
    if str(row.get("status", "") or "") == "converted" or row.get("converted_at"):
        return False
    exp = row.get("expires_at")
    if exp is not None and int(exp) < now:
        return False
    return True


def _classify_click(ad_click_id: str, viewer_sub: str, cutoff: int, now: int):
    """Resolve an explicit click id -> (row_or_None, reason). Strict: an explicit
    id that is unknown / foreign / expired / already-converted is a hard no-op and
    is NEVER silently swapped for a different last-click (that would double-attribute
    a retried purchase)."""
    try:
        resp = T.ad_clicks.get_item(Key={"ad_click_id": ad_click_id})
    except Exception:
        logger.warning("ad_attribution_get_failed click=%s", ad_click_id)
        return None, "lookup_error"
    row = resp.get("Item")
    if not row:
        return None, "unknown_click"
    if str(row.get("viewer_sub", "") or "") != viewer_sub:
        return None, "foreign_click"
    if str(row.get("status", "") or "") == "converted" or row.get("converted_at"):
        return None, "already_converted"
    exp = row.get("expires_at")
    if int(row.get("created_at", 0) or 0) < cutoff or (exp is not None and int(exp) < now):
        return None, "expired_click"
    return row, "eligible"


def find_last_click(viewer_sub: str, *, now: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Return the most recent eligible (unexpired, unconverted) AdClicks row for
    the viewer via GSI ByViewer, or None. Last-click: newest created_at first."""
    if not viewer_sub:
        return None
    now = now or now_ts()
    cutoff = now - ATTRIBUTION_WINDOW_SECONDS
    try:
        resp = T.ad_clicks.query(
            IndexName="ByViewer",
            KeyConditionExpression=Key("viewer_sub").eq(viewer_sub)
            & Key("created_at").gte(cutoff),
            ScanIndexForward=False,  # most-recent click first
            Limit=25,
        )
    except Exception:
        logger.warning("ad_attribution_query_failed viewer=%s", viewer_sub)
        return None
    for row in resp.get("Items", []):
        if _eligible(row, viewer_sub, cutoff, now):
            return row
    return None


def attribute_conversion(
    *,
    viewer_sub: str,
    conversion_type: str,
    conversion_value_cents: int = 0,
    ad_click_id: str = "",
    now: Optional[int] = None,
) -> Dict[str, Any]:
    """Attribute a conversion (subscription / purchase / unlock) to the viewer's
    ad click and charge the CPA bid.

    Resolution: an explicit, still-eligible ``ad_click_id`` wins; otherwise (or if
    the explicit id is stale/foreign/converted) fall back to the viewer's last
    click within 7d. No eligible click -> no-op. Marks the click converted
    atomically, then charges charge_conversion (funds-guarded, idempotent).
    """
    if not viewer_sub:
        return {"attributed": False, "reason": "no_viewer"}
    now = now or now_ts()
    cutoff = now - ATTRIBUTION_WINDOW_SECONDS

    if ad_click_id:
        # Explicit handle (from the app CTA store, ADV-405): resolve strictly.
        row, reason = _classify_click(ad_click_id, viewer_sub, cutoff, now)
        if row is None:
            return {"attributed": False, "reason": reason, "ad_click_id": ad_click_id}
    else:
        # No explicit handle: fall back to the viewer's last click within 7d.
        row = find_last_click(viewer_sub, now=now)
        if not row:
            return {"attributed": False, "reason": "no_click"}

    resolved_click_id = str(row.get("ad_click_id"))

    # Atomic last-click claim -> the primary idempotency guard: exactly one
    # successful claim (and therefore at most one conversion charge) per click.
    try:
        T.ad_clicks.update_item(
            Key={"ad_click_id": resolved_click_id},
            UpdateExpression=(
                "SET #s = :converted, converted_at = :t, "
                "conversion_type = :ct, conversion_value_cents = :v"
            ),
            ConditionExpression="attribute_not_exists(converted_at) AND #s <> :converted",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":converted": "converted",
                ":t": now,
                ":ct": conversion_type,
                ":v": int(conversion_value_cents or 0),
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            logger.info("ad_conversion_already_attributed click=%s", resolved_click_id)
            return {"attributed": False, "reason": "already_converted", "ad_click_id": resolved_click_id}
        raise

    # Charge the campaign its CPA bid (funds-guarded via _process_charge). The
    # content owner drives the placement-aware split: present -> creator share +
    # platform remainder; empty (standalone newsfeed) -> platform 100%.
    from app.services import ad_billing

    content_owner_sub = str(row.get("content_owner_sub", "") or "")
    bid_cpa_cents = int(row.get("bid_cpa_cents") or 0)
    result: Dict[str, Any] = {
        "attributed": True,
        "ad_click_id": resolved_click_id,
        "conversion_type": conversion_type,
        "content_owner_sub": content_owner_sub,
        "campaign_id": str(row.get("campaign_id", "") or ""),
    }
    if bid_cpa_cents > 0:
        try:
            charge = ad_billing.charge_conversion(
                account_id=str(row.get("account_id", "") or ""),
                campaign_id=str(row.get("campaign_id", "") or ""),
                creative_id=str(row.get("creative_id", "") or ""),
                creator_id=content_owner_sub,
                content_id=str(row.get("content_id", "") or ""),
                bid_cpa_cents=bid_cpa_cents,
                conversion_value_cents=int(conversion_value_cents or 0),
                idempotency_key="%s#conversion" % resolved_click_id,
            )
            result["charge"] = charge
        except Exception:
            logger.warning("ad_conversion_charge_failed click=%s", resolved_click_id, exc_info=True)
            result["charge"] = {"ok": False, "reason": "charge_error"}
    else:
        result["charge"] = {"ok": True, "reason": "no_cpa_bid", "charge_cents": 0}
    logger.info(
        "ad_conversion_attributed click=%s type=%s owner=%s cpa=%s",
        resolved_click_id, conversion_type, content_owner_sub or "-", bid_cpa_cents,
    )
    return result
