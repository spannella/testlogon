#!/usr/bin/env python3
"""ADV-B4 apply script (ADV-401/402/403/404/406). Idempotent + anchor-asserted.

Usage: python3 advb4_apply.py <repo_root>

Patches (string-anchored, NOT line-numbered, so it applies to both the dev clone
and the divergent prod tree):
  1. NEW app/services/ad_attribution.py                (ADV-401 last-click 7d)
  2. app/routers/subscription_server.py  SubscribeIn + subscribe hook  (ADV-402)
  3. app/models.py                        CartPurchaseIn.ad_click_id    (ADV-403)
  4. app/routers/shoppingcart.py          purchase hook                 (ADV-403)
  5. app/routers/newsfeed.py              UnlockPostRequest + unlock hook (ADV-404)
  6. app/services/ad_billing.py           creator credit type -> "credit" (ADV-406)

Each patch is a no-op if already applied (prints SKIP). Any missing anchor aborts
the whole run BEFORE writing anything (two-phase: validate all, then write all).
"""
import os
import sys

AD_ATTRIBUTION_PY = '''"""ADV-401: last-click CPA attribution over the AdClicks store.

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
'''


# ---- anchor-based edits (old -> new). Each is validated before any write. ----

SUBSCRIBE_MODEL_OLD = '''class SubscribeIn(BaseModel):
    subscriber_id: Optional[str] = None
    interval: Optional[Literal["month", "year"]] = None'''
SUBSCRIBE_MODEL_NEW = '''class SubscribeIn(BaseModel):
    subscriber_id: Optional[str] = None
    # ADV-402: optional last-click CPA attribution handle carried from an ad CTA.
    ad_click_id: Optional[str] = None
    interval: Optional[Literal["month", "year"]] = None'''

SUBSCRIBE_HOOK_OLD = '''        logger.warning("check_milestone failed on subscription signup", exc_info=True)

    refresh_subscription_calendar_events(sub, plan)
    return attach_subscription_profiles(sub)'''
SUBSCRIBE_HOOK_NEW = '''        logger.warning("check_milestone failed on subscription signup", exc_info=True)

    # ADV-402: attribute this subscription to the subscriber's last ad click
    # (explicit ad_click_id or last-click within 7d) and charge the CPA bid.
    # Only on a real charge (not a free trial). Best-effort: never break signup.
    if status != "trialing":
        try:
            from app.services.ad_attribution import attribute_conversion
            attribute_conversion(
                viewer_sub=subscriber_id,
                conversion_type="subscription",
                conversion_value_cents=int(sub.get("price_cents") or 0),
                ad_click_id=getattr(body, "ad_click_id", "") or "",
            )
        except Exception:
            logger.warning("ad_conversion_attribution_failed subscribe sub=%s", subscriber_id, exc_info=True)

    refresh_subscription_calendar_events(sub, plan)
    return attach_subscription_profiles(sub)'''

CART_MODEL_OLD = '''class CartPurchaseIn(BaseModel):
    promo_code: Optional[str] = None
    promo_code_id: Optional[str] = None'''
CART_MODEL_NEW = '''class CartPurchaseIn(BaseModel):
    promo_code: Optional[str] = None
    promo_code_id: Optional[str] = None
    # ADV-403: optional last-click CPA attribution handle carried from an ad CTA.
    ad_click_id: Optional[str] = None'''

CART_HOOK_OLD = '''        promo_code_id=body.promo_code_id,
    )
    audit_event(
        "cart_purchased",'''
CART_HOOK_NEW = '''        promo_code_id=body.promo_code_id,
    )
    # ADV-403: attribute this purchase to the buyer's last ad click (explicit
    # ad_click_id or last-click 7d) and charge the CPA bid. Idempotent: a retried
    # purchase re-resolves the same (already-converted) click -> no double charge.
    try:
        from app.services.ad_attribution import attribute_conversion
        attribute_conversion(
            viewer_sub=ctx["user_sub"],
            conversion_type="purchase",
            conversion_value_cents=int(purchase.get("purchased_total_cents") or 0),
            ad_click_id=getattr(body, "ad_click_id", "") or "",
        )
    except Exception:
        pass
    audit_event(
        "cart_purchased",'''

UNLOCK_MODEL_OLD = '''class UnlockPostRequest(BaseModel):
    post_id: str
    payment_method_id: Optional[str] = None'''
UNLOCK_MODEL_NEW = '''class UnlockPostRequest(BaseModel):
    post_id: str
    payment_method_id: Optional[str] = None
    # ADV-404: optional last-click CPA attribution handle carried from an ad CTA.
    ad_click_id: Optional[str] = None'''

UNLOCK_HOOK_OLD = '''        advance_progress(user_id, "unlock_count")
    except Exception:
        logger.debug("achievement hook: unlock_count", exc_info=True)

    return UnlockPostResponse(post_id=req.post_id, payment_intent=pi)'''
UNLOCK_HOOK_NEW = '''        advance_progress(user_id, "unlock_count")
    except Exception:
        logger.debug("achievement hook: unlock_count", exc_info=True)

    # ADV-404: attribute this paid unlock to the unlocker's last ad click
    # (explicit ad_click_id or last-click 7d) and charge the CPA bid. Best-effort.
    try:
        from app.services.ad_attribution import attribute_conversion
        attribute_conversion(
            viewer_sub=user_id,
            conversion_type="unlock",
            conversion_value_cents=int(price or 0),
            ad_click_id=getattr(req, "ad_click_id", "") or "",
        )
    except Exception:
        logger.warning("ad_conversion_attribution_failed unlock post=%s", req.post_id, exc_info=True)

    return UnlockPostResponse(post_id=req.post_id, payment_intent=pi)'''

# ADV-406: align the dev clone creator credit entry_type to "credit" (prod already
# has "credit"). Uniquely scoped by the surrounding _split_revenue creator credit.
BILLING_OLD = '''    # Credit creator via existing billing ledger
    if creator_share > 0 and creator_id:
        try:
            _sk, credit_item = new_ledger_entry(
                key_name="pk",
                key_value=user_pk(creator_id),
                entry_type="ad_revenue_credit",'''
BILLING_NEW = '''    # Credit creator via existing billing ledger
    if creator_share > 0 and creator_id:
        try:
            _sk, credit_item = new_ledger_entry(
                key_name="pk",
                key_value=user_pk(creator_id),
                # ADV-406: type "credit" so ad-revenue share shows in creator
                # earnings/payouts (creator_earnings filters type=="credit"),
                # Bug#3-safe. Aligns the dev clone with prod.
                entry_type="credit",'''


def patch_file(path, old, new, label):
    """Return (action, new_content). action in {apply, skip, missing}."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    if new in content:
        return ("skip", content)
    if old not in content:
        return ("missing", content)
    if content.count(old) != 1:
        raise SystemExit("ABORT %s: anchor not unique (%d matches) in %s" % (label, content.count(old), path))
    return ("apply", content.replace(old, new, 1))


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: advb4_apply.py <repo_root>")
    root = sys.argv[1]
    p = lambda rel: os.path.join(root, rel)

    edits = [
        (p("app/routers/subscription_server.py"), SUBSCRIBE_MODEL_OLD, SUBSCRIBE_MODEL_NEW, "ADV-402-model"),
        (p("app/routers/subscription_server.py"), SUBSCRIBE_HOOK_OLD, SUBSCRIBE_HOOK_NEW, "ADV-402-hook"),
        (p("app/models.py"), CART_MODEL_OLD, CART_MODEL_NEW, "ADV-403-model"),
        (p("app/routers/shoppingcart.py"), CART_HOOK_OLD, CART_HOOK_NEW, "ADV-403-hook"),
        (p("app/routers/newsfeed.py"), UNLOCK_MODEL_OLD, UNLOCK_MODEL_NEW, "ADV-404-model"),
        (p("app/routers/newsfeed.py"), UNLOCK_HOOK_OLD, UNLOCK_HOOK_NEW, "ADV-404-hook"),
    ]

    # Phase 1: validate every anchor. Accumulate per-file cumulative edits.
    file_state = {}
    plan = []
    for path, old, new, label in edits:
        cur = file_state.get(path)
        if cur is None:
            with open(path, "r", encoding="utf-8") as f:
                cur = f.read()
        if new in cur:
            print("SKIP  %-22s (already applied)" % label)
            file_state[path] = cur
            continue
        if old not in cur:
            raise SystemExit("ABORT %s: anchor not found in %s" % (label, path))
        if cur.count(old) != 1:
            raise SystemExit("ABORT %s: anchor not unique (%d) in %s" % (label, cur.count(old), path))
        cur = cur.replace(old, new, 1)
        file_state[path] = cur
        plan.append(label)
        print("PLAN  %-22s" % label)

    # ADV-406 (3-state, tolerant): dev clone has entry_type="ad_revenue_credit"
    # (apply -> "credit"+comment); prod already has entry_type="credit" (aligned,
    # SKIP). The creator-credit line is uniquely scoped by user_pk(creator_id).
    billing_path = p("app/services/ad_billing.py")
    bcur = file_state.get(billing_path)
    if bcur is None:
        with open(billing_path, "r", encoding="utf-8") as f:
            bcur = f.read()
    PROD_CREDIT_MARK = (
        '                key_value=user_pk(creator_id),\n'
        '                entry_type="credit",'
    )
    if BILLING_NEW in bcur or PROD_CREDIT_MARK in bcur:
        print("SKIP  ADV-406-entrytype      (already type=\"credit\")")
    elif BILLING_OLD in bcur:
        if bcur.count(BILLING_OLD) != 1:
            raise SystemExit("ABORT ADV-406: anchor not unique")
        file_state[billing_path] = bcur.replace(BILLING_OLD, BILLING_NEW, 1)
        plan.append("ADV-406-entrytype")
        print("PLAN  ADV-406-entrytype")
    else:
        raise SystemExit("ABORT ADV-406: creator-credit anchor not found in ad_billing.py")

    # Phase 2: write ad_attribution.py + all patched files.
    attr_path = p("app/services/ad_attribution.py")
    if os.path.exists(attr_path) and open(attr_path, encoding="utf-8").read() == AD_ATTRIBUTION_PY:
        print("SKIP  ad_attribution.py    (identical)")
    else:
        with open(attr_path, "w", encoding="utf-8") as f:
            f.write(AD_ATTRIBUTION_PY)
        print("WROTE app/services/ad_attribution.py")

    for path, content in file_state.items():
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print("WROTE %s" % os.path.relpath(path, root))

    print("OK applied=%d" % len(plan))


if __name__ == "__main__":
    main()
