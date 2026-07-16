from __future__ import annotations

from typing import Any, Dict, List, Optional

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.core.time import now_ts


def _pk_creator(creator_id: str) -> str:
    return f"CREATOR#{creator_id}"


def _pk_subscriber(subscriber_id: str) -> str:
    return f"SUBSCRIBER#{subscriber_id}"


# SUBX-30: the set of subscription statuses that grant CURRENT access (lifecycle
# bound below by grace-extended current_period_end). 'canceling' = cancel-at-
# period-end: KEEP access until the period ends (the E1 sweeper flips it to
# 'canceled', which is excluded).
_LIVE_STATUSES = {"active", "past_due", "trialing", "canceling"}


def get_subscription_settings(creator_id: str) -> Dict[str, Any]:
    try:
        item = T.subscriptions.get_item(Key={"pk": _pk_creator(creator_id), "sk": "SETTINGS"}).get("Item")
    except Exception:
        item = None
    if not item:
        return {"require_subscription": False, "disable_auto_renew": False, "updated_at": 0}
    return {
        "require_subscription": bool(item.get("require_subscription", False)),
        "disable_auto_renew": bool(item.get("disable_auto_renew", False)),
        "updated_at": int(item.get("updated_at") or 0),
    }


def set_subscription_settings(
    creator_id: str,
    *,
    require_subscription: bool,
    disable_auto_renew: bool = False,
) -> Dict[str, Any]:
    item = {
        "pk": _pk_creator(creator_id),
        "sk": "SETTINGS",
        "require_subscription": bool(require_subscription),
        "disable_auto_renew": bool(disable_auto_renew),
        "updated_at": now_ts(),
    }
    T.subscriptions.put_item(Item=item)
    return get_subscription_settings(creator_id)


def creator_requires_subscription(creator_id: str) -> bool:
    return bool(get_subscription_settings(creator_id).get("require_subscription"))


# =============================================================================
# SUBX-30 PER-TIER MODEL - reconcile the abandoned fan_club TIER# primitives with
# the subscription PLAN# model so every real subscription resolves an ORDERED
# tier LEVEL (>=1, higher = more premium). Used by the tier-aware gate (SUBX-31)
# so a viewer only unlocks content at/below their subscribed tier.
# =============================================================================

def _monthly_equiv_cents(price_cents: Any, interval: Optional[str]) -> int:
    """Normalise a price to a per-month basis so annual vs monthly plans rank on
    a common axis (SUBX-11 parity)."""
    try:
        p = int(price_cents or 0)
    except Exception:
        p = 0
    if (interval or "month").lower() == "year":
        return int(round(p / 12.0))
    return p


def get_plan_level(creator_id: str, plan_id: str) -> int:
    """SUBX-30: resolve an ordered TIER LEVEL (>=1) for a plan. Resolution order,
    each falling through when absent:
      1. an explicit ``level`` persisted on the PLAN# META (X4 authoring);
      2. a fan_club ``TIER#`` whose ``plan_id`` matches (bridge the abandoned
         fan_club tier model into the PLAN# world);
      3. DERIVED by price rank - the plan's DENSE 1-based rank among the
         creator's active plans by monthly-equivalent price ascending (cheapest
         paid plan = level 1; equal prices share a level).
    Returns 1 when a level cannot otherwise be derived (a paid subscriber is at
    least the lowest tier - never strand them), 0 only when creator/plan is
    missing entirely."""
    if not creator_id or not plan_id:
        return 0
    # 1. explicit level on the PLAN# META
    meta = None
    try:
        meta = T.subscriptions.get_item(Key={"pk": f"PLAN#{plan_id}", "sk": "META"}).get("Item")
    except Exception:
        meta = None
    if meta and meta.get("level") is not None:
        try:
            return max(1, int(meta.get("level")))
        except Exception:
            pass
    # 2. fan_club TIER# bridge (TIER# links plan_id -> level)
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(_pk_creator(creator_id)) & Key("sk").begins_with("TIER#"),
        )
        for t in resp.get("Items", []):
            if t.get("plan_id") == plan_id and t.get("active", True) and t.get("level") is not None:
                return max(1, int(t.get("level")))
    except Exception:
        pass
    # 3. derived dense price-rank among the creator's active plans
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(_pk_creator(creator_id)) & Key("sk").begins_with("PLAN#"),
        )
        plans = [p for p in resp.get("Items", []) if (p.get("status") or "active") == "active"]
    except Exception:
        plans = []
    if not plans:
        return 1 if meta else 0
    plans.sort(key=lambda p: (_monthly_equiv_cents(p.get("price_cents"), p.get("interval")), int(p.get("created_at") or 0)))
    rank = 1
    last_price: Optional[int] = None
    resolved = 1
    for p in plans:
        pr = _monthly_equiv_cents(p.get("price_cents"), p.get("interval"))
        if last_price is not None and pr > last_price:
            rank += 1
        last_price = pr
        if p.get("plan_id") == plan_id:
            resolved = rank
    return resolved


def viewer_max_tier_level(viewer_id: str, creator_id: str) -> int:
    """SUBX-30/31/33: the HIGHEST tier level the viewer currently holds via a
    LIFECYCLE-ACTIVE subscription to ``creator_id`` (0 = none). A viewer with
    multiple subs to the same creator (or a downgrade pending) resolves to the
    max, so a bundle/multi-sub holder is NOT over-locked, and an upgrade unlocks
    the higher tier immediately. Re-locks on expiry because a lapsed period is
    excluded here (same bound as ``has_active_subscription``).

    Prefers a persisted ``tier_level`` on the sub record (stable against later
    re-ranking; written at subscribe/gift/plan-change and by the SUBX-32
    backfill) and falls back to live ``get_plan_level`` for legacy subs."""
    if not viewer_id or not creator_id:
        return 0
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(_pk_subscriber(viewer_id)) & Key("sk").begins_with("SUB#"),
        )
    except Exception:
        return 0
    now = now_ts()
    best = 0
    for item in resp.get("Items", []):
        if item.get("creator_id") != creator_id:
            continue
        if (item.get("status") or "").lower() not in _LIVE_STATUSES:
            continue
        period_end = int(item.get("current_period_end") or 0)
        grace_until = int(item.get("grace_until") or 0)
        effective_end = max(period_end, grace_until)
        if effective_end and effective_end <= now:
            continue
        lvl = item.get("tier_level")
        if lvl is None:
            lvl = get_plan_level(creator_id, str(item.get("plan_id") or ""))
        try:
            lvl = int(lvl)
        except Exception:
            lvl = 1
        if lvl > best:
            best = lvl
    return best


def get_subscriber_tier_level(subscriber_id: str, creator_id: str) -> Optional[int]:
    """SUBX-30 AC: the resolved tier level for a real subscription subscriber
    (None when they hold no lifecycle-active sub to the creator)."""
    lvl = viewer_max_tier_level(subscriber_id, creator_id)
    return lvl if lvl > 0 else None


def has_active_subscription(subscriber_id: str, creator_id: str, *, required_level: int = 0) -> bool:
    """SUB-E1 lifecycle-aware access check. When ``required_level`` <= 0 this is
    the original BINARY "any active sub" gate (unchanged - every existing caller
    keeps its behaviour). When ``required_level`` >= 1 (SUBX-31) it grants only
    when the viewer's HIGHEST held tier is at/above the required level."""
    if required_level and required_level > 0:
        return viewer_max_tier_level(subscriber_id, creator_id) >= int(required_level)
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(_pk_subscriber(subscriber_id)) & Key("sk").begins_with("SUB#"),
        )
    except Exception:
        return False
    items: List[Dict[str, Any]] = resp.get("Items", [])
    now = now_ts()
    for item in items:
        if item.get("creator_id") != creator_id:
            continue
        status = (item.get("status") or "").lower()
        # SUB-E1: expired/canceled subs never grant access.
        # SUB-E2 PART 2 (SUB-25): 'canceling' = cancel-at-period-end; KEEP access
        # until current_period_end (the effective_end check below bounds it); the
        # E1 sweeper flips it to 'canceled' (excluded) at period end.
        if status not in _LIVE_STATUSES:
            continue
        # SUB-E1 expiry enforcement: access is bounded by the paid period
        # (grace-extended). A lapsed sub (period elapsed with no successful
        # renewal) or a past_due sub beyond grace LOSES access. A record
        # with no period info (legacy/grandfathered) is left un-enforced.
        period_end = int(item.get("current_period_end") or 0)
        grace_until = int(item.get("grace_until") or 0)
        effective_end = max(period_end, grace_until)
        if effective_end and effective_end <= now:
            continue
        return True
    return False


def is_platform_admin(user_id: str) -> bool:
    """SUB-E3: best-effort platform-admin/root check for owner+ADMIN bypass on
    gated surfaces. Reads the users table role; never raises."""
    if not user_id:
        return False
    try:
        from app.core.tables import T
        item = T.users.get_item(Key={"user_sub": user_id}).get("Item") or {}
    except Exception:
        return False
    return str(item.get("role") or "").strip().lower() in {"admin", "root"}


def content_locked_for_viewer(
    viewer_id: str,
    creator_id: str,
    *,
    subscriber_only: bool = True,
    required_level: int = 0,
) -> bool:
    """SUB-E3 / SUBX-31 single source of truth for subscriber-only content gating.

    Returns True when a subscriber-only item owned by ``creator_id`` must be
    LOCKED (body withheld, non-destructive paywall) for ``viewer_id``:
      * not flagged subscriber-only        -> False (open)
      * owner / platform admin             -> False (bypass)
      * active subscriber AT/ABOVE the
        item's ``required_level``          -> False (unlocked)
      * syndicate-bundle holder            -> False (unlocked, never tier-capped)
      * everyone else                      -> True  (locked)

    ``required_level`` (SUBX-31) is the item's minimum tier level. 0 (default)
    preserves the pre-tier BINARY behaviour: ANY active sub unlocks - so ALL
    pre-existing content (which carries no tier requirement) and ALL existing
    subscribers behave exactly as before (SUBX-32 grandfather). A level >= 1
    unlocks only for a viewer whose held tier is at/above it; a lower-tier
    subscriber is locked out and upsold.

    Re-locks automatically on expiry because the subscription check is
    lifecycle-aware (SUB-E1: bounded by grace-extended current_period_end)."""
    if not subscriber_only:
        return False
    if not creator_id:
        return False
    if viewer_id and viewer_id == creator_id:
        return False
    if is_platform_admin(viewer_id):
        return False
    if viewer_id and has_active_subscription(viewer_id, creator_id, required_level=required_level):
        return False
    try:
        from app.services.syndicate_subscriptions import has_bundle_access
        if viewer_id and has_bundle_access(viewer_id, creator_id):
            return False
    except Exception:
        pass
    return True


def list_active_subscriber_ids(creator_id: str) -> List[str]:
    """ADV2 R4: enumerate the user_ids of users with an ACTIVE subscription to
    ``creator_id``. Reads the creator-index partition (``CREATOR#{creator_id}``,
    ``SUB#`` items) written by ``subscription_server.save_subscription`` -- the
    same index ``count_active_subscribers`` trusts -- so NO GSI/backfill is
    required. Deduped, active/trialing/past_due only. Best-effort (returns what
    it has on error)."""
    subs: List[str] = []
    seen: set = set()
    last = None
    try:
        while True:
            kwargs: Dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq(_pk_creator(creator_id))
                & Key("sk").begins_with("SUB#"),
            }
            if last:
                kwargs["ExclusiveStartKey"] = last
            resp = T.subscriptions.query(**kwargs)
            for it in resp.get("Items", []):
                status = (it.get("status") or "").lower()
                if status not in {"active", "trialing", "past_due"}:
                    continue
                sub = str(it.get("subscriber_id") or "")
                if sub and sub not in seen:
                    seen.add(sub)
                    subs.append(sub)
            last = resp.get("LastEvaluatedKey")
            if not last:
                break
    except Exception:
        return subs
    return subs


def can_access_creator(subscriber_id: str, creator_id: str) -> bool:
    if subscriber_id == creator_id:
        return True
    if not creator_requires_subscription(creator_id):
        return True
    if is_platform_admin(subscriber_id):  # SUB-E3: admin bypass
        return True
    if has_active_subscription(subscriber_id, creator_id):
        return True
    # Check syndicate bundle access (SYND-002)
    try:
        from app.services.syndicate_subscriptions import has_bundle_access
        if has_bundle_access(subscriber_id, creator_id):
            return True
    except Exception:
        pass
    return False


def require_subscription_access(subscriber_id: str, creator_id: str) -> None:
    if not can_access_creator(subscriber_id, creator_id):
        raise HTTPException(status_code=403, detail="Subscription required to access this creator")


def tier_label_for_level(creator_id: str, required_level: int) -> Optional[str]:
    """SUBX-31 app upsell: the display NAME of the cheapest active plan whose
    tier level is >= ``required_level`` - i.e. the tier a locked-out viewer must
    buy to unlock. None when no such plan / no requirement."""
    if not creator_id or not required_level or required_level < 1:
        return None
    try:
        resp = T.subscriptions.query(
            KeyConditionExpression=Key("pk").eq(_pk_creator(creator_id)) & Key("sk").begins_with("PLAN#"),
        )
        plans = [p for p in resp.get("Items", []) if (p.get("status") or "active") == "active"]
    except Exception:
        return None
    best_name = None
    best_price = None
    for p in plans:
        lvl = get_plan_level(creator_id, str(p.get("plan_id") or ""))
        if lvl < required_level:
            continue
        price = _monthly_equiv_cents(p.get("price_cents"), p.get("interval"))
        if best_price is None or price < best_price:
            best_price = price
            best_name = p.get("name")
    return best_name
