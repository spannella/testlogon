"""SUBX-32 migration: backfill a persisted ``tier_level`` onto EXISTING
lifecycle-active subscription records so per-tier gating is stable against later
plan re-ranking.

Migration rule (NO existing subscriber loses access they paid for):
  * An existing sub maps to its PLAN's resolved level via
    subscription_access.get_plan_level (explicit level -> fan_club TIER# bridge ->
    dense price-rank). When a plan can no longer be resolved (archived/deleted),
    grandfather to level 1 (the LOWEST paid tier) so the subscriber is never
    stranded above their access.
  * Pre-tier CONTENT carries no ``required_tier_level`` (defaults to 0 = binary),
    so ALL existing content stays unlocked for ANY active subscriber regardless of
    this backfill. The backfill only makes the tier dimension explicit for the
    NEW per-tier content; it can never REMOVE access.
  * Idempotent: only writes a sub that lacks ``tier_level`` (skips already-set),
    and even a re-run computes the same value. Read-side already falls back to
    live resolution, so the backfill is optional hardening, not a correctness gate.

Usage:  python backfill_tier_level.py            # DRY RUN (reports only)
        python backfill_tier_level.py --apply    # writes tier_level
"""
import sys
from boto3.dynamodb.conditions import Attr
from app.core.tables import T
from app.services.subscription_access import get_plan_level

APPLY = "--apply" in sys.argv
LIVE = {"active", "past_due", "trialing", "canceling"}

scanned = updated = skipped = grandfathered = 0
last = None
while True:
    kw = {"FilterExpression": Attr("sk").begins_with("SUB#") & Attr("entity").eq("subscription")}
    if last:
        kw["ExclusiveStartKey"] = last
    resp = T.subscriptions.scan(**kw)
    for it in resp.get("Items", []):
        # only the canonical META rows drive the write set; index rows are updated alongside
        scanned += 1
        status = (it.get("status") or "").lower()
        if status not in LIVE:
            continue
        if it.get("tier_level") is not None:
            skipped += 1
            continue
        cid = str(it.get("creator_id") or "")
        pid = str(it.get("plan_id") or "")
        lvl = get_plan_level(cid, pid)
        if not lvl or lvl < 1:
            lvl = 1
            grandfathered += 1
        updated += 1
        if APPLY:
            subid = it.get("subscription_id")
            keys = [
                {"pk": f"SUBSCRIBER#{it.get('subscriber_id')}", "sk": f"SUB#{subid}"},
                {"pk": f"CREATOR#{cid}", "sk": f"SUB#{subid}"},
                {"pk": f"SUBSCRIPTION#{subid}", "sk": "META"},
            ]
            for k in keys:
                try:
                    T.subscriptions.update_item(
                        Key=k,
                        UpdateExpression="SET tier_level = :l",
                        ConditionExpression="attribute_exists(pk)",
                        ExpressionAttributeValues={":l": int(lvl)},
                    )
                except Exception:
                    pass
    last = resp.get("LastEvaluatedKey")
    if not last:
        break

mode = "APPLIED" if APPLY else "DRY-RUN"
print(f"[{mode}] scanned_sub_rows={scanned} to_update={updated} (grandfathered_to_L1={grandfathered}) already_set={skipped}")
