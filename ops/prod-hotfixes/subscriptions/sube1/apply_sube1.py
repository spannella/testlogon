#!/usr/bin/env python3
"""SUB-E1 anchored, idempotent patcher. Runs on the dev clone AND prod.

Patches (besides the new app/services/subscription_renewal.py which is deployed
separately):
  1. subscription_access.has_active_subscription -> period/grace expiry enforcement
  2. settings.py -> 4 subscription-renewal config knobs
  3. alerts.DEFAULT_PUSH_EVENT_TYPES -> 4 default-on subscription push types
  4. main.py -> register start_subscription_renewal_task
  5. subscription_server.py -> admin run-renewals trigger endpoint + imports

Each patch is anchor-matched and skipped if its marker is already present.
"""
import io
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."


def _read(p):
    with io.open(p, "r", encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with io.open(p, "w", encoding="utf-8") as f:
        f.write(s)


def patch(path, anchor, new, marker):
    full = ROOT + "/" + path
    src = _read(full)
    if marker in src:
        print("SKIP (already applied):", path)
        return
    if anchor not in src:
        print("!! ANCHOR NOT FOUND:", path)
        print("   anchor repr:", repr(anchor[:80]))
        sys.exit(3)
    n = src.count(anchor)
    if n != 1:
        print("!! ANCHOR NOT UNIQUE (%d):" % n, path, repr(anchor[:60]))
        sys.exit(4)
    _write(full, src.replace(anchor, new))
    print("PATCHED:", path)


# 1) subscription_access.has_active_subscription -----------------------------
patch(
    "app/services/subscription_access.py",
    anchor=(
        '    items: List[Dict[str, Any]] = resp.get("Items", [])\n'
        "    for item in items:\n"
        '        if item.get("creator_id") != creator_id:\n'
        "            continue\n"
        '        status = (item.get("status") or "").lower()\n'
        '        if status in {"active", "past_due", "trialing"}:\n'
        "            return True\n"
        "    return False\n"
    ),
    new=(
        '    items: List[Dict[str, Any]] = resp.get("Items", [])\n'
        "    now = now_ts()\n"
        "    for item in items:\n"
        '        if item.get("creator_id") != creator_id:\n'
        "            continue\n"
        '        status = (item.get("status") or "").lower()\n'
        "        # SUB-E1: expired/canceled subs never grant access.\n"
        '        if status not in {"active", "past_due", "trialing"}:\n'
        "            continue\n"
        "        # SUB-E1 expiry enforcement: access is bounded by the paid period\n"
        "        # (grace-extended). A lapsed sub (period elapsed with no successful\n"
        "        # renewal) or a past_due sub beyond grace LOSES access. A record\n"
        "        # with no period info (legacy/grandfathered) is left un-enforced.\n"
        '        period_end = int(item.get("current_period_end") or 0)\n'
        '        grace_until = int(item.get("grace_until") or 0)\n'
        "        effective_end = max(period_end, grace_until)\n"
        "        if effective_end and effective_end <= now:\n"
        "            continue\n"
        "        return True\n"
        "    return False\n"
    ),
    marker="SUB-E1 expiry enforcement",
)

# 2) settings.py -------------------------------------------------------------
patch(
    "app/core/settings.py",
    anchor='    billing_dunning_retry_schedule_seconds: str = os.environ.get("BILLING_DUNNING_RETRY_SCHEDULE_SECONDS", "3600,86400,172800")\n',
    new=(
        '    billing_dunning_retry_schedule_seconds: str = os.environ.get("BILLING_DUNNING_RETRY_SCHEDULE_SECONDS", "3600,86400,172800")\n'
        "    # SUB-E1: recurring subscription renewal + dunning + expiry engine.\n"
        '    subscription_renewal_enabled: bool = os.environ.get("SUBSCRIPTION_RENEWAL_ENABLED", "true").lower() == "true"\n'
        '    subscription_renewal_interval_seconds: int = int(os.environ.get("SUBSCRIPTION_RENEWAL_INTERVAL_SECONDS", "900"))\n'
        '    subscription_dunning_retry_days: str = os.environ.get("SUBSCRIPTION_DUNNING_RETRY_DAYS", "1,3,5,7")\n'
        '    subscription_grace_days: int = int(os.environ.get("SUBSCRIPTION_GRACE_DAYS", "7"))\n'
    ),
    marker="SUBSCRIPTION_RENEWAL_ENABLED",
)

# 3) alerts.DEFAULT_PUSH_EVENT_TYPES -----------------------------------------
patch(
    "app/services/alerts.py",
    anchor=(
        '    "order_delivered",         # your order was delivered (buyer, D4)\n'
        "]\n"
    ),
    new=(
        '    "order_delivered",         # your order was delivered (buyer, D4)\n'
        '    "subscription_renewed",         # SUB-E1: your subscription renewed\n'
        '    "subscription_renewal_failed",  # SUB-E1: a renewal charge failed\n'
        '    "subscription_expiring",        # SUB-E1: subscription entering grace\n'
        '    "subscription_expired",         # SUB-E1: subscription access ended\n'
        "]\n"
    ),
    marker="subscription_renewed",
)

# 4) main.py registration ----------------------------------------------------
patch(
    "app/main.py",
    anchor="from app.services.billing_dunning import start_billing_dunning_task\n",
    new=(
        "from app.services.billing_dunning import start_billing_dunning_task\n"
        "from app.services.subscription_renewal import start_subscription_renewal_task\n"
    ),
    marker="from app.services.subscription_renewal import start_subscription_renewal_task",
)
patch(
    "app/main.py",
    anchor='    app.add_event_handler("startup", start_billing_dunning_task)\n',
    new=(
        '    app.add_event_handler("startup", start_billing_dunning_task)\n'
        '    app.add_event_handler("startup", start_subscription_renewal_task)  # SUB-E1\n'
    ),
    marker='start_subscription_renewal_task)  # SUB-E1',
)

# 5) subscription_server.py: imports + admin endpoint ------------------------
patch(
    "app/routers/subscription_server.py",
    anchor="from fastapi import APIRouter, Header, HTTPException, Query, Request\n",
    new="from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request\n",
    marker="from fastapi import APIRouter, Depends, Header",
)
patch(
    "app/routers/subscription_server.py",
    anchor="from app.services.subscription_cycle_orders import emit_subscription_cycle_order\n",
    new=(
        "from app.services.subscription_cycle_orders import emit_subscription_cycle_order\n"
        "from app.auth.policy import require_admin_or_root\n"
    ),
    marker="from app.auth.policy import require_admin_or_root",
)
patch(
    "app/routers/subscription_server.py",
    anchor='    sub["updated_at"] = ts\n    save_subscription(sub)\n    return {"ok": True, "event_id": event_id}\n',
    new=(
        '    sub["updated_at"] = ts\n    save_subscription(sub)\n    return {"ok": True, "event_id": event_id}\n\n\n'
        "# -----------------------------\n"
        "# SUB-E1 — manual/admin trigger for the recurring renewal + dunning sweep\n"
        "# (mirrors the moderation/shipment simulate drivers; the periodic task in\n"
        "# main.py runs it on a wall-clock interval). Admin/root gated.\n"
        "# -----------------------------\n"
        '@router.post("/ui/admin/subscriptions/run-renewals")\n'
        "async def admin_run_renewals(\n"
        "    request: Request,\n"
        "    limit: int = Query(default=1000, ge=1, le=5000),\n"
        "    now_override: Optional[int] = Query(default=None),\n"
        "    _admin=Depends(require_admin_or_root),\n"
        "):\n"
        '    """Drive one renewal/dunning/expiry sweep now. ``now_override`` (unix ts)\n'
        "    lets an operator/verifier evaluate due-ness against a chosen wall clock.\n"
        '    Returns the sweep action summary."""\n'
        "    from app.services.subscription_renewal import run_renewal_sweep\n"
        "\n"
        "    return run_renewal_sweep(now=now_override, limit=limit)\n"
    ),
    marker="/ui/admin/subscriptions/run-renewals",
)

print("ALL PATCHES DONE")
