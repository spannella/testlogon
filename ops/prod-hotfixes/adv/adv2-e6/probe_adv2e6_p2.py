#!/usr/bin/env python3
"""Read-only anchor probe for ADV2-E6 phase 2 (run on prod BEFORE patching)."""
import os
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()

ANCHORS = {
    "app/services/syndicate_revenue_split.py": [
        "def get_split_config(syndicate_id: str) -> Dict[str, Any]:\n",
    ],
    "app/services/syndicate_treasury.py": [
        "def refund_advertising(\n",
    ],
    "app/services/ad_billing.py": [
        (
            "    platform_share = charge_cents - creator_share\n"
            "    platform_share_pct = (\n"
            "        (platform_share * 100) // charge_cents if charge_cents > 0 else PLATFORM_REVENUE_SHARE_PCT\n"
            "    )\n"
        ),
        "                amount_cents=creator_share,\n",
        "                revenue_cents=creator_share,\n",
        (
            "    # Write platform revenue record to ad_billing table so the platform's\n"
            "    # share is durably recorded for audit/reconciliation (GAP-0049).\n"
        ),
        (
            "        \"platform_entry_sk\": platform_entry_sk,\n"
            "        \"revenue_share_bps\": creator_bps,\n"
            "    }\n"
        ),
        (
            "        \"creator_credit_sk\": split.get(\"creator_credit_sk\", \"\"),\n"
            "        \"creator_credit_ts\": int(split.get(\"creator_credit_ts\", 0)),\n"
            "        \"platform_entry_sk\": split.get(\"platform_entry_sk\", \"\"),\n"
            "    }\n"
        ),
    ],
    "app/routers/ads.py": [
        "from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form\n",
        (
            "    from app.services.syndicates import _require_admin\n"
            "    _require_admin(syndicate_id, ctx[\"user_sub\"])\n"
            "    return list_syndicate_ad_accounts(syndicate_id, ctx[\"user_sub\"])\n"
        ),
    ],
}
MARKERS = {
    "app/services/syndicate_revenue_split.py": "get_ad_placement_member_share_bps",
    "app/services/syndicate_treasury.py": "def credit_placement_earning",
    "app/services/ad_billing.py": "split_syndicate_id",
    "app/routers/ads.py": "get_syndicate_ad_placement_config_endpoint",
}

ok = True
for rel, anchors in ANCHORS.items():
    p = os.path.join(ROOT, rel)
    txt = open(p, encoding="utf-8").read()
    already = MARKERS[rel] in txt
    for a in anchors:
        n = txt.count(a)
        status = "OK" if n == 1 else ("ALREADY_APPLIED" if already else "**MISS**")
        if n != 1 and not already:
            ok = False
        print("%s: count=%d %s :: %r" % (rel, n, status, a[:55]))
    print("%s: already_applied=%s" % (rel, already))
print("PROBE_RESULT", "ALL_ANCHORS_OK" if ok else "ANCHOR_PROBLEM")
