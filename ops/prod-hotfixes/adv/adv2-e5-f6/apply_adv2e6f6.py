#!/usr/bin/env python3
"""ADV2-E5 (F6) idempotent apply. app/services/ad_dm_audience.py ships as a
committed repo file. This script (a) patches app/services/ad_messaging.py so the
shared _run_send accepts an optional send-time re-gate (eligibility_fn) -- a
no-op for F5 -- and (b) appends the F6 advertiser mass-DM endpoints block to
app/routers/ads.py. Both steps are marker-guarded so it is safe to re-run on the
divergent prod files. ROOT selects the repo (default ".").
"""
import os
import sys

ROOT = os.environ.get("ROOT", ".")
ADS = os.path.join(ROOT, "app", "routers", "ads.py")
AMSG = os.path.join(ROOT, "app", "services", "ad_messaging.py")
ADDM = os.path.join(ROOT, "app", "services", "ad_dm_audience.py")
BLOCK = os.path.join(os.path.dirname(__file__), "ads_f6_endpoints_block.py")
ADS_MARKER = "F6 advertiser direct mass-DM (ADV2-E5 / ADV2-601..610)"

if not os.path.exists(ADDM):
    print("ERROR ad_dm_audience.py missing (should be a committed repo file):", ADDM)
    sys.exit(1)
if not os.path.exists(AMSG):
    print("ERROR ad_messaging.py missing (F5 must ship first):", AMSG)
    sys.exit(1)

# ── (a) patch _run_send to accept eligibility_fn (send-time re-gate) ──
amsg = open(AMSG, "r", encoding="utf-8").read()
if "eligibility_fn" in amsg:
    print("AMSG_PATCH_SKIPPED_ALREADY_PRESENT")
else:
    sig_old = (
        "    content_owner_sub: str, body: str, recipients: List[str],\n"
        ") -> Dict[str, Any]:\n"
        "    send_id = \"amsgsend_%s\" % uuid.uuid4().hex[:12]"
    )
    sig_new = (
        "    content_owner_sub: str, body: str, recipients: List[str],\n"
        "    eligibility_fn=None,\n"
        ") -> Dict[str, Any]:\n"
        "    send_id = \"amsgsend_%s\" % uuid.uuid4().hex[:12]"
    )
    loop_old = (
        "    for recipient in recipients:\n"
        "        r = deliver_to_recipient("
    )
    loop_new = (
        "    for recipient in recipients:\n"
        "        if eligibility_fn is not None and not eligibility_fn(recipient):\n"
        "            # ADV2-606 send-time re-gate: recipient became ineligible\n"
        "            # (unfollowed / opted out) between resolve and dispatch -> DROP.\n"
        "            results.append({\"recipient_sub\": recipient,\n"
        "                            \"state\": \"excluded_ineligible\", \"charge_cents\": 0})\n"
        "            continue\n"
        "        r = deliver_to_recipient("
    )
    if sig_old not in amsg:
        print("ERROR _run_send signature anchor not found in ad_messaging.py")
        sys.exit(2)
    if loop_old not in amsg:
        print("ERROR _run_send loop anchor not found in ad_messaging.py")
        sys.exit(2)
    amsg = amsg.replace(sig_old, sig_new, 1).replace(loop_old, loop_new, 1)
    open(AMSG, "w", encoding="utf-8").write(amsg)
    print("AMSG_PATCH_DONE")

# ── (b) append the F6 endpoints block to ads.py ──
ads = open(ADS, "r", encoding="utf-8").read()
if ADS_MARKER in ads:
    print("APPEND_SKIPPED_ALREADY_PRESENT")
else:
    block = open(BLOCK, "r", encoding="utf-8").read()
    if not ads.endswith("\n"):
        ads += "\n"
    open(ADS, "w", encoding="utf-8").write(ads + block)
    print("APPEND_DONE")

import py_compile
py_compile.compile(ADDM, doraise=True)
py_compile.compile(AMSG, doraise=True)
py_compile.compile(ADS, doraise=True)
print("PYCOMPILE_OK")
