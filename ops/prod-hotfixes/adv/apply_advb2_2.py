#!/usr/bin/env python3
"""ADV-203 reconciliation: suppress the legacy phantom-CPM creator credit for
advertiser-funded paid pre-rolls (poster is credited from real ad spend via
ad_billing._split_revenue instead) — no double-credit. Idempotent."""
import sys, io, os, py_compile

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."

def patch(path, edits, sentinel):
    with io.open(path, "r", encoding="utf-8") as f:
        src = f.read()
    if sentinel in src:
        print("SKIP (already patched):", path); return
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise SystemExit("ANCHOR MATCH=%d (expected 1) in %s for:\n%s" % (n, path, old[:160]))
        src = src.replace(old, new)
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)
    py_compile.compile(path, doraise=True)
    print("PATCHED:", path)

# ---- ad_placement.py ----
AP = os.path.join(ROOT, "app/services/ad_placement.py")
ap_edits = [
(
'''    creative_id: str = "",
    event_type: str = "impression",  # "impression" | "complete" | "skip"
''',
'''    creative_id: str = "",
    event_type: str = "impression",  # "impression" | "complete" | "skip"
    # ADV-203: when False, suppress the legacy phantom-CPM creator credit (used
    # for advertiser-funded paid pre-rolls, where the poster is credited from
    # real ad spend via ad_billing._split_revenue instead — no double-credit).
    credit_revenue: bool = True,
'''),
(
'''    if event_type == "complete":
        if _claim_complete_slot(
''',
'''    if event_type == "complete" and credit_revenue:
        if _claim_complete_slot(
'''),
]
patch(AP, ap_edits, sentinel="ADV-203: when False, suppress")

# ---- vod_ad_supported.py ----
VOD = os.path.join(ROOT, "app/services/vod_ad_supported.py")
vod_edits = [
(
'''        record_ad_impression(
            video_id=video_id,
            user_id=user_id,
            slot_type=target.get("slot_type", "pre_roll"),
            slot_index=int(target.get("slot_index", 0)),
            creative_id=target.get("creative_id", ""),
            event_type=event_type,
        )
''',
'''        record_ad_impression(
            video_id=video_id,
            user_id=user_id,
            slot_type=target.get("slot_type", "pre_roll"),
            slot_index=int(target.get("slot_index", 0)),
            creative_id=target.get("creative_id", ""),
            event_type=event_type,
            # ADV-203: for a paid pre-roll (ad_click_id present) the poster is
            # credited from advertiser spend via _charge_preroll_completion, so
            # suppress the legacy phantom-CPM credit here to avoid double-credit.
            credit_revenue=not bool(target.get("ad_click_id")),
        )
'''),
]
patch(VOD, vod_edits, sentinel="credit_revenue=not bool(target")

print("ALL_PATCHES2_OK")
