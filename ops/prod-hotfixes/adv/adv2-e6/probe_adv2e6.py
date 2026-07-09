"""Read-only anchor probe for ADV2-E6 phase1 (run on prod BEFORE patching)."""
import os, sys
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
ANCHORS = {
    "app/services/ad_accounts.py": [
        '        "owner_sub": owner_sub,\n        "company_name": data.company_name,',
    ],
    "app/routers/ads.py": [
        "from app.services.ad_accounts import (\n    create_ad_account,",
    ],
    "app/services/ad_serving.py": [
        '        _owner_sub = str((_acct or {}).get("owner_sub", "") or "")\n',
        '        if _owner_sub and _owner_sub == str(user_id or ""):\n            continue\n',
        '        candidates.append({\n            "campaign": campaign,\n            "creatives": creatives,\n            "score": score,\n        })',
        '            "content_owner_sub": content_owner_id or "",\n            "surface": surface,',
        '        "content_owner_id": content_owner_id or "",\n        "promo_code_id": creative.get("promo_code_id"),',
    ],
}
MARKERS = {
    "app/services/ad_accounts.py": "def create_syndicate_ad_account",
    "app/routers/ads.py": "syndicate_ad_account_endpoint",
    "app/services/ad_serving.py": "_is_syndicate_ad",
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
        print(f"{rel}: count={n} {status} :: {a[:55]!r}")
    print(f"{rel}: already_applied={already}")
print("PROBE_RESULT", "ALL_ANCHORS_OK" if ok else "ANCHOR_PROBLEM")
