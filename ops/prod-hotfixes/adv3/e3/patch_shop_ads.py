#!/usr/bin/env python3
"""ADV3-7 (C4): shop_ads.py — diversity threading + deferred mint (no orphans)."""
import io, sys

P = "app/services/shop_ads.py"

EDITS = [
    (
        '    from app.services.ad_serving import serve_ad\n'
        '\n'
        '    units: List[Dict[str, Any]] = []\n'
        '    seen: set = set()\n'
        '    ctx = {}\n',
        '    from app.services.ad_serving import commit_ad_click, serve_ad\n'
        '\n'
        '    units: List[Dict[str, Any]] = []\n'
        '    seen: set = set()\n'
        '    won_campaigns: set = set()\n'
        '    ctx = {}\n',
    ),
    (
        '                content_owner_id="",       # STANDALONE -> platform 100% (no creator)\n'
        '                require_product=True,       # shop serves ONLY product ads\n'
        '            )\n',
        '                content_owner_id="",       # STANDALONE -> platform 100% (no creator)\n'
        '                require_product=True,       # shop serves ONLY product ads\n'
        '                exclude_campaign_ids=won_campaigns,  # ADV3-7 (C4): distinct advertisers\n'
        '                defer_ad_click=True,        # ADV3-7 (C4): mint only on keep\n'
        '            )\n',
    ),
    (
        '        if creative_id in seen:\n'
        '            continue\n'
        '        seen.add(creative_id)\n'
        '\n'
        '        card = {\n',
        '        if creative_id in seen:\n'
        '            continue\n'
        '        seen.add(creative_id)\n'
        '        # ADV3-7 (C4): commit the deferred AdClicks row only for a KEPT unit\n'
        '        # (no-product / duplicate spins above leave no orphan) and exclude this\n'
        '        # campaign from later spins so the page shows distinct advertisers.\n'
        '        commit_ad_click(ad)\n'
        '        _won = ad.get("campaign_id", "")\n'
        '        if _won:\n'
        '            won_campaigns.add(str(_won))\n'
        '\n'
        '        card = {\n',
    ),
]


def main():
    with io.open(P, "r", encoding="utf-8") as f:
        src = f.read()
    orig = src
    for i, (old, new) in enumerate(EDITS, 1):
        if new in src and old not in src:
            print("edit %d: already applied, skip" % i)
            continue
        n = src.count(old)
        if n != 1:
            print("edit %d: ANCHOR NOT UNIQUE (count=%d) -- ABORT" % (i, n))
            sys.exit(2)
        src = src.replace(old, new)
        print("edit %d: applied" % i)
    if src == orig:
        print("no changes")
        return
    with io.open(P, "w", encoding="utf-8") as f:
        f.write(src)
    print("WROTE", P)


if __name__ == "__main__":
    main()
