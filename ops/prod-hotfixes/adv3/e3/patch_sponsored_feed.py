#!/usr/bin/env python3
"""ADV3-7 (C4): sponsored_feed.py — diversity + deferred mint on group/syndicate feeds."""
import io, sys

P = "app/services/sponsored_feed.py"

EDITS = [
    # 1. build_sponsored_unit: exclusion param + deferred mint + commit-on-keep
    (
        '    hidden_ids: Optional[Set[str]] = None,\n'
        ') -> Optional[Dict[str, Any]]:\n'
        '    """Serve one STANDALONE sponsored unit for ``surface`` (platform-100%)."""\n'
        '    try:\n'
        '        from app.services.ad_serving import serve_ad\n'
        '\n'
        '        ad = serve_ad(\n'
        '            surface=surface,\n'
        '            content_type="post",\n'
        '            creator_id="platform",\n'
        '            content_id=content_id,\n'
        '            slot_type="sponsored_post",\n'
        '            user_id=viewer_id,\n'
        '        )\n'
        '        if not ad.get("filled") or ad.get("is_house_ad"):\n'
        '            return None\n'
        '\n'
        '        creative_id = ad.get("creative_id", "")\n'
        '        if hidden_ids and creative_id in hidden_ids:\n'
        '            return None\n',
        '    hidden_ids: Optional[Set[str]] = None,\n'
        '    exclude_campaign_ids: Optional[Set[str]] = None,\n'
        ') -> Optional[Dict[str, Any]]:\n'
        '    """Serve one STANDALONE sponsored unit for ``surface`` (platform-100%)."""\n'
        '    try:\n'
        '        from app.services.ad_serving import commit_ad_click, serve_ad\n'
        '\n'
        '        ad = serve_ad(\n'
        '            surface=surface,\n'
        '            content_type="post",\n'
        '            creator_id="platform",\n'
        '            content_id=content_id,\n'
        '            slot_type="sponsored_post",\n'
        '            user_id=viewer_id,\n'
        '            exclude_campaign_ids=exclude_campaign_ids,\n'
        '            defer_ad_click=True,\n'
        '        )\n'
        '        if not ad.get("filled") or ad.get("is_house_ad"):\n'
        '            return None\n'
        '\n'
        '        creative_id = ad.get("creative_id", "")\n'
        '        if hidden_ids and creative_id in hidden_ids:\n'
        '            return None\n'
        '\n'
        '        # ADV3-7 (C4): commit the deferred AdClicks row only for a kept unit.\n'
        '        commit_ad_click(ad)\n',
    ),
    # 2. inject_sponsored loop: thread won-campaign-ids
    (
        '    result: List[Dict[str, Any]] = []\n'
        '    count = 0\n'
        '    for i, post in enumerate(items):\n'
        '        result.append(post)\n'
        '        if (i + 1) % interval == 0 and count < max_sponsored:\n'
        '            if isinstance(post, dict) and not post.get("allow_ads_near", True):\n'
        '                continue\n'
        '            unit = build_sponsored_unit(\n'
        '                viewer_id=viewer_id,\n'
        '                surface=surface,\n'
        '                content_id=f"{content_prefix}_slot_{i}",\n'
        '                position=i,\n'
        '                hidden_ids=hidden,\n'
        '            )\n'
        '            if unit:\n'
        '                result.append(unit)\n'
        '                count += 1\n'
        '    return result\n',
        '    result: List[Dict[str, Any]] = []\n'
        '    count = 0\n'
        '    won_campaign_ids: Set[str] = set()  # ADV3-7 (C4): per-page advertiser diversity\n'
        '    for i, post in enumerate(items):\n'
        '        result.append(post)\n'
        '        if (i + 1) % interval == 0 and count < max_sponsored:\n'
        '            if isinstance(post, dict) and not post.get("allow_ads_near", True):\n'
        '                continue\n'
        '            unit = build_sponsored_unit(\n'
        '                viewer_id=viewer_id,\n'
        '                surface=surface,\n'
        '                content_id=f"{content_prefix}_slot_{i}",\n'
        '                position=i,\n'
        '                hidden_ids=hidden,\n'
        '                exclude_campaign_ids=won_campaign_ids,\n'
        '            )\n'
        '            if unit:\n'
        '                result.append(unit)\n'
        '                count += 1\n'
        '                _cid = unit.get("campaign_id")\n'
        '                if _cid:\n'
        '                    won_campaign_ids.add(str(_cid))\n'
        '    return result\n',
    ),
    # 3. inject_sponsored_syndicate loop: thread won-campaign-ids
    (
        '    result: List[Dict[str, Any]] = []\n'
        '    count = 0\n'
        '    for i, post in enumerate(items):\n'
        '        result.append(post)\n'
        '        if (i + 1) % interval == 0 and count < max_sponsored:\n'
        '            unit = build_sponsored_unit(\n'
        '                viewer_id=viewer_sub,\n'
        '                surface="syndicate_feed",\n'
        '                content_id=f"synd_{syndicate_id}_slot_{i}",\n'
        '                position=i,\n'
        '                hidden_ids=hidden,\n'
        '            )\n'
        '            if unit:\n'
        '                result.append(_to_syndicate_shape(unit, syndicate_id=syndicate_id))\n'
        '                count += 1\n'
        '    return result\n',
        '    result: List[Dict[str, Any]] = []\n'
        '    count = 0\n'
        '    won_campaign_ids: Set[str] = set()  # ADV3-7 (C4): per-page advertiser diversity\n'
        '    for i, post in enumerate(items):\n'
        '        result.append(post)\n'
        '        if (i + 1) % interval == 0 and count < max_sponsored:\n'
        '            unit = build_sponsored_unit(\n'
        '                viewer_id=viewer_sub,\n'
        '                surface="syndicate_feed",\n'
        '                content_id=f"synd_{syndicate_id}_slot_{i}",\n'
        '                position=i,\n'
        '                hidden_ids=hidden,\n'
        '                exclude_campaign_ids=won_campaign_ids,\n'
        '            )\n'
        '            if unit:\n'
        '                result.append(_to_syndicate_shape(unit, syndicate_id=syndicate_id))\n'
        '                count += 1\n'
        '                _cid = unit.get("campaign_id")\n'
        '                if _cid:\n'
        '                    won_campaign_ids.add(str(_cid))\n'
        '    return result\n',
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
