#!/usr/bin/env python3
"""ADV3-7 (C4/C6): newsfeed.py — diversity threading + ranked-feed injection."""
import io, sys

P = "app/routers/newsfeed.py"

EDITS = [
    # A. _fetch_sponsored_post: exclusion param + deferred mint + commit-on-keep
    (
        'def _fetch_sponsored_post(\n'
        '    viewer_id: str,\n'
        '    position: int,\n'
        '    hidden_ids: Set[str],\n'
        ') -> Optional[Dict[str, Any]]:\n'
        '    """Fetch a sponsored post from the ad serving engine."""\n'
        '    try:\n'
        '        from app.services.ad_serving import serve_ad\n'
        '        ad = serve_ad(\n'
        '            surface="newsfeed",\n'
        '            content_type="post",\n'
        '            creator_id="platform",\n'
        '            content_id=f"feed_slot_{position}",\n'
        '            slot_type="sponsored_post",\n'
        '            user_id=viewer_id,\n'
        '        )\n'
        '        if not ad.get("filled") or ad.get("is_house_ad"):\n'
        '            return None\n'
        '\n'
        '        creative_id = ad.get("creative_id", "")\n'
        '        if creative_id in hidden_ids:\n'
        '            logger.debug(\n'
        '                "sponsored_injection_skipped",\n'
        '                extra={"viewer_id": viewer_id, "reason": "hidden", "creative_id": creative_id},\n'
        '            )\n'
        '            return None\n',
        'def _fetch_sponsored_post(\n'
        '    viewer_id: str,\n'
        '    position: int,\n'
        '    hidden_ids: Set[str],\n'
        '    exclude_campaign_ids: Optional[Set[str]] = None,\n'
        ') -> Optional[Dict[str, Any]]:\n'
        '    """Fetch a sponsored post from the ad serving engine."""\n'
        '    try:\n'
        '        from app.services.ad_serving import commit_ad_click, serve_ad\n'
        '        ad = serve_ad(\n'
        '            surface="newsfeed",\n'
        '            content_type="post",\n'
        '            creator_id="platform",\n'
        '            content_id=f"feed_slot_{position}",\n'
        '            slot_type="sponsored_post",\n'
        '            user_id=viewer_id,\n'
        '            exclude_campaign_ids=exclude_campaign_ids,\n'
        '            defer_ad_click=True,\n'
        '        )\n'
        '        if not ad.get("filled") or ad.get("is_house_ad"):\n'
        '            return None\n'
        '\n'
        '        creative_id = ad.get("creative_id", "")\n'
        '        if creative_id in hidden_ids:\n'
        '            logger.debug(\n'
        '                "sponsored_injection_skipped",\n'
        '                extra={"viewer_id": viewer_id, "reason": "hidden", "creative_id": creative_id},\n'
        '            )\n'
        '            return None\n'
        '\n'
        '        # ADV3-7 (C4): commit the deferred AdClicks row only now that this\n'
        '        # unit is being kept (a no-fill / hidden spin leaves no orphan row).\n'
        '        commit_ad_click(ad)\n',
    ),
    # B. _inject_sponsored_posts: thread won-campaign-ids for per-page diversity
    (
        '    result: List[Dict[str, Any]] = []\n'
        '    sponsored_count = 0\n'
        '\n'
        '    for i, post in enumerate(posts):\n'
        '        result.append(post)\n'
        '        # Inject after every `_interval` organic posts\n'
        '        if (i + 1) % _interval == 0 and sponsored_count < _max:\n'
        '            # Check if the post allows ads near it\n'
        '            if not post.get("allow_ads_near", True):\n'
        '                logger.debug(\n'
        '                    "sponsored_injection_skipped",\n'
        '                    extra={"viewer_id": viewer_id, "reason": "allow_ads_near_false"},\n'
        '                )\n'
        '                continue\n'
        '            sponsored = _fetch_sponsored_post(viewer_id, i, hidden_ids)\n'
        '            if sponsored:\n'
        '                result.append(sponsored)\n'
        '                sponsored_count += 1\n'
        '\n'
        '    return result\n',
        '    result: List[Dict[str, Any]] = []\n'
        '    sponsored_count = 0\n'
        '    # ADV3-7 (C4): thread already-won campaign ids so each slot draws a\n'
        '    # DISTINCT advertiser instead of the top bidder monopolizing the page.\n'
        '    won_campaign_ids: Set[str] = set()\n'
        '\n'
        '    for i, post in enumerate(posts):\n'
        '        result.append(post)\n'
        '        # Inject after every `_interval` organic posts\n'
        '        if (i + 1) % _interval == 0 and sponsored_count < _max:\n'
        '            # Check if the post allows ads near it\n'
        '            if not post.get("allow_ads_near", True):\n'
        '                logger.debug(\n'
        '                    "sponsored_injection_skipped",\n'
        '                    extra={"viewer_id": viewer_id, "reason": "allow_ads_near_false"},\n'
        '                )\n'
        '                continue\n'
        '            sponsored = _fetch_sponsored_post(\n'
        '                viewer_id, i, hidden_ids, exclude_campaign_ids=won_campaign_ids\n'
        '            )\n'
        '            if sponsored:\n'
        '                result.append(sponsored)\n'
        '                sponsored_count += 1\n'
        '                _cid = sponsored.get("campaign_id")\n'
        '                if _cid:\n'
        '                    won_campaign_ids.add(str(_cid))\n'
        '\n'
        '    return result\n',
    ),
    # C. for-you ranked branch: inject sponsored posts
    (
        '    items = _hydrate_feed_posts_for_viewer(user_id, post_ids)\n'
        '    if not items:\n'
        '        return _chronological_fallback("chronological_fallback")\n'
        '\n'
        '    record_newsfeed_recsys_request(mode="for_you", source="for_you")\n',
        '    items = _hydrate_feed_posts_for_viewer(user_id, post_ids)\n'
        '    if not items:\n'
        '        return _chronological_fallback("chronological_fallback")\n'
        '\n'
        '    # ADV3-7 (C6): the ranked For-You branch previously returned WITHOUT ad\n'
        '    # injection (only chronological GET /feed monetized). Inject sponsored\n'
        '    # posts here too so the ranked surface carries paid inventory; the\n'
        '    # injector honours each post\'s allow_ads_near flag.\n'
        '    items = _inject_sponsored_posts(items, user_id)\n'
        '\n'
        '    record_newsfeed_recsys_request(mode="for_you", source="for_you")\n',
    ),
    # D. document /feed/interesting as intentionally unmonetized (id-list)
    (
        '    """FEED-007: List post_ids the current viewer marked interesting.\n'
        '\n'
        '    Powers the "more like this" feed-ranking boost: callers prioritise these\n'
        '    posts (and same-author posts) in ranking.\n'
        '    """\n',
        '    """FEED-007: List post_ids the current viewer marked interesting.\n'
        '\n'
        '    Powers the "more like this" feed-ranking boost: callers prioritise these\n'
        '    posts (and same-author posts) in ranking.\n'
        '\n'
        '    ADV3-7 (C6): this endpoint returns a bare post_id LIST (a ranking-signal\n'
        '    lookup), not a rendered feed of post objects, so it carries no sponsored\n'
        '    slots by design -- it is intentionally unmonetized. Sponsored injection\n'
        '    lives on the rendered surfaces (GET /feed and GET /feed/for-you).\n'
        '    """\n',
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
