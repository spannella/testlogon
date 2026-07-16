#!/usr/bin/env python3
"""ADV3-7 (C4/C5/C7): ad_serving.py — fill diversity + pacing + platform guard.

Exact-string, anchor-checked, idempotent. Applies byte-identically to the dev
clone and prod (which were byte-identical on this file per the divergence probe).
"""
import io, sys

P = "app/services/ad_serving.py"

EDITS = [
    # 1. signature: add exclusion + defer params
    (
        '    user_context: Optional[Dict[str, Any]] = None,\n'
        '    content_owner_id: str = "",\n'
        '    require_product: bool = False,\n'
        ') -> Dict[str, Any]:\n',
        '    user_context: Optional[Dict[str, Any]] = None,\n'
        '    content_owner_id: str = "",\n'
        '    require_product: bool = False,\n'
        '    exclude_campaign_ids: Optional[Any] = None,\n'
        '    exclude_account_ids: Optional[Any] = None,\n'
        '    defer_ad_click: bool = False,\n'
        ') -> Dict[str, Any]:\n',
    ),
    # 2. reserved-creator constant
    (
        'DEFAULT_FREQ_CAPS = {"1h": 3, "24h": 10, "7d": 30}\n'
        'WINDOW_SECONDS = {"1h": 3600, "24h": 86400, "7d": 604800}\n',
        'DEFAULT_FREQ_CAPS = {"1h": 3, "24h": 10, "7d": 30}\n'
        'WINDOW_SECONDS = {"1h": 3600, "24h": 86400, "7d": 604800}\n'
        '\n'
        '# ADV3-7 (C7): reserved pseudo-creator ids that back STANDALONE ad units\n'
        '# (newsfeed / shop / sponsored-feed serve with creator_id="platform"). These\n'
        '# can never be configured to suppress fill -- see the guard in serve_ad.\n'
        'RESERVED_AD_CREATOR_IDS = frozenset({"platform"})\n',
    ),
    # 3. platform guard + exclusion-set normalize
    (
        '    # 1. Check creator allows ads\n'
        '    creator_settings = get_creator_ad_settings(creator_id)\n'
        '    if not creator_settings.get("allow_ads", True):\n'
        '        return _empty_response("creator_ads_disabled")\n',
        '    # 1. Check creator allows ads. ADV3-7 (C7): the reserved "platform"\n'
        '    #    pseudo-creator backs every STANDALONE unit; a stray admin write to its\n'
        '    #    ad settings must never darken all standalone fill at once, so the\n'
        '    #    reserved id is force-permissive and cannot be configured to suppress.\n'
        '    if creator_id in RESERVED_AD_CREATOR_IDS:\n'
        '        creator_settings = {"allow_ads": True}\n'
        '    else:\n'
        '        creator_settings = get_creator_ad_settings(creator_id)\n'
        '        if not creator_settings.get("allow_ads", True):\n'
        '            return _empty_response("creator_ads_disabled")\n'
        '\n'
        '    # ADV3-7 (C4): normalize per-fetch exclusion sets so a multi-slot caller\n'
        '    # can thread already-won campaign/account ids and avoid a single-advertiser\n'
        '    # monopoly across a page.\n'
        '    _excl_camp = {str(x) for x in (exclude_campaign_ids or ())}\n'
        '    _excl_acct = {str(x) for x in (exclude_account_ids or ())}\n',
    ),
    # 4. per-fetch exclusion in the candidate loop
    (
        '    for campaign in active_campaigns:\n'
        '        account_id = campaign["account_id"]\n',
        '    for campaign in active_campaigns:\n'
        '        account_id = campaign["account_id"]\n'
        '\n'
        '        # ADV3-7 (C4): per-fetch exclusion (multi-slot diversity).\n'
        '        if str(campaign.get("campaign_id")) in _excl_camp or str(account_id) in _excl_acct:\n'
        '            continue\n',
    ),
    # 5. pacing after budget check
    (
        '        # Budget check\n'
        '        if not _has_budget(campaign):\n'
        '            continue\n',
        '        # Budget check\n'
        '        if not _has_budget(campaign):\n'
        '            continue\n'
        '\n'
        '        # ADV3-7 (C5): budget PACING. A daily-budget campaign that is ahead of\n'
        '        # its expected spend-to-now is probabilistically skipped so delivery\n'
        '        # spreads across the day instead of front-loading each morning.\n'
        '        if not _passes_pacing(campaign):\n'
        '            continue\n',
    ),
    # 6. mint block -> build item + conditional (deferred) write
    (
        '    ad_click_id = uuid.uuid4().hex\n'
        '    try:\n'
        '        _now = now_ts()\n'
        '        T.ad_clicks.put_item(Item={\n'
        '            "ad_click_id": ad_click_id,\n'
        '            "viewer_sub": user_id,\n'
        '            "campaign_id": winner["campaign"]["campaign_id"],\n'
        '            "account_id": winner["campaign"]["account_id"],\n'
        '            "creative_id": creative["creative_id"],\n'
        '            "product_id": creative.get("product_id", "") or "",\n'
        '            "content_owner_sub": content_owner_id or "",\n'
        '            "is_syndicate_ad": bool(winner.get("is_syndicate_ad")),\n'
        '            "syndicate_id": str(winner.get("syndicate_id") or ""),\n'
        '            "surface": surface,\n'
        '            "slot_type": slot_type,\n'
        '            "content_id": content_id,\n'
        '            "status": "served",\n'
        '            "self_promo": is_self_win,\n'
        '            "effective_price_cents": cleared_cpm,\n'
        '            "effective_cpm_cents": cleared_cpm,\n'
        '            "bid_cpc_cents": win_cpc,\n'
        '            "bid_cpa_cents": win_cpa,\n'
        '            "gross_bid_cpm_cents": win_cpm,\n'
        '            "created_at": _now,\n'
        '            "expires_at": _now + 604800,\n'
        '        })\n'
        '    except Exception:\n'
        '        logger.warning(\n'
        '            "ad_click_mint_failed campaign=%s", winner["campaign"].get("campaign_id")\n'
        '        )\n',
        '    ad_click_id = uuid.uuid4().hex\n'
        '    _now = now_ts()\n'
        '    _click_item = {\n'
        '        "ad_click_id": ad_click_id,\n'
        '        "viewer_sub": user_id,\n'
        '        "campaign_id": winner["campaign"]["campaign_id"],\n'
        '        "account_id": winner["campaign"]["account_id"],\n'
        '        "creative_id": creative["creative_id"],\n'
        '        "product_id": creative.get("product_id", "") or "",\n'
        '        "content_owner_sub": content_owner_id or "",\n'
        '        "is_syndicate_ad": bool(winner.get("is_syndicate_ad")),\n'
        '        "syndicate_id": str(winner.get("syndicate_id") or ""),\n'
        '        "surface": surface,\n'
        '        "slot_type": slot_type,\n'
        '        "content_id": content_id,\n'
        '        "status": "served",\n'
        '        "self_promo": is_self_win,\n'
        '        "effective_price_cents": cleared_cpm,\n'
        '        "effective_cpm_cents": cleared_cpm,\n'
        '        "bid_cpc_cents": win_cpc,\n'
        '        "bid_cpa_cents": win_cpa,\n'
        '        "gross_bid_cpm_cents": win_cpm,\n'
        '        "created_at": _now,\n'
        '        "expires_at": _now + 604800,\n'
        '    }\n'
        '    # ADV3-7 (C4): defer the write for multi-slot callers so an orphan served\n'
        '    # row is never minted for a candidate that gets discarded. Single-serve\n'
        '    # callers persist immediately, unchanged.\n'
        '    if not defer_ad_click:\n'
        '        try:\n'
        '            T.ad_clicks.put_item(Item=_click_item)\n'
        '        except Exception:\n'
        '            logger.warning(\n'
        '                "ad_click_mint_failed campaign=%s", winner["campaign"].get("campaign_id")\n'
        '            )\n',
    ),
    # 7. return dict -> named var
    (
        '    return {\n'
        '        "filled": True,\n'
        '        "creative_id": creative["creative_id"],\n'
        '        "format": creative.get("format", "native_post"),\n',
        '    _serve_response = {\n'
        '        "filled": True,\n'
        '        "creative_id": creative["creative_id"],\n'
        '        "format": creative.get("format", "native_post"),\n',
    ),
    # 8. attach pending row + return
    (
        '        "promo_code_id": creative.get("promo_code_id"),\n'
        '        "affiliate_link_id": creative.get("affiliate_link_id"),\n'
        '    }\n'
        '\n'
        '\n'
        '# --- ADV2-201/E2: structured CTA click-through targets ',
        '        "promo_code_id": creative.get("promo_code_id"),\n'
        '        "affiliate_link_id": creative.get("affiliate_link_id"),\n'
        '    }\n'
        '    # ADV3-7 (C4): stash the deferred AdClicks row so a multi-slot caller can\n'
        '    # commit it only for a unit it actually keeps (see commit_ad_click).\n'
        '    if defer_ad_click:\n'
        '        _serve_response["_pending_ad_click"] = _click_item\n'
        '    return _serve_response\n'
        '\n'
        '\n'
        '# --- ADV2-201/E2: structured CTA click-through targets ',
    ),
    # 9. commit_ad_click + _passes_pacing before _has_budget
    (
        'def _has_budget(campaign: dict) -> bool:\n'
        '    budget = int(campaign.get("budget_cents", 0))\n',
        'def commit_ad_click(ad: Optional[Dict[str, Any]]) -> None:\n'
        '    """ADV3-7 (C4): persist a DEFERRED AdClicks row.\n'
        '\n'
        '    serve_ad(defer_ad_click=True) does NOT write the AdClicks row, so a\n'
        '    multi-slot caller that discards a candidate (duplicate creative, hidden\n'
        '    ad, no-product spin) never leaves an orphan served row. The caller\n'
        '    commits the row only for a unit it actually returns."""\n'
        '    item = (ad or {}).get("_pending_ad_click")\n'
        '    if not item:\n'
        '        return\n'
        '    try:\n'
        '        T.ad_clicks.put_item(Item=item)\n'
        '    except Exception:\n'
        '        logger.warning("ad_click_commit_failed campaign=%s", item.get("campaign_id"))\n'
        '\n'
        '\n'
        '# ── Internal helpers ────────────────────────────\n'
        '\n'
        '\n'
        'def _passes_pacing(campaign: dict, now: Optional[datetime] = None) -> bool:\n'
        '    """ADV3-7 (C5): probabilistic pacing for DAILY-budget campaigns.\n'
        '\n'
        '    Non-daily campaigns (and pacing disabled) always pass. For a daily budget\n'
        '    we compare the fraction of the UTC day elapsed against the fraction of the\n'
        '    daily budget already spent. At/under pace (plus a small slack) -> serve;\n'
        '    ahead of pace -> serve with probability expected/actual, so an early burst\n'
        '    is throttled back toward an even spread instead of going dark by 9am.\n'
        '    Fails open on any error (never silently drops all fill)."""\n'
        '    try:\n'
        '        if not bool(getattr(S, "ad_pacing_enabled", True)):\n'
        '            return True\n'
        '        if str(campaign.get("budget_type", "")) != "daily":\n'
        '            return True\n'
        '        daily_budget = int(campaign.get("daily_budget_cents", campaign.get("budget_cents", 0)) or 0)\n'
        '        if daily_budget <= 0:\n'
        '            return True\n'
        '        spent_today = int(campaign.get("spent_today_cents", 0) or 0)\n'
        '        n = now or datetime.now(timezone.utc)\n'
        '        secs = n.hour * 3600 + n.minute * 60 + n.second\n'
        '        min_frac = float(getattr(S, "ad_pacing_min_fraction", 0.02) or 0.0)\n'
        '        elapsed_frac = max(secs / 86400.0, min_frac)\n'
        '        spent_frac = spent_today / daily_budget\n'
        '        slack = float(getattr(S, "ad_pacing_slack", 0.15) or 0.0)\n'
        '        target = elapsed_frac * (1.0 + slack)\n'
        '        if spent_frac <= target:\n'
        '            return True\n'
        '        serve_prob = target / spent_frac if spent_frac > 0 else 1.0\n'
        '        return random.random() < max(0.0, min(1.0, serve_prob))\n'
        '    except Exception:\n'
        '        return True\n'
        '\n'
        '\n'
        'def _has_budget(campaign: dict) -> bool:\n'
        '    budget = int(campaign.get("budget_cents", 0))\n',
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
        print("no changes (already applied)")
        return
    with io.open(P, "w", encoding="utf-8") as f:
        f.write(src)
    print("WROTE", P)


if __name__ == "__main__":
    main()
