import io, sys

def patch(path, edits):
    with io.open(path, 'r', encoding='utf-8') as f:
        s = f.read()
    orig = s
    for old, new, n in edits:
        c = s.count(old)
        assert c == n, 'FAIL %s expected %d got %d for: %r' % (path, n, c, old[:70])
        s = s.replace(old, new)
    if s != orig:
        with io.open(path, 'w', encoding='utf-8') as f:
            f.write(s)
        print('PATCHED', path)
    else:
        print('NOCHANGE', path)

base = sys.argv[1].rstrip('/')
SERV = base + '/app/services/ad_serving.py'
BILL = base + '/app/services/ad_billing.py'
ADS = base + '/app/routers/ads.py'

patch(SERV, [
('    # 4. Select winner (highest score)\n    candidates.sort(key=lambda c: c["score"], reverse=True)\n    winner = candidates[0]\n',
 '    # 4. Select winner (highest score) + ADV-302 second-price auction.\n    candidates.sort(key=lambda c: c["score"], reverse=True)\n    winner = candidates[0]\n    # ADV-302: rank by effective bid (bid_cpm x relevance=1.0). The winner clears\n    # at the runner-up bid + 1c (capped at its own bid); a lone bidder clears at\n    # the reserve floor. cleared_cpm is what track_ad_event bills, so an advertiser\n    # never pays more than the next-highest rival would have. CPC/CPA carried for\n    # the click/conversion charge.\n    _CPM_FLOOR = 50\n    _CPM_DEF, _CPC_DEF, _CPA_DEF = 500, 50, 500\n    win_cpm = int(winner["campaign"].get("bid_cpm_cents", _CPM_DEF) or _CPM_DEF)\n    if len(candidates) > 1:\n        runner_up_cpm = int(round(candidates[1]["score"]))\n        cleared_cpm = min(win_cpm, runner_up_cpm + 1)\n    else:\n        cleared_cpm = _CPM_FLOOR\n    cleared_cpm = max(1, min(cleared_cpm, win_cpm))\n    win_cpc = int(winner["campaign"].get("bid_cpc_cents", _CPC_DEF) or _CPC_DEF)\n    win_cpa = int(winner["campaign"].get("bid_cpa_cents", _CPA_DEF) or _CPA_DEF)\n', 1),
('    ad_click_id = uuid.uuid4().hex\n    _bid_cpm_win = int(winner["campaign"].get("bid_cpm_cents", 500) or 500)\n    try:',
 '    ad_click_id = uuid.uuid4().hex\n    try:', 1),
('            "status": "served",\n            "effective_price_cents": _bid_cpm_win,\n',
 '            "status": "served",\n            "effective_price_cents": cleared_cpm,\n            "effective_cpm_cents": cleared_cpm,\n            "bid_cpc_cents": win_cpc,\n            "bid_cpa_cents": win_cpa,\n            "gross_bid_cpm_cents": win_cpm,\n', 1),
])

patch(SERV, [
('    view_time_ms: int = 0,\n    geo_country: str = "",\n) -> Dict[str, Any]:\n    """Record an ad event and process billing.',
 '    view_time_ms: int = 0,\n    geo_country: str = "",\n    ad_click_id: str = "",\n) -> Dict[str, Any]:\n    """Record an ad event and process billing.', 1),
('    # Update frequency cap on impression\n    if event == "impression":\n        _increment_frequency_cap(user_id, campaign_id)\n\n    return {"ok": True, "event_id": event_id, "flagged": False, "fraud_score": fraud_score}',
 '''    # Update frequency cap on impression
    if event == "impression":
        _increment_frequency_cap(user_id, campaign_id)

    # -- ADV-303/304: real charge on a NEWSFEED impression/click --------
    # After the fraud gate passes, debit the advertiser via the funds-guarded
    # _process_charge. Surface-gated: the pre-roll surface already charges on
    # video-completion (broadcast_ads) so it is skipped here to avoid a double
    # charge. Idempotent per (ad_click_id, event) so a retried track never
    # double-bills. Revenue split via _split_revenue -> content owner when
    # present, else platform-only (standalone feed unit).
    charged = False
    charge_cents = 0
    charge_reason = ""
    _billable = (
        event in ("impression", "click")
        and surface not in ("preroll", "pre_roll", "midroll", "postroll")
        and bool(ad_click_id)
    )
    if _billable:
        try:
            from app.services import ad_billing
            from app.services.ad_campaigns import get_campaign
            click_row = {}
            try:
                _r = T.ad_clicks.get_item(Key={"ad_click_id": ad_click_id})
                click_row = _r.get("Item") or {}
            except Exception:
                click_row = {}
            content_owner_sub = str(click_row.get("content_owner_sub", "") or "")
            idem = "%s#%s" % (ad_click_id, event)
            if event == "impression":
                cpm = click_row.get("effective_price_cents")
                if cpm is None:
                    cpm = (get_campaign(account_id, campaign_id) or {}).get("bid_cpm_cents", 500)
                res = ad_billing.charge_impression(
                    account_id=account_id, campaign_id=campaign_id,
                    creative_id=creative_id, creator_id=content_owner_sub,
                    content_id=content_id, bid_cpm_cents=int(cpm or 500),
                    idempotency_key=idem,
                )
            else:
                cpc = click_row.get("bid_cpc_cents")
                if cpc is None:
                    cpc = (get_campaign(account_id, campaign_id) or {}).get("bid_cpc_cents", 50)
                res = ad_billing.charge_click(
                    account_id=account_id, campaign_id=campaign_id,
                    creative_id=creative_id, creator_id=content_owner_sub,
                    content_id=content_id, bid_cpc_cents=int(cpc or 50),
                    idempotency_key=idem,
                )
            charged = bool(res.get("ok"))
            charge_cents = int(res.get("charge_cents", 0) or 0)
            charge_reason = str(res.get("reason", "") or "")
            if charged and charge_cents > 0:
                try:
                    T.ad_clicks.update_item(
                        Key={"ad_click_id": ad_click_id},
                        UpdateExpression="SET #s = :s",
                        ExpressionAttributeNames={"#s": "status"},
                        ExpressionAttributeValues={
                            ":s": "clicked" if event == "click" else "impressed"
                        },
                    )
                except Exception:
                    pass
        except Exception:
            logger.warning("ad_track_charge_failed event=%s click=%s", event, ad_click_id)

    return {
        "ok": True, "event_id": event_id, "flagged": False,
        "fraud_score": fraud_score, "charged": charged,
        "charge_cents": charge_cents, "charge_reason": charge_reason,
    }''', 1),
])

patch(BILL, [
('def charge_click(\n    *, account_id: str, campaign_id: str, creative_id: str,\n    creator_id: str, content_id: str, bid_cpc_cents: int,\n) -> dict:\n    """Charge advertiser for one click (CPC model)."""\n    return _process_charge(\n        account_id=account_id, campaign_id=campaign_id,\n        entry_type="click_charge", charge_cents=bid_cpc_cents,\n        creator_id=creator_id, reason="Ad click",\n        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpc"},\n    )',
 'def charge_click(\n    *, account_id: str, campaign_id: str, creative_id: str,\n    creator_id: str, content_id: str, bid_cpc_cents: int,\n    idempotency_key: str = "",\n) -> dict:\n    """Charge advertiser for one click (CPC model)."""\n    return _process_charge(\n        account_id=account_id, campaign_id=campaign_id,\n        entry_type="click_charge", charge_cents=bid_cpc_cents,\n        creator_id=creator_id, reason="Ad click",\n        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpc"},\n        idempotency_key=idempotency_key,\n    )', 1),
('def charge_conversion(\n    *, account_id: str, campaign_id: str, creative_id: str,\n    creator_id: str, content_id: str, bid_cpa_cents: int,\n) -> dict:\n    """Charge advertiser for one conversion (CPA model)."""\n    return _process_charge(\n        account_id=account_id, campaign_id=campaign_id,\n        entry_type="conversion_charge", charge_cents=bid_cpa_cents,\n        creator_id=creator_id, reason="Ad conversion",\n        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpa"},\n    )',
 'def charge_conversion(\n    *, account_id: str, campaign_id: str, creative_id: str,\n    creator_id: str, content_id: str, bid_cpa_cents: int,\n    idempotency_key: str = "",\n) -> dict:\n    """Charge advertiser for one conversion (CPA model)."""\n    return _process_charge(\n        account_id=account_id, campaign_id=campaign_id,\n        entry_type="conversion_charge", charge_cents=bid_cpa_cents,\n        creator_id=creator_id, reason="Ad conversion",\n        meta={"creative_id": creative_id, "content_id": content_id, "model": "cpa"},\n        idempotency_key=idempotency_key,\n    )', 1),
('    creator_share = max(0, (charge_cents * creator_bps) // 10000)\n    platform_share = charge_cents - creator_share',
 '    # ADV-303/406: a standalone unit (no content owner) books platform-100%;\n    # split with a creator only when the ad ran in front of their content.\n    if creator_id:\n        creator_share = max(0, (charge_cents * creator_bps) // 10000)\n    else:\n        creator_share = 0\n    platform_share = charge_cents - creator_share', 1),
])

patch(ADS, [
('        view_time_ms=body.view_time_ms,\n        geo_country=body.geo_country,\n    )',
 '        view_time_ms=body.view_time_ms,\n        geo_country=body.geo_country,\n        ad_click_id=getattr(body, "ad_click_id", "") or "",\n    )', 1),
])
print('DONE2')
