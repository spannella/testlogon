p = "app/services/ad_serving.py"
s = open(p, encoding="utf-8").read()
orig = s

# ---- EDIT: record_cta_click -- fraud gate + canonical {id}#click idempotency ----
old = '''    else:
        try:
            from app.services import ad_billing
            from app.services.ad_campaigns import get_campaign
            account_id = str(row.get("account_id", "") or "")
            campaign_id = str(row.get("campaign_id", "") or "")
            cpc = row.get("bid_cpc_cents")
            if cpc is None:
                cpc = (get_campaign(account_id, campaign_id) or {}).get("bid_cpc_cents", 50)
            res = ad_billing.charge_click(
                account_id=account_id, campaign_id=campaign_id,
                creative_id=str(row.get("creative_id", "") or ""),
                creator_id=content_owner_sub,
                content_id=str(row.get("content_id", "") or ""),
                bid_cpc_cents=int(cpc or 50),
                idempotency_key="%s#cta#%s" % (ad_click_id, cta_type),
            )
            charged = bool(res.get("ok"))
            charge_cents = int(res.get("charge_cents", 0) or 0)
            reason = str(res.get("reason", "") or "")
        except Exception:
            logger.warning("cta_click_charge_failed click=%s cta=%s", ad_click_id, cta_type)
            reason = "charge_error"'''
new = '''    else:
        account_id = str(row.get("account_id", "") or "")
        campaign_id = str(row.get("campaign_id", "") or "")
        # ADV3-2/E4: the CTA CPC charge MUST pass the same fraud gate as the
        # track path (record_cta_click previously skipped it entirely). A flagged
        # tap is recorded, feeds account-fraud stats + auto-suspend, and is NOT
        # charged. Mirrors track_ad_event's fraud handling.
        if getattr(S, "ad_fraud_detection_enabled", True):
            try:
                from app.services import ad_fraud_prevention as fraud
                fr = fraud.check_fraud(
                    user_id=viewer_sub,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    creative_id=str(row.get("creative_id", "") or ""),
                    campaign_id=campaign_id,
                    event_type="click",
                    geo_country=str(row.get("geo_country", "") or ""),
                )
                if fr.flagged:
                    fraud.record_fraud_event(
                        event_id="cta_%s_%s_%s" % (ad_click_id, cta_type, now_ts()),
                        user_id=viewer_sub, ip_address=ip_address,
                        account_id=account_id, campaign_id=campaign_id,
                        creative_id=str(row.get("creative_id", "") or ""),
                        event_type="click", fraud_result=fr,
                    )
                    fraud.maybe_auto_suspend(account_id=account_id)
                    return {
                        "ok": True, "ad_click_id": ad_click_id, "cta_type": cta_type,
                        "target_id": target_id or "", "content_owner_sub": content_owner_sub,
                        "campaign_id": campaign_id, "charged": False, "charge_cents": 0,
                        "flagged": True, "reason": "fraud_flagged",
                    }
                fraud.record_account_activity(account_id=account_id, flagged=False)
            except Exception:
                logger.warning("cta_fraud_check_failed click=%s cta=%s", ad_click_id, cta_type)
        try:
            from app.services import ad_billing
            from app.services.ad_campaigns import get_campaign
            cpc = row.get("bid_cpc_cents")
            if cpc is None:
                cpc = (get_campaign(account_id, campaign_id) or {}).get("bid_cpc_cents", 50)
            res = ad_billing.charge_click(
                account_id=account_id, campaign_id=campaign_id,
                creative_id=str(row.get("creative_id", "") or ""),
                creator_id=content_owner_sub,
                content_id=str(row.get("content_id", "") or ""),
                bid_cpc_cents=int(cpc or 50),
                # ADV3-2/A3: reuse the CANONICAL {ad_click_id}#click idempotency
                # key shared with track_ad_event's click charge, so a creative
                # with BOTH a click-through and an in-player CTA bills CPC exactly
                # ONCE per ad_click_id (first-of-either charges, the second no-ops).
                idempotency_key="%s#click" % ad_click_id,
            )
            charged = bool(res.get("ok"))
            charge_cents = int(res.get("charge_cents", 0) or 0)
            reason = str(res.get("reason", "") or "")
        except Exception:
            logger.warning("cta_click_charge_failed click=%s cta=%s", ad_click_id, cta_type)
            reason = "charge_error"'''
assert old in s, "cta charge block not found"
s = s.replace(old, new, 1)

assert s != orig
open(p, "w", encoding="utf-8").write(s)
print("ad_serving.py patched OK; delta bytes:", len(s) - len(orig))
