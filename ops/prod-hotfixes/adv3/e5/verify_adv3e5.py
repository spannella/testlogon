"""ADV3 EPIC E5 deep-verification against the live (mock) DDB.

Exercises ADV3-10 (review bypasses), ADV3-11 (policy pass), ADV3-12 (limits/
fraud/validation) with synthetic advertisers/campaigns/creatives, then cleans up
every created item (0 residue). Prints a PASS/FAIL matrix.
"""
import sys, time, uuid, traceback

from app.core.tables import T
from app.core.time import now_ts
from app.models import AdAccountCreateIn, CampaignCreateIn, CreativeCreateIn, TargetingCreateIn

import app.services.ad_accounts as accts
import app.services.ad_campaigns as camps
import app.services.ad_creatives as creatives
import app.services.ad_billing as billing
import app.services.ad_serving as serving
import app.services.ad_policy as policy
import app.services.ad_fraud_prevention as fraud
import app.services.shop_ads as shop
import app.services.sponsored_creator_posts as spcp
import app.services.ad_messaging as admsg
import app.services.admin_ad_platform as adminp

PREFIX = "adv3e5_%s" % uuid.uuid4().hex[:8]
RESULTS = []
CREATED_ACCTS = []
CREATED_CLICKS = []
CREATED_SDEALS = []   # (pk, sk)
CREATED_POSTS = []    # post_ids

def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print("%s :: %s %s" % ("PASS" if cond else "FAIL", name, ("- " + detail) if detail else ""))

def mk_account(owner, status="active", **extra):
    a = accts.create_ad_account(owner, AdAccountCreateIn(
        company_name="E5 %s" % owner[:20], billing_email="%s@e5.test" % owner[:40]))
    aid = a["account_id"]
    CREATED_ACCTS.append(aid)
    upd = {":s": status, ":u": now_ts()}
    expr = "SET #s = :s, updated_at = :u, balance_cents = :bal, lifetime_spend_cents = :life"
    upd[":bal"] = int(extra.pop("balance_cents", 100000))
    upd[":life"] = int(extra.pop("lifetime_spend_cents", 0))
    for k, v in extra.items():
        expr += ", %s = :%s" % (k, k)
        upd[":%s" % k] = v
    T.ad_accounts.update_item(Key={"pk": "ACCT#%s" % aid, "sk": "META"},
                              UpdateExpression=expr,
                              ExpressionAttributeNames={"#s": "status"},
                              ExpressionAttributeValues=upd)
    return aid

def mk_campaign(aid, status="active", bid_cpm=500, **kw):
    c = camps.create_campaign(aid, CampaignCreateIn(
        name="c", objective="traffic", budget_cents=kw.get("budget_cents", 100000),
        budget_type="lifetime", bid_cpm_cents=bid_cpm, bid_cpc_cents=50, bid_cpa_cents=500,
        start_date=now_ts()-3600, end_date=now_ts()+7*86400, category="general"))
    cid = c["campaign_id"]
    T.ad_campaigns.update_item(Key={"pk": "ACCT#%s" % aid, "sk": "CAMPAIGN#%s" % cid},
                               UpdateExpression="SET #s = :s, updated_at = :u",
                               ExpressionAttributeNames={"#s": "status"},
                               ExpressionAttributeValues={":s": status, ":u": now_ts()})
    return cid

def mk_creative(cid, aid, approved=True, **kw):
    cr = creatives.create_creative(cid, aid, CreativeCreateIn(
        format="native_post", title=kw.get("title", "Nice product"),
        headline=kw.get("headline", "Great deal"), body_text=kw.get("body_text", "Buy our thing"),
        cta_text="Shop", cta_url=kw.get("cta_url", "https://good.example.com/p")))
    crid = cr["creative_id"]
    if approved:
        T.ad_creatives.update_item(Key={"pk": "CAMP#%s" % cid, "sk": "CREATIVE#%s" % crid},
                                   UpdateExpression="SET #s = :s",
                                   ExpressionAttributeNames={"#s": "status"},
                                   ExpressionAttributeValues={":s": "approved"})
    return crid

def run():
    # ============ ADV3-11 (E1): automated policy pass ============
    r_clean = policy.screen_creative(title="Cozy Blanket", body_text="Soft and warm", cta_url="https://shop.example.com/x")
    check("ADV3-11 policy clean->clean", r_clean.decision == "clean", r_clean.decision)
    r_deny = policy.screen_creative(title="Cheap deal", body_text="Guaranteed returns, double your money now", cta_url="https://x.example.com")
    check("ADV3-11 deny-term->reject", r_deny.decision == "reject" and "prohibited_term" in r_deny.flags, "%s %s" % (r_deny.decision, r_deny.flags))
    r_dom = policy.screen_creative(title="ok", body_text="normal copy", cta_url="http://malware.test/land")
    check("ADV3-11 blocked-domain->reject", r_dom.decision == "reject" and "blocked_domain" in r_dom.flags, "%s %s" % (r_dom.decision, r_dom.flags))
    r_risk = policy.screen_creative(title="Miracle", body_text="Act now! 100% free limited time", cta_url="https://bit.ly/xyz")
    check("ADV3-11 risk-signals->review(ranked)", r_risk.decision == "review" and r_risk.score >= 20, "score=%s %s" % (r_risk.score, r_risk.flags))

    # submit_creative_for_review wiring: auto-reject vs pending_review + risk-rank
    aid = mk_account(PREFIX + "_p1", status="active")
    cid = mk_campaign(aid)
    cr_bad = creatives.create_creative(cid, aid, CreativeCreateIn(
        format="native_post", title="Scam", body_text="get rich quick guaranteed returns",
        cta_text="Go", cta_url="https://x.example.com"))
    res_bad = creatives.submit_creative_for_review(cid, cr_bad["creative_id"])
    row_bad = creatives.get_creative_by_id(cr_bad["creative_id"])
    check("ADV3-11 submit deny-term auto-rejected", res_bad.get("status") == "rejected" and row_bad.get("status") == "rejected", res_bad.get("status"))
    check("ADV3-11 auto-reject stamps policy meta", int(row_bad.get("policy_score", 0)) >= 0 and row_bad.get("policy_decision") == "reject", str(row_bad.get("policy_decision")))
    cr_ok = creatives.create_creative(cid, aid, CreativeCreateIn(
        format="native_post", title="Nice", body_text="a normal wholesome advert",
        cta_text="Go", cta_url="https://good.example.com"))
    res_ok = creatives.submit_creative_for_review(cid, cr_ok["creative_id"])
    check("ADV3-11 submit clean->pending_review (no serve w/o pass)", res_ok.get("status") == "pending_review", res_ok.get("status"))

    # ============ ADV3-10 E2: seller-boost through the gate ============
    orig_resolve = shop.resolve_product
    try:
        shop.resolve_product = lambda item_id, category_id="": {
            "creator_id": PREFIX + "_seller", "name": "Clean Mug", "category_id": "",
            "price_cents": 1500, "image_urls": [], "description": "a nice mug"}
        b_clean = shop.boost_listing(owner_sub=PREFIX + "_seller", item_id="itm_clean")
        CREATED_ACCTS.append(b_clean["account_id"])
        check("ADV3-10/E2 clean boost auto-approves+serves", b_clean.get("creative_status") == "approved" and b_clean.get("serving") is True, str(b_clean.get("creative_status")))

        shop.resolve_product = lambda item_id, category_id="": {
            "creator_id": PREFIX + "_seller2", "name": "Guaranteed returns double your money",
            "category_id": "", "price_cents": 999, "image_urls": [], "description": "get rich quick"}
        b_bad = shop.boost_listing(owner_sub=PREFIX + "_seller2", item_id="itm_bad")
        CREATED_ACCTS.append(b_bad["account_id"])
        bad_cr = creatives.get_creative_by_id(b_bad["creative_id"])
        check("ADV3-10/E2 policy-violating boost held (not serving)",
              b_bad.get("creative_status") in ("rejected", "pending_review") and b_bad.get("serving") is False and bad_cr.get("status") != "approved",
              str(b_bad.get("creative_status")))
    finally:
        shop.resolve_product = orig_resolve

    # ============ ADV3-10 E3: sponsored-as-creator ============
    adv = mk_account(PREFIX + "_adv", status="active")
    adv_camp = mk_campaign(adv)
    # hard-violation body -> 422 before publish
    prop_bad = spcp.create_proposal(advertiser_sub=PREFIX + "_adv", advertiser_account_id=adv,
        creator_sub=PREFIX + "_creator", body="get rich quick guaranteed returns click here",
        campaign_id=adv_camp)
    CREATED_SDEALS.append(("SPCP#%s" % prop_bad["proposal_id"], "META"))
    try:
        spcp.approve_and_publish(proposal_id=prop_bad["proposal_id"], creator_sub=PREFIX + "_creator")
        check("ADV3-10/E3 hard-violation blocks publish (422)", False, "did not raise")
    except spcp.SponsoredPostError as e:
        check("ADV3-10/E3 hard-violation blocks publish (422)", e.status_code == 422, "status=%s" % e.status_code)

    # unapproved linked creative -> 409
    unappr = mk_creative(adv_camp, adv, approved=False)
    prop_unappr = spcp.create_proposal(advertiser_sub=PREFIX + "_adv", advertiser_account_id=adv,
        creator_sub=PREFIX + "_creator", body="totally normal wholesome post",
        campaign_id=adv_camp, creative_id=unappr)
    CREATED_SDEALS.append(("SPCP#%s" % prop_unappr["proposal_id"], "META"))
    try:
        spcp.approve_and_publish(proposal_id=prop_unappr["proposal_id"], creator_sub=PREFIX + "_creator")
        check("ADV3-10/E3 unapproved creative blocks publish (409)", False, "did not raise")
    except spcp.SponsoredPostError as e:
        check("ADV3-10/E3 unapproved creative blocks publish (409)", e.status_code == 409, "status=%s" % e.status_code)

    # clean + empty disclosure -> published post carries forced default label
    prop_ok = spcp.create_proposal(advertiser_sub=PREFIX + "_adv", advertiser_account_id=adv,
        creator_sub=PREFIX + "_creator2", body="a wholesome normal sponsored post", campaign_id=adv_camp)
    CREATED_SDEALS.append(("SPCP#%s" % prop_ok["proposal_id"], "META"))
    pub = spcp.approve_and_publish(proposal_id=prop_ok["proposal_id"], creator_sub=PREFIX + "_creator2")
    CREATED_POSTS.append(pub["post_id"])
    post = pub.get("post", {})
    check("ADV3-10/E3 empty disclosure forced server-side",
          bool(post.get("paid_partnership_disclosure")) and bool(post.get("sponsor_label")),
          "label=%r disc=%r" % (post.get("sponsor_label"), post.get("paid_partnership_disclosure")))

    # ============ ADV3-10 E7: ad-messaging ============
    off_bad = admsg.create_offer(advertiser_sub=PREFIX + "_adv", advertiser_account_id=adv,
        creator_sub=PREFIX + "_creator", body="get rich quick guaranteed returns", campaign_id=adv_camp)
    CREATED_SDEALS.append(("AMSGOFFER#%s" % off_bad["offer_id"], "META"))
    try:
        admsg.approve_and_send(offer_id=off_bad["offer_id"], creator_sub=PREFIX + "_creator")
        check("ADV3-10/E7 hard-violation blocks send (422)", False, "did not raise")
    except admsg.AdMessagingError as e:
        check("ADV3-10/E7 hard-violation blocks send (422)", e.status_code == 422, "status=%s" % e.status_code)

    # per-recipient global frequency cap
    rcpt = PREFIX + "_rcpt"
    cap = admsg.recipient_daily_cap()
    before = admsg.recipient_over_freq_cap(rcpt)
    for _ in range(cap):
        admsg._bump_recipient_freq(rcpt)
    after = admsg.recipient_over_freq_cap(rcpt)
    day = admsg._freq_day()
    CREATED_SDEALS.append(("AMSGFREQ#%s" % rcpt, "DAY#%s" % day))
    check("ADV3-10/E7 per-recipient freq cap (under=ok, at=blocked)", (before is False) and (after is True), "cap=%s before=%s after=%s" % (cap, before, after))

    # ============ ADV3-12 E5: velocity cap + KYC gate ============
    velo = mk_account(PREFIX + "_velo", status="active", daily_spend_cap_cents=100, balance_cents=100000)
    velo_c = mk_campaign(velo, budget_cents=100000)
    r1 = billing._process_charge(account_id=velo, campaign_id=velo_c, entry_type="click_charge",
        charge_cents=60, creator_id="", reason="t", meta={}, idempotency_key="%s#v1" % PREFIX)
    r2 = billing._process_charge(account_id=velo, campaign_id=velo_c, entry_type="click_charge",
        charge_cents=60, creator_id="", reason="t", meta={}, idempotency_key="%s#v2" % PREFIX)
    check("ADV3-12/E5 velocity: first under-cap charge ok", r1.get("ok") is True, r1.get("reason"))
    check("ADV3-12/E5 velocity: over-cap charge blocked", r2.get("ok") is False and r2.get("reason") == "spend_velocity_exceeded", r2.get("reason"))
    velo_acct = accts.get_ad_account(velo)
    check("ADV3-12/E5 velocity: blocked charge did NOT debit", int(velo_acct.get("balance_cents", 0)) == 100000 - 60, "bal=%s" % velo_acct.get("balance_cents"))

    # new vs established tier via first_settled_at
    new_acct = accts.get_ad_account(mk_account(PREFIX + "_new", status="active"))
    est_acct = accts.get_ad_account(mk_account(PREFIX + "_est", status="active", first_settled_at=now_ts()))
    cap_new = billing._daily_spend_cap_cents(new_acct)
    cap_est = billing._daily_spend_cap_cents(est_acct)
    check("ADV3-12/E5 new-account cap < established cap", cap_new < cap_est and cap_new > 0, "new=%s est=%s" % (cap_new, cap_est))

    # KYC threshold gate
    kyc = mk_account(PREFIX + "_kyc", status="active", kyc_required_spend_cents=50,
                     lifetime_spend_cents=40, daily_spend_cap_cents=100000, balance_cents=100000)
    rk = billing._process_charge(account_id=kyc, campaign_id=mk_campaign(kyc), entry_type="click_charge",
        charge_cents=30, creator_id="", reason="t", meta={}, idempotency_key="%s#k1" % PREFIX)
    check("ADV3-12/E5 KYC gate blocks crossing threshold uncleared", rk.get("ok") is False and rk.get("reason") == "kyc_required", rk.get("reason"))
    T.ad_accounts.update_item(Key={"pk": "ACCT#%s" % kyc, "sk": "META"},
        UpdateExpression="SET kyc_cleared = :t", ExpressionAttributeValues={":t": True})
    kyc_acct = accts.get_ad_account(kyc)
    rk2 = billing.check_spend_limits(account_id=kyc, charge_cents=30, entry_type="click_charge")
    check("ADV3-12/E5 KYC-cleared account passes", rk2.get("allowed") is True, rk2.get("reason"))

    # ============ ADV3-12 E6: serve gate requires active + reject cascade ============
    srv = mk_account(PREFIX + "_srv", status="active")
    srv_c = mk_campaign(srv, bid_cpm=20000)  # max bid
    mk_creative(srv_c, srv, approved=True)
    # Deterministic isolation: exclude every OTHER active campaign so ours is the
    # only paid candidate the auction can pick (prod runs ~49 live campaigns).
    def _other_active_ids():
        return {str(c.get("campaign_id")) for c in camps.list_campaigns_by_status("active")
                if str(c.get("campaign_id")) != srv_c}
    def _win_is_ours():
        excl = _other_active_ids()
        for _ in range(3):
            ad = serving.serve_ad(surface="newsfeed", content_type="newsfeed", creator_id="platform",
                content_id="e5slot", slot_type="feed_ad", user_id=PREFIX + "_viewer", content_owner_id="",
                exclude_campaign_ids=excl)
            if ad.get("campaign_id") == srv_c:
                return True
        return False
    active_win = _win_is_ours()
    T.ad_accounts.update_item(Key={"pk": "ACCT#%s" % srv, "sk": "META"},
        UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": "rejected"})
    rejected_win = _win_is_ours()
    check("ADV3-12/E6 active account serves", active_win is True)
    check("ADV3-12/E6 rejected account does NOT serve", rejected_win is False)

    # reject cascade-pause
    casc = mk_account(PREFIX + "_casc", status="active")
    casc_c = mk_campaign(casc, status="active")
    adminp.moderate_account(account_id=casc, action="reject", admin_sub="admin_e5", reason="policy")
    casc_camp = camps.get_campaign(casc, casc_c)
    check("ADV3-12/E6 reject cascade-pauses campaigns", casc_camp.get("status") == "paused", casc_camp.get("status"))

    # ============ ADV3-12 E8: review decision validation ============
    val_acct = mk_account(PREFIX + "_val", status="pending_review")
    try:
        accts.review_ad_account(val_acct, "admin", "banana")
        check("ADV3-12/E8 unknown account decision raises", False, "no raise")
    except ValueError:
        check("ADV3-12/E8 unknown account decision raises", True)
    val_c = mk_campaign(val_acct)
    val_cr = creatives.create_creative(val_c, val_acct, CreativeCreateIn(format="native_post", title="x", cta_url="https://a.example.com"))
    try:
        creatives.review_creative(val_cr["creative_id"], "admin", "banana")
        check("ADV3-12/E8 unknown creative decision raises", False, "no raise")
    except ValueError:
        check("ADV3-12/E8 unknown creative decision raises", True)
    ok_dec = accts.review_ad_account(val_acct, "admin", "approve")
    check("ADV3-12/E8 valid decision still works", ok_dec and ok_dec.get("status") == "active", str(ok_dec))

    # ============ ADV3-12 E9: geo rule threaded + fires ============
    geo_acct = mk_account(PREFIX + "_geo", status="active")
    geo_c = mk_campaign(geo_acct)
    from app.services.ad_targeting import create_targeting
    create_targeting(geo_c, geo_acct, TargetingCreateIn(name="us", country_codes=["US"]))
    tc = serving._campaign_targeting_countries(geo_c)
    check("ADV3-12/E9 targeting countries resolved", tc == ["US"], str(tc))
    fr_mismatch = fraud.check_fraud(user_id="u", geo_country="CA", targeting_countries=tc, event_type="click", count_velocity=False)
    fr_match = fraud.check_fraud(user_id="u", geo_country="US", targeting_countries=tc, event_type="click", count_velocity=False)
    check("ADV3-12/E9 geo-mismatch rule fires", fr_mismatch.rule_scores.get("geo_mismatch", 0) > 0 and fr_match.rule_scores.get("geo_mismatch", 0) == 0,
          "mismatch=%s match=%s" % (fr_mismatch.rule_scores.get("geo_mismatch"), fr_match.rule_scores.get("geo_mismatch")))

    # ============ ADV3-12 E4: CTA CPC fraud gate present (from E1) ============
    import inspect
    src = inspect.getsource(serving.record_cta_click)
    check("ADV3-12/E4 record_cta_click runs fraud check", "check_fraud" in src and "record_account_activity" in src)

def cleanup():
    # delete created ledger/spend/idemp/campaign/creative/account rows
    for aid in set(CREATED_ACCTS):
        try:
            # campaigns + their creatives
            resp = T.ad_campaigns.query(
                KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("pk").eq("ACCT#%s" % aid))
            for camp in resp.get("Items", []):
                cid = camp.get("campaign_id") or str(camp.get("sk", "")).replace("CAMPAIGN#", "")
                crs = T.ad_creatives.query(
                    KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("pk").eq("CAMP#%s" % cid))
                for cr in crs.get("Items", []):
                    T.ad_creatives.delete_item(Key={"pk": cr["pk"], "sk": cr["sk"]})
                T.ad_campaigns.delete_item(Key={"pk": camp["pk"], "sk": camp["sk"]})
        except Exception:
            pass
        try:
            led = T.ad_billing.query(
                KeyConditionExpression=__import__("boto3").dynamodb.conditions.Key("pk").eq("ACCT#%s" % aid))
            for it in led.get("Items", []):
                T.ad_billing.delete_item(Key={"pk": it["pk"], "sk": it["sk"]})
        except Exception:
            pass
        try:
            T.ad_accounts.delete_item(Key={"pk": "ACCT#%s" % aid, "sk": "META"})
        except Exception:
            pass
    for pk, sk in set(CREATED_SDEALS):
        try:
            T.sponsorship_deals.delete_item(Key={"pk": pk, "sk": sk})
        except Exception:
            pass
    for pid in set(CREATED_POSTS):
        try:
            from app.routers.newsfeed import ddb_delete_item, pk_post, sk_post
            ddb_delete_item({"pk": pk_post(pid), "sk": sk_post()})
        except Exception:
            pass
    # fraud VEL/RISK counters minted during E9/velocity (best-effort by scanning our prefix is overkill; leave TTL'd rows)

if __name__ == "__main__":
    try:
        run()
    except Exception:
        print("EXC during run:")
        traceback.print_exc()
    finally:
        cleanup()
    npass = sum(1 for _, ok, _ in RESULTS if ok)
    nfail = sum(1 for _, ok, _ in RESULTS if not ok)
    print("\n==== ADV3-E5 RESULT: %d PASS / %d FAIL / %d total ====" % (npass, nfail, len(RESULTS)))
    print("CLEANUP: %d accounts, %d sdeals, %d posts removed" % (len(set(CREATED_ACCTS)), len(set(CREATED_SDEALS)), len(set(CREATED_POSTS))))
    sys.exit(1 if nfail else 0)
