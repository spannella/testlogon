import time, json
def E(m): print("EVIDENCE| " + str(m), flush=True)
RES = []
def CHECK(name, cond, detail=""):
    RES.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + " :: " + str(detail), flush=True)

TS = int(time.time())
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.models import AdAccountCreateIn, CampaignCreateIn, CreativeCreateIn, CtaActionIn
from app.services import ad_accounts, ad_campaigns, ad_creatives, ad_billing, ad_serving, ad_attribution
ADMIN = "adv2e2_admin"

# ---- seed a dominating advertiser (wins the 2nd-price auction) ----
acct = ad_accounts.create_ad_account("adv2e2_owner_%d" % TS,
        AdAccountCreateIn(company_name="E2 CTA Co", billing_email="e2cta.%d@testlogon.example" % TS))
AID = acct["account_id"]
ad_accounts.review_ad_account(AID, ADMIN, "approve")
ad_billing.deposit_funds(AID, 2000000, "")
E("advertiser AID=%s balance=%d" % (AID, ad_billing._get_balance(AID)))

camp = ad_campaigns.create_campaign(AID, CampaignCreateIn(name="E2 CTA Camp", objective="conversions",
        budget_cents=2000000, budget_type="lifetime",
        bid_cpm_cents=20000, bid_cpc_cents=1234, bid_cpa_cents=5678, category="general"))
CID = camp["campaign_id"]
ad_campaigns.submit_campaign_for_review(AID, CID)
ad_campaigns.review_campaign(CID, ADMIN, "approve")
# Own fresh campaign: bump its CPM above the standing prod field (competitors bid
# up to 30000) via a direct write on MY OWN campaign row so it wins the 2nd-price
# auction deterministically. CPC/CPA (1234/5678) unchanged -> those are what the
# CTA/conversion charges bill.
T.ad_campaigns.update_item(Key={"pk": "ACCT#%s" % AID, "sk": "CAMPAIGN#%s" % CID},
        UpdateExpression="SET bid_cpm_cents=:b", ExpressionAttributeValues={":b": 999999})
E("campaign=%s bid_cpm=999999(own) bid_cpc=1234 bid_cpa=5678" % CID)

ctas = [
    CtaActionIn(cta_type="buy_product", target_id="prod_e2_%d" % TS, label="Shop now"),
    CtaActionIn(cta_type="view_product", target_id="prod_e2_%d" % TS, label="View"),
    CtaActionIn(cta_type="tip", target_id="", label="Tip creator"),
    CtaActionIn(cta_type="subscribe", target_id="", label="Subscribe"),
    CtaActionIn(cta_type="subscribe_other", target_id="acct_other_%d" % TS, label="Follow Acme"),
]
cr = ad_creatives.create_creative(CID, AID, CreativeCreateIn(format="image", title="E2 CTA",
        headline="Click through", cta_text="Learn more", cta_url="https://e2.example/learn",
        skip_after_seconds=5, ctas=ctas))
CRID = cr["creative_id"]
T.ad_creatives.update_item(Key={"pk": cr["pk"], "sk": cr["sk"]},
        UpdateExpression="SET image_url=:u",
        ExpressionAttributeValues={":u": "https://images.unsplash.com/photo-1447933601403-0c6688de566e?w=1200&q=80"})
ad_creatives.submit_creative_for_review(CID, CRID)
ad_creatives.review_creative(CRID, ADMIN, "approve")
stored = ad_creatives.get_creative(CID, CRID)
CHECK("ADV2-201_creative_persists_ctas", len(stored.get("ctas") or []) == 5,
      "stored_ctas=%s" % json.dumps(stored.get("ctas")))

CREATOR = "e2_creator_%d" % TS   # placement content owner (video/live in front of a creator)

def serve(viewer):
    return ad_serving.serve_ad(surface="preroll", content_type="vod", creator_id=CREATOR,
            content_id="vid_e2_%d" % TS, slot_type="pre_roll", user_id=viewer, content_owner_id=CREATOR)

def creator_credits(sub):
    it = T.billing.query(KeyConditionExpression=Key("pk").eq("USER#%s" % sub) & Key("sk").begins_with("LEDGER#")).get("Items", [])
    return sum(int(x.get("amount_cents", 0)) for x in it if x.get("type") == "credit")

# ---- 1. a served ad carries CTA target(s) (ADV2-202) ----
V1 = "e2_viewer_%d_1" % TS
s1 = serve(V1)
served_ctas = s1.get("ctas") or []
types = sorted([c.get("cta_type") for c in served_ctas])
won = bool(s1.get("filled")) and s1.get("creative_id") == CRID
CHECK("ADV2-202_serve_carries_cta_targets",
      won and len(served_ctas) == 5 and {"buy_product","view_product","tip","subscribe","subscribe_other"} <= set(types),
      "won=%s types=%s" % (won, types))
ACK1 = s1.get("ad_click_id")
E("serve1 ad_click_id=%s ctas=%s" % (ACK1, json.dumps(served_ctas)))

# ---- 2. CTA tap -> CPC charge (funds-guarded, idempotent per ad_click_id+cta_type) ----
b0 = ad_billing._get_balance(AID)
r_buy = ad_serving.record_cta_click(ad_click_id=ACK1, cta_type="buy_product", viewer_sub=V1, target_id="prod")
b1 = ad_billing._get_balance(AID)
CHECK("CTA_tap_charges_CPC", r_buy.get("charged") and r_buy.get("charge_cents") == 1234 and (b0 - b1) == 1234,
      "r=%s advertiser_delta=%d" % (json.dumps(r_buy), b0 - b1))
r_buy2 = ad_serving.record_cta_click(ad_click_id=ACK1, cta_type="buy_product", viewer_sub=V1, target_id="prod")
b2 = ad_billing._get_balance(AID)
CHECK("CTA_CPC_idempotent_repeat0", r_buy2.get("charge_cents") == 0 and (b1 - b2) == 0 and r_buy2.get("reason") == "duplicate",
      "r=%s advertiser_delta=%d" % (json.dumps(r_buy2), b1 - b2))
cc = creator_credits(CREATOR)
CHECK("placement_split_creator_credited", cc > 0, "creator(%s) credit_total=%s (share of 1234 CPC)" % (CREATOR, cc))

# ---- 3. buy_product tap -> purchase carries ad_click_id -> CPA fires + attributed ----
bb = ad_billing._get_balance(AID)
conv = ad_attribution.attribute_conversion(viewer_sub=V1, conversion_type="purchase",
        conversion_value_cents=9999, ad_click_id=ACK1)
ba = ad_billing._get_balance(AID)
CHECK("buy_product_CPA_fires_attributed", conv.get("attributed") and (bb - ba) == 5678,
      "conv=%s advertiser_delta=%d" % (json.dumps(conv), bb - ba))

# ---- 4. subscribe tap -> subscription attributed CPA (fresh click) ----
V2 = "e2_viewer_%d_2" % TS
s2 = serve(V2); ACK2 = s2.get("ad_click_id")
rc = ad_serving.record_cta_click(ad_click_id=ACK2, cta_type="subscribe", viewer_sub=V2)
bsub0 = ad_billing._get_balance(AID)
conv2 = ad_attribution.attribute_conversion(viewer_sub=V2, conversion_type="subscribe",
        conversion_value_cents=1500, ad_click_id=ACK2)
bsub1 = ad_billing._get_balance(AID)
CHECK("subscribe_CTA_charges_CPC", rc.get("charged") and rc.get("charge_cents") == 1234, "rc=%s" % json.dumps(rc))
CHECK("subscribe_CPA_attributed", conv2.get("attributed") and (bsub0 - bsub1) == 5678,
      "conv=%s advertiser_delta=%d" % (json.dumps(conv2), bsub0 - bsub1))

# ---- 5. tip CTA -> NO advertiser charge (tip credits the creator only) ----
V3 = "e2_viewer_%d_3" % TS
s3 = serve(V3); ACK3 = s3.get("ad_click_id")
bt0 = ad_billing._get_balance(AID)
rt = ad_serving.record_cta_click(ad_click_id=ACK3, cta_type="tip", viewer_sub=V3, target_id="")
bt1 = ad_billing._get_balance(AID)
CHECK("tip_CTA_no_advertiser_charge",
      (not rt.get("charged")) and rt.get("charge_cents") == 0 and (bt0 - bt1) == 0 and rt.get("reason") == "tip_no_advertiser_charge",
      "rt=%s advertiser_delta=%d" % (json.dumps(rt), bt0 - bt1))
row3 = T.ad_clicks.get_item(Key={"ad_click_id": ACK3}).get("Item") or {}
CHECK("tip_click_not_converted_no_cpa", row3.get("status") != "converted" and not row3.get("converted_at"),
      "status=%s converted_at=%s" % (row3.get("status"), row3.get("converted_at")))

print("=== SUMMARY ===", flush=True)
allok = all(ok for _, ok in RES)
for n, ok in RES:
    print(("PASS " if ok else "FAIL ") + n, flush=True)
print("OVERALL " + ("ALL_PASS" if allok else "FAILED"), flush=True)
