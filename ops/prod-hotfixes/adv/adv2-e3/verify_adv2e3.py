"""ADV2-E3 (F3 self-advertising) money-path verify -- in-process on prod DDB.

Proves: self-promo (no funding) serves in front of the creator's OWN content;
serve+impression+click+CTA write ZERO ledger rows (debit/credit nobody);
always_win beats a paying advertiser on the own slot; fill_only serves only when
no paid ad is eligible (paid present -> paid wins); self-promo NEVER serves on a
different creator's content; a creator PAID campaign is still self-excluded from
their own view (but serves to others).
"""
import json, uuid
from boto3.dynamodb.conditions import Key

from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_serving, ad_campaigns
from app.services.ad_serving import serve_ad, track_ad_event, record_cta_click
from app.models import CampaignCreateIn

SUF = uuid.uuid4().hex[:8]
C  = "sp_creator_" + SUF     # self-promo creator (owns the content + the promo)
V  = "sp_viewer_" + SUF      # separate viewer
A  = "sp_adv_" + SUF         # paying advertiser
C2 = "sp_creator2_" + SUF    # a DIFFERENT creator
VC = "sp_vcreator_" + SUF    # a neutral content creator (for the self-excl-to-others test)
FAKE_CAT = "adv2e3cat_" + SUF  # a category no real prod campaign uses -> isolates the test

acct_C     = "adacct_spC_" + SUF      # C's (unfunded) self-promo ad account
acct_A     = "adacct_spA_" + SUF      # A's funded paid ad account
acct_Cpaid = "adacct_spCp_" + SUF     # C's funded PAID ad account (self-excl test)

RESULTS = []
def check(name, cond, detail=""):
    RESULTS.append({"name": name, "pass": bool(cond), "detail": str(detail)})
    print(("PASS " if cond else "FAIL ") + name + ("  :: " + str(detail) if detail else ""))

def put_acct(acct_id, owner, bal):
    T.ad_accounts.put_item(Item={
        "pk": f"ACCT#{acct_id}", "sk": "META", "account_id": acct_id,
        "owner_sub": owner, "status": "active", "balance_cents": bal,
        "lifetime_spend_cents": 0, "created_at": now_ts(),
    })

def approved_creative(campaign_id, title):
    cid = "cr_" + uuid.uuid4().hex[:10]
    T.ad_creatives.put_item(Item={
        "pk": f"CAMP#{campaign_id}", "sk": f"CREATIVE#{cid}", "creative_id": cid,
        "campaign_id": campaign_id, "format": "native_post", "title": title,
        "status": "approved", "created_at": now_ts(),
    })
    return cid

def set_status(acct_id, camp_id, status):
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{acct_id}", "sk": f"CAMPAIGN#{camp_id}"},
        UpdateExpression="SET #s = :s", ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": status},
    )

def ad_ledger(acct_id):
    r = T.ad_billing.query(KeyConditionExpression=Key("pk").eq(f"ACCT#{acct_id}"))
    rows = r.get("Items", [])
    led = [x for x in rows if str(x.get("sk", "")).startswith("LEDGER#")]
    idm = [x for x in rows if str(x.get("sk", "")).startswith("IDEMP#")]
    return led, idm

def acct_bal(acct_id):
    it = T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct_id}", "sk": "META"}).get("Item") or {}
    return int(it.get("balance_cents", 0) or 0)

def user_credit_rows(sub):
    r = T.billing.query(KeyConditionExpression=Key("pk").eq(f"USER#{sub}"))
    return [x for x in r.get("Items", []) if str(x.get("sk", "")).startswith("LEDGER#")]

def click_row(acid):
    return T.ad_clicks.get_item(Key={"ad_click_id": acid}).get("Item") or {}

# ── Isolation: a unique category whitelist on the test creators means ONLY
#    campaigns tagged FAKE_CAT are eligible -> real prod paid campaigns (other
#    categories) are filtered out, making the auction deterministic. Self-promo
#    bypasses the category filter, so this does not affect self-promo eligibility.
for cr in (C, C2, VC):
    T.billing.put_item(Item={
        "pk": f"USER#{cr}", "sk": "AD_SETTINGS", "allow_ads": True,
        "min_cpm_cents": 0, "allowed_ad_categories": [FAKE_CAT],
    })

def tag_category(acct_id, camp_id):
    T.ad_campaigns.update_item(
        Key={"pk": f"ACCT#{acct_id}", "sk": f"CAMPAIGN#{camp_id}"},
        UpdateExpression="SET category = :c", ExpressionAttributeValues={":c": FAKE_CAT},
    )

# ── Accounts
put_acct(acct_C, C, 0)              # self-promo: NO funding
put_acct(acct_A, A, 5_000_000)     # funded advertiser
put_acct(acct_Cpaid, C, 5_000_000) # C's funded paid account

# ── Campaigns (create via the real model + create_campaign)
sp_fill_item = ad_campaigns.create_campaign(acct_C, CampaignCreateIn(
    name="Promote my content (fill)", objective="awareness",
    budget_cents=0, budget_type="lifetime",
    is_self_promo=True, self_promo_mode="fill_only"))
sp_fill = sp_fill_item["campaign_id"]

sp_always_item = ad_campaigns.create_campaign(acct_C, CampaignCreateIn(
    name="Promote my content (always)", objective="awareness",
    budget_cents=0, budget_type="lifetime",
    is_self_promo=True, self_promo_mode="always_win"))
sp_always = sp_always_item["campaign_id"]

paid_A_item = ad_campaigns.create_campaign(acct_A, CampaignCreateIn(
    name="Paid advertiser", objective="awareness",
    budget_cents=1_000_000, budget_type="lifetime", bid_cpm_cents=20000))
paid_A = paid_A_item["campaign_id"]

paid_C_item = ad_campaigns.create_campaign(acct_Cpaid, CampaignCreateIn(
    name="C paid campaign", objective="awareness",
    budget_cents=1_000_000, budget_type="lifetime", bid_cpm_cents=20000))
paid_C = paid_C_item["campaign_id"]

tag_category(acct_A, paid_A)      # only FAKE_CAT campaigns are eligible on the test creators
tag_category(acct_Cpaid, paid_C)

for camp in (sp_fill, sp_always, paid_A, paid_C):
    approved_creative(camp, "creative-" + camp[-4:])

# ── ADV2-301 model/persistence contract
check("301 self-promo campaign persisted is_self_promo=True", sp_fill_item.get("is_self_promo") is True)
check("301 self-promo auto-activates (status=active, no review)", sp_fill_item.get("status") == "active", sp_fill_item.get("status"))
check("301 self-promo bids forced to 0",
      sp_fill_item.get("bid_cpm_cents") == 0 and sp_fill_item.get("bid_cpc_cents") == 0 and sp_fill_item.get("bid_cpa_cents") == 0,
      f"cpm={sp_fill_item.get('bid_cpm_cents')}")
check("301 self-promo needs no funding (budget 0 accepted, acct balance 0)",
      sp_fill_item.get("budget_cents") == 0 and acct_bal(acct_C) == 0)
check("301 self_promo_mode persisted", sp_fill_item.get("self_promo_mode") == "fill_only" and sp_always_item.get("self_promo_mode") == "always_win")
check("301 paid campaign stays draft (needs review)", paid_A_item.get("status") == "draft" and paid_A_item.get("is_self_promo") is False)

# activate the paid campaigns; start with ONLY sp_fill self-promo active
set_status(acct_A, paid_A, "active")
set_status(acct_Cpaid, paid_C, "active")
set_status(acct_C, sp_always, "paused")
set_status(acct_Cpaid, paid_C, "paused")   # off until scenario 5
set_status(acct_A, paid_A, "paused")       # off until scenario 2

# ══ SCENARIO 1: self-promo (fill_only) serves in front of C's OWN content;
#    serve+impression+click+CTA => ZERO ledger rows, debit/credit NOBODY.
led_c0, idm_c0 = ad_ledger(acct_C)
cred_c0 = user_credit_rows(C)
r1 = serve_ad(surface="newsfeed", content_type="video", creator_id=C,
              content_id="vid_" + SUF, slot_type="feed", user_id=V, content_owner_id=C)
check("302 fill_only serves self-promo on OWN content (filled)", r1.get("filled") is True, r1.get("fill_reason"))
check("302 winner is the self-promo campaign", r1.get("campaign_id") == sp_fill and r1.get("is_self_promo") is True, r1.get("campaign_id"))
acid1 = r1.get("ad_click_id", "")
cr1 = click_row(acid1)
check("302 AdClicks row self_promo=True + effective_price_cents=0",
      cr1.get("self_promo") is True and int(cr1.get("effective_price_cents", -1)) == 0,
      f"self_promo={cr1.get('self_promo')} price={cr1.get('effective_price_cents')}")

imp = track_ad_event(event="impression", creative_id=r1["creative_id"], campaign_id=sp_fill,
                     account_id=acct_C, surface="newsfeed", slot_type="feed",
                     content_id="vid_" + SUF, creator_id=C, user_id=V, ad_click_id=acid1)
clk = track_ad_event(event="click", creative_id=r1["creative_id"], campaign_id=sp_fill,
                     account_id=acct_C, surface="newsfeed", slot_type="feed",
                     content_id="vid_" + SUF, creator_id=C, user_id=V, ad_click_id=acid1)
cta = record_cta_click(ad_click_id=acid1, cta_type="buy_product", viewer_sub=V)
check("303 impression short-circuits (no charge)", imp.get("charged") is False and imp.get("charge_cents") == 0 and imp.get("charge_reason") == "self_promo_no_charge", imp)
check("303 click short-circuits (no charge)", clk.get("charged") is False and clk.get("charge_cents") == 0 and clk.get("charge_reason") == "self_promo_no_charge", clk)
check("303 CTA click short-circuits (no charge)", cta.get("charge_cents") == 0 and cta.get("reason") == "self_promo_no_charge", cta)

led_c1, idm_c1 = ad_ledger(acct_C)
cred_c1 = user_credit_rows(C)
check("303 ZERO ad_billing ledger rows written for self-promo acct", len(led_c1) == len(led_c0) == 0, f"before={len(led_c0)} after={len(led_c1)}")
check("303 ZERO idempotency/charge markers written", len(idm_c1) == len(idm_c0) == 0, f"before={len(idm_c0)} after={len(idm_c1)}")
check("303 creator credited NOTHING (no USER billing credit rows added)", len(cred_c1) == len(cred_c0), f"before={len(cred_c0)} after={len(cred_c1)}")
check("303 self-promo advertiser account NOT debited (balance still 0)", acct_bal(acct_C) == 0)

# ══ SCENARIO 2: always_win self-promo BEATS a funded paying advertiser on OWN slot.
set_status(acct_C, sp_fill, "paused")
set_status(acct_C, sp_always, "active")
set_status(acct_A, paid_A, "active")
a_bal0 = acct_bal(acct_A); a_led0, _ = ad_ledger(acct_A)
r2 = serve_ad(surface="newsfeed", content_type="video", creator_id=C,
              content_id="vid2_" + SUF, slot_type="feed", user_id=V, content_owner_id=C)
check("302 always_win self-promo displaces the paid ad on OWN slot",
      r2.get("is_self_promo") is True and r2.get("campaign_id") == sp_always, f"winner={r2.get('campaign_id')} self={r2.get('is_self_promo')}")
cr2 = click_row(r2.get("ad_click_id", ""))
check("302 always_win AdClicks self_promo=True + price 0", cr2.get("self_promo") is True and int(cr2.get("effective_price_cents", -1)) == 0)
# fire impression on the self-promo win -> paid advertiser must NOT be charged
track_ad_event(event="impression", creative_id=r2["creative_id"], campaign_id=sp_always,
               account_id=acct_C, surface="newsfeed", slot_type="feed",
               content_id="vid2_" + SUF, creator_id=C, user_id=V, ad_click_id=r2.get("ad_click_id", ""))
a_led1, _ = ad_ledger(acct_A)
check("302 paying advertiser NOT charged when self-promo wins", acct_bal(acct_A) == a_bal0 and len(a_led1) == len(a_led0), f"bal {a_bal0}->{acct_bal(acct_A)}")

# ══ SCENARIO 3: fill_only serves ONLY when no paid eligible -> paid present => PAID wins.
set_status(acct_C, sp_always, "paused")
set_status(acct_C, sp_fill, "active")   # fill_only + paid_A both active
r3 = serve_ad(surface="newsfeed", content_type="video", creator_id=C,
              content_id="vid3_" + SUF, slot_type="feed", user_id=V, content_owner_id=C)
check("302 fill_only YIELDS to the paid ad (paid wins)",
      r3.get("is_self_promo") is False and r3.get("campaign_id") == paid_A, f"winner={r3.get('campaign_id')} self={r3.get('is_self_promo')}")
cr3 = click_row(r3.get("ad_click_id", ""))
check("302 paid winner AdClicks self_promo=False + price>0",
      cr3.get("self_promo") in (False, None) and int(cr3.get("effective_price_cents", 0)) > 0, f"price={cr3.get('effective_price_cents')}")

# ══ SCENARIO 4: self-promo NEVER serves on a DIFFERENT creator's content.
set_status(acct_C, sp_always, "active")   # both self-promo active
set_status(acct_A, paid_A, "paused")      # no paid eligible for C2 either
r4 = serve_ad(surface="newsfeed", content_type="video", creator_id=C2,
              content_id="vidX_" + SUF, slot_type="feed", user_id=V, content_owner_id=C2)
check("302 self-promo does NOT serve on a different creator's content",
      r4.get("is_self_promo") is not True and r4.get("campaign_id") not in (sp_fill, sp_always),
      f"filled={r4.get('filled')} house={r4.get('is_house_ad')} winner={r4.get('campaign_id')}")

# ══ SCENARIO 4b: self-promo never serves as a STANDALONE unit (content_owner empty).
r4b = serve_ad(surface="newsfeed", content_type="video", creator_id=C,
               content_id="vidS_" + SUF, slot_type="feed", user_id=V, content_owner_id="")
check("302 self-promo does NOT serve as a standalone unit (empty content_owner)",
      r4b.get("is_self_promo") is not True and r4b.get("campaign_id") not in (sp_fill, sp_always),
      f"house={r4b.get('is_house_ad')} winner={r4b.get('campaign_id')}")

# ══ SCENARIO 5: a creator PAID campaign is still self-excluded from their OWN view.
set_status(acct_C, sp_fill, "paused")
set_status(acct_C, sp_always, "paused")
set_status(acct_Cpaid, paid_C, "active")
r5a = serve_ad(surface="newsfeed", content_type="video", creator_id=C,
               content_id="vidP_" + SUF, slot_type="feed", user_id=C, content_owner_id=C)
check("self-exclusion: C's PAID campaign is NOT served to C (owner==viewer)",
      r5a.get("campaign_id") != paid_C, f"winner={r5a.get('campaign_id')} house={r5a.get('is_house_ad')}")
r5b = serve_ad(surface="newsfeed", content_type="video", creator_id=VC,
               content_id="vidP2_" + SUF, slot_type="feed", user_id=V, content_owner_id="")
# VC whitelists FAKE_CAT so only paid_C is eligible; V != owner so it is NOT excluded.
check("self-exclusion is owner-scoped: C's PAID campaign DOES serve to another viewer",
      r5b.get("campaign_id") == paid_C and r5b.get("is_self_promo") is False, f"winner={r5b.get('campaign_id')}")

npass = sum(1 for r in RESULTS if r["pass"]); ntot = len(RESULTS)
print("\n==== ADV2-E3 VERIFY: %d/%d PASS ====" % (npass, ntot))
print(json.dumps({"pass": npass, "total": ntot, "suffix": SUF,
                  "campaigns": {"sp_fill": sp_fill, "sp_always": sp_always, "paid_A": paid_A, "paid_C": paid_C},
                  "failures": [r for r in RESULTS if not r["pass"]]}, indent=2))
