"""ADV-B4 in-process prod verification (run with prod env: DEV_MODE=1 + .env.local).

Proves, against prod DDB:
  * ADV-401 last-click attribution service (find_last_click over GSI ByViewer).
  * ADV-402 ad-click -> SUBSCRIBE (real endpoint) charges CPA + marks AdClicks converted.
  * ADV-404 ad-click -> POST-UNLOCK (real endpoint) charges CPA + marks AdClicks converted.
  * ADV-403 ad-click -> cart PURCHASE attribution (service-level) + model field.
  * ADV-406 standalone (no owner) -> platform books FULL charge (== CPA, not 30%);
            video (owner present) -> poster share + platform remainder.
  * Idempotency: a repeat conversion for the same ad_click_id does NOT double-charge.
"""
import asyncio
import time
from decimal import Decimal

from app.core.tables import T
from app.core.time import now_ts
from app.services import ad_attribution
from app.services.billing_shared import user_pk

RUN = str(int(time.time()))  # run-unique suffix so re-runs never collide
ACCT = "advb4acct"
OWNER = "advb4owner"        # advertiser account owner sub
CAMP = "advb4camp"
CRE = "advb4cr"
POSTER = "advb4_poster_" + RUN  # content owner (video pre-roll poster)
CPA = 500                    # bid_cpa_cents
def rid(base):
    return "advb4_%s_%s" % (base, RUN)

RESULTS = []
def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + ("  " + detail if detail else ""))

def bal():
    it = T.ad_accounts.get_item(Key={"pk": f"ACCT#{ACCT}", "sk": "META"}).get("Item") or {}
    return int(it.get("balance_cents", 0))

def click_row(cid):
    return T.ad_clicks.get_item(Key={"ad_click_id": cid}).get("Item") or {}

def platform_credit_for(content_id):
    """Sum platform_revenue_credit rows (T.ad_billing pk=PLATFORM#revenue) for content_id."""
    r = T.ad_billing.query(
        KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": "PLATFORM#revenue"},
        ScanIndexForward=False, Limit=200,
    )
    tot = 0
    for it in r.get("Items", []):
        if (it.get("meta") or {}).get("content_id") == content_id and it.get("entry_type") == "platform_revenue_credit":
            tot += int(it.get("amount_cents", 0))
    return tot

def creator_credit_for(sub, content_id):
    """Sum type=='credit' ledger rows for creator matching content_id."""
    from boto3.dynamodb.conditions import Key, Attr
    r = T.billing.query(
        KeyConditionExpression=Key("pk").eq(user_pk(sub)) & Key("sk").begins_with("LEDGER#"),
        FilterExpression=Attr("type").eq("credit"),
        ScanIndexForward=False, Limit=200,
    )
    tot = 0
    for it in r.get("Items", []):
        if (it.get("meta") or {}).get("content_id") == content_id:
            tot += int(it.get("amount_cents", 0))
    return tot

def seed_account():
    T.ad_accounts.put_item(Item={
        "pk": f"ACCT#{ACCT}", "sk": "META", "account_id": ACCT, "owner_sub": OWNER,
        "company_name": "ADVB4 Test Co", "status": "active", "balance_cents": 100000,
        "lifetime_spend_cents": 0, "created_at": now_ts(),
    })
    T.ad_campaigns.put_item(Item={
        "pk": f"ACCT#{ACCT}", "sk": f"CAMPAIGN#{CAMP}", "account_id": ACCT, "campaign_id": CAMP,
        "name": "ADVB4 Campaign", "status": "active", "objective": "conversions",
        "budget_cents": 100000, "spent_today_cents": 0, "lifetime_spent_cents": 0,
        "bid_cpm_cents": 500, "bid_cpc_cents": 50, "bid_cpa_cents": CPA, "created_at": now_ts(),
    })

def mint_click(cid, viewer, content_owner, content_id):
    now = now_ts()
    T.ad_clicks.put_item(Item={
        "ad_click_id": cid, "viewer_sub": viewer, "campaign_id": CAMP, "account_id": ACCT,
        "creative_id": CRE, "content_owner_sub": content_owner or "",
        "surface": "vod" if content_owner else "newsfeed",
        "slot_type": "preroll" if content_owner else "sponsored_post",
        "content_id": content_id, "status": "served",
        "effective_price_cents": 5000, "effective_cpm_cents": 5000,
        "bid_cpc_cents": 50, "bid_cpa_cents": CPA, "gross_bid_cpm_cents": 5000,
        "created_at": now, "expires_at": now + 604800,
    })


# ---------------------------------------------------------------------------
seed_account()
print("== seeded advertiser balance:", bal())

# ---- ADV-401 last-click service --------------------------------------------
V_LC = rid("lc_viewer")
mint_click(rid("lc_old"), V_LC, "", rid("lc"))
time.sleep(1)
mint_click(rid("lc_new"), V_LC, "", rid("lc"))
lc = ad_attribution.find_last_click(V_LC)
check("ADV-401 last-click returns most-recent unexpired click",
      lc and lc.get("ad_click_id") == rid("lc_new"), f"got={lc and lc.get('ad_click_id')}")
# expired click -> ignored
now = now_ts()
T.ad_clicks.put_item(Item={"ad_click_id": rid("lc_exp"), "viewer_sub": rid("lc_exp_v"),
    "campaign_id": CAMP, "account_id": ACCT, "creative_id": CRE, "content_owner_sub": "",
    "surface": "newsfeed", "slot_type": "sponsored_post", "content_id": "x", "status": "served",
    "bid_cpa_cents": CPA, "created_at": now - 700000, "expires_at": now - 90000})
check("ADV-401 expired click is not attributable",
      ad_attribution.find_last_click(rid("lc_exp_v")) is None)

# ---- ADV-402 ad-click -> SUBSCRIBE (real endpoint) -------------------------
from app.routers import subscription_server as ss
from starlette.requests import Request as StarletteRequest
def fake_req():
    return StarletteRequest({"type": "http", "method": "POST", "path": "/", "headers": [],
        "query_string": b"", "client": ("127.0.0.1", 0), "server": ("prod", 8000)})

PLAN_ID = rid("plan")
ss.save_plan({"plan_id": PLAN_ID, "creator_id": POSTER, "status": "active", "currency": "USD",
    "price_cents": 999, "interval": "month", "name": "ADVB4 Plan", "created_at": now_ts()})
V_SUB = rid("sub_viewer")
CLICK_SUB = rid("click_sub"); CID_SUB = rid("sub_ep")
mint_click(CLICK_SUB, V_SUB, "", CID_SUB)  # standalone
b0 = bal()
try:
    asyncio.run(ss.subscribe(PLAN_ID, ss.SubscribeIn(ad_click_id=CLICK_SUB),
                             fake_req(), x_user_id=V_SUB))
    sub_ok = True; sub_err = ""
except Exception as e:
    sub_ok = False; sub_err = repr(e)[:200]
b1 = bal()
row = click_row(CLICK_SUB)
check("ADV-402 subscribe endpoint ran", sub_ok, sub_err)
check("ADV-402 subscribe -> advertiser debited CPA(500)", (b0 - b1) == CPA, f"delta={b0-b1}")
check("ADV-402 subscribe -> AdClicks marked converted",
      row.get("status") == "converted" and row.get("conversion_type") == "subscription")
check("ADV-406 standalone subscribe -> platform books FULL charge (==500, not 150/30%)",
      platform_credit_for(CID_SUB) == CPA, f"platform={platform_credit_for(CID_SUB)}")
check("ADV-406 standalone -> NO creator credit row",
      creator_credit_for(POSTER, CID_SUB) == 0)

# ---- ADV-404 ad-click -> POST-UNLOCK (real endpoint) -----------------------
from app.routers import newsfeed as nf
POST_ID = rid("post")
nf.tbl.put_item(Item={"pk": nf.pk_post(POST_ID), "sk": nf.sk_post(), "post_id": POST_ID,
    "user_id": POSTER, "locked": True, "unlock_price_cents": 499, "unlock_count": 0,
    "kind": "text", "created_at": nf.now_iso()})
V_UNL = rid("unlock_viewer")
CLICK_UNL = rid("click_unlock"); CID_UNL = rid("unlock_ep")
mint_click(CLICK_UNL, V_UNL, POSTER, CID_UNL)  # video (owner=poster)
b0 = bal()
try:
    nf.unlock_post(nf.UnlockPostRequest(post_id=POST_ID, ad_click_id=CLICK_UNL),
                   user_id=V_UNL, _kyc=None)
    unl_ok = True; unl_err = ""
except Exception as e:
    unl_ok = False; unl_err = repr(e)[:200]
b1 = bal()
row = click_row(CLICK_UNL)
check("ADV-404 unlock endpoint ran", unl_ok, unl_err)
check("ADV-404 unlock -> advertiser debited CPA(500)", (b0 - b1) == CPA, f"delta={b0-b1}")
check("ADV-404 unlock -> AdClicks marked converted",
      row.get("status") == "converted" and row.get("conversion_type") == "unlock")
pc = platform_credit_for(CID_UNL); cc = creator_credit_for(POSTER, CID_UNL)
check("ADV-406 video unlock -> poster credited 70% share (350) type=credit", cc == 350, f"poster={cc}")
check("ADV-406 video unlock -> platform credited 30% remainder (150)", pc == 150, f"platform={pc}")

# ---- Idempotency: repeat conversion for same click does NOT double-charge --
b0 = bal()
r2 = ad_attribution.attribute_conversion(viewer_sub=V_SUB, conversion_type="subscription",
                                         conversion_value_cents=999, ad_click_id=CLICK_SUB)
b1 = bal()
check("IDEMP repeat conversion (same ad_click_id) is a no-op (already_converted)",
      r2.get("attributed") is False and r2.get("reason") == "already_converted", str(r2))
check("IDEMP repeat conversion does NOT debit again", (b0 - b1) == 0, f"delta={b0-b1}")

# ---- ADV-403 cart purchase attribution (service + model field) -------------
from app.models import CartPurchaseIn
check("ADV-403 CartPurchaseIn accepts ad_click_id",
      "ad_click_id" in CartPurchaseIn.model_fields)
V_CART = rid("cart_viewer")
CLICK_CART = rid("click_cart")
mint_click(CLICK_CART, V_CART, "", rid("cart_ep"))  # standalone
b0 = bal()
rc = ad_attribution.attribute_conversion(viewer_sub=V_CART, conversion_type="purchase",
                                         conversion_value_cents=2599, ad_click_id=CLICK_CART)
b1 = bal()
check("ADV-403 cart purchase attribution charges CPA + converts",
      rc.get("attributed") and (b0 - b1) == CPA and click_row(CLICK_CART).get("status") == "converted",
      f"delta={b0-b1} res={rc.get('reason')}")

# ---- summary ---------------------------------------------------------------
passed = sum(1 for _, ok, _ in RESULTS if ok)
print(f"\n==== ADV-B4 RESULT: {passed}/{len(RESULTS)} checks passed ====")
print("ALL_PASS" if passed == len(RESULTS) else "SOME_FAIL")
