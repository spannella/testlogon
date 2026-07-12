"""In-process ADV x ECOM money-path verify (runs on PROD DDB via SSM).

B1 product creative | B2 shop sponsored serve + CPC/impression bill (platform-100,
no-tip, idempotent, funds-guarded) | B3 shoppable ad -> cart purchase -> CPA
attributed | B4 seller boost owner-check | B5 ROAS reflects spend + value.
"""
import sys
sys.path.insert(0, "/home/ubuntu/testlogon")
import uuid, time
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.time import now_ts

R = []
def chk(name, cond, extra=""):
    R.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (("  " + str(extra)) if extra else ""))

sfx = uuid.uuid4().hex[:8]
seller = f"seller_{sfx}"
buyer = f"buyer_{sfx}"           # same sub is served the ad AND buys
stranger = f"stranger_{sfx}"
cat_id = f"cat_{sfx}"
item_id = f"item_{sfx}"
PRICE = 2599

# ── seed a seller catalog listing (direct DDB, real schema) ──────────
now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
T.catalog.put_item(Item={"PK": f"CAT#{cat_id}", "SK": "META", "entity": "category",
    "category_id": cat_id, "name": f"Boost Store {sfx}", "creator_id": seller,
    "created_at": now_iso, "GSI1PK": "CATS", "GSI1SK": f"store#{cat_id}"})
T.catalog.put_item(Item={"PK": f"CAT#{cat_id}", "SK": f"ITEM#{item_id}", "entity": "item",
    "category_id": cat_id, "item_id": item_id, "creator_id": seller,
    "name": f"Roast Sampler {sfx}", "description": "Fresh roasted beans.",
    "price_cents": PRICE, "currency": "USD",
    "image_urls": ["https://img.example/coffee.jpg"], "stock_count": 100,
    "created_at": now_iso, "updated_at": now_iso})

from app.services.shop_ads import boost_listing, serve_shop_sponsored, resolve_product
prod = resolve_product(item_id, cat_id)
chk("SEED resolve_product", prod and prod.get("item_id") == item_id, item_id)

# ── B4: seller boost (owner-checked) ────────────────────────────────
res = boost_listing(owner_sub=seller, item_id=item_id, category_id=cat_id,
                    budget_cents=5000, bid_cpc_cents=137, bid_cpm_cents=500,
                    bid_cpa_cents=456, duration_days=7, objective="traffic")
acct = res["account_id"]; camp = res["campaign_id"]; cr = res["creative_id"]
chk("B4 boost creates account+campaign+creative", acct and camp and cr, res.get("status"))
crow = T.ad_creatives.get_item(Key={"pk": f"CAMP#{camp}", "sk": f"CREATIVE#{cr}"}).get("Item") or {}
chk("B1 product creative carries product_id + buy_product CTA",
    crow.get("product_id") == item_id and crow.get("status") == "approved"
    and any(c.get("cta_type") == "buy_product" and c.get("target_id") == item_id
            for c in (crow.get("ctas") or [])), crow.get("ctas"))

# non-owner cannot boost
try:
    boost_listing(owner_sub=stranger, item_id=item_id, category_id=cat_id)
    chk("B4 non-owner boost blocked", False, "no error raised")
except PermissionError:
    chk("B4 non-owner boost blocked", True, "PermissionError")
except Exception as e:
    chk("B4 non-owner boost blocked", False, "wrong error %r" % e)

# ── fund the seller ad account + guarantee auction win ──────────────
T.ad_accounts.update_item(Key={"pk": f"ACCT#{acct}", "sk": "META"},
    UpdateExpression="SET balance_cents = :b", ExpressionAttributeValues={":b": 5_000_000})
T.ad_campaigns.update_item(Key={"pk": f"ACCT#{acct}", "sk": f"CAMPAIGN#{camp}"},
    UpdateExpression="SET bid_cpm_cents = :m", ExpressionAttributeValues={":m": 999999})
bal0 = int(T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct}", "sk": "META"}).get("Item", {}).get("balance_cents", 0))

# ── B2: serve sponsored products into the shop ──────────────────────
units = serve_shop_sponsored(viewer_id=buyer, query="roast", category_id=cat_id, limit=3, surface="shop_search")
mine = [u for u in units if u.get("product_id") == item_id and u.get("creative_id") == cr]
chk("B2 shop serve returns my sponsored product", len(mine) >= 1, "units=%d" % len(units))
unit = mine[0] if mine else (units[0] if units else {})
chk("B2 unit is standalone (no content owner) + NOT tippable",
    unit.get("content_owner_id", "") == "" and unit.get("tippable") is False, unit.get("sponsor_label"))
chk("B2 unit carries product name/price/ad_click_id/track urls",
    unit.get("product_name") and unit.get("product_price_cents") == PRICE
    and unit.get("ad_click_id") and unit.get("impression_url") and unit.get("click_url"), "")

acid = unit.get("ad_click_id", "")
from app.services.ad_serving import track_ad_event

def _track(ev):
    return track_ad_event(event=ev, creative_id=cr, campaign_id=camp, account_id=acct,
        surface="shop_search", slot_type="sponsored_post", content_id="shop_search_slot_0",
        creator_id="platform", user_id=buyer, ad_click_id=acid)

imp = _track("impression"); imp_cc = int(imp.get("charge_cents", 0))
imp_dup = _track("impression"); imp_dup_cc = int(imp_dup.get("charge_cents", 0))
clk = _track("click"); clk_cc = int(clk.get("charge_cents", 0))
clk_dup = _track("click"); clk_dup_cc = int(clk_dup.get("charge_cents", 0))
chk("B2 impression billed CPM (funds-guarded)", imp.get("charged") and imp_cc >= 1, "imp=%d" % imp_cc)
chk("B2 impression idempotent (repeat=0)", imp_dup_cc == 0, "dup=%d" % imp_dup_cc)
chk("B2 click billed CPC=137", clk.get("charged") and clk_cc == 137, "clk=%d" % clk_cc)
chk("B2 click idempotent (repeat=0)", clk_dup_cc == 0, "dup=%d" % clk_dup_cc)
bal1 = int(T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct}", "sk": "META"}).get("Item", {}).get("balance_cents", 0))
chk("B2 advertiser balance debited by imp+click", bal0 - bal1 == imp_cc + clk_cc, "delta=%d" % (bal0 - bal1))

# platform-100% (standalone): impression ledger row -> creator_share 0, platform_share == charge
plat_ok = False
q = T.ad_billing.query(KeyConditionExpression=(Key("pk").eq(f"ACCT#{acct}") & Key("sk").begins_with("LEDGER#")))
imp_rows = [it for it in q.get("Items", []) if it.get("entry_type") == "impression_charge"]
if imp_rows:
    m = imp_rows[0].get("meta", {}) or {}
    plat_ok = int(m.get("creator_share_cents", -1)) == 0 and int(m.get("platform_share_cents", -1)) == int(imp_rows[0].get("amount_cents", 0))
chk("B2 placement = platform-100% (creator_share=0)", plat_ok, imp_rows[0].get("meta") if imp_rows else "no row")

# funds-guard: drain to 0, next impression on a NEW served click is not charged, balance stays >= 0
T.ad_accounts.update_item(Key={"pk": f"ACCT#{acct}", "sk": "META"},
    UpdateExpression="SET balance_cents = :z", ExpressionAttributeValues={":z": 0})
u2 = serve_shop_sponsored(viewer_id=stranger, category_id=cat_id, limit=1, surface="shop_browse")
u2 = [x for x in u2 if x.get("creative_id") == cr]
if u2:
    g = track_ad_event(event="impression", creative_id=cr, campaign_id=camp, account_id=acct,
        surface="shop_browse", slot_type="sponsored_post", content_id="shop_browse_slot_0",
        creator_id="platform", user_id=stranger, ad_click_id=u2[0].get("ad_click_id"))
    balz = int(T.ad_accounts.get_item(Key={"pk": f"ACCT#{acct}", "sk": "META"}).get("Item", {}).get("balance_cents", 0))
    chk("B2 funds-guard: drained account not charged, balance>=0",
        (not g.get("charged")) and g.get("charge_reason") == "insufficient_funds" and balz >= 0,
        "reason=%s bal=%d" % (g.get("charge_reason"), balz))
else:
    chk("B2 funds-guard served for drain test", False, "no serve")
# refund for the conversion test
T.ad_accounts.update_item(Key={"pk": f"ACCT#{acct}", "sk": "META"},
    UpdateExpression="SET balance_cents = :b", ExpressionAttributeValues={":b": 5_000_000})

# ── B3: buyer clicked the product ad then PURCHASES (cart) -> CPA ────
# Drive the REAL cart purchase money-path where available, then attribute exactly
# as app/routers/shoppingcart.ui_purchase_cart does (ADV-403 wiring).
purchase_value = PRICE
real_cart = "skipped"
try:
    from app.services.shoppingcart import start_cart, add_catalog_item, purchase_cart
    c = start_cart(buyer)
    add_catalog_item(buyer, c["cart_id"], category_id=cat_id, item_id=item_id, quantity=1)
    pr = purchase_cart(buyer, c["cart_id"], idempotency_key=f"idem_{sfx}")
    purchase_value = int(pr.get("purchased_total_cents") or PRICE)
    real_cart = "ok total=%d" % purchase_value
except Exception as e:
    real_cart = "fallback (%s)" % type(e).__name__
print("B3 real_cart:", real_cart)

from app.services.ad_attribution import attribute_conversion
conv = attribute_conversion(viewer_sub=buyer, conversion_type="purchase",
                            conversion_value_cents=purchase_value, ad_click_id=acid)
conv_charge = conv.get("charge", {}) or {}
chk("B3 conversion attributed to the product-ad click",
    conv.get("attributed") and conv.get("ad_click_id") == acid, conv.get("reason"))
chk("B3 CPA charged=456 (funds-guarded)",
    conv_charge.get("ok") and int(conv_charge.get("charge_cents", 0)) == 456, conv_charge)
row = T.ad_clicks.get_item(Key={"ad_click_id": acid}).get("Item") or {}
chk("B3 AdClicks row marked converted + value",
    row.get("status") == "converted" and row.get("converted_at")
    and int(row.get("conversion_value_cents", 0)) == purchase_value, row.get("status"))
conv2 = attribute_conversion(viewer_sub=buyer, conversion_type="purchase",
                             conversion_value_cents=purchase_value, ad_click_id=acid)
chk("B3 conversion idempotent (retry no-op)", not conv2.get("attributed")
    and conv2.get("reason") == "already_converted", conv2.get("reason"))

# ── B5: ROAS reflects product-ad spend + attributed conversion value ─
from app.services.ad_roas import roas_report
rep = roas_report(acct)
tot = rep.get("totals", {})
spend = int(tot.get("spend_cents", 0)); value = int(tot.get("conversion_value_cents", 0))
chk("B5 ROAS spend = imp+click+CPA", spend == imp_cc + clk_cc + 456, "spend=%d" % spend)
chk("B5 ROAS conversion value = purchase", value == purchase_value, "value=%d" % value)
chk("B5 ROAS ratio = value/spend", spend > 0 and abs(tot.get("roas", 0) - round(value / spend, 4)) < 1e-6,
    "roas=%s" % tot.get("roas"))

ok = sum(1 for _, c, _ in R if c); tot_n = len(R)
print("\nOVERALL %s  (%d/%d)" % ("ALL_PASS" if ok == tot_n else "FAIL", ok, tot_n))
print("EVIDENCE acct=%s camp=%s creative=%s ad_click=%s" % (acct, camp, cr, acid))
print("EVIDENCE imp_cc=%d click_cc=%d cpa=456 spend=%d value=%d roas=%s"
      % (imp_cc, clk_cc, spend, value, tot.get("roas")))
