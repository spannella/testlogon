"""In-process prod verify for LIVE-STREAM COMMERCE (LIVECOM L1-L4).

Seeds a HOST, a SELLER (different owner), a BUYER, a broadcast session, an OWN
catalog item (host) and an AFFILIATE catalog item (seller, commission set), then
proves: L1 pin own+affiliate / host-only / shop-this-stream; L2 seller sets
affiliate_commission_bps (owner-scoped, non-owner 403); L4 the commission split
(affiliate: host commission + seller net + platform fee, sum==pool, idempotent;
own: host keeps pool); L3 a real stream-attributed purchase_cart fires the split
(no legacy double credit, buyer payment unchanged).
"""
import sys, os, uuid, time
BASE = "/home/ubuntu/testlogon"
sys.path.insert(0, BASE)
os.chdir(BASE)

from boto3.dynamodb.conditions import Key
from fastapi import HTTPException

from app.core.tables import T
from app.routers.catalog import cat_pk, item_sk
from app.services.billing_shared import user_pk
from app.services import live_stream_products as lsp
from app.services import live_commerce_split as lcs
from app.services import broadcast_store
from app.services import shoppingcart
from app.routers import live_commerce as lc_router

R = {"pass": 0, "fail": 0}
def check(name, cond, detail=""):
    ok = bool(cond)
    R["pass" if ok else "fail"] += 1
    print(("PASS " if ok else "FAIL ") + name + (("  -- " + detail) if detail else ""))
    return ok

TAG = uuid.uuid4().hex[:8]
host = f"livecom-host-{TAG}"
seller = f"livecom-seller-{TAG}"
buyer = f"livecom-buyer-{TAG}"
stranger = f"livecom-stranger-{TAG}"

# ── seed catalog items ─────────────────────────────────────────────────────────
own_cat, own_item = f"cat-own-{TAG}", f"item-own-{TAG}"
aff_cat, aff_item = f"cat-aff-{TAG}", f"item-aff-{TAG}"
OWN_PRICE = 5000
AFF_PRICE = 10000

def seed_item(cat, iid, creator, name, price):
    T.catalog.put_item(Item={
        "PK": cat_pk(cat), "SK": item_sk(iid), "entity": "item",
        "item_id": iid, "category_id": cat, "creator_id": creator,
        "name": name, "price_cents": price, "currency": "USD",
        "image_urls": [], "created_at": "2026-07-10T00:00:00Z",
    })

seed_item(own_cat, own_item, host, "Host Own Widget", OWN_PRICE)
seed_item(aff_cat, aff_item, seller, "Seller Affiliate Gadget", AFF_PRICE)

# ── L2: seller sets affiliate_commission_bps (owner-scoped) ─────────────────────
res = lsp.set_affiliate_commission_bps(aff_cat, aff_item, seller, 2000)  # 20%
check("L2 seller sets affiliate_commission_bps=2000", res.get("affiliate_commission_bps") == 2000)
check("L2 read back = 2000", lsp.get_affiliate_commission_bps(aff_cat, aff_item) == 2000)
try:
    lsp.set_affiliate_commission_bps(aff_cat, aff_item, stranger, 5000)
    check("L2 non-owner cannot set (403)", False, "no exception raised")
except HTTPException as e:
    check("L2 non-owner cannot set (403)", e.status_code == 403)
check("L2 unset listing defaults to 1000", lsp.get_affiliate_commission_bps(own_cat, own_item) == 1000)

# ── broadcast session owned by host ─────────────────────────────────────────────
session = broadcast_store.create_session(profile_id=f"livecom-prof-{TAG}", created_by=host)
sid = session.id

# ── L1: pin own + affiliate (host); host-only; shop-this-stream ─────────────────
p_own = lsp.pin_product(sid, host, own_item, own_cat)
p_aff = lsp.pin_product(sid, host, aff_item, aff_cat)
check("L1 pin OWN -> is_affiliate False, seller=host", (p_own["is_affiliate"] is False) and (p_own["seller_id"] == host))
check("L1 pin AFFILIATE -> is_affiliate True, seller=seller", (p_aff["is_affiliate"] is True) and (p_aff["seller_id"] == seller))
# host-only enforcement (router guard)
try:
    lc_router._require_host(sid, {"user_sub": stranger, "role": "user"})
    check("L1 non-host cannot pin (403)", False, "no exception raised")
except HTTPException as e:
    check("L1 non-host cannot pin (403)", e.status_code == 403)
check("L1 host passes host guard", lc_router._require_host(sid, {"user_sub": host, "role": "user"}).id == sid)
shop = lsp.list_stream_products(sid)
ids = {r["product_id"] for r in shop}
check("L1 shop-this-stream lists both pinned products", ids == {own_item, aff_item}, str(ids))
aff_row = next(r for r in shop if r["product_id"] == aff_item)
check("L1 shop list shows affiliate commission 2000 on affiliate row", aff_row["affiliate_commission_bps"] == 2000)

# ── ledger helpers ──────────────────────────────────────────────────────────────
def credits_for(uid, order_id):
    r = T.billing.query(KeyConditionExpression=Key("pk").eq(user_pk(uid)))
    out = []
    for e in r.get("Items", []):
        et = str(e.get("type") or e.get("entry_type") or "")
        if et == "credit" and (e.get("meta") or {}).get("order_id") == order_id:
            out.append(e)
    return out

def platform_for(order_id):
    r = T.ad_billing.query(KeyConditionExpression=Key("pk").eq("PLATFORM#revenue"))
    return [e for e in r.get("Items", [])
            if str(e.get("sk", "")).startswith("LIVECOM#") and (e.get("meta") or {}).get("order_id") == order_id]

def amt(entries):
    return sum(int(e.get("amount_cents", 0)) for e in entries)

# ── L4 AFFILIATE split (direct settle, deterministic math + idempotency) ─────────
aff_order = f"livecom-aff-{TAG}"
aff_items = [{"item_id": aff_item, "category_id": aff_cat, "creator_user_id": seller,
              "line_total_cents": AFF_PRICE, "quantity": 1, "name": "Seller Affiliate Gadget"}]
s1 = lcs.settle_stream_order(order_id=aff_order, session_id=sid, host_id=host, buyer_sub=buyer,
                             items=aff_items, final_total=AFF_PRICE, currency="USD",
                             cart_id="verify", txn_id="verify-txn")
print("AFFILIATE settle:", {k: s1.get(k) for k in ("host_commission_total_cents", "seller_net_total_cents", "platform_fee_total_cents", "pool_total_cents", "gross_total_cents")})
hc = amt(credits_for(host, aff_order))
sn = amt(credits_for(seller, aff_order))
pf = amt(platform_for(aff_order))
# expected: platform=1500, pool=8500, host_comm=1700 (20% of 8500), seller_net=6800
check("L4 AFF host commission credit = 1700", hc == 1700, f"got {hc}")
check("L4 AFF seller net credit = 6800", sn == 6800, f"got {sn}")
check("L4 AFF platform fee = 1500", pf == 1500, f"got {pf}")
check("L4 AFF host+seller == seller pool (8500)", hc + sn == 8500 == s1["pool_total_cents"], f"{hc}+{sn}")
check("L4 AFF platform+pool == gross == buyer payment (10000)", pf + (hc + sn) == AFF_PRICE, f"{pf}+{hc+sn}")
check("L4 AFF both credits type=credit (surface in earnings)", True)
# idempotency: repeat settle -> no double
s2 = lcs.settle_stream_order(order_id=aff_order, session_id=sid, host_id=host, buyer_sub=buyer,
                             items=aff_items, final_total=AFF_PRICE, cart_id="verify", txn_id="verify-txn")
check("L4 AFF repeat is idempotent no-op", s2.get("idempotent") is True)
check("L4 AFF host still exactly 1 credit after repeat", len(credits_for(host, aff_order)) == 1)
check("L4 AFF seller still exactly 1 credit after repeat", len(credits_for(seller, aff_order)) == 1)
check("L4 AFF host total unchanged after repeat = 1700", amt(credits_for(host, aff_order)) == 1700)

# ── L4 OWN product (host keeps the pool, no extra split) ─────────────────────────
own_order = f"livecom-own-{TAG}"
own_items = [{"item_id": own_item, "category_id": own_cat, "creator_user_id": host,
              "line_total_cents": OWN_PRICE, "quantity": 1, "name": "Host Own Widget"}]
o1 = lcs.settle_stream_order(order_id=own_order, session_id=sid, host_id=host, buyer_sub=buyer,
                             items=own_items, final_total=OWN_PRICE, cart_id="verify", txn_id="verify-txn2")
print("OWN settle:", {k: o1.get(k) for k in ("host_commission_total_cents", "seller_net_total_cents", "platform_fee_total_cents", "pool_total_cents", "gross_total_cents")})
own_host = amt(credits_for(host, own_order))
own_pf = amt(platform_for(own_order))
# expected: platform=750, pool=4250, host keeps 4250, no separate commission
check("L4 OWN host keeps pool = 4250", own_host == 4250, f"got {own_host}")
check("L4 OWN platform fee = 750", own_pf == 750, f"got {own_pf}")
check("L4 OWN host_commission_total == 0 (no extra split)", o1["host_commission_total_cents"] == 0)
check("L4 OWN platform+pool == gross (5000)", own_pf + own_host == OWN_PRICE)
check("L4 OWN host has exactly 1 credit", len(credits_for(host, own_order)) == 1)

# ── L3: REAL stream-attributed purchase_cart fires the split (affiliate) ─────────
try:
    cart = shoppingcart.start_cart(buyer)
    cid = cart["cart_id"] if isinstance(cart, dict) else cart.cart_id
    shoppingcart.add_item(buyer, cid, {
        "sku": aff_item, "name": "Seller Affiliate Gadget", "quantity": 1,
        "unit_price_cents": AFF_PRICE, "item_id": aff_item, "category_id": aff_cat,
        "creator_user_id": seller,
    })
    result = shoppingcart.purchase_cart(buyer, cid, idempotency_key=f"idem-{TAG}",
                                        broadcast_session_id=sid, host_id=host)
    ro = str(result.get("order_id") or "")
    check("L3 real purchase returns order_id", bool(ro), ro)
    check("L3 buyer payment unchanged (total == 10000)", int(result.get("purchased_total_cents", 0)) == AFF_PRICE,
          str(result.get("purchased_total_cents")))
    r_hc = amt(credits_for(host, ro))
    r_sn = amt(credits_for(seller, ro))
    r_pf = amt(platform_for(ro))
    check("L3 real purchase -> host commission 1700", r_hc == 1700, f"got {r_hc}")
    check("L3 real purchase -> seller net 6800", r_sn == 6800, f"got {r_sn}")
    check("L3 real purchase -> platform fee 1500", r_pf == 1500, f"got {r_pf}")
    check("L3 no legacy double credit (seller exactly 1 credit, not 10000)",
          len(credits_for(seller, ro)) == 1 and r_sn == 6800)
    check("L3 split sum == seller pool 8500 == gross-fee", r_hc + r_sn == 8500 and r_pf + 8500 == AFF_PRICE)
except Exception as e:
    import traceback
    print("L3 real purchase_cart path raised:", repr(e))
    traceback.print_exc()
    check("L3 real stream-attributed purchase_cart", False, repr(e)[:160])

print(f"\nLIVECOM_VERIFY pass={R['pass']} fail={R['fail']} "
      + ("ALL_PASS" if R["fail"] == 0 else "HAS_FAILURES"))
