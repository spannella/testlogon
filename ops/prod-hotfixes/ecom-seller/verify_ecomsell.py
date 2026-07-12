import sys, os, time, json
ROOT = "/home/ubuntu/testlogon"; sys.path.insert(0, ROOT); os.chdir(ROOT)
from boto3.dynamodb.conditions import Key
from app.core.tables import T
from app.core.settings import S
import app.services.shoppingcart as scart
import app.services.seller_ship_groups as ssg
import app.services.order_lifecycle as ol
from app.services.profile import save_profile

R = {"pass": 0, "fail": 0}
def chk(name, cond, extra=""):
    ok = bool(cond)
    R["pass" if ok else "fail"] += 1
    print(("PASS" if ok else "FAIL"), name, ("" if ok else "<<") , extra if not ok else "")

ts = int(time.time())
buyer   = f"vbuyer_{ts}@testlogon.example"
sellerA = f"vsellerA_{ts}@testlogon.example"
sellerB = f"vsellerB_{ts}@testlogon.example"

catA, itemA = f"catA_{ts}", f"itemA_{ts}"
catB, itemB = f"catB_{ts}", f"itemB_{ts}"
T.catalog.put_item(Item={"PK": f"CAT#{catA}", "SK": f"ITEM#{itemA}", "entity": "item",
    "name": "Handmade Blue Mug", "currency": "USD", "price_cents": 2500, "creator_id": sellerA, "stock_count": 10})
T.catalog.put_item(Item={"PK": f"CAT#{catB}", "SK": f"ITEM#{itemB}", "entity": "item",
    "name": "Vintage Vinyl Record", "currency": "USD", "price_cents": 4200, "creator_id": sellerB, "stock_count": 10})

# buyer profile w/ mailing address (echoed into purchase.buyer.mailing_address)
addr = {"line1": "123 Market St", "line2": "Apt 5", "city": "Columbus", "state": "OH",
        "postal_code": "43215", "country": "US", "name": "Val Buyer"}
try:
    save_profile(buyer, {"display_name": "Val Buyer", "displayed_email": buyer, "mailing_address": addr}, [])
    print("profile saved")
except Exception as e:
    print("save_profile err (fallback to addresses):", repr(e))
    try:
        from app.services.addresses import create_address
        create_address(buyer, {**addr, "is_primary": True})
    except Exception as e2:
        print("create_address err:", repr(e2))

# ============ TEST 1: single-seller order ============
print("\n==== TEST 1 single-seller ====")
cart = scart.start_cart(buyer)["cart_id"]
scart.add_catalog_item(buyer, cart, category_id=catA, item_id=itemA, quantity=2)
res = scart.purchase_cart(buyer, cart, idempotency_key=f"idem1_{ts}")
order1 = res["order_id"]
print("order1", order1, "buyer.mailing_address in purchase:", bool((res.get("buyer") or {}).get("mailing_address")))

g1 = ssg.list_by_order(order1)
chk("T1 exactly 1 seller ship-group", len(g1) == 1, f"got {len(g1)}")
grp = g1[0] if g1 else {}
chk("T1 group seller == sellerA", grp.get("seller_id") == sellerA, grp.get("seller_id"))
li = (grp.get("line_items") or [{}])[0]
chk("T1 REAL line name (not internal_api_package)", li.get("name") == "Handmade Blue Mug", li.get("name"))
chk("T1 qty=2", int(li.get("quantity", 0)) == 2, li.get("quantity"))
chk("T1 unit_price=2500", int(li.get("unit_price_cents", 0)) == 2500, li.get("unit_price_cents"))
chk("T1 subtotal=5000", int(grp.get("subtotal_cents", 0)) == 5000, grp.get("subtotal_cents"))
st = grp.get("ship_to") or {}
chk("T1 buyer ship_to city", st.get("city") == "Columbus", st)
chk("T1 buyer_id present", grp.get("buyer_id") == buyer, grp.get("buyer_id"))
# no payment internals in the group row
leaked = [k for k in grp.keys() if k in ("purchase_txn_id", "payment", "payment_method", "card", "pm_id", "ledger_entry_id")]
chk("T1 NO buyer payment internals on group row", not leaked, leaked)
chk("T1 group born 'approved'", grp.get("status") == "approved", grp.get("status"))

# G4: the ORDER line item name is the real product name (buyer order detail)
lc = ol.get_order_lifecycle(order1)
oname = lc.line_items[0].name if lc.line_items else None
chk("G4 order line name == real product name", oname == "Handmade Blue Mug", oname)

# G1: seller got a "you sold it" in-app alert
try:
    al = T.alerts.query(KeyConditionExpression=Key("user_sub").eq(sellerA)).get("Items", [])
    sold = [a for a in al if a.get("event") == "shop_item_sold"]
    chk("G1 sellerA got shop_item_sold alert", len(sold) >= 1, f"{len(al)} alerts")
    if sold:
        a0 = sold[0]
        chk("G1 alert deep-links to sale", str(a0.get("action_url", "")).find(grp.get("ship_group_id","")) >= 0 or "seller/orders" in str(a0.get("action_url","")), a0.get("action_url"))
        print("   alert title:", a0.get("title"), "| action_url:", a0.get("action_url"))
except Exception as e:
    chk("G1 sellerA got shop_item_sold alert", False, repr(e))

# ============ seller-scoped endpoint via TestClient (real HTTP stack) ============
print("\n==== G3 seller-scoped endpoint (non-admin) ====")
from fastapi.testclient import TestClient
from app.main import app
import app.services.sessions as sess
CUR = {"sub": sellerA, "role": "user"}
app.dependency_overrides[sess.require_ui_session] = lambda: {"user_sub": CUR["sub"], "role": CUR["role"]}
c = TestClient(app)
sg1 = grp.get("ship_group_id")

CUR["sub"] = sellerA
r = c.get("/ui/seller/sales")
chk("G3 GET /ui/seller/sales 200 (non-admin)", r.status_code == 200, r.status_code)
sales = r.json().get("sales", []) if r.status_code == 200 else []
ids = [s["ship_group_id"] for s in sales]
chk("G3 sellerA sees own group", sg1 in ids, ids)
if sales:
    s0 = next((s for s in sales if s["ship_group_id"] == sg1), sales[0])
    chk("G3 list carries buyer ship_to", (s0.get("ship_to") or {}).get("city") == "Columbus", s0.get("ship_to"))
    chk("G3 list carries real line name", (s0.get("line_items") or [{}])[0].get("name") == "Handmade Blue Mug", s0.get("line_items"))
    body_keys = set(json.dumps(s0).lower().split('"'))
    chk("G3 no payment/card/txn field in payload", not any(k in json.dumps(s0).lower() for k in ("purchase_txn", "payment_method", '"card"', "pm_id")), s0.keys())

# a DIFFERENT seller must NOT see sellerA's group
CUR["sub"] = sellerB
rb = c.get("/ui/seller/sales")
idsB = [s["ship_group_id"] for s in rb.json().get("sales", [])] if rb.status_code == 200 else []
chk("G3 sellerB does NOT see sellerA's group", sg1 not in idsB, idsB)

# sellerA detail 200; sellerB detail 404 (isolation)
CUR["sub"] = sellerA
rd = c.get(f"/ui/seller/sales/{sg1}")
chk("G3 sellerA GET own detail 200", rd.status_code == 200, rd.status_code)
CUR["sub"] = sellerB
rd2 = c.get(f"/ui/seller/sales/{sg1}")
chk("G3 sellerB GET sellerA detail 404", rd2.status_code == 404, rd2.status_code)

# sellerB cannot transition sellerA's group
rt = c.post(f"/ui/seller/sales/{sg1}/transition", json={"target_status": "allocated"})
chk("G3 sellerB transition sellerA group 404", rt.status_code == 404, rt.status_code)

# sellerA fulfils: approved -> allocated -> picking -> packed -> shipped
print("\n==== fulfilment lifecycle (seller-scoped) ====")
CUR["sub"] = sellerA
ok_chain = True; laststatus = None
for tgt in ["allocated", "picking", "packed", "shipped"]:
    tr = c.post(f"/ui/seller/sales/{sg1}/transition", json={"target_status": tgt, "tracking_number": ("1Z999" if tgt == "shipped" else None), "carrier": ("UPS" if tgt == "shipped" else None)})
    laststatus = tr.json().get("status") if tr.status_code == 200 else f"HTTP{tr.status_code}:{tr.text[:120]}"
    if tr.status_code != 200 or tr.json().get("status") != tgt:
        ok_chain = False
    print("   ->", tgt, tr.status_code, laststatus)
chk("fulfil approved->allocated->picking->packed->shipped", ok_chain and laststatus == "shipped", laststatus)
# illegal transition rejected (shipped->allocated)
ri = c.post(f"/ui/seller/sales/{sg1}/transition", json={"target_status": "allocated"})
chk("illegal transition 409", ri.status_code == 409, ri.status_code)

# ============ TEST 2: multi-seller cart splits per seller ============
print("\n==== TEST 2 multi-seller split ====")
cart2 = scart.start_cart(buyer)["cart_id"]
scart.add_catalog_item(buyer, cart2, category_id=catA, item_id=itemA, quantity=1)
scart.add_catalog_item(buyer, cart2, category_id=catB, item_id=itemB, quantity=1)
res2 = scart.purchase_cart(buyer, cart2, idempotency_key=f"idem2_{ts}")
order2 = res2["order_id"]
g2 = ssg.list_by_order(order2)
chk("T2 two seller ship-groups", len(g2) == 2, len(g2))
bysel = {gg["seller_id"]: gg for gg in g2}
chk("T2 sellerA group only Mug", (bysel.get(sellerA, {}).get("line_items") or [{}])[0].get("name") == "Handmade Blue Mug", bysel.get(sellerA, {}).get("line_items"))
chk("T2 sellerB group only Vinyl", (bysel.get(sellerB, {}).get("line_items") or [{}])[0].get("name") == "Vintage Vinyl Record", bysel.get(sellerB, {}).get("line_items"))
chk("T2 sellerA group has NO vinyl", all(li.get("name") != "Vintage Vinyl Record" for li in bysel.get(sellerA, {}).get("line_items", [])), True)
chk("T2 sellerB group has NO mug", all(li.get("name") != "Handmade Blue Mug" for li in bysel.get(sellerB, {}).get("line_items", [])), True)

# each seller only sees THEIR portion via the scoped endpoint
CUR["sub"] = sellerA
allA = [li.get("name") for s in c.get("/ui/seller/sales").json().get("sales", []) for li in s.get("line_items", [])]
chk("T2 sellerA scoped list never shows Vinyl", "Vintage Vinyl Record" not in allA, allA)
CUR["sub"] = sellerB
allB = [li.get("name") for s in c.get("/ui/seller/sales").json().get("sales", []) for li in s.get("line_items", [])]
chk("T2 sellerB scoped list never shows Mug", "Handmade Blue Mug" not in allB, allB)

# idempotent re-approval: purchasing already-purchased cart doesn't duplicate groups
before = len(ssg.list_by_order(order1))
scart.purchase_cart(buyer, cart, idempotency_key=f"idem1_{ts}")
after = len(ssg.list_by_order(order1))
chk("idempotent: no duplicate groups on replay", before == after == 1, f"{before}->{after}")

print("\n==== SUMMARY", f"PASS={R['pass']} FAIL={R['fail']}", "OVERALL", ("ALL_PASS" if R["fail"] == 0 else "HAS_FAILURES"), "====")
print("ARTIFACTS", json.dumps({"buyer": buyer, "sellerA": sellerA, "sellerB": sellerB, "order1": order1, "order2": order2, "sg1": sg1}))
