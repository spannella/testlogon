import os, sys, time, json
os.environ.setdefault("DEV_MODE", "1")
ROOT = "/home/ubuntu/testlogon"; sys.path.insert(0, ROOT); os.chdir(ROOT)
import app.services.shoppingcart as scart
import app.services.seller_ship_groups as ssg

BUYER = os.environ.get("DEMO_BUYER", "ben.buyer.1783660379@testlogon.example")
CAT = os.environ.get("DEMO_CAT", "mia_store_1783660379")
ITEM = os.environ.get("DEMO_ITEM", "mug_1783660379")
ts = int(time.time())

cart = scart.start_cart(BUYER)["cart_id"]
scart.add_catalog_item(BUYER, cart, category_id=CAT, item_id=ITEM, quantity=1)
res = scart.purchase_cart(BUYER, cart, idempotency_key=f"demo_{ts}")
order = res["order_id"]
groups = ssg.list_by_order(order)
g = groups[0] if groups else {}
sg = g.get("ship_group_id")
li = (g.get("line_items") or [{}])[0]
st = g.get("ship_to") or {}
print("ORDER", order)
print("SHIP_GROUP", sg)
print("ACTION_URL", f"/seller/orders?sale={sg}")
print("LINE_ITEM", li.get("name"), "qty", li.get("quantity"), "subtotal_cents", g.get("subtotal_cents"))
print("SHIP_TO", json.dumps({k: st.get(k) for k in ("name", "line1", "line2", "city", "state", "postal_code")}))
print("STATUS", g.get("status"))
print("PURCHASE_DONE " + json.dumps({"sg": sg, "order": order}))
