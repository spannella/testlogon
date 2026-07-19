import json, os, sys, time
sys.path.insert(0, os.path.expanduser("~/dev/testlogon")); os.chdir(os.path.expanduser("~/dev/testlogon"))
import requests, e2e_admin_session_setup as S
API="http://localhost:8000"; TS=int(time.time())
def sess(sub, role="user"):
    S.ensure_auth_user(sub, sub.split("@")[0], role); S.ensure_profile(sub, sub.split("@")[0])
    return S.create_session(sub, role=role)
def client(se):
    s=requests.Session()
    for c in se["cookies"]: s.cookies.set(c["name"], c["value"])
    s.headers.update({"x-csrf-token": se["csrf_token"]}); return s
SELLER=f"e2e_seller_{TS}@test.local"; SELLER2=f"e2e_seller2_{TS}@test.local"
seller=client(sess(SELLER)); seller2=client(sess(SELLER2))
buyer=client(sess("e2e_alice@test.local")); buyer2=client(sess("e2e_bob@test.local"))

def mk_item(sc, cat, item, name):
    sc.post(f"{API}/ui/catalog/categories", json={"category_id":cat,"name":name,"description":"x"})
    sc.post(f"{API}/ui/catalog/categories/{cat}/items", json={"item_id":item,"name":name,"description":"x","price_cents":1500,"currency":"USD","stock_count":50})

# multi-seller order: 2 sellers
mk_item(seller,  f"c1_{TS}", f"i1_{TS}", "Widget A")
mk_item(seller2, f"c2_{TS}", f"i2_{TS}", "Widget B")
cart=buyer.post(f"{API}/ui/shoppingcart/carts", json={}).json(); cid=cart["cart_id"]
buyer.post(f"{API}/ui/shoppingcart/carts/{cid}/items/catalog", json={"category_id":f"c1_{TS}","item_id":f"i1_{TS}","quantity":1})
buyer.post(f"{API}/ui/shoppingcart/carts/{cid}/items/catalog", json={"category_id":f"c2_{TS}","item_id":f"i2_{TS}","quantity":1})
pur=buyer.post(f"{API}/ui/shoppingcart/carts/{cid}/purchase", headers={"X-Idempotency-Key":f"idem_{TS}"}, json={}).json()
oid=pur["order_id"]; txn=pur.get("purchase_txn_id")
print("order", oid, "sellers", 2)

# seller1 ships, seller2 does NOT (partial). Each ships own group.
def ship(sc, tn):
    sales=sc.get(f"{API}/ui/seller/sales").json()["sales"]
    sg=[s for s in sales if s.get("order_id")==oid][0]["ship_group_id"]
    for st,ex in [("allocated",{}),("picking",{}),("packed",{}),("shipped",{"tracking_number":tn,"carrier":"fedex"})]:
        b={"target_status":st}; b.update(ex); sc.post(f"{API}/ui/seller/sales/{sg}/transition", json=b)
    return sg
sg1=ship(seller, f"FDX1_{TS}")

def summ(label, r):
    j=r.json(); 
    print(f"\n## {label} [HTTP {r.status_code}]")
    print(" fulfillment_status:", j.get("fulfillment_status"))
    sh=j.get("shipments") or j.get("ship_groups") or []
    print(" tracking_numbers:", j.get("tracking_numbers"))
    for s in sh:
        print("   -", s.get("carrier"), s.get("tracking_number"), s.get("status"), "| sg:", s.get("ship_group_id"))
    return j

# DETAIL
summ("DETAIL /ui/orders/{id}/lifecycle (partial: 1 of 2 shipped)", buyer.get(f"{API}/ui/orders/{oid}/lifecycle", params={"include":"ship_groups"}))
# LIST
lst=buyer.get(f"{API}/ui/orders", params={"limit":5}).json()
row=[o for o in lst["orders"] if o["order_id"]==oid][0]
print("\n## LIST row for order")
print(" fulfillment_status:", row.get("fulfillment_status"))
for s in row.get("shipments",[]): print("   -", s.get("carrier"), s.get("tracking_number"), s.get("status"))
# ECM-007
summ("ECM-007 /ui/shoppingcart/orders/{id}", buyer.get(f"{API}/ui/shoppingcart/orders/{oid}"))

# now seller2 ships too -> full shipped -> both shipments present
sg2=ship(seller2, f"UPS2_{TS}")
summ("DETAIL after BOTH shipped (multi-seller aggregate)", buyer.get(f"{API}/ui/orders/{oid}/lifecycle"))

# SCOPE: buyer2 must see NOTHING on this order's detail/list
r=buyer2.get(f"{API}/ui/orders/{oid}/lifecycle")
print("\n## SCOPE buyer2 /lifecycle:", r.status_code, "(expect 404)")
r=buyer2.get(f"{API}/ui/shoppingcart/orders/{oid}")
j=r.json(); print("## SCOPE buyer2 ECM-007:", r.status_code, "ship_groups:", j.get("ship_groups"), "(expect [])")

# DELIVERED -> completed reconcile
buyer.post(f"{API}/ui/orders/{oid}/confirm-delivery", json={})
d=buyer.get(f"{API}/ui/orders/{oid}/lifecycle").json()
print("\n## after confirm-delivery: lifecycle_status:", d.get("lifecycle_status"), "fulfillment_status:", d.get("fulfillment_status"))
print("ARTIFACTS", json.dumps({"order":oid,"sg1":sg1,"sg2":sg2}))
