"""ECOMX E4 LIVE verify — real HTTP against the running uvicorn (:8000) + live
DDB-Local. NOT an in-process TestClient. Proves the buyer-flow backend:

 B3/A7  checkout WITH a shipping address adds shipping + tax to the charged total;
        the seller is credited from MERCHANDISE only (not shipping/tax).
 B3     a digital/self-purchase (no seller) collects NO shipping/tax.
 B2     a fresh PHYSICAL order reads PENDING (not COMPLETED) + order_status present.
 B2     an instant (no ship-group) order completes immediately (COMPLETED).
 B6     buyer confirm-received drives the physical order/txn -> COMPLETED.
 B3     ship-to on the seller ship group == the selected checkout address.

Auto-cleans all synthetic rows (0 residue).
"""
import base64, hashlib, os, time, json, sys
import urllib.request, urllib.error
from http.cookiejar import CookieJar

sys.path.insert(0, os.path.expanduser("/home/ubuntu/testlogon"))
os.environ.setdefault("DEV_MODE", "1")
from app.core.tables import T
from app.services.billing_shared import user_pk

BASE = "http://127.0.0.1:8000"
STAMP = int(time.time())
PW = "E4-Verify-Pw-%d" % STAMP
results = []
CL = {"users": [], "billing_pks": set(), "catalog": [], "carts": [], "orders": [],
      "addresses": [], "ship_groups": [], "txns": []}

def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, ("" if ok else "  <<< " + str(detail)))

def http(method, path, cj, body=None, extra=None):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"}
    if extra: hdrs.update(extra)
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=hdrs)
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try:
        r = op.open(req, timeout=30)
        return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try: payload = json.loads(e.read().decode() or "{}")
        except Exception: payload = {}
        return e.status, payload

def csrf_of(cj):
    for c in cj:
        if c.name == "ui_csrf":
            return c.value
    return ""

def mkuser(sub):
    salt = os.urandom(16); iters = 200000
    h = hashlib.pbkdf2_hmac("sha256", PW.encode(), salt, iters)
    T.users.put_item(Item={"user_sub": sub, "email": sub, "display_name": sub.split("@")[0],
        "password_hash": {"hash_b64": base64.b64encode(h).decode(),
        "salt_b64": base64.b64encode(salt).decode(), "iterations": iters},
        "role": "user", "created_at": STAMP, "_ecomx_e4_synth": True})
    CL["users"].append(sub); CL["billing_pks"].add(user_pk(sub))

def seed_pm(sub, pm_id="pm_card_visa"):
    T.billing.put_item(Item={"pk": user_pk(sub), "sk": "PM#%s" % pm_id,
        "payment_method_id": pm_id, "brand": "visa", "last4": "4242", "_ecomx_e4_synth": True})
    b = T.billing.get_item(Key={"pk": user_pk(sub), "sk": "BILLING"}).get("Item") or {"pk": user_pk(sub), "sk": "BILLING"}
    b["default_payment_method_id"] = pm_id; b["_ecomx_e4_synth"] = True
    T.billing.put_item(Item=b); CL["billing_pks"].add(user_pk(sub))

def seed_catalog(cat, iid, name, price, seller, stock=None):
    item = {"PK": "CAT#%s" % cat, "SK": "ITEM#%s" % iid, "entity": "item",
            "category_id": cat, "item_id": iid, "name": name, "price_cents": price,
            "currency": "USD", "creator_id": seller, "_ecomx_e4_synth": True}
    if stock is not None: item["stock_count"] = stock
    T.catalog.put_item(Item=item); CL["catalog"].append((cat, iid))

def login(sub):
    cj = CookieJar()
    st, r = http("POST", "/ui/session/start", cj, {"challenge_context": {"username": sub, "password": PW}})
    return cj, st, r

def new_cart(cj):
    st, r = http("POST", "/ui/shoppingcart/carts", cj, {"currency": "USD"}, {"X-CSRF-Token": csrf_of(cj)})
    cid = r.get("cart_id") or r.get("id") or ""
    if cid: CL["carts"].append(cid)
    return cid

def add_catalog(cj, cid, cat, iid, qty=1):
    return http("POST", "/ui/shoppingcart/carts/%s/items/catalog" % cid, cj,
                {"category_id": cat, "item_id": iid, "quantity": qty}, {"X-CSRF-Token": csrf_of(cj)})

def create_address(cj):
    st, r = http("POST", "/ui/addresses", cj,
        {"line1": "500 Ship St", "city": "Austin", "region": "TX",
         "postal_code": "78701", "country": "US", "recipient_name": "E4 Buyer"},
        {"X-CSRF-Token": csrf_of(cj)})
    aid = r.get("address_id") or r.get("id") or ""
    if aid: CL["addresses"].append(aid)
    return st, aid, r

def purchase(cj, cid, address_id=None, idem=None):
    body = {}
    if address_id: body["address_id"] = address_id
    return http("POST", "/ui/shoppingcart/carts/%s/purchase" % cid, cj, body,
                {"X-CSRF-Token": csrf_of(cj), "X-Idempotency-Key": idem or ("e4-%s-%d" % (cid, STAMP))})

BUYER = "e4buyer+%d@ecomx.test" % STAMP
SELLER = "e4seller+%d@ecomx.test" % STAMP
CAT = "e4cat%d" % STAMP

try:
    mkuser(BUYER); mkuser(SELLER); seed_pm(BUYER)
    seed_catalog(CAT, "phys", "Physical Widget", 5000, SELLER, stock=50)
    seed_catalog(CAT, "selfitem", "Self Digital", 3000, BUYER, stock=None)

    cj, st, _ = login(BUYER); rec("login", st == 200, st)
    _, aid, ar = create_address(cj); rec("create address", bool(aid), (ar if not aid else aid))
    cid = new_cart(cj); add_catalog(cj, cid, CAT, "phys", qty=1)
    st, pr = purchase(cj, cid, address_id=aid, idem="e4-phys-%d" % STAMP)
    rec("physical purchase 200", st == 200, (st, pr))
    merch = pr.get("merchandise_cents"); ship = pr.get("shipping_cents"); tax = pr.get("tax_cents")
    total = pr.get("purchased_total_cents")
    rec("B3 merchandise=5000", merch == 5000, merch)
    rec("B3 shipping>0 added", (ship or 0) > 0, ship)
    rec("B3 tax>0 added", (tax or 0) > 0, tax)
    rec("A7 total == merch+ship+tax", total == (merch or 0)+(ship or 0)+(tax or 0), (total, merch, ship, tax))
    phys_txn = pr.get("purchase_txn_id"); phys_order = pr.get("order_id")
    if phys_txn: CL["txns"].append((BUYER, phys_txn))
    if phys_order: CL["orders"].append(phys_order)

    seller_credits = [e for e in T.billing.query(KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": user_pk(SELLER)}).get("Items", [])
        if str(e.get("sk","")).startswith("LEDGER#") and (e.get("meta") or {}).get("order_id")==phys_order]
    net = sum(int((e.get("meta") or {}).get("seller_net_cents") or 0) for e in seller_credits)
    rec("A7 seller net from merch only (4250)", net == 4250, (net, [(e.get('meta') or {}).get('seller_net_cents') for e in seller_credits]))

    st, info = http("GET", "/ui/purchase-history/transactions/%s" % phys_txn, cj)
    rec("B2 fresh order status=PENDING", info.get("status") == "PENDING", info.get("status"))
    rec("B2 order_status surfaced", bool(info.get("order_status")), info.get("order_status"))
    rec("B2 completed_at absent at t=0", not info.get("completed_at"), info.get("completed_at"))

    sgs = []
    if phys_order:
        sgs = T.seller_ship_groups.query(IndexName="GSI_ORDER",
            KeyConditionExpression="order_id = :o", ExpressionAttributeValues={":o": phys_order}).get("Items", [])
    for sg in sgs: CL["ship_groups"].append((sg.get("seller_id"), sg.get("ship_group_id")))
    ship_to_ok = any((sg.get("ship_to") or {}).get("postal_code") == "78701" for sg in sgs)
    rec("B3 seller ship_to == checkout address", ship_to_ok and len(sgs) >= 1, [sg.get("ship_to") for sg in sgs])

    st, cinfo = http("POST", "/ui/purchase-history/transactions/%s/confirm-received" % phys_txn, cj, {}, {"X-CSRF-Token": csrf_of(cj)})
    rec("B6 confirm-received 200", st == 200, (st, cinfo))
    rec("B6 status->COMPLETED", cinfo.get("status") == "COMPLETED", cinfo.get("status"))
    rec("B6 completed_at set", bool(cinfo.get("completed_at")), cinfo.get("completed_at"))

    cid2 = new_cart(cj); add_catalog(cj, cid2, CAT, "selfitem", qty=1)
    st, pr2 = purchase(cj, cid2, address_id=aid, idem="e4-self-%d" % STAMP)
    rec("self purchase 200", st == 200, (st, pr2))
    rec("B3 self: no shipping", (pr2.get("shipping_cents") or 0) == 0, pr2.get("shipping_cents"))
    rec("B3 self: no tax", (pr2.get("tax_cents") or 0) == 0, pr2.get("tax_cents"))
    self_txn = pr2.get("purchase_txn_id")
    if self_txn: CL["txns"].append((BUYER, self_txn))
    if pr2.get("order_id"): CL["orders"].append(pr2.get("order_id"))
    st, info2 = http("GET", "/ui/purchase-history/transactions/%s" % self_txn, cj)
    rec("B2 instant(no-ship) -> COMPLETED", info2.get("status") == "COMPLETED", info2.get("status"))

finally:
    for (b, tid) in CL["txns"]:
        try:
            rows = T.purchase_transactions.query(KeyConditionExpression="user_sub = :u",
                ExpressionAttributeValues={":u": b}).get("Items", [])
            for r in rows:
                if r.get("txn_id") == tid:
                    T.purchase_transactions.delete_item(Key={"user_sub": r["user_sub"], "sk": r["sk"]})
        except Exception as e: print("cleanup txn", e)
    for (s, sg) in CL["ship_groups"]:
        try: T.seller_ship_groups.delete_item(Key={"seller_id": s, "ship_group_id": sg})
        except Exception as e: print("cleanup sg", e)
    for oid in CL["orders"]:
        try:
            for r in T.orders.query(KeyConditionExpression="order_id = :o", ExpressionAttributeValues={":o": oid}).get("Items", []):
                T.orders.delete_item(Key={"order_id": r["order_id"], "sk": r["sk"]})
        except Exception as e: print("cleanup order", e)
    for (cat, iid) in CL["catalog"]:
        try: T.catalog.delete_item(Key={"PK": "CAT#%s" % cat, "SK": "ITEM#%s" % iid})
        except Exception as e: print("cleanup cat", e)
    for pk in CL["billing_pks"]:
        try:
            for r in T.billing.query(KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": pk}).get("Items", []):
                T.billing.delete_item(Key={"pk": r["pk"], "sk": r["sk"]})
        except Exception as e: print("cleanup billing", e)
    try:
        for r in T.shopping_cart.query(KeyConditionExpression="PK = :p",
            ExpressionAttributeValues={":p": "USER#%s" % BUYER}).get("Items", []):
            T.shopping_cart.delete_item(Key={"PK": r["PK"], "SK": r["SK"]})
    except Exception: pass
    for aid in CL["addresses"]:
        try: T.addresses.delete_item(Key={"user_sub": BUYER, "address_id": aid})
        except Exception as e: print("cleanup addr", e)
    for u in CL["users"]:
        try: T.users.delete_item(Key={"user_sub": u})
        except Exception as e: print("cleanup user", e)
    npass = sum(1 for _, ok, _ in results if ok); ntot = len(results)
    print("\n==== E4 VERIFY %d/%d PASS ====" % (npass, ntot))
    if npass != ntot:
        print("FAILURES:", [(n, d) for n, ok, d in results if not ok])
    sys.exit(0 if npass == ntot else 1)
