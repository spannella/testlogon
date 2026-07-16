"""ECOMX E2 LIVE verify — order-lifecycle UNIFICATION. Real HTTP against the
running uvicorn (:8000) + live DDB-Local — NOT an in-process TestClient.

Proves D1-D11 / ECOMX-20..24:
  D1  header advances past `approved` (created->approved->...->shipped) driven by
      the SELLER ship-group transitions writing BACK to the header.
  D3  multi-seller aggregation: header stays partially_shipped until ALL groups
      ship; header->shipped only when every group shipped.
  D4  delivered->completed once every group's tracking is delivered.
  D5  return flow: a refund approved on a SHIPPED order -> header `returned` +
      inventory restocked.
  ECOMX-23 the buyer read surfaces agree: /ui/orders/{id}/lifecycle (header) ==
      /ui/orders/{id}/tracking (aggregate) == the txn-tracking read (populated
      off the ship-group, fixing the txn-vs-ship-group key mismatch).
  ECOMX-21 buyer "confirm delivery" drives completion.
  ECOMX-24 orphan sweep: a `created` header with a COMPLETED txn self-heals to
      approved + populates ship groups.
  Idempotent replays + no illegal transition + no regression to the ecom core.

Auto-cleans all synthetic rows (0 residue).
"""
import base64, hashlib, os, time, json, sys
import urllib.request, urllib.error
from http.cookiejar import CookieJar

sys.path.insert(0, os.path.expanduser("/home/ubuntu/testlogon"))
sys.path.insert(0, os.path.expanduser("~/dev/testlogon"))
os.environ.setdefault("DEV_MODE", "1")
from app.core.tables import T
from app.services.billing_shared import user_pk

BASE = "http://127.0.0.1:8000"
STAMP = int(time.time())
PW = "E2-Verify-Pw-%d" % STAMP
results = []
_cleanup = {"users": [], "billing_pks": set(), "catalog": [], "orders": [], "refunds": []}


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, ("" if ok else "  <<< " + str(detail)))


def mkuser(sub, role="user"):
    salt = os.urandom(16); iters = 200000
    h = hashlib.pbkdf2_hmac("sha256", PW.encode(), salt, iters)
    T.users.put_item(Item={
        "user_sub": sub, "email": sub, "display_name": sub.split("@")[0],
        "password_hash": {"hash_b64": base64.b64encode(h).decode(),
                          "salt_b64": base64.b64encode(salt).decode(), "iterations": iters},
        "role": role, "created_at": STAMP, "_ecomx_e2_synth": True})
    _cleanup["users"].append(sub)
    _cleanup["billing_pks"].add(user_pk(sub))


def seed_pm(sub, pm_id="pm_card_visa"):
    T.billing.put_item(Item={"pk": user_pk(sub), "sk": "PM#%s" % pm_id,
                             "payment_method_id": pm_id, "brand": "visa", "last4": "4242",
                             "_ecomx_e2_synth": True})
    b = T.billing.get_item(Key={"pk": user_pk(sub), "sk": "BILLING"}).get("Item") or {
        "pk": user_pk(sub), "sk": "BILLING"}
    b["default_payment_method_id"] = pm_id
    b["_ecomx_e2_synth"] = True
    T.billing.put_item(Item=b)
    _cleanup["billing_pks"].add(user_pk(sub))


def seed_catalog(cat, iid, name, price, seller, stock=None):
    item = {"PK": "CAT#%s" % cat, "SK": "ITEM#%s" % iid, "entity": "item",
            "category_id": cat, "item_id": iid, "name": name, "price_cents": price,
            "currency": "USD", "creator_id": seller, "_ecomx_e2_synth": True}
    if stock is not None:
        item["stock_count"] = stock
    T.catalog.put_item(Item=item)
    _cleanup["catalog"].append((cat, iid))


def csrf_of(cj):
    for c in cj:
        if c.name == "ui_csrf":
            return c.value
    return ""


def http(method, path, cj, body=None, extra=None):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"}
    if extra:
        hdrs.update(extra)
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=hdrs)
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    try:
        r = op.open(req, timeout=30)
        return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode() or "{}")
        except Exception:
            payload = {}
        return e.status, payload


def login(sub):
    cj = CookieJar()
    st, resp = http("POST", "/ui/session/start", cj,
                    {"challenge_context": {"username": sub, "password": PW}})
    return cj, st, resp


def new_cart(cj):
    st, r = http("POST", "/ui/shoppingcart/carts", cj, {"currency": "USD"},
                 {"X-CSRF-Token": csrf_of(cj)})
    return st, (r.get("cart_id") or r.get("id") or ""), r


def add_catalog(cj, cid, cat, iid, qty=1):
    return http("POST", "/ui/shoppingcart/carts/%s/items/catalog" % cid, cj,
                {"category_id": cat, "item_id": iid, "quantity": qty},
                {"X-CSRF-Token": csrf_of(cj)})


def purchase(cj, cid, idem=None):
    return http("POST", "/ui/shoppingcart/carts/%s/purchase" % cid, cj, {},
                {"X-CSRF-Token": csrf_of(cj),
                 "X-Idempotency-Key": idem or ("idem-%s-%d" % (cid, STAMP))})


def header(order_id):
    return T.orders.get_item(Key={"order_id": order_id, "sk": "ORDER"}).get("Item") or {}


def lifecycle_status(order_id):
    return str(header(order_id).get("lifecycle_status") or "")


def fulfillment_status(order_id):
    return str(header(order_id).get("fulfillment_status") or "")


def seller_groups(order_id):
    return T.seller_ship_groups.scan(
        FilterExpression="order_id = :o",
        ExpressionAttributeValues={":o": order_id}).get("Items", [])


def seller_transition(cj, sg_id, target, tracking=None, carrier=None, idem=None):
    body = {"target_status": target}
    if tracking:
        body["tracking_number"] = tracking
    if carrier:
        body["carrier"] = carrier
    if idem:
        body["idempotency_key"] = idem
    return http("POST", "/ui/seller/sales/%s/transition" % sg_id, cj, body,
                {"X-CSRF-Token": csrf_of(cj)})


BUYER = "e2buyer+%d@ecomx.test" % STAMP
SELLERA = "e2seller-a+%d@ecomx.test" % STAMP
SELLERB = "e2seller-b+%d@ecomx.test" % STAMP
ADMIN = "e2admin+%d@ecomx.test" % STAMP
CAT = "e2cat%d" % STAMP
# UPS-format tracking numbers so detect_carrier resolves a real carrier + URL.
TRK_A = "1Z999AA10123456784"
TRK_B = "1Z999BB10123456785"


def track(order_id):
    if order_id:
        _cleanup["orders"].append(order_id)


try:
    for u in (BUYER, SELLERA, SELLERB):
        mkuser(u)
    mkuser(ADMIN, role="admin")
    seed_pm(BUYER)
    seed_catalog(CAT, "widgetA", "Widget A", 1000, SELLERA, stock=50)
    seed_catalog(CAT, "widgetB", "Widget B", 2000, SELLERB, stock=50)

    cjB, stB, _ = login(BUYER)
    cjSA, stSA, _ = login(SELLERA)
    cjSB, stSB, _ = login(SELLERB)
    cjAD, stAD, _ = login(ADMIN)
    rec("logins 200", stB == 200 and stAD == 200 and stSA == 200 and stSB == 200,
        "buyer=%s sellerA=%s sellerB=%s admin=%s csrfA=%s" % (stB, stSA, stSB, stAD, bool(csrf_of(cjSA))))

    # ══ SCENARIO 1: single-seller full progression created->...->completed ══
    _, cid, _ = new_cart(cjB)
    add_catalog(cjB, cid, CAT, "widgetA", 2)
    st, pr = purchase(cjB, cid)
    oid1 = pr.get("order_id", "")
    track(oid1)
    txn1 = pr.get("purchase_txn_id", "")
    rec("S1: purchase 200 + order", st == 200 and bool(oid1), "st=%s r=%s" % (st, pr))
    rec("S1/D1: header at approved after purchase (past created)",
        lifecycle_status(oid1) == "approved", "lc=%s" % lifecycle_status(oid1))

    grps = seller_groups(oid1)
    rec("S1: one seller ship-group created", len(grps) == 1, "n=%s" % len(grps))
    sg1 = grps[0]["ship_group_id"] if grps else ""

    # seller drives approved->allocated->picking->packed, header MIRRORS each step
    seen = {}
    for tgt in ("allocated", "picking", "packed"):
        stt, _ = seller_transition(cjSA, sg1, tgt)
        seen[tgt] = (stt, lifecycle_status(oid1))
    rec("S1/D1: header follows group approved->allocated->picking->packed",
        all(seen[t][0] == 200 for t in seen) and lifecycle_status(oid1) == "packed",
        "seen=%s" % seen)

    # seller ships (with tracking) -> header shipped, tracking record created
    stt, sresp = seller_transition(cjSA, sg1, "shipped", tracking=TRK_A, carrier="UPS")
    rec("S1/D1: seller ship 200", stt == 200, "st=%s" % stt)
    rec("S1/D1: header==shipped after single group ships",
        lifecycle_status(oid1) == "shipped", "lc=%s" % lifecycle_status(oid1))

    # ECOMX-23: buyer canonical order-tracking read agrees + carries the real #
    st, trk = http("GET", "/ui/orders/%s/tracking" % oid1, cjB)
    ship0 = (trk.get("shipments") or [{}])[0]
    rec("S1/ECOMX-23: order-tracking populated w/ real tracking# + url",
        st == 200 and ship0.get("tracking_number") == TRK_A and bool(ship0.get("tracking_url")),
        "st=%s tn=%s url=%s" % (st, ship0.get("tracking_number"), ship0.get("tracking_url")))

    # ECOMX-23: the buyer txn-tracking read (off txn_id) now ALSO populates off
    # the ship group (was permanently empty pre-E2).
    st, txntrk = http("GET", "/ui/purchase-history/transactions/%s/tracking" % txn1, cjB)
    rec("S1/ECOMX-23: txn-tracking populates off ship-group (key mismatch fixed)",
        st == 200 and txntrk.get("tracking_number") == TRK_A,
        "st=%s tn=%s" % (st, txntrk.get("tracking_number")))

    # D4: advance tracking via the REAL carrier-ingestion webhook (keyed by
    # ship_group_id) -> header completes. This exercises the actual carrier feed
    # rail, not just the admin demo simulate.
    def track_webhook(sg, status):
        return http("POST", "/ui/shipping/tracking/webhook", CookieJar(),
                    {"ship_group_id": sg, "status": status, "source": "verify"})
    stw, _ = track_webhook(sg1, "out_for_delivery")
    rec("S1/D4: webhook out_for_delivery -> fulfillment=out_for_delivery, lifecycle still shipped",
        stw == 200 and lifecycle_status(oid1) == "shipped" and fulfillment_status(oid1) == "out_for_delivery",
        "stw=%s lc=%s ff=%s" % (stw, lifecycle_status(oid1), fulfillment_status(oid1)))
    stw, _ = track_webhook(sg1, "delivered")
    rec("S1/D4: header==completed once tracking delivered (via webhook)",
        stw == 200 and lifecycle_status(oid1) == "completed", "stw=%s lc=%s" % (stw, lifecycle_status(oid1)))

    # header == tracking (no contradiction)
    st, trk2 = http("GET", "/ui/orders/%s/tracking" % oid1, cjB)
    rec("S1/ECOMX-23: header(completed)==tracking(delivered) no contradiction",
        trk2.get("fulfillment_status") == "delivered" and lifecycle_status(oid1) == "completed",
        "ff=%s lc=%s" % (trk2.get("fulfillment_status"), lifecycle_status(oid1)))

    # idempotent replay: re-ship the already-shipped group is a no-op success
    stt, _ = seller_transition(cjSA, sg1, "shipped", idem="replay-1")
    rec("S1: idempotent seller re-ship replay -> 200 no-op (header stays completed)",
        stt == 200 and lifecycle_status(oid1) == "completed", "st=%s lc=%s" % (stt, lifecycle_status(oid1)))

    # ══ SCENARIO 2: MULTI-SELLER aggregation (partial ship) ══
    _, cid2, _ = new_cart(cjB)
    add_catalog(cjB, cid2, CAT, "widgetA", 1)   # seller A
    add_catalog(cjB, cid2, CAT, "widgetB", 1)   # seller B
    st, pr2 = purchase(cjB, cid2, idem="idem-multi-%d" % STAMP)
    oid2 = pr2.get("order_id", "")
    track(oid2)
    grps2 = {g["seller_id"]: g["ship_group_id"] for g in seller_groups(oid2)}
    rec("S2: two seller ship-groups (A+B)", len(grps2) == 2, "grps=%s" % list(grps2))
    sgA = grps2.get(SELLERA, "")
    sgB = grps2.get(SELLERB, "")

    # only seller A ships -> header must be partially_shipped, NOT shipped
    for tgt in ("allocated", "picking", "packed", "shipped"):
        seller_transition(cjSA, sgA, tgt, tracking=(TRK_A if tgt == "shipped" else None),
                          carrier=("UPS" if tgt == "shipped" else None))
    rec("S2/D3: one-of-two shipped -> fulfillment=partially_shipped",
        fulfillment_status(oid2) == "partially_shipped", "ff=%s" % fulfillment_status(oid2))
    rec("S2/D3: header lifecycle NOT shipped while a group is unshipped",
        lifecycle_status(oid2) != "shipped" and lifecycle_status(oid2) in ("approved", "allocated", "picking", "packed"),
        "lc=%s" % lifecycle_status(oid2))

    # now seller B ships too -> header advances to shipped
    for tgt in ("allocated", "picking", "packed", "shipped"):
        seller_transition(cjSB, sgB, tgt, tracking=(TRK_B if tgt == "shipped" else None),
                          carrier=("UPS" if tgt == "shipped" else None))
    rec("S2/D3: header==shipped only after ALL groups ship",
        lifecycle_status(oid2) == "shipped" and fulfillment_status(oid2) == "shipped",
        "lc=%s ff=%s" % (lifecycle_status(oid2), fulfillment_status(oid2)))

    # order-tracking aggregates BOTH shipments
    st, trkm = http("GET", "/ui/orders/%s/tracking" % oid2, cjB)
    rec("S2/ECOMX-23: order-tracking aggregates 2 shipments",
        st == 200 and trkm.get("shipment_count") == 2, "n=%s" % trkm.get("shipment_count"))

    # deliver ONLY A -> still not completed; deliver B -> completed
    http("POST", "/ui/shipping/tracking/webhook", CookieJar(),
         {"ship_group_id": sgA, "status": "delivered", "source": "verify"})
    rec("S2/D4: one-of-two delivered -> NOT completed",
        lifecycle_status(oid2) == "shipped", "lc=%s" % lifecycle_status(oid2))
    http("POST", "/ui/shipping/tracking/webhook", CookieJar(),
         {"ship_group_id": sgB, "status": "delivered", "source": "verify"})
    rec("S2/D4: header==completed once BOTH delivered",
        lifecycle_status(oid2) == "completed", "lc=%s" % lifecycle_status(oid2))

    # ══ SCENARIO 3: buyer "confirm delivery" (ECOMX-21) ══
    _, cid3, _ = new_cart(cjB)
    add_catalog(cjB, cid3, CAT, "widgetA", 1)
    st, pr3 = purchase(cjB, cid3, idem="idem-confirm-%d" % STAMP)
    oid3 = pr3.get("order_id", "")
    track(oid3)
    sg3 = seller_groups(oid3)[0]["ship_group_id"]
    for tgt in ("allocated", "picking", "packed", "shipped"):
        seller_transition(cjSA, sg3, tgt, tracking=(TRK_A if tgt == "shipped" else None), carrier="UPS")
    st, cd = http("POST", "/ui/orders/%s/confirm-delivery" % oid3, cjB,
                  extra={"X-CSRF-Token": csrf_of(cjB)})
    rec("S3/ECOMX-21: buyer confirm-delivery -> header completed",
        st == 200 and lifecycle_status(oid3) == "completed",
        "st=%s lc=%s" % (st, lifecycle_status(oid3)))
    # idempotent second confirm
    st2, _ = http("POST", "/ui/orders/%s/confirm-delivery" % oid3, cjB,
                  extra={"X-CSRF-Token": csrf_of(cjB)})
    rec("S3/ECOMX-21: confirm-delivery idempotent (2nd call still 200, stays completed)",
        st2 == 200 and lifecycle_status(oid3) == "completed", "st=%s" % st2)

    # ══ SCENARIO 4: RETURN flow (ECOMX-22) — refund on a SHIPPED order ══
    _, cid4, _ = new_cart(cjB)
    add_catalog(cjB, cid4, CAT, "widgetA", 3)
    st, pr4 = purchase(cjB, cid4, idem="idem-return-%d" % STAMP)
    oid4 = pr4.get("order_id", "")
    track(oid4)
    txn4 = pr4.get("purchase_txn_id", "")
    stockA_before_return = int((T.catalog.get_item(Key={"PK": "CAT#%s" % CAT, "SK": "ITEM#widgetA"}).get("Item") or {}).get("stock_count", -1))
    # create the refund request WHILE approved (allowed), then ship, then admin approves.
    st, rr = http("POST", "/ui/billing/refund-requests", cjB,
                  {"transaction_entry_id": txn4, "reason": "changed mind"},
                  {"X-CSRF-Token": csrf_of(cjB)})
    req_id = rr.get("refund_request_id") or rr.get("request_id") or ""
    if req_id:
        _cleanup["refunds"].append(req_id)
    rec("S4: refund request created (approved-state) 201/200", st in (200, 201) and bool(req_id), "st=%s r=%s" % (st, rr))
    # ship it
    sg4 = seller_groups(oid4)[0]["ship_group_id"]
    for tgt in ("allocated", "picking", "packed", "shipped"):
        seller_transition(cjSA, sg4, tgt, tracking=(TRK_A if tgt == "shipped" else None), carrier="UPS")
    rec("S4: order shipped before return", lifecycle_status(oid4) == "shipped", "lc=%s" % lifecycle_status(oid4))
    # admin approves the refund -> return flow fires
    st, ap = http("POST", "/ui/admin/refund-requests/%s/approve" % req_id, cjAD, {},
                  {"X-CSRF-Token": csrf_of(cjAD)})
    rec("S4/D5: admin approve refund 200", st == 200, "st=%s r=%s" % (st, ap))
    rec("S4/D5: shipped order -> header RETURNED after refund approve",
        lifecycle_status(oid4) == "returned", "lc=%s" % lifecycle_status(oid4))
    stockA_after_return = int((T.catalog.get_item(Key={"PK": "CAT#%s" % CAT, "SK": "ITEM#widgetA"}).get("Item") or {}).get("stock_count", -1))
    rec("S4/D5: inventory restocked by returned qty (3)",
        stockA_after_return == stockA_before_return + 3,
        "before=%s after=%s" % (stockA_before_return, stockA_after_return))

    # ══ SCENARIO 5: ILLEGAL transition guard + no orphan ══
    _, cid5, _ = new_cart(cjB)
    add_catalog(cjB, cid5, CAT, "widgetA", 1)
    st, pr5 = purchase(cjB, cid5, idem="idem-illegal-%d" % STAMP)
    oid5 = pr5.get("order_id", "")
    track(oid5)
    sg5 = seller_groups(oid5)[0]["ship_group_id"]
    # approved -> shipped directly is ILLEGAL (must go through allocated/picking/packed)
    st, ill = http("POST", "/ui/seller/sales/%s/transition" % sg5, cjSA,
                   {"target_status": "shipped"}, {"X-CSRF-Token": csrf_of(cjSA)})
    rec("S5: illegal group transition approved->shipped -> 409",
        st == 409, "st=%s r=%s" % (st, ill))
    rec("S5: header unchanged after illegal (still approved, no orphan)",
        lifecycle_status(oid5) == "approved", "lc=%s" % lifecycle_status(oid5))

    # ══ SCENARIO 6: ORPHAN self-heal sweep (ECOMX-24) ══
    _, cid6, _ = new_cart(cjB)
    add_catalog(cjB, cid6, CAT, "widgetA", 1)
    st, pr6 = purchase(cjB, cid6, idem="idem-orphan-%d" % STAMP)
    oid6 = pr6.get("order_id", "")
    track(oid6)
    # Simulate the crash-mid-purchase: force the header BACK to `created` while
    # the COMPLETED txn + buyer_debit_txn_id remain (the exact orphan state).
    # Clear any ship groups the tail created so the sweep must re-populate them.
    for g in seller_groups(oid6):
        T.seller_ship_groups.delete_item(Key={"seller_id": g["seller_id"], "ship_group_id": g["ship_group_id"]})
    T.orders.update_item(Key={"order_id": oid6, "sk": "ORDER"},
                         UpdateExpression="SET lifecycle_status = :c, #s = :ps",
                         ExpressionAttributeNames={"#s": "status"},
                         ExpressionAttributeValues={":c": "created", ":ps": "pending_payment"})
    rec("S6: orphan seeded (header forced back to created, txn COMPLETED)",
        lifecycle_status(oid6) == "created" and bool(header(oid6).get("buyer_debit_txn_id")),
        "lc=%s txn=%s" % (lifecycle_status(oid6), header(oid6).get("buyer_debit_txn_id")))
    st, sweep = http("POST", "/ui/orders/admin/reconcile-stuck", cjAD, {},
                     {"X-CSRF-Token": csrf_of(cjAD)})
    rec("S6/ECOMX-24: sweep promoted the orphan to approved",
        st == 200 and lifecycle_status(oid6) == "approved" and sweep.get("promoted", 0) >= 1,
        "st=%s lc=%s sweep=%s" % (st, lifecycle_status(oid6), sweep))
    rec("S6/ECOMX-24: sweep re-populated the ship group",
        len(seller_groups(oid6)) >= 1, "n=%s" % len(seller_groups(oid6)))

    # ══ REGRESSION: admin can still drive the header transition endpoint ══
    st, _ = http("POST", "/ui/orders/%s/transition" % oid5, cjAD,
                 {"target_status": "held", "reason": "regression check"},
                 {"X-CSRF-Token": csrf_of(cjAD)})
    rec("REG: admin /transition still works (held)", st == 200 and lifecycle_status(oid5) == "held",
        "st=%s lc=%s" % (st, lifecycle_status(oid5)))

except Exception as e:
    import traceback
    traceback.print_exc()
    rec("EXCEPTION", False, str(e))

finally:
    def _safe(fn):
        try:
            fn()
        except Exception as ex:
            print("cleanup warn:", ex)

    for sub in _cleanup["users"]:
        _safe(lambda s=sub: T.users.delete_item(Key={"user_sub": s}))
    for pk in _cleanup["billing_pks"]:
        rows = T.billing.query(KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": pk}).get("Items", [])
        for r in rows:
            _safe(lambda r=r: T.billing.delete_item(Key={"pk": r["pk"], "sk": r["sk"]}))
    for (cat, iid) in _cleanup["catalog"]:
        _safe(lambda c=cat, i=iid: T.catalog.delete_item(Key={"PK": "CAT#%s" % c, "SK": "ITEM#%s" % i}))
    for sub in _cleanup["users"]:
        rows = T.shopping_cart.query(KeyConditionExpression="PK = :p",
                                     ExpressionAttributeValues={":p": user_pk(sub)}).get("Items", [])
        for r in rows:
            _safe(lambda r=r: T.shopping_cart.delete_item(Key={"PK": r["PK"], "SK": r["SK"]}))
    for oid in set(_cleanup["orders"]):
        rows = T.orders.query(KeyConditionExpression="order_id = :o",
                              ExpressionAttributeValues={":o": oid}).get("Items", [])
        for r in rows:
            _safe(lambda r=r: T.orders.delete_item(Key={"order_id": r["order_id"], "sk": r["sk"]}))
        try:
            for r in T.order_items.query(KeyConditionExpression="order_id = :o",
                                         ExpressionAttributeValues={":o": oid}).get("Items", []):
                _safe(lambda r=r: T.order_items.delete_item(Key={"order_id": r["order_id"], "item_id": r["item_id"]}))
        except Exception:
            pass
        try:
            for r in T.seller_ship_groups.scan(FilterExpression="order_id = :o",
                                               ExpressionAttributeValues={":o": oid}).get("Items", []):
                _safe(lambda r=r: T.seller_ship_groups.delete_item(Key={"seller_id": r["seller_id"], "ship_group_id": r["ship_group_id"]}))
                _safe(lambda r=r: T.shipment_tracking.delete_item(Key={"ship_group_id": r["ship_group_id"]}))
        except Exception:
            pass
    for req in _cleanup["refunds"]:
        _safe(lambda q=req: T.refund_requests.delete_item(Key={"pk": "REFUND#%s" % q, "sk": "META"}))

    npass = sum(1 for _, ok, _ in results if ok)
    print("\n==== ECOMX E2 VERIFY: %d/%d PASS ====" % (npass, len(results)))
    if npass != len(results):
        print("FAILURES:")
        for n, ok, d in results:
            if not ok:
                print("  -", n, "::", d)
        sys.exit(1)
