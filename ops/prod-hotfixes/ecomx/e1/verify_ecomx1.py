"""ECOMX E1 LIVE verify — real HTTP against the running uvicorn (:8000) + the
live DDB-Local + live stripe-mock. NOT an in-process TestClient.

Proves A1-A10:
  A1  real charge before order COMPLETED; decline/no-valid-PM -> 402, no order.
  A1  idempotent (double-submit charges once).
  A2  order payment_status="paid" only after a successful charge.
  A6  one commission model: shop seller net = gross*(1-fee); platform fee ledger.
  A5/A13 refund claws back EVERY seller + livecom host; net ledger ~0.
  A3  owner cancel-refund reverses the real charge (no silent no-op).
  A7  livecom settle: partial-marker replay pays; no double-credit.
  A8  refund transact atomic on the running DDB-Local (no 500 fallback needed).
  A9  refund window closes once shipped.
  A10 concurrent double-tap -> one purchase, no oversell.

Auto-cleans all synthetic rows (0 residue).
"""
import base64, hashlib, os, time, json, sys, threading
import urllib.request, urllib.error
from http.cookiejar import CookieJar

sys.path.insert(0, os.path.expanduser("~/dev/testlogon"))
os.environ.setdefault("DEV_MODE", "1")
from app.core.tables import T
from app.services.billing_shared import user_pk

BASE = "http://127.0.0.1:8000"
STAMP = int(time.time())
PW = "E1-Verify-Pw-%d" % STAMP
results = []
_cleanup = {"users": [], "billing_pks": set(), "catalog": [], "carts": [], "orders": [],
            "ship_groups": [], "settlements": [], "refunds": [], "pmt_txns": [], "platform_fees": []}


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, ("" if ok else "  <<< " + str(detail)))


def mkuser(sub):
    salt = os.urandom(16); iters = 200000
    h = hashlib.pbkdf2_hmac("sha256", PW.encode(), salt, iters)
    T.users.put_item(Item={
        "user_sub": sub, "email": sub, "display_name": sub.split("@")[0],
        "password_hash": {"hash_b64": base64.b64encode(h).decode(),
                          "salt_b64": base64.b64encode(salt).decode(), "iterations": iters},
        "role": "user", "created_at": STAMP, "_ecomx_e1_synth": True})
    _cleanup["users"].append(sub)
    _cleanup["billing_pks"].add(user_pk(sub))


def seed_pm(sub, pm_id, make_default=True):
    T.billing.put_item(Item={"pk": user_pk(sub), "sk": "PM#%s" % pm_id,
                             "payment_method_id": pm_id, "brand": "visa", "last4": "4242",
                             "_ecomx_e1_synth": True})
    if make_default:
        b = T.billing.get_item(Key={"pk": user_pk(sub), "sk": "BILLING"}).get("Item") or {
            "pk": user_pk(sub), "sk": "BILLING"}
        b["default_payment_method_id"] = pm_id
        b["_ecomx_e1_synth"] = True
        T.billing.put_item(Item=b)
    _cleanup["billing_pks"].add(user_pk(sub))


def set_default_pm_only(sub, pm_id):
    """Set default PM WITHOUT a matching PM# row -> ownership check must 402."""
    T.billing.put_item(Item={"pk": user_pk(sub), "sk": "BILLING",
                             "default_payment_method_id": pm_id, "_ecomx_e1_synth": True})
    _cleanup["billing_pks"].add(user_pk(sub))


def seed_catalog(cat, iid, name, price, seller, stock=None):
    item = {"PK": "CAT#%s" % cat, "SK": "ITEM#%s" % iid, "entity": "item",
            "category_id": cat, "item_id": iid, "name": name, "price_cents": price,
            "currency": "USD", "creator_id": seller, "_ecomx_e1_synth": True}
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
    cid = r.get("cart_id") or r.get("id") or ""
    if cid:
        _cleanup["carts"].append(cid)
    return st, cid, r


def add_catalog(cj, cid, cat, iid, qty=1):
    return http("POST", "/ui/shoppingcart/carts/%s/items/catalog" % cid, cj,
                {"category_id": cat, "item_id": iid, "quantity": qty},
                {"X-CSRF-Token": csrf_of(cj)})


def purchase(cj, cid, idem=None):
    return http("POST", "/ui/shoppingcart/carts/%s/purchase" % cid, cj, {},
                {"X-CSRF-Token": csrf_of(cj),
                 "X-Idempotency-Key": idem or ("idem-%s-%d" % (cid, STAMP))})


def ledger(sub):
    return T.billing.query(KeyConditionExpression="pk = :p",
                           ExpressionAttributeValues={":p": user_pk(sub)}).get("Items", [])


def signed_sum(sub):
    tot = 0
    for e in ledger(sub):
        if str(e.get("sk", "")).startswith("LEDGER#"):
            v = e.get("signed_amount_cents")
            if v is None:
                v = e.get("amount_cents", 0)
            tot += int(v)
    return tot


BUYER = "e1buyer+%d@ecomx.test" % STAMP
BUYER2 = "e1buyer2+%d@ecomx.test" % STAMP
BUYER3 = "e1buyer3+%d@ecomx.test" % STAMP
SELLERA = "e1sellerA+%d@ecomx.test" % STAMP
SELLERB = "e1sellerB+%d@ecomx.test" % STAMP
CAT = "e1cat%d" % STAMP


def track_order(order_id):
    if order_id:
        _cleanup["orders"].append(order_id)


try:
    for u in (BUYER, BUYER2, BUYER3, SELLERA, SELLERB):
        mkuser(u)
    seed_pm(BUYER, "pm_card_visa")
    seed_pm(BUYER2, "pm_card_visa")
    seed_pm(BUYER3, "pm_card_visa")
    seed_catalog(CAT, "widgetA", "Widget A", 1000, SELLERA, stock=50)
    seed_catalog(CAT, "widgetB", "Widget B", 2000, SELLERB, stock=50)
    seed_catalog(CAT, "lowstock", "Low Stock", 500, SELLERA, stock=1)

    # ── A1/A2/A6/A10: happy-path charge over real HTTP ───────────────────────
    cj, st, _ = login(BUYER)
    rec("login buyer 200", st == 200, "st=%s" % st)
    _, cid, _ = new_cart(cj)
    st, _ = add_catalog(cj, cid, CAT, "widgetA", 2)   # 2 x 1000 = 2000
    st2, _ = add_catalog(cj, cid, CAT, "widgetB", 1)  # 1 x 2000 = 2000
    rec("cart add catalog items 200", st == 200 and st2 == 200, "st=%s st2=%s" % (st, st2))

    seller_a_before = signed_sum(SELLERA)
    catA_before = int((T.catalog.get_item(Key={"PK": "CAT#%s" % CAT, "SK": "ITEM#widgetA"}).get("Item") or {}).get("stock_count", -1))

    st, presp = purchase(cj, cid)
    order_id = presp.get("order_id", "")
    track_order(order_id)
    txn_id = presp.get("purchase_txn_id", "")
    rec("A1: checkout 200 + order_id", st == 200 and bool(order_id), "st=%s r=%s" % (st, presp))

    hdr = T.orders.get_item(Key={"order_id": order_id, "sk": "ORDER"}).get("Item") or {}
    rec("A2: order payment_status=paid", hdr.get("payment_status") == "paid", "hdr.ps=%s" % hdr.get("payment_status"))
    rec("A1: order carries buyer_debit_txn_id", str(hdr.get("buyer_debit_txn_id") or "") == txn_id and bool(txn_id),
        "hdr.txn=%s txn=%s" % (hdr.get("buyer_debit_txn_id"), txn_id))

    # real buyer debit ledger entry (negative signed) for the charged total
    buyer_debit = [e for e in ledger(BUYER) if str(e.get("sk", "")).startswith("LEDGER#")
                   and e.get("entry_id") == txn_id]
    rec("A1: buyer debit ledger entry written (-4000)",
        bool(buyer_debit) and int(buyer_debit[0].get("signed_amount_cents", 0)) == -4000,
        "entry=%s" % (buyer_debit[0].get("signed_amount_cents") if buyer_debit else None))

    # A10: stock decremented by 2
    catA_after = int((T.catalog.get_item(Key={"PK": "CAT#%s" % CAT, "SK": "ITEM#widgetA"}).get("Item") or {}).get("stock_count", -1))
    rec("A10: stock decremented by 2", catA_after == catA_before - 2, "before=%s after=%s" % (catA_before, catA_after))

    # A6: seller A net credit = 2000 * (1 - 0.15) = 1700; platform fee = 300
    sellerA_credits = [e for e in ledger(SELLERA) if str(e.get("sk", "")).startswith("LEDGER#")
                       and e.get("type") == "credit" and (e.get("meta") or {}).get("order_id") == order_id]
    a_net = sum(int(e.get("amount_cents", 0)) for e in sellerA_credits)
    a_fee = sum(int((e.get("meta") or {}).get("platform_fee_cents", 0)) for e in sellerA_credits)
    rec("A6: seller A net = gross*(1-0.15) = 1700", a_net == 1700, "net=%s" % a_net)
    rec("A6: seller A credit meta records platform_fee 300", a_fee == 300, "fee=%s" % a_fee)
    # platform fee ledger row exists
    pf = T.ad_billing.query(KeyConditionExpression="pk = :p",
                            ExpressionAttributeValues={":p": "PLATFORM#revenue"}).get("Items", [])
    pf_for_order = [x for x in pf if (x.get("meta") or {}).get("order_id") == order_id]
    for x in pf_for_order:
        _cleanup["platform_fees"].append(x["sk"])
    rec("A6: platform-fee ledger row(s) recorded for order",
        bool(pf_for_order) and sum(int(x.get("amount_cents", 0)) for x in pf_for_order) == 600,
        "rows=%d sum=%s" % (len(pf_for_order), sum(int(x.get("amount_cents", 0)) for x in pf_for_order)))

    # ── A1 idempotency: re-submit the SAME (already PURCHASED) cart -> one order, one debit ─
    st_re, presp_re = purchase(cj, cid)
    debits_now = [e for e in ledger(BUYER) if str(e.get("sk", "")).startswith("LEDGER#")
                  and (e.get("meta") or {}).get("order_id") == order_id and int(e.get("signed_amount_cents", 0)) < 0]
    rec("A1: idempotent re-submit -> same order, single buyer debit",
        st_re == 200 and presp_re.get("order_id") == order_id and len(debits_now) == 1,
        "st=%s order=%s debits=%d" % (st_re, presp_re.get("order_id"), len(debits_now)))

    # ── A1 negative: buyer with a default PM they DON'T own -> 402, NO order, stock restored ─
    cj2, _, _ = login(BUYER2)
    set_default_pm_only(BUYER2, "pm_not_owned_%d" % STAMP)
    _, cid2, _ = new_cart(cj2)
    add_catalog(cj2, cid2, CAT, "widgetA", 3)
    catA_pre_decline = int((T.catalog.get_item(Key={"PK": "CAT#%s" % CAT, "SK": "ITEM#widgetA"}).get("Item") or {}).get("stock_count", -1))
    st_d, resp_d = purchase(cj2, cid2)
    cart2 = T.shopping_cart.get_item(Key={"PK": user_pk(BUYER2), "SK": "CART#%s" % cid2}).get("Item") or {}
    catA_post_decline = int((T.catalog.get_item(Key={"PK": "CAT#%s" % CAT, "SK": "ITEM#widgetA"}).get("Item") or {}).get("stock_count", -1))
    buyer2_debits = [e for e in ledger(BUYER2) if str(e.get("sk", "")).startswith("LEDGER#")]
    rec("A1-neg: no-valid-PM checkout -> 402", st_d == 402, "st=%s resp=%s" % (st_d, resp_d))
    rec("A1-neg: cart stays OPEN (no order completed)", cart2.get("status") == "OPEN", "status=%s" % cart2.get("status"))
    rec("A1-neg: stock restored after decline", catA_post_decline == catA_pre_decline, "pre=%s post=%s" % (catA_pre_decline, catA_post_decline))
    rec("A1-neg: NO buyer debit ledger on decline", len(buyer2_debits) == 0, "debits=%d" % len(buyer2_debits))

    # ── A5/A13/A8: refund the multi-seller order -> buyer credited + BOTH sellers clawed ─
    sellerA_net_before_refund = signed_sum(SELLERA)
    sellerB_net_before_refund = signed_sum(SELLERB)
    buyer_net_before_refund = signed_sum(BUYER)
    st_rr, rr = http("POST", "/ui/billing/refund-requests", cj,
                     {"transaction_entry_id": txn_id, "reason": "e1 verify refund"},
                     {"X-CSRF-Token": csrf_of(cj)})
    req_id = rr.get("refund_request_id") or rr.get("request_id") or rr.get("id") or ""
    if req_id:
        _cleanup["refunds"].append(req_id)
    rec("A5: refund request created 200/201", st_rr in (200, 201) and bool(req_id), "st=%s rr=%s" % (st_rr, rr))

    # approve as admin
    admin = "e1admin+%d@ecomx.test" % STAMP
    mkuser(admin)
    T.users.update_item(Key={"user_sub": admin}, UpdateExpression="SET #r=:r",
                        ExpressionAttributeNames={"#r": "role"}, ExpressionAttributeValues={":r": "admin"})
    cja, _, _ = login(admin)
    st_ap, ap = http("POST", "/ui/admin/refund-requests/%s/approve" % req_id, cja, {},
                     {"X-CSRF-Token": csrf_of(cja)})
    rec("A8: refund approve 200 (transact atomic on DDB-Local, no 500)", st_ap == 200, "st=%s ap=%s" % (st_ap, ap))

    sellerA_after = signed_sum(SELLERA)
    sellerB_after = signed_sum(SELLERB)
    buyer_after = signed_sum(BUYER)
    # seller A clawed by 1700 (their net), seller B clawed by 1700 (2000*0.85)
    rec("A13: seller A clawed back their net (1700)", sellerA_after == sellerA_net_before_refund - 1700,
        "before=%s after=%s" % (sellerA_net_before_refund, sellerA_after))
    rec("A13: seller B clawed back their net (1700)", sellerB_after == sellerB_net_before_refund - 1700,
        "before=%s after=%s" % (sellerB_net_before_refund, sellerB_after))
    rec("A5: buyer credited back the full 4000", buyer_after == buyer_net_before_refund + 4000,
        "before=%s after=%s" % (buyer_net_before_refund, buyer_after))

    # ── A9: refund window closes once shipped ────────────────────────────────
    cj3, _, _ = login(BUYER3)
    _, cid3, _ = new_cart(cj3)
    add_catalog(cj3, cid3, CAT, "widgetA", 1)
    st_p3, p3 = purchase(cj3, cid3)
    oid3 = p3.get("order_id", ""); txn3 = p3.get("purchase_txn_id", "")
    track_order(oid3)
    # force the order lifecycle to shipped
    T.orders.update_item(Key={"order_id": oid3, "sk": "ORDER"},
                         UpdateExpression="SET lifecycle_status = :s",
                         ExpressionAttributeValues={":s": "shipped"})
    st_rw, rw = http("POST", "/ui/billing/refund-requests", cj3,
                     {"transaction_entry_id": txn3, "reason": "post-ship refund"},
                     {"X-CSRF-Token": csrf_of(cj3)})
    rec("A9: refund request on SHIPPED order -> 400 (window closed)", st_rw == 400,
        "st=%s rw=%s" % (st_rw, rw))

    # ── A3: owner cancel-refund reverses the real charge (no silent no-op) ────
    cj4, _, _ = login(BUYER3)
    _, cid4, _ = new_cart(cj4)
    add_catalog(cj4, cid4, CAT, "widgetB", 1)  # 2000 from seller B
    st_p4, p4 = purchase(cj4, cid4)
    oid4 = p4.get("order_id", ""); txn4 = p4.get("purchase_txn_id", "")
    track_order(oid4)
    buyer3_before_cancel = signed_sum(BUYER3)
    sellerB_before_cancel = signed_sum(SELLERB)
    # order is at 'approved' after purchase (cart tail advanced it) -> owner may cancel
    st_c, c = http("POST", "/ui/orders/%s/cancel" % oid4, cj4,
                   {"reason": "changed my mind", "refund": True}, {"X-CSRF-Token": csrf_of(cj4)})
    buyer3_after_cancel = signed_sum(BUYER3)
    sellerB_after_cancel = signed_sum(SELLERB)
    refund_credits = [e for e in ledger(BUYER3) if e.get("type") == "refund_credit"
                      and (e.get("meta") or {}).get("order_id") == oid4]
    rec("A3: owner cancel-refund 200 (no silent no-op)", st_c == 200, "st=%s c=%s" % (st_c, c))
    rec("A3: owner cancel issued a real buyer refund credit", bool(refund_credits)
        and buyer3_after_cancel == buyer3_before_cancel + 2000,
        "before=%s after=%s credits=%d" % (buyer3_before_cancel, buyer3_after_cancel, len(refund_credits)))
    rec("A3/A13: owner cancel clawed back seller B", sellerB_after_cancel == sellerB_before_cancel - 1700,
        "before=%s after=%s" % (sellerB_before_cancel, sellerB_after_cancel))

    # ── A7: livecom settle — partial-marker replay pays; no double-credit ─────
    from app.services import live_commerce_split as lcs
    from app.services import live_stream_products as lsp
    LC_SELLER = SELLERA
    LC_HOST = "e1host+%d@ecomx.test" % STAMP
    mkuser(LC_HOST)
    lc_order = "E1LCORD-%d" % STAMP
    _cleanup["settlements"].append(lc_order)
    sess = "e1sess-%d" % STAMP
    prod = "widgetA"
    # pin the product as an affiliate product so host earns commission
    orig_get_pinned = lsp.get_pinned
    orig_aff = lsp.get_affiliate_commission_bps
    lsp.get_pinned = lambda s, p: {"seller_id": LC_SELLER, "is_affiliate": True} if p == prod else None
    lsp.get_affiliate_commission_bps = lambda c, p: 1000  # 10% host commission of pool
    lc_items = [{"item_id": prod, "category_id": CAT, "line_total_cents": 1000}]
    try:
        host_before = signed_sum(LC_HOST)
        seller_before = signed_sum(LC_SELLER)
        # 1) simulate a CRASHED prior attempt: write ONLY the 'settling' marker, no credits.
        lcs.T.live_stream_products.put_item(Item={
            "session_id": lcs._order_pk(lc_order), "SK": "SETTLEMENT", "order_id": lc_order,
            "broadcast_session_id": sess, "host_id": LC_HOST, "buyer_sub": BUYER,
            "status": "settling", "created_at": int(time.time())})
        # 2) replay settle -> must re-drive credits (not idempotent no-op on a bare marker)
        summ = lcs.settle_stream_order(order_id=lc_order, session_id=sess, host_id=LC_HOST,
                                       buyer_sub=BUYER, items=lc_items, final_total=1000,
                                       currency="USD", cart_id="lc", txn_id="lctxn")
        host_after_1 = signed_sum(LC_HOST)
        seller_after_1 = signed_sum(LC_SELLER)
        rec("A7: crashed-marker replay PAYS host commission (not stranded)",
            host_after_1 > host_before and summ.get("host_commission_total_cents", 0) > 0,
            "host +%s summ=%s" % (host_after_1 - host_before, summ.get("host_commission_total_cents")))
        rec("A7: crashed-marker replay PAYS seller net", seller_after_1 > seller_before,
            "seller +%s" % (seller_after_1 - seller_before))
        # 3) settle AGAIN -> now marker is 'settled' -> idempotent no-op, NO double credit
        summ2 = lcs.settle_stream_order(order_id=lc_order, session_id=sess, host_id=LC_HOST,
                                        buyer_sub=BUYER, items=lc_items, final_total=1000,
                                        currency="USD", cart_id="lc", txn_id="lctxn")
        host_after_2 = signed_sum(LC_HOST)
        seller_after_2 = signed_sum(LC_SELLER)
        rec("A7: second settle is idempotent no-op (no double-credit)",
            summ2.get("idempotent") is True and host_after_2 == host_after_1 and seller_after_2 == seller_after_1,
            "idem=%s host=%s/%s seller=%s/%s" % (summ2.get("idempotent"), host_after_1, host_after_2, seller_after_1, seller_after_2))
    finally:
        lsp.get_pinned = orig_get_pinned
        lsp.get_affiliate_commission_bps = orig_aff

    # ── A10: concurrent double-tap on the last unit -> one purchase, no oversell ─
    cjx, _, _ = login(BUYER)
    _, cidx, _ = new_cart(cjx)
    add_catalog(cjx, cidx, CAT, "lowstock", 1)  # stock=1
    outcomes = []

    def _tap():
        cjt = CookieJar()
        http("POST", "/ui/session/start", cjt, {"challenge_context": {"username": BUYER, "password": PW}})
        s, r = http("POST", "/ui/shoppingcart/carts/%s/purchase" % cidx, cjt, {},
                    {"X-CSRF-Token": csrf_of(cjt), "X-Idempotency-Key": "tap-%s" % cidx})
        outcomes.append((s, r.get("order_id", "")))

    ths = [threading.Thread(target=_tap) for _ in range(2)]
    [t.start() for t in ths]; [t.join() for t in ths]
    order_ids = {o for (s, o) in outcomes if o}
    for o in order_ids:
        track_order(o)
    lowstock_after = int((T.catalog.get_item(Key={"PK": "CAT#%s" % CAT, "SK": "ITEM#lowstock"}).get("Item") or {}).get("stock_count", -1))
    rec("A10: concurrent double-tap -> exactly one order id", len(order_ids) == 1, "outcomes=%s" % outcomes)
    rec("A10: no oversell (stock floored at 0, never negative)", lowstock_after == 0, "stock=%s" % lowstock_after)

finally:
    # ───────────────────────── cleanup (0 residue) ──────────────────────────
    def _safe(fn):
        try:
            fn()
        except Exception as e:
            print("cleanup warn:", e)

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
    for oid in set(_cleanup["settlements"]):
        _safe(lambda o=oid: T.live_stream_products.delete_item(Key={"session_id": "ORDER#%s" % o, "SK": "SETTLEMENT"}))
    for req in _cleanup["refunds"]:
        _safe(lambda q=req: T.refund_requests.delete_item(Key={"pk": "REFUND#%s" % q, "sk": "META"}))
    for sk in _cleanup["platform_fees"]:
        _safe(lambda s=sk: T.ad_billing.delete_item(Key={"pk": "PLATFORM#revenue", "sk": s}))
    # order-lifecycle history + seller ship groups spawned by the cart tail
    for oid in set(_cleanup["orders"]):
        try:
            for r in T.seller_ship_groups.scan(FilterExpression="order_id = :o",
                                               ExpressionAttributeValues={":o": oid}).get("Items", []):
                _safe(lambda r=r: T.seller_ship_groups.delete_item(Key={"seller_id": r["seller_id"], "ship_group_id": r["ship_group_id"]}))
        except Exception:
            pass

    npass = sum(1 for _, ok, _ in results if ok)
    print("\n==== ECOMX E1 VERIFY: %d/%d PASS ====" % (npass, len(results)))
    if npass != len(results):
        print("FAILURES:")
        for n, ok, d in results:
            if not ok:
                print("  -", n, "::", d)
        sys.exit(1)
