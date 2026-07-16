"""E3 LIVE verify: real carrier-tracking advancement, one detector, once-only
delivery pushes + deep-link, buyer-tracking key-mismatch fix — driven over REAL
HTTP against the running prod uvicorn (NOT an in-process TestClient)."""
import base64, hashlib, os, time, json, sys
import urllib.request, urllib.error
from http.cookiejar import CookieJar

sys.path.insert(0, "/home/ubuntu/testlogon")
os.environ.setdefault("DEV_MODE", "1")
from app.core.tables import T
from app.services import seller_ship_groups as ssg
from app.services import shipment_tracking as st
from app.services import carrier_tracking as ct

BASE = "http://127.0.0.1:8000"
STAMP = int(time.time())
SELLER = "e3seller+%d@ecomx.test" % STAMP
BUYER = "e3buyer+%d@ecomx.test" % STAMP
ADMIN = "e3admin+%d@ecomx.test" % STAMP
PW = "E3-Verify-Pw-%d" % STAMP
ORDER_ID = "E3ORD-%d" % STAMP
TRACKING = "1Z999AA10123456784"  # UPS format
results = []
created_users = []
created_groups = []
created_tracking = []
created_txn = None
created_alerts_users = [SELLER, BUYER]


def chk(name, ok):
    results.append((name, bool(ok)))


def mkuser(sub, role="user"):
    salt = os.urandom(16); iters = 200000
    h = hashlib.pbkdf2_hmac("sha256", PW.encode(), salt, iters)
    T.users.put_item(Item={
        "user_sub": sub, "email": sub, "display_name": sub.split("@")[0],
        "password_hash": {"hash_b64": base64.b64encode(h).decode(),
                          "salt_b64": base64.b64encode(salt).decode(), "iterations": iters},
        "role": role, "created_at": STAMP, "_ecomx_e3_synth": True})
    created_users.append(sub)


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
        r = op.open(req, timeout=20)
        return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode() or "{}")
        except Exception:
            payload = {}
        return e.status, payload


def login(sub):
    cj = CookieJar()
    st_, resp = http("POST", "/ui/session/start", cj,
                     {"challenge_context": {"username": sub, "password": PW}})
    return cj, st_, resp


def count_alerts(sub, event):
    """Count alert rows for a user with a given alert event (scan the alerts table)."""
    try:
        resp = T.alerts.query(
            KeyConditionExpression="user_sub = :u",
            ExpressionAttributeValues={":u": sub},
        )
    except Exception:
        # table may be PK/SK named differently; fall back to scan
        resp = T.alerts.scan(FilterExpression="user_sub = :u",
                             ExpressionAttributeValues={":u": sub})
    n = 0
    matched = []
    for it in resp.get("Items", []):
        ev = str(it.get("event") or (it.get("details") or {}).get("alert_type") or "")
        if ev == event:
            n += 1
            matched.append(it)
    return n, matched


try:
    mkuser(SELLER); mkuser(BUYER); mkuser(ADMIN, role="admin")
    sg_id = hashlib.sha1(("%s#%s" % (ORDER_ID, SELLER)).encode()).hexdigest()
    now = int(time.time())
    # Seed an APPROVED seller ship-group for the order.
    T.seller_ship_groups.put_item(Item={
        "seller_id": SELLER, "ship_group_id": sg_id, "order_id": ORDER_ID,
        "buyer_id": BUYER, "status": "approved", "buyer_name": "E3 Buyer", "buyer_email": BUYER,
        "ship_to": {"line1": "3 Track Way", "city": "Shipton", "region": "CA",
                    "postal_code": "90003", "country": "US"},
        "line_items": [{"item_id": "sku-e3", "sku": "sku-e3", "name": "E3 Gadget",
                        "quantity": 1, "unit_price_cents": 1500, "line_total_cents": 1500}],
        "item_count": 1, "subtotal_cents": 1500, "currency": "USD",
        "created_at": now, "updated_at": now, "_ecomx_e3_synth": True})
    created_groups.append((SELLER, sg_id))
    created_tracking.append(sg_id)

    # Seed a buyer TXN linked to the order (external_ref=ORDER_ID) so the buyer
    # txn-tracking GET resolves the ship-group tracking.
    txn_id = "e3txn" + hashlib.sha1(("%s" % STAMP).encode()).hexdigest()[:20]
    created_at = now
    T.purchase_transactions.put_item(Item={
        "user_sub": BUYER, "sk": "TXN#%d#%s" % (created_at, txn_id), "txn_id": txn_id,
        "buyer_id": BUYER, "created_at": created_at, "updated_at": created_at,
        "status": "COMPLETED", "amount": "15.00", "currency": "USD", "version": 1,
        "external_ref": ORDER_ID, "metadata": {"order_id": ORDER_ID},
        "_ecomx_e3_synth": True})
    created_txn = (BUYER, "TXN#%d#%s" % (created_at, txn_id), txn_id)

    # ---- ECOMX-31: ONE detector -> one carrier + one URL ----
    car = ct.detect_carrier(TRACKING)
    chk("ECOMX-31 one detector resolves %s -> ups" % TRACKING, car == "ups")
    url = ct.build_tracking_url(car, TRACKING)
    chk("ECOMX-31 one valid tracking URL built", bool(url) and TRACKING in (url or ""))
    chk("ECOMX-31 carrier_tracking.detect delegates to shipment_tracking (UPS<->ups)",
        st.detect_carrier(TRACKING) == "UPS" and car == "ups")

    # ---- seller logs in, walks group to shipped WITH tracking # ----
    scj, sst, _ = login(SELLER)
    chk("seller login 200", sst == 200)
    for tgt in ("allocated", "picking", "packed"):
        code, resp = http("POST", "/ui/seller/sales/%s/transition" % sg_id, scj,
                          {"target_status": tgt}, {"x-csrf-token": csrf_of(scj)})
        if code != 200:
            code, resp = http("POST", "/ui/seller/sales/%s/transition" % sg_id, scj,
                              {"target_status": tgt}, {"x-csrf-token": csrf_of(scj)})
    code, resp = http("POST", "/ui/seller/sales/%s/transition" % sg_id, scj,
                      {"target_status": "shipped", "tracking_number": TRACKING, "carrier": "UPS"},
                      {"x-csrf-token": csrf_of(scj)})
    if code != 200:
        code, resp = http("POST", "/ui/seller/sales/%s/transition" % sg_id, scj,
                          {"target_status": "shipped", "tracking_number": TRACKING, "carrier": "UPS"},
                          {"x-csrf-token": csrf_of(scj)})
    chk("seller mark shipped w/ tracking# 200", code == 200 and (resp or {}).get("status") == "shipped")

    # a shipment_tracking record was created keyed by ship_group.
    rec = st.get_tracking(sg_id)
    chk("shipment_tracking record created on ship (label_created)",
        bool(rec) and rec.get("status") == "label_created" and rec.get("tracking_number") == TRACKING)
    chk("tracking record carrier detected UPS", (rec or {}).get("carrier") == "UPS")

    # ---- buyer Track screen shows the REAL carrier/number/status ----
    bcj, bst, _ = login(BUYER)
    chk("buyer login 200", bst == 200)
    # (a) ship-group-keyed live route
    code, tr = http("GET", "/ui/orders/tracking/%s" % sg_id, bcj)
    chk("buyer GET /ui/orders/tracking/{sg} 200", code == 200)
    chk("  ship-group route shows carrier+number+status",
        tr.get("carrier") == "UPS" and tr.get("tracking_number") == TRACKING and tr.get("status") == "label_created")
    chk("  ship-group route returns a valid tracking_url", bool(tr.get("tracking_url")))
    # (b) buyer TXN-keyed route (KEY MISMATCH FIX) -> resolves order -> ship-group tracking
    code, tr2 = http("GET", "/ui/purchase-history/transactions/%s/tracking" % txn_id, bcj)
    chk("buyer GET txn-tracking 200 (key-mismatch fix)", code == 200)
    chk("  txn-tracking POPULATES from ship-group (carrier=UPS)", tr2.get("carrier") == "UPS")
    chk("  txn-tracking shows tracking number", tr2.get("tracking_number") == TRACKING)
    chk("  txn-tracking shows status", bool(tr2.get("status")))

    # ---- ECOMX-30: status ADVANCES FOR REAL via run-progression (no admin simulate click) ----
    acj, ast_, _ = login(ADMIN)
    chk("admin login 200", ast_ == 200)
    seen = [rec.get("status")]
    for _ in range(6):
        code, summ = http("POST", "/ui/admin/shipment-tracking/run-progression", acj, None,
                          {"x-csrf-token": csrf_of(acj)})
        cur = st.get_tracking(sg_id)
        seen.append((cur or {}).get("status"))
        if (cur or {}).get("status") == "delivered":
            break
    chk("ECOMX-30 run-progression endpoint 200", code == 200)
    chk("ECOMX-30 status advanced through in_transit", "in_transit" in seen)
    chk("ECOMX-30 status advanced through out_for_delivery", "out_for_delivery" in seen)
    chk("ECOMX-30 status reached delivered (no admin simulate click)",
        (st.get_tracking(sg_id) or {}).get("status") == "delivered")

    # ---- once-only delivery pushes + deep-link ----
    n_ofd, m_ofd = count_alerts(BUYER, "order_out_for_delivery")
    n_del, m_del = count_alerts(BUYER, "order_delivered")
    chk("out_for_delivery buyer alert fired EXACTLY once", n_ofd == 1)
    chk("delivered buyer alert fired EXACTLY once", n_del == 1)
    dl = ""
    if m_del:
        dl = str(m_del[0].get("action_url") or (m_del[0].get("details") or {}).get("action_url") or "")
    chk("delivered alert carries a deep-link action_url", "order=" in dl and "track=1" in dl and ("ship_group=" in dl))

    # extra run-progression passes must NOT re-fire the pushes (idempotent).
    for _ in range(2):
        http("POST", "/ui/admin/shipment-tracking/run-progression", acj, None, {"x-csrf-token": csrf_of(acj)})
    n_ofd2, _ = count_alerts(BUYER, "order_out_for_delivery")
    n_del2, _ = count_alerts(BUYER, "order_delivered")
    chk("re-running progression does NOT duplicate pushes", n_ofd2 == 1 and n_del2 == 1)

    # ---- ECOMX-32: monotonic guard — a regress can't un-deliver ----
    before = (st.get_tracking(sg_id) or {}).get("status")
    st.advance(ship_group_id=sg_id, status="in_transit", source="test-regress")
    after = (st.get_tracking(sg_id) or {}).get("status")
    chk("ECOMX-32 monotonic guard refuses delivered->in_transit regress",
        before == "delivered" and after == "delivered")
    # out-of-order webhook (in_transit after delivered) via the LIVE webhook route also refused.
    code, wres = http("POST", "/ui/shipping/tracking/webhook", CookieJar(),
                      {"ship_group_id": sg_id, "status": "in_transit"})
    chk("ECOMX-32 out-of-order webhook can't regress delivered",
        (st.get_tracking(sg_id) or {}).get("status") == "delivered")

    # ---- deep-link resolves: the alert action_url path is a known buyer surface ----
    chk("deep-link path is /orders (buyer order surface)", dl.startswith("/orders?order="))

    # ---- REGRESSION: seller sales + refund routes still healthy ----
    code, _ = http("GET", "/ui/seller/sales", scj)
    chk("REGRESSION seller /ui/seller/sales still 200", code == 200)
    code, oj = http("GET", "/openapi.json", CookieJar())
    paths = list((oj or {}).get("paths", {}).keys())
    chk("REGRESSION refund-requests routes still mounted",
        any("refund" in p for p in paths))
    chk("REGRESSION run-progression route present", "/ui/admin/shipment-tracking/run-progression" in paths)

finally:
    # cleanup
    try:
        if created_txn:
            T.purchase_transactions.delete_item(Key={"user_sub": created_txn[0], "sk": created_txn[1]})
    except Exception as e:
        print("cleanup txn err", e)
    for sg in created_tracking:
        try:
            T.shipment_tracking.delete_item(Key={"ship_group_id": sg})
        except Exception as e:
            print("cleanup track err", e)
    for (sid, gid) in created_groups:
        try:
            T.seller_ship_groups.delete_item(Key={"seller_id": sid, "ship_group_id": gid})
        except Exception as e:
            print("cleanup grp err", e)
    # alerts cleanup (best-effort): delete synthetic buyer alerts
    for sub in created_alerts_users:
        try:
            r = T.alerts.query(KeyConditionExpression="user_sub = :u",
                               ExpressionAttributeValues={":u": sub})
            for it in r.get("Items", []):
                key = {k: it[k] for k in it if k in ("user_sub", "sk", "alert_id", "created_at")}
                try:
                    T.alerts.delete_item(Key=key)
                except Exception:
                    pass
        except Exception:
            pass
    for sub in created_users:
        try:
            T.users.delete_item(Key={"user_sub": sub})
        except Exception as e:
            print("cleanup user err", e)

print("\n=== E3 LIVE CARRIER-TRACKING VERIFY MATRIX ===")
allok = True
for name, ok in results:
    print(("PASS" if ok else "FAIL"), "-", name); allok = allok and ok
print("=== RESULT:", "ALL PASS" if allok else "HAS FAILURES", "===")
print("cleanup: removed", len(created_groups), "groups,", len(created_tracking), "tracking,",
      len(created_users), "users, 1 txn")
sys.exit(0 if allok else 1)
